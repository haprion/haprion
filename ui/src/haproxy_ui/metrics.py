"""One status reading, turned into the rows that are kept.

The cache and the samples answer different questions from the same read.
`cluster_status` holds what is true now and is replaced every poll; these rows
hold what was true then and are never updated. So the poller writes both from
one reading rather than asking the nodes twice.

Read out of the stored status document rather than through `parse_status`, for
the reason `health.pool_health` gives: a poll that reached one node of two
still carries the node that answered, and `parse_status` refuses an envelope it
cannot fully believe. A pass that recorded nothing whenever one node was
unreachable would lose the half of the cluster that is fine, on exactly the
days the samples are worth having.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

#
# HAProxy's own `show stat` column names. The same list appears in
# `install/node/haproxy-node-status`, which reads them, and in migration 0018,
# which stores them. Three lists is two too many, and they cannot be one: the
# node script is installed rather than imported and a migration must not import
# application code. `test_metric_samples` compares all three instead.
#
METRIC_COUNTERS: tuple[str, ...] = (
    "scur",
    "stot",
    "bin",
    "bout",
    "req_tot",
    "qcur",
    "ereq",
    "econ",
    "eresp",
    "dreq",
    "dresp",
    "wretr",
    "wredis",
    "hrsp_2xx",
    "hrsp_3xx",
    "hrsp_4xx",
    "hrsp_5xx",
)


@dataclass(frozen=True, slots=True)
class ListenerSample:
    node: str
    frontend: str
    owns_vip: bool | None
    uptime_sec: int | None
    status: str | None
    counters: Mapping[str, int] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class MemberSample:
    node: str
    backend: str
    member: str
    uptime_sec: int | None
    status: str | None
    check_status: str | None
    check_code: str | None
    counters: Mapping[str, int] = field(default_factory=dict)


def _text(value: object) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def _count(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _counters(value: object) -> dict[str, int]:
    """The counters this row reported a number for, and only those.

    A name left out is a column that does not apply or a node that did not
    report it. Carried as zero it would read as "counted, and it was none",
    which is the one confusion these rows exist to avoid - so the column is
    left null and the difference survives into the table.
    """

    if not isinstance(value, Mapping):
        return {}
    found = {}
    for name in METRIC_COUNTERS:
        number = _count(value.get(name))
        if number is not None:
            found[name] = number
    return found


def _entries(value: object) -> Sequence[Any]:
    if isinstance(value, Sequence) and not isinstance(value, str | bytes):
        return value
    return ()


def samples(result: Mapping[str, Any]) -> tuple[list[ListenerSample], list[MemberSample]]:
    """What one status reading is worth keeping, split the way B94 splits it.

    **Listeners come from every node.** A standby's `req_tot` of zero is a real
    measurement and the expected one; a standby whose listener counted anything
    at all is traffic arriving at a node that does not hold the address, which
    is worth being able to see afterwards.

    **Pool members come only from the node that holds the VIP.** The generated
    backend carries `source <the VIP's address>`, that address is held by the
    keepalived master, and the standby's health check is answered to whoever
    holds it. Its `DOWN` is not a measurement of the backend, so storing it
    would be storing `down` every minute about a server that is up.

    A node whose ownership is unknown contributes no member rows either. Not
    knowing who held the address is precisely not knowing whether the verdict
    means anything, and a row that cannot be attributed is worse than no row.
    """

    listeners: list[ListenerSample] = []
    members: list[MemberSample] = []

    for entry in _entries(result.get("nodes")):
        if not isinstance(entry, Mapping):
            continue
        status = entry.get("status")
        if not isinstance(status, Mapping):
            continue
        node = _text(entry.get("name")) or _text(status.get("node"))
        if node is None:
            continue

        vip = status.get("vip")
        held = vip.get("owner") if isinstance(vip, Mapping) else None
        owns_vip = held if isinstance(held, bool) else None

        runtime = status.get("runtime")
        uptime = _count(runtime.get("uptime_sec")) if isinstance(runtime, Mapping) else None

        for row in _entries(status.get("frontends")):
            if not isinstance(row, Mapping):
                continue
            frontend = _text(row.get("frontend"))
            if frontend is None:
                continue
            listeners.append(
                ListenerSample(
                    node=node,
                    frontend=frontend,
                    owns_vip=owns_vip,
                    uptime_sec=uptime,
                    status=_text(row.get("status")),
                    counters=_counters(row.get("counters")),
                )
            )

        if owns_vip is not True:
            continue

        for row in _entries(status.get("servers")):
            if not isinstance(row, Mapping):
                continue
            backend = _text(row.get("backend"))
            member = _text(row.get("server"))
            if backend is None or member is None:
                continue
            members.append(
                MemberSample(
                    node=node,
                    backend=backend,
                    member=member,
                    uptime_sec=uptime,
                    status=_text(row.get("status")),
                    check_status=_text(row.get("check_status")),
                    check_code=_text(row.get("check_code")),
                    counters=_counters(row.get("counters")),
                )
            )

    return listeners, members


@dataclass(frozen=True, slots=True)
class Sample:
    """One reading, as the reader gets it back.

    Over a long window the reader hands back one sample per bucket rather than
    every row, and then `floor_uptime_sec` matters: it is the lowest uptime
    seen anywhere inside that bucket. Without it a restart that happened
    between two kept samples would be invisible, because the process can climb
    back past the previous reading before the next one is taken - and the
    interval would be reported as a quiet stretch of the busiest hour.
    """

    observed_at: datetime
    member: str
    uptime_sec: int | None
    counters: Mapping[str, int | None]
    floor_uptime_sec: int | None = None
    #
    # Which node counted it. Pool members are stored only from the node holding
    # the VIP, so the series changes author at a failover and the two halves
    # are different processes' cumulative counters. Without this the reader
    # cannot tell that apart from one process that kept counting.
    #
    node: str | None = None


@dataclass(frozen=True, slots=True)
class Interval:
    """What happened between two samples, or that it cannot be said.

    A counter is `None` where the difference cannot be trusted, which is not
    the same as zero. Zero means the two readings agreed and nothing happened
    in between; `None` means the second reading cannot be subtracted from the
    first at all - and drawing that as a flat line would be inventing calm.
    """

    started_at: datetime
    ended_at: datetime
    counters: Mapping[str, int | None]
    restarted: bool
    #
    # The other reason a difference cannot be taken: the two readings were
    # counted by different nodes. Kept apart from `restarted` because the
    # sentence a reader needs is different - one process began again, or the
    # address moved and another machine started answering.
    #
    handed_over: bool = False

    @property
    def seconds(self) -> float:
        return (self.ended_at - self.started_at).total_seconds()


def intervals(samples: Sequence[Sample]) -> list[Interval]:
    """Cumulative readings turned into what happened between them.

    HAProxy's counters climb from the moment the process started and go back to
    zero when it restarts, so a difference is the only thing with meaning - and
    a difference across a restart has none.

    **A restart is read from the uptime, not from the counters.** A counter that
    fell could be a restart or could be a reading of a different process
    entirely; `uptime_sec` falling says which, and it is why the poller stores
    it beside every row. Where the uptime cannot be compared - an older node
    reported none - a counter that fell is still refused rather than guessed,
    because the alternative is reporting a busy minute as a quiet one.

    Events between the last reading and the restart are lost either way. The
    process that counted them is gone, and the new one starts from zero, so the
    interval that spans a restart reports `None` rather than the new process's
    total: that total is real, but it is not what happened in this interval.

    **A change of node is refused for the same reason, and it does not show up
    in the uptime.** Pool members are recorded only from the node holding the
    VIP, so a failover hands the series to a machine that has been up longer
    than the one it replaced - higher uptime and higher counters, which is
    exactly what a healthy interval looks like. Subtracting across it reports
    the incoming node's lifetime total as this interval's traffic. What
    happened between the last reading of one and the first of the other was
    never observed by either, and no arithmetic recovers it.

    Samples that predate the node being carried have `node` as `None`. Two of
    those are compared as before rather than treated as a change, so a reader
    of older rows keeps the behaviour it had.
    """

    ordered = sorted(samples, key=lambda sample: (sample.observed_at, sample.node or ""))
    found: list[Interval] = []

    for earlier, later in zip(ordered, ordered[1:], strict=False):
        #
        # The floor inside the later bucket, where there is one, because a
        # restart can happen and be climbed past between two kept samples.
        # Falling back to the sample's own uptime is what makes this the same
        # comparison on raw rows, where every reading is its own bucket.
        #
        floor = later.floor_uptime_sec if later.floor_uptime_sec is not None else later.uptime_sec
        restarted = (
            earlier.uptime_sec is not None and floor is not None and floor < earlier.uptime_sec
        )
        handed_over = (
            earlier.node is not None and later.node is not None and earlier.node != later.node
        )
        counters: dict[str, int | None] = {}
        for name in METRIC_COUNTERS:
            before = earlier.counters.get(name)
            after = later.counters.get(name)
            if restarted or handed_over or before is None or after is None or after < before:
                counters[name] = None
            else:
                counters[name] = after - before
        found.append(
            Interval(
                started_at=earlier.observed_at,
                ended_at=later.observed_at,
                counters=counters,
                restarted=restarted,
                handed_over=handed_over,
            )
        )
    return found


@dataclass(frozen=True, slots=True)
class Total:
    """One counter summed over a window, and how much of the window it covers.

    **The coverage is not a footnote, it is half the reading.** An earlier
    version answered a window with a hole in it with nothing at all, on the
    grounds that a partial sum reads as the whole window's traffic and would be
    compared against one that was complete. The danger is real; withholding the
    number is the wrong answer to it. A month with one reload in it is a month
    with one reload in it, and refusing to say anything about the other 27 days
    leaves the operator with an em dash where the data is.

    So the number is given and the coverage travels with it, always, in the same
    breath. `whole` is what the strict version used to return; what changed is
    that not-whole now still carries what was counted.
    """

    label: str
    value: int
    counted_sec: float
    span_sec: float

    @property
    def whole(self) -> bool:
        """Whether every interval in the window could be counted."""

        return self.counted_sec >= self.span_sec

    @property
    def coverage(self) -> int:
        """How much of the window the figure covers, as a whole percent.

        Rounded down, so a window missing any measurable part of itself cannot
        round up to a confident 100. An empty window covers nothing and says
        100 rather than dividing by zero: there is no span to have missed, and
        `measured` is the property that says the window is empty.
        """

        if self.span_sec <= 0:
            return 100
        return int(self.counted_sec / self.span_sec * 100)


def totalled(found: Sequence[Interval], name: str, label: str = "") -> Total:
    """One counter summed over a run of intervals, with the part it could not see.

    Intervals whose difference could not be taken - a restart, a change of
    node, a counter the node did not report - contribute neither to the value
    nor to the time counted. The window's own span includes them, which is
    precisely what makes the difference between the two visible.
    """

    value = 0
    counted = 0.0
    span = 0.0
    for interval in found:
        span += interval.seconds
        amount = interval.counters.get(name)
        if amount is None:
            continue
        value += amount
        counted += interval.seconds
    return Total(label=label, value=value, counted_sec=counted, span_sec=span)


def spark_paths(
    values: Sequence[int | None], *, width: float, height: float
) -> tuple[list[str], int]:
    """A sparkline as one SVG path per unbroken run, and the peak it is scaled to.

    **A gap is drawn as a gap.** An interval whose difference could not be taken
    - a restart, a counter the node did not report - ends the current path and
    the next known value starts a new one. Joining across it would draw a
    straight line through the one place the data does not know what happened,
    which reads as the calmest part of the window.

    Scaled to its own peak rather than to a fixed ceiling, because the question
    a sparkline answers is "what shape", not "how much" - the number beside it
    answers that. A window with no traffic has no peak to scale to and is drawn
    flat on the baseline, which is the truth: nothing happened.
    """

    known = [value for value in values if value is not None]
    peak = max(known) if known else 0
    if len(values) < 2:
        return [], peak

    step = width / (len(values) - 1)
    runs: list[list[str]] = []
    current: list[str] = []

    for index, value in enumerate(values):
        if value is None:
            if len(current) > 1:
                runs.append(current)
            current = []
            continue
        x = index * step
        y = height if peak == 0 else height - (value / peak) * height
        current.append(f"{'M' if not current else 'L'}{x:.1f} {y:.1f}")
    if len(current) > 1:
        runs.append(current)

    return [" ".join(run) for run in runs], peak


#
# What the object page shows, and why these and not the other fourteen. Each
# answers a question somebody actually arrives with: did anything reach this
# pool, did it answer, did it refuse, could it be reached at all, and did it
# have to try twice. The rest are kept in the table for the day a question
# needs them - a card that shows everything answers nothing.
#
CARD_COUNTERS: tuple[tuple[str, str], ...] = (
    ("req_tot", "Requests"),
    ("hrsp_2xx", "2xx"),
    ("hrsp_4xx", "4xx"),
    ("hrsp_5xx", "5xx"),
    ("econ", "Connection errors"),
    ("wretr", "Retries"),
)

#
# The drawing's own coordinate space, not its size on screen. The stylesheet
# gives it the width the card has to spare and the stroke is told not to scale,
# so a wide card gets a wide line rather than a thick one. Generous, because a
# month at six-hourly buckets is 120 points and they have to be far enough
# apart that a reader can put a finger on one and say roughly when it was.
#
SPARK_WIDTH = 1000.0
SPARK_HEIGHT = 64.0

#
# How many labels go under the line. Enough to locate a bump - "about
# two-thirds along" is not an answer somebody can act on, and a date is - and
# few enough that they do not collide on a narrow card.
#
SPARK_TICKS = 5


@dataclass(frozen=True, slots=True)
class PoolTraffic:
    """One pool's window, ready to draw.

    Named by the runtime's own name for the pool, which is the only name that
    exists for a proxy nobody wrote here.
    """

    backend: str
    intervals: int
    started_at: datetime | None
    ended_at: datetime | None
    #
    # One `Total` per `CARD_COUNTERS` entry, in that order. Each carries its
    # own coverage, so a figure the window could not fully see is printed with
    # what it did see rather than as an em dash.
    #
    totals: tuple[Total, ...]
    paths: tuple[str, ...]
    #
    # (percentage across, label) so the template can place each one without
    # knowing the drawing's coordinate space. Written as a percentage because
    # the line is stretched to whatever width the card has, and a label
    # positioned in the SVG's own units would drift away from the point it
    # names as soon as it was.
    #
    ticks: tuple[tuple[float, str], ...]
    peak: int
    restarted: bool
    handed_over: bool = False
    #
    # How much of the window's time sits in intervals that could be measured at
    # all, as a whole percent. A property of the window rather than of any one
    # counter: a restart and a change of node cost every figure the same
    # stretch, while a counter the node never reported costs only itself and
    # says so on its own figure.
    #
    coverage: int = 100

    @property
    def quiet(self) -> bool:
        """Whether the whole window is a measured nothing.

        The figures and the line stay either way - they are the reading, and
        an interface that removes them to avoid repeating itself has removed
        the answer to keep the phrasing tidy. What this earns is one sentence
        under them saying the stillness was measured, and the dropping of the
        peak label, which beside a flat line and a row of zeros is the third
        copy of one fact.

        A window with a single unknown interval is not quiet - it is a window
        with a hole, which is a different sentence.
        """

        return self.measured and all(total.whole and total.value == 0 for total in self.totals)

    @property
    def measured(self) -> bool:
        """Whether there is a window at all, as opposed to one that is empty.

        A pool with no samples has not been observed; a pool with samples and
        no traffic has. The page says different things about them, and the
        difference is the one this whole table exists to keep.
        """

        return self.intervals > 0


def spark_ticks(
    found: Sequence[Interval], *, fmt: str, count: int = SPARK_TICKS
) -> list[tuple[float, str]]:
    """Where the line sits in time, as evenly spaced labels along it.

    Without these the shape is unlocatable: a reader can see that something
    happened but not whether it was ten days ago or twenty, which is the
    question a month-long window is opened to answer.

    Taken from the intervals themselves rather than computed from the window's
    span, so the labels name moments that were actually measured. A window with
    less history than it asks for then says so by where its labels start,
    instead of drawing a month whose first three weeks are an assumption.
    """

    if len(found) < 2:
        return []
    places = min(count, len(found))
    step = (len(found) - 1) / (places - 1) if places > 1 else 0
    ticks: list[tuple[float, str]] = []
    for index in range(places):
        at = found[round(index * step)]
        ticks.append((index / (places - 1) * 100 if places > 1 else 0.0, at.ended_at.strftime(fmt)))
    return ticks


def window_coverage(found: Sequence[Interval]) -> int:
    """How much of a window's time could be measured at all, as a whole percent.

    Counted from the structural gaps alone - a restart, a change of node -
    because those are what cost every figure on the card the same stretch of
    time. A counter the node did not report is a hole in that figure and not in
    the window, and folding it in here once produced a card that announced 0%
    coverage beside a figure covering half the window.

    Rounded down, so a window missing a measurable part of itself cannot round
    up to a confident 100.
    """

    span = sum(interval.seconds for interval in found)
    if span <= 0:
        return 100
    measured = sum(
        interval.seconds
        for interval in found
        if not interval.restarted and not interval.handed_over
    )
    return int(measured / span * 100)


def pool_traffic(
    backend: str, samples: Sequence[Sample], *, tick_format: str = "%H:%M"
) -> PoolTraffic:
    found = intervals(samples)
    totals = tuple(totalled(found, name, label) for name, label in CARD_COUNTERS)
    paths, peak = spark_paths(
        [interval.counters.get("req_tot") for interval in found],
        width=SPARK_WIDTH,
        height=SPARK_HEIGHT,
    )
    return PoolTraffic(
        backend=backend,
        intervals=len(found),
        started_at=found[0].started_at if found else None,
        ended_at=found[-1].ended_at if found else None,
        totals=totals,
        paths=tuple(paths),
        ticks=tuple(spark_ticks(found, fmt=tick_format)),
        peak=peak,
        restarted=any(interval.restarted for interval in found),
        handed_over=any(interval.handed_over for interval in found),
        coverage=window_coverage(found),
    )


#
# The windows the object page offers, and the bucket each one is drawn at.
# Chosen so every window lands between roughly sixty and a hundred and eighty
# points: fewer and the shape is a guess, more and they are narrower than the
# line is thick. The 10-minute and 1-hour widths are deliberately the phase's
# own rollup resolutions - the same arithmetic will read a rollup table when
# one exists, and the raw rows are what answers until then.
#
@dataclass(frozen=True, slots=True)
class Window:
    key: str
    label: str
    span: timedelta
    bucket: timedelta
    #
    # How a tick under the line is written. An hour needs the minute and no
    # date; a month needs the date and no minute - and a label carrying both
    # is one nobody reads twice.
    #
    tick: str
    #
    # What one point on the line covers, in words, so the peak can say "per
    # 10 minutes" instead of leaving a reader to work out what a sample is.
    #
    bucket_label: str


WINDOWS: tuple[Window, ...] = (
    Window("1h", "the last hour", timedelta(hours=1), timedelta(minutes=1), "%H:%M", "minute"),
    Window(
        "24h", "the last 24 hours", timedelta(hours=24), timedelta(minutes=10), "%H:%M", "10 min"
    ),
    Window("7d", "the last 7 days", timedelta(days=7), timedelta(hours=1), "%a %d", "hour"),
    Window("30d", "the last 30 days", timedelta(days=30), timedelta(hours=6), "%d %b", "6 hours"),
)

#
# 24 hours, because the question the card is opened with is usually "is this
# normal", and an hour is too short to have a normal. The shorter window is
# still there for the middle of an incident, where the last hour is the only
# part that matters.
#
DEFAULT_WINDOW = "24h"

#
# How long the raw samples are kept, and therefore where the reader stops
# asking the raw table and starts asking the hourly rollup. The same number
# lives in the retention command, which is what makes it true; here it decides
# which table a window is answered from.
#
# It is a fixed age rather than "whatever the rollup happens to hold", so the
# two halves of a long window cannot overlap and an hour cannot be counted
# twice. The rollup is computed with six days of slack for exactly that reason.
#
RAW_RETENTION = timedelta(days=7)


def window(asked: str | None) -> Window:
    """One of the offered windows, by key, falling back to the default.

    An unknown key is the default rather than a refusal: it arrives in a query
    string somebody may have typed or a link that outlived a change, and a page
    that answers 400 for it has turned a stale bookmark into an error.
    """

    for entry in WINDOWS:
        if entry.key == asked:
            return entry
    return next(entry for entry in WINDOWS if entry.key == DEFAULT_WINDOW)
