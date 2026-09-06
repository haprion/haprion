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

import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
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


#
# The ceilings a line may be scaled to, per power of ten. Round numbers a
# reader recognises without doing arithmetic, and all even, so the halfway
# gridline is a whole number too - `40` above `80` reads at a glance where
# `37` above `74` reads as a measurement of something.
#
# 1 is here so that a peak already on a round number keeps it - a pool topping
# out at exactly 10 should be drawn against 10, not against 20 with a third of
# the card left empty. `MIN_CEILING` is what stops that from also giving a pool
# that peaked at one request a midpoint of half a request.
#
CEILING_STEPS: tuple[int, ...] = (1, 2, 3, 4, 5, 6, 8, 10)
MIN_CEILING = 2


def ceiling_for(peak: int) -> int:
    """The round number a line is drawn against, at or above its peak.

    **Not the peak itself, which is what it used to be.** A line scaled to its
    own maximum touches the top of the card whatever it measures, so a pool
    serving three requests a minute and one serving three thousand drew the
    same picture - and switching windows silently changed what "high" meant.
    Against a fixed round ceiling the height of the line is information.
    """

    if peak <= 0:
        return 0
    unit = 10 ** math.floor(math.log10(peak))
    for step in CEILING_STEPS:
        candidate = step * unit
        if candidate >= peak and candidate >= MIN_CEILING:
            return int(candidate)
    return int(10 * unit)


@dataclass(frozen=True, slots=True)
class Level:
    """One horizontal guide across the drawing, and what it is worth."""

    label: str
    #
    # Where it sits, twice: in the drawing's own units for the line inside the
    # SVG, and as a share of the height for the label beside it, which is HTML
    # and knows nothing of the viewBox.
    #
    y: float
    share: float


def levels_for(ceiling: int, *, height: float) -> tuple[Level, ...]:
    """The ceiling, its halfway mark and the floor - or nothing to say.

    **The zero is not the obvious one it looked like.** It was left out at
    first, on the grounds that the line rests on the baseline and the card
    would be labelling something already visible. Seen on a real card it read
    as a scale that had been cut off: two numbers hanging in the middle of the
    drawing with nothing underneath to measure them against. An axis needs its
    origin to be an axis.

    A window with no traffic has no ceiling to divide, and `0` alone across an
    empty card is furniture rather than a scale.
    """

    if ceiling <= 0:
        return ()
    return tuple(
        Level(label=_plainly(ceiling * share), y=height * (1 - share), share=(1 - share) * 100)
        for share in (1.0, 0.5, 0.0)
    )


def _plainly(value: float) -> str:
    """A number without a decimal point it does not need."""

    return f"{value:.0f}" if float(value).is_integer() else f"{value:.1f}"


@dataclass(frozen=True, slots=True)
class Point:
    """One plotted bucket, where it sits and what a hover over it says."""

    at: datetime
    x: float
    y: float
    value: int
    reading: str
    #
    # Whether a reading stood behind it, as opposed to a bucket the line rests
    # on the baseline for. The drawing treats them alike on the maintainer's
    # call; the hover does not, because "0" and "nobody was watching" are not
    # the same answer to "what happened at 09:40".
    #
    measured: bool = True


#
# The grid every bucket is measured from, and it must be an absolute moment
# rather than the window's own start.
#
# The reader's SQL bins rows with `date_bin(width, observed_at, '2000-01-01')`,
# which is a fixed grid. A drawing that binned the same readings from `now -
# span` would use a grid that moves every time the page is loaded, and the two
# would sit a fraction of a bucket apart: some buckets would hold two readings
# and their neighbours none, which draws a sawtooth down to zero - and a
# different sawtooth on every refresh. It did, for one release.
#
BUCKET_EPOCH = datetime(2000, 1, 1, tzinfo=UTC)


def _bucket_of(at: datetime, bucket: timedelta) -> int:
    return int((at - BUCKET_EPOCH) / bucket)


def bucketed(
    found: Sequence[Interval],
    *,
    start: datetime,
    end: datetime,
    bucket: timedelta,
) -> list[tuple[datetime, dict[str, int | None], bool]]:
    """The window as fixed buckets, each carrying what happened inside it.

    **Traffic is shared out over the time it covers, not dropped on one
    bucket.** A reading answers for the stretch since the previous one, and
    that stretch does not have to be one bucket: the poller runs on its own
    period, a poll can be late, and a long window reads hourly rollup rows into
    six-hour buckets. Attributing the whole count to the bucket the reading
    lands in leaves its neighbours at zero and draws a spike beside a hole,
    both invented. Splitting it by overlap keeps the total and puts it where
    the time was.

    A counter that could not be differenced anywhere across a bucket makes that
    counter unknown for the bucket. It is not shared out as zero, which is the
    one value it is known not to be.

    Returns one entry per bucket in the window: when it begins, what it counted,
    and whether anything was recorded for it at all.
    """

    #
    # Whole buckets only. The window's edges fall wherever `now` puts them, so
    # the first and last buckets it touches are part buckets - and a part
    # bucket holds part of a bucket's traffic, which draws as a dip at each end
    # that no reader can tell from a quiet minute. The one at the right is the
    # minute in progress and dipped on every page load.
    #
    first = math.ceil((start - BUCKET_EPOCH) / bucket)
    last = _bucket_of(end, bucket) - 1

    counted: dict[int, dict[str, float]] = {}
    unknown: dict[int, set[str]] = {}
    touched: set[int] = set()

    for interval in found:
        span = interval.seconds
        if span <= 0:
            continue
        for index in range(
            _bucket_of(interval.started_at, bucket), _bucket_of(interval.ended_at, bucket) + 1
        ):
            edge = BUCKET_EPOCH + bucket * index
            overlap = (
                min(interval.ended_at, edge + bucket) - max(interval.started_at, edge)
            ).total_seconds()
            if overlap <= 0 or not first <= index <= last:
                continue
            touched.add(index)
            share = overlap / span
            for name in METRIC_COUNTERS:
                value = interval.counters.get(name)
                if value is None:
                    unknown.setdefault(index, set()).add(name)
                    continue
                counted.setdefault(index, {})[name] = (
                    counted.setdefault(index, {}).get(name, 0.0) + value * share
                )

    grid: list[tuple[datetime, dict[str, int | None], bool]] = []
    for index in range(first, last + 1):
        at = BUCKET_EPOCH + bucket * index
        missing = unknown.get(index, set())
        totals: dict[str, int | None] = {}
        for name in METRIC_COUNTERS:
            if name in missing:
                totals[name] = None
            else:
                totals[name] = round(counted.get(index, {}).get(name, 0.0))
        grid.append((at, totals, index in touched))
    return grid


def spark(
    found: Sequence[Interval],
    *,
    width: float,
    height: float,
    start: datetime,
    end: datetime,
    bucket: timedelta,
) -> tuple[list[str], list[Point], int]:
    """A sparkline on an absolute time axis, its hover points, and its peak.

    **The axis is the window, not the data.** An earlier version spaced the
    readings evenly across the card, so a day of samples filled a 30-day view
    edge to edge and the same shape meant a different stretch of time in every
    window. Trends are read by comparing one part of a window against another;
    that needs a fixed scale, so a point sits where its moment sits.

    **A bucket nothing was recorded for rests on the baseline.** The
    maintainer's call, and the reason is the card's purpose: a trend is read off
    a continuous line, and a window that only draws where the poller has history
    gives a month-long view a short scribble in one corner. The cost is stated
    rather than hidden - the line cannot then separate "no traffic" from "no
    poller", so the hover says which of the two each bucket was, and the figures
    beside the card carry their own coverage.

    **A counter that could not be differenced is still a gap.** A restart, a
    change of node, a counter the node did not report: the line breaks there and
    the next known value starts a new run. That is deliberately not the same as
    an empty bucket. Something was measured across it and could not be turned
    into a rate, which is a narrower and more suspicious thing than a stretch
    nobody sampled - and it is the one the figures' coverage is counted from.

    **Scaled to a round ceiling at or above its peak**, so the height of the
    line means something. Drawn against its own maximum it touched the top of
    the card whatever it measured, which made every window look equally busy
    and every pool look alike. A window with no traffic has no ceiling and is
    drawn flat on the baseline, which is the truth: nothing happened.
    """

    seconds = (end - start).total_seconds()
    if seconds <= 0 or bucket <= timedelta(0):
        return [], [], 0

    grid = bucketed(found, start=start, end=end, bucket=bucket)
    peak = max(
        (value for _, totals, _ in grid if (value := totals.get("req_tot")) is not None),
        default=0,
    )
    ceiling = ceiling_for(peak)

    runs: list[list[str]] = []
    current: list[str] = []
    points: list[Point] = []

    for at, totals, measured in grid:
        value = totals.get("req_tot")
        position = min(max((at - start).total_seconds() / seconds, 0.0), 1.0)
        x = position * width
        if value is None:
            if len(current) > 1:
                runs.append(current)
            current = []
            points.append(
                Point(at=at, x=x, y=height, value=0, reading=reading_at(at, totals), measured=True)
            )
            continue
        y = height if ceiling == 0 else height - (value / ceiling) * height
        current.append(f"{'M' if not current else 'L'}{x:.1f} {y:.1f}")
        points.append(
            Point(
                at=at,
                x=x,
                y=y,
                value=value,
                reading=reading_at(at, totals) if measured else unread_at(at),
                measured=measured,
            )
        )
    if len(current) > 1:
        runs.append(current)

    return [" ".join(run) for run in runs], points, peak


def unread_at(at: datetime) -> str:
    """What a bucket says when the line rests on the baseline without a reading.

    The line cannot make this distinction - it is drawn at zero either way, so
    that a month-long window has a month-long line - so the hover is where it
    is kept. Without it the card would answer "how much traffic at 03:00 last
    Tuesday" with a confident nothing, for an hour the poller was not running.
    """

    return f"{at.strftime(TIMESTAMP)} · no reading"


def reading_at(at: datetime, totals: Mapping[str, int | None]) -> str:
    """What one bucket says when the pointer rests on it.

    Every figure the card carries, not only the one the line draws, because the
    question a spike raises is usually about a different counter than the one
    that showed it - a rise in requests is asked about together with what
    answered them.

    A counter that could not be measured says so rather than being left out.
    Absent from the list it would read as zero, which is the one thing it is
    not known to be.
    """

    when = at.strftime(TIMESTAMP)
    parts = [
        f"{label} {value if (value := totals.get(name)) is not None else 'not measured'}"
        for name, label in CARD_COUNTERS
    ]
    return f"{when} · " + " · ".join(parts)


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
# How a moment is written wherever one is printed in full: `yy-mm-dd
# hh:mm:ss` on a 24-hour clock. Fixed width, unambiguous between the
# reader's conventions, and sortable as text - which the axis labels are
# not trying to be, since they are read at a glance rather than compared.
#
TIMESTAMP = "%y-%m-%d %H:%M:%S"

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
    #
    # The horizontal guides, top first. Empty for a window with no traffic:
    # there is no ceiling to divide, and two zeroes across an empty card are
    # furniture rather than a scale.
    #
    levels: tuple[Level, ...]
    #
    # The highest bucket, kept for the drawing's own description. It is no
    # longer printed beside the line - the ceiling above it says the same thing
    # in a rounder number, and two near-identical figures is the repetition the
    # card was stripped of.
    #
    peak: int
    restarted: bool
    #
    # One per plotted reading, for the hover targets drawn over the line. The
    # paths alone cannot answer "what exactly was that spike, and when" - a
    # shape is read at a glance and a number is read on purpose.
    #
    points: tuple[Point, ...] = ()
    #
    # How wide one bucket is in the drawing's own units, so a hover target can
    # be the width of what it represents rather than of the line.
    #
    hit_width: float = 0.0
    handed_over: bool = False
    #
    # How much of the window's time sits in intervals that could be measured at
    # all, as a whole percent. A property of the window rather than of any one
    # counter: a restart and a change of node cost every figure the same
    # stretch, while a counter the node never reported costs only itself and
    # says so on its own figure.
    #
    coverage: int = 100

    #
    # There was a `quiet` property here, and the sentence it turned on -
    # "nothing reached this pool in the last hour" - was removed on the
    # maintainer's call. A row of zeros beside a flat line already says it, and
    # saying it a third time in prose is what made the card wordy. The figures
    # and the line are the reading; `measured` still separates a window that
    # counted nothing from one that has nothing to count.
    #
    @property
    def measured(self) -> bool:
        """Whether there is a window at all, as opposed to one that is empty.

        A pool with no samples has not been observed; a pool with samples and
        no traffic has. The page says different things about them, and the
        difference is the one this whole table exists to keep.
        """

        return self.intervals > 0


def spark_ticks(
    *, start: datetime, end: datetime, fmt: str, count: int = SPARK_TICKS
) -> list[tuple[float, str]]:
    """Where the line sits in time, as evenly spaced labels across the window.

    Without these the shape is unlocatable: a reader can see that something
    happened but not whether it was ten days ago or twenty, which is the
    question a month-long window is opened to answer.

    Computed from the window rather than from the readings. They used to name
    moments that had been measured, which meant a 30-day view holding one day
    of samples labelled both its ends with the same date - honest about the
    data and misleading about the axis, now that the axis is the window. The
    labels are the scale; where the readings start is shown by where the line
    starts.
    """

    if count < 2 or end <= start:
        return []
    seconds = (end - start).total_seconds()
    ticks: list[tuple[float, str]] = []
    for index in range(count):
        share = index / (count - 1)
        at = start + timedelta(seconds=seconds * share)
        ticks.append((share * 100, at.strftime(fmt)))
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
    backend: str,
    samples: Sequence[Sample],
    *,
    tick_format: str = "%H:%M",
    start: datetime,
    end: datetime,
    bucket: timedelta,
) -> PoolTraffic:
    """One pool's card, drawn across the window that was asked for.

    The window is given rather than derived from the samples. What the card
    shows is "the last 30 days", and a view that quietly redrew itself as "the
    last day, stretched" would answer a question nobody asked - and would make
    two windows of the same pool incomparable, which is the whole use of them.
    """

    found = intervals(samples)
    totals = tuple(totalled(found, name, label) for name, label in CARD_COUNTERS)
    paths, points, peak = spark(
        found,
        width=SPARK_WIDTH,
        height=SPARK_HEIGHT,
        start=start,
        end=end,
        bucket=bucket,
    )
    buckets = max((end - start) / bucket, 1) if bucket else 1
    return PoolTraffic(
        backend=backend,
        intervals=len(found),
        started_at=found[0].started_at if found else None,
        ended_at=found[-1].ended_at if found else None,
        totals=totals,
        paths=tuple(paths),
        points=tuple(points),
        hit_width=SPARK_WIDTH / buckets,
        ticks=tuple(spark_ticks(start=start, end=end, fmt=tick_format)),
        levels=levels_for(ceiling_for(peak), height=SPARK_HEIGHT),
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
