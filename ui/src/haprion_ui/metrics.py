"""One status reading, turned into the rows that are kept.

The cache and the samples answer different questions from the same read.
`cluster_status` holds what is true now and is replaced every poll; these rows
hold what was true then and are never updated. So the poller writes both from
one reading rather than asking the nodes twice.

Read out of the stored status document rather than through `parse_status`, for
the reason `health.backend_health` gives: a poll that reached one node of two
still carries the node that answered, and `parse_status` refuses an envelope it
cannot fully believe. A pass that recorded nothing whenever one node was
unreachable would lose the half of the cluster that is fine, on exactly the
days the samples are worth having.
"""

from __future__ import annotations

import math
import re
from collections.abc import Mapping, Sequence
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlencode
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from haprion.generate import (
    METRICS_FRONTEND,
    PREFIX,
    WAF_BACKEND,
    backend_name,
    runtime_backends,
)
from haprion.guid import redirect_suffixes
from haprion.proxy_model import Proxy

#
# HAProxy's own `show stat` column names. The same list appears in
# `install/node/haprion-node-status`, which reads them, and in migration 0018,
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

#
# dnsdist's counters for a dns pool (Fas 19a B4), kept in the backend rows
# beside HAProxy's: on the pool's own row every query reaching its listener,
# those over TCP, those refused for `allow_from` and those its servers
# answered; on a server's row its queries and answers. Migration 0057 stores
# them, and the node reports them under the names in `DNS_POOL` and
# `DNS_SERVER`.
#
DNS_COUNTERS: tuple[str, ...] = ("dns_queries", "dns_tcp", "dns_refused", "dns_answered")
DNS_POOL = {
    "queries": "dns_queries",
    "tcp_queries": "dns_tcp",
    "refused": "dns_refused",
    "answered": "dns_answered",
}
#
# No latency (B253, 26-10-06): dnsdist's is a running average that starts at
# nought at every start, and nothing here drew it. Prometheus reads dnsdist.
#
DNS_SERVER = {"queries": "dns_queries", "answered": "dns_answered"}
#
# IPVS's counters for a syslog pool (Fas 19b B3), in the same rows: the virtual
# server's on the pool's own row, each receiver's on its own. One message is
# one datagram (`ops`), so packets in are messages. Migration 0061 stores them,
# and the node reports them as `packets` and `bytes`.
#
SYSLOG_COUNTERS: tuple[str, ...] = ("syslog_messages", "syslog_bytes")
SYSLOG_ROW = {"packets": "syslog_messages", "bytes": "syslog_bytes"}
#
# Every counter a series is drawn and summed from.
#
SERIES_COUNTERS: tuple[str, ...] = (*METRIC_COUNTERS, *DNS_COUNTERS, *SYSLOG_COUNTERS)
#
# What a pool's own row is called, HAProxy's word for it, which a dns pool's
# row borrows so the two are read alike.
#
POOL_ROW = "BACKEND"


@dataclass(frozen=True, slots=True)
class FrontendSample:
    node: str
    frontend: str
    owns_vip: bool | None
    uptime_sec: int | None
    status: str | None
    counters: Mapping[str, int] = field(default_factory=dict)
    counters_kept: bool | None = None


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
    counters_kept: bool | None = None


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


def samples(result: Mapping[str, Any]) -> tuple[list[FrontendSample], list[MemberSample]]:
    """What one status reading is worth keeping, split the way B94 splits it.

    **Frontends come from every node.** A standby's `req_tot` of zero is a real
    measurement and the expected one; a standby whose frontend counted anything
    at all is traffic arriving at a node that does not hold the address, which
    is worth being able to see afterwards.

    **Backend members come only from the node that holds the VIP.** The generated
    backend carries `source <the VIP's address>`, that address is held by the
    keepalived master, and the standby's health check is answered to whoever
    holds it. Its `DOWN` is not a measurement of the backend, so storing it
    would be storing `down` every minute about a server that is up.

    A node whose ownership is unknown contributes no member rows either. Not
    knowing who held the address is precisely not knowing whether the verdict
    means anything, and a row that cannot be attributed is worse than no row.
    """

    frontends: list[FrontendSample] = []
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
        #
        # Whether HAProxy keeps this node's counters across a reload (N3): its
        # uptime starts again either way, and this says whether the counters
        # did. A pool's own row never does - backends carry no GUID while
        # HAProxy cannot carry them (`guid.py`) - so it is false there.
        #
        shared = runtime.get("shared_counters") if isinstance(runtime, Mapping) else None
        kept = shared if isinstance(shared, bool) else None

        for row in _entries(status.get("frontends")):
            if not isinstance(row, Mapping):
                continue
            frontend = _text(row.get("frontend"))
            if frontend is None:
                continue
            frontends.append(
                FrontendSample(
                    node=node,
                    frontend=frontend,
                    owns_vip=owns_vip,
                    uptime_sec=uptime,
                    status=_text(row.get("status")),
                    counters=_counters(row.get("counters")),
                    counters_kept=kept,
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
                    counters_kept=False if kept is not None and member == POOL_ROW else kept,
                )
            )

        members.extend(_dns_samples(node, status.get("dns_listener")))
        members.extend(_syslog_samples(node, status.get("ipvs")))

    return frontends, members


def _dns_samples(node: str, listener: object) -> list[MemberSample]:
    """A node's dns pools and servers as backend rows (Fas 19a B4).

    The holder's only, as for HAProxy, which `samples` has already decided:
    the standby's dnsdist binds the same address and is asked nothing. The
    uptime is dnsdist's own, because it restarts whenever its configuration
    changes and HAProxy does not.
    """

    counted = listener.get("counters") if isinstance(listener, Mapping) else None
    if not isinstance(counted, Mapping):
        return []
    uptime = _count(counted.get("uptime_sec"))
    found: list[MemberSample] = []
    for row in _entries(counted.get("pools")):
        pool = _text(row.get("pool")) if isinstance(row, Mapping) else None
        if pool is None:
            continue
        found.append(
            MemberSample(
                node=node,
                backend=pool,
                member=POOL_ROW,
                uptime_sec=uptime,
                status=None,
                check_status=None,
                check_code=None,
                counters=_renamed(row, DNS_POOL),
            )
        )
    for row in _entries(counted.get("servers")):
        if not isinstance(row, Mapping):
            continue
        pool, server = _text(row.get("pool")), _text(row.get("server"))
        if pool is None or server is None or server == POOL_ROW:
            continue
        found.append(
            MemberSample(
                node=node,
                backend=pool,
                member=server,
                uptime_sec=uptime,
                status=_text(row.get("status")),
                check_status=None,
                check_code=None,
                counters=_renamed(row, DNS_SERVER),
            )
        )
    return found


def _syslog_samples(node: str, ipvs: object) -> list[MemberSample]:
    """A node's syslog pools and receivers as backend rows (Fas 19b B3).

    The holder's only, as `samples` has decided: messages reach the node that
    carries the address, and the standby's table counts nothing. Only the
    virtual servers the node's installed file names - a pool and `s1`, `s2`...
    as the generator wrote them - since a row has to say whose pool it is.

    No uptime: IPVS reports none. A receiver keepalived put back counts from
    nought, and 0048's rule leaves the interval it fell in without a figure.
    A receiver it took out is DOWN with no counters, which is a state and not a
    count of none.
    """

    services = ipvs.get("services") if isinstance(ipvs, Mapping) else None
    found: list[MemberSample] = []
    for service in _entries(services):
        if not isinstance(service, Mapping) or service.get("protocol") != "udp":
            continue
        pool = _text(service.get("pool"))
        if pool is None:
            continue
        found.append(
            MemberSample(
                node=node,
                backend=pool,
                member=POOL_ROW,
                uptime_sec=None,
                status=None,
                check_status=None,
                check_code=None,
                counters=_renamed(service, SYSLOG_ROW),
            )
        )
        for receiver in _entries(service.get("receivers")):
            if not isinstance(receiver, Mapping):
                continue
            server = _text(receiver.get("server"))
            if server is None or server == POOL_ROW:
                continue
            found.append(
                MemberSample(
                    node=node,
                    backend=pool,
                    member=server,
                    uptime_sec=None,
                    status=_text(receiver.get("status")),
                    check_status=None,
                    check_code=None,
                    counters=_renamed(receiver, SYSLOG_ROW),
                )
            )
    return found


def _renamed(row: Mapping[str, Any], names: Mapping[str, str]) -> dict[str, int]:
    """The node's figures under the columns that keep them; unreported ones left out."""

    found = {}
    for reported, column in names.items():
        number = _count(row.get(reported))
        if number is not None and number >= 0:
            found[column] = number
    return found


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
    # Which node counted it. Backend members are stored only from the node holding
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

    **A restart loses what came before it and nothing after.** The process that
    counted the earlier events is gone; the one that replaced it started at
    zero, so its own counters are exactly the traffic since it started - a
    measurement, not an estimate. That part is counted, and only the remainder
    of the interval is unknown.

    This used to report the whole interval as `None`, and how much that threw
    away depended on the bucket: a minute on the hour view, six hours on the
    month view. The same reload therefore subtracted six hours of traffic from
    the month and a minute from the hour, so the longer window showed the
    smaller number - which is not a coverage note, it is two answers to one
    question. Measured on the live cluster 2026-09-06: 31 381 requests over 24
    hours and 18 702 over 30 days, from one reload each window shared.

    The interval is still marked `restarted`, because part of it is still
    unaccounted for and the reader is owed that. What changed is that the part
    that was measured is no longer discarded with it.

    **A difference is only ever taken between two readings by the same node.**
    Backend members are recorded from the node holding the VIP, so a failover
    hands the series to a machine that has been up longer than the one it
    replaced - higher uptime and higher counters, which is exactly what a
    healthy interval looks like. Subtracting across it would report the
    incoming node's lifetime total as this interval's traffic. Pairing inside
    each node's own series is what makes that impossible rather than something
    to detect afterwards, and it is why `handed_over` is no longer set: there
    is no pair for it to describe.

    Samples that predate the node being carried have `node` as `None`. They
    form one series among themselves, which is the behaviour a reader of older
    rows had.
    """

    #
    # Paired within each node's own series, never across two of them.
    #
    # The samples arrive as one list because they are one backend's history,
    # but they are written by whichever node is holding the address, and two
    # nodes' cumulative counters are two processes' lifetimes. Ordering them
    # together by time and pairing neighbours therefore invented a difference
    # at every point the author changed - refused as `handed_over`, which cost
    # the whole interval either side of it.
    #
    # What that cost in practice, measured on the live cluster 2026-09-06: the
    # standby node wrote four samples inside one hour in which the active node
    # wrote 648. On the 7-day view a bucket keeps one reading per node, so that
    # hour became active 16:59 -> standby 17:34 -> active 17:59, two refused
    # differences spanning the whole hour, and the card said 1 % of it could be
    # measured. On the 30-day view the same four rows would take six hours.
    #
    # Paired per node the stray rows form no pair at all - a lone sample is not
    # an interval - and the active node's series runs through the hour
    # unbroken. A real failover is not lost either: the outgoing node's
    # intervals end where its samples stop, the incoming node's begin where its
    # own start, and the stretch between them is time nobody observed. It is
    # the one thing no arithmetic recovers, and it is now measured as the
    # seconds it actually was rather than as the two buckets that happened to
    # touch it.
    #
    series: dict[str, list[Sample]] = {}
    for sample in samples:
        series.setdefault(sample.node or "", []).append(sample)

    found: list[Interval] = []
    pairs: list[tuple[Sample, Sample]] = []
    for readings in series.values():
        readings.sort(key=lambda sample: sample.observed_at)
        pairs.extend(zip(readings, readings[1:], strict=False))
    pairs.sort(key=lambda pair: (pair[1].observed_at, pair[1].node or ""))

    for earlier, later in pairs:
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
        for name in SERIES_COUNTERS:
            before = earlier.counters.get(name)
            after = later.counters.get(name)
            if handed_over or before is None or after is None:
                #
                # A handover is the case no arithmetic reaches: neither node
                # observed what happened between the last reading of one and
                # the first of the other, and the incoming node's totals are
                # its own lifetime rather than this interval's.
                #
                counters[name] = None
            elif restarted:
                #
                # What the process that is running now has counted since it
                # started, which began inside this interval. The rest of the
                # interval belonged to a process that is gone.
                #
                counters[name] = after
            elif after < before:
                #
                # A counter that fell with no restart to explain it. Reporting
                # a busy minute as a quiet one is the one outcome worse than
                # reporting nothing.
                #
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
    found.extend(_handovers(series))
    found.sort(key=lambda interval: (interval.ended_at, interval.started_at))
    return found


def _handovers(series: Mapping[str, Sequence[Sample]]) -> list[Interval]:
    """The unobserved stretch between one node's last reading and the next's.

    A failover is real and it costs real time: the outgoing node stopped
    reporting, the incoming one had not begun, and nobody counted what happened
    in between. That stretch is an interval with no counters - it is exactly as
    long as it was, rather than as long as the buckets that touch it.

    **Only between series that do not overlap.** A node that reports a handful
    of rows while another is reporting throughout has not taken anything over;
    the address never moved, and treating those rows as a handover is what cost
    a whole hour on the live cluster. Overlapping series say the two were
    reporting at the same time, and no time was lost between them.
    """

    spans = sorted(
        (
            min(reading.observed_at for reading in readings),
            max(reading.observed_at for reading in readings),
        )
        for readings in series.values()
        if readings
    )
    handovers: list[Interval] = []
    for (_, earlier_end), (later_start, _) in zip(spans, spans[1:], strict=False):
        if later_start <= earlier_end:
            continue
        handovers.append(
            Interval(
                started_at=earlier_end,
                ended_at=later_start,
                counters=dict.fromkeys(SERIES_COUNTERS),
                restarted=False,
                handed_over=True,
            )
        )
    return handovers


@dataclass(frozen=True, slots=True)
class Total:
    """One counter summed over a window, and whether any of it could be counted.

    **The figure is printed without a coverage mark.** It used to carry a star
    and "Counted over N% of the window" whenever restarts or a change of node
    cut into it. The counters are cumulative, so a missed poll costs nothing
    and a reload only the seconds between the last poll and the reload - and
    the share was taken against the summed intervals rather than the window,
    so a node taking the address back after days added those days twice. A
    7-day card on internal said 64 % with every request counted (measured
    2026-10-06). The mark cost the reader more than the seconds it stood for,
    and was removed on the maintainer's call.
    """

    label: str
    value: int
    counted_sec: float
    span_sec: float

    @property
    def shown(self) -> str:
        """The figure as the card prints it, shortened only when it has to be.

        Nine digits are printed in full, because the reserved column is nine
        wide and a figure that fits is always better read exactly - the answer
        to "how many requests" is the number, not an approximation of it.

        Past that the column would have to grow, and a column that grows is the
        text moving under the reader again. So a billion becomes `1.23 B`: the
        magnitude is what anyone reads at that size anyway, and the exact
        figure is a hover away in the note row rather than gone.

        `B` and `T` for the short scale, which is what English-language
        interfaces and HAProxy's own documentation use.
        """

        if self.value < 1_000_000_000:
            return str(self.value)
        for limit, suffix in ((1_000_000_000_000, "B"), (1_000_000_000_000_000, "T")):
            if self.value < limit:
                return f"{self.value / (limit // 1000):.2f} {suffix}"
        return f"{self.value / 1_000_000_000_000_000:.2f} Q"

    @property
    def shortened(self) -> bool:
        """Whether `shown` is an approximation the exact figure belongs beside."""

        return self.value >= 1_000_000_000

    @property
    def known(self) -> bool:
        """Whether any of the window could be counted at all.

        Nothing counted is not nought traffic. A window whose every interval
        was refused - one reading each from two nodes, and nothing in between -
        has a sum of zero because there was nothing to add, and printing that
        as `0` would be a measurement nobody made.
        """

        return self.counted_sec > 0 or self.span_sec <= 0


def totalled(found: Sequence[Interval], name: str, label: str = "") -> Total:
    """One counter summed over a run of intervals.

    What was measured goes into the value, including the traffic a new process
    counted since a restart. The time counted is what `Total.known` reads: a
    window none of whose intervals could be differenced has no figure, not a
    zero. A change of node contributes to neither.
    """

    value = 0
    counted = 0.0
    span = 0.0
    for interval in found:
        span += interval.seconds
        amount = interval.counters.get(name)
        if amount is not None:
            value += amount
        if amount is not None and not interval.restarted and not interval.handed_over:
            counted += interval.seconds
    return Total(label=label, value=value, counted_sec=counted, span_sec=span)


#
# The ceilings a line may be scaled to, per power of ten. Round numbers a
# reader recognises without doing arithmetic, and all even, so the halfway
# gridline is a whole number too - `40` above `80` reads at a glance where
# `37` above `74` reads as a measurement of something.
#
# 1 is here so that a peak already on a round number keeps it - a backend topping
# out at exactly 10 should be drawn against 10, not against 20 with a third of
# the card left empty. `MIN_CEILING` is what stops that from also giving a backend
# that peaked at one request a midpoint of half a request.
#
CEILING_STEPS: tuple[int, ...] = (1, 2, 3, 4, 5, 6, 8, 10)
MIN_CEILING = 2


def ceiling_for(peak: int) -> int:
    """The round number a line is drawn against, at or above its peak.

    **Not the peak itself, which is what it used to be.** A line scaled to its
    own maximum touches the top of the card whatever it measures, so a backend
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
    # The bucket's start as whole seconds, which is what a link to it is
    # written with. Seconds rather than a formatted time: the value travels in
    # a query string and comes back parsed, and every format that reads nicely
    # in a URL is also one that a zone or a locale can change the meaning of.
    #
    stamp: int = 0
    #
    # Whether this bucket falls inside the range the reader has marked.
    #
    selected: bool = False
    #
    # The same figures the hover text says, kept apart so the card's own figure
    # row can be written with them without parsing a sentence. `None` is a
    # counter this bucket could not measure, which the row prints rather than
    # skips.
    #
    figures: tuple[tuple[str, int | None], ...] = ()
    #
    # The bucket's moment, written the way the card writes every other one.
    # The hover sentence carries it too, but the figure row needs it on its
    # own and should not have to cut it back out of a sentence.
    #
    moment: str = ""
    #
    # What qualifies the figures, where anything does: a gap, or an hour
    # nobody sampled. Empty when the bucket has figures.
    #
    note: str = ""


#
# The grid every bucket is measured from, and it must be an absolute moment
# rather than the window's own start.
#
# The reader's SQL bins rows with `date_bin(width, observed_at, '2000-01-01
# 00:00:00+00')` (`db.BUCKET_EPOCH_SQL`), which is a fixed grid - in UTC, as
# this one is; a bare date is read in the server's time zone. A drawing that binned the same readings from `now -
# span` would use a grid that moves every time the page is loaded, and the two
# would sit a fraction of a bucket apart: some buckets would hold two readings
# and their neighbours none, which draws a sawtooth down to zero - and a
# different sawtooth on every refresh. It did, for one release.
#
BUCKET_EPOCH = datetime(2000, 1, 1, tzinfo=UTC)


def _bucket_of(at: datetime, bucket: timedelta) -> int:
    return int((at - BUCKET_EPOCH) / bucket)


#
# How much of a bucket must be measured before it is drawn at all.
#
# A bucket used to be all or nothing: one interval that could not be
# differenced - a ten-second reload, a failover - made every counter unknown
# for every bucket that interval touched, so the 7-day view drew a two-hour
# hole for ten seconds of downtime. A gap in a time axis that is twelve
# hundred times wider than the thing it stands for is not a cautious reading of
# the data, it is a wrong one: the width is the only quantity a gap has.
#
# The thresholds are the ones monitoring has long settled on. RRDtool's
# `xFilesFactor` invalidates a bucket only when less than a set share of it was
# collected, and defaults to a half. Prometheus' `rate()` divides the increase
# it saw by the time it saw it and scales that to the window it was asked
# about, breaking the series only after a whole staleness period with no sample
# at all.
#
COVERAGE_DRAWN = 0.5


@dataclass(frozen=True, slots=True)
class Bucket:
    """One fixed bucket of the window, and how much of it was seen.

    Coverage is per counter rather than per bucket. A restart and a change of
    node cost every counter the same stretch, but a counter a node did not
    report costs only itself - and a bucket that answered for requests and not
    for retries should say so about retries alone.
    """

    at: datetime
    counters: Mapping[str, int | None]
    #
    # Whether any interval reached this bucket at all. A bucket nothing was
    # recorded for is a different thing from one that was watched and could
    # not be differenced, and only the second is a gap.
    #
    sampled: bool
    #
    # Per counter, the share of the bucket's own length that could be measured,
    # from 0 to 1.
    #
    covered: Mapping[str, float]


def bucketed(
    found: Sequence[Interval],
    *,
    start: datetime,
    end: datetime,
    bucket: timedelta,
) -> list[Bucket]:
    """The window as fixed buckets, each carrying what happened inside it.

    **Traffic is shared out over the time it covers, not dropped on one
    bucket.** A reading answers for the stretch since the previous one, and
    that stretch does not have to be one bucket: the poller runs on its own
    period, a poll can be late, and a long window reads hourly rollup rows into
    six-hour buckets. Attributing the whole count to the bucket the reading
    lands in leaves its neighbours at zero and draws a spike beside a hole,
    both invented. Splitting it by overlap keeps the total and puts it where
    the time was.

    **A bucket is measured over the part of it that could be differenced, and
    scaled to its whole length.** What is summed is only observed traffic; what
    it is divided by is only observed time. An hour that lost ten seconds to a
    reload is drawn from its other fifty-nine minutes and fifty seconds, which
    is a measurement of that hour rather than a guess about it - the same
    arithmetic `rate()` does, and the reason the drawn buckets stay comparable
    with each other at all. The part that was not seen is carried on the bucket
    as `covered` instead of being hidden inside the figure.

    **Below `COVERAGE_DRAWN` the counter is unknown for the bucket**, because
    at some point what was seen is too small a corner of the hour to speak for
    it. It is still never shared out as zero, which is the one value it is
    known not to be.

    **Coverage is counted against the part of the bucket the series reaches,
    not against the bucket.** A history that begins halfway through an hour
    leaves the first half unobservable rather than unmeasured: nobody was owed
    a reading there, and no amount of polling would have produced one. Counting
    it as missing would call the first and last bucket of every series a gap,
    and scaling across it would double a figure for time that does not belong
    to the series at all.

    Returns one entry per bucket in the window.
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
    bucket_sec = bucket.total_seconds()
    #
    # The stretch the series could have answered for at all, which is what
    # coverage is a share of.
    #
    reaches_from = min((interval.started_at for interval in found), default=None)
    reaches_to = max((interval.ended_at for interval in found), default=None)

    counted: dict[int, dict[str, float]] = {}
    seen: dict[int, dict[str, float]] = {}
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
            for name in SERIES_COUNTERS:
                value = interval.counters.get(name)
                if value is None:
                    #
                    # Not counted and not counted against: this stretch simply
                    # was not measured, and the bucket is answered from the
                    # stretches that were.
                    #
                    continue
                counted.setdefault(index, {})[name] = (
                    counted.setdefault(index, {}).get(name, 0.0) + value * share
                )
                seen.setdefault(index, {})[name] = (
                    seen.setdefault(index, {}).get(name, 0.0) + overlap
                )

    grid: list[Bucket] = []
    for index in range(first, last + 1):
        at = BUCKET_EPOCH + bucket * index
        measured = seen.get(index, {})
        observable = bucket_sec
        if reaches_from is not None and reaches_to is not None:
            observable = max(
                (min(reaches_to, at + bucket) - max(reaches_from, at)).total_seconds(), 0.0
            )
        totals: dict[str, int | None] = {}
        covered: dict[str, float] = {}
        for name in SERIES_COUNTERS:
            #
            # Capped at the bucket: consecutive intervals cannot overlap each
            # other, but a rounding of the last fraction of a second should not
            # be able to report more than a whole.
            #
            measured_sec = min(measured.get(name, 0.0), observable)
            share = measured_sec / observable if observable else 0.0
            covered[name] = share
            if index not in touched:
                totals[name] = 0
            elif share < COVERAGE_DRAWN:
                totals[name] = None
            else:
                totals[name] = round(
                    counted.get(index, {}).get(name, 0.0) * observable / measured_sec
                )
        grid.append(Bucket(at=at, counters=totals, sampled=index in touched, covered=covered))
    return grid


@dataclass(frozen=True, slots=True)
class Selection:
    """A stretch of the window the reader has marked off by clicking it.

    Two clicks, and the second may land before the first - a range is dragged
    out in whichever direction the eye moved, and refusing the backwards one
    would be a rule the drawing gives no sign of.

    Held in the query string rather than in the page, so a marked range can be
    reloaded, bookmarked and pasted to somebody else. Mid-incident that last
    one is the whole point: "look at these twenty minutes" is a link, not a
    description of where to click.
    """

    since: datetime | None = None
    until: datetime | None = None

    @property
    def started(self) -> bool:
        """One end marked and the other still open."""

        return self.since is not None and self.until is None

    @property
    def complete(self) -> bool:
        return self.since is not None and self.until is not None

    def counted(self, start: datetime, end: datetime) -> tuple[datetime, datetime]:
        """The stretch the figures answer for: the marks, or the whole window.

        A half-marked range is still the whole window. One click has not asked
        a question yet, and answering it with the stretch from the mark to now
        would be a figure the reader never asked for changing under the second
        click.
        """

        if self.since is None or self.until is None:
            return start, end
        return self.since, self.until

    def holds(self, at: datetime, bucket: timedelta) -> bool:
        """Whether a bucket beginning at `at` falls inside the marked range.

        The single clicked bucket counts as inside while the range is still
        open, so the first click leaves a mark rather than appearing to do
        nothing at all.
        """

        if self.since is None:
            return False
        if self.until is None:
            return self.since <= at < self.since + bucket
        return self.since <= at < self.until


def selection(
    raw_since: str | None,
    raw_until: str | None,
    *,
    start: datetime,
    end: datetime,
    bucket: timedelta,
) -> Selection:
    """The marked range a query string asks for, snapped to the drawn buckets.

    **Nonsense clears rather than fails.** These values arrive in a bookmark
    that outlived a window, from a hand-edited URL, or from a range marked on
    the hour view and reloaded on the month. A page that answered 400 to any of
    those would be answering a question of its own making; the reader asked to
    see traffic.

    **Snapped to the bucket grid**, because a bucket is the smallest thing the
    drawing can show and a range that began inside one could not be drawn where
    it claims. The end is snapped up, so a marked bucket is included whole -
    clicking one bucket twice measures that bucket, not nothing.

    The range is clamped to the window and ordered. A second click before the
    first is a range, not a mistake.
    """

    ends: list[datetime] = []
    for raw in (raw_since, raw_until):
        if raw is None:
            continue
        try:
            at = datetime.fromtimestamp(int(raw), UTC)
        except (TypeError, ValueError, OSError, OverflowError):
            return Selection()
        if not start <= at <= end:
            return Selection()
        ends.append(BUCKET_EPOCH + bucket * _bucket_of(at, bucket))
    if not ends:
        return Selection()
    if len(ends) == 1:
        return Selection(since=ends[0])
    first, last = min(ends), max(ends)
    return Selection(since=first, until=last + bucket)


def _carried(base: Mapping[str, str]) -> dict[str, str]:
    """Every query parameter except the marks themselves."""

    return {name: value for name, value in base.items() if name not in ("from", "to")}


def link_clear(base: Mapping[str, str]) -> str:
    """The same page with the marks taken off.

    The third click does this too. This is the same thing said in a place the
    reader can find without knowing that, because "click a third time" is a
    rule the drawing does not state anywhere.
    """

    query = urlencode(_carried(base))
    return f"?{query}" if query else "?"


def range_label(chosen: Selection) -> str:
    """The marked range as one line, in the reader's own clock.

    The end's date is dropped where it repeats the start's, which is the
    common case: a range is usually marked inside one afternoon, and printing
    the date twice makes the reader compare two long strings to find the one
    difference between them.
    """

    if chosen.since is None or chosen.until is None:
        return ""
    since, until = shown(chosen.since), shown(chosen.until)
    if since.date() == until.date():
        return f"{since.strftime(TIMESTAMP)} → {until.strftime('%H:%M:%S')}"
    return f"{since.strftime(TIMESTAMP)} → {until.strftime(TIMESTAMP)}"


def link_to(base: Mapping[str, str], chosen: Selection, stamp: int) -> str:
    """Where a click on one bucket leads, given what is already marked.

    Three clicks and three answers, which is the whole interaction: the first
    marks an end, the second closes the range, and the third clears it. The
    state lives in the link rather than in the page, so the same rule holds for
    a reader with script and for one without - and a browser's back button
    walks the marks back one at a time, which is what a reader expects of
    something that changed the address.

    Every other parameter is carried through. The window a range was marked in
    is part of what the range means, and a click that quietly reset it to the
    default would answer about a different stretch of time than the one under
    the pointer.
    """

    carried = _carried(base)
    if chosen.complete:
        marks: dict[str, str] = {}
    elif chosen.since is not None:
        marks = {"from": str(int(chosen.since.timestamp())), "to": str(stamp)}
    else:
        marks = {"from": str(stamp)}
    query = urlencode({**carried, **marks})
    return f"?{query}" if query else "?"


def spark(
    found: Sequence[Interval],
    *,
    width: float,
    height: float,
    start: datetime,
    end: datetime,
    bucket: timedelta,
    ceiling: int | None = None,
    chosen: Selection | None = None,
    figures: Figures | None = None,
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
    poller", so the hover says which of the two each bucket was.

    **A counter that could not be differenced is still a gap.** A restart, a
    change of node, a counter the node did not report: the line breaks there and
    the next known value starts a new run. That is deliberately not the same as
    an empty bucket. Something was measured across it and could not be turned
    into a rate, which is a narrower and more suspicious thing than a stretch
    nobody sampled.

    **Scaled to a round ceiling at or above its peak**, so the height of the
    line means something. Drawn against its own maximum it touched the top of
    the card whatever it measured, which made every window look equally busy
    and every backend look alike. A window with no traffic has no ceiling and is
    drawn flat on the baseline, which is the truth: nothing happened.

    **A caller may supply that ceiling instead**, which is how several lines
    come to share one scale. A page comparing backends is asking which of them
    carries the traffic, and that question cannot be answered from cards that
    each rescale to their own maximum: the quiet backend and the busy one draw the
    same picture. The peak returned is still this line's own, so a caller can
    tell a flat line from a flat card.
    """

    seconds = (end - start).total_seconds()
    if seconds <= 0 or bucket <= timedelta(0):
        return [], [], 0
    chosen = chosen or Selection()
    figures = figures or HTTP_FIGURES

    grid = bucketed(found, start=start, end=end, bucket=bucket)
    peak = max(
        (value for entry in grid if (value := entry.counters.get(figures.line)) is not None),
        default=0,
    )
    if ceiling is None:
        ceiling = ceiling_for(peak)

    runs: list[list[str]] = []
    current: list[str] = []
    points: list[Point] = []
    bucket_width = width * bucket.total_seconds() / seconds

    for entry in grid:
        at = entry.at
        totals = derived(entry.counters)
        measured = entry.sampled
        value = totals.get(figures.line)
        share = entry.covered.get(figures.line, 0.0)
        position = min(max((at - start).total_seconds() / seconds, 0.0), 1.0)
        x = position * width
        point_x = min(x + bucket_width / 2, width)
        if value is None:
            if current:
                runs.append(current)
            current = []
            points.append(
                Point(
                    at=at,
                    x=point_x,
                    y=height,
                    value=0,
                    reading=gap_at(at, share),
                    measured=True,
                    stamp=int(at.timestamp()),
                    selected=chosen.holds(at, bucket),
                    figures=tuple((label, None) for _name, label in figures.counters),
                    moment=shown(at).strftime(TIMESTAMP),
                    note=gap_note(share),
                )
            )
            continue
        y = height if ceiling == 0 else height - (value / ceiling) * height
        right = min(x + bucket_width, width)
        current.append(f"{'M' if not current else 'L'}{x:.1f} {y:.1f}")
        current.append(f"L{right:.1f} {y:.1f}")
        points.append(
            Point(
                at=at,
                x=point_x,
                y=y,
                value=value,
                reading=reading_at(at, totals, figures.counters) if measured else unread_at(at),
                measured=measured,
                stamp=int(at.timestamp()),
                selected=chosen.holds(at, bucket),
                figures=tuple(
                    (label, totals.get(name) if measured else None)
                    for name, label in figures.counters
                ),
                moment=shown(at).strftime(TIMESTAMP),
                note="" if measured else "No samples at this time",
            )
        )
    if current:
        runs.append(current)

    return [" ".join(run) for run in runs], points, peak


def shown(at: datetime) -> datetime:
    """One moment, in the clock the person reading it is holding.

    Every time in this module is stored and reasoned about in UTC, which is
    right, and was also what the card printed - so an operator on CEST read
    12:27 for something that happened at 14:27 and correlated it against a
    journal two hours away. A card whose times cannot be lined up against
    `journalctl` or a deploy is a card that sends people to the wrong minute.

    The host's own zone unless the reader's browser has said its own (B190):
    that zone is set for the request by `read_in`, and everything else - the
    poller, the worker, a browser that has not said yet - reads the machine's
    clock, the one `journalctl` and the timers keep.
    """

    return at.astimezone(_READER_ZONE.get())


def wall(moment: datetime) -> datetime:
    """A time without a zone, typed by the reader, placed in the reader's clock.

    The inverse of `shown`: a filter field says "14:05" and means the clock
    the page printed its times in, so it is read in the same one.
    """

    zone = _READER_ZONE.get()
    return moment.replace(tzinfo=zone) if zone is not None else moment.astimezone()


def read_in(name: str | None) -> None:
    """Show the rest of this request's times in the named zone, or the host's.

    The name comes from a cookie, so from anyone: it is held to the shape of an
    IANA name before zoneinfo sees it, and a name this host's zone data does
    not know falls back to the host's clock rather than failing the page.
    """

    zone: ZoneInfo | None = None
    if name and len(name) <= 64 and ZONE_NAME.fullmatch(name):
        try:
            zone = ZoneInfo(name)
        except (ZoneInfoNotFoundError, ValueError):
            zone = None
    _READER_ZONE.set(zone)


#
# Per request, not per process: a context variable is copied into each request's
# task and each threadpool call, so one reader's zone never reaches another's
# page. Unset means the host's zone.
#
_READER_ZONE: ContextVar[ZoneInfo | None] = ContextVar("reader_zone", default=None)
#
# Bounded parts and the length tested before it, so a hostile cookie cannot make
# the match itself the expensive step (CodeQL py/polynomial-redos, 2026-09-27).
#
ZONE_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_+-]{0,63}(?:/[A-Za-z0-9_+-]{1,63}){0,2}")


def unread_at(at: datetime) -> str:
    """What a bucket says when the line rests on the baseline without a reading.

    The line cannot make this distinction - it is drawn at zero either way, so
    that a month-long window has a month-long line - so the hover is where it
    is kept. Without it the card would answer "how much traffic at 03:00 last
    Tuesday" with a confident nothing, for an hour the poller was not running.
    """

    return f"{shown(at).strftime(TIMESTAMP)} · no reading"


def gap_at(at: datetime, covered: float = 0.0) -> str:
    """Name a bucket whose request count could not be measured.

    A bucket reaches this only when too little of it was seen to answer for it,
    so the share that *was* seen is the reader's next question - "nothing at
    all" and "a fifth of it, which is not enough" send an operator to different
    places.
    """

    when = shown(at).strftime(TIMESTAMP)
    if covered <= 0:
        return f"{when} · data gap"
    return f"{when} · data gap · only {round(covered * 100)}% of it was measured"


def gap_note(covered: float) -> str:
    """Why a marked-off gap has no figures, in the card's own row."""

    if covered <= 0:
        return "Nothing measured in this bucket"
    return f"Only {round(covered * 100)}% measured, not shown"


def reading_at(
    at: datetime,
    totals: Mapping[str, int | None],
    counters: tuple[tuple[str, str], ...] | None = None,
) -> str:
    """What one bucket says when the pointer rests on it.

    Every figure the card carries, not only the one the line draws, because the
    question a spike raises is usually about a different counter than the one
    that showed it - a rise in requests is asked about together with what
    answered them.

    A counter that could not be measured says so rather than being left out.
    Absent from the list it would read as zero, which is the one thing it is
    not known to be.
    """

    when = shown(at).strftime(TIMESTAMP)
    parts = [
        f"{label} {value if (value := totals.get(name)) is not None else 'not measured'}"
        for name, label in (counters or CARD_COUNTERS)
    ]
    return f"{when} · " + " · ".join(parts)


#
# What the object page shows, and why these and not the other fourteen. Each
# answers a question somebody actually arrives with: did anything reach this
# backend, did it answer, did it refuse, could it be reached at all, and did it
# have to try twice. The rest are kept in the table for the day a question
# needs them - a card that shows everything answers nothing.
#
CARD_COUNTERS: tuple[tuple[str, str], ...] = (
    ("req_tot", "Requests"),
    ("hrsp_2xx", "2xx"),
    ("hrsp_3xx", "3xx"),
    ("hrsp_4xx", "4xx"),
    ("hrsp_5xx", "5xx"),
    ("econ", "Connection errors"),
    ("wretr", "Retries"),
)

#
# The dashboard's traffic row: what every VIP carried, summed. Bytes in and out
# rather than errors, because the row answers "how much is flowing", and the
# per-backend questions stay on the cards that can name a backend.
#
SUMMARY_COUNTERS: tuple[tuple[str, str], ...] = (
    ("req_tot", "Requests"),
    ("bin", "Bytes in"),
    ("bout", "Bytes out"),
)

#
# A dns object's card (Fas 19a B4, chosen 26-10-06): what its listener was
# asked, what its servers answered, what `allow_from` refused, what got no
# answer at all, and how much came over TCP. No response codes: dnsdist 2.1
# counts those for the whole process, not per pool.
#
# Unanswered is worked out rather than stored - asked, less refused, less
# answered - so it includes queries no server was up to take, which a
# server's own count of timeouts would miss.
#
DNS_UNANSWERED = "dns_unanswered"
DNS_CARD_COUNTERS: tuple[tuple[str, str], ...] = (
    ("dns_queries", "Queries"),
    ("dns_answered", "Answered"),
    ("dns_refused", "Refused"),
    (DNS_UNANSWERED, "Unanswered"),
    ("dns_tcp", "Over TCP"),
)
#
# The ones summed from the stored differences, in the order a reader returns them.
#
DNS_SUMMED: tuple[tuple[str, str], ...] = tuple(
    (name, label) for name, label in DNS_CARD_COUNTERS if name != DNS_UNANSWERED
)


@dataclass(frozen=True, slots=True)
class Figures:
    """What one kind of card draws: the counter its line follows and its figures."""

    line: str
    counters: tuple[tuple[str, str], ...]
    rate: str


#
# A syslog object's card (Fas 19b B3): what arrived, in messages and bytes.
# Nothing is refused or answered - IPVS forwards every datagram that reaches
# the address - so there is nothing else to count.
#
SYSLOG_CARD_COUNTERS: tuple[tuple[str, str], ...] = (
    ("syslog_messages", "Messages"),
    ("syslog_bytes", "Bytes"),
)

HTTP_FIGURES = Figures(line="req_tot", counters=CARD_COUNTERS, rate="Requests")
DNS_FIGURES = Figures(line="dns_queries", counters=DNS_CARD_COUNTERS, rate="Queries")
SYSLOG_FIGURES = Figures(line="syslog_messages", counters=SYSLOG_CARD_COUNTERS, rate="Messages")


def _unanswered(asked: int | None, *answered: int | None) -> int | None:
    if asked is None or any(part is None for part in answered):
        return None
    return max(asked - sum(part for part in answered if part is not None), 0)


def derived(counters: Mapping[str, int | None]) -> Mapping[str, int | None]:
    """A bucket's counters with what is worked out from them added.

    Floored at zero: an answer that arrives in the next bucket leaves its
    question unanswered in this one for a moment, and a negative count would be
    a reading nobody made.
    """

    if "dns_queries" not in counters:
        return counters
    return {
        **counters,
        DNS_UNANSWERED: _unanswered(
            counters.get("dns_queries"), counters.get("dns_refused"), counters.get("dns_answered")
        ),
    }


def dns_measurement(found: BackendMeasurement) -> BackendMeasurement:
    """A dns pool's summed figures (`DNS_SUMMED`) in the card's order, Unanswered added.

    Unanswered is known only as far as all three it is worked out from are.
    """

    summed = dict(zip((name for name, _label in DNS_SUMMED), found.totals, strict=True))
    parts = [summed["dns_queries"], summed["dns_refused"], summed["dns_answered"]]
    asked, refused, answered = parts
    missing = Total(
        label="Unanswered",
        value=max(asked.value - refused.value - answered.value, 0),
        counted_sec=min(part.counted_sec for part in parts),
        span_sec=asked.span_sec,
    )
    summed[DNS_UNANSWERED] = missing
    return BackendMeasurement(
        intervals=found.intervals,
        started_at=found.started_at,
        ended_at=found.ended_at,
        totals=tuple(summed[name] for name, _label in DNS_CARD_COUNTERS),
        restarted=found.restarted,
        handed_over=found.handed_over,
    )


def summed(figures: Figures) -> tuple[tuple[str, str], ...]:
    """The counters a card's figures are read from: a dns card's Unanswered is worked out."""

    return DNS_SUMMED if figures is DNS_FIGURES else figures.counters


def measured(figures: Figures, found: BackendMeasurement) -> BackendMeasurement:
    """What was read from `summed(figures)`, as the card shows it."""

    return dns_measurement(found) if figures is DNS_FIGURES else found


@dataclass(frozen=True, slots=True)
class BackendMeasurement:
    """One window measured independently of how its line is drawn.

    A line needs tens of buckets; a cumulative counter needs every retained
    reading.  Keeping those two products separate is what makes changing the
    window's drawing resolution unable to change the figures beside it.
    """

    intervals: int
    started_at: datetime | None
    ended_at: datetime | None
    totals: tuple[Total, ...]
    restarted: bool
    handed_over: bool


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
class BackendTraffic:
    """One series' window, ready to draw.

    Named by the runtime's own name for it, which is the only name that exists
    for a proxy nobody wrote here. A backend and a frontend are drawn by the same
    arithmetic against the same axis, so they are one type: the difference
    between them is which table the readings came out of, and that difference
    is spent by the time a card exists.
    """

    series: str
    intervals: int
    started_at: datetime | None
    ended_at: datetime | None
    #
    # One `Total` per `CARD_COUNTERS` entry, in that order.
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
    #
    # How many intervals the drawing was built from, as opposed to `intervals`,
    # which counts what the figures were measured from. See `measured`.
    #
    drawn_intervals: int = 0
    handed_over: bool = False
    #
    # What the line counts, for the heading beside the rate unit.
    #
    rate: str = "Requests"

    #
    # There was a `quiet` property here, and the sentence it turned on -
    # "nothing reached this backend in the last hour" - was removed on the
    # maintainer's call. A row of zeros beside a flat line already says it, and
    # saying it a third time in prose is what made the card wordy. The figures
    # and the line are the reading; `measured` still separates a window that
    # counted nothing from one that has nothing to count.
    #
    @property
    def measured(self) -> bool:
        """Whether there is a window at all, as opposed to one that is empty.

        A backend with no samples has not been observed; a backend with samples and
        no traffic has. The page says different things about them, and the
        difference is the one this whole table exists to keep.

        Either count answers it. The figures may have been measured over a
        marked range that holds nothing while the window around it holds a
        week - the card still has a line to draw, and the empty figures say the
        rest.
        """

        return self.intervals > 0 or self.drawn_intervals > 0


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
        ticks.append((share * 100, shown(at).strftime(fmt)))
    return ticks


#
# What the generator puts in front of every name it writes. Taken from the
# engine rather than spelled again here: the interface reads these names out of
# the metrics tables, where they are strings by then, but the rule that made
# them belongs to one module and a second copy is a second thing to change.
#
GENERATED_PREFIX = f"{PREFIX}-"

#
# The protocols a VIP frontend is built for, longest first so `https` is not
# matched as `http` with a stray `s`.
#
LISTENER_PROTOCOLS = ("https", "http")

#
# A generated redirect answer as it was named until 2026-10-05: eight hex
# characters derived from the route. Recognised by shape only where no object
# accounts for the name - a redirect whose object is gone; the names since then
# are named from paths and recognised through the objects (`redirect_targets`).
#
REDIRECT_SUFFIX = re.compile(r"-redirect-[0-9a-f]{8}$")


@dataclass(frozen=True, slots=True)
class Listening:
    """A VIP frontend's name, read back into the two facts it was built from.

    The generator writes `mgd-<vip>-<protocol>`, so the name on a metrics row
    carries a VIP the network page already names and a protocol that belongs
    beside it rather than inside it. Printing the raw name made a reader match
    `mgd-vip-int-http` against `vip-int` by eye, which is a translation the
    page should be doing.

    A name that does not fit the rule is kept whole and its protocol left
    empty. The rule is the generator's and could change; guessing at a name
    that does not match it would rename somebody's frontend on screen.
    """

    vip: str
    protocol: str
    port: int | None = None
    """A tcp frontend's port: one frontend per raw port, `mgd-<vip>-tcp-<port>`."""

    @property
    def known(self) -> bool:
        return bool(self.protocol)


def listening(frontend: str) -> Listening:
    """`mgd-vip-int-http` as the VIP `vip-int` serving `http`; `-tcp-5432` as tcp on 5432."""

    name = frontend.removeprefix(GENERATED_PREFIX)
    vip, _, port = name.rpartition("-tcp-")
    if vip and port.isdigit():
        return Listening(vip=vip, protocol="tcp", port=int(port))
    for protocol in LISTENER_PROTOCOLS:
        if name.endswith(f"-{protocol}"):
            return Listening(vip=name[: -len(protocol) - 1], protocol=protocol)
    return Listening(vip=frontend, protocol="")


def is_exporter(frontend: str) -> bool:
    """The metrics exporter's own frontend (Fas 15), which no site is served on.

    It listens for the monitoring system's scrapes. On a page of what arrived at
    each address it would be a card of somebody's poll interval, and in the
    dashboard's traffic it would count those polls as visitors.
    """

    return frontend == METRICS_FRONTEND


def is_engine(backend: str) -> bool:
    """The WAF engine's backend (Fas 21), which no site is served from.

    The generator writes it on every cluster with the engine, so HAProxy can
    hand requests to the engine for a verdict. Its requests are those hand-offs
    rather than visitors, and on a page of what each backend served it would be
    a card of the WAF counting itself - the exporter's frontend for the same
    reason (`is_exporter`). Shown unintentionally until 2026-10-04.
    """

    return backend == WAF_BACKEND


def is_redirect(backend: str) -> bool:
    """Whether a name no object accounts for has the shape of a redirect answer.

    It carries counters like any backend and belongs on the page, but not in a
    comparison of backends: it has no servers, it answers 301 itself, and letting
    it into the shared scale would size every real backend against traffic that
    never reached one. Names an object accounts for are told apart by
    `backend_targets` instead.
    """

    return bool(REDIRECT_SUFFIX.search(backend))


@dataclass(frozen=True, slots=True)
class BackendTarget:
    """One generated backend, as a reader should see it.

    `current` is the name the generator gives it.
    """

    label: str
    current: str
    redirect: bool = False


def backend_targets(objects: Mapping[str, Proxy]) -> dict[str, BackendTarget]:
    """Every backend the objects produce, under the name the generator gives it.

    Resolved by building rather than by parsing: every pool and every route
    that redirects is asked what the generator calls it, and the answer is
    compared with the name the metrics row carries. So no name is split on a hyphen that might belong to somebody's
    object, and a name nothing accounts for is simply left alone.

    A pool is labelled by its own name, which is also what HAProxy and a
    dashboard call it; a redirect by what it does.
    """

    found: dict[str, BackendTarget] = {}
    for name, proxy in objects.items():
        for pool in proxy.backends:
            current = backend_name(proxy, pool)
            target = BackendTarget(label=current, current=current)
            found[current] = target
        suffixes = redirect_suffixes(proxy)
        for route in proxy.routes:
            redirect = route.redirect
            if redirect is None:
                continue
            suffix = suffixes[(route.path, route.match)]
            current = backend_name(proxy, suffix)
            target = BackendTarget(
                label=f"{name} · {route.path} → {redirect.location}",
                current=current,
                redirect=True,
            )
            found[current] = target
    return found


def renamed_backends(before: Proxy | None, after: Proxy) -> tuple[dict[str, str], list[str]]:
    """What a publish of `after` renames, old name to new, and the names it brings into use.

    A pool is renamed when exactly one pool goes and one comes: the operator
    changed the name and kept the backend. Two or more at once cannot be paired
    without guessing, and a guess would draw one backend's history under
    another's name, so they are not. A redirect is the same route when its
    path and match are, and is renamed when its name changed with its object's.

    The names in use afterwards that were not before are returned as well, so a
    name given out again stops counting for the backend that once had it.
    """

    introduced = sorted(
        set(runtime_backends(after)) - set(runtime_backends(before) if before else ())
    )
    if before is None:
        return {}, introduced
    renamed: dict[str, str] = {}
    gone = sorted(set(before.backends) - set(after.backends))
    came = sorted(set(after.backends) - set(before.backends))
    pairs: list[tuple[str, str]] = []
    if len(gone) == 1 and len(came) == 1:
        pairs.append((gone[0], came[0]))
    then, now = redirect_suffixes(before), redirect_suffixes(after)
    pairs += [(then[route], suffix) for route, suffix in now.items() if route in then]
    for old, new in pairs:
        current = backend_name(after, new)
        name = backend_name(before, old)
        if name != current:
            renamed[name] = current
    return renamed, introduced


def split_backends(
    backends: Sequence[str], targets: Mapping[str, BackendTarget]
) -> tuple[list[str], list[str]]:
    """A cluster's backends as (pools, redirects), in their order.

    An older name is left out once its current name has history of its own:
    the two are one backend, and two cards for it would read as two. Until the
    change is deployed the older name is the only one, and is drawn.
    """

    seen = set(backends)
    pools: list[str] = []
    redirects: list[str] = []
    for name in backends:
        target = targets.get(name)
        if target is None:
            (redirects if is_redirect(name) else pools).append(name)
        elif target.current == name or target.current not in seen:
            (redirects if target.redirect else pools).append(name)
    return pools, redirects


def backend_label(name: str, targets: Mapping[str, BackendTarget]) -> str:
    """What a card calls a backend: its object's account of it, or the name less its prefix.

    A name no object accounts for loses only the prefix. `mgd-<object>-<backend>`
    cannot be split any further without knowing which hyphen the operator's own
    names contain, and a page that guessed would relabel a backend whenever
    somebody used a hyphen.
    """

    target = targets.get(name)
    return target.label if target else name.removeprefix(GENERATED_PREFIX)


def shared_ceiling(
    series: Sequence[Sequence[Interval]],
    *,
    start: datetime,
    end: datetime,
    bucket: timedelta,
    figures: Figures | None = None,
) -> int:
    """One round ceiling at or above every line's peak.

    The comparison view's whole claim is that two cards can be held against
    each other, and that is only true while they are drawn against the same
    scale. Measured across the buckets each line will actually be drawn at,
    not across the raw readings: a peak that two buckets share is not a peak
    the drawing ever shows, and scaling to it would leave every line sitting
    in the bottom third of its card for no visible reason.

    The cost is stated rather than hidden. A cluster with one busy backend and
    several quiet ones draws the quiet ones nearly flat - which is the honest
    picture, and the one a per-card ceiling was concealing by giving a backend
    serving three requests the same shape as one serving three thousand.
    """

    line = (figures or HTTP_FIGURES).line
    peak = 0
    for found in series:
        grid = bucketed(found, start=start, end=end, bucket=bucket)
        peak = max(
            peak,
            max(
                (value for entry in grid if (value := entry.counters.get(line)) is not None),
                default=0,
            ),
        )
    return ceiling_for(peak)


def backend_traffic(
    series: str,
    found: Sequence[Interval],
    *,
    tick_format: str = "%H:%M",
    start: datetime,
    end: datetime,
    bucket: timedelta,
    measurement: BackendMeasurement | None = None,
    ceiling: int | None = None,
    chosen: Selection | None = None,
    figures: Figures | None = None,
) -> BackendTraffic:
    """One series' card, drawn across the window that was asked for.

    The window is given rather than derived from the samples. What the card
    shows is "the last 30 days", and a view that quietly redrew itself as "the
    last day, stretched" would answer a question nobody asked - and would make
    two windows of the same backend incomparable, which is the whole use of them.
    """

    figures = figures or HTTP_FIGURES
    if measurement is None:
        counted = [
            Interval(
                started_at=interval.started_at,
                ended_at=interval.ended_at,
                counters=derived(interval.counters),
                restarted=interval.restarted,
                handed_over=interval.handed_over,
            )
            for interval in found
        ]
        measurement = BackendMeasurement(
            intervals=len(found),
            started_at=found[0].started_at if found else None,
            ended_at=found[-1].ended_at if found else None,
            totals=tuple(totalled(counted, name, label) for name, label in figures.counters),
            restarted=any(interval.restarted for interval in found),
            handed_over=any(interval.handed_over for interval in found),
        )
    paths, points, peak = spark(
        found,
        width=SPARK_WIDTH,
        height=SPARK_HEIGHT,
        start=start,
        end=end,
        bucket=bucket,
        ceiling=ceiling,
        chosen=chosen,
        figures=figures,
    )
    buckets = max((end - start) / bucket, 1) if bucket else 1
    drawn = peak if ceiling is None else ceiling
    return BackendTraffic(
        series=series,
        intervals=measurement.intervals,
        #
        # What the drawing itself has, beside what the figures were measured
        # from. The two differ whenever the figures come from SQL at stored
        # resolution - and whenever a range is marked, because the measurement
        # then answers for the marks rather than for the window. A range marked
        # over a stretch nobody sampled has no intervals at all, and reading
        # emptiness from it replaced every card on the page with "No samples
        # yet.", drawing and scale and dates included, leaving the reader to
        # guess that the marks rather than the backend had gone quiet.
        #
        drawn_intervals=len(found),
        started_at=measurement.started_at,
        ended_at=measurement.ended_at,
        totals=measurement.totals,
        paths=tuple(paths),
        points=tuple(points),
        hit_width=SPARK_WIDTH / buckets,
        ticks=tuple(spark_ticks(start=start, end=end, fmt=tick_format)),
        levels=levels_for(ceiling_for(drawn) if ceiling is None else drawn, height=SPARK_HEIGHT),
        peak=peak,
        restarted=measurement.restarted,
        handed_over=measurement.handed_over,
        rate=figures.rate,
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
    # Compact unit beside each graph's y-axis reading.
    rate_unit: str


WINDOWS: tuple[Window, ...] = (
    Window(
        "1h", "the last hour", timedelta(hours=1), timedelta(minutes=1), "%H:%M", "minute", "min"
    ),
    Window(
        "24h",
        "the last 24 hours",
        timedelta(hours=24),
        timedelta(minutes=10),
        "%H:%M",
        "10 min",
        "10 min",
    ),
    Window("7d", "the last 7 days", timedelta(days=7), timedelta(hours=1), "%a %d", "hour", "h"),
    Window(
        "30d", "the last 30 days", timedelta(days=30), timedelta(hours=6), "%d %b", "6 hours", "6 h"
    ),
)

#
# 24 hours, because the question the card is opened with is usually "is this
# normal", and an hour is too short to have a normal. The shorter window is
# still there for the middle of an incident, where the last hour is the only
# part that matters.
#
DEFAULT_WINDOW = "24h"


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
