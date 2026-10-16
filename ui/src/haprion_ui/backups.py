"""Read model for the state backups held on the nodes.

Like the other pages, this layer knows only the envelope the poller cached. It
reaches no node, and it creates nothing: taking a backup is an administrative
command, and a restore is a documented recovery procedure with a person reading
it. What the interface owes an operator is the answer to one question, on a
normal working day rather than during an incident - **is there a recent backup
on every node, and can I still see the one I would restore from.**

That is why a node with no backup at all is treated as harshly as a node that
could not be read. An empty listing looks calm - no errors, no old archives, a
row that renders fine - and it is the worst state on the page.

The archives are dated by the node's own backup run, which is a different clock
from the poll. Both ages are therefore shown: how old the newest archive is
answers whether backups are running, and how old the reading is answers whether
this page can be believed.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, time, timedelta
from typing import Any, Literal

from haprion import backup_schedule

from haprion_ui import metrics
from haprion_ui.cluster_identity import accent_index
from haprion_ui.dashboard import observation_label, relative_age
from haprion_ui.db import ClusterBackups

type Tone = Literal["healthy", "warning", "critical", "unknown"]

#
# How old the newest archive may be, judged against the cluster's own schedule
# (review 2026-09-28 F03: the limits were a daily run's, and a weekly schedule
# working as asked read as overdue by its third day).
#
# One missed run is a warning rather than an alarm - a node that was down for
# maintenance is the ordinary cause - so the warning comes half a day after the
# longest gap the schedule leaves, and a run finishing late does not light the
# page up. For a daily run that is a day and a half.
#
LATE_MARGIN = timedelta(hours=12)

#
# A week without a backup is not a late run, whatever the schedule. Whatever
# should have taken it has been failing unnoticed since, and everything
# restored from here would be a week behind the configuration the nodes are
# actually serving. A schedule with longer gaps than that turns critical once a
# second run is missed.
#
BACKUP_CRITICAL_FLOOR = timedelta(days=7)

#
# A schedule that is off, unreadable or unknown gives nothing to judge by. The
# archives are then held to a daily run's limits, which is what the schedule
# card beside them is already warning about.
#
DAILY = backup_schedule.Schedule("00:00")


@dataclass(frozen=True, slots=True)
class AgeLimits:
    warning: timedelta
    critical: timedelta


NOT_YET = "No backups yet"


def _started(schedule: Any) -> bool:
    """Whether backups were ever due: unknown counts as yes, a timer that never ran as no."""

    reported = _mapping(schedule)
    return not reported.get("unit") or _moment(reported.get("last_run")) is not None


def _age_limits(schedule: Any) -> AgeLimits:
    reported = _mapping(schedule)
    shape = None
    if reported.get("known") is True and reported.get("enabled") is True:
        shape = backup_schedule.describe(reported.get("calendar"))
    gap = (shape or DAILY).longest_gap()
    return AgeLimits(
        warning=gap + LATE_MARGIN,
        critical=max(BACKUP_CRITICAL_FLOOR, 2 * gap + LATE_MARGIN),
    )


#
# The archive list opens on this many archives per node, newest first, and
# pages back through the rest. Per node rather than per page of rows, so a
# two-node cluster shows each node's last ten runs side by side instead of one
# node's history pushing the other's off the page.
#
ARCHIVES_PER_PAGE = 10


@dataclass(frozen=True, slots=True)
class ArchiveView:
    node: str
    version: str
    taken: str
    taken_iso: str | None
    age_label: str
    size: str
    latest: bool
    # Which page of the list this archive is on: its rank on its own node,
    # newest first, divided by ARCHIVES_PER_PAGE.
    page: int


@dataclass(frozen=True, slots=True)
class NodeBackupsView:
    name: str
    label: str
    tone: Tone
    detail: str
    latest: str
    age_label: str
    count: int
    shown_count: int
    total_size: str


@dataclass(frozen=True, slots=True)
class BackupClusterView:
    cluster: str
    accent: int | None
    configured: bool
    label: str
    tone: Tone
    detail: str
    observed_at: datetime | None
    observed_iso: str | None
    age_label: str
    stale: bool
    nodes: tuple[NodeBackupsView, ...]
    archives: tuple[ArchiveView, ...]
    retained_count: int
    shown_count: int
    truncated: bool
    page_count: int
    # The most archives any one node lists, which is where the last page ends.
    deepest: int
    schedule: ScheduleView | None


@dataclass(frozen=True, slots=True)
class ScheduleView:
    """What is supposed to be taking these backups, and whether it still is."""

    unit: str
    label: str
    tone: Tone
    calendar: str
    last_run: str
    next_run: str
    outcome: str
    #
    # What the calendar means, in words, and the form fields that would say it
    # again. `readable` falls back to the expression itself for a calendar the
    # form cannot express - one edited by hand on the manager.
    #
    readable: str
    time: str
    #
    # The schedule's time in the reader's clock, or empty when it reads the
    # same there: the timer runs on the manager's clock (B169), and a reader
    # in another zone should not have to convert it by hand (B190).
    #
    reader_time: str
    frequency: str
    weekdays: tuple[str, ...]
    day_of_month: int
    retention: int | None
    enabled: bool


@dataclass(frozen=True, slots=True)
class BackupOverview:
    clusters: tuple[BackupClusterView, ...]
    cluster_count: int
    node_count: int
    protected_count: int


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _text(value: Any, fallback: str = "—") -> str:
    return value if isinstance(value, str) and value else fallback


def _integer(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _moment(value: Any) -> datetime | None:
    text = _text(value, "")
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _size(total: int) -> str:
    """An archive size, in the unit an operator would say it in.

    Binary units, because that is what `ls -lh` and `du -h` on the node report,
    and a page that disagrees with the shell about the size of the same file
    invites somebody to work out which one is lying.
    """

    if total < 1024:
        return f"{total} B"
    if total < 1024 * 1024:
        return f"{total / 1024:.0f} KiB"
    if total < 1024 * 1024 * 1024:
        return f"{total / (1024 * 1024):.1f} MiB"
    return f"{total / (1024 * 1024 * 1024):.1f} GiB"


def _taken(moment: datetime | None, fallback: str) -> str:
    """When the archive was taken, on the manager's clock like the command line.

    The archive's own name carries the local time it was taken at, the timers
    that take them are set on the same clock, and `metrics.shown` says why every
    page reads that way: a time that cannot be lined up against `journalctl`
    sends people to the wrong minute.
    """

    if moment is None:
        return fallback
    return metrics.shown(moment).strftime("%Y-%m-%d %H:%M")


def _archive_views(node: str, value: Any, *, now: datetime) -> tuple[ArchiveView, ...]:
    if not isinstance(value, list):
        return ()
    archives: list[ArchiveView] = []
    #
    # Ranked by name rather than by the order the listing arrived in: the page
    # an archive lands on is its place in this node's history, and the name is
    # the stamp the run gave it.
    #
    named = [(_text(_mapping(entry).get("version"), ""), _mapping(entry)) for entry in value]
    ranked = sorted(
        ((version, item) for version, item in named if version),
        key=lambda pair: pair[0],
        reverse=True,
    )
    for rank, (version, item) in enumerate(ranked):
        taken_at = _moment(item.get("created_at"))
        size = _integer(item.get("size_bytes"))
        archives.append(
            ArchiveView(
                node=node,
                version=version,
                taken=_taken(taken_at, version),
                taken_iso=None if taken_at is None else taken_at.astimezone(UTC).isoformat(),
                age_label="—" if taken_at is None else relative_age(taken_at, now),
                size="—" if size is None else _size(size),
                latest=item.get("latest") is True,
                page=rank // ARCHIVES_PER_PAGE,
            )
        )
    return tuple(archives)


def _newest(archives: tuple[ArchiveView, ...], value: Any) -> datetime | None:
    """When this node last took a backup, read from the listing itself.

    `latest_version` names the archive but the timestamp is on the entry, and
    the two can disagree while a run is in flight. The newest `created_at` is
    what the age is measured from, so the page cannot report an archive as fresh
    on the strength of a name.
    """

    if not isinstance(value, list):
        return None
    moments = [_moment(_mapping(entry).get("created_at")) for entry in value]
    known = [moment for moment in moments if moment is not None]
    return max(known) if known and archives else None


def _node_state(
    *,
    available: bool,
    error: str | None,
    archives: tuple[ArchiveView, ...],
    retained_count: int,
    newest_at: datetime | None,
    now: datetime,
    limits: AgeLimits,
    started: bool = True,
) -> tuple[str, Tone, str]:
    if not available:
        return "Unreadable", "critical", error or "The backup directory could not be read"
    if not archives and not started:
        #
        # A new cluster: no schedule has run yet, so there is nothing missing
        # either (Fas 18, finding 71). Red here read as a fault on the first
        # visit; the getting-started list is what asks for the schedule.
        #
        return NOT_YET, "unknown", ""
    if not archives:
        #
        # No error, no archives. Nothing on this row looks wrong, and there is
        # nothing here to restore from.
        #
        return "No backups", "critical", "This node holds no state backup"
    if newest_at is None:
        return "Undated", "warning", "The archives carry no usable timestamp"
    age = now - newest_at
    if age > limits.critical:
        return "Stale backups", "critical", f"Newest archive is {relative_age(newest_at, now)}"
    if age > limits.warning:
        return "Backup overdue", "warning", f"Newest archive is {relative_age(newest_at, now)}"
    return (
        "Current",
        "healthy",
        f"{retained_count} archive{'' if retained_count == 1 else 's'} kept",
    )


def _node_view(
    value: Any, *, now: datetime, limits: AgeLimits, started: bool = True
) -> tuple[NodeBackupsView, tuple[ArchiveView, ...]]:
    node = _mapping(value)
    name = _text(node.get("name"), "Unnamed node")
    raw = node.get("backups")
    listed: list[Any] = raw if isinstance(raw, list) else []
    archives = _archive_views(name, listed, now=now)
    retained_count = _integer(node.get("retained_count"))
    if retained_count is None or retained_count < len(archives):
        # Older cached envelopes predate the explicit retained count.  Their
        # complete listing remains the best available answer.
        retained_count = len(archives)
    newest_at = _newest(archives, listed)
    error = _mapping(node.get("error")).get("message")
    label, tone, detail = _node_state(
        available=node.get("available") is True,
        error=_text(error, ""),
        archives=archives,
        retained_count=retained_count,
        newest_at=newest_at,
        now=now,
        limits=limits,
        started=started,
    )
    listed_size = sum((_integer(_mapping(entry).get("size_bytes")) or 0) for entry in listed)
    retained_size = _integer(node.get("retained_size_bytes"))
    if retained_size is None or retained_size < listed_size:
        retained_size = listed_size
    return (
        NodeBackupsView(
            name=name,
            label=label,
            tone=tone,
            detail=detail,
            latest=_text(node.get("latest_version"), "—") if archives else "",
            age_label="—" if newest_at is None else relative_age(newest_at, now),
            count=retained_count,
            shown_count=len(archives),
            total_size=_size(retained_size) if retained_size else "—",
        ),
        archives,
    )


def _stamp(value: Any) -> str:
    """A scheduled moment, in the reader's clock like every other time on the page."""

    moment = _moment(value)
    return "—" if moment is None else metrics.shown(moment).strftime("%Y-%m-%d %H:%M")


def _elapsed(value: Any, now: datetime) -> str:
    """The same moment with how long ago it was, for a run that has happened.

    Only ever used backwards. `relative_age` never looks into the future - it
    clamps ahead of now to "Just now" - so a next run rendered through it would
    claim the thing that has not happened yet just did.
    """

    moment = _moment(value)
    if moment is None:
        return "—"
    return f"{_stamp(value)} ({relative_age(moment, now)})"


def _schedule_view(
    value: Any, *, now: datetime, newest: ArchiveView | None = None
) -> ScheduleView | None:
    """The timer, read from the same envelope the archives came from.

    A missing timer and a disabled one are both critical and are worded
    differently, because they are fixed differently: one unit was removed, the
    other is present and switched off.
    """

    schedule = _mapping(value)
    unit = _text(schedule.get("unit"), "")
    if not unit:
        return None

    outcome = _text(schedule.get("last_result"), "")
    label: str
    tone: Tone
    if schedule.get("known") is not True:
        label, tone = "Timer missing", "critical"
    elif schedule.get("scheduled") is False and schedule.get("enabled") is not True:
        #
        # A cluster whose timer instance nobody has set yet. Not a fault - the
        # form on the card is where it becomes one - so it is not shouted.
        #
        label, tone = "Not scheduled", "warning"
    elif schedule.get("enabled") is not True:
        label, tone = "Disabled", "critical"
    elif outcome not in ("", "success"):
        #
        # The timer fires and the run it starts fails. Nothing else on this page
        # would show it: the archives simply stop getting newer, which reads as
        # an old backup rather than as a broken one.
        #
        label, tone = "Last run failed", "critical"
    elif schedule.get("active") is not True:
        label, tone = "Not running", "warning"
    else:
        label, tone = "Scheduled", "healthy"

    next_run = _stamp(schedule.get("next_run"))
    calendar = _text(schedule.get("calendar"), "no calendar")
    raw_retention = schedule.get("retention")
    retention = raw_retention if type(raw_retention) is int else None
    shape = backup_schedule.describe(schedule.get("calendar"))
    return ScheduleView(
        unit=unit,
        label=label,
        tone=tone,
        calendar=calendar,
        #
        # The newest archive on any node, however it was taken. The timer's own
        # last trigger is not this: a *Back up now* runs through the socket
        # helper and never fires the timer, so a strip that reported the
        # trigger said "36 minutes ago" beside nodes backed up a minute ago.
        #
        last_run=f"{newest.taken} ({newest.age_label})"
        if newest is not None and newest.taken_iso is not None
        else _elapsed(schedule.get("last_run"), now),
        #
        # A disabled or unscheduled timer still reports the elapse it would
        # have had. Showing it would promise a run that is not going to happen.
        #
        next_run=next_run if schedule.get("enabled") is True and tone != "critical" else "—",
        #
        # systemd reports `success` for a timer that has never fired; beside
        # "last backup —" it claimed a run that did not happen.
        #
        outcome=outcome if outcome and _moment(schedule.get("last_run")) is not None else "—",
        #
        # A cluster nobody has scheduled carries the template's default calendar.
        # Saying "Every day at 05:00" under *Not scheduled* would describe a run
        # that is not going to happen; the form below offers it instead.
        #
        readable="No schedule set"
        if label == "Not scheduled"
        else (_readable(shape) if shape else calendar),
        time=shape.time if shape else "05:00",
        reader_time=_in_reader_clock(shape.time, now) if shape and label != "Not scheduled" else "",
        frequency=shape.frequency if shape else "daily",
        weekdays=shape.weekdays if shape else (),
        day_of_month=shape.day_of_month or 1 if shape else 1,
        retention=retention,
        enabled=schedule.get("enabled") is True,
    )


def _in_reader_clock(clock: str, now: datetime) -> str:
    """Today's `HH:MM` on the manager, as the reader's clock reads it, or ''.

    Today's, because the difference moves with daylight saving on either side.
    Empty when both clocks print the same, so a reader on the manager's zone -
    or one like it - sees the schedule exactly as before.
    """

    hour, _, minute = clock.partition(":")
    try:
        wall = time(int(hour), int(minute))
    except ValueError:
        #
        # A hand-edited calendar can say 29:00; the expression beside it is
        # already shown as written, and there is no moment to convert.
        #
        return ""
    manager = datetime.combine(now.astimezone().date(), wall).astimezone()
    reader = metrics.shown(manager)
    if reader.strftime("%H:%M %Z") == manager.strftime("%H:%M %Z"):
        return ""
    return reader.strftime("%H:%M %Z")


WEEKDAY_NAMES = {
    "Mon": "Monday",
    "Tue": "Tuesday",
    "Wed": "Wednesday",
    "Thu": "Thursday",
    "Fri": "Friday",
    "Sat": "Saturday",
    "Sun": "Sunday",
}


def _readable(shape: backup_schedule.Schedule) -> str:
    """`*-*-* 05:00:00` as a person would say it."""

    if shape.frequency == "weekly":
        if shape.weekdays == backup_schedule.WEEKDAYS:
            return f"Every day at {shape.time}"
        if shape.weekdays == backup_schedule.WEEKDAYS[:5]:
            return f"Every weekday at {shape.time}"
        names = [WEEKDAY_NAMES[day] for day in shape.weekdays]
        listed = " and ".join(filter(None, (", ".join(names[:-1]), names[-1])))
        return f"Every {listed} at {shape.time}"
    if shape.frequency == "monthly":
        return f"On day {shape.day_of_month} of every month at {shape.time}"
    return f"Every day at {shape.time}"


def _empty(cluster: str, *, configured: bool) -> BackupClusterView:
    return BackupClusterView(
        cluster=cluster,
        accent=accent_index(cluster),
        configured=configured,
        label="No backup data yet",
        tone="unknown",
        detail="Waiting for the first backup listing",
        observed_at=None,
        observed_iso=None,
        age_label="Never",
        stale=False,
        nodes=(),
        archives=(),
        retained_count=0,
        shown_count=0,
        truncated=False,
        page_count=1,
        deepest=0,
        schedule=None,
    )


def _state(
    reading: ClusterBackups,
    *,
    stale: bool,
    nodes: tuple[NodeBackupsView, ...],
) -> tuple[str, Tone, str]:
    """What this cluster's backup listing means, as a badge and a sentence.

    The worst node decides, and it is named. "1 of 2 nodes" is what an operator
    acts on; a cluster-level "degraded" would send them to the table to work out
    which node it meant.
    """

    if reading.poll_error:
        return "Collection unavailable", "critical", "The poller could not read the backups"
    if reading.outcome == "failed":
        return "Backups unavailable", "critical", "The backup listing could not be read"
    if stale:
        return "Stale data", "warning", "Backup data needs a fresh poll"
    if not nodes:
        return "No nodes listed", "unknown", "The listing named no node"

    if all(node.label == NOT_YET for node in nodes):
        return NOT_YET, "unknown", ""
    severity = ("critical", "warning", "unknown", "healthy")
    worst = min(nodes, key=lambda node: severity.index(node.tone))
    if worst.tone == "healthy":
        return "Current", "healthy", f"Every node backed up · newest {worst.age_label}"
    return f"{worst.name}: {worst.label.lower()}", worst.tone, worst.detail


def _cluster_view(
    reading: ClusterBackups,
    *,
    configured: bool,
    now: datetime,
    stale_after: timedelta,
) -> BackupClusterView:
    result = _mapping(reading.result)
    entries = result.get("nodes")
    nodes: list[NodeBackupsView] = []
    archives: list[ArchiveView] = []
    limits = _age_limits(result.get("schedule"))
    started = _started(result.get("schedule"))
    if isinstance(entries, list):
        for entry in entries:
            node, node_archives = _node_view(entry, now=now, limits=limits, started=started)
            nodes.append(node)
            archives.extend(node_archives)
    stale = now - reading.observed_at > stale_after
    label, tone, detail = _state(reading, stale=stale, nodes=tuple(nodes))

    newest_first = sorted(archives, key=lambda entry: (entry.version, entry.node), reverse=True)
    ordered = tuple(sorted(newest_first, key=lambda entry: entry.page))
    deepest = max((node.shown_count for node in nodes), default=0)
    return BackupClusterView(
        cluster=reading.cluster,
        accent=accent_index(reading.cluster),
        configured=configured,
        label=label,
        tone=tone,
        detail=detail,
        observed_at=reading.observed_at,
        observed_iso=reading.observed_at.astimezone(UTC).isoformat(),
        age_label=observation_label(reading.observed_at, now),
        stale=stale,
        nodes=tuple(nodes),
        #
        # Newest first, and across nodes rather than per node: the question is
        # what can be restored and how recent it is, and the two nodes' runs
        # interleave in time. Grouped by page first, so each page is a
        # contiguous run of rows the browser can show or hide as a block.
        #
        archives=ordered,
        #
        # The listing reports both the returned and retained count, so a full
        # fourteen-at-the-limit list is not mistaken for a truncated one.
        #
        retained_count=sum(node.count for node in nodes),
        shown_count=len(archives),
        truncated=any(node.shown_count < node.count for node in nodes),
        page_count=max(-(-deepest // ARCHIVES_PER_PAGE), 1),
        deepest=deepest,
        schedule=_schedule_view(
            result.get("schedule"), now=now, newest=ordered[0] if ordered else None
        ),
    )


def build_backup_overview(
    configured_clusters: Iterable[str],
    readings: Iterable[ClusterBackups],
    *,
    now: datetime | None = None,
    stale_after: timedelta,
) -> BackupOverview:
    """Combine configured clusters and their newest cached backup listing."""

    now = now or datetime.now(UTC)
    rows = {reading.cluster: reading for reading in readings}
    clusters: list[BackupClusterView] = []
    for cluster in tuple(configured_clusters):
        reading = rows.pop(cluster, None)
        clusters.append(
            _empty(cluster, configured=True)
            if reading is None
            else _cluster_view(reading, configured=True, now=now, stale_after=stale_after)
        )
    for cluster in sorted(rows):
        clusters.append(
            _cluster_view(rows[cluster], configured=False, now=now, stale_after=stale_after)
        )

    nodes = tuple(node for cluster in clusters for node in cluster.nodes)
    return BackupOverview(
        clusters=tuple(clusters),
        cluster_count=len(clusters),
        node_count=len(nodes),
        #
        # A node counts as protected only when its newest archive is recent
        # enough to restore from. Counting nodes that merely hold something
        # would report a node whose last backup is from June as covered.
        #
        protected_count=sum(node.tone == "healthy" for node in nodes),
    )
