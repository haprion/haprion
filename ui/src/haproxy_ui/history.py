"""Read model for the saved configuration version history.

Like the proxy overview, this layer knows only the envelope the poller cached.
It cannot reach Git, and it does not count versions itself: the numbering is
arithmetic over a repository's first-parent history, done once in the engine, and
a second implementation here would be free to disagree with the command line
about what "version 7" means.

The question the page exists to answer is not "what happened" - that is an audit
trail, and this phase has no data source for one. It is "what is saved, and is
any of it waiting to be published", which the cached listing does answer.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from haproxy_ui import metrics
from haproxy_ui.cluster_identity import accent_index
from haproxy_ui.dashboard import observation_label
from haproxy_ui.db import ClusterHistory

type Tone = Literal["healthy", "warning", "critical", "unknown"]

#
# Versions per page. The poller lists up to the helper's ceiling and the page
# arrives whole; the browser shows one page at a time, the way the archive
# list on Node backups does (Fas 14 point 8).
#
VERSIONS_PER_PAGE = 10


@dataclass(frozen=True, slots=True)
class VersionView:
    number: int
    version: str
    expected_commit: str
    date: str
    comment: str
    published: bool
    current: bool
    #
    # Who asked for the version, from its `Requested-By` trailer (B207); "—"
    # for everything recorded before it.
    #
    requested_by: str = "—"
    page: int = 0


@dataclass(frozen=True, slots=True)
class HistoryClusterView:
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
    published: str
    unpublished: int
    total: int
    truncated: bool
    versions: tuple[VersionView, ...]
    #
    # The published version as a number: what the deploy button sends, so the
    # helper refuses to roll out a version this page did not show.
    #
    target_version: int | None = None
    page_count: int = 1


@dataclass(frozen=True, slots=True)
class HistoryOverview:
    clusters: tuple[HistoryClusterView, ...]
    cluster_count: int
    published_count: int
    waiting_count: int


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _integer(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _text(value: Any, fallback: str = "—") -> str:
    return value if isinstance(value, str) and value else fallback


def _saved_at(value: Any) -> str:
    """The contract's timestamp, in the reader's clock like every other time.

    Once UTC, to match `haproxy-list` beside it; since B190 every page shows
    one clock, the reader's, and a history that alone kept another was the
    time that differed by an hour without saying so.
    """

    text = _text(value, "")
    if not text:
        return "—"
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return text[:32]
    if parsed.tzinfo is None:
        return parsed.strftime("%Y-%m-%d %H:%M")
    return metrics.shown(parsed).strftime("%Y-%m-%d %H:%M")


def _version_view(value: Any, published_hash: str | None, rank: int) -> VersionView | None:
    entry = _mapping(value)
    number = _integer(entry.get("version"))
    if number is None:
        return None
    #
    # The commit is not a column any more; it is the version number's title,
    # for matching against a RELEASE stamp or `git log`. Nothing is looked up
    # with it here.
    #
    #
    # Matched by hash, like the engine does: after a history reset an old number
    # can name a different commit, and the hash is what the nodes were given.
    #
    commit = _text(entry.get("hash"), "")
    return VersionView(
        number=number,
        version=f"v{number}",
        # The complete poller-supplied hash: what a revert binds to, and the
        # version number's title.
        expected_commit=commit,
        date=_saved_at(entry.get("created_at")),
        comment=_text(entry.get("comment"), "(no comment)"),
        published=bool(commit) and commit == published_hash,
        current=entry.get("current") is True,
        requested_by=_text(entry.get("requested_by")),
        page=rank // VERSIONS_PER_PAGE,
    )


def _empty(cluster: str, *, configured: bool) -> HistoryClusterView:
    return HistoryClusterView(
        cluster=cluster,
        accent=accent_index(cluster),
        configured=configured,
        label="No history yet",
        tone="unknown",
        detail="Waiting for the first version listing",
        observed_at=None,
        observed_iso=None,
        age_label="Never",
        stale=False,
        published="—",
        unpublished=0,
        total=0,
        truncated=False,
        versions=(),
    )


def _saved_count(total: int) -> str:
    return "1 saved version" if total == 1 else f"{total} saved versions"


def _state(
    reading: ClusterHistory,
    *,
    stale: bool,
    versions: tuple[VersionView, ...],
    published_version: int | None,
    unpublished: int | None,
    total: int,
) -> tuple[str, Tone, str]:
    """What this cluster's listing means, as a badge, a tone and a sentence.

    The badge states the cluster's publication state and the sentence adds a
    fact the badge does not carry. They deliberately do not restate each other:
    the row inside the table already marks which version is published, so a card
    that says "Published" three ways spends space without adding anything.
    """

    if reading.poll_error:
        return "Collection unavailable", "critical", "The poller could not read the history"
    if reading.outcome != "done":
        return "History unavailable", "critical", "The saved history could not be read"
    if stale:
        return "Stale data", "warning", "History needs a fresh poll"
    if not versions:
        return "No versions yet", "unknown", "Nothing has been saved for this cluster"
    if published_version is None:
        return "Nothing published", "unknown", f"{_saved_count(total)}, none published"
    if unpublished is None:
        #
        # The published release is older than the versions listed. Saying
        # "0 waiting" here would be a guess, and it would be the reassuring one.
        #
        return (
            "Published is older",
            "warning",
            f"v{published_version} is not in this listing",
        )
    if unpublished == 0:
        return "Published", "healthy", _saved_count(total)
    return (
        f"{unpublished} unpublished",
        "warning",
        f"Published is v{published_version} · {_saved_count(total)}",
    )


def _cluster_view(
    reading: ClusterHistory,
    *,
    configured: bool,
    now: datetime,
    stale_after: timedelta,
    #
    # True only in snapshot mode, where the readings describe a moment that has
    # passed and `now` is that moment rather than the wall clock. It changes
    # what the freshness line says, not how staleness is judged. See
    # `dashboard.observation_label`.
    #
    captured: bool = False,
) -> HistoryClusterView:
    result = _mapping(reading.result)
    published_version = _integer(result.get("published_version"))
    published_hash = _text(result.get("published_hash"), "") or None
    entries = result.get("versions")
    parsed: list[VersionView] = []
    if isinstance(entries, list):
        for entry in entries:
            version = _version_view(entry, published_hash, len(parsed))
            if version is not None:
                parsed.append(version)
    versions = tuple(parsed)
    unpublished = _integer(result.get("unpublished"))
    total = _integer(result.get("total_versions")) or 0
    stale = now - reading.observed_at > stale_after

    label, tone, detail = _state(
        reading,
        stale=stale,
        versions=versions,
        published_version=published_version,
        unpublished=unpublished,
        total=total,
    )
    return HistoryClusterView(
        cluster=reading.cluster,
        accent=accent_index(reading.cluster),
        configured=configured,
        label=label,
        tone=tone,
        detail=detail,
        observed_at=reading.observed_at,
        observed_iso=reading.observed_at.astimezone(UTC).isoformat(),
        age_label=observation_label(reading.observed_at, now, captured=captured),
        stale=stale,
        published="—" if published_version is None else f"v{published_version}",
        unpublished=unpublished or 0,
        total=total,
        truncated=result.get("truncated") is True,
        versions=versions,
        target_version=published_version
        if published_version is not None and published_version > 0
        else None,
        page_count=max(-(-len(versions) // VERSIONS_PER_PAGE), 1),
    )


def build_history_overview(
    configured_clusters: Iterable[str],
    readings: Iterable[ClusterHistory],
    *,
    now: datetime | None = None,
    stale_after: timedelta,
    #
    # True only in snapshot mode, where the readings describe a moment that has
    # passed and `now` is that moment rather than the wall clock. It changes
    # what the freshness line says, not how staleness is judged. See
    # `dashboard.observation_label`.
    #
    captured: bool = False,
) -> HistoryOverview:
    """Combine configured clusters and their newest cached version listing."""

    now = now or datetime.now(UTC)
    rows = {reading.cluster: reading for reading in readings}
    clusters: list[HistoryClusterView] = []
    for cluster in tuple(configured_clusters):
        reading = rows.pop(cluster, None)
        clusters.append(
            _empty(cluster, configured=True)
            if reading is None
            else _cluster_view(
                reading, configured=True, now=now, stale_after=stale_after, captured=captured
            )
        )
    for cluster in sorted(rows):
        clusters.append(
            _cluster_view(
                rows[cluster], configured=False, now=now, stale_after=stale_after, captured=captured
            )
        )

    return HistoryOverview(
        clusters=tuple(clusters),
        cluster_count=len(clusters),
        published_count=sum(cluster.published != "—" for cluster in clusters),
        waiting_count=sum(cluster.unpublished for cluster in clusters),
    )
