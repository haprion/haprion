"""What the poller read from each cluster, and the search index built from it."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from typing import Any

from haprion import node_resources
from psycopg import Connection, sql
from psycopg.rows import class_row
from psycopg.types.json import Jsonb

from haprion_ui import search_index
from haprion_ui.traffic_logs import like_pattern


@dataclass(frozen=True, slots=True)
class ClusterStatus:
    cluster: str
    observed_at: datetime
    outcome: str
    result: dict[str, Any]
    warnings: list[Any]
    error: dict[str, Any] | None
    poll_error: str | None


@dataclass(frozen=True, slots=True)
class ClusterInventory:
    """The last published configuration inventory the poller could read."""

    cluster: str
    observed_at: datetime
    outcome: str
    result: dict[str, Any]
    warnings: list[Any]
    error: dict[str, Any] | None
    poll_error: str | None


@dataclass(frozen=True, slots=True)
class ClusterBackups:
    """The last state backup listing the poller could read for one cluster."""

    cluster: str
    observed_at: datetime
    outcome: str
    result: dict[str, Any]
    warnings: list[Any]
    error: dict[str, Any] | None
    poll_error: str | None


@dataclass(frozen=True, slots=True)
class ClusterCertificates:
    """The last certificate metadata the poller could read for one cluster."""

    cluster: str
    observed_at: datetime
    outcome: str
    result: dict[str, Any]
    warnings: list[Any]
    error: dict[str, Any] | None
    poll_error: str | None


@dataclass(frozen=True, slots=True)
class ManagerCertificates:
    """The last reading of what the manager holds - the registry and what the
    interface is served with - asked for with no cluster (B304)."""

    observed_at: datetime
    outcome: str
    result: dict[str, Any]
    warnings: list[Any]
    error: dict[str, Any] | None
    poll_error: str | None


@dataclass(frozen=True, slots=True)
class ClusterSettingsRow:
    """The last settings reading - log targets and metrics - for one cluster (Fas 15)."""

    cluster: str
    observed_at: datetime
    outcome: str
    result: dict[str, Any]
    warnings: list[Any]
    error: dict[str, Any] | None
    poll_error: str | None


@dataclass(frozen=True, slots=True)
class ClusterNetwork:
    """The last network description the poller could read for one cluster."""

    cluster: str
    observed_at: datetime
    outcome: str
    result: dict[str, Any]
    warnings: list[Any]
    error: dict[str, Any] | None
    poll_error: str | None


@dataclass(frozen=True, slots=True)
class ClusterObjects:
    """The last reading of one cluster's proxy objects as they are written.

    Distinct from `ClusterInventory`, which holds published HAProxy
    configuration. That answers what a node is serving; this answers what an
    edit is made against, and the two are the same only until somebody edits.
    """

    cluster: str
    observed_at: datetime
    outcome: str
    result: dict[str, Any]
    warnings: list[Any]
    error: dict[str, Any] | None
    poll_error: str | None


@dataclass(frozen=True, slots=True)
class ClusterHistory:
    """The last version listing the poller could read for one cluster."""

    cluster: str
    observed_at: datetime
    outcome: str
    result: dict[str, Any]
    warnings: list[Any]
    error: dict[str, Any] | None
    poll_error: str | None


#
# Older than this, the previous reading is not used for a CPU share: an average
# over a poller that stood still for an hour describes that hour, not now.
#
CPU_READING_MAX_GAP = timedelta(minutes=5)


def _with_cpu_shares(result: Mapping[str, Any], previous: Any) -> Mapping[str, Any]:
    """Each node's CPU share since its previous reading, as `cpu_percent` beside its status.

    `null` without a previous reading of the same node, so the first answer
    after a gap shows a dash rather than a figure averaged over the gap.
    """

    nodes = result.get("nodes")
    if not isinstance(nodes, list):
        return result
    before: dict[str, Any] = {}
    if isinstance(previous, Mapping) and isinstance(previous.get("nodes"), list):
        for node in previous["nodes"]:
            if isinstance(node, Mapping) and isinstance(node.get("status"), Mapping):
                before[str(node.get("name"))] = node["status"].get("resources")
    shared: list[Any] = []
    for node in nodes:
        if not isinstance(node, Mapping):
            shared.append(node)
            continue
        status = node.get("status")
        current = status.get("resources") if isinstance(status, Mapping) else None
        shared.append(
            {
                **node,
                "cpu_percent": node_resources.cpu_percent(
                    before.get(str(node.get("name"))), current
                ),
            }
        )
    return {**result, "nodes": shared}


def _forward_receivers(node: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    status = node.get("status")
    forwarding = status.get("log_forwarding") if isinstance(status, Mapping) else None
    receivers = forwarding.get("receivers") if isinstance(forwarding, Mapping) else None
    if not isinstance(receivers, list):
        return []
    return [receiver for receiver in receivers if isinstance(receiver, Mapping)]


def _with_forward_waiting(
    result: Mapping[str, Any], previous: Any, now: datetime
) -> Mapping[str, Any]:
    """Per node, since when each log receiver's queue has not been empty (26-10-12).

    A receiver that keeps up empties its queue within seconds; one whose queue
    is still not empty minutes later is not being reached - on a quiet cluster
    long before the queue is long enough to say so by its size. Carried from
    reading to reading as `forward_waiting_since`, beside the node's status,
    as the CPU share is; a receiver whose queue is empty, or a node without a
    recent previous reading, starts again from now.

    So does a queue shorter than at the previous reading: lines left it, so the
    receiver is reached. One far away always has a few lines on their way, and
    a clock that waited for an empty queue would call it unreached (review
    26-10-12 F3). One out of reach keeps or grows its queue.
    """

    nodes = result.get("nodes")
    if not isinstance(nodes, list):
        return result
    before: dict[str, Mapping[str, Any]] = {}
    queued_before: dict[str, dict[str, Any]] = {}
    if isinstance(previous, Mapping) and isinstance(previous.get("nodes"), list):
        for node in previous["nodes"]:
            if not isinstance(node, Mapping):
                continue
            if isinstance(node.get("forward_waiting_since"), Mapping):
                before[str(node.get("name"))] = node["forward_waiting_since"]
            queued_before[str(node.get("name"))] = {
                str(receiver.get("name")): receiver.get("queued")
                for receiver in _forward_receivers(node)
            }
    carried: list[Any] = []
    for node in nodes:
        if not isinstance(node, Mapping):
            carried.append(node)
            continue
        earlier = before.get(str(node.get("name")), {})
        sizes = queued_before.get(str(node.get("name")), {})
        waiting: dict[str, str] = {}
        for receiver in _forward_receivers(node):
            queued = receiver.get("queued")
            if isinstance(queued, int) and not isinstance(queued, bool) and queued > 0:
                name = str(receiver.get("name"))
                kept = earlier.get(name)
                size = sizes.get(name)
                shrank = isinstance(size, int) and not isinstance(size, bool) and queued < size
                waiting[name] = kept if isinstance(kept, str) and not shrank else now.isoformat()
        carried.append({**node, "forward_waiting_since": waiting})
    return {**result, "nodes": carried}


def record_cluster_status(
    connection: Connection[Any],
    *,
    cluster: str,
    outcome: str,
    result: Mapping[str, Any],
    warnings: Any = None,
    error: Mapping[str, Any] | None = None,
    poll_error: str | None = None,
) -> None:
    """Write what one cluster last said. Insert or replace, never accumulate.

    One row per cluster rather than a history: this is a cache of the newest
    answer, and what happened over time belongs in metrics, which is a later
    phase with different retention. Keeping every poll here would grow without
    bound to answer a question nothing asks.

    `observed_at` appears nowhere in this statement. The database sets it, on
    insert by default and on update by trigger, so the freshness a reader
    trusts is not something the writer supplies.
    """

    with connection.cursor() as cursor:
        #
        # The previous answer, read before it is replaced: CPU use is a rate,
        # and this row is the only place the previous reading is kept (B239).
        #
        cursor.execute(
            "select result, now() - observed_at <= %(fresh)s "
            "  from cluster_status where cluster = %(cluster)s",
            {"cluster": cluster, "fresh": CPU_READING_MAX_GAP},
        )
        previous = cursor.fetchone()
        recent = previous[0] if previous and previous[1] else None
        result = _with_cpu_shares(result, recent)
        result = _with_forward_waiting(result, recent, datetime.now(UTC))
        cursor.execute(
            "insert into cluster_status (cluster, outcome, result, warnings, error, poll_error) "
            "values (%(cluster)s, %(outcome)s, %(result)s, %(warnings)s, %(error)s, %(poll)s) "
            "on conflict (cluster) do update set "
            "    outcome = excluded.outcome, "
            "    result = excluded.result, "
            "    warnings = excluded.warnings, "
            "    error = excluded.error, "
            "    poll_error = excluded.poll_error",
            {
                "cluster": cluster,
                "outcome": outcome,
                "result": Jsonb(dict(result)),
                "warnings": Jsonb(list(warnings or [])),
                "error": None if error is None else Jsonb(dict(error)),
                "poll": poll_error,
            },
        )


def cluster_statuses(connection: Connection[Any]) -> list[ClusterStatus]:
    """Every cluster's newest reading, oldest observation first.

    Ordered by age rather than by name, so whatever has gone stale is what a
    reader sees at the top - which is the row that means something is wrong.
    """

    with connection.cursor(row_factory=class_row(ClusterStatus)) as cursor:
        cursor.execute(
            "select cluster, observed_at, outcome, result, warnings, error, poll_error "
            "  from cluster_status "
            " order by observed_at asc"
        )
        return cursor.fetchall()


def record_cluster_inventory(
    connection: Connection[Any],
    *,
    cluster: str,
    outcome: str,
    result: Mapping[str, Any],
    warnings: Any = None,
    error: Mapping[str, Any] | None = None,
    poll_error: str | None = None,
) -> None:
    """Replace one cluster's cached inventory with the newest helper answer."""

    with connection.cursor() as cursor:
        cursor.execute(
            "insert into cluster_inventory (cluster, outcome, result, warnings, error, poll_error) "
            "values (%(cluster)s, %(outcome)s, %(result)s, %(warnings)s, %(error)s, %(poll)s) "
            "on conflict (cluster) do update set "
            "    outcome = excluded.outcome, "
            "    result = excluded.result, "
            "    warnings = excluded.warnings, "
            "    error = excluded.error, "
            "    poll_error = excluded.poll_error",
            {
                "cluster": cluster,
                "outcome": outcome,
                "result": Jsonb(dict(result)),
                "warnings": Jsonb(list(warnings or [])),
                "error": None if error is None else Jsonb(dict(error)),
                "poll": poll_error,
            },
        )


def cluster_inventories(connection: Connection[Any]) -> list[ClusterInventory]:
    """Every cluster's newest inventory, with the stalest one first."""

    with connection.cursor(row_factory=class_row(ClusterInventory)) as cursor:
        cursor.execute(
            "select cluster, observed_at, outcome, result, warnings, error, poll_error "
            "  from cluster_inventory "
            " order by observed_at asc"
        )
        return cursor.fetchall()


COMMIT_SHAPE = re.compile(r"^[0-9a-f]{40,64}$")


def versions_without_diff(
    connection: Connection[Any], *, cluster: str, limit: int
) -> tuple[str, ...]:
    """The newest listed versions of a cluster whose diff is not kept yet.

    Read from the listing the previous pass stored: the first pass after a
    publish lists the new version, and the next one asks for its diff.
    """

    with connection.cursor() as cursor:
        cursor.execute(
            "select version ->> 'hash' from cluster_history history, "
            "     jsonb_array_elements(case jsonb_typeof(history.result -> 'versions') "
            "         when 'array' then history.result -> 'versions' else '[]'::jsonb end) "
            "     with ordinality as listed(version, position) "
            " where history.cluster = %(cluster)s "
            "   and not exists (select 1 from version_diff kept "
            "                    where kept.cluster = history.cluster "
            "                      and kept.commit = version ->> 'hash') "
            " order by position limit %(limit)s",
            {"cluster": cluster, "limit": limit},
        )
        return tuple(
            row[0]
            for row in cursor.fetchall()
            if isinstance(row[0], str) and COMMIT_SHAPE.fullmatch(row[0])
        )


def record_version_diffs(
    connection: Connection[Any], *, cluster: str, result: Mapping[str, Any]
) -> int:
    """Keep the diffs a listing carried, once each; answer how many were new."""

    diffs = result.get("diffs")
    if not isinstance(diffs, Mapping):
        return 0
    written = 0
    with connection.cursor() as cursor:
        for commit, diff in diffs.items():
            if not isinstance(commit, str) or not COMMIT_SHAPE.fullmatch(commit):
                continue
            if not isinstance(diff, Mapping):
                continue
            cursor.execute(
                "insert into version_diff (cluster, commit, diff) "
                "values (%(cluster)s, %(commit)s, %(diff)s) on conflict do nothing",
                {"cluster": cluster, "commit": commit, "diff": Jsonb(dict(diff))},
            )
            written += cursor.rowcount
    return written


def read_version_diff(
    connection: Connection[Any], *, cluster: str, commit: str
) -> Mapping[str, Any] | None:
    """One version's diff as kept, or None when it has not been fetched yet."""

    if not COMMIT_SHAPE.fullmatch(commit):
        return None
    with connection.cursor() as cursor:
        cursor.execute(
            "select diff from version_diff where cluster = %(cluster)s and commit = %(commit)s",
            {"cluster": cluster, "commit": commit},
        )
        row = cursor.fetchone()
    return None if row is None else row[0]


def record_cluster_history(
    connection: Connection[Any],
    *,
    cluster: str,
    outcome: str,
    result: Mapping[str, Any],
    warnings: Any = None,
    error: Mapping[str, Any] | None = None,
    poll_error: str | None = None,
) -> None:
    """Replace one cluster's cached version listing with the newest answer.

    Without `diffs`: those are kept per version in `version_diff`
    (`record_version_diffs`, the source's second write), and a listing carrying
    up to ten of them on every pass would only make this row large.
    """

    result = {key: value for key, value in result.items() if key != "diffs"}

    with connection.cursor() as cursor:
        cursor.execute(
            "insert into cluster_history (cluster, outcome, result, warnings, error, poll_error) "
            "values (%(cluster)s, %(outcome)s, %(result)s, %(warnings)s, %(error)s, %(poll)s) "
            "on conflict (cluster) do update set "
            "    outcome = excluded.outcome, "
            "    result = excluded.result, "
            "    warnings = excluded.warnings, "
            "    error = excluded.error, "
            "    poll_error = excluded.poll_error",
            {
                "cluster": cluster,
                "outcome": outcome,
                "result": Jsonb(dict(result)),
                "warnings": Jsonb(list(warnings or [])),
                "error": None if error is None else Jsonb(dict(error)),
                "poll": poll_error,
            },
        )


def cluster_history(connection: Connection[Any], cluster: str) -> ClusterHistory | None:
    """One cluster's cached version listing, or nothing when it has never been read.

    Separate from `cluster_histories` rather than filtered out of it: the
    recovery path asks about exactly one cluster and needs the answer's age, and
    fetching every cluster to discard all but one would make the query's cost
    grow with an installation that has nothing to do with the question.
    """

    with connection.cursor(row_factory=class_row(ClusterHistory)) as cursor:
        cursor.execute(
            "select cluster, observed_at, outcome, result, warnings, error, poll_error "
            "  from cluster_history "
            " where cluster = %(cluster)s",
            {"cluster": cluster},
        )
        return cursor.fetchone()


def cluster_histories(
    connection: Connection[Any], *, cluster: str | None = None
) -> list[ClusterHistory]:
    """Every cluster's newest version listing, with the stalest one first."""

    with connection.cursor(row_factory=class_row(ClusterHistory)) as cursor:
        cursor.execute(
            sql.SQL(
                "select cluster, observed_at, outcome, result, warnings, error, poll_error "
                "from cluster_history {scope} order by observed_at asc"
            ).format(scope=sql.SQL("where cluster = %(cluster)s" if cluster is not None else "")),
            {"cluster": cluster},
        )
        return cursor.fetchall()


def record_cluster_backups(
    connection: Connection[Any],
    *,
    cluster: str,
    outcome: str,
    result: Mapping[str, Any],
    warnings: Any = None,
    error: Mapping[str, Any] | None = None,
    poll_error: str | None = None,
) -> None:
    """Replace one cluster's cached state backup listing with the newest helper answer."""

    with connection.cursor() as cursor:
        cursor.execute(
            "insert into cluster_backups (cluster, outcome, result, warnings, error, poll_error) "
            "values (%(cluster)s, %(outcome)s, %(result)s, %(warnings)s, %(error)s, %(poll)s) "
            "on conflict (cluster) do update set "
            "    outcome = excluded.outcome, "
            "    result = excluded.result, "
            "    warnings = excluded.warnings, "
            "    error = excluded.error, "
            "    poll_error = excluded.poll_error",
            {
                "cluster": cluster,
                "outcome": outcome,
                "result": Jsonb(dict(result)),
                "warnings": Jsonb(list(warnings or [])),
                "error": None if error is None else Jsonb(dict(error)),
                "poll": poll_error,
            },
        )


def cluster_backups(connection: Connection[Any]) -> list[ClusterBackups]:
    """Every cluster's newest state backup listing, with the stalest one first."""

    with connection.cursor(row_factory=class_row(ClusterBackups)) as cursor:
        cursor.execute(
            "select cluster, observed_at, outcome, result, warnings, error, poll_error "
            "  from cluster_backups "
            " order by observed_at asc"
        )
        return cursor.fetchall()


def record_cluster_certificates(
    connection: Connection[Any],
    *,
    cluster: str,
    outcome: str,
    result: Mapping[str, Any],
    warnings: Any = None,
    error: Mapping[str, Any] | None = None,
    poll_error: str | None = None,
) -> None:
    """Replace one cluster's cached certificate metadata with the newest helper answer."""

    with connection.cursor() as cursor:
        cursor.execute(
            "insert into cluster_certificates (cluster, outcome, result, warnings, error, poll_error) "
            "values (%(cluster)s, %(outcome)s, %(result)s, %(warnings)s, %(error)s, %(poll)s) "
            "on conflict (cluster) do update set "
            "    outcome = excluded.outcome, "
            "    result = excluded.result, "
            "    warnings = excluded.warnings, "
            "    error = excluded.error, "
            "    poll_error = excluded.poll_error",
            {
                "cluster": cluster,
                "outcome": outcome,
                "result": Jsonb(dict(result)),
                "warnings": Jsonb(list(warnings or [])),
                "error": None if error is None else Jsonb(dict(error)),
                "poll": poll_error,
            },
        )


def cluster_certificates(
    connection: Connection[Any], *, cluster: str | None = None
) -> list[ClusterCertificates]:
    """Every cluster's newest certificate metadata, with the stalest one first."""

    with connection.cursor(row_factory=class_row(ClusterCertificates)) as cursor:
        cursor.execute(
            sql.SQL(
                "select cluster, observed_at, outcome, result, warnings, error, poll_error "
                "from cluster_certificates {scope} order by observed_at asc"
            ).format(scope=sql.SQL("where cluster = %(cluster)s" if cluster is not None else "")),
            {"cluster": cluster},
        )
        return cursor.fetchall()


def record_manager_certificates(
    connection: Connection[Any],
    *,
    outcome: str,
    result: Mapping[str, Any],
    warnings: Any = None,
    error: Mapping[str, Any] | None = None,
    poll_error: str | None = None,
) -> None:
    """Replace the manager's certificate reading with the newest helper answer (B304)."""

    with connection.cursor() as cursor:
        cursor.execute(
            "insert into manager_certificates (outcome, result, warnings, error, poll_error) "
            "values (%(outcome)s, %(result)s, %(warnings)s, %(error)s, %(poll)s) "
            "on conflict (id) do update set "
            "    outcome = excluded.outcome, "
            "    result = excluded.result, "
            "    warnings = excluded.warnings, "
            "    error = excluded.error, "
            "    poll_error = excluded.poll_error",
            {
                "outcome": outcome,
                "result": Jsonb(dict(result)),
                "warnings": Jsonb(list(warnings or [])),
                "error": None if error is None else Jsonb(dict(error)),
                "poll": poll_error,
            },
        )


def manager_certificates(connection: Connection[Any]) -> ManagerCertificates | None:
    """The manager's newest certificate reading; None before the poller has made one."""

    with connection.cursor(row_factory=class_row(ManagerCertificates)) as cursor:
        cursor.execute(
            "select observed_at, outcome, result, warnings, error, poll_error "
            "from manager_certificates where id = 1"
        )
        return cursor.fetchone()


def record_cluster_network(
    connection: Connection[Any],
    *,
    cluster: str,
    outcome: str,
    result: Mapping[str, Any],
    warnings: Any = None,
    error: Mapping[str, Any] | None = None,
    poll_error: str | None = None,
) -> None:
    """Replace one cluster's cached network description with the newest helper answer."""

    with connection.cursor() as cursor:
        cursor.execute(
            "insert into cluster_network (cluster, outcome, result, warnings, error, poll_error) "
            "values (%(cluster)s, %(outcome)s, %(result)s, %(warnings)s, %(error)s, %(poll)s) "
            "on conflict (cluster) do update set "
            "    outcome = excluded.outcome, "
            "    result = excluded.result, "
            "    warnings = excluded.warnings, "
            "    error = excluded.error, "
            "    poll_error = excluded.poll_error",
            {
                "cluster": cluster,
                "outcome": outcome,
                "result": Jsonb(dict(result)),
                "warnings": Jsonb(list(warnings or [])),
                "error": None if error is None else Jsonb(dict(error)),
                "poll": poll_error,
            },
        )


def cluster_networks(
    connection: Connection[Any], *, cluster: str | None = None
) -> list[ClusterNetwork]:
    """Every cluster's newest network description, with the stalest one first."""

    with connection.cursor(row_factory=class_row(ClusterNetwork)) as cursor:
        cursor.execute(
            sql.SQL(
                "select cluster, observed_at, outcome, result, warnings, error, poll_error "
                "from cluster_network {scope} order by observed_at asc"
            ).format(scope=sql.SQL("where cluster = %(cluster)s" if cluster is not None else "")),
            {"cluster": cluster},
        )
        return cursor.fetchall()


def record_cluster_settings(
    connection: Connection[Any],
    *,
    cluster: str,
    outcome: str,
    result: Mapping[str, Any],
    warnings: Any = None,
    error: Mapping[str, Any] | None = None,
    poll_error: str | None = None,
) -> None:
    """Replace one cluster's cached settings with the newest helper answer."""

    with connection.cursor() as cursor:
        cursor.execute(
            "insert into cluster_settings (cluster, outcome, result, warnings, error, poll_error) "
            "values (%(cluster)s, %(outcome)s, %(result)s, %(warnings)s, %(error)s, %(poll)s) "
            "on conflict (cluster) do update set "
            "    outcome = excluded.outcome, "
            "    result = excluded.result, "
            "    warnings = excluded.warnings, "
            "    error = excluded.error, "
            "    poll_error = excluded.poll_error",
            {
                "cluster": cluster,
                "outcome": outcome,
                "result": Jsonb(dict(result)),
                "warnings": Jsonb(list(warnings or [])),
                "error": None if error is None else Jsonb(dict(error)),
                "poll": poll_error,
            },
        )


def record_cluster_list(connection: Connection[Any], clusters: Sequence[str]) -> None:
    """Replace the list of clusters that exist with the poller's newest reading."""

    with connection.cursor() as cursor:
        cursor.execute(
            "insert into cluster_list (clusters) values (%(clusters)s) "
            "on conflict (id) do update set clusters = excluded.clusters",
            {"clusters": Jsonb(list(clusters))},
        )


def replace_search_entries(
    connection: Connection[Any],
    *,
    cluster: str | None,
    source: str,
    entries: Sequence[search_index.Entry],
) -> int:
    """Replace what one reading of one cluster contributes to the search (B222).

    In the caller's transaction, so the search never sees the cluster with its
    old rows gone and its new ones not yet written.

    Rows that already say exactly this are left alone (review 2026-10-03, D5):
    most readings change nothing, and rewriting them every poll cost a delete
    and an insert in two indexes, one of them trigram, for each. Compared in
    the same transaction against what is stored, so a write that failed before
    is not mistaken for one that happened.
    """

    #
    # The manager's own rows have no cluster (B304), and `= null` matches none.
    #
    scope = sql.SQL(
        "where cluster is null and source = %(source)s"
        if cluster is None
        else "where cluster = %(cluster)s and source = %(source)s"
    )
    wanted = sorted(
        (entry.kind, entry.title, entry.label, entry.value, entry.href, entry.admin_only)
        for entry in entries
    )
    with connection.cursor() as cursor:
        cursor.execute(
            sql.SQL(
                "select kind, title, label, value, href, admin_only from search_entry {scope}"
            ).format(scope=scope),
            {"cluster": cluster, "source": source},
        )
        if sorted(tuple(row) for row in cursor.fetchall()) == wanted:
            return len(entries)
        cursor.execute(
            sql.SQL("delete from search_entry {scope}").format(scope=scope),
            {"cluster": cluster, "source": source},
        )
        cursor.executemany(
            "insert into search_entry "
            "(cluster, source, kind, title, label, value, href, admin_only) "
            "values (%(cluster)s, %(source)s, %(kind)s, %(title)s, %(label)s, %(value)s, "
            "%(href)s, %(admin_only)s)",
            [
                {
                    "cluster": entry.cluster,
                    "source": entry.source,
                    "kind": entry.kind,
                    "title": entry.title,
                    "label": entry.label,
                    "value": entry.value,
                    "href": entry.href,
                    "admin_only": entry.admin_only,
                }
                for entry in entries
            ],
        )
    return len(entries)


def prune_search_entries(connection: Connection[Any], clusters: Sequence[str]) -> int:
    """Remove what clusters that no longer exist left in the search."""

    with connection.cursor() as cursor:
        cursor.execute(
            "delete from search_entry "
            "where cluster is not null and not (cluster = any(%(clusters)s))",
            {"clusters": list(clusters)},
        )
        return cursor.rowcount


def backend_rows(
    connection: Connection[Any], *, cluster: str, addresses: Sequence[str]
) -> list[tuple[str, str, str]]:
    """(server, object, link) for the objects in `cluster` that name any of `addresses`."""

    if not addresses:
        return []
    with connection.cursor() as cursor:
        cursor.execute(
            "select value, title, href from search_entry "
            " where cluster = %(cluster)s and source = 'objects' and kind = 'proxy' "
            "   and label = %(label)s and value = any(%(addresses)s)",
            {
                "cluster": cluster,
                "label": search_index.BACKEND_LABEL,
                "addresses": list(addresses),
            },
        )
        return [(str(value), str(title), str(href)) for value, title, href in cursor.fetchall()]


def search(
    connection: Connection[Any],
    query: str,
    *,
    role: str,
    clusters: Sequence[str],
    page: int = 1,
) -> search_index.Results:
    """One page of the header's search, answered by the trigram index.

    Grouped per thing found, with every value of it that matched; a
    certificate is one thing however many clusters list it. The order and the
    page are the database's, so a page past the first costs what the first
    does.
    """

    query = search_index.normalise(query)
    if not query:
        return search_index.Results(query, (), 0, 1)
    page = max(1, page)
    kinds = list(search_index.KINDS)
    with connection.cursor() as cursor:
        cursor.execute(
            "select kind, shown_cluster, title, href, "
            "       string_agg(distinct case when label = '' then value "
            "                            else label || ' ' || value end, ', '), "
            "       count(*) over () "
            "  from (select kind, title, href, label, value, "
            "               case when kind = 'certificate' then '' else cluster end as shown_cluster "
            "          from search_entry "
            "         where lower(value) like %(pattern)s "
            "           and (cluster is null or cluster = any(%(clusters)s)) "
            "           and (%(admin)s or not admin_only)) hits "
            " group by kind, shown_cluster, title, href "
            " order by array_position(%(kinds)s::text[], kind), shown_cluster, lower(title) "
            " limit %(limit)s offset %(offset)s",
            {
                "pattern": like_pattern(query),
                "clusters": list(clusters),
                "admin": role == "admin",
                "kinds": kinds,
                "limit": search_index.PAGE_SIZE,
                "offset": (page - 1) * search_index.PAGE_SIZE,
            },
        )
        rows = cursor.fetchall()
    total = int(rows[0][5]) if rows else 0
    hits = [
        search_index.Hit(
            kind=kind,
            cluster=cluster or None,
            title=title,
            matched=matched or "",
            href=search_index.reader_href(kind, href, role),
        )
        for kind, cluster, title, href, matched, _total in rows
    ]
    return search_index.Results(query, search_index.grouped(hits), total, page)


def cluster_list(connection: Connection[Any]) -> tuple[str, ...] | None:
    """The clusters the poller last read from the cluster file, in its order; None before it has."""

    with connection.cursor() as cursor:
        cursor.execute("select clusters from cluster_list where id = 1")
        row = cursor.fetchone()
    if row is None or not isinstance(row[0], list):
        return None
    return tuple(str(name) for name in row[0])


def cluster_list_observed(connection: Connection[Any]) -> datetime | None:
    """When the poller last wrote the cluster list - it does on every pass; None before the first."""

    with connection.cursor() as cursor:
        cursor.execute("select observed_at from cluster_list where id = 1")
        row = cursor.fetchone()
    return None if row is None else row[0]


def retention_completed(connection: Connection[Any]) -> datetime | None:
    """When `haprion-retention prune` last finished a whole run (0090, 05-09)."""

    with connection.cursor() as cursor:
        cursor.execute("select completed_at from retention_run")
        row = cursor.fetchone()
    return row[0] if row else None


def partition_horizons(
    connection: Connection[Any], tables: Iterable[str]
) -> dict[str, date | None]:
    """The last day each partitioned table has a partition for, from the catalog.

    Partitions are named `<table>_YYYYMMDD` by the functions that make them;
    a default partition has no date and is not counted. None for a table with
    no dated partition, or that does not exist.
    """

    names = list(tables)
    with connection.cursor() as cursor:
        cursor.execute(
            "select parent.relname, max(substring(child.relname from '_([0-9]{8})$')) "
            "  from pg_inherits "
            "  join pg_class parent on parent.oid = pg_inherits.inhparent "
            "  join pg_class child on child.oid = pg_inherits.inhrelid "
            " where parent.relname = any(%(names)s) "
            " group by parent.relname",
            {"names": names},
        )
        found = {str(name): last for name, last in cursor.fetchall()}
    return {
        name: datetime.strptime(found[name], "%Y%m%d").date() if found.get(name) else None
        for name in names
    }


def begin_cluster_pass(connection: Connection[Any], cluster: str) -> None:
    """Mark the start of a pass over one cluster (0068). The moment is the database's."""

    with connection.cursor() as cursor:
        cursor.execute(
            "insert into cluster_pass (cluster) values (%(cluster)s) "
            "on conflict (cluster) do update set began_at = statement_timestamp()",
            {"cluster": cluster},
        )


def settle_cluster_pass(connection: Connection[Any], cluster: str) -> None:
    """Every reading of the pass begun last is recorded: it is what the cluster is read through."""

    with connection.cursor() as cursor:
        cursor.execute(
            "update cluster_pass set settled_from = began_at where cluster = %(cluster)s",
            {"cluster": cluster},
        )


def clusters_catching_up(
    connection: Connection[Any], clusters: Sequence[str], *, within: timedelta
) -> list[str]:
    """The clusters whose last finished job no whole pass has read since (0068).

    A job that ended more than `within` ago is caught up whatever the poller
    did: a poller that is down must not leave a page waiting on it for good,
    and the pages say for themselves how old their readings are. Only a
    cluster's two newest jobs are looked at - one runs at a time, so the newest
    finished one is among them - which the job's own index answers.
    """

    with connection.cursor() as cursor:
        cursor.execute(
            "select c.cluster"
            "  from unnest(%(clusters)s::text[]) as c (cluster)"
            "  cross join lateral ("
            "      select max(recent.finished_at) as finished"
            "        from (select finished_at from job"
            "               where job.cluster = c.cluster"
            "               order by created_at desc limit 2) recent"
            "  ) last"
            "  left join cluster_pass p on p.cluster = c.cluster"
            " where last.finished > statement_timestamp() - %(within)s"
            "   and (p.settled_from is null or p.settled_from <= last.finished)"
            " order by c.cluster",
            {"clusters": list(clusters), "within": within},
        )
        return [str(cluster) for (cluster,) in cursor.fetchall()]


def cluster_settings(connection: Connection[Any]) -> list[ClusterSettingsRow]:
    """Every cluster's newest settings reading, with the stalest one first."""

    with connection.cursor(row_factory=class_row(ClusterSettingsRow)) as cursor:
        cursor.execute(
            "select cluster, observed_at, outcome, result, warnings, error, poll_error "
            "  from cluster_settings "
            " order by observed_at asc"
        )
        return cursor.fetchall()


def record_cluster_objects(
    connection: Connection[Any],
    *,
    cluster: str,
    outcome: str,
    result: Mapping[str, Any],
    warnings: Any = None,
    error: Mapping[str, Any] | None = None,
    poll_error: str | None = None,
) -> None:
    """Replace one cluster's cached objects with the newest helper answer.

    Or confirm them, when the helper said the listing the poller holds still
    stands (B222): an update that changes nothing, which the table's trigger
    turns into a fresh `observed_at`. Rewriting the same eight megabytes every
    pass to say the same thing was the cost this avoids.
    """

    if outcome == "done" and result.get("unchanged") is True:
        with connection.cursor() as cursor:
            cursor.execute(
                "update cluster_objects set outcome = outcome "
                " where cluster = %(cluster)s and outcome = 'done'",
                {"cluster": cluster},
            )
        return

    with connection.cursor() as cursor:
        cursor.execute(
            "insert into cluster_objects (cluster, outcome, result, warnings, error, poll_error) "
            "values (%(cluster)s, %(outcome)s, %(result)s, %(warnings)s, %(error)s, %(poll)s) "
            "on conflict (cluster) do update set "
            "    outcome = excluded.outcome, "
            "    result = excluded.result, "
            "    warnings = excluded.warnings, "
            "    error = excluded.error, "
            "    poll_error = excluded.poll_error",
            {
                "cluster": cluster,
                "outcome": outcome,
                "result": Jsonb(dict(result)),
                "warnings": Jsonb(list(warnings or [])),
                "error": None if error is None else Jsonb(dict(error)),
                "poll": poll_error,
            },
        )


def objects_fingerprint(connection: Connection[Any], cluster: str) -> str | None:
    """The fingerprint of the objects listing the poller holds, if it holds one."""

    with connection.cursor() as cursor:
        cursor.execute(
            "select result ->> 'fingerprint' from cluster_objects "
            " where cluster = %(cluster)s and outcome = 'done'",
            {"cluster": cluster},
        )
        row = cursor.fetchone()
    return row[0] if row is not None and isinstance(row[0], str) else None


def cluster_objects(
    connection: Connection[Any], *, cluster: str | None = None
) -> list[ClusterObjects]:
    """Every cluster's newest objects reading, with the stalest one first."""

    with connection.cursor(row_factory=class_row(ClusterObjects)) as cursor:
        cursor.execute(
            sql.SQL(
                "select cluster, observed_at, outcome, result, warnings, error, poll_error "
                "from cluster_objects {scope} order by observed_at asc"
            ).format(scope=sql.SQL("where cluster = %(cluster)s" if cluster is not None else "")),
            {"cluster": cluster},
        )
        return cursor.fetchall()
