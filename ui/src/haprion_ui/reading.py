"""What a page reads before it draws: the cluster list and the poller's readings (K01, review 2026-10-28).

The pages read the manager's state through the poller's cache, never from the
nodes. A `Source` names one cached reading; `read_source` gives every listed
cluster's row of it, or none, as one consistent pair with the cluster list.
`read_concurrently` runs independent reads on their own connections.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import Request

from haprion_ui import (
    cluster_nodes,
    db,
    demo,
)
from haprion_ui.config import Config

#
# How many of a traffic page's readings run at once, each on its own pooled
# connection. Every card asks two questions - its line and its figures - and
# the answers are independent, so asking them one after another only added
# their times up. Measured 2026-10-01 against a copy at production density
# (two clusters, a week of raw samples every 20 s, the hourly rollup behind
# it) with PostgreSQL held to two CPUs, the size this installation is built
# for: the 7- and 30-day windows took 1.28 s in sequence, 0.85 s two at a
# time, and four bought nothing more on two cores - it only took them from the
# poller and the worker.
#
TRAFFIC_READERS = 2


def read_concurrently[T](pool: Any, reads: Sequence[Callable[[Any], T]]) -> list[T]:
    """Each read on a connection of its own, at most `TRAFFIC_READERS` at once.

    The answers come back in the order asked. A read that fails fails the page,
    as it did when they ran one by one.
    """

    def run(read: Callable[[Any], T]) -> T:
        with pool.connection() as connection:
            return read(connection)

    if len(reads) <= 1:
        return [run(read) for read in reads]
    #
    # A thread does not inherit the request's context. Each read runs in a copy
    # of it, so its queries are counted with the page that asked (`timing`).
    #
    context = copy_context()
    with ThreadPoolExecutor(max_workers=TRAFFIC_READERS) as readers:
        return list(readers.map(lambda read: context.copy().run(run, read), reads))


@dataclass(frozen=True, slots=True)
class Source:
    """Where one kind of cached reading comes from, in each of the two modes.

    A page must never choose its own source: an interface can be showing the
    synthetic fixture, and a view that reached the database directly would
    quietly show real rows on a page labelled as fixture data. Stated once, per kind of reading, so a new page
    picks a source rather than inventing one.
    """

    demo_rows: Callable[[], Iterable[Any]]
    cached_rows: Callable[[Any], Iterable[Any]]
    scoped_rows: Callable[[Any, str], Iterable[Any]] | None = None


#
# The cached readers are wrapped rather than referenced, so the lookup happens
# when the page is rendered. Binding `db.cluster_statuses` here would capture the
# function at import and quietly ignore a test that replaces it.
#
STATUS_SOURCE = Source(
    demo.status_rows,
    lambda connection: db.cluster_statuses(connection),
)

INVENTORY_SOURCE = Source(
    demo.inventory_rows,
    lambda connection: db.cluster_inventories(connection),
)

HISTORY_SOURCE = Source(
    demo.history_rows,
    lambda connection: db.cluster_histories(connection),
    lambda connection, cluster: db.cluster_histories(connection, cluster=cluster),
)

BACKUP_SOURCE = Source(
    demo.backup_rows,
    lambda connection: db.cluster_backups(connection),
)

CERTIFICATE_SOURCE = Source(
    demo.certificate_rows,
    lambda connection: db.cluster_certificates(connection),
    lambda connection, cluster: db.cluster_certificates(connection, cluster=cluster),
)

NETWORK_SOURCE = Source(
    demo.network_rows,
    lambda connection: db.cluster_networks(connection),
    lambda connection, cluster: db.cluster_networks(connection, cluster=cluster),
)

#
# The cluster's own settings (Fas 15).
#
SETTINGS_SOURCE = Source(
    demo.settings_rows,
    lambda connection: db.cluster_settings(connection),
)

OBJECTS_SOURCE = Source(
    demo.object_rows,
    lambda connection: db.cluster_objects(connection),
    lambda connection, cluster: db.cluster_objects(connection, cluster=cluster),
)

#
# The readings the header's search covers, by the operation that wrote them
# (B222). The cluster list is the fifth, and is not a reading.
#
SEARCHED_SOURCES = (
    ("objects", OBJECTS_SOURCE),
    ("network", NETWORK_SOURCE),
    ("cert_list", CERTIFICATE_SOURCE),
    ("status", STATUS_SOURCE),
)


def listed_clusters(request: Request, config: Config) -> tuple[str, ...]:
    """The clusters this interface shows, in the order it shows them."""

    if config.demo_fixture:
        return demo.CLUSTERS
    #
    # The clusters the poller last read from the cluster file (B206), so one
    # created or removed from Settings is on the pages at the next pass.
    # `ui.toml`'s list only until the poller has written one.
    #
    return _cluster_list(request, config)[0]


def cluster_creations(request: Request, recent: list[Any]) -> list[cluster_nodes.Creating]:
    """Clusters being created that the list does not show yet (finding 51)."""

    config = request.app.state.config
    return cluster_nodes.creations(
        recent,
        listed_clusters(request, config),
        now=datetime.now(UTC),
        settle=timedelta(seconds=config.poller.interval_seconds * 2),
    )


def _cluster_list(request: Request, config: Config) -> tuple[tuple[str, ...], bool]:
    """The live list and whether it came from the cluster file rather than `ui.toml`."""

    with request.app.state.pool.connection() as connection:
        listed = db.cluster_list(connection)
    # Empty is an answer (B302): no cluster yet, or the last one removed.
    return (listed, True) if listed is not None else (config.clusters, False)


def read_source(
    request: Request,
    config: Config,
    source: Source,
    *,
    cluster: str | None = None,
    clusters: tuple[str, ...] | None = None,
) -> tuple[tuple[str, ...], Iterable[Any]]:
    """The clusters to render and their newest readings."""

    if config.demo_fixture:
        # The fixture times its readings from the moment it is read, so it needs
        # no clock of its own; it is never stale.
        return (
            demo.CLUSTERS,
            [
                row
                for row in source.demo_rows()
                if cluster is None or getattr(row, "cluster", None) == cluster
            ],
        )
    listed, from_file = _cluster_list(request, config) if clusters is None else (clusters, True)
    if cluster is not None and cluster not in listed:
        return listed, ()
    with request.app.state.pool.connection() as connection:
        rows = (
            source.scoped_rows(connection, cluster)
            if cluster is not None and source.scoped_rows is not None
            else source.cached_rows(connection)
        )
    if cluster is not None:
        rows = [row for row in rows if getattr(row, "cluster", None) == cluster]
    #
    # A cluster the cluster file no longer names has been removed (Settings or
    # `haprion-cluster remove`), and its last cached readings are never deleted:
    # the poller has no delete privilege. Drawn, it stayed on every page as "Not
    # configured" for good (review 2026-09-30 F1). With the list from `ui.toml`
    # the old card stays, because there a removal is a hand edit worth seeing.
    #
    if from_file:
        rows = [row for row in rows if getattr(row, "cluster", None) in listed]
    return listed, rows


def read_manager_certificates(request: Request, config: Config) -> db.ManagerCertificates | None:
    """What the manager holds - the registry, what the interface is served
    with - read whether or not a cluster exists (B304)."""

    if config.demo_fixture:
        return demo.manager_certificates()
    with request.app.state.pool.connection() as connection:
        return db.manager_certificates(connection)


def read_certificate_takeouts(request: Request, config: Config) -> dict[str, db.TakenOut] | None:
    """The newest download per external certificate (26-10-18); None in the demo,
    which has no audit trail and keeps the rows it always had."""

    if config.demo_fixture:
        return None
    with request.app.state.pool.connection() as connection:
        return db.certificate_takeouts(connection)
