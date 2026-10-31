"""What one object's page and the API read about it: the stored document beside what is served.

Both ask the same cached readings and put them together the same way, so the
object page and `GET .../objects/{name}` cannot say different things about one
object (the listing and the page did, before they shared `health.object_states`).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from fastapi import Request

from haprion_ui import dashboard, db, health, history, network, objects, proxies
from haprion_ui.config import Config
from haprion_ui.reading import (
    HISTORY_SOURCE,
    INVENTORY_SOURCE,
    NETWORK_SOURCE,
    OBJECTS_SOURCE,
    STATUS_SOURCE,
    read_source,
)


@dataclass(frozen=True, slots=True)
class ObjectReading:
    detail: objects.ObjectDetail
    #
    # The readings the detail was put together from, for the parts of the page
    # that read further into them.
    #
    written: objects.ObjectView | None
    described: network.NetworkClusterView | None
    status_rows: tuple[Any, ...]
    object_rows: tuple[Any, ...]


def read_object(
    request: Request, config: Config, clusters: Iterable[str], cluster: str, name: str
) -> ObjectReading:
    """One object of a listed cluster: its stored document and publication."""

    clusters = tuple(clusters)
    _, object_rows = read_source(request, config, OBJECTS_SOURCE)
    _, inventory_rows = read_source(request, config, INVENTORY_SOURCE)
    overview = proxies.build_proxy_overview(
        clusters,
        inventory_rows,
        stale_after=config.poller.stale_after,
    )
    published = tuple(
        proxy for view in overview.clusters if view.cluster == cluster for proxy in view.proxies
    )
    _, history_rows = read_source(request, config, HISTORY_SOURCE)
    listing = history.build_history_overview(
        clusters,
        history_rows,
        stale_after=config.poller.stale_after,
    )
    versions = tuple(
        version for view in listing.clusters if view.cluster == cluster for version in view.versions
    )
    #
    # Released is not serving, so the deploy state is read too. Reporting a
    # release as live while every node still pulls the previous one is the
    # one thing this card must not do.
    #
    _, status_rows = read_source(request, config, STATUS_SOURCE)
    board = dashboard.build_dashboard(
        clusters,
        status_rows,
        stale_after=config.poller.stale_after,
    )
    serving = next((view for view in board.clusters if view.cluster == cluster), None)
    #
    # What the nodes report, not the target they were given. The cluster
    # view's `version` is the version they are meant to reach, so using it
    # here would have the page say "the nodes are on v29" at the exact
    # moment they are not.
    #
    running = sorted({node.version for node in serving.nodes}) if serving else []
    node_version = running[0] if len(running) == 1 else ", ".join(running)
    #
    # An object that names no VIP is served on the cluster's default, which
    # is why the address is read from the network description rather than
    # from the object.
    #
    # The object's own VIP where it names one (B221, 2026-10-01): until
    # then this said "default" for every object, including one served on
    # another address. The default below is for an object with no stored
    # document, served from configuration not written here.
    #
    _, network_rows = read_source(request, config, NETWORK_SOURCE)
    network_rows = tuple(network_rows)
    object_rows = tuple(object_rows)
    status_rows = tuple(status_rows)
    written = next(
        (
            view
            for row in object_rows
            if row.cluster == cluster
            for view in objects.cluster_object_views(row)
            if view.name == name
        ),
        None,
    )
    # As the objects helper reported it (B222).
    resolved = written.addresses if written is not None else None
    described = next(
        (
            view
            for view in network.build_network_overview(
                clusters,
                network_rows,
                stale_after=config.poller.stale_after,
            )
            if view.cluster == cluster
        ),
        None,
    )
    vip = next((item for item in described.vips if item.is_default), None) if described else None
    #
    # Whether *this* object is one the pending deploy carries. The release
    # state is the cluster's, and wearing it here told somebody opening an
    # untouched site that it was waiting for a deploy - the same mistake
    # the listing rows made before they were given this per-object answer.
    #
    object_state = health.object_states(status_rows, cluster=cluster).get(name, objects.UNKNOWN)
    #
    # The same fallback the listing uses, so the two pages cannot say
    # different things about one object. Where the releases cannot be
    # compared, a publish job naming this object is still a fact about
    # something that happened - and it is asked only for that.
    #
    if object_state == objects.UNKNOWN:
        with request.app.state.pool.connection() as connection:
            carried = objects.carried_since_deploy(db.recent_jobs(connection, cluster=cluster))
        if name in carried:
            object_state = objects.CHANGED
    detail = objects.build_object_detail(
        cluster,
        name,
        object_rows,
        published,
        versions,
        release_state=serving.release_state if serving else "",
        node_version=node_version,
        object_state=object_state,
        vip=resolved.vip_name if resolved else (vip.name if vip else None),
        vip_address=(resolved.vip.address or None) if resolved else (vip.address if vip else None),
        vip_is_default=resolved.vip_is_default if resolved else vip is not None,
        stale_after=config.poller.stale_after,
    )
    return ObjectReading(
        detail=detail,
        written=written,
        described=described,
        status_rows=status_rows,
        object_rows=object_rows,
    )
