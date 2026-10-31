"""What the stored objects add to a read of the traffic log.

Two things the rows alone do not know: the destination behind a generated
server name (`s1`), and which backends and hostnames one object owns. The
traffic log page and the API's traffic route both ask here, so a row means the
same in both.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from haprion.proxy_model import ModelError, load_proxy

from haprion_ui import objects, traffic_logs

type Owned = tuple[tuple[str, ...], tuple[str, ...]]


def log_scope(
    object_rows: Iterable[Any], *, cluster: str, selected_object: str
) -> tuple[dict[tuple[str, str, str], str], Owned | None]:
    """The server addresses of every cluster read, and one object's backends and hostnames.

    `owned` is None when no object is selected. An object the cluster does not
    have is owned by nothing, so it matches no request rather than every one.
    """

    server_addresses: dict[tuple[str, str, str], str] = {}
    owned: Owned | None = ((), ()) if selected_object else None
    for object_row in object_rows:
        views = objects.cluster_object_views(object_row)
        if selected_object and object_row.cluster == cluster:
            found = next((view for view in views if view.name == selected_object), None)
            if found is not None:
                owned = (
                    tuple(found.runtime_backends or ()),
                    traffic_logs.owned_hosts(
                        found.hostnames,
                        (
                            name
                            for view in views
                            if view.name != found.name
                            for name in view.hostnames
                        ),
                    ),
                )
        parsed = []
        for view in views:
            if not view.readable:
                continue
            try:
                parsed.append(load_proxy(view.name, view.document.encode()))
            except (ModelError, UnicodeError):
                continue
        server_addresses.update(
            traffic_logs.configured_server_addresses(object_row.cluster, parsed)
        )
    return server_addresses, owned
