"""One cluster's network description, as a document rather than as objects.

The tables an object points at - the addresses it can be served on, the
addresses it can leave from, and the groups it can be restricted to - shaped
for a caller that is not the generator. The interface reads this; so does an
operator running ``haproxy-network``, and both get the same answer because
there is only one function producing it.

Two fields exist for the reader rather than for the configuration. ``origin``
says whether the description was read from the cluster repository or derived
from the engine's own configuration, because only the first can be edited
through the publish path - a derived table can be shown and never changed.
``ownership_vip`` is reported and is deliberately not part of any table: it is
the address ``deploy`` checks node ownership against, it lives outside the
repository on purpose, and a reader that offers to edit the other addresses has
to be able to say why it will not offer to edit that one.
"""

from __future__ import annotations

from typing import Any

from haproxy_mgmt.config import Cluster
from haproxy_mgmt.managed_publish import managed_proxies
from haproxy_mgmt.repo_snapshot import read_tree_files, resolve_head


def network_result(cluster: Cluster) -> dict[str, Any]:
    """Everything a reader needs about where this cluster's traffic goes."""

    network = cluster.network()
    # The page's address table is a cached read, so the compare-and-swap value
    # has to travel with the same observation.  A write built from an older
    # observation is refused by the publishing helper instead of replacing a
    # newer network description it has not shown the operator.
    _branch, head = resolve_head(cluster.config_path)
    files = read_tree_files(cluster.config_path, head)
    default_vip_object_count = sum(proxy.listen.vip is None for proxy in managed_proxies(files))
    return {
        "cluster": cluster.cluster_id,
        "head": head,
        "origin": "repository" if network.from_repository else "cluster_file",
        "ownership_vip": cluster.vip,
        "default_vip": network.default_vip,
        "default_vip_object_count": default_vip_object_count,
        "vips": [
            {"name": vip.name, "address": vip.address, "source": vip.source}
            for vip in sorted(network.vips.values(), key=lambda entry: entry.name)
        ],
        "sources": [
            {"name": name, "address": network.sources[name]} for name in sorted(network.sources)
        ],
        "groups": [
            {"name": name, "members": list(network.networks[name])}
            for name in sorted(network.networks)
        ],
    }
