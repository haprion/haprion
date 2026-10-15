"""Ports other programs hold on every address of a cluster's nodes (26-10-15).

A program listening on every address - a monitoring agent on `0.0.0.0:6556` -
holds its port on the VIP as well, and an object on that port cannot bind it
there: the deploy fails on `cannot bind socket` and rolls back. The manager
cannot know this from the configuration, so a publish asks the nodes, through
the status reading the poller makes every minute, and refuses the object before
anything is deployed.

A node that does not answer is not a reason to stop a publish: the deploy's
rollback still catches the collision, and a node that is down must not block
every change to the cluster. It is named instead (`unread`), and the publish
says the ports were not checked there.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from haprion.cluster_status import ClusterStatus, StatusError
from haprion.config import Cluster, PathPolicy

type Holders = tuple[tuple[str, str | None], ...]


@dataclass(frozen=True, slots=True)
class HeldPorts:
    """(protocol, port) to the (node, program) pairs holding it, and the nodes not read."""

    held: Mapping[tuple[str, int], Holders] = field(default_factory=dict)
    unread: tuple[str, ...] = ()


def from_status(status: ClusterStatus) -> HeldPorts:
    held: dict[tuple[str, int], list[tuple[str, str | None]]] = {}
    unread: list[str] = []
    for node in status.nodes:
        if not node.status_ok or node.wildcard_listeners is None:
            unread.append(node.name)
            continue
        for protocol, port, program in node.wildcard_listeners:
            held.setdefault((protocol, port), []).append((node.name, program))
    return HeldPorts(
        held={key: tuple(holders) for key, holders in sorted(held.items())},
        unread=tuple(unread),
    )


def read(policy: PathPolicy, cluster: Cluster) -> HeldPorts:
    """The nodes' answer, by the status identity the deploy reads them with."""

    names = tuple(node.name for node in cluster.nodes)
    if policy.status_identity is None:
        return HeldPorts(unread=names)
    #
    # Imported here: the deploy helper is a command module, and the reading is
    # its `read_status` so a publish and a deploy ask the nodes one way.
    #
    from haprion.cli.deploy_helper import read_status

    try:
        return from_status(read_status(cluster, policy.status_identity))
    except (StatusError, OSError):
        return HeldPorts(unread=names)
