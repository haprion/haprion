"""The addresses the nodes share their stick tables at (B270).

Looked up from each node's `mgmt_host` when a cluster that shares its tables
is published, never stored: a node that changes address keeps needing only its
DNS record and keepalived changed, and the next publish follows. The manager
already reaches the nodes by the same names, so this adds no dependency on DNS
that was not there.

HAProxy reads a `peer` line's address when it loads the configuration, so what
is written is the address and never the name: a name that does not resolve at
a node's reload would stop HAProxy there.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable, Sequence
from typing import Any

from haprion.config import Cluster, ConfigError

Lookup = Callable[..., Sequence[tuple[Any, ...]]]


def addresses(cluster: Cluster, lookup: Lookup = socket.getaddrinfo) -> tuple[tuple[str, str], ...]:
    """Each node's name and the one address its `mgmt_host` gives, in the cluster's order.

    One address and no choice among several. Two would be a guess about which
    one the other node reaches, and a wrong guess is a section that never
    connects while every publish reports success.
    """

    found: list[tuple[str, str]] = []
    for node in cluster.nodes:
        try:
            answers = lookup(node.mgmt_host, None, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise ConfigError(
                f"cannot look up {node.mgmt_host} for node {node.name}, which sharing counters "
                f"needs: {exc}"
            ) from exc
        unique = sorted({str(ipaddress.ip_address(answer[4][0])) for answer in answers})
        if len(unique) != 1:
            shown = ", ".join(unique) if unique else "no address"
            raise ConfigError(
                f"{node.mgmt_host} for node {node.name} gives {shown}; sharing counters needs "
                "exactly one address per node"
            )
        found.append((node.name, unique[0]))
    return tuple(found)
