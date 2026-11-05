"""Ports other programs hold on every address of a cluster's nodes (26-10-15).

A program listening on every address - a monitoring agent on `0.0.0.0:6556` -
holds its port on the VIP as well, and an object on that port cannot bind it
there: the deploy fails on `cannot bind socket` and rolls back. The manager
cannot know this from the configuration, so a publish asks the nodes, through
the status reading the poller makes every minute, and refuses the object before
anything is deployed.

A node that does not answer is not a reason to stop a publish: the deploy's
rollback still catches the collision, and a node that is down must not block
every change to the cluster. Its ports are simply not checked there, and the
publish says so when an object starts to need what only a node can have.

The same reading says what each node that answered can serve: the WAF engine,
dnsdist, the syslog objects' file. An object that needs one a node lacks is
refused here, for the terminal, the page and the API alike (K04, 26-11-05).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from haprion.cluster_status import ClusterStatus, StatusError
from haprion.config import Cluster, PathPolicy

if TYPE_CHECKING:
    from haprion.proxy_model import Proxy

type Holders = tuple[tuple[str, str | None], ...]


@dataclass(frozen=True, slots=True)
class HeldPorts:
    """(protocol, port) to the (node, program) pairs holding it."""

    held: Mapping[tuple[str, int], Holders] = field(default_factory=dict)
    lacking: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    """Per feature (`waf`, `dns`, `syslog`), the nodes that answered and cannot serve it."""
    unchecked: tuple[str, ...] = ()
    """The nodes nothing was read from - all of them when the reading failed altogether."""


def from_status(status: ClusterStatus) -> HeldPorts:
    held: dict[tuple[str, int], list[tuple[str, str | None]]] = {}
    for node in status.nodes:
        if not node.status_ok or node.wildcard_listeners is None:
            continue
        for protocol, port, program in node.wildcard_listeners:
            held.setdefault((protocol, port), []).append((node.name, program))
    lacking: dict[str, tuple[str, ...]] = {}
    for feature, attribute in (
        ("waf", "waf_engine_installed"),
        ("dns", "dns_listener_installed"),
        ("syslog", "ipvs_included"),
    ):
        names = tuple(
            sorted(
                node.name
                for node in status.nodes
                if node.status_ok and getattr(node, attribute) is not True
            )
        )
        if names:
            lacking[feature] = names
    return HeldPorts(
        held={key: tuple(holders) for key, holders in sorted(held.items())},
        lacking=lacking,
        unchecked=tuple(sorted(node.name for node in status.nodes if not node.status_ok)),
    )


def read(policy: PathPolicy, cluster: Cluster) -> HeldPorts:
    """The nodes' answer, by the status identity the deploy reads them with."""

    everyone = tuple(sorted(node.name for node in cluster.nodes))
    if policy.status_identity is None:
        return HeldPorts(unchecked=everyone)
    #
    # Imported here: the deploy helper is a command module, and the reading is
    # its `read_status` so a publish and a deploy ask the nodes one way.
    #
    from haprion.cli.deploy_helper import read_status

    try:
        return from_status(read_status(cluster, policy.status_identity))
    except (StatusError, OSError):
        return HeldPorts(unchecked=everyone)


def _joined(names: tuple[str, ...]) -> str:
    return names[0] if len(names) == 1 else f"{', '.join(names[:-1])} and {names[-1]}"


def _needs(proxy: Proxy | None) -> frozenset[str]:
    """The node features an object needs: the WAF engine, dnsdist, the syslog file."""

    if proxy is None:
        return frozenset()
    found = set()
    if proxy.inspected is not None:
        found.add("waf")
    if proxy.listen.protocol in ("dns", "syslog"):
        found.add(proxy.listen.protocol)
    return frozenset(found)


def starting_needs(written: Proxy, stored: Proxy | None) -> frozenset[str]:
    """What this object starts to need from the nodes: the part of `_needs` it did not need before."""

    return _needs(written) - _needs(stored)


FEATURES = {"waf": "the WAF engine", "dns": "dnsdist", "syslog": "the syslog file's include"}


def unchecked_warning(nodes: Sequence[str], features: Sequence[str]) -> str:
    """What is said when an object starts to need a feature and a node was not asked."""

    wanted = [FEATURES[feature] for feature in features if feature in FEATURES]
    return (
        f"{_joined(tuple(nodes))} did not answer, so {_joined(tuple(wanted))} could not be "
        "checked there; the deploy refuses the release on a node that lacks it"
    )


def node_refusal(held: HeldPorts, name: str, written: Proxy, stored: Proxy | None) -> str:
    """Why this object may not be published for the nodes that answered; empty when it may.

    One rule for every way in. Only what the object starts to need is held to
    it: one that already needed the feature keeps, changes or turns it off, as
    the page allows for the WAF engine. A node that did not answer is not asked
    (see the top of this module).
    """

    starting = starting_needs(written, stored)
    if "waf" in starting and (nodes := held.lacking.get("waf")):
        return (
            f"The WAF engine is not installed on {_joined(nodes)}, so {name} cannot start using it."
        )
    if "dns" in starting and (nodes := held.lacking.get("dns")):
        return f"{name} is a DNS object and dnsdist is not installed on {_joined(nodes)}."
    if "syslog" in starting and (nodes := held.lacking.get("syslog")):
        return (
            f"{name} is a syslog object and keepalived on {_joined(nodes)} does not read the "
            "file the syslog objects are written to."
        )
    return ""
