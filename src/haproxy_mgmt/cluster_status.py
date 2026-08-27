"""Reading a cluster status result, once, for everyone who needs one.

`haproxy-status-root` answers in the frozen schema in
`schemas/v1/haproxy-status.schema.json`. Deploy needs to know who owns the VIP
and what each node is running; the interface will need the same answer later,
and the poller after that. Every one of them reading the payload its own way is
how they end up disagreeing about whether it is safe to act.

Deliberately defensive about shape
----------------------------------
A node status arrives over SSH from a machine this code does not control, and
the helper that collects it treats "the JSON parsed" as "the status is valid".
It is not the same thing: `null` parses, and so does a list. A payload that is
merely well-formed must therefore not be able to make a reader crash - it has to
come back as a node whose status could not be used, which is a state the matrix
already knows how to handle.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from haproxy_mgmt.deploy_plan import ClusterObservation, NodeObservation, VipState

#
# Exit codes carried over from the command being replaced: bad input is the
# caller's fault, anything else means the cluster could not be read.
#
EXIT_BAD_INPUT = 64
EXIT_UNAVAILABLE = 68


class StatusError(Exception):
    """The status result could not be used at all."""

    def __init__(self, message: str, *, exit_code: int = EXIT_UNAVAILABLE):
        super().__init__(message)
        self.exit_code = exit_code


@dataclass(frozen=True, slots=True)
class NodeStatus:
    name: str
    mgmt_host: str
    reachable: bool
    status_ok: bool
    owns_vip: bool | None
    release_hash: str | None
    error_code: str | None


@dataclass(frozen=True, slots=True)
class ClusterStatus:
    cluster: str | None
    nodes: tuple[NodeStatus, ...]
    vip_state: VipState
    vip_owners: tuple[str, ...]
    warnings: tuple[str, ...]

    def observation(self) -> ClusterObservation:
        """The same reading, in the terms the deploy matrix decides in."""

        return ClusterObservation(
            nodes=tuple(
                NodeObservation(
                    name=node.name,
                    status_ok=node.status_ok,
                    owns_vip=node.owns_vip,
                    release_hash=node.release_hash,
                )
                for node in self.nodes
            ),
            vip_state=self.vip_state,
        )

    def node(self, name: str) -> NodeStatus:
        for node in self.nodes:
            if node.name == name:
                return node
        raise StatusError(f"the status result does not mention node '{name}'")


def _mapping(value: object) -> Mapping[str, Any]:
    """A mapping, or an empty one. Never an exception, never a crash."""

    return value if isinstance(value, Mapping) else {}


def _text(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _node(entry: Mapping[str, Any]) -> NodeStatus:
    status = _mapping(entry.get("status"))
    #
    # `status_ok` is only believed when the status is actually a mapping. The
    # collecting helper sets it as soon as the JSON parsed, so a node that
    # answered `null` arrives here claiming a status it does not have.
    #
    usable = bool(entry.get("status_ok")) and bool(status)
    owner = _mapping(status.get("vip")).get("owner")
    return NodeStatus(
        name=str(entry.get("name", "")),
        mgmt_host=str(entry.get("mgmt_host", "")),
        reachable=bool(entry.get("reachable")),
        status_ok=usable,
        owns_vip=owner if isinstance(owner, bool) else None,
        release_hash=_text(_mapping(status.get("release")).get("hash")),
        error_code=_text(_mapping(entry.get("error")).get("code"))
        or (None if usable else "node_status_invalid"),
    )


def parse_status(payload: object) -> ClusterStatus:
    """One status envelope, turned into something worth deciding on.

    Raises rather than returning a half-empty result when the envelope itself is
    unusable: a deploy that proceeds on a status it could not read is the exact
    failure the whole two-tree model exists to prevent.
    """

    envelope = _mapping(payload)
    if not envelope:
        raise StatusError("the status helper did not return a usable result")

    result = envelope.get("result")
    if not isinstance(result, Mapping):
        error = _mapping(envelope.get("error"))
        message = _text(error.get("message")) or "cluster status unavailable"
        code = EXIT_BAD_INPUT if error.get("code") == "bad_input" else EXIT_UNAVAILABLE
        raise StatusError(message, exit_code=code)

    entries = result.get("nodes")
    if not isinstance(entries, Sequence) or isinstance(entries, str | bytes) or not entries:
        raise StatusError("the status result contains no nodes")

    summary = _mapping(result.get("summary"))
    raw_state = summary.get("vip_state")
    try:
        vip_state = VipState(str(raw_state))
    except ValueError:
        #
        # Taken from the summary rather than recomputed from the per-node
        # answers, on purpose: two readers deriving cluster-wide ownership their
        # own way is how the status command and the deploy command end up
        # disagreeing about whether it is safe to act. An unrecognised value is
        # therefore a refusal, not something to work around.
        #
        raise StatusError(f"unsupported VIP state in status result: {raw_state!r}") from None

    owners = summary.get("vip_owners")
    warnings = envelope.get("warnings")

    return ClusterStatus(
        cluster=_text(envelope.get("cluster")),
        nodes=tuple(_node(_mapping(entry)) for entry in entries),
        vip_state=vip_state,
        vip_owners=tuple(str(name) for name in owners) if isinstance(owners, Sequence) else (),
        warnings=tuple(str(item) for item in warnings) if isinstance(warnings, Sequence) else (),
    )
