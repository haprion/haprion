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
from dataclasses import dataclass, field
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
class ServerHealth:
    """One pool member as the node's own HAProxy sees it.

    This is the answer to "is my health check working", and it is the node's to
    give: the checks have been running against the servers this node was told
    about, from the address this node uses. Nothing that probes from somewhere
    else can say the same thing.
    """

    backend: str
    server: str
    status: str | None
    check_status: str | None
    check_code: str | None
    check_duration_ms: int | None
    last_change_sec: int | None

    @property
    def up(self) -> bool:
        """Whether HAProxy would send traffic here right now.

        `UP` and `no check` both mean usable - the second is a server nobody
        asked to be checked, which is not the same as a server that failed one.
        """

        return (self.status or "").upper().startswith(("UP", "NO CHECK"))


@dataclass(frozen=True, slots=True)
class NodeStatus:
    name: str
    mgmt_host: str
    reachable: bool
    status_ok: bool
    owns_vip: bool | None
    release_hash: str | None
    error_code: str | None
    #
    # (id, fingerprint) pairs in id order, or None when the node said nothing
    # about certificates at all. The distinction matters: a node that reports an
    # empty list is missing every referenced certificate, while a node that
    # reports nothing cannot be compared and must not be counted as verified.
    #
    certificates: tuple[tuple[str, str], ...] | None = None
    #
    # None when the node said nothing about its servers - an older status
    # script, or a runtime socket that could not be read. An empty tuple means
    # the node answered and has no members, which is a different fact.
    #
    servers: tuple[ServerHealth, ...] | None = None


@dataclass(frozen=True, slots=True)
class ClusterStatus:
    cluster: str | None
    nodes: tuple[NodeStatus, ...]
    vip_state: VipState
    vip_owners: tuple[str, ...]
    warnings: tuple[str, ...]
    #
    # The summary exactly as the status helper wrote it. A deploy result has to
    # carry the initial and final summary, and the contract says they are the
    # status command's summary object - so it is passed through rather than
    # rebuilt. Rebuilding it would be a second derivation of the one thing both
    # commands must agree on.
    #
    summary: Mapping[str, Any] = field(default_factory=dict)

    def observation(self) -> ClusterObservation:
        """The same reading, in the terms the deploy matrix decides in."""

        return ClusterObservation(
            nodes=tuple(
                NodeObservation(
                    name=node.name,
                    status_ok=node.status_ok,
                    owns_vip=node.owns_vip,
                    release_hash=node.release_hash,
                    certificates=node.certificates,
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


def _certificates(status: Mapping[str, Any]) -> tuple[tuple[str, str], ...] | None:
    """What the node says it carries, or None when it did not say.

    Entries without both an id and a fingerprint are dropped rather than
    guessed at: a half-described certificate cannot be compared, and treating it
    as present would let a node look current on bytes nobody checked.
    """

    entries = status.get("certificates")
    if not isinstance(entries, list):
        return None

    pairs = []
    for entry in entries:
        item = _mapping(entry)
        identifier = _text(item.get("id"))
        fingerprint = _text(item.get("fingerprint_sha256"))
        if identifier is not None and fingerprint is not None:
            pairs.append((identifier, fingerprint))
    return tuple(sorted(pairs))


def _servers(status: Mapping[str, Any]) -> tuple[ServerHealth, ...] | None:
    """What the node's runtime reported, or None when it reported nothing.

    Entries without a backend and a server name are dropped: a row that cannot
    be attributed to a pool member cannot be shown beside one, and guessing
    which member it belongs to is how a healthy server gets somebody else's
    verdict.
    """

    entries = status.get("servers")
    if not isinstance(entries, list):
        return None

    members = []
    for entry in entries:
        item = _mapping(entry)
        backend = _text(item.get("backend"))
        server = _text(item.get("server"))
        if backend is None or server is None:
            continue
        members.append(
            ServerHealth(
                backend=backend,
                server=server,
                status=_text(item.get("status")),
                check_status=_text(item.get("check_status")),
                check_code=_text(item.get("check_code")),
                check_duration_ms=_count(item.get("check_duration_ms")),
                last_change_sec=_count(item.get("last_change_sec")),
            )
        )
    return tuple(members)


def _count(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


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
        certificates=_certificates(status),
        servers=_servers(status),
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
        summary=summary,
    )
