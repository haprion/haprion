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
    #
    # HAProxy's own counter columns for this row, by their own names, and only
    # where the node reported a number. A name that is absent is a counter this
    # row does not have or a node that did not report it - which is not the
    # same fact as a counter standing at zero, and `.get` keeps them apart.
    #
    counters: Mapping[str, int] = field(default_factory=dict)
    #
    # Drain or maintenance as somebody set it (B263): `ready`, `drain` or
    # `maint`, None from a node that did not say. `status` cannot carry it - a
    # drained server whose check fails reads DOWN there.
    #
    admin: str | None = None

    @property
    def up(self) -> bool:
        """Whether HAProxy would send traffic here right now.

        `UP` and `no check` both mean usable - the second is a server nobody
        asked to be checked, which is not the same as a server that failed one.
        """

        return (self.status or "").upper().startswith(("UP", "NO CHECK"))

    @property
    def held(self) -> bool:
        """Whether somebody took this server out of service on purpose.

        Then it is not a fault, whatever its check says. From the admin state
        where the node reports one; from an older node, the status column's
        own MAINT or DRAIN - but not `MAINT (resolution)` or `MAINT (via …)`,
        which are HAProxy's verdicts and not anybody's choice.
        """

        if self.admin is not None:
            return self.admin in ("drain", "maint")
        return (self.status or "").upper() in ("MAINT", "DRAIN")


@dataclass(frozen=True, slots=True)
class FrontendTraffic:
    """One listener as the node's own HAProxy counts it.

    A frontend runs no health check, so there is no verdict here - only what
    arrived. It is reported because a backend with three green servers and a
    listener that never received the request are indistinguishable from the
    server rows alone, which is exactly how one site answered 503 with every
    server UP. See B89.
    """

    frontend: str
    status: str | None
    counters: Mapping[str, int] = field(default_factory=dict)


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
    #
    # None on a node still running a status script from before the listeners
    # were reported, told apart from a node that answered and has none.
    #
    frontends: tuple[FrontendTraffic, ...] | None = None
    #
    # Does the node carry the keepalived address list its release publishes?
    # None when it did not say - an older status script, or a file it could not
    # read. A release hash cannot answer this: a deploy that activated the
    # configuration and failed to activate the addresses leaves the new hash in
    # place with the old list restored. See B57 and the deploy matrix.
    #
    addresses_current: bool | None = None
    #
    # Whether keepalived.conf includes the installed list. Reported, never
    # compared: the include line is one deliberate step by a person, one node at
    # a time, and the node deploy exits 0 without it.
    #
    addresses_included: bool | None = None
    #
    # The same two for the syslog objects' IPVS file (B256). Current is True
    # on a node that does not report the file - see `ipvs_current`.
    #
    ipvs_current: bool | None = True
    ipvs_included: bool | None = None


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
                    addresses_current=node.addresses_current,
                    ipvs_current=node.ipvs_current,
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
                counters=_counters(item.get("counters")),
                admin=_admin(item.get("admin")),
            )
        )
    return tuple(members)


ADMIN_STATES = ("ready", "drain", "maint")


def _admin(value: object) -> str | None:
    return value if isinstance(value, str) and value in ADMIN_STATES else None


def _counters(value: object) -> Mapping[str, int]:
    """The counter names this row reported a number for.

    Anything that is not a number is left out rather than carried as zero. A
    frontend has no `econ` and a server no `req_tot`, so the missing ones are
    the normal case - and a caller that reads a zero it was never told is a
    caller that will report a listener as having received nothing.
    """

    if not isinstance(value, Mapping):
        return {}
    counted = ((str(name), _count(cell)) for name, cell in value.items())
    return {name: number for name, number in counted if number is not None}


def _frontends(status: Mapping[str, Any]) -> tuple[FrontendTraffic, ...] | None:
    """What the node's listeners counted, or None when it said nothing.

    Rows without a name are dropped for the same reason a pool member's is: a
    count that cannot be attributed to a listener cannot be shown beside one.
    """

    entries = status.get("frontends")
    if not isinstance(entries, list):
        return None

    listeners = []
    for entry in entries:
        item = _mapping(entry)
        name = _text(item.get("frontend"))
        if name is None:
            continue
        listeners.append(
            FrontendTraffic(
                frontend=name,
                status=_text(item.get("status")),
                counters=_counters(item.get("counters")),
            )
        )
    return tuple(listeners)


def _addresses(status: Mapping[str, Any]) -> Mapping[str, Any] | None:
    """The node's three address measurements, or None when it reported none."""

    data = _mapping(status.get("keepalived")).get("addresses")
    return data if isinstance(data, Mapping) else None


def addresses_current(status: Mapping[str, Any]) -> bool | None:
    """Does the node carry the address list its release publishes?

    True also when the release publishes none: an absent list means the
    addresses are not managed from here, never that the node should be emptied,
    and the node deploy says the same. None is reserved for what nobody
    measured - an older status script, or a file that could not be read - so an
    unverifiable node is never counted as verified.
    """

    data = _addresses(status)
    if data is None:
        return None
    return _carried(data)


def _carried(data: Mapping[str, Any]) -> bool | None:
    """Published, installed, sha256 of each: does the node carry what the release publishes?"""

    if data.get("published") is False:
        return True

    published = _text(data.get("published_sha256"))
    installed = _text(data.get("installed_sha256"))
    if published is None:
        return None
    if installed is None:
        #
        # The release publishes a list the node does not carry. Absent is a
        # measured answer and means behind; unreadable is not an answer at all.
        #
        return False if data.get("installed") is False else None
    return published == installed


def addresses_included(status: Mapping[str, Any]) -> bool | None:
    data = _addresses(status)
    if data is None:
        return None
    included = data.get("included")
    return included if isinstance(included, bool) else None


def _ipvs(status: Mapping[str, Any]) -> Mapping[str, Any] | None:
    data = status.get("ipvs")
    return data if isinstance(data, Mapping) else None


def ipvs_current(status: Mapping[str, Any]) -> bool | None:
    """Does the node carry the IPVS virtual servers its release publishes (B256)?

    The address list's measurements and rule, for the syslog objects' file. A
    node whose bundle predates the file says nothing and is not held to it:
    it neither installs nor reports it, a deploy would not change that, and
    the interface offers syslog only where every node reports it - as dnsdist.
    """

    data = _ipvs(status)
    if data is None:
        return True
    carried = _carried(data)
    #
    # Carried and not read is not current either (review 26-10-08, F1): the
    # file's virtual servers are syslog objects forwarded nowhere, and the
    # deploy refuses the release on this node until the include is there.
    #
    if carried is True and ipvs_unread(status):
        return False
    return carried


def ipvs_unread(status: Mapping[str, Any]) -> bool:
    """Whether the release asks for virtual servers keepalived on this node does not read."""

    data = _ipvs(status)
    if data is None or data.get("included") is not False:
        return False
    servers = data.get("published_servers")
    return isinstance(servers, int) and not isinstance(servers, bool) and servers > 0


def ipvs_included(status: Mapping[str, Any]) -> bool | None:
    """Whether keepalived.conf includes the installed file at its top level."""

    data = _ipvs(status)
    if data is None:
        return None
    included = data.get("included")
    return included if isinstance(included, bool) else None


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
        addresses_current=addresses_current(status),
        addresses_included=addresses_included(status),
        ipvs_current=ipvs_current(status),
        ipvs_included=ipvs_included(status),
        certificates=_certificates(status),
        servers=_servers(status),
        frontends=_frontends(status),
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


def keepalived_state(keepalived: Any) -> str | None:
    """The VRRP state to show for a node: STOPPED when keepalived is not running.

    The node reports two facts - whether the service is active, and what its
    notify script last wrote to the state file - and the file outlives a
    stopped keepalived. Shown as it stood, a stopped node read MASTER beside
    "Keepalived: INACTIVE" (2026-09-25). CLI and interface both show this.
    """

    if not isinstance(keepalived, dict):
        return None
    if keepalived.get("active") is False:
        return "STOPPED"
    state = keepalived.get("state")
    return state if isinstance(state, str) and state else None
