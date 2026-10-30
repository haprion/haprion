"""Reading a cluster status result, once, for everyone who needs one.

`haproxy-status-root` answers in the frozen schema in
`schemas/v1/haprion-status.schema.json`. Deploy needs to know who owns the VIP
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

from haprion import exit_codes
from haprion.deploy_plan import ClusterObservation, NodeObservation, VipState


class StatusError(Exception):
    """The status result could not be used at all."""

    def __init__(self, message: str, *, exit_code: int = exit_codes.UNAVAILABLE):
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
    #
    # Whether rsyslog reads the log forwarding this release carries (review
    # 26-10-13, A1). True on a node that does not report it - see
    # `forwarding_current`.
    #
    forwarding_current: bool | None = True
    #
    # Whether the steps after the HAProxy reload all succeeded (`release.complete`).
    # True on a node that does not report it - see `release_complete`.
    #
    release_complete: bool | None = True
    #
    # Whether keepalived runs on the node, as it said (B320); None when it did
    # not say.
    #
    keepalived_active: bool | None = None
    #
    # The other nodes this one shares its stick tables with, by name, and
    # whether each is connected (B270). None when the node did not say - an
    # older status script, or a runtime socket it could not read.
    #
    peers: tuple[tuple[str, bool], ...] | None = None
    #
    # The CA files the node carries for its pools (B276), as (id, bundle
    # fingerprint). None on a node whose status script predates them.
    #
    authorities: tuple[tuple[str, str], ...] | None = None
    #
    # The certificates' chain fingerprints as the node reports them, as (id,
    # chain) for each one that did. Empty on a node whose status script
    # predates the field; its certificates are then judged by the leaf alone.
    #
    chains: tuple[tuple[str, str], ...] = ()
    #
    # Ports another program holds on every address of the node, and so on its
    # VIPs (26-10-15), as (protocol, port, program or None). None on a node that
    # did not say - an older status script, or `ss` it could not read.
    #
    wildcard_listeners: tuple[tuple[str, int, str | None], ...] | None = None
    #
    # Whether the node's status carries the `traffic_stream` key at all, null or
    # not (B403). A node installed before it was reported leaves it out, and
    # that is what tells a deploy the node's package is too old to refuse a
    # release that logs to the traffic socket. None when the status is unusable.
    #
    traffic_stream_reported: bool | None = None


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
                    forwarding_current=node.forwarding_current,
                    release_complete=node.release_complete,
                    keepalived_active=node.keepalived_active,
                    certificates=node.certificates,
                    authorities=node.authorities,
                    chains=node.chains,
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


def _flag(value: object) -> bool | None:
    return value if isinstance(value, bool) else None


def _certificates(
    status: Mapping[str, Any], key: str = "certificates"
) -> tuple[tuple[str, str], ...] | None:
    """What the node says it carries, or None when it did not say.

    Entries without both an id and a fingerprint are dropped rather than
    guessed at: a half-described certificate cannot be compared, and treating it
    as present would let a node look current on bytes nobody checked. The
    authorities (B276) are read the same way, from their own key.
    """

    entries = status.get(key)
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


def _chains(status: Mapping[str, Any]) -> tuple[tuple[str, str], ...]:
    """The chain fingerprint each carried certificate reports, where it does.

    A node reports the SHA-256 over every certificate block in the file next
    to the leaf's (`chain_sha256`), because two files can share a leaf and
    differ in the intermediates behind it. An entry without it is left out,
    and the leaf alone then judges that certificate.
    """

    entries = status.get("certificates")
    if not isinstance(entries, list):
        return ()
    pairs = []
    for entry in entries:
        item = _mapping(entry)
        identifier = _text(item.get("id"))
        chain = _text(item.get("chain_sha256"))
        if identifier is not None and chain is not None:
            pairs.append((identifier, chain))
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


def forwarding_current(status: Mapping[str, Any]) -> bool | None:
    """Does rsyslog on the node read the log forwarding its release carries (A1)?

    The deploy installs the file after the reload and restores the previous
    one when rsyslog refuses it, which leaves the new release hash with the
    old receivers. Unlike the address list, a release without the file asks
    for none: the deploy removes it, so an installed file is then behind. A
    node whose status predates the measurement says nothing and is not held to
    it, as with the IPVS file - its bundle reports nothing a deploy could
    change.
    """

    data = status.get("forward_file")
    if not isinstance(data, Mapping):
        return True
    published = data.get("published")
    installed = data.get("installed")
    if published is False:
        if installed is False:
            return True
        return False if installed is True else None
    if published is not True:
        return None
    if installed is False:
        return False
    wanted = _text(data.get("published_sha256"))
    carried = _text(data.get("installed_sha256"))
    if wanted is None or carried is None:
        return None
    return wanted == carried


def traffic_stream_problem(status: Mapping[str, Any]) -> str | None:
    """Why the node drops every traffic record its release logs, or None (review 2026-10-30-igen, R3).

    The reason only, which `haprion-status` and the interface each put in a sentence.

    A node prepared by this version's step 4 keeps a traffic line only when it
    came in on HAProxy's own socket. A release an older manager published, or
    one a revert put back, logs the stream elsewhere; the node then drops it
    until the cluster is published again, and nothing else says so. A node
    that does not report the field, or logs no stream, says nothing.
    """

    stream = status.get("traffic_stream")
    if not isinstance(stream, Mapping):
        return None
    if stream.get("to_socket") is True:
        if stream.get("socket") is False:
            return (
                "HAProxy's traffic socket is missing or open to other accounts;"
                " run  sudo haprion-node-prepare  on the node"
            )
        return None
    if stream.get("marked_only") is True:
        return "its release was published for nodes before this version; publish the cluster again"
    return None


def release_complete(status: Mapping[str, Any]) -> bool | None:
    """Did every step after the HAProxy reload succeed on the node?

    `haprion-pull-deploy` keeps a marker from the reload until keepalived's
    configuration, address list and IPVS file, the rejoin and the log
    forwarding are all in place. A step that failed leaves it, and the node
    reports the new release hash with `complete: false`; nothing else says so
    when the failed step was keepalived.conf itself, which no other field
    measures. A node that does not report the field is not held to it.
    """

    value = _mapping(status.get("release")).get("complete")
    return value if isinstance(value, bool) else True


BEHIND_RELEASE = "release"
BEHIND_ADDRESSES = "address list"
BEHIND_IPVS = "IPVS file"
BEHIND_FORWARDING = "log forwarding"
BEHIND_STEPS = "steps after the reload"


def behind_part(status: Mapping[str, Any], target_hash: str | None) -> str | None:
    """Which part of the published release a node does not carry, or None.

    In the order the deploy installs them, so the first answer is the one the
    next deploy meets first. A node whose release is the target and whose
    `current` is still false is behind in one of the files the release
    activates after the reload; saying "not on the target release" about it
    is wrong, and `haprion-status` names the part (review 26-10-13 r16k, F1).
    """

    observed = _text(_mapping(status.get("release")).get("hash"))
    if target_hash is not None and observed != target_hash:
        return BEHIND_RELEASE
    if addresses_current(status) is False:
        return BEHIND_ADDRESSES
    if ipvs_current(status) is False:
        return BEHIND_IPVS
    if forwarding_current(status) is False:
        return BEHIND_FORWARDING
    if release_complete(status) is False:
        return BEHIND_STEPS
    return None


def _count(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def ahead_of(status: Mapping[str, Any], published: object) -> tuple[int, int] | None:
    """The node's version and the published one when the node is past it (R2 26-10-27, F18).

    A revert publishes a new, higher version, so no deploy from this manager
    leaves a node past what it published. A node that is ahead runs a version
    this manager has no record of - the manager was put back from older state -
    and a deploy would replace its configuration with the older one. Called
    *behind*, it was offered exactly that deploy.
    """

    version = _count(_mapping(status.get("release")).get("version"))
    published_version = _count(published)
    if version is None or published_version is None or version <= published_version:
        return None
    return version, published_version


def ahead_words(version: int, published: int) -> str:
    """What `haprion-status` and the interface say about a node `ahead_of` names."""

    return (
        f"runs version {version}, which this manager has no record of, as after a restore of the"
        f" manager from older state. A deploy puts version {published} on it"
    )


def _peers(status: Mapping[str, Any]) -> tuple[tuple[str, bool], ...] | None:
    reported = status.get("peers")
    if not isinstance(reported, list):
        return None
    return tuple(
        (str(peer.get("name", "")), peer.get("connected") is True)
        for peer in reported
        if isinstance(peer, Mapping)
    )


def _wildcard_listeners(
    status: Mapping[str, Any],
) -> tuple[tuple[str, int, str | None], ...] | None:
    reported = status.get("wildcard_listeners")
    if not isinstance(reported, list):
        return None
    found: list[tuple[str, int, str | None]] = []
    for entry in reported:
        if not isinstance(entry, Mapping):
            continue
        protocol = entry.get("protocol")
        port = _count(entry.get("port"))
        if protocol not in ("tcp", "udp") or port is None:
            continue
        found.append((str(protocol), port, _text(entry.get("program"))))
    return tuple(found)


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
        forwarding_current=forwarding_current(status),
        release_complete=release_complete(status),
        keepalived_active=_flag(_mapping(status.get("keepalived")).get("active")),
        certificates=_certificates(status),
        authorities=_certificates(status, "authorities"),
        chains=_chains(status),
        servers=_servers(status),
        frontends=_frontends(status),
        peers=_peers(status),
        wildcard_listeners=_wildcard_listeners(status),
        traffic_stream_reported=("traffic_stream" in status) if usable else None,
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
        code = exit_codes.USAGE if error.get("code") == "bad_input" else exit_codes.UNAVAILABLE
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
