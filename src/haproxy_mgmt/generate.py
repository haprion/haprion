"""Proxy objects in, HAProxy configuration out.

This is the generator. It takes the objects the application writes under
`managed/proxies/` and produces the files that go under `managed/generated/`,
and it is the only place in the system that knows HAProxy's configuration
language. Everything it emits is decided here and nowhere else: the matching
rules come from `route_match`, the stable names from `guid`, and the shape of
the input from `proxy_model`.

**One shared frontend, many backend files.** A frontend owns its listening
port, and two frontends on one port do not fail loudly - HAProxy binds with
SO_REUSEPORT, both come up, and the kernel splits new connections between them
at random, which is worse than a crash because nothing reports it. So every
object's routing goes into one generated frontend per protocol, and each object gets its own file holding only its backends. It is
the same shape as a content switching virtual server in front of a set of load
balancing virtual servers: one thing owns the address, many things sit behind
it.

The per-object files all share the number `1001`, deliberately. Sorting inside
the band is alphabetical and backends have no meaningful order between them, so
nothing has to hand out numbers - and adding an object therefore cannot renumber
the objects that were already there.

Every generated file is self-contained: mode, timeouts and options are written
out rather than inherited from a `defaults` section in `core/`. A generated file
whose behaviour depends on a file somebody else maintains is a file that changes
meaning without being regenerated.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field

from haproxy_mgmt.check_policy import check_speaks_tls
from haproxy_mgmt.config import AbuseProtection, ConfigError, UnknownHost, Vip
from haproxy_mgmt.guid import (
    backend_guid,
    frontend_guid,
    listener_guid_prefix,
    redirect_name,
    server_guid,
)
from haproxy_mgmt.proxy_model import (
    URL_PLACEHOLDER,
    Backend,
    Health,
    Proxy,
    Route,
    Server,
    is_range,
)

#
# Not defined here. The lists, and where they came from, live in `tls_policy` -
# a cluster's own `core/haproxy.cfg` carries the same Mozilla recommendation,
# and the two had already drifted apart by one cipher before there was one
# place to point at.
#
from haproxy_mgmt.release_layout import CRT_LIST_TARGET
from haproxy_mgmt.reservations import NOTHING_RESERVED, Reservations
from haproxy_mgmt.route_match import order_routes
from haproxy_mgmt.tls_policy import BACKEND_POLICIES, TLS_POLICIES

#
# Marks everything this module writes. A generated section can then never
# collide with a handwritten one in `core/` or `manual/`, and anybody reading
# `show stat` on a node can tell at a glance which half of the configuration a
# name came from.
#
PREFIX = "mgd"

#
# The ACL naming the addresses whose forwarded headers are believed. One per
# frontend and named for the whole layer rather than for an object, because
# the question it answers - who is allowed to say where a request came from -
# belongs to the cluster and not to any site on it.
#
TRUSTED_ACL = f"{PREFIX}-trusted-proxy"

#
# What a generated redirect backend is called, before the derived part. Named
# rather than numbered so that reading `show stat` says what the section is.
#
REDIRECT_PREFIX = "redirect"

#
# How many source addresses one frontend keeps counters for. Entries expire
# after a single window, so this bounds a burst of distinct addresses rather
# than a day of traffic; HAProxy allocates it up front, and 1m of ip entries is
# a few tens of megabytes.
#
ABUSE_TABLE_SIZE = "1m"

FRONTEND_FILE = "1000-frontends.cfg"
OBJECT_BAND = "1001"

#
# Where a node keeps the certificates it may serve. Part of the node-side
# contract rather than a choice this generator makes - `docs/INSTALLATION.md`
# describes the directory, and `candidate_validation` rewrites exactly this
# prefix when it validates a candidate inside a sandbox that has no /etc.
# Changing it here without changing that rewrite would make validation pass
# against certificates the node will never load.
#
NODE_CERTIFICATE_DIR = "/etc/haproxy/certs"

#
# Offered on every TLS listener. HTTP/2 is what a current browser negotiates
# when it is allowed to, and the ordering states the preference; `http/1.1`
# stays for everything that cannot.
#
ALPN = "h2,http/1.1"

#
# What a certificate list is called. Not `.cfg`, and not in `conf.d`: the node
# loads that directory with `-f`, which reads every file in it.
#
CRT_LIST_SUFFIX = ".list"

#
# The V1 defaults from the plan, written into every generated section. `tunnel`
# is what makes a WebSocket upgrade survive without a separate switch in the
# interface: an upgraded connection stops being a series of requests, and the
# client and server timeouts would otherwise close it while it is idle and
# healthy. It belongs in the backend and only there - HAProxy takes the tunnel
# timeout from the backend, and says so about the same line in a frontend:
# "will be ignored because frontend has no backend capability". Measured on
# 3.4.4 on this machine.
#
TIMEOUT_CONNECT = "5s"
TIMEOUT_CLIENT = "50s"
TIMEOUT_SERVER = "50s"
TIMEOUT_TUNNEL = "1h"

#
# How a single failed connection attempt is answered. Both are written out
# rather than inherited, and only one of them changes anything.
#
# `retries 3` is HAProxy's own default made visible - measured on 3.4.4 on this
# machine, where a request to a dead pool logs three retries before it gives
# up. It applies to connection attempts, so nothing is ever sent twice: a
# request that reached the server is not retried.
#
# `option redispatch` is the one that matters, and it is off by default. Without
# it, every retry goes back to the same server that just refused the
# connection, so a pool of two with one dead server answers every other request
# with 503. Measured the same way on the same machine: `503 200` alternating
# without it, four requests out of four served with it. It also breaks cookie
# persistence when the server a visitor is stuck to is gone, which is the whole
# point - a lost session beats a dead site.
#
RETRIES = 3

HEADER = (
    "#",
    "# Generated by haproxy-manager. Do not edit.",
    "#",
    "# This file is rewritten in full every time the objects it comes from are",
    "# published. An edit here survives until the next publication and then",
    "# disappears without a trace in the diff of what was published.",
    "#",
)


@dataclass(frozen=True, slots=True)
class GeneratedLayer:
    """What one generation produced, split by where it has to be written."""

    configuration: dict[str, str]
    """`managed/generated/`, and `conf.d/` on the node. HAProxy loads these."""

    certificate_lists: dict[str, str]
    """`managed/crt-lists/`, and `crt-lists/` on the node. Bind lines name these."""

    object_parts: dict[str, dict[str, str]] = field(default_factory=dict)
    """Per object, the four pieces its behaviour is spread across.

    The same bytes as `configuration` and `certificate_lists`, split by which
    object they belong to rather than by which file they land in. A release
    manifest hashes these so two releases can be compared per object, which is
    a question the flat file listing cannot answer: the frontend is shared, so
    a change to one object moves a file every other object also sits in.

    Kept apart for exactly that reason. `listener` holds only what the group
    decides - the bind line, the timeouts, the forwarded and abuse rules - and
    never a sibling's routing, so adding a second site to a VIP does not report
    the first one as changed.
    """


class GeneratorError(ConfigError):
    """A set of objects cannot be turned into configuration.

    A `ConfigError`, so it leaves the publishing path carrying exit code 65 and
    is reported like every other refusal about input.
    """


#
# The port each protocol is served on unless a cluster says otherwise. A
# default rather than a constant: most deployments terminate on the standard
# ports, but a cluster that sits behind something else does not, and a port
# nailed into the generator would be an environment value living in code.
#
PORTS = {"http": 80, "https": 443}


def generate(
    proxies: Sequence[Proxy],
    *,
    vips: Mapping[str, Vip],
    default_vip: str,
    certificates: Sequence[str] = (),
    resolvers: str | None = None,
    networks: Mapping[str, Sequence[str]] | None = None,
    sources: Mapping[str, str] | None = None,
    unknown_host: UnknownHost | None = None,
    trusted_proxies: Sequence[str] = (),
    abuse_protection: AbuseProtection | None = None,
    reservations: Reservations = NOTHING_RESERVED,
    ports: Mapping[str, int] = PORTS,
    certificate_sans: Mapping[str, Sequence[str]] | None = None,
    allow_certificate_mismatch: bool = False,
) -> GeneratedLayer:
    """Every file the generated layer consists of.

    The whole layer at once rather than one object at a time, because the
    frontend is shared: what one object routes cannot be decided without
    knowing what the others route. The caller writes the returned mappings and
    deletes anything else it finds in their directories, so an object that was
    removed takes its configuration with it.

    Two mappings and not one, because they land in different places and the
    difference matters: `configuration` is what the node loads with `-f`, and
    `-f` on a directory reads every file in it. A certificate list among them
    would be parsed as configuration and fail the deploy.
    """

    ordered = sorted(proxies, key=lambda proxy: proxy.name)
    _refuse_duplicate_names(ordered)
    _refuse_shared_hostnames(ordered)

    unsupported = [
        proxy
        for proxy in ordered
        if proxy.listen.protocol != "tcp" and proxy.listen.protocol not in ports
    ]
    if unsupported:
        #
        # Refused rather than skipped. Silently generating nothing for an
        # object somebody published would take the site down and report
        # success, which is the one outcome worse than a refusal.
        #
        names = ", ".join(proxy.name for proxy in unsupported)
        raise GeneratorError(
            f"this version generates http, https and tcp objects; cannot generate: {names}"
        )
    _refuse_unknown_certificates(ordered, certificates)
    if certificate_sans is not None and not allow_certificate_mismatch:
        _refuse_uncovered_hostnames(ordered, certificate_sans)
    known_networks = dict(networks or {})
    _refuse_unknown_networks(ordered, known_networks)

    known_sources = dict(sources or {})
    placed = [(_vip_of(proxy, vips, default_vip), proxy) for proxy in ordered]
    #
    # After placement, not before: a reservation names an address, so the gate
    # cannot ask its question until every object knows which VIP it sits on.
    #
    _refuse_reserved(placed, reservations, ports)
    _refuse_shared_listeners(placed, ports)

    listings: dict[str, str] = {}
    shared: dict[str, dict[str, list[str]]] = {}
    files = {
        FRONTEND_FILE: _frontend_file(
            placed,
            ports,
            known_networks,
            unknown_host,
            tuple(trusted_proxies),
            abuse_protection,
            listings,
            shared,
        )
    }
    for vip, proxy in placed:
        files[f"{OBJECT_BAND}-{proxy.name}.cfg"] = _object_file(
            proxy, _source_of(proxy, vip, known_sources), resolvers
        )
    parts = {
        proxy.name: {
            "backends": files[f"{OBJECT_BAND}-{proxy.name}.cfg"],
            "routing": _lines(shared.get(proxy.name, {}).get("routing", [])),
            "listener": _lines(shared.get(proxy.name, {}).get("listener", [])),
            "certificate": _certificate_line(proxy),
        }
        for _, proxy in placed
    }
    return GeneratedLayer(configuration=files, certificate_lists=listings, object_parts=parts)


def _source_of(proxy: Proxy, vip: Vip, sources: Mapping[str, str]) -> str | None:
    """The address this object connects to backends from.

    The VIP's own source unless the object names another. An object that names
    one the cluster does not define is refused rather than quietly falling back
    to the default: leaving from an unexpected address is exactly what a
    firewall rule further in will notice, at the worst possible moment.
    """

    if proxy.listen.source is None:
        return vip.source
    try:
        return sources[proxy.listen.source]
    except KeyError:
        known = ", ".join(sorted(sources)) or "none"
        raise GeneratorError(
            f"{proxy.name} leaves from the source address {proxy.listen.source}, which this "
            f"cluster does not define. Known source addresses: {known}"
        ) from None


def _vip_of(proxy: Proxy, vips: Mapping[str, Vip], default_vip: str) -> Vip:
    """Which of the cluster's addresses this object sits on.

    An object that names an address the cluster does not have is refused here
    rather than defaulted onto some other address. Publishing a site onto the
    wrong VIP is not a smaller failure than not publishing it - it is a site
    reachable from a network that was never meant to reach it.
    """

    name = proxy.listen.vip or default_vip
    try:
        return vips[name]
    except KeyError:
        known = ", ".join(sorted(vips))
        raise GeneratorError(
            f"{proxy.name} sits on the VIP {name}, which this cluster does not have. "
            f"Known VIPs: {known}"
        ) from None


def _refuse_reserved(
    placed: Sequence[tuple[Vip, Proxy]], reservations: Reservations, ports: Mapping[str, int]
) -> None:
    """What the handwritten half of the configuration has already claimed.

    Refused here rather than left to the node, because both failures are ones
    HAProxy does not report as failures. A duplicated hostname is answered by
    whichever frontend happens to come first in the directory, and two
    frontends on one port both bind it under SO_REUSEPORT and then split the
    traffic at random - so the publish says it worked and the node answers
    correctly for roughly half the connections.

    Ports are asked per address. A cluster with several VIPs is the whole point
    of the file - something handwritten beside the generated objects - and a
    port claimed cluster-wide would block every managed object on every other
    address as well, which makes the reservation unusable exactly where it is
    needed. An entry written without an address still claims every one of them,
    because a `bind` line without an address does.
    """

    for _vip, proxy in placed:
        taken = sorted(set(proxy.hostnames) & reservations.hostnames)
        if taken:
            raise GeneratorError(
                f"{proxy.name} claims a hostname reserved in manual/reservations.yaml: "
                f"{', '.join(taken)}"
            )

    if not reservations.tcp_ports and not reservations.tcp_listeners:
        return
    #
    # Only the listeners objects actually cause to be bound. Reserving an
    # address and port nothing generated listens on is a person writing down
    # what the handwritten side uses, which is the file's whole purpose.
    #
    for vip, proxy in placed:
        port = proxy.listen.port
        if port is not None and reservations.claims(vip.address, port):
            raise GeneratorError(
                f"{proxy.name} listens on {vip.name} port {port}, which "
                f"manual/reservations.yaml reserves for handwritten configuration"
            )

    wanted = {
        (vip.name, vip.address, protocol)
        for protocol in ports
        for vip, proxy in placed
        if _serves_shared(proxy, protocol)
    }
    for name, address, protocol in sorted(wanted):
        port = ports.get(protocol)
        if port is not None and reservations.claims(address, port):
            raise GeneratorError(
                f"this cluster serves {protocol} on {name} port {port}, which "
                f"manual/reservations.yaml reserves for handwritten configuration"
            )


def _refuse_unknown_certificates(proxies: Sequence[Proxy], certificates: Sequence[str]) -> None:
    """A certificate an object may choose is one the cluster distributes.

    The model cannot ask this question - it reads one object and knows nothing
    about the cluster - so it is asked here, against the allowlist the cluster
    configuration carries. A name that is merely plausible would reach the node
    as a path to a file that is not there, and HAProxy refuses to start on a
    missing certificate rather than serving the site without TLS.
    """

    allowed = set(certificates)
    for proxy in proxies:
        wanted = proxy.listen.certificate
        if wanted is not None and wanted not in allowed:
            known = ", ".join(sorted(allowed)) or "none"
            raise GeneratorError(
                f"{proxy.name} asks for the certificate {wanted}, which this cluster does not "
                f"distribute. Available: {known}"
            )


def covers(san: str, hostname: str) -> bool:
    """Whether one name in a certificate answers for one hostname.

    A wildcard stands for exactly one label - `*.example.com` answers for
    `shop.example.com` and not for `a.b.example.com`, and not for
    `example.com` itself. That rule is the whole reason this function exists:
    it is the part people get wrong, it looks right until a browser refuses,
    and HAProxy serves the certificate either way without a word.

    Compared lowercased. Hostnames have already been held to `HOSTNAME` by the
    model, and a certificate's own names are matched case-insensitively by
    every client that reads them.
    """

    san = san.lower()
    hostname = hostname.lower()
    if not san.startswith("*."):
        return san == hostname
    suffix = san[1:]
    if not hostname.endswith(suffix):
        return False
    label = hostname[: -len(suffix)]
    return bool(label) and "." not in label


def _refuse_uncovered_hostnames(
    proxies: Sequence[Proxy], certificate_sans: Mapping[str, Sequence[str]]
) -> None:
    """A name served under a certificate that does not answer for it.

    HAProxy does not refuse this and cannot: a certificate is a file it loads,
    not a claim it checks against the objects using it. The client is what
    refuses, which makes the site look broken to visitors while every layer
    here reports success.

    Only checked where the caller supplied coverage data. A cluster whose
    installation has no certificate root configured cannot answer the question
    at all, and refusing every https object there would be worse than not
    asking - see `docs/INSTALLATION.md`.

    A certificate the caller has no entry for is not treated as covering
    nothing. `_refuse_unknown_certificates` has already held every name to the
    cluster's own list, so an absence here means the file could not be read,
    and inventing a refusal from a failed read would block a publish for a
    reason that has nothing to do with the object.
    """

    for proxy in proxies:
        wanted = proxy.listen.certificate
        if wanted is None:
            continue
        sans = certificate_sans.get(wanted)
        if sans is None:
            continue
        uncovered = [
            hostname
            for hostname in proxy.hostnames
            if not any(covers(san, hostname) for san in sans)
        ]
        if uncovered:
            known = ", ".join(sorted(sans)) or "nothing"
            raise GeneratorError(
                f"{proxy.name} serves {', '.join(uncovered)} under the certificate {wanted}, "
                f"which does not answer for {'that name' if len(uncovered) == 1 else 'those names'}. "
                f"{wanted} covers: {known}. To do this deliberately, publish again with the "
                f"certificate mismatch override."
            )


def _refuse_unknown_networks(
    proxies: Sequence[Proxy], networks: Mapping[str, Sequence[str]]
) -> None:
    """A restriction that names nothing would be no restriction at all.

    Refused rather than ignored, and that is the whole point: an allowlist that
    silently matched no addresses would deny every visitor, and an allowlist
    silently dropped would admit every visitor. Both are worse than being told
    the name is unknown.
    """

    for proxy in proxies:
        for name in proxy.allow_from:
            if is_range(name) or name in networks:
                continue
            known = ", ".join(sorted(networks)) or "none"
            raise GeneratorError(
                f"{proxy.name} is restricted to the group {name}, which this cluster does "
                f"not define. Known groups: {known}"
            )


def _refuse_duplicate_names(proxies: Sequence[Proxy]) -> None:
    names = [proxy.name for proxy in proxies]
    duplicates = sorted({name for name in names if names.count(name) > 1})
    if duplicates:
        raise GeneratorError(f"two objects share a name: {', '.join(duplicates)}")


def _serves_shared(proxy: Proxy, protocol: str) -> bool:
    """Whether this object causes the cluster's shared frontend for a protocol.

    Asking `listen.protocol` alone is not enough: a https object with
    redirect_http also puts a frontend on the http port, and that frontend
    binds the port exactly as firmly as one that named it.
    """

    if proxy.listen.protocol == "tcp":
        return False
    if proxy.listen.protocol == protocol:
        return True
    return protocol == "http" and proxy.listen.redirect_http


def _refuse_shared_listeners(placed: Sequence[tuple[Vip, Proxy]], ports: Mapping[str, int]) -> None:
    """One address and port may be bound exactly once.

    Measured on 3.4.4 rather than assumed: two frontends on one port do not
    kill the process. HAProxy binds with SO_REUSEPORT, both listeners come up,
    and the kernel hands each new connection to one of them at random - so a
    tcp object and an http frontend on one port split the traffic between two
    different readings of the same bytes, and nothing anywhere reports it.
    A crash would at least be noticed, which makes this the only place the
    collision can be caught.

    Only tcp objects can collide this way. Two http objects on one address
    share a frontend by design; a tcp object is a frontend of its own, and its
    port is written in the object rather than in the cluster.
    """

    taken: dict[tuple[str, int], str] = {}
    for vip, proxy in placed:
        if proxy.listen.protocol != "tcp":
            continue
        port = proxy.listen.port
        if port is None:
            #
            # The model requires a port for tcp, so reaching this means the two
            # layers have drifted. A refusal rather than an assertion, so it
            # survives running with -O.
            #
            raise GeneratorError(f"{proxy.name} listens on tcp without naming a port")
        earlier = taken.get((vip.name, port))
        if earlier is not None:
            raise GeneratorError(
                f"{earlier} and {proxy.name} both listen on {vip.name} port {port}"
            )
        for protocol, shared in sorted(ports.items()):
            if shared == port and any(
                other_vip.name == vip.name and _serves_shared(other, protocol)
                for other_vip, other in placed
            ):
                raise GeneratorError(
                    f"{proxy.name} listens on {vip.name} port {port}, which this cluster "
                    f"already serves {protocol} on"
                )
        taken[(vip.name, port)] = proxy.name


def _refuse_shared_hostnames(proxies: Sequence[Proxy]) -> None:
    """A hostname belongs to one object, and the cluster is where that is true.

    Two objects claiming the same hostname is not an override, it is a coin
    toss decided by file order, and the loser is a site that is simply gone.
    The model can only see one object at a time, so this is the first place the
    question can be asked at all.
    """

    owners: dict[str, str] = {}
    for proxy in proxies:
        for hostname in proxy.hostnames:
            if hostname in owners:
                raise GeneratorError(
                    f"{hostname} is claimed by both {owners[hostname]} and {proxy.name}"
                )
            owners[hostname] = proxy.name


def _frontend_name(vip: Vip, protocol: str) -> str:
    return f"{PREFIX}-{vip.name}-{protocol}"


def _backend_name(proxy: str, backend: str) -> str:
    return f"{PREFIX}-{proxy}-{backend}"


def _acl_name(proxy: str, suffix: str) -> str:
    return f"{PREFIX}-{proxy}-{suffix}"


def _lines(*blocks: Iterable[str]) -> str:
    out: list[str] = []
    for block in blocks:
        out.extend(block)
    return "\n".join(out) + "\n"


def _record(
    shared: dict[str, dict[str, list[str]]],
    name: str,
    *,
    listener: Sequence[str] = (),
    routing: Sequence[str] = (),
) -> None:
    """Keep one object's share of the shared file, as it is written.

    An object can appear twice - a site that also redirects plain http sits in
    two groups - so the lines accumulate rather than replace. Groups are walked
    in sorted order, which is what makes the result the same on every run.
    """

    entry = shared.setdefault(name, {"listener": [], "routing": []})
    entry["listener"].extend(listener)
    entry["routing"].extend(routing)


def _frontend_file(
    placed: Sequence[tuple[Vip, Proxy]],
    ports: Mapping[str, int],
    networks: Mapping[str, Sequence[str]],
    unknown_host: UnknownHost | None,
    trusted_proxies: Sequence[str],
    abuse_protection: AbuseProtection | None,
    listings: dict[str, str],
    shared: dict[str, dict[str, list[str]]],
) -> str:
    """Where every request is decided: one frontend per address and protocol.

    Objects that share an address share a frontend, because an address and
    port can be bound exactly once. Objects on different addresses end up in
    different frontends and cannot reach each other's routes at all, which is
    what makes a second VIP a real separation rather than a label.
    """

    #
    # An https object that redirects plain http needs a listener on port 80 as
    # well, on the same address, whether or not any object actually serves http
    # there. Both land in the same group, so the redirect and a site that
    # really is http cannot end up in two frontends fighting over one port.
    #
    groups: dict[tuple[str, str], list[tuple[Vip, Proxy, str]]] = {}
    tcp: list[tuple[Vip, Proxy]] = []
    for vip, proxy in placed:
        if proxy.listen.protocol == "tcp":
            #
            # A frontend of its own, not a group. A tcp listener has nothing to
            # decide with - no name and no path - so two objects on one port
            # could not be told apart even if HAProxy would bind it twice.
            #
            tcp.append((vip, proxy))
            continue
        groups.setdefault((vip.name, proxy.listen.protocol), []).append((vip, proxy, "serve"))
        if proxy.listen.redirect_http:
            groups.setdefault((vip.name, "http"), []).append((vip, proxy, "redirect"))

    body: list[str] = []
    fallbacks: list[str] = []
    for key in sorted(groups):
        members = sorted(groups[key], key=lambda member: member[1].name)
        vip = members[0][0]
        protocol = key[1]
        identity = f"{vip.name}-{protocol}"
        #
        # The group's own lines, kept as their own list because they are what
        # every member of this listener is subject to and nothing a member
        # decides. A release manifest fingerprints them per object, so the list
        # must not pick up a sibling's routing on the way past.
        #
        envelope = [
            "",
            f"frontend {_frontend_name(vip, protocol)}",
            f"    guid {frontend_guid(identity)}",
            f"    bind {vip.address}:{ports[protocol]}"
            f"{_tls(members, protocol, _listing_name(identity, listings, members, protocol))}"
            f" guid-prefix {listener_guid_prefix(identity)}",
            "    mode http",
            "    option httplog",
            f"    timeout client {TIMEOUT_CLIENT}",
            *_forwarded_rules(protocol, trusted_proxies),
            *_abuse_rules(abuse_protection, bool(trusted_proxies)),
        ]
        #
        # Written after the members in the file, but part of the same envelope:
        # it is the listener's answer for a name no member claims.
        #
        tail: list[str] = []
        if unknown_host is not None:
            tail.append(f"    default_backend {_fallback_name(vip, protocol)}")
            fallbacks.extend(_fallback(vip, protocol, unknown_host))
        body += envelope
        for _, proxy, role in members:
            rules = _frontend_rules(proxy, role, networks, members=members)
            body.extend(rules)
            _record(shared, proxy.name, listener=[*envelope, *tail], routing=rules)
        body += tail
    for vip, proxy in sorted(tcp, key=lambda member: member[1].name):
        #
        # A tcp object owns its whole frontend, so there is no envelope to
        # separate: the bind line is as much its own as the rules are.
        #
        block = _tcp_frontend(vip, proxy, networks, abuse_protection)
        body.extend(block)
        _record(shared, proxy.name, routing=block)
    body.extend(fallbacks)
    if not body:
        body = ["", "# No object listens anywhere on this cluster."]
    return _lines(HEADER, body)


def _tcp_frontend(
    vip: Vip,
    proxy: Proxy,
    networks: Mapping[str, Sequence[str]],
    abuse_protection: AbuseProtection | None,
) -> list[str]:
    """One raw port, forwarded to one pool.

    Everything the HTTP frontends do with `http-request` happens here at
    connection time instead: there is no request to inspect, so who may connect
    and how fast are the only two questions that can be asked at all - and both
    are answered before a byte is forwarded.
    """

    port = proxy.listen.port
    if port is None:
        raise GeneratorError(f"{proxy.name} listens on tcp without naming a port")
    identity = f"{vip.name}-tcp-{port}"
    lines = [
        "",
        f"frontend {_frontend_name(vip, f'tcp-{port}')}",
        f"    guid {frontend_guid(identity)}",
        f"    bind {vip.address}:{port} guid-prefix {listener_guid_prefix(identity)}",
        "    mode tcp",
        "    option tcplog",
        f"    timeout client {TIMEOUT_CLIENT}",
    ]
    if proxy.allow_from:
        allowed = sorted(
            {
                cidr
                for entry in proxy.allow_from
                for cidr in ((entry,) if is_range(entry) else networks[entry])
            }
        )
        acl = _acl_name(proxy.name, "allow")
        lines += [
            f"    acl {acl} src {' '.join(allowed)}",
            #
            # Rejected at connection time rather than denied at request time:
            # there is no request. The client sees a closed connection, which
            # is all a raw protocol can be told.
            #
            f"    tcp-request connection reject unless {acl}",
        ]
    if abuse_protection is not None and abuse_protection.max_new_connections is not None:
        window = abuse_protection.window
        lines += [
            f"    stick-table type ip size {ABUSE_TABLE_SIZE} expire {window} "
            f"store conn_rate({window})",
            "    tcp-request connection track-sc0 src",
            f"    tcp-request connection reject "
            f"if {{ sc_conn_rate(0) gt {abuse_protection.max_new_connections} }}",
        ]
    if proxy.backend is None:
        #
        # The model requires one for tcp, so reaching this means the two layers
        # have drifted. Refused rather than written as `mgd-db-`, which is a
        # name no backend section carries and a configuration HAProxy would
        # then refuse on the node instead of here.
        #
        raise GeneratorError(f"{proxy.name} listens on tcp without naming a backend")
    lines.append(f"    default_backend {_backend_name(proxy.name, proxy.backend)}")
    return lines


def _forwarded_rules(protocol: str, trusted_proxies: Sequence[str]) -> list[str]:
    """What the backend is told about a visitor it never speaks to directly.

    Behind a proxy an application has no way of its own to learn who connected
    or how. Measured on this machine: a request that arrived over TLS reached
    the backend as plain HTTP carrying only `host`, `user-agent` and `accept`.
    The client address and the scheme exist only here, and are lost unless they
    are written into headers.

    The scheme matters more than it looks. An application that believes it is
    reached over plain http builds `http://` redirects, the proxy sends the
    visitor back to https, and the login loops - a proxy fault that reads as an
    application fault.

    Every one of these headers is deleted before it is set, and that is the
    whole security of the arrangement: they are ordinary request headers, so a
    visitor can send `X-Forwarded-For: 127.0.0.1` and claim to be anybody.
    Believing one is worse than having none. The exception is a request that
    arrives from an address the cluster named as a trusted proxy, which is a
    machine that has already established these facts and whose chain should be
    extended rather than thrown away.

    `option forwardfor` sits in the backend, since that is the only section
    HAProxy takes it in, and it appends rather than replaces - so behind a
    trusted proxy the address it adds extends the chain.
    """

    lines = []
    condition = ""
    if trusted_proxies:
        lines.append(f"    acl {TRUSTED_ACL} src {' '.join(sorted(trusted_proxies))}")
        condition = f" unless {TRUSTED_ACL}"
    return lines + [
        f"    http-request del-header X-Forwarded-For{condition}",
        f"    http-request del-header X-Forwarded-Proto{condition}",
        f"    http-request del-header X-Forwarded-Host{condition}",
        f"    http-request set-header X-Forwarded-Proto {protocol}{condition}",
        f"    http-request set-header X-Forwarded-Host %[req.hdr(host),field(1,:),lower]{condition}",
    ]


def _abuse_rules(protection: AbuseProtection | None, trusted: bool) -> list[str]:
    """A brake on one source address that is plainly not a visitor.

    The table lives in the frontend because the address is what gets flooded,
    not the site. `expire` is one window: an entry that has stopped counting
    has nothing left to say, and a longer life would only hold memory.

    Refused with 429 rather than dropped silently. A client that is merely
    misconfigured - a retry loop, a monitoring script - can read a status code
    and be fixed; a silent drop looks like a network fault and gets debugged
    for an afternoon.

    Behind a trusted proxy the address to count is not the one the connection
    came from - that is the proxy, and counting it would see one client making
    all the traffic in the world and refuse everybody within one window. The
    forwarded address is counted instead, and the *last* element of the header
    rather than the first: a visitor may put anything in front, and the last
    entry is the one the trusted proxy wrote from what it actually saw.
    Measured here - two visitors behind one proxy, and braking the noisy one
    left the other served.
    """

    if protection is None:
        return []
    window = protection.window
    stored = ["http_req_rate", "http_err_rate"]
    #
    # A rule carries one condition, so the exception is written as a negated
    # ACL alongside the counter rather than as a second `unless` - which parses
    # as an ACL named "unless" and is refused by HAProxy, measured here.
    #
    lines = [
        f"    stick-table type ip size {ABUSE_TABLE_SIZE} expire {window} "
        f"store {','.join(f'{name}({window})' for name in stored)}",
    ]
    if trusted:
        #
        # Two rules with opposite conditions rather than one: HAProxy takes the
        # first that matches, so a request through the proxy is counted by the
        # forwarded address and every other request by the address it came
        # from. A request from a trusted proxy with no header at all matches
        # neither and is counted by nothing, which is the right answer - there
        # is no address to hold responsible.
        #
        lines.append(f"    http-request track-sc0 req.hdr_ip(X-Forwarded-For,-1) if {TRUSTED_ACL}")
        lines.append(f"    http-request track-sc0 src unless {TRUSTED_ACL}")
    else:
        lines.append("    http-request track-sc0 src")

    for fetch, limit in (
        ("sc_http_req_rate(0)", protection.max_requests),
        ("sc_http_err_rate(0)", protection.max_errors),
    ):
        if limit is not None:
            lines.append(f"    http-request deny deny_status 429 if {{ {fetch} gt {limit} }}")
    return lines


def _listing_name(
    identity: str,
    listings: dict[str, str],
    members: Sequence[tuple[Vip, Proxy, str]],
    protocol: str,
) -> str:
    """Name this listener's certificate list, and produce it in the same breath.

    Named after the frontend it belongs to, so a file and the line that reads
    it can be matched without following an index.

    Nothing at all for a listener that serves no TLS. A plain http frontend has
    no `crt-list` on its bind line, and a file nothing names would still be
    published, deployed and read by whoever went looking for what uses it.
    """

    if protocol != "https":
        return ""
    name = f"{identity}{CRT_LIST_SUFFIX}"
    listings[name] = _crt_list(members)
    return name


def _crt_list(members: Sequence[tuple[Vip, Proxy, str]]) -> str:
    """Every certificate this listener may serve, and any terms of its own.

    One listener, many certificates, chosen per connection by SNI - and HAProxy
    will hold one of them to different terms than the next, which is what lets
    a site with a requirement of its own keep sharing an address. The options
    ride on the certificate's line; the bind line's policy applies to every
    line that names none.

    Each object owns one line with explicit SNI filters. HAProxy may therefore
    load one certificate on several lines and choose the object's terms by the
    name offered in the handshake. Keeping the line per object also keeps its
    release-manifest fingerprint independent of a sibling.
    """

    lines: list[str] = []
    certificates: list[str] = []
    for _, proxy, role in members:
        certificate = proxy.listen.certificate
        if role != "serve" or certificate is None:
            continue
        certificates.append(certificate)
        lines.append(_certificate_terms(certificate, proxy.listen.tls_policy, proxy.hostnames))
    fallback = _certificate_terms(sorted(certificates)[0], None)
    return "".join(f"{line}\n" for line in (fallback, *sorted(lines)))


def _certificate_terms(certificate: str, policy: str | None, hostnames: Sequence[str] = ()) -> str:
    """One line of a certificate list: the file, and any terms of its own."""

    options = "" if policy is None else f" [{TLS_POLICIES[policy].strip()}]"
    filters = "" if not hostnames else f" {' '.join(sorted(hostnames))}"
    return f"{NODE_CERTIFICATE_DIR}/{certificate}.pem{options}{filters}"


def _certificate_line(proxy: Proxy) -> str:
    """The line this object puts in its listener's certificate list.

    The same writer the list itself uses, not a second rendering of the same
    rule: a manifest that fingerprinted a certificate one way while the node
    was served another would report a difference nobody made, or miss one
    somebody did.

    Empty for an object that terminates no TLS. `_crt_list` writes a line only
    for a member serving under a certificate, and this answers for the same
    member.
    """

    certificate = proxy.listen.certificate
    if proxy.listen.protocol != "https" or certificate is None:
        return ""
    return f"{_certificate_terms(certificate, proxy.listen.tls_policy, proxy.hostnames)}\n"


def _tls(members: Sequence[tuple[Vip, Proxy, str]], protocol: str, listing: str) -> str:
    """The TLS half of a bind line: where this listener's certificates are listed.

    A list in a file of its own rather than a run of `crt` arguments, because a
    `crt` argument carries no terms - and a site that needs its own is the
    whole point of B82b. The path is relative to this file's directory, which
    `default-path config` in `core/haproxy.cfg` is what makes work: the node
    validates a copy of the release at a different path before installing it,
    and an absolute path would have to be rewritten to be checked at all.

    The bind line keeps the VIP's policy. It applies to every certificate whose
    own line names none, which is the normal case.
    """

    if protocol != "https":
        return ""
    #
    # Absent, the listener takes whatever `core/` sets. Written only where the
    # cluster named a policy, because a bind line overrides `core/` in both
    # directions and a default here could loosen a cluster nobody looked at.
    #
    vip = members[0][0]
    policy = "" if vip.tls_policy is None else TLS_POLICIES[vip.tls_policy]
    return f" ssl crt-list ../{CRT_LIST_TARGET}/{listing} alpn {ALPN}{policy}"


def _allow_rules(proxy: Proxy, networks: Mapping[str, Sequence[str]], host: str) -> list[str]:
    """Who gets an answer, when the answer is not for everybody.

    Written as a deny rather than as a condition on `use_backend`, so that a
    restricted object refuses a visitor outright instead of falling through to
    whatever the next matching rule happens to be. `http-request` rules run
    before routing, which is the right moment for this question.
    """

    if not proxy.allow_from:
        return []
    allowed = sorted(
        {
            cidr
            for entry in proxy.allow_from
            for cidr in ((entry,) if is_range(entry) else networks[entry])
        }
    )
    acl = _acl_name(proxy.name, "allow")
    return [
        f"    acl {acl} src {' '.join(allowed)}",
        f"    http-request deny deny_status 403 if {host} !{acl}",
    ]


def _message(proxy: Proxy, message: str) -> str:
    """One object's message with the site's name filled in.

    The first hostname, where an object claims several. They are aliases for
    one site, and a message listing all of them would read as a directory
    rather than as a sentence; the first is the one the object leads with.

    Substituted here rather than at request time on purpose - see `URL_PLACEHOLDER`.
    A hostname has already been held to `HOSTNAME`, so nothing that could
    change where the configuration line ends can arrive through it.

    The escape is the other half of the model letting a message carry `$`. The
    line is written in double quotes, where HAProxy would expand `$HOME` into
    a value from the node's environment; a backslash before it is a literal
    dollar there, measured on 3.4.4 on this machine. Quotes and backslashes never reach
    here - the model refuses them - so there is nothing else to escape and
    nothing that could already be escaped.
    """

    filled = message.replace(URL_PLACEHOLDER, proxy.hostnames[0])
    return filled.replace("$", "\\$")


def _maintenance_rule(proxy: Proxy, host: str) -> list[str]:
    """The answer while an object is deliberately out of service.

    Written before this object's `use_backend` lines rather than instead of
    them. `http-request return` ends the transaction, so nothing below it is
    reached for these names - and leaving the routing in place means turning
    maintenance off changes one rule instead of regenerating the object's whole
    contribution, and the pools stay routed to and therefore stay checked.

    Conditional on the host, which is what makes it safe here at all: an
    unconditional `http-request` rule in a shared frontend would answer for
    every object on the address, which is why the unknown-name answer is a
    backend and this one is not.

    `no-store` because the page is a temporary truth. A browser that cached a
    503 would keep showing it after the site came back, and the visitor would
    have no way to tell.
    """

    if proxy.maintenance is None:
        return []
    return [
        f"    http-request return status 503 content-type text/plain "
        f'string "{_message(proxy, proxy.maintenance.message)}" '
        f'hdr cache-control "no-store" if {host}'
    ]


def _host_acl(proxy: Proxy) -> list[str]:
    """Which requests belong to this object at all.

    The Host header is lowercased and its port removed before comparison. A
    client is free to send `Shop.Example.com:80`, and a rule that only matched
    the spelling in the object would work until the day something sent the
    other one.
    """

    acl = _acl_name(proxy.name, "host")
    return [
        f"    acl {acl} req.hdr(host),field(1,:),lower -m str {hostname}"
        for hostname in proxy.hostnames
    ]


def _path_acl(proxy: Proxy, route: Route, index: int) -> tuple[str, list[str]]:
    """One route's path condition, in the semantics `route_match` freezes.

    A prefix becomes two lines with the same ACL name, which HAProxy reads as
    an OR: the prefix exactly, or the prefix followed by a separator. That pair
    is the segment boundary - it is why `/api` does not match `/apix` - and it
    is a rule about where a path may end rather than about how it starts.

    An exact route also accepts its own trailing slash, because the frozen
    semantics say `/health` and `/health/` are one route.
    """

    acl = _acl_name(proxy.name, f"path{index}")
    if route.match == "exact":
        return acl, [
            f"    acl {acl} path -m str {route.path}",
            f"    acl {acl} path -m str {route.path}/",
        ]
    return acl, [
        f"    acl {acl} path -m str {route.path}",
        f"    acl {acl} path -m beg {route.path}/",
    ]


def _rewrite_rule(route: Route) -> list[str]:
    """What the backend is given, when it is not what arrived.

    Written in the backend, and that placement is not a style choice. HAProxy
    evaluates `http-request` rules before `use_backend`, so a rewrite in the
    frontend changes the path that the routing decision is then made on: a
    request for `/api/orders` becomes `/v2/orders`, no longer matches the ACL
    that was about to send it to the API pool, and quietly falls through to
    whatever matches last. Measured on this machine with HAProxy 3.4.4 on
    2026-08-31 - it does not fail, it routes to the wrong place.

    Rules inside a backend run after the backend has been chosen, which is
    exactly when a path may be rewritten.

    The pattern accepts the prefix with or without its trailing slash and
    always produces a path starting with `/`, which is the same result
    `route_match.rewrite` computes - the tests hold the two against each other.
    """

    strip = route.strip_prefix
    add = route.add_prefix or ""
    if strip is None and not add:
        return []
    if strip is None:
        return [f"    http-request replace-path (.*) {add}\\1"]
    return [f"    http-request replace-path ^{strip}/?(.*) {add}/\\1"]


def _fallback_name(vip: Vip, protocol: str) -> str:
    return f"{PREFIX}-{vip.name}-{protocol}-unknown"


def _fallback(vip: Vip, protocol: str, unknown_host: UnknownHost) -> list[str]:
    """The answer for a name no object claims.

    A backend rather than a rule in the frontend, because `http-request` rules
    run before `use_backend` and an unconditional one there would answer every
    request, claimed name or not. A `default_backend` is reached only when no
    rule matched, which is exactly the question being answered.
    """

    lines = ["", f"backend {_fallback_name(vip, protocol)}", "    mode http"]
    if unknown_host.redirect is not None:
        lines.append(f"    http-request redirect location {unknown_host.redirect} code 301")
    else:
        lines.append(
            f"    http-request return status {unknown_host.status} "
            f'content-type text/plain string "No site is configured for this name."'
        )
    return lines


def _frontend_rules(
    proxy: Proxy,
    role: str = "serve",
    networks: Mapping[str, Sequence[str]] | None = None,
    *,
    members: Sequence[tuple[Vip, Proxy, str]] = (),
) -> list[str]:
    """One object's whole contribution to the shared frontend.

    The routes are written in the order `order_routes` decides, and that order
    is the only thing consulted at runtime: HAProxy takes the first
    `use_backend` whose condition holds. Deciding it here rather than at
    request time is what makes the file a complete description of where traffic
    goes.
    """

    host = _acl_name(proxy.name, "host")
    lines = ["", f"    # {proxy.name}", *_host_acl(proxy)]

    allow = _allow_rules(proxy, networks or {}, host)
    lines.extend(allow)

    if role == "redirect":
        #
        # The whole of this object's presence on port 80: everything that
        # arrives for one of its names is told to come back over TLS, and
        # nothing is served in cleartext, not even a path.
        #
        return [*lines, f"    redirect scheme https code 301 if {host}"]

    lines.extend(_tls_sni_guard(proxy, host, members))

    lines.extend(_maintenance_rule(proxy, host))

    decisions: list[str] = []
    for index, route in enumerate(order_routes(proxy.routes)):
        backend = _backend_name(proxy.name, _destination(route))
        if route.path == "/" and route.match == "prefix":
            #
            # The root prefix matches every path, so a path condition would be
            # a rule that is always true. The host condition alone is both
            # shorter and honest about what is being decided.
            #
            condition = host
        else:
            acl, acl_lines = _path_acl(proxy, route, index)
            lines.extend(acl_lines)
            condition = f"{host} {acl}"
        decisions.append(f"    use_backend {backend} if {condition}")

    return lines + decisions


def _tls_sni_guard(
    proxy: Proxy, host_acl: str, members: Sequence[tuple[Vip, Proxy, str]]
) -> list[str]:
    """Do not route an HTTP site over another policy group's TLS connection."""

    served = [(vip, member) for vip, member, role in members if role == "serve"]
    policies = {member.listen.tls_policy or vip.tls_policy for vip, member in served}
    if proxy.listen.protocol != "https" or len(policies) < 2:
        return []
    vip = next(vip for vip, member in served if member is proxy)
    policy = proxy.listen.tls_policy or vip.tls_policy
    allowed = sorted(
        {
            hostname
            for other_vip, member in served
            if (member.listen.tls_policy or other_vip.tls_policy) == policy
            for hostname in member.hostnames
        }
    )
    sni_acl = _acl_name(proxy.name, "tls-sni")
    return [
        f"    acl {sni_acl} ssl_fc_sni,lower -m str {' '.join(allowed)}",
        f"    http-request deny deny_status 421 if {host_acl} !{sni_acl}",
    ]


def _destination(route: Route) -> str:
    """The backend name a route sends to, whether it is a pool or an answer.

    A redirect's name is derived from what it does rather than from where it
    sits in the list. Adding a route above it then moves no name, and therefore
    no GUID and no counter - the same reason a server is identified by its
    address instead of its position.
    """

    if route.backend is not None:
        return route.backend
    redirect = route.redirect
    if redirect is None:
        #
        # The model refuses a route that sets neither, so reaching this means
        # the two layers have drifted. Said as a refusal rather than as an
        # assertion, so it survives the day somebody runs with -O.
        #
        raise GeneratorError(f"a route sends nowhere: {route.path}")
    name = redirect_name(route.path, route.match, redirect.location)
    return f"{REDIRECT_PREFIX}-{name}"


def _redirect_backends(proxy: Proxy) -> list[str]:
    lines: list[str] = []
    for route in order_routes(proxy.routes):
        if route.redirect is None:
            continue
        name = _destination(route)
        lines += [
            "",
            f"backend {_backend_name(proxy.name, name)}",
            f"    guid {backend_guid(proxy.name, name)}",
            "    mode http",
            #
            # Written in single quotes: a redirect location is a log-format
            # string, so `%` has to be doubled, and HAProxy expands `$NAME`
            # inside double quotes but not inside single ones. Both measured on
            # 3.4.4 on this machine.
            #
            f"    http-request redirect location '{_header_value(route.redirect.location)}' "
            f"code {route.redirect.status}",
        ]
    return lines


def _object_file(proxy: Proxy, source: str | None, resolvers: str | None) -> str:
    rewrites = _rewrites_per_backend(proxy)
    body: list[str] = []
    for name in sorted(proxy.backends):
        body.extend(_backend(proxy, proxy.backends[name], rewrites[name], source, resolvers))
    body.extend(_redirect_backends(proxy))
    return _lines(HEADER, ["#", f"# Object: {proxy.name}", "#"], body)


def _rewrites_per_backend(proxy: Proxy) -> dict[str, list[str]]:
    """The path rewrite each pool applies, and a refusal when routes disagree.

    Since the rewrite has to live in the backend, every route reaching a given
    pool has to want the same rewrite. Two routes that send to one pool while
    stripping different prefixes are asking for two backends, and saying so is
    better than generating configuration where one of the two rules silently
    wins. Giving them separate pool names costs nothing and reads correctly.
    """

    rewrites: dict[str, list[str]] = {name: [] for name in proxy.backends}
    seen: dict[str, Route] = {}
    for route in proxy.routes:
        if route.backend is None:
            continue
        earlier = seen.get(route.backend)
        if earlier is None:
            seen[route.backend] = route
            rewrites[route.backend] = _rewrite_rule(route)
            continue
        if (earlier.strip_prefix, earlier.add_prefix) != (route.strip_prefix, route.add_prefix):
            raise GeneratorError(
                f"{proxy.name}: {earlier.path} and {route.path} both send to the backend "
                f"{route.backend} but rewrite the path differently; give them separate backends"
            )
    return rewrites


def _server_name(index: int) -> str:
    """A stable, printable name for one pool member.

    The position, not the address. The name is what appears in logs and in
    `show stat`, where an address is already a column of its own; identity for
    the purpose of keeping counters across a reload is the server's GUID, and
    that one is derived from the address precisely so that reordering the pool
    does not move it.
    """

    return f"s{index + 1}"


def _balance(backend: Backend) -> str:
    """The `balance` line, in the two spellings HAProxy uses for it.

    A header is named inside parentheses and a query parameter after a space -
    verified against 3.4.4 on this machine rather than assumed, since the two
    look interchangeable and are not.
    """

    if backend.balance == "hdr":
        return f"hdr({backend.balance_key})"
    if backend.balance == "url_param":
        return f"url_param {backend.balance_key}"
    return backend.balance


def _header_lines(proxy: Proxy) -> list[str]:
    """The object's own header edits, in the backend where they cannot spread.

    In the backend rather than the frontend for the same reason the rewrites
    are: a frontend is shared between every object on an address, and a rule
    there would need a condition on every line to stay this object's.

    Values are written in single quotes. HAProxy expands `$NAME` inside double
    quotes and not inside single ones, measured on 3.4.4 on this machine, so
    single quoting is what lets a value hold a dollar sign at all. `%` is a
    log-format alias even there and has to be doubled - HAProxy says so itself
    when it refuses to start: "Maybe you want to write a single '%', use the
    syntax '%%'".
    """

    lines: list[str] = []
    for phase, actions in (
        ("request", proxy.headers.request),
        ("response", proxy.headers.response),
    ):
        for name, value in actions.assign:
            lines.append(f"    http-{phase} set-header {name} '{_header_value(value)}'")
        for name, value in actions.append:
            lines.append(f"    http-{phase} add-header {name} '{_header_value(value)}'")
        for name in actions.remove:
            lines.append(f"    http-{phase} del-header {name}")
    return lines


def _header_value(value: str) -> str:
    return value.replace("%", "%%")


def _hsts_line(proxy: Proxy) -> list[str]:
    """The Strict-Transport-Security header, written where it can be written.

    In the backend, not the frontend, and that is HAProxy's rule rather than a
    preference: an `http-response` rule in a frontend cannot read the request's
    Host header, and HAProxy says so out loud - "will never match because it
    only involves keywords that are incompatible with 'frontend http-response
    header rule'". Measured on 3.4.4 on this machine. In a backend no condition
    is needed at all, since a backend belongs to exactly one object.
    """

    hsts = proxy.listen.hsts
    if hsts is None:
        return []
    value = f"max-age={hsts.max_age}"
    if hsts.include_subdomains:
        value += "; includeSubDomains"
    return [f'    http-response set-header Strict-Transport-Security "{value}"']


def _server_address(server: Server, resolvers: str | None) -> str:
    """How a member's address is kept current, when it is a name.

    Without a resolvers section HAProxy looks a hostname up once, while it is
    starting, and keeps that answer until the next reload. A container host
    that changes address, a rebuilt VM, a moved service - all of them take the
    site down until somebody happens to publish again, and in the interface it
    looks like a dead backend rather than like stale DNS.

    `init-addr last,libc,none` is what makes that safe in the other direction
    too: if DNS is unreachable at startup the server begins disabled instead of
    HAProxy refusing to start. Measured on 3.4.4 here - it is a notice, not an
    error. An address needs none of this, so it gets none of it.
    """

    if resolvers is None:
        return ""
    try:
        ipaddress.ip_address(server.host)
    except ValueError:
        return f" resolvers {resolvers} init-addr last,libc,none"
    return ""


def _backend(
    proxy: Proxy,
    backend: Backend,
    rewrites: list[str],
    source: str | None,
    resolvers: str | None = None,
) -> list[str]:
    name = _backend_name(proxy.name, backend.name)
    raw = proxy.listen.protocol == "tcp"
    lines = [
        "",
        f"backend {name}",
        f"    guid {backend_guid(proxy.name, backend.name)}",
        f"    mode {'tcp' if raw else 'http'}",
        f"    balance {_balance(backend)}",
        f"    timeout connect {TIMEOUT_CONNECT}",
        f"    timeout server {TIMEOUT_SERVER}",
    ]
    if not raw:
        #
        # Both are HTTP-only and HAProxy says so in a warning rather than an
        # error: the tunnel timeout is what an upgraded connection lives on,
        # and a raw stream is already a tunnel, while `forwardfor` writes a
        # header a raw connection has nowhere to put.
        #
        lines.append(f"    timeout tunnel {TIMEOUT_TUNNEL}")
    lines += [
        f"    retries {RETRIES}",
        "    option redispatch",
    ]
    if not raw:
        lines.append("    option forwardfor")
    if source is not None:
        #
        # The address this pool is reached from. Written per backend because
        # that is the only place HAProxy takes it. It is the VIP's own source
        # unless the object named another: traffic normally leaves from the
        # address paired with the one it arrived on, which is what a firewall
        # rule further in is written against.
        #
        lines.append(f"    source {source}")
    lines.extend(rewrites)
    lines.extend(_hsts_line(proxy))
    lines.extend(_header_lines(proxy))
    lines.extend(_unavailable_lines(proxy))

    if backend.max_connections is not None:
        #
        # What does not fit on a server waits here rather than being refused.
        # HAProxy takes this wait from `timeout connect` when nobody says
        # otherwise - read from its documentation on this machine - and it is
        # written out so the file says how long a queued request may wait
        # instead of leaving it to be inferred from another line.
        #
        lines.append(f"    timeout queue {TIMEOUT_CONNECT}")

    if backend.cookie is not None:
        #
        # `insert` adds the cookie, `indirect` removes it again before the
        # request reaches the application so it never sees a cookie it did not
        # set, and `nocache` stops a shared cache from storing one visitor's
        # cookie and handing it to the next.
        #
        lines.append(f"    cookie {backend.cookie} insert indirect nocache")

    lines.extend(_health_lines(backend.health))

    for index, server in enumerate(backend.servers):
        name = _server_name(index)
        cookie = f" cookie {name}" if backend.cookie is not None else ""
        backup = " backup" if server.backup else ""
        limit = f" maxconn {backend.max_connections}" if backend.max_connections else ""
        #
        # Per server rather than per backend, because that is where HAProxy
        # takes both: the limit is one machine's capacity and the ramp is one
        # machine coming back, and a pool-wide number would be neither.
        #
        ramp = f" slowstart {backend.slow_start}" if backend.slow_start else ""
        lines.append(
            f"    server {name} {server.host}:{server.port}"
            f" guid {server_guid(proxy.name, backend.name, server)}"
            f"{_server_tls(backend, server)}{_server_address(server, resolvers)}"
            f"{_server_check(backend, server)}{cookie}{backup}{limit}{ramp}"
        )
    return lines


def _unavailable_lines(proxy: Proxy) -> list[str]:
    """The three answers that mean the pool could not serve the request.

    502, 503 and 504 look identical to a visitor - a grey page from something
    that is not the site - and telling them apart is the operator's job, not
    theirs. One message covers all three so the answer does not depend on which
    way the pool failed.

    Written per backend because that is where HAProxy takes it, and because a
    message naming the site would be wrong in a shared frontend.

    A string rather than a file: `errorfile` would need HTML carried to every
    node and versioned with the release, which is a lot of machinery for a
    sentence. Measured on 3.4.4 on this machine.
    """

    if proxy.unavailable is None:
        return []
    return [
        f"    http-error status {status} content-type text/plain "
        f'string "{_message(proxy, proxy.unavailable.message)}"'
        for status in (502, 503, 504)
    ]


def _health_lines(health: Health) -> list[str]:
    """The check itself, in the form the chosen protocol takes.

    The six monitor types an ADC lists are combinations of three choices, and
    they land on three different HAProxy mechanisms: a bare connection, a
    `tcp-check` exchange, and an `httpchk` request. Each was validated against
    3.4.4 on this machine.
    """

    if health.type == "disabled":
        return []

    if health.type == "tcp":
        if health.send is None:
            #
            # A plain connection attempt. `ssl-hello-chk` makes it a TLS
            # handshake instead, which is the difference between "the port
            # answers" and "the service behind it still has a working
            # certificate".
            #
            return ["    option ssl-hello-chk"] if health.tls is True else []
        connect = "    tcp-check connect ssl" if health.tls is True else "    tcp-check connect"
        return [
            "    option tcp-check",
            connect,
            f"    tcp-check send {health.send}",
            f"    tcp-check expect string {health.expect}",
        ]

    lines = ["    option httpchk"]
    if health.tls is True:
        lines.append("    http-check connect ssl")
    send = f"    http-check send meth GET uri {health.path}"
    if health.host is not None:
        #
        # Without this a backend doing name-based virtual hosting answers the
        # check with a 404 or a redirect, and a healthy pool is reported down.
        #
        send += f" hdr Host {health.host}"
    lines.append(send)
    lines.append(f"    http-check expect status {health.expect_status}")
    if health.expect_body is not None:
        lines.append(f"    http-check expect string {health.expect_body}")
    return lines


def _connects_with_ssl(health: Health) -> bool:
    """Whether the check opens its own TLS connection, rather than just greeting.

    `option ssl-hello-chk` is a handshake and nothing else - no certificate is
    judged, and HAProxy asks for no verification policy, which the golden cases
    prove by validating without one. `http-check connect ssl` and `tcp-check
    connect ssl` are real connections, and those are the ones that need the
    server line to say what happens to the certificate.
    """

    if health.tls is not True:
        return False
    return health.type == "http" or health.send is not None


def _check_encryption(backend: Backend, health: Health) -> str:
    """Whether the check speaks TLS, in HAProxy's words rather than the form's.

    Three answers, and every one of them was measured on 3.4.4 on this machine
    on 2026-09-05, against a local TLS server and a local plaintext one, with
    `show stat` as the verdict rather than `haproxy -c`:

    * **Following the pool** writes nothing. A TLS pool checked on its traffic
      port inherits the handshake - `L7OK 200` - and a plain pool is checked in
      plain.
    * **A check port breaks that inheritance.** A TLS pool with `check port`
      and nothing said ran the check *in plaintext* and answered `L7OK 200`
      from a plaintext port, which is why `check-ssl` is written there. Sent to
      a port that does not speak TLS it is `L6RSP` and the server goes down -
      the same code that reached the health card and cost an evening.
    * **`no-check-ssl` is the way to say plaintext on a TLS pool**, and it
      works: `L7OK 200` against the plaintext port while traffic stays on TLS.
      Without it the combination could not be expressed at all.

    The fourth line, `verify none` for a TLS check on a plain pool, is on the
    server line rather than here - it is a property of the connection, not of
    the check - and lives in `_server_tls` with the rest of them.
    """

    #
    # What the answer is comes from `check_policy`; this decides how to write
    # it. The two used to be one function here, and the interface's probe held
    # a second copy of the deciding half - which drifted, and cost B92.
    #
    if not check_speaks_tls(backend, health):
        #
        # Only where there is something to opt out of. On a plain pool the
        # check is already plaintext, and the word would say a decision was
        # made where none was needed.
        #
        return " no-check-ssl" if backend.tls is not None else ""
    if backend.tls is not None and health.port is not None:
        #
        # Inheritance stops at a different port, so what would have been
        # implied is written out. The decision is unchanged - this pool's
        # check speaks TLS either way - and only its spelling depends on
        # where the check is sent.
        #
        return " check-ssl"
    return ""


def _server_check(backend: Backend, server: Server) -> str:
    """The check on the server line, with whether it is encrypted beside it.

    HAProxy's own documentation for 3.4.4 on this machine, under `ssl`: "health
    checks are automatically sent in SSL too unless there is a 'port' or an
    'addr' directive indicating the check should be sent to a different
    location." Which of the three answers that leaves is `_check_encryption`.
    """

    health = backend.health
    if health.type == "disabled":
        return ""
    port = f" port {health.port}" if health.port is not None else ""
    encrypted = _check_encryption(backend, health)
    #
    # No `check-sni`, and that is measured rather than assumed. Making the
    # check send the name too looks obviously right - a check that speaks a
    # different handshake than the traffic reports on something nobody asked
    # about - but on 3.4.4 it makes the check fail with `L6RSP` against a pool
    # the same configuration serves perfectly. Measured 2026-09-04, both ways,
    # against the same pool: `sni` alone answers 200 and `sni` with `check-sni`
    # answers 503 because every server is marked down.
    #
    # So the argument for adding it stands and the behaviour does not. Left out
    # until somebody can say why it fails, rather than carried because the
    # reasoning was appealing.
    #
    return f" check{port}{encrypted} inter {health.interval} rise {health.rise} fall {health.fall}"


def _server_tls(backend: Backend, server: Server) -> str:
    """How this pool is reached, when it is reached over TLS.

    `@system-ca` is HAProxy's own name for the trust store the operating system
    maintains. Naming it rather than writing a path keeps an environment value
    out of the generator - and `verify required` without a CA is refused by
    HAProxy outright, measured on 3.4.4, so there is no silent third option
    where verification quietly does nothing.

    **`sni` is not optional here.** Measured on 3.4.4 on 2026-09-04, against a
    pool whose certificate a browser and `openssl s_client` both accept:
    `ssl verify required ca-file @system-ca` without `sni` fails the handshake
    on every request - `SC--`, no connection established, three retries in a
    millisecond - and the site answers 503 while its health check stays green.
    Adding `sni` fixed it; `verifyhost` alone did not. Five configurations were
    compared to isolate that, and the TLS policy turned out to be innocent.

    The name comes from the server's own host, which the model has already
    required to be a name rather than an address for exactly this reason.
    """

    if backend.tls is None:
        #
        # A plain pool whose check speaks TLS anyway - a health endpoint on its
        # own TLS port, which happens. HAProxy defaults server-side SSL to
        # verifying, and refuses a configuration that verifies with no CA:
        # "verify is enabled by default but no CA file specified". `verify
        # none` alone, without `ssl`, answers that without making the pool
        # itself TLS - measured `L7OK 200` on 3.4.4, 2026-09-05.
        #
        # Not verified, and it cannot be. A certificate is checked against a
        # name, HAProxy's check sends no SNI, and `check-sni` fails outright
        # (see `_server_check`). The form says this in a sentence rather than
        # leaving it to be discovered here.
        #
        return " verify none" if _connects_with_ssl(backend.health) else ""
    #
    # Two answers on one line, and they are separate questions. `verify` is
    # whether the certificate has to be trusted; the policy is how old the
    # handshake may be. Written in that order because that is how the object
    # reads.
    #
    policy = BACKEND_POLICIES[backend.tls.policy]
    if backend.tls.verify == "none":
        return f" ssl verify none{policy}"
    return f" ssl verify required ca-file @system-ca sni str({server.host}){policy}"
