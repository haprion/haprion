"""Proxy objects in, HAProxy configuration out.

This is the generator. It takes the objects the application writes under
`managed/proxies/` and produces the files that go under `managed/generated/`,
and it is the only place in the system that knows HAProxy's configuration
language. Everything it emits is decided here and nowhere else: the matching
rules come from `route_match`, the stable names from `guid`, and the shape of
the input from `proxy_model`.

**One shared frontend, many backend files.** A frontend owns its listening
port, and HAProxy will not bind the same port twice - the configuration passes
`haproxy -c` and then the process exits at startup, which is the worst place to
find out. So every object's routing goes into one generated frontend per
protocol, and each object gets its own file holding only its backends. It is
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
from haproxy_mgmt.reservations import NOTHING_RESERVED, Reservations
from haproxy_mgmt.route_match import order_routes

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
# What each TLS policy a VIP may name means on a bind line. The names are
# `config.TLS_POLICY_NAMES`; the syntax is here, because this is the module
# that writes HAProxy.
#
# The cipher sets are Mozilla's, and they are written as one string per policy
# rather than assembled from parts: a cipher list is an ordered preference, and
# code that builds one out of pieces makes the order an accident.
#
# Both were put through `haproxy -c` on this machine on 3.4.4, and `modern` was
# run: a client held to TLS 1.2 got no handshake at all, and a TLS 1.3 client
# was served.
#
TLS_1_2_CIPHERS = (
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
    "DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305"
)
TLS_1_3_CIPHERSUITES = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"
TLS_POLICIES = {
    "intermediate": (
        f" ssl-min-ver TLSv1.2 ciphers {TLS_1_2_CIPHERS} ciphersuites {TLS_1_3_CIPHERSUITES}"
    ),
    "modern": f" ssl-min-ver TLSv1.3 ciphersuites {TLS_1_3_CIPHERSUITES}",
}

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
) -> dict[str, str]:
    """Every file the generated layer consists of, keyed by filename.

    The whole layer at once rather than one object at a time, because the
    frontend is shared: what one object routes cannot be decided without
    knowing what the others route. The caller writes the returned mapping and
    deletes anything else it finds in `managed/generated/`, so an object that
    was removed takes its configuration with it.
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
    _refuse_reserved(ordered, reservations, ports)
    _refuse_unknown_certificates(ordered, certificates)
    known_networks = dict(networks or {})
    _refuse_unknown_networks(ordered, known_networks)

    known_sources = dict(sources or {})
    placed = [(_vip_of(proxy, vips, default_vip), proxy) for proxy in ordered]
    _refuse_shared_listeners(placed, ports)

    files = {
        FRONTEND_FILE: _frontend_file(
            placed, ports, known_networks, unknown_host, tuple(trusted_proxies), abuse_protection
        )
    }
    for vip, proxy in placed:
        files[f"{OBJECT_BAND}-{proxy.name}.cfg"] = _object_file(
            proxy, _source_of(proxy, vip, known_sources), resolvers
        )
    return files


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
    proxies: Sequence[Proxy], reservations: Reservations, ports: Mapping[str, int]
) -> None:
    """What the handwritten half of the configuration has already claimed.

    Refused here rather than left to the node, because both failures are ones
    HAProxy does not report as failures. A duplicated hostname is answered by
    whichever frontend happens to come first in the directory, and two
    frontends on one port pass `haproxy -c` and then kill the process at
    startup - so the publish says it worked and the node stops serving.
    """

    for proxy in proxies:
        taken = sorted(set(proxy.hostnames) & reservations.hostnames)
        if taken:
            raise GeneratorError(
                f"{proxy.name} claims a hostname reserved in manual/reservations.yaml: "
                f"{', '.join(taken)}"
            )

    if not reservations.tcp_ports:
        return
    #
    # Only the ports objects actually cause to be bound. Reserving a port
    # nothing generated listens on is a person writing down what the
    # handwritten side uses, which is the file's whole purpose.
    #
    for proxy in proxies:
        if proxy.listen.port is not None and proxy.listen.port in reservations.tcp_ports:
            raise GeneratorError(
                f"{proxy.name} listens on port {proxy.listen.port}, which "
                f"manual/reservations.yaml reserves for handwritten configuration"
            )

    wanted = {proxy.listen.protocol for proxy in proxies if proxy.listen.protocol != "tcp"}
    wanted |= {"http" for proxy in proxies if proxy.listen.redirect_http}
    for protocol in sorted(wanted):
        port = ports.get(protocol)
        if port is not None and port in reservations.tcp_ports:
            raise GeneratorError(
                f"this cluster serves {protocol} on port {port}, which "
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


def _refuse_shared_listeners(placed: Sequence[tuple[Vip, Proxy]], ports: Mapping[str, int]) -> None:
    """One address and port may be bound exactly once.

    The failure this prevents is the one B47 measured: two frontends on one
    port pass `haproxy -c` and then kill the process at startup, so a publish
    reports success and the node stops answering for everything.

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
                other.listen.protocol == protocol and other_vip.name == vip.name
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


def _frontend_file(
    placed: Sequence[tuple[Vip, Proxy]],
    ports: Mapping[str, int],
    networks: Mapping[str, Sequence[str]],
    unknown_host: UnknownHost | None,
    trusted_proxies: Sequence[str],
    abuse_protection: AbuseProtection | None,
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
        body += [
            "",
            f"frontend {_frontend_name(vip, protocol)}",
            f"    guid {frontend_guid(identity)}",
            f"    bind {vip.address}:{ports[protocol]}"
            f"{_tls(members, protocol)} guid-prefix {listener_guid_prefix(identity)}",
            "    mode http",
            "    option httplog",
            f"    timeout client {TIMEOUT_CLIENT}",
            *_forwarded_rules(protocol, trusted_proxies),
            *_abuse_rules(abuse_protection, bool(trusted_proxies)),
        ]
        for _, proxy, role in members:
            body.extend(_frontend_rules(proxy, role, networks))
        if unknown_host is not None:
            body.append(f"    default_backend {_fallback_name(vip, protocol)}")
            fallbacks.extend(_fallback(vip, protocol, unknown_host))
    for vip, proxy in sorted(tcp, key=lambda member: member[1].name):
        body.extend(_tcp_frontend(vip, proxy, networks, abuse_protection))
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
    lines.append(f"    default_backend {_backend_name(proxy.name, proxy.backend or '')}")
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


def _tls(members: Sequence[tuple[Vip, Proxy, str]], protocol: str) -> str:
    """The TLS half of a bind line: every certificate this listener may serve.

    One listener, many certificates, chosen per connection by SNI. They are
    listed in a fixed order so the file is stable, and the first one is what a
    client that sends no SNI - or an unknown one - is given.
    """

    if protocol != "https":
        return ""
    wanted = sorted(
        {
            proxy.listen.certificate
            for _, proxy, role in members
            if role == "serve" and proxy.listen.certificate is not None
        }
    )
    crt = "".join(f" crt {NODE_CERTIFICATE_DIR}/{name}.pem" for name in wanted)
    #
    # Absent, the listener takes whatever `core/` sets. Written only where the
    # cluster named a policy, because a bind line overrides `core/` in both
    # directions and a default here could loosen a cluster nobody looked at.
    #
    vip = members[0][0]
    policy = "" if vip.tls_policy is None else TLS_POLICIES[vip.tls_policy]
    return f" ssl{crt} alpn {ALPN}{policy}"


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
    """

    return message.replace(URL_PLACEHOLDER, proxy.hostnames[0])


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
    proxy: Proxy, role: str = "serve", networks: Mapping[str, Sequence[str]] | None = None
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
            f"{_server_tls(backend)}{_server_address(server, resolvers)}"
            f"{_server_check(backend.health)}{cookie}{backup}{limit}{ramp}"
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
            return ["    option ssl-hello-chk"] if health.tls else []
        connect = "    tcp-check connect ssl" if health.tls else "    tcp-check connect"
        return [
            "    option tcp-check",
            connect,
            f"    tcp-check send {health.send}",
            f"    tcp-check expect string {health.expect}",
        ]

    lines = ["    option httpchk"]
    if health.tls:
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


def _server_check(health: Health) -> str:
    if health.type == "disabled":
        return ""
    port = f" port {health.port}" if health.port is not None else ""
    return f" check{port} inter {health.interval} rise {health.rise} fall {health.fall}"


def _server_tls(backend: Backend) -> str:
    """How this pool is reached, when it is reached over TLS.

    `@system-ca` is HAProxy's own name for the trust store the operating system
    maintains. Naming it rather than writing a path keeps an environment value
    out of the generator - and `verify required` without a CA is refused by
    HAProxy outright, measured on 3.4.4, so there is no silent third option
    where verification quietly does nothing.
    """

    if backend.tls is None:
        return ""
    if backend.tls.verify == "none":
        return " ssl verify none"
    return " ssl verify required ca-file @system-ca"
