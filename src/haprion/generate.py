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
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field

from haprion import advanced as advanced_config
from haprion import dnsdist_config, geo, ipvs_config
from haprion.check_policy import check_speaks_tls
from haprion.cluster_settings import NOTHING as NO_SETTINGS
from haprion.cluster_settings import ClusterSettings, LogTarget, Metrics
from haprion.config import AbuseProtection, ConfigError, UnknownHost, Vip
from haprion.guid import (
    frontend_guid,
    listener_guid_prefix,
    redirect_suffixes,
    server_guid,
)
from haprion.proxy_model import (
    DEFAULT_DOWN_INTERVAL,
    DEFAULT_FAST_INTERVAL,
    OUTSIDE_HAPROXY,
    OWN_PORT,
    URL_PLACEHOLDER,
    Backend,
    Health,
    Proxy,
    Route,
    Server,
    Waf,
    WafException,
    is_range,
)

#
# Not defined here. The lists, and where they came from, live in `tls_policy` -
# a cluster's own `core/haproxy.cfg` carries the same Mozilla recommendation,
# and the two had already drifted apart by one cipher before there was one
# place to point at.
#
from haprion.release_layout import CRT_LIST_TARGET
from haprion.reservations import NOTHING_RESERVED, Reservations
from haprion.route_match import order_routes
from haprion.tls_policy import BACKEND_POLICIES, TLS_POLICIES

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
# How many source addresses one table keeps counters for. A bound, not an
# allocation: HAProxy takes memory per entry as addresses arrive (measured on
# 3.4.6, 26-10-10: forty empty tables of 1m cost under a megabyte).
#
ABUSE_TABLE_SIZE = "1m"
#
# Keyed `ipv6`, which holds an IPv4 address as `::ffff:a.b.c.d` and answers to
# it written plainly. `ip` keeps only an IPv6 address's last 32 bits - `::1`
# became the key `0.0.0.1` (measured on 3.4.6, 26-10-10) - so every IPv6
# visitor whose address ended the same shared one count, and one block.
#
TABLE_KEY = "ipv6"
#
# The section the nodes share their stick tables in (B270). Every table the
# generator writes names it when the cluster has turned sharing on.
#
PEERS_SECTION = f"{PREFIX}-peers"

#
# The stick counter an object's own rate limit tracks on. Not 0, which the
# cluster's abuse brake holds in the frontend; see `_rate_lines`.
#
RATE_COUNTER = 1
#
# Dynamic blocking's two slots (B271): the address is counted on the fourth and
# marked on the fifth, past the cluster's brake, the rate limit and the one the
# advanced text may use. HAProxy's default is three slots, so a cluster with it
# needs `tune.stick-counters 5` in its core (`stick_counters_problem`).
#
BLOCK_COUNT_COUNTER = 3
BLOCK_MARK_COUNTER = 4
BLOCK_RULE = "dynamic-block:deny"

FRONTEND_FILE = "1000-frontends.cfg"
#
# What applies to the whole cluster rather than to an object (Fas 15, B209):
# the rings that carry the traffic log to external receivers, and the metrics
# exporter. Sorts before the frontends; HAProxy resolves a ring by name after
# reading everything, so the order is not load-bearing (measured 2026-09-29).
#
CLUSTER_FILE = "1000-cluster.cfg"
METRICS_FRONTEND = f"{PREFIX}-metrics"
METRICS_IDENTITY = "cluster-metrics"
OBJECT_BAND = "1001"

#
# The WAF engine (Fas 21 del B, B229-B233). Coraza SPOA runs beside HAProxy on
# every node, on loopback, and reads `coraza.yaml` from the release's `waf/`,
# which the node links at /etc/haproxy/waf as it does `maps/`. The port is
# part of the node-side contract like that directory: the node's deploy reads
# it back out of `coraza.yaml` to confirm the engine listens.
#
WAF_FILE = "1000-waf.cfg"
WAF_DIRECTORY = "/etc/haproxy/waf"
WAF_ENGINE_PORT = 9520
WAF_BACKEND = f"{PREFIX}-waf-engine"
WAF_IDENTITY = "cluster-waf"
WAF_SPOE_ENGINE = "coraza"
WAF_SPOE_GROUP = "coraza-req"
#
# The engine's answer to a name it does not know. An object's application is
# named after the object, which cannot begin with `_`; a HAProxy process still
# finishing connections after a reload may name an object that has just been
# removed, and the engine stops on an unknown name unless a default exists.
# The default inspects nothing - the object it would have inspected is gone.
#
WAF_UNKNOWN_APPLICATION = "_unknown"

#
# Where a node keeps the certificates it may serve. Part of the node-side
# contract rather than a choice this generator makes - `docs/user-manual.md`
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

# A second, opt-in stream. The ordinary `option httplog` output is deliberately
# untouched: this profile applies only to the additional per-frontend log
# target. `%HPO` is the path alone: no query string, and no scheme or host
# either. `%HP` also drops the query, but under HTTP/2 it is the absolute
# URI - measured on 3.4.4: `http://host/h2path` for an h2 request, `/h1path`
# for the same request over HTTP/1.1. HAProxy owns JSON quoting for every
# string value through `+json`.
#
# `format local` is HAProxy's default, RFC3164 without the hostname field, and
# it is what the ordinary `option httplog` stream already speaks. Naming
# `rfc3164` instead makes HAProxy insert a hostname before the tag, and
# rsyslog's local-socket reader does not parse hostnames: it took `localhost`
# as the program name, matched no rule, and the record fell through into
# /var/log/syslog. Measured on a node and against a real rsyslogd.
#
# `%rt` is not decoration. rsyslog ships with `$RepeatedMsgReduction on`, which
# silently collapses consecutive byte-identical messages into one - measured on
# a node: three sends, one line written. Without a field that differs per
# request, two identical requests inside the same second with identical timings
# and byte counts become one traffic record, and nothing anywhere says a record
# was dropped. The per-process request counter makes every record distinct, and
# is a useful ordering key on its own.
TRAFFIC_LOG_PROFILE = f"{PREFIX}-traffic-json"
HTTP_TRAFFIC_LOG_FORMAT = (
    '"%{+json}o %(schema)[int(1)] %(at)Ts %(request)rt %(client)ci %(method)HM '
    "%(host)[var(txn.traffic_host)] %(path)HPO %(frontend)f %(backend)b "
    "%(server)s %(status)ST %(request_time)TR %(queue_time)Tw "
    "%(connect_time)Tc %(response_time)Tr %(total_time)Ta %(bytes)B %(rule)[var(txn.rule)] "
    #
    # What the WAF engine found (B233): the CRS rules it matched and the
    # request's anomaly score, exactly as it reported them. Cut at the
    # column's bound; the collector keeps whole rule IDs only.
    #
    "%(waf_rules)[var(txn.coraza.rule_ids),bytes(0,1024)] "
    "%(waf_score)[var(txn.coraza.anomaly_score)] "
    #
    # The engine's transaction ID, which it hands back to HAProxy: the same ID
    # its own log puts on every rule it matched, so the WAF page can tell what
    # was found in this request (migration 0052, B234).
    #
    '%(waf_id)[var(txn.coraza.id),bytes(0,96)]"'
)
#
# The same record for an external receiver, and which node wrote it. The
# syslog header cannot say: `log-send-hostname` is global and would put the
# host name into `core/`'s own `log /dev/log` lines too, the form rsyslog's
# local reader misparses (measured 2026-09-29). A field in the record says it
# without touching anything else; the node's own file needs none, the
# collector knows whom it fetched from.
#
EXTERNAL_LOG_PROFILE = f"{PREFIX}-traffic-json-external"
EXTERNAL_LOG_FORMAT = HTTP_TRAFFIC_LOG_FORMAT.replace(
    "%(schema)[int(1)] ", "%(schema)[int(1)] %(node)H ", 1
)

HEADER = (
    "#",
    "# Generated by Haprion. Do not edit.",
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

    map_files: dict[str, str] = field(default_factory=dict)
    """`managed/maps/`, and `maps/` on the node: one network list per country (B228)."""

    waf_files: dict[str, str] = field(default_factory=dict)
    """`managed/waf/`, and `waf/` on the node: the engine's and SPOE's configuration.

    Empty when no object uses the engine - and then the release carries no
    `waf/`, which is what turns the engine off on the nodes (B230). The rule
    set itself is not generated; the publishing path copies it beside these.
    """

    dns_files: dict[str, str] = field(default_factory=dict)
    """`managed/dns/`, and `dns/` on the node: dnsdist's configuration (B249).

    Empty when no object is dns - and then the release carries no `dns/`,
    which is what stops dnsdist on the nodes.
    """

    ipvs: str = ipvs_config.HEADER
    """`managed/keepalived/ipvs.conf`: the syslog objects' IPVS virtual servers (B256).

    Always a file, with no virtual server when no object is syslog - which is
    what removes the previous release's from the nodes.
    """

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
    traffic_logging: bool = False,
    settings: ClusterSettings = NO_SETTINGS,
    countries: geo.Countries | None = None,
    peer_nodes: Sequence[tuple[str, str]] = (),
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
    _refuse_shared_backend_names(ordered)
    _refuse_shared_section_names(ordered)

    unsupported = [
        proxy
        for proxy in ordered
        if proxy.listen.protocol not in OWN_PORT and proxy.listen.protocol not in ports
    ]
    if unsupported:
        #
        # Refused rather than skipped. Silently generating nothing for an
        # object somebody published would take the site down and report
        # success, which is the one outcome worse than a refusal.
        #
        names = ", ".join(proxy.name for proxy in unsupported)
        raise GeneratorError(
            f"this version generates http, https, tcp, dns and syslog objects; cannot generate: "
            f"{names}"
        )
    _refuse_unknown_certificates(ordered, certificates)
    if certificate_sans is not None and not allow_certificate_mismatch:
        _refuse_uncovered_hostnames(ordered, certificate_sans)
    known_networks = dict(networks or {})
    _refuse_unknown_networks(ordered, known_networks)

    known_sources = dict(sources or {})
    everything = [(vip_of(proxy, vips, default_vip), proxy) for proxy in ordered]
    #
    # After placement, not before: a reservation names an address, so the gate
    # cannot ask its question until every object knows which VIP it sits on.
    # Every object, dns included: dnsdist binds its address and port as firmly
    # as HAProxy does, on UDP and TCP both.
    #
    _refuse_reserved(everything, reservations, ports)
    _refuse_shared_listeners(everything, ports)
    if settings.metrics is not None:
        _refuse_metrics_port(settings.metrics, everything, reservations, ports)
    peers = _peers_section(settings, peer_nodes, reservations)
    placed = [
        (vip, proxy) for vip, proxy in everything if proxy.listen.protocol not in OUTSIDE_HAPROXY
    ]
    resolving = [
        (vip, proxy, source_of(proxy, vip, known_sources))
        for vip, proxy in everything
        if proxy.listen.protocol == "dns"
    ]
    scrapers = settings.metrics.sources if settings.metrics is not None else ()
    if resolving:
        _refuse_loopback_port(
            dnsdist_config.STATS_PORT, "the DNS listener's statistics", settings, reservations
        )
        if scrapers:
            _refuse_dns_statistics_port(everything)
    #
    # A named dns server is written with the address saved beside it when the
    # object was saved (B252, B261); nothing is looked up here. A name saved
    # without one refuses the publish as any other object that cannot be
    # generated, and says to save the object again.
    #
    try:
        dns = dnsdist_config.render(resolving, known_networks, scrapers)
    except dnsdist_config.Unresolved as exc:
        raise GeneratorError(str(exc)) from exc
    try:
        ipvs = ipvs_config.render(
            [(vip, proxy) for vip, proxy in everything if proxy.listen.protocol == "syslog"]
        )
    except ValueError as exc:
        raise GeneratorError(str(exc)) from exc

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
            traffic_logging,
            settings.log_targets,
            PEERS_SECTION if peers else None,
        )
    }
    if settings.log_targets or settings.metrics is not None or peers:
        files[CLUSTER_FILE] = _cluster_file(settings, peers)
    guarded = [proxy for proxy in ordered if proxy.inspected is not None]
    if guarded:
        _refuse_loopback_port(WAF_ENGINE_PORT, "the WAF engine", settings, reservations)
        files[WAF_FILE] = _waf_backend_file()
    for vip, proxy in placed:
        files[f"{OBJECT_BAND}-{proxy.name}.cfg"] = _object_file(
            proxy,
            source_of(proxy, vip, known_sources),
            resolvers,
            tuple(trusted_proxies),
            PEERS_SECTION if peers else None,
            known_networks,
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
    parts.update(dns.parts)
    parts.update(ipvs.parts)
    return GeneratedLayer(
        configuration=files,
        certificate_lists=listings,
        object_parts=parts,
        map_files=_country_files(ordered, countries),
        waf_files=_waf_files(guarded),
        dns_files=dns.files,
        ipvs=ipvs.file,
    )


def _refuse_dns_statistics_port(placed: Sequence[tuple[Vip, Proxy]]) -> None:
    """dnsdist's statistics port, which it takes on every address once Prometheus reads it (B253).

    Every IPv4 address, as the exporter's, so a tcp or dns object on the same
    port of a VIP would meet it there.
    """

    port = dnsdist_config.STATS_PORT
    for _vip, proxy in placed:
        if proxy.listen.protocol in ("tcp", "dns") and proxy.listen.port == port:
            raise GeneratorError(
                f"port {port} is where Prometheus reads the DNS listener's statistics, and "
                f"{proxy.name} listens on it"
            )


def _refuse_loopback_port(
    port: int, what: str, settings: ClusterSettings, reservations: Reservations
) -> None:
    """A loopback port an engine beside HAProxy takes, which nothing else may.

    The exporter binds its port on every address, loopback included, and a
    reservation is a port the handwritten half binds; either on the engine's
    port would leave one of the two unable to listen.
    """

    if settings.metrics is not None and settings.metrics.port == port:
        raise GeneratorError(f"the metrics port {port} is the port {what} listens on")
    if port in reservations.tcp_ports or any(
        reserved == port for _address, reserved in reservations.tcp_listeners
    ):
        raise GeneratorError(
            f"port {port} is reserved in manual/reservations.yaml, and {what} listens on it"
        )


def _waf_backend_file() -> str:
    """Where HAProxy reaches the engine: one SPOP server on loopback.

    Not health-checked, on purpose. A check marks the engine down until it has
    answered twice - measured 2026-10-02: an engine started a moment after
    HAProxy was refused for every request for seconds after it listened. On
    loopback a refused connection is immediate, so without a check a request
    to a stopped engine fails at once (and `on_engine_error` decides), and the
    first request after it is back is inspected.

    At once only with `retries 0`. Without it the backend takes HAProxy's own
    default of 3 and retries the refused connection until the SPOE processing
    timeout runs out: every request waited 0.5 s while the engine was down
    (review 2026-10-04 F4, measured on a node and in 3.4.6 here; with the line,
    0.6 ms down and the same verdicts up).
    """

    engine = Server(host="127.0.0.1", port=WAF_ENGINE_PORT)
    return _lines(
        HEADER,
        [
            "",
            f"backend {WAF_BACKEND}",
            "    mode spop",
            "    retries 0",
            f"    server engine 127.0.0.1:{WAF_ENGINE_PORT}"
            f" guid {server_guid(WAF_IDENTITY, 'engine', engine)}",
        ],
    )


#
# The engine's base settings, ahead of the rule set. Coraza's own
# recommendations, less what does not apply here: the request body is read up
# to what HAProxy hands over (its buffer) and a longer one is inspected as far
# as it goes rather than refused; responses are not inspected; nothing is
# written to an audit log. The two body processors make a JSON or XML body
# something the rules can read. Coraza's own body-parse refusals are left out:
# the CRS judges what a request carries, and a refusal outside its rule range
# would leave no rule ID on the traffic record.
#
WAF_BASE = (
    "SecRuleEngine On",
    "SecRequestBodyAccess On",
    "SecRequestBodyLimit 13107200",
    "SecRequestBodyInMemoryLimit 131072",
    "SecRequestBodyLimitAction ProcessPartial",
    "SecRequestBodyJsonDepthLimit 1024",
    "SecResponseBodyAccess Off",
    "SecAuditEngine Off",
    'SecRule REQUEST_HEADERS:Content-Type "^(?:application(?:/soap\\+|/)|text/)xml" '
    '"id:200000,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML"',
    'SecRule REQUEST_HEADERS:Content-Type "^application/json" '
    '"id:200001,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"',
    'SecRule REQUEST_HEADERS:Content-Type "^application/[a-z0-9.-]+[+]json" '
    '"id:200006,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"',
)


#
# An exception's own rules, numbered from here within each object's
# application (the base uses 2000xx; the rule set 9xxxxx). Each object has its
# own rule set, so the numbers repeat between objects without meeting.
#
WAF_EXCEPTION_FIRST_ID = 210000


def _waf_exception_directives(exceptions: Sequence[WafException]) -> tuple[list[str], list[str]]:
    """What the exceptions add before the rule set, and after it.

    An exception on paths is a phase 1 rule ahead of the rule set, which takes
    the rule (or the field from it) away for that request only; the path is
    compared exactly, after the same decoding and normalising the rule set
    applies. One on every path changes the rule itself, once, after the rule
    set has defined it. Both forms measured in a real HAProxy and engine
    (26-10-03), including that `/search/../admin` is not `/search`.
    """

    before: list[str] = []
    after: list[str] = []
    number = WAF_EXCEPTION_FIRST_ID
    for exception in exceptions:
        if exception.field:
            action = f"ctl:ruleRemoveTargetById={exception.rule};{exception.field}"
        else:
            action = f"ctl:ruleRemoveById={exception.rule}"
        if not exception.paths:
            after.append(
                f'SecRuleUpdateTargetById {exception.rule} "!{exception.field}"'
                if exception.field
                else f"SecRuleRemoveById {exception.rule}"
            )
            continue
        for path in exception.paths:
            before.append(
                f'SecRule REQUEST_FILENAME "@streq {path}" "id:{number},phase:1,pass,nolog,'
                f't:none,t:urlDecodeUni,t:normalisePath,{action}"'
            )
            number += 1
    return before, after


def _waf_files(guarded: Sequence[Proxy]) -> dict[str, str]:
    """`coraza.yaml` - one application per object - and the SPOE configuration."""

    if not guarded:
        return {}
    crs = f"{WAF_DIRECTORY}/crs"
    applications = []
    for proxy in guarded:
        assert proxy.waf is not None  # noqa: S101 - `guarded` holds only these
        before, after = _waf_exception_directives(proxy.waf.exceptions)
        directives = [
            *WAF_BASE,
            *before,
            f"Include {crs}/crs-setup.conf",
            #
            # CRS reads the level from this variable if set before its
            # initialisation; its own setup file leaves id 900000 to us.
            #
            f'SecAction "id:900000,phase:1,pass,t:none,nolog,'
            f'setvar:tx.blocking_paranoia_level={proxy.waf.paranoia}"',
            f"Include {crs}/rules/*.conf",
            *after,
        ]
        applications.append(_waf_application(proxy.name, directives))
    applications.append(_waf_application(WAF_UNKNOWN_APPLICATION, ["SecRuleEngine Off"]))
    configuration = "\n".join(
        [
            *HEADER,
            f"bind: 127.0.0.1:{WAF_ENGINE_PORT}",
            "log_level: info",
            "log_file: /dev/stdout",
            "log_format: json",
            f"default_application: {WAF_UNKNOWN_APPLICATION}",
            "applications:",
            *applications,
        ]
    )
    spoe = _lines(
        HEADER,
        [
            "",
            f"[{WAF_SPOE_ENGINE}]",
            f"spoe-agent {WAF_SPOE_ENGINE}-agent",
            f"    groups {WAF_SPOE_GROUP}",
            f"    option var-prefix {WAF_SPOE_ENGINE}",
            "    option set-on-error error",
            "    timeout hello 2s",
            "    timeout idle 2m",
            "    timeout processing 500ms",
            f"    use-backend {WAF_BACKEND}",
            "",
            f"spoe-message {WAF_SPOE_GROUP}",
            "    args app=var(txn.coraza.app) id=var(txn.coraza.request) src-ip=src "
            "src-port=src_port dst-ip=dst dst-port=dst_port method=method path=path query=query version=req.ver "
            "headers=req.hdrs body=req.body exportRuleIDs=bool(true)",
            "",
            f"spoe-group {WAF_SPOE_GROUP}",
            f"    messages {WAF_SPOE_GROUP}",
        ],
    )
    return {"coraza.yaml": configuration + "\n", "spoe.conf": spoe}


def _waf_application(name: str, directives: Sequence[str]) -> str:
    """One application in `coraza.yaml`. The directives are a literal block:
    nothing in them is YAML, and nothing in them comes from a person except
    numbers the model has already held to their ranges."""

    return "\n".join(
        [
            f"  - name: {name}",
            "    directives: |",
            *(f"      {line}" for line in directives),
            "    response_check: false",
            "    transaction_ttl_ms: 60000",
            "    log_level: warn",
            "    log_file: /dev/stdout",
            "    log_format: json",
        ]
    )


def _ring_name(target: LogTarget) -> str:
    return f"{PREFIX}-log-{target.name}"


def _cluster_file(settings: ClusterSettings, peers: Sequence[str] = ()) -> str:
    """The rings to external log receivers, and the metrics exporter.

    One ring per receiver and never two servers in one: every server in a ring
    receives the same copy and the ring moves at the slowest one's pace, so a
    receiver that stops reading would hold back the others (3.4.4 manual).
    What does not fit in a ring while its receiver is away is dropped; the
    traffic is not held up (measured 2026-09-29).
    """

    body: list[str] = []
    for target in settings.log_targets:
        address = f"[{target.address}]" if ":" in target.address else target.address
        body.extend(
            (
                "",
                f"ring {_ring_name(target)}",
                f'    description "Traffic log to {target.name}"',
                "    format rfc5424",
                "    maxlen 2048",
                f"    size {target.buffer_kib * 1024}",
                "    timeout connect 5s",
                "    timeout server 10s",
                f"    server {target.name} {address}:{target.port} log-proto octet-count"
                + (" ssl verify required ca-file @system-ca" if target.tls else ""),
            )
        )
    if settings.metrics is not None:
        body.extend(_metrics_frontend(settings.metrics))
    body.extend(peers)
    return _lines(HEADER, body)


def _peers_section(
    settings: ClusterSettings,
    nodes: Sequence[tuple[str, str]],
    reservations: Reservations,
) -> list[str]:
    """The section the nodes share their stick tables in, or nothing (B270).

    One `peer` line per node with the address the caller looked up, and the
    same file on every node: HAProxy finds its own line by its host name, so a
    node's name has to be its host name. The other form - `bind` and `server`
    lines - cannot be one file for all nodes, because the local node's line may
    carry no address there (measured on 3.4.6).
    """

    if settings.peers is None:
        return []
    port = settings.peers.port
    if not nodes:
        raise GeneratorError("sharing counters needs the nodes' addresses, and none were given")
    if port in reservations.tcp_ports:
        raise GeneratorError(
            f"peers port {port} is reserved in manual/reservations.yaml for every address"
        )
    lines = ["", f"peers {PEERS_SECTION}"]
    for name, address in nodes:
        shown = f"[{address}]" if ":" in address else address
        lines.append(f"    peer {name} {shown}:{port}")
    return lines


def _metrics_frontend(metrics: Metrics) -> list[str]:
    """HAProxy's own Prometheus exporter, for the sources the cluster names.

    Bound on every IPv4 address, not on a VIP: both nodes read the same file,
    and a scrape of each node is what shows the passive one too. The source
    list and the nodes' firewall are what keep it private. Only failures are
    logged; a scrape every few seconds is not traffic anybody reads.
    """

    return [
        "",
        f"frontend {METRICS_FRONTEND}",
        f"    guid {frontend_guid(METRICS_IDENTITY)}",
        f"    bind :{metrics.port} guid-prefix {listener_guid_prefix(METRICS_IDENTITY)}",
        "    mode http",
        "    option dontlog-normal",
        f"    timeout client {TIMEOUT_CLIENT}",
        "    http-request deny deny_status 403 unless { src " + " ".join(metrics.sources) + " }",
        "    http-request use-service prometheus-exporter if { path /metrics }",
        "    http-request return status 404",
    ]


def _refuse_metrics_port(
    metrics: Metrics,
    placed: Sequence[tuple[Vip, Proxy]],
    reservations: Reservations,
    ports: Mapping[str, int],
) -> None:
    """The exporter's port, which it takes on every address.

    Anything else on that port - generated or reserved for the handwritten
    half - would bind it too, and under SO_REUSEPORT the kernel would split
    connections between the two at random with nothing reporting it.
    """

    port = metrics.port
    if port in reservations.tcp_ports or any(
        reserved == port for _address, reserved in reservations.tcp_listeners
    ):
        raise GeneratorError(
            f"the metrics port {port} is reserved in manual/reservations.yaml for handwritten "
            "configuration"
        )
    for _vip, proxy in placed:
        used = {proxy.listen.port} if proxy.listen.protocol in ("tcp", "dns") else set()
        if proxy.listen.protocol in ports:
            used.add(ports[proxy.listen.protocol])
        if proxy.listen.redirect_http:
            used.add(ports["http"])
        if port in used:
            raise GeneratorError(f"the metrics port {port} is the port {proxy.name} listens on")


def source_of(proxy: Proxy, vip: Vip, sources: Mapping[str, str]) -> str | None:
    """The address this object connects to backends from.

    Public because the objects listing reports it (B222): a reader that worked
    the address out for itself would be a second copy of this rule.

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


def vip_of(proxy: Proxy, vips: Mapping[str, Vip], default_vip: str) -> Vip:
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
    #
    # Not a syslog object's: a reservation is a TCP port (`tcp_ports`), and
    # IPVS takes the address and port on UDP alone.
    #
    for vip, proxy in placed:
        port = proxy.listen.port
        if (
            port is not None
            and proxy.listen.protocol != "syslog"
            and reservations.claims(vip.address, port)
        ):
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
    asking - see `docs/user-manual.md`.

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
        named = [
            *proxy.allow_from,
            *(proxy.deny_from.sources if proxy.deny_from is not None else ()),
            *(source for rule in proxy.deny_rules for source in rule.sources),
            *(proxy.dynamic_block.exempt if proxy.dynamic_block is not None else ()),
        ]
        for name in named:
            if is_range(name) or geo.is_country(name) or name in networks:
                continue
            known = ", ".join(sorted(networks)) or "none"
            raise GeneratorError(
                f"{proxy.name} names the group {name}, which this cluster does "
                f"not define. Known groups: {known}"
            )


def _refuse_duplicate_names(proxies: Sequence[Proxy]) -> None:
    # One pass, not a count per name (review 2026-10-03, K2): quadratic at 10 000 objects.
    counted = Counter(proxy.name for proxy in proxies)
    duplicates = sorted(name for name, count in counted.items() if count > 1)
    if duplicates:
        raise GeneratorError(f"two objects share a name: {', '.join(duplicates)}")


def _refuse_shared_backend_names(proxies: Sequence[Proxy]) -> None:
    """Every backend the objects produce, under a name no other one has.

    A pool is named by itself since 2026-10-06 (B250), so two objects with a
    pool called `web` meet here, and so do object `a`'s redirect `a-redirect`
    and somebody's pool of that name. HAProxy would refuse either on `-c`,
    pointing at a generated file; said here, it names the objects.
    """

    owners: dict[str, list[str]] = {}
    for proxy in proxies:
        for name in runtime_backends(proxy):
            owners.setdefault(name, []).append(proxy.name)
    shared = sorted(
        f"{name} ({', '.join(sorted(objects))})"
        for name, objects in owners.items()
        if len(objects) > 1
    )
    if shared:
        raise GeneratorError(
            f"a backend name must be unique in the cluster, and two objects use {'; '.join(shared)}"
        )


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

    Only tcp, dns and syslog objects can collide this way. Two http objects on
    one address share a frontend by design; a tcp object is a frontend of its
    own, a dns object a dnsdist listener on UDP and TCP both, a syslog object
    an IPVS virtual server on UDP, and their port is written in the object
    rather than in the cluster.

    Per transport: a syslog object takes the port on UDP only, so it may
    share a number with a tcp object or a cluster's http port, and meets a dns
    object - whose UDP the kernel would hand to IPVS before dnsdist ever saw
    it - and another syslog object.
    """

    taken: dict[tuple[str, int], str] = {}
    datagrams: dict[tuple[str, int], str] = {}
    for vip, proxy in placed:
        if proxy.listen.protocol not in OWN_PORT:
            continue
        port = proxy.listen.port
        if port is None:
            #
            # The model requires a port for tcp and dns, so reaching this means
            # the two layers have drifted. A refusal rather than an assertion,
            # so it survives running with -O.
            #
            raise GeneratorError(
                f"{proxy.name} listens on {proxy.listen.protocol} without naming a port"
            )
        if proxy.listen.protocol in ("dns", "syslog"):
            earlier = datagrams.get((vip.name, port))
            if earlier is not None:
                raise GeneratorError(
                    f"{earlier} and {proxy.name} both listen on {vip.name} port {port}/udp"
                )
            datagrams[(vip.name, port)] = proxy.name
        if proxy.listen.protocol == "syslog":
            continue
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


def _refuse_shared_section_names(proxies: Sequence[Proxy]) -> None:
    """Sections the objects' texts add must not meet each other or the generator's.

    Each text's names begin with its object's (the model sees to that), but
    `a-b-cache` is a name both `a` and `a-b` may choose, and an object called
    after the generator's prefix could choose one of its names. HAProxy would
    refuse the duplicate on `-c`, pointing at a generated file; said here, it
    names the two objects instead.
    """

    #
    # And not a backend the generator writes: a pool is named by itself since
    # B250, so object `a`'s text may add `a-cache` while object `b` has a pool
    # called `a-cache`.
    #
    backends = {name: proxy.name for proxy in proxies for name in runtime_backends(proxy)}
    owners: dict[str, str] = {}
    for proxy in proxies:
        if proxy.advanced is None:
            continue
        for section in proxy.advanced.placement.sections:
            if section.name in backends:
                raise GeneratorError(
                    f"{proxy.name}: the advanced config's section {section.name} has the name of "
                    f"a backend of {backends[section.name]}"
                )
            if section.name.startswith(f"{PREFIX}-"):
                raise GeneratorError(
                    f"{proxy.name}: the advanced config's section {section.name} begins with "
                    f"{PREFIX}-, which is the generator's"
                )
            other = owners.setdefault(section.name, proxy.name)
            if other != proxy.name:
                raise GeneratorError(
                    f"{other} and {proxy.name} both add a section called {section.name} "
                    f"in their advanced config"
                )


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


def backend_name(proxy: Proxy, name: str) -> str:
    """What one of an object's pools or redirects is called in HAProxy (B250).

    A pool is called what the operator named it, and nothing else: the name is
    the `proxy` label HAProxy's exporter gives every metric, so it is what a
    dashboard shows. The model refuses a pool name in the generator's own `mgd-` space, and
    `_refuse_shared_backend_names` makes it unique in the cluster.

    A redirect has no pool to be named after, so it keeps its object's name in
    front of its suffix (`redirect_suffixes`), which never equals a pool name of
    the same object.
    """

    if name in proxy.backends:
        return name
    return f"{proxy.name}-{name}"


def runtime_backends(proxy: Proxy) -> list[str]:
    """Every backend the generator writes for one object, pools then redirects."""

    redirects = sorted(set(redirect_suffixes(proxy).values()))
    return [backend_name(proxy, name) for name in (*proxy.backends, *redirects)]


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
    traffic_logging: bool,
    log_targets: Sequence[LogTarget] = (),
    peers: str | None = None,
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
    #
    # The structured record is the same wherever it goes: the node's own file
    # when traffic logging is on, and every external target either way.
    #
    structured = traffic_logging or bool(log_targets)
    profiles = (
        *(((TRAFFIC_LOG_PROFILE, HTTP_TRAFFIC_LOG_FORMAT),) if traffic_logging else ()),
        *(((EXTERNAL_LOG_PROFILE, EXTERNAL_LOG_FORMAT),) if log_targets else ()),
    )
    for profile, record in profiles if groups else ():
        body.extend(
            (
                "",
                f"log-profile {profile}",
                '    log-tag "haproxy-traffic"',
                #
                # A connection that dies before a request - an SSL handshake
                # failure, a malformed request - is logged at the error step
                # with the plain-text error format, on every log target the
                # frontend has, including this one. Measured on a node: it
                # landed in the JSONL file as text. The classic stream keeps
                # it through the global target; this stream is transactions.
                #
                "    on error drop",
                f"    on close format {record}",
            )
        )
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
            *(
                (f"    log /dev/log len 2048 format local profile {TRAFFIC_LOG_PROFILE} local2",)
                if traffic_logging
                else ()
            ),
            *(
                f"    log ring@{_ring_name(target)} len 2048 format rfc5424 "
                f"profile {EXTERNAL_LOG_PROFILE} local2"
                for target in log_targets
            ),
            *(
                ("    http-request set-var(txn.traffic_host) req.hdr(host),cut_crlf,bytes(0,253)",)
                if structured
                else ()
            ),
            *(
                (f"    filter spoe engine {WAF_SPOE_ENGINE} config {WAF_DIRECTORY}/spoe.conf",)
                if any(
                    proxy.inspected is not None and role == "serve" for _, proxy, role in members
                )
                else ()
            ),
            f"    timeout client {TIMEOUT_CLIENT}",
            *_forwarded_rules(protocol, trusted_proxies),
            *_abuse_rules(abuse_protection, bool(trusted_proxies), peers),
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
        tls_names = _tls_group_names(members, protocol)
        for _, proxy, role in members:
            rules = _frontend_rules(
                proxy, role, networks, tls_names=tls_names, trusted=bool(trusted_proxies)
            )
            body.extend(rules)
            _record(shared, proxy.name, listener=[*envelope, *tail], routing=rules)
        body += tail
    for vip, proxy in sorted(tcp, key=lambda member: member[1].name):
        #
        # A tcp object owns its whole frontend, so there is no envelope to
        # separate: the bind line is as much its own as the rules are.
        #
        block = _tcp_frontend(vip, proxy, networks, abuse_protection, peers)
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
    peers: str | None = None,
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
        acl = _acl_name(proxy.name, "allow")
        lines += [
            *_address_acl(acl, "src", proxy.allow_from, networks),
            #
            # Rejected at connection time rather than denied at request time:
            # there is no request. The client sees a closed connection, which
            # is all a raw protocol can be told.
            #
            f"    tcp-request connection reject unless {acl}",
        ]
    if proxy.deny_from is not None:
        #
        # Always `deny` here - the model refuses `log` on tcp, which has no
        # traffic record for a logged match to appear on.
        #
        acl = _acl_name(proxy.name, "deny-from")
        lines += [
            *_address_acl(acl, "src", proxy.deny_from.sources, networks),
            f"    tcp-request connection reject if {acl}",
        ]
    if abuse_protection is not None and abuse_protection.max_new_connections is not None:
        window = abuse_protection.window
        lines += [
            _stick_table(window, f"conn_rate({window})", peers),
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
    lines += _tcp_block_lines(proxy, networks)
    limit = proxy.rate_limit
    if limit is not None and limit.max_new_connections is not None:
        #
        # The object's own counter, on the second slot: the first is the
        # cluster's above, and a stream tracks each slot once - a second
        # `track-sc0` would be ignored without a word. The table lives in the
        # object's backend, since a section holds one table and this
        # frontend's is the cluster's.
        #
        table = backend_name(proxy, proxy.backend)
        lines += [
            f"    tcp-request connection track-sc{RATE_COUNTER} src table {table}",
            f"    tcp-request connection reject "
            f"if {{ sc_conn_rate({RATE_COUNTER}) gt {limit.max_new_connections} }}",
        ]
    lines.append(f"    default_backend {backend_name(proxy, proxy.backend)}")
    if proxy.advanced is not None:
        lines.extend(advanced_config.block(proxy.name, proxy.advanced.placement.frontend))
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


def _stick_table(window: str, stored: str, peers: str | None) -> str:
    """One generated stick table, shared with the other nodes when peers is named (B270)."""

    line = (
        f"    stick-table type {TABLE_KEY} size {ABUSE_TABLE_SIZE} expire {window} store {stored}"
    )
    return f"{line} peers {peers}" if peers else line


def _abuse_rules(
    protection: AbuseProtection | None, trusted: bool, peers: str | None = None
) -> list[str]:
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
    lines = [_stick_table(window, ",".join(f"{name}({window})" for name in stored), peers)]
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


def _allow_rules(
    proxy: Proxy, networks: Mapping[str, Sequence[str]], host: str, trusted: bool = False
) -> list[str]:
    """Who gets an answer, when the answer is not for everybody.

    Written as a deny rather than as a condition on `use_backend`, so that a
    restricted object refuses a visitor outright instead of falling through to
    whatever the next matching rule happens to be. `http-request` rules run
    before routing, which is the right moment for this question.
    """

    if not proxy.allow_from:
        return []
    acl = _acl_name(proxy.name, "allow")
    return [
        *_address_acl(acl, _client_fetch(trusted), proxy.allow_from, networks),
        f"    http-request deny deny_status 403 if {host} !{acl}",
    ]


MAPS_DIRECTORY = "/etc/haproxy/maps"


def _address_acl(
    acl: str, fetch: str, entries: Sequence[str], networks: Mapping[str, Sequence[str]]
) -> list[str]:
    """One address condition: groups and ranges inline, each country from its file.

    Lines with one ACL name are read by HAProxy as an OR, so a list mixing
    `office` and `country:SE` is one condition. The file is named by the
    country alone; its networks are written by `_country_files`, and the
    nodes' validation already points `/etc/haproxy/maps/` at the candidate's
    own copy.
    """

    lines = []
    cidrs = _cidrs(entries, networks)
    if cidrs:
        lines.append(f"    acl {acl} {fetch} {' '.join(cidrs)}")
    for entry in sorted(entry for entry in entries if geo.is_country(entry)):
        lines.append(f"    acl {acl} {fetch} -f {MAPS_DIRECTORY}/{geo.file_name(geo.code(entry))}")
    return lines


def countries_named(proxies: Sequence[Proxy]) -> frozenset[str]:
    """Every country some object names, as the database spells it (`SE`)."""

    return frozenset(
        geo.code(entry)
        for proxy in proxies
        for entry in (
            *proxy.allow_from,
            *(proxy.deny_from.sources if proxy.deny_from is not None else ()),
            *(source for rule in proxy.deny_rules for source in rule.sources),
        )
        if geo.is_country(entry)
    )


def _country_files(proxies: Sequence[Proxy], countries: geo.Countries | None) -> dict[str, str]:
    """One file of networks per country named, headed by the database's date.

    The date is what tells a reader - and the staleness check - which data a
    cluster runs. A country named with no reader to answer for it is refused:
    a rule that silently matched nobody would admit everyone it meant to
    refuse, and refuse everyone it meant to admit.
    """

    named = countries_named(proxies)
    if not named:
        return {}
    if countries is None:
        raise GeneratorError(
            f"objects name countries ({', '.join(sorted(named))}) and no location data was given"
        )
    missing = sorted(named - set(countries.networks))
    if missing:
        raise GeneratorError(f"no location data for: {', '.join(missing)}")
    return {
        geo.file_name(country): (
            f"# IPFire Location {countries.stamp} (CC BY-SA 4.0) {country}\n"
            + "".join(f"{network}\n" for network in countries.networks[country])
        )
        for country in sorted(named)
    }


def _cidrs(entries: Sequence[str], networks: Mapping[str, Sequence[str]]) -> list[str]:
    """Group names resolved to the cluster's ranges, literal ranges kept."""

    return sorted(
        {
            cidr
            for entry in entries
            if not geo.is_country(entry)
            for cidr in ((entry,) if is_range(entry) else networks[entry])
        }
    )


def _uses_sources(proxy: Proxy) -> bool:
    return bool(
        proxy.allow_from
        or proxy.deny_from is not None
        or any(rule.sources for rule in proxy.deny_rules)
    )


def _client_fetch(trusted: bool) -> str:
    """Where an address condition reads the visitor from (B227, question 1).

    Without a trusted proxy that is the connection, as it always was, and the
    generated text is unchanged. Behind one it is the address `_client_rules`
    took from the last X-Forwarded-For element - the same reading the rate
    limit counts - since the connection is then the proxy, and a list held
    against it would admit or refuse every visitor at once.
    """

    return "var(txn.client) -m ip" if trusted else "src"


def _client_rules(proxy: Proxy, host: str, trusted: bool) -> list[str]:
    """The visitor's address, once per object that asks about addresses.

    A request from a trusted proxy that carries no header gets no address at
    all: an allowlist then refuses it and a denylist lets it pass, the same
    answer the rate limit gives - there is no address to hold responsible.
    """

    if not trusted or not _uses_sources(proxy):
        return []
    return [
        f"    http-request set-var(txn.client) req.hdr_ip(X-Forwarded-For,-1) "
        f"if {host} {TRUSTED_ACL}",
        f"    http-request set-var(txn.client) src if {host} !{TRUSTED_ACL}",
    ]


HEADER_MATCH_FLAGS = {"equals": "str", "prefix": "beg", "contains": "sub"}


def _verdict(condition: str, name: str, mode: str) -> list[str]:
    """What a matched rule does, and the name it leaves on the traffic record.

    A logged match keeps the first rule that met the request, so the record
    names the rule that would have refused it first; a refusal names itself
    whatever was logged before, since that is the rule that answered.
    """

    if mode == "log":
        return [
            f"    http-request set-var(txn.rule) str({name}:log) "
            f"if {condition} !{{ var(txn.rule) -m found }}"
        ]
    return [
        f"    http-request set-var(txn.rule) str({name}:deny) if {condition}",
        f"    http-request deny deny_status 403 if {condition}",
    ]


#
# The path an access rule reads (review 2026-10-04 F2, B242): percent-decoded,
# with runs of slashes made one, as nginx matches its locations. HAProxy's own
# `path` is neither, so `/%61dmin`, `//admin` and `/admin%2Fx` passed a rule on
# `/admin` to a backend that serves them as `/admin` (measured in 3.4.6).
# `normalize-uri` would do it but is experimental in 3.4.6, and missed `%2F`
# and `%2e%2e` (measured). Dot segments are not resolved but refused - see
# `_access_path_rules`. The backend still gets the path as it was sent.
#
# And read as the backends that are least strict read it (review 26-10-09, F1):
# lowercased, as IIS ignores case; with `;parameters` cut from each segment, as
# Java servers do (`/admin;jsessionid=1`); and with dots and spaces cut from a
# segment's end, as Windows does (`/admin.`, `/admin%20`). Measured on 3.4.6:
# each of those passed a rule on `/admin` before. A rule on `/admin` then also
# refuses `/Admin` behind a backend that tells them apart - a path nobody uses.
# Regular expressions without groups, which converter arguments cannot hold.
#
ACCESS_PATH_EXPRESSION = (
    r"path,url_dec,lower,regsub(;[^/]*,,g),regsub([.\x20]+/,/,g),"
    r"regsub([.\x20]+$,,g),regsub(/+,/,g)"
)
ACCESS_PATH = "var(txn.access_path)"
#
# A control character once decoded - `%00`, a line break - which no browser
# sends and some servers cut a path at. Refused as dot segments are.
#
CONTROL_CHARACTER = r"%(0[0-9a-f]|1[0-9a-f]|7f)"
#
# A `.` or `..` segment once decoded. A regular expression with no groups cannot
# resolve them however often it is applied (`/././…` always leaves one), and
# converter arguments cannot hold the groups that could; an ACL pattern can.
# Browsers resolve them before sending, so a request that still has one was
# written by hand.
#
DOT_SEGMENT = r"(^|/)\.\.?(/|$)"


def _access_path_rules(proxy: Proxy, host: str) -> list[str]:
    """The path the access rules read, and the refusal of dot segments and control characters.

    Only on an object with a rule on a path other than every path. The refusal
    is 400, as nginx answers a path that leaves the root, and follows the rules
    it protects: it refuses when any of them refuses and only looks when all of
    them only look.
    """

    rules = [
        rule
        for rule in proxy.deny_rules
        if rule.path is not None and not (rule.path == "/" and rule.path_match == "prefix")
    ]
    if not rules:
        return []
    dots = _acl_name(proxy.name, "path-dots")
    controls = _acl_name(proxy.name, "path-chars")
    lines = [
        f"    http-request set-var(txn.access_path) {ACCESS_PATH_EXPRESSION} if {host}",
        f"    acl {dots} path,url_dec -m reg {DOT_SEGMENT}",
        f"    acl {controls} path -m reg -i {CONTROL_CHARACTER}",
    ]
    for acl, name in ((dots, "path-dots"), (controls, "path-chars")):
        condition = f"{host} {acl}"
        if any(rule.mode == "deny" for rule in rules):
            lines += [
                f"    http-request set-var(txn.rule) str({name}:deny) if {condition}",
                f"    http-request deny deny_status 400 if {condition}",
            ]
        else:
            lines += _verdict(condition, name, "log")
    return lines


def _access_rules(
    proxy: Proxy, networks: Mapping[str, Sequence[str]], host: str, trusted: bool
) -> list[str]:
    """`deny_from`, `deny_rules` and `max_request_body`, in that order (Fas 21).

    After `allow_from` and before routing, as `_allow_rules` is: a refusal
    has to come before any `use_backend` could send the request on.
    """

    lines: list[str] = []
    fetch = _client_fetch(trusted)
    if proxy.deny_from is not None:
        acl = _acl_name(proxy.name, "deny-from")
        lines.extend(_address_acl(acl, fetch, proxy.deny_from.sources, networks))
        lines.extend(_verdict(f"{host} {acl}", "deny-from", proxy.deny_from.mode))
    lines.extend(_access_path_rules(proxy, host))
    for index, rule in enumerate(proxy.deny_rules):
        prefix = f"rule{index}"
        condition = [host]
        if rule.path is not None:
            acl = _acl_name(proxy.name, f"{prefix}-path")
            if rule.path == "/" and rule.path_match == "prefix":
                #
                # Every path, as for a route: the host alone says it.
                #
                pass
            elif rule.path_match == "exact":
                lines += [
                    f"    acl {acl} {ACCESS_PATH} -m str {rule.path.lower()}",
                    f"    acl {acl} {ACCESS_PATH} -m str {rule.path.lower()}/",
                ]
                condition.append(acl)
            else:
                lines += [
                    f"    acl {acl} {ACCESS_PATH} -m str {rule.path.lower()}",
                    f"    acl {acl} {ACCESS_PATH} -m beg {rule.path.lower()}/",
                ]
                condition.append(acl)
        if rule.methods:
            acl = _acl_name(proxy.name, f"{prefix}-method")
            lines.append(f"    acl {acl} method {' '.join(rule.methods)}")
            condition.append(acl)
        if rule.header is not None:
            acl = _acl_name(proxy.name, f"{prefix}-header")
            #
            # `req.fhdr`, not `req.hdr`: the latter splits a value at its
            # commas, so `contains` would never see a value that has one.
            #
            flag = HEADER_MATCH_FLAGS[rule.header.match]
            lines.append(
                f"    acl {acl} req.fhdr({rule.header.name}) -m {flag} '{rule.header.value}'"
            )
            condition.append(acl)
        if rule.sources:
            acl = _acl_name(proxy.name, f"{prefix}-source")
            lines.extend(_address_acl(acl, fetch, rule.sources, networks))
            condition.append(f"!{acl}" if rule.source_negate else acl)
        lines.extend(_verdict(" ".join(condition), rule.name, rule.mode))
    if proxy.max_request_body is not None:
        #
        # `req.body_size` is the declared length, or what has arrived of a
        # chunked body - measured in 3.4.6: it holds every declared length and
        # a chunked body that fits in the buffer, and nothing longer (B227).
        # The longer chunked request is let through and marked, so the WAF
        # page shows whether it happens before anyone refuses it.
        #
        size = f"{{ req.body_size gt {proxy.max_request_body} }}"
        lines += [
            f"    http-request set-var(txn.rule) str(body-limit:deny) if {host} {size}",
            f"    http-request deny deny_status 413 if {host} {size}",
            f"    http-request set-var(txn.rule) str(body-unbounded:log) if {host} "
            f"{{ req.hdr(transfer-encoding) -m found }} !{{ req.hdr(content-length) -m found }} "
            f"!{{ var(txn.rule) -m found }}",
        ]
    return lines


def _waf_body_rules(proxy: Proxy, waf: Waf, host: str) -> list[str]:
    """A body the engine could not read to its end (review 2026-10-04 F1, B243).

    The engine gets what HAProxy's buffer holds after `wait-for-body` - about
    15 kB of a 16 kB buffer - and an attack after that much padding passed
    `block` uninspected (measured). `req.body_size` is the declared length, or
    what has been parsed of a chunked body, and `req.body_len` what the buffer
    holds; the difference is above zero exactly when the body did not fit,
    with a length and chunked alike (measured in 3.4.6). A body that arrives
    too slowly is answered 408 by `wait-for-body` and never gets here.

    `block` refuses it with 413, `log` marks it; `large_bodies` are the paths
    that expect it, where it is let through with what fitted inspected. Matched
    on the path decoded and with its slashes merged, as the access rules are.
    """

    short = "{ req.body_size,sub(txn.waf_body) gt 0 }"
    lines = [f"    http-request set-var(txn.waf_body) req.body_len if {host}"]
    condition = f"{host} {short}"
    if waf.large_bodies:
        acl = _acl_name(proxy.name, "large-body")
        for path in waf.large_bodies:
            if path == "/":
                return []
            lines += [
                f"    acl {acl} {ACCESS_PATH_EXPRESSION} -m str {path.lower()}",
                f"    acl {acl} {ACCESS_PATH_EXPRESSION} -m beg {path.lower()}/",
            ]
        condition += f" !{acl}"
    if waf.mode == "block":
        return [
            *lines,
            f"    http-request set-var(txn.rule) str(waf-body:deny) if {condition}",
            f"    http-request deny deny_status 413 if {condition}",
        ]
    return [*lines, *_verdict(condition, "waf-body", "log")]


def _waf_rules(proxy: Proxy, host: str) -> list[str]:
    """Ask the engine about the request, then decide on its answer (B232).

    After the access rules, so what they refuse never costs an inspection,
    and before routing. The body is waited for - up to a second, and up to
    the buffer - so the engine reads a form as well as a query. The engine
    always judges as if it blocked; whether its verdict refuses is `mode`,
    here, so changing it changes HAProxy's configuration and nothing else.
    """

    waf = proxy.inspected
    if waf is None:
        return []
    verdict = "{ var(txn.coraza.action) -m str deny }"
    failed = "{ var(txn.coraza.error) -m found }"
    lines = [
        f"    http-request wait-for-body time 1s if {host}",
        f"    http-request set-var(txn.coraza.app) str({proxy.name}) if {host}",
        #
        # The engine takes this as its transaction ID, puts it on every rule it
        # logs and hands it back as txn.coraza.id - and its log names no
        # object, so the ID does (B234; measured 26-10-03, Coraza SPOA v0.9.0).
        #
        f'    http-request set-var-fmt(txn.coraza.request) "{proxy.name}.%[uuid]" if {host}',
        f"    http-request send-spoe-group {WAF_SPOE_ENGINE} {WAF_SPOE_GROUP} if {host}",
        *_verdict(f"{host} {verdict}", "crs", "deny" if waf.mode == "block" else "log"),
    ]
    if waf.on_engine_error == "deny":
        lines += [
            f"    http-request set-var(txn.rule) str(waf-engine:deny) if {host} {failed}",
            f"    http-request deny deny_status 503 if {host} {failed}",
        ]
    else:
        lines += _verdict(f"{host} {failed}", "waf-engine", "log")
    #
    # After the engine's answer: a record whose engine did not answer says so
    # first, and a refused body names itself whatever was logged before.
    #
    return [*lines, *_waf_body_rules(proxy, waf, host)]


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
    tls_names: Mapping[str, str] | None = None,
    trusted: bool = False,
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

    lines.extend(_client_rules(proxy, host, trusted))
    allow = _allow_rules(proxy, networks or {}, host, trusted)
    lines.extend(allow)

    if role == "redirect":
        #
        # The whole of this object's presence on port 80: everything that
        # arrives for one of its names is told to come back over TLS, and
        # nothing is served in cleartext, not even a path.
        #
        return [*lines, f"    redirect scheme https code 301 if {host}"]

    lines.extend(_tls_sni_guard(proxy, host, tls_names or {}))

    lines.extend(_access_rules(proxy, networks or {}, host, trusted))

    lines.extend(_waf_rules(proxy, host))

    lines.extend(_maintenance_rule(proxy, host))

    decisions: list[str] = []
    for index, route in enumerate(order_routes(proxy.routes)):
        backend = backend_name(proxy, _destination(proxy, route))
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


def _tls_group_names(members: Sequence[tuple[Vip, Proxy, str]], protocol: str) -> dict[str, str]:
    """Build each policy's allowed SNI names once for this frontend."""

    if protocol != "https":
        return {}
    served = [(vip, member) for vip, member, role in members if role == "serve"]
    policies: dict[str | None, set[str]] = {}
    for vip, member in served:
        policies.setdefault(member.listen.tls_policy or vip.tls_policy, set()).update(
            member.hostnames
        )
    if len(policies) < 2:
        return {}
    allowed = {policy: " ".join(sorted(names)) for policy, names in policies.items()}
    return {
        member.name: allowed[member.listen.tls_policy or vip.tls_policy] for vip, member in served
    }


def _tls_sni_guard(proxy: Proxy, host_acl: str, tls_names: Mapping[str, str]) -> list[str]:
    """Do not route an HTTP site over another policy group's TLS connection."""

    allowed = tls_names.get(proxy.name)
    if proxy.listen.protocol != "https" or allowed is None:
        return []
    sni_acl = _acl_name(proxy.name, "tls-sni")
    return [
        f"    acl {sni_acl} ssl_fc_sni,lower -m str {allowed}",
        f"    http-request deny deny_status 421 if {host_acl} !{sni_acl}",
    ]


def _destination(proxy: Proxy, route: Route) -> str:
    """The backend name a route sends to, whether it is a pool or an answer.

    A redirect's name is derived from its path (`redirect_suffixes`) rather
    than from where it sits in the list. Adding a route above it then moves no
    name, and therefore no GUID and no counter - the same reason a server is
    identified by its address instead of its position.
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
    return redirect_suffixes(proxy)[(route.path, route.match)]


def _redirect_backends(proxy: Proxy) -> list[str]:
    lines: list[str] = []
    for route in order_routes(proxy.routes):
        if route.redirect is None:
            continue
        name = _destination(proxy, route)
        lines += [
            "",
            f"backend {backend_name(proxy, name)}",
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


def _object_file(
    proxy: Proxy,
    source: str | None,
    resolvers: str | None,
    trusted_proxies: Sequence[str] = (),
    peers: str | None = None,
    networks: Mapping[str, Sequence[str]] | None = None,
) -> str:
    rewrites = _rewrites_per_backend(proxy)
    body: list[str] = []
    names = sorted(proxy.backends)
    for name in names:
        body.extend(
            _backend(
                proxy,
                proxy.backends[name],
                rewrites[name],
                source,
                resolvers,
                _counter_lines(proxy, name, names[0], trusted_proxies, peers, networks or {}),
            )
        )
    body.extend(_redirect_backends(proxy))
    body.extend(_block_tables(proxy, peers))
    body.extend(_added_sections(proxy, source))
    return _lines(HEADER, ["#", f"# Object: {proxy.name}", "#"], body)


def _added_sections(proxy: Proxy, source: str | None) -> list[str]:
    """The sections the object's advanced config adds, under their own names (B223).

    Written as they stand, with two lines the generator adds to a backend: its
    identity, like every section here has, and the object's source - a backend
    the text adds is still this object reaching something, and the address it
    reaches it from is the interface's (B215). The identity is the object's and
    the name's, kept apart from the pools' by a separator no pool name can hold.
    """

    if proxy.advanced is None:
        return []
    lines: list[str] = []
    for section in proxy.advanced.placement.sections:
        generated: list[str] = []
        if section.kind == "backend" and source is not None:
            generated.append(f"    source {source}")
        lines.extend(advanced_config.section_block(proxy.name, section, generated))
    return lines


def block_tables(proxy_name: str) -> tuple[str, str]:
    """The two tables of an object's dynamic blocking: (counted, blocked) (B271).

    In the generator's own `mgd-` space, which no pool may take, so neither can
    meet a pool's name; `haprion-node-status` knows them by the same shape and
    leaves them out of what it reports as pools.
    """

    return f"{PREFIX}-{proxy_name}-dynblock-rate", f"{PREFIX}-{proxy_name}-dynblock"


def _block_tables(proxy: Proxy, peers: str | None) -> list[str]:
    """The sections holding the object's dynamic blocking tables, or nothing.

    A section holds one table, and the object's first pool holds the rate
    limit's, so each table is a backend of its own with nothing else in it.
    The alternatives were measured on 3.4.6 (26-10-10) and both crash
    `haproxy -c`: tables in a `peers` section with no peer of the node's own,
    and a `disabled` backend holding a table.

    The blocked table's expiry is the block: an entry lives `block_for` after
    the last request that went over the limit, by the node's own timer, and
    `show table` reads the time left from it.
    """

    block = proxy.dynamic_block
    if block is None:
        return []
    counted, blocked = block_tables(proxy.name)
    window = block.window
    if block.max_new_connections is not None:
        stored = f"conn_rate({window})"
    else:
        stored = f"http_req_rate({window}),http_err_rate({window})"
    return [
        "",
        f"backend {counted}",
        _stick_table(window, stored, peers),
        "",
        f"backend {blocked}",
        _stick_table(block.block_for, "gpc(1)", peers),
    ]


def _block_exempt(
    proxy: Proxy, networks: Mapping[str, Sequence[str]], *, forwarded: bool
) -> tuple[list[str], str, str]:
    """The exemption ACLs and the conditions that use them: (lines, by source, forwarded).

    One ACL per key: an address behind a trusted proxy is its forwarded one,
    every other address the one it came from. Empty conditions without an
    exemption, so the rules read as if it did not exist.
    """

    block = proxy.dynamic_block
    if block is None or not block.exempt:
        return [], "", ""
    by_source = _acl_name(proxy.name, "dynblock-exempt")
    lines = _address_acl(by_source, "src", block.exempt, networks)
    if not forwarded:
        return lines, f" !{by_source}", ""
    by_forwarded = _acl_name(proxy.name, "dynblock-exempt-fwd")
    lines += _address_acl(by_forwarded, "req.hdr_ip(X-Forwarded-For,-1)", block.exempt, networks)
    return lines, f" !{by_source}", f" !{by_forwarded}"


def _http_block_lines(
    proxy: Proxy, trusted: bool, networks: Mapping[str, Sequence[str]]
) -> list[str]:
    """An http object's dynamic blocking, as it lands in each of its pools (B271).

    Every request is counted, and one over either limit marks its address in
    the blocked table - or starts its time again if it is already there. A
    marked address is answered with the chosen status for as long as the mark
    lives, and its traffic record says `dynamic-block:deny`, which is what
    tells it apart from a 404 the application gave. The answer is HAProxy's
    own, so it is not one of the errors counted: a block cannot extend itself.
    Measured on 3.4.6 (26-10-10, `private/ban-prov-20261010/`).

    Written before the rate limit's rules, which would otherwise refuse a
    flood with 429 before it was counted here, and the block would never
    start. An exempt address is neither counted nor answered with a block.
    """

    block = proxy.dynamic_block
    if block is None or block.max_new_connections is not None:
        return []
    counted, blocked = block_tables(proxy.name)
    over = _acl_name(proxy.name, "dynblock-over")
    lines, exempt_source, exempt_forwarded = _block_exempt(proxy, networks, forwarded=trusted)
    #
    # Two lines with one name are one condition, read as an OR - so either
    # limit is enough. Read when a rule asks, after this request was counted.
    #
    for fetch, limit in (
        (f"sc_http_req_rate({BLOCK_COUNT_COUNTER})", block.max_requests),
        (f"sc_http_err_rate({BLOCK_COUNT_COUNTER})", block.max_errors),
    ):
        if limit is not None:
            lines.append(f"    acl {over} {fetch} gt {limit}")
    count = f"    http-request track-sc{BLOCK_COUNT_COUNTER}"
    mark = f"    http-request track-sc{BLOCK_MARK_COUNTER}"
    forwarded = "req.hdr_ip(X-Forwarded-For,-1)"
    if trusted:
        lines += [
            f"{count} {forwarded} table {counted} if {TRUSTED_ACL}{exempt_forwarded}",
            f"{count} src table {counted} if !{TRUSTED_ACL}{exempt_source}",
            f"{mark} {forwarded} table {blocked} if {TRUSTED_ACL}{exempt_forwarded} {over}",
            f"{mark} src table {blocked} if !{TRUSTED_ACL}{exempt_source} {over}",
            f"    http-request set-var(txn.rule) str({BLOCK_RULE}) "
            f"if {TRUSTED_ACL}{exempt_forwarded} {{ {forwarded},in_table({blocked}) }} "
            f"|| !{TRUSTED_ACL}{exempt_source} {{ src,in_table({blocked}) }}",
        ]
    else:
        condition = f" if{exempt_source}" if exempt_source else ""
        lines += [
            f"{count} src table {counted}{condition}",
            f"{mark} src table {blocked} if{exempt_source} {over}",
            f"    http-request set-var(txn.rule) str({BLOCK_RULE}) "
            f"if{exempt_source} {{ src,in_table({blocked}) }}",
        ]
    lines.append(
        f"    http-request deny deny_status {block.status} "
        f"if {{ var(txn.rule) -m str {BLOCK_RULE} }}"
    )
    return lines


def _tcp_block_lines(proxy: Proxy, networks: Mapping[str, Sequence[str]]) -> list[str]:
    """A tcp object's dynamic blocking, at connection time in its own frontend (B271).

    The same counter and mark as an http object's, on new connections: a
    blocked address has its connection closed before a byte is forwarded.
    Before the rate limit's reject, for the reason `_http_block_lines` gives.
    """

    block = proxy.dynamic_block
    if block is None or block.max_new_connections is None:
        return []
    counted, blocked = block_tables(proxy.name)
    over = _acl_name(proxy.name, "dynblock-over")
    lines, exempt, _ = _block_exempt(proxy, networks, forwarded=False)
    condition = f" if{exempt}" if exempt else ""
    return [
        *lines,
        f"    acl {over} sc_conn_rate({BLOCK_COUNT_COUNTER}) gt {block.max_new_connections}",
        f"    tcp-request connection track-sc{BLOCK_COUNT_COUNTER} src table {counted}{condition}",
        f"    tcp-request connection track-sc{BLOCK_MARK_COUNTER} src table {blocked} "
        f"if{exempt} {over}",
        f"    tcp-request connection reject if{exempt} {{ src,in_table({blocked}) }}",
    ]


def _counter_lines(
    proxy: Proxy,
    backend: str,
    holder: str,
    trusted_proxies: Sequence[str],
    peers: str | None,
    networks: Mapping[str, Sequence[str]],
) -> list[str]:
    """The object's counters in one of its pools: dynamic blocking, then the rate limit.

    The trust ACL is written once per pool, ahead of both: an ACL belongs to
    the section that declares it, and the frontend's copy is invisible here.
    """

    table, rules = _rate_lines(proxy, backend, holder, trusted_proxies, peers)
    blocking = _http_block_lines(proxy, bool(trusted_proxies), networks)
    trust: list[str] = []
    if trusted_proxies and (blocking or rules):
        trust = [f"    acl {TRUSTED_ACL} src {' '.join(sorted(trusted_proxies))}"]
    return [*table, *trust, *blocking, *rules]


def _rate_lines(
    proxy: Proxy,
    backend: str,
    holder: str,
    trusted_proxies: Sequence[str],
    peers: str | None = None,
) -> tuple[list[str], list[str]]:
    """The object's own rate limit, as it lands in one of its backends.

    One table for the whole object, kept in its first pool, and every pool
    counting into it - so a limit of a hundred is a hundred across all of the
    object's paths and not a hundred per path. A section of its own for the
    table would have said the same thing, but HAProxy reports every section
    in `show stat`, and a backend with no servers would turn up on the traffic
    page as a pool of this site that never carries anything. Measured on
    3.4.4 on this machine (2026-09-30): two pools, one table, the third
    request refused whichever path it asked for.

    The counter is the second slot, `sc1`. The first is the cluster's abuse
    brake in the shared frontend, and a slot a stream is already tracking is
    ignored when a later rule tracks it again - so reusing `sc0` here would
    count nothing and refuse nobody.

    Behind a trusted proxy the forwarded address is counted, the last one in
    the header, for the reason `_abuse_rules` gives. The trust ACL is written
    again here because an ACL belongs to the section that declares it; the
    frontend's copy is invisible in a backend.

    A tcp object's limit is not written here: it has no request to refuse, so
    the rule sits in its own frontend and only the table lives in the backend.

    Returned as (the table, the rules), so the trust ACL the rules need can be
    written between them once for every counter in the pool (`_counter_lines`).
    """

    limit = proxy.rate_limit
    if limit is None:
        return [], []
    window = limit.window
    table = backend_name(proxy, holder)
    if limit.max_requests is None:
        if backend != holder:
            return [], []
        return [_stick_table(window, f"conn_rate({window})", peers)], []
    held: list[str] = []
    if backend == holder:
        held.append(_stick_table(window, f"http_req_rate({window})", peers))
    lines: list[str] = []
    track = f"    http-request track-sc{RATE_COUNTER}"
    if trusted_proxies:
        lines += [
            f"{track} req.hdr_ip(X-Forwarded-For,-1) table {table} if {TRUSTED_ACL}",
            f"{track} src table {table} unless {TRUSTED_ACL}",
        ]
    else:
        lines.append(f"{track} src table {table}")
    lines.append(
        f"    http-request deny deny_status 429 "
        f"if {{ sc_http_req_rate({RATE_COUNTER}) gt {limit.max_requests} }}"
    )
    return held, lines


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
    rate: Sequence[str] = (),
) -> list[str]:
    name = backend_name(proxy, backend.name)
    raw = proxy.listen.protocol == "tcp"
    #
    # A pool written by hand (B224) is the text's: the balance, the pool's
    # timeouts, the checks, the cookie and the servers come from it, and the
    # cluster's defaults where it says nothing. Written here as well they would
    # be two answers in one section, and HAProxy takes the later one without a
    # word - measured on 3.4.6, 2026-10-01.
    #
    by_hand = backend.written_by_hand
    lines = [
        "",
        f"backend {name}",
        f"    mode {'tcp' if raw else 'http'}",
    ]
    if not by_hand:
        lines += [
            f"    balance {_balance(backend)}",
            f"    timeout connect {TIMEOUT_CONNECT}",
            f"    timeout server {TIMEOUT_SERVER}",
        ]
    if not raw and not by_hand:
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
    #
    # Before every other request rule, so a source over its limit is refused
    # before its path is rewritten or its headers are touched.
    #
    lines.extend(rate)
    lines.extend(rewrites)
    lines.extend(_hsts_line(proxy))
    lines.extend(_header_lines(proxy))
    lines.extend(_unavailable_lines(proxy))

    if backend.max_connections is not None and not by_hand:
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

    if not by_hand:
        lines.extend(_health_lines(backend.health))

    for index, server in enumerate(backend.servers):
        name = _server_name(index)
        cookie = f" cookie {name}" if backend.cookie is not None else ""
        backup = " backup" if server.backup else ""
        weight = f" weight {server.weight}" if server.weight is not None else ""
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
            f"{_server_check(backend, server)}{cookie}{weight}{backup}{limit}{ramp}"
        )
    #
    # Last, so the cluster's brake and the object's limit have run and the
    # text can read their counters (B223 point 2).
    #
    if proxy.advanced is not None:
        lines.extend(advanced_config.block(proxy.name, proxy.advanced.placement.backend))
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
    #
    # What the object writes, or ours - see `DEFAULT_FAST_INTERVAL`.
    #
    fast = health.fast_interval or DEFAULT_FAST_INTERVAL
    down = health.down_interval or DEFAULT_DOWN_INTERVAL
    faster = f" fastinter {fast} downinter {down}"
    return (
        f" check{port}{encrypted} inter {health.interval}{faster}"
        f" rise {health.rise} fall {health.fall}"
    )


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
