"""What a proxy object is, before it is HAProxy configuration.

This is the generator's input: one object per file, written by the application
and read here. It deliberately speaks the vocabulary of somebody who runs
proxies - site, hostnames, routes, backend pools, health checks - and not the
vocabulary of HAProxy. Nothing in this module mentions a frontend, an acl or a
`use_backend`, because translating between the two is the generator's job and
the whole reason the application exists.

Read from bytes rather than from a path, and that is not an accident of
plumbing. The generator's input is the committed tree, the same bytes
`git archive` produces, exactly as `release_layout` takes its tree. A generator
that could fall back to a working tree would let an uncommitted change appear in
generated configuration, which is the same mistake `inventory` refuses to make.

Everything is refused rather than defaulted where a default would be a guess. An
unknown field is an error: a key nobody expected is either a typo that silently
does nothing, or a feature this version does not have and the writer thinks it
does. Both are worse than being told.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import yaml

from haproxy_mgmt.config import ConfigError, _mapping, _only_keys, _required_string

#
# Bounded for the same reason every other document this system reads is: a file
# that reaches the parser is a file somebody could have made enormous.
#
MAX_MODEL_BYTES = 256 * 1024

#
# The object's identity. It is the filename, part of every generated name, and
# the seed of every GUID, so it has to be stable, lowercase and free of anything
# that means something to a path or to HAProxy.
#
NAME = re.compile(r"^[a-z][a-z0-9-]{0,39}$")

#
# A hostname as it appears in a Host header. Not a full RFC validation - that
# would reject things HAProxy happily serves - but enough that a value which is
# obviously something else, such as a URL or an address with a port, is caught
# where the writer can still fix it.
#
HOSTNAME = re.compile(
    r"^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
    r"(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$"
)

#
# A path prefix as a route matches on. Absolute, no query, no wildcards: the
# matching rules are about segments, and a pattern language here would make the
# frozen semantics ambiguous before the first golden file exists.
#
ROUTE_PATH = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*$")

PROTOCOLS = ("http", "https", "tcp")
#
# The balancing algorithms an object may choose, read from HAProxy 3.4.4's own
# documentation on this machine. HAProxy has more - `hash`, `hdr()`,
# `url_param()`, `rdp-cookie` - and they are left out on purpose: each takes an
# expression as an argument, and a field where somebody writes an expression is
# the raw HAProxy syntax this project has decided not to have.
#
#   roundrobin  in turn, by weight. The fair default for HTTP.
#   static-rr   the same without on-the-fly weight changes; no server limit.
#   leastconn   fewest connections first. For long-lived sessions, not short
#               HTTP ones - HAProxy's own documentation says so.
#   first       fill one server before using the next, so idle ones can be
#               powered off. Only meaningful together with a connection limit.
#   source      hash the client address, so one client keeps one server. The
#               stickiness you get without asking the browser to hold a cookie.
#   uri         hash the path, so one URL keeps one server. What a cache in the
#               backend wants.
#   random      pick at random. Behaves well when several proxies balance over
#               the same pool and would otherwise agree on the same "next" one.
#
#   hdr         hash one request header's value, named by `balance_key`. What
#               a multi-tenant backend wants when the tenant is in a header.
#   url_param   hash one query parameter's value, named by `balance_key`. The
#               usual way to keep one logged-in user on one server without
#               involving a cookie.
#
# `hash <expression>` is the one HAProxy offers that is left out, and it is
# left out for a reason rather than an oversight: its argument is an arbitrary
# HAProxy expression, which is the raw configuration syntax this project has
# decided not to have. `rdp-cookie` waits for TCP support, since it is
# meaningless in an HTTP backend, and `sticky` is for log backends.
#
BALANCE = (
    "roundrobin",
    "static-rr",
    "leastconn",
    "first",
    "source",
    "uri",
    "random",
    "hdr",
    "url_param",
)

#
# The algorithms that hash something the request carries by name, and therefore
# need to be told which name.
#
BALANCE_NEEDS_KEY = ("hdr", "url_param")

#
# A query parameter name. Deliberately narrower than what a URL may carry: this
# value is written into a configuration line, and a name needing escaping there
# is a name worth refusing where somebody can still change it.
#
PARAMETER = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

#
# A cookie name, as a cookie name is allowed to look. Narrow for the same
# reason everything else here is: it is written into a configuration line and
# read back by a browser, and the intersection of what both accept is smaller
# than either.
#
COOKIE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")

#
# An HTTP field name, as RFC 9110 defines a token.
#
HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}$")

#
# What a maintenance page may say. The value is written into a double-quoted
# configuration line, so a quote or a backslash would end that line somewhere
# other than where it looks like it ends. `$` is out for a measured reason
# rather than a cautious one: HAProxy 3.4.4 on this machine expands `$HOME`
# inside double quotes, and a message meant for visitors would then carry a
# value from the node's environment.
#
MESSAGE = re.compile(r"^[A-Za-z0-9 %#.,:;!?()'/@+-]{1,200}$")

#
# The one thing a message may ask to have filled in: the site's own name. It is
# substituted where the configuration is generated, not where the request is
# answered, so a visitor reads a name this object actually claims. HAProxy can
# do the second - `lf-string` with `%[req.hdr(host)]` - and that would print
# back whatever header the client sent, which is a different and worse thing.
# `%` is otherwise literal in a HAProxy `string`, measured on 3.4.4 on this
# machine, so the token is ours alone to read.
#
URL_PLACEHOLDER = "%URL%"

#
# Anything else between percent signs is refused rather than passed through. A
# message that reads `%SITE%` to its author and prints `%SITE%` to a visitor is
# the silent kind of wrong this model exists to prevent.
#
PLACEHOLDER = re.compile(r"%[A-Za-z_]+%")
#
# What a health check speaks. The variants an ADC lists separately - TCP,
# TCP-ECV, HTTP, HTTP-ECV, HTTPS, HTTPS-ECV - are combinations of three
# independent choices here rather than six names: which protocol, whether it
# runs over TLS, and whether it looks at the answer. The same reasoning as the
# path modes: a combination of fields that each say what they do beats a
# vocabulary somebody has to look up.
#
HEALTH_TYPES = ("disabled", "tcp", "http")

#
# How often, and how many answers in a row it takes to change a server's mind.
# HAProxy's own defaults, written out rather than inherited, so the generated
# file says what it does.
#
DEFAULT_INTERVAL = "2s"
DEFAULT_RISE = 2
DEFAULT_FALL = 3

#
# The status range a check accepts when nobody said. Also HAProxy's own
# behaviour made explicit: without it, anything below 500 counts as healthy -
# including a 302 to a login page, which is exactly the answer a broken
# application gives.
#
DEFAULT_EXPECT_STATUS = "200-399"

DURATION = re.compile(r"^[1-9][0-9]{0,4}(ms|s|m)$")
STATUS_RANGE = re.compile(r"^[1-5][0-9]{2}(-[1-5][0-9]{2})?$")

#
# What a check may send and look for. Narrow on purpose: the value is written
# into a configuration line, and whitespace, quotes or backslashes there change
# where the line ends rather than what the check looks for.
#
PROBE = re.compile(r"^[A-Za-z0-9._:/+=@-]{1,64}$")
MATCH_MODES = ("exact", "prefix")
VERIFY_MODES = ("system", "none")


class ModelError(ConfigError):
    """A proxy object cannot be understood.

    A `ConfigError`, so it carries exit code 65 - "the input is wrong" - and is
    reported the same way as every other refusal on the publishing path.
    """


@dataclass(frozen=True, slots=True)
class Server:
    """One pool member.

    `backup` is the classic active/passive pair: a member that takes no traffic
    at all while any non-backup member is up, and everything the moment none
    is. It is a property of the member rather than of the pool, because which
    machine is the standby is exactly what a reader needs to see on the line
    that names it.
    """

    host: str
    port: int
    backup: bool = False


@dataclass(frozen=True, slots=True)
class Health:
    """How a backend member is decided to be usable.

    `disabled` is spelled out rather than being the absence of the section. A
    pool with no health checking is a decision somebody made, and it should read
    like one in a diff.

    `host` exists because of a failure mode that looks like something else
    entirely: a backend doing name-based virtual hosting answers a check with
    no Host header with a 404 or a redirect, the pool goes down, and the
    interface reports a dead server that is in fact perfectly healthy.
    """

    type: str
    tls: bool = False
    port: int | None = None
    path: str | None = None
    host: str | None = None
    expect_status: str | None = None
    expect_body: str | None = None
    send: str | None = None
    expect: str | None = None
    interval: str = DEFAULT_INTERVAL
    rise: int = DEFAULT_RISE
    fall: int = DEFAULT_FALL


@dataclass(frozen=True, slots=True)
class BackendTls:
    verify: str


@dataclass(frozen=True, slots=True)
class Backend:
    name: str
    balance: str
    servers: tuple[Server, ...]
    health: Health
    tls: BackendTls | None = None
    cookie: str | None = None
    """The name of the cookie that keeps one visitor on one member.

    Session persistence, and deliberately not a balancing algorithm.
    `balance source` is the version that needs no cookie and breaks the moment
    a group of visitors shares an address - an office behind NAT, a mobile
    network - because they then share a server too. A cookie follows the
    session rather than the address.
    """
    balance_key: str | None = None
    """Which header or query parameter `hdr` and `url_param` hash.

    Required by those two and refused by every other algorithm, rather than
    ignored. A key set next to `roundrobin` means somebody believed the pool
    was sticky when it was not, and finding that out from a support call is
    worse than finding it out from the editor.
    """


@dataclass(frozen=True, slots=True)
class Route:
    """One matching rule and where it sends what it matched.

    `strip_prefix` and `add_prefix` are two optional fields rather than one mode
    with four values. The four modes the plan names - preserve, strip, add,
    strip+add - are then the four combinations, and each one reads as what it
    does to the path instead of as a word to look up.
    """

    path: str
    match: str
    backend: str
    strip_prefix: str | None = None
    add_prefix: str | None = None

    @property
    def segments(self) -> int:
        """How specific this route is, counted the way the plan freezes it.

        Segments rather than characters: `/a/b` beats `/abcdef`, because a
        deeper path is a more specific statement about the request than a longer
        one. Decided here and written into file order by the generator, so
        nothing at runtime depends on how a list happened to be sorted.
        """

        return len([part for part in self.path.split("/") if part])


#
# The longest promise HSTS may make. Two years is what the preload lists ask
# for, and more than that is a commitment nobody can honour by editing
# configuration - the browser stops asking.
#
MAX_HSTS_AGE = 63072000


@dataclass(frozen=True, slots=True)
class Hsts:
    """A promise to the browser that this name is https from now on.

    Off unless asked for, and it is the one setting in the model that cannot
    be taken back by changing configuration: for `max_age` seconds the browser
    refuses plain http on its own, whatever the server now says.
    `include_subdomains` extends that to names this object may not even own,
    which is why it is a separate, deliberate word rather than part of a
    preset.
    """

    max_age: int
    include_subdomains: bool = False


@dataclass(frozen=True, slots=True)
class Maintenance:
    """This object is out of service on purpose, and says so.

    Taking a site down by deleting its object loses everything the object
    knows - its routes, its pools, its checks - and the way back is to write it
    again from memory. This is the other way: the object stays exactly as it
    is, and every request for its names is answered with a page instead of
    being routed.

    The message is required rather than defaulted. A maintenance mode with
    nothing to say produces the naked 503 that B49 objected to in the first
    place, only now on purpose; the whole difference between the two is that
    somebody wrote down what is happening and when it ends.
    """

    message: str


@dataclass(frozen=True, slots=True)
class Unavailable:
    """What a visitor is told when no server in the pool can answer.

    The one page a site cannot serve for itself: 502 and 503 arise precisely
    when nothing behind the proxy is answering, so an error page hosted by the
    application is unreachable exactly when it is needed. Left out, HAProxy
    serves its own grey text, which says nothing about which site this was or
    who to tell.

    A line of text rather than a file. A real HTML page would have to be
    carried to every node, versioned with the release and reviewed like
    configuration, and none of that is worth it for a sentence.
    """

    message: str


@dataclass(frozen=True, slots=True)
class Listen:
    """Where this object is reached, and how.

    `vip` names one of the cluster's addresses rather than being an address.
    An address is an environment value and belongs in the cluster
    configuration; the object says which of them it sits on, and the same
    object therefore means the same thing in a rehearsal cluster and in
    production. Left out, it means the cluster's default VIP, which is the
    normal case and the only case until somebody adds a second one.
    """

    protocol: str
    vip: str | None = None
    source: str | None = None
    certificate: str | None = None
    redirect_http: bool = False
    hsts: Hsts | None = None


@dataclass(frozen=True, slots=True)
class Proxy:
    name: str
    hostnames: tuple[str, ...]
    listen: Listen
    routes: tuple[Route, ...]
    backends: Mapping[str, Backend]
    allow_from: tuple[str, ...] = ()
    """Who may reach this object at all. Empty means everyone.

    An entry is either the name of a group the cluster defines, or a literal
    address or range. The named form is the better one where it fits - the
    object says "the office" and which addresses that is stays in the cluster
    configuration, so the same object means the same thing in a rehearsal
    cluster and in production - but a range that belongs to one site and
    nothing else has no business being named cluster-wide, and writing it here
    is then the honest answer rather than a workaround.

    This is a different question from the trusted proxy list. That one decides
    whose forwarded headers are believed; this one decides who gets an answer.
    """

    maintenance: Maintenance | None = None
    """Set while the site is deliberately out of service. None means serving."""

    unavailable: Unavailable | None = None
    """What to say when the pool cannot answer. None means HAProxy's own text."""


def _string(value: Mapping[str, Any], key: str, location: str, allowed: tuple[str, ...]) -> str:
    result = _required_string(value, key, location)
    if result not in allowed:
        raise ModelError(f"{location}.{key} must be one of: {', '.join(allowed)}")
    return result


def _boolean(value: Mapping[str, Any], key: str, location: str, *, default: bool) -> bool:
    result = value.get(key, default)
    if not isinstance(result, bool):
        raise ModelError(f"{location}.{key} must be true or false")
    return result


def _optional_prefix(value: Mapping[str, Any], key: str, location: str) -> str | None:
    raw = value.get(key)
    if raw is None:
        return None
    if not isinstance(raw, str) or not ROUTE_PATH.match(raw) or raw == "/":
        raise ModelError(f"{location}.{key} must be an absolute path below /")
    return raw.rstrip("/") or None


def _server(value: Any, location: str) -> Server:
    data = _mapping(value, location)
    _only_keys(data, {"host", "port", "backup"}, location)
    host = _required_string(data, "host", location)
    port = data.get("port")
    #
    # A bool is an int in Python, and `port: true` would otherwise be port 1.
    # The same check the worker's payload validation makes, for the same reason.
    #
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise ModelError(f"{location}.port must be a port number")
    return Server(host=host, port=port, backup=_boolean(data, "backup", location, default=False))


_HTTP_ONLY = ("path", "host", "expect_status", "expect_body")
_TCP_ONLY = ("send", "expect")
_TIMING = ("tls", "port", "interval", "rise", "fall")


def _health(value: Any, location: str) -> Health:
    data = _mapping(value, location)
    _only_keys(data, {"type", *_HTTP_ONLY, *_TCP_ONLY, *_TIMING}, location)
    kind = _string(data, "type", location, HEALTH_TYPES)

    if kind == "disabled":
        unusable = sorted(set(data) - {"type"})
        if unusable:
            raise ModelError(
                f"{location} is disabled, so it cannot also be configured: {', '.join(unusable)}"
            )
        return Health(type=kind)

    for key in _TCP_ONLY if kind == "http" else _HTTP_ONLY:
        if data.get(key) is not None:
            raise ModelError(f"{location}.{key} means nothing for a {kind} health check")

    interval = data.get("interval", DEFAULT_INTERVAL)
    if not isinstance(interval, str) or not DURATION.match(interval):
        raise ModelError(f"{location}.interval must be a duration such as 5s or 500ms")

    tls = _boolean(data, "tls", location, default=False)
    #
    # A separate port for the check, because a health endpoint is not always on
    # the port that serves traffic - plenty of systems answer on their own
    # management port instead. Absent means the server's own port, which is the
    # usual case and needs no words.
    #
    port = data.get("port")
    if port is not None and (
        not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535
    ):
        raise ModelError(f"{location}.port must be a port number")
    rise = _count(data, "rise", location, DEFAULT_RISE)
    fall = _count(data, "fall", location, DEFAULT_FALL)

    if kind == "http":
        path = data.get("path")
        if not isinstance(path, str) or not ROUTE_PATH.match(path):
            raise ModelError(f"{location}.path must be an absolute path for an http health check")
        host = data.get("host")
        if host is not None and (not isinstance(host, str) or not HOSTNAME.match(host)):
            raise ModelError(f"{location}.host must be a hostname")
        status = data.get("expect_status", DEFAULT_EXPECT_STATUS)
        if not isinstance(status, str) or not STATUS_RANGE.match(status):
            raise ModelError(f"{location}.expect_status must be a status or range, such as 200-299")
        return Health(
            type=kind,
            path=path,
            host=host,
            expect_status=status,
            expect_body=_probe(data, "expect_body", location),
            tls=tls,
            port=port,
            interval=interval,
            rise=rise,
            fall=fall,
        )

    send = _probe(data, "send", location)
    expect = _probe(data, "expect", location)
    if (send is None) != (expect is None):
        #
        # Sending without looking at the answer proves only that the port is
        # open, which a plain connection already proved; looking without
        # sending waits for a greeting that most protocols never volunteer.
        #
        raise ModelError(f"{location}.send and {location}.expect belong together")
    return Health(
        type=kind,
        send=send,
        expect=expect,
        tls=tls,
        port=port,
        interval=interval,
        rise=rise,
        fall=fall,
    )


def _count(data: Mapping[str, Any], key: str, location: str, default: int) -> int:
    value = data.get(key, default)
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 10:
        raise ModelError(f"{location}.{key} must be a small number of checks")
    return value


def _probe(data: Mapping[str, Any], key: str, location: str) -> str | None:
    value = data.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not PROBE.match(value):
        raise ModelError(
            f"{location}.{key} must be a short value without spaces, quotes or backslashes"
        )
    return value


def _balance_key(data: Mapping[str, Any], balance: str, location: str) -> str | None:
    key = data.get("balance_key")
    if balance not in BALANCE_NEEDS_KEY:
        if key is not None:
            raise ModelError(
                f"{location}.balance_key means nothing for balance: {balance}; "
                f"it names what hdr or url_param hashes"
            )
        return None
    if not isinstance(key, str):
        raise ModelError(f"{location}.balance_key is required for balance: {balance}")
    pattern = HEADER_NAME if balance == "hdr" else PARAMETER
    if not pattern.match(key):
        what = "an HTTP header name" if balance == "hdr" else "a query parameter name"
        raise ModelError(f"{location}.balance_key must be {what}")
    return key


def _backend(name: str, value: Any, location: str) -> Backend:
    data = _mapping(value, location)
    _only_keys(data, {"balance", "balance_key", "cookie", "servers", "health", "tls"}, location)
    balance = _string(data, "balance", location, BALANCE)
    balance_key = _balance_key(data, balance, location)

    servers = data.get("servers")
    if not isinstance(servers, list) or not servers:
        raise ModelError(f"{location}.servers must list at least one server")
    members = tuple(
        _server(item, f"{location}.servers[{index}]") for index, item in enumerate(servers)
    )
    #
    # Two members at the same address and port are almost certainly a copied
    # line rather than an intent, and HAProxy would happily balance between
    # them and report a pool that looks twice as healthy as it is.
    #
    addresses = [(member.host, member.port) for member in members]
    if len(set(addresses)) != len(addresses):
        raise ModelError(f"{location}.servers lists the same host and port twice")

    tls = data.get("tls")
    backend_tls = None
    if tls is not None:
        tls_data = _mapping(tls, f"{location}.tls")
        _only_keys(tls_data, {"verify"}, f"{location}.tls")
        backend_tls = BackendTls(
            verify=_string(tls_data, "verify", f"{location}.tls", VERIFY_MODES)
        )

    health = _health(data.get("health", {"type": "disabled"}), f"{location}.health")
    if health.type == "http" and health.tls and backend_tls is None:
        #
        # Measured on HAProxy 3.4.4: a check that connects with TLS to a server
        # that has no TLS settings is refused outright - "verify is enabled by
        # default but no CA file specified". Rather than pick a verification
        # policy on somebody's behalf, and quietly pick the insecure one at
        # that, the object has to say which it wants.
        #
        raise ModelError(
            f"{location}.health checks over tls, so {location}.tls must say whether the "
            f"certificate is verified"
        )

    cookie = data.get("cookie")
    if cookie is not None and (not isinstance(cookie, str) or not COOKIE.match(cookie)):
        raise ModelError(f"{location}.cookie must be a usable cookie name")

    return Backend(
        name=name,
        balance=balance,
        balance_key=balance_key,
        cookie=cookie,
        servers=members,
        health=health,
        tls=backend_tls,
    )


def _route(value: Any, location: str, backends: set[str]) -> Route:
    data = _mapping(value, location)
    _only_keys(data, {"path", "match", "backend", "strip_prefix", "add_prefix"}, location)

    path = _required_string(data, "path", location)
    if not ROUTE_PATH.match(path):
        raise ModelError(f"{location}.path must be an absolute path")
    path = path.rstrip("/") or "/"

    match = data.get("match", "prefix")
    if match not in MATCH_MODES:
        raise ModelError(f"{location}.match must be one of: {', '.join(MATCH_MODES)}")

    backend = _required_string(data, "backend", location)
    if backend not in backends:
        raise ModelError(f"{location}.backend names no backend in this object: {backend}")

    strip = _optional_prefix(data, "strip_prefix", location)
    if strip is not None and not path.startswith(strip):
        raise ModelError(f"{location}.strip_prefix must be a prefix of the route's own path")

    return Route(
        path=path,
        match=str(match),
        backend=backend,
        strip_prefix=strip,
        add_prefix=_optional_prefix(data, "add_prefix", location),
    )


def dump_document(fields: Mapping[str, Any]) -> str:
    """Write a proxy object out as the YAML it is stored as.

    The counterpart of `load_proxy`, and here rather than in whichever caller
    happens to need it: an object written by the interface and an object
    written by hand have to be the same document, and two serialisers would
    eventually disagree about quoting or key order in a way that shows up as a
    confusing diff rather than as an error.

    Key order is preserved rather than sorted, because the order is the reading
    order - what the site is, then where it listens, then where traffic goes.
    """

    return yaml.safe_dump(dict(fields), sort_keys=False, default_flow_style=False)


def load_proxy(name: str, document: bytes) -> Proxy:
    """Read one proxy object, or say exactly what is wrong with it.

    `name` is the object's identity - the filename without its suffix - and the
    document must agree with it. Two sources for one identity is how a rename
    ends up producing configuration under the old name.

    The shared validation helpers are reused rather than reimplemented, so a
    malformed mapping is described here the same way it is everywhere else in
    the engine - but they raise `ConfigError`, and a module that promises its
    own error type has to keep that promise. Every refusal leaves this function
    as a `ModelError`, and callers therefore need to know one name.
    """

    try:
        return _load_proxy(name, document)
    except ModelError:
        raise
    except ConfigError as exc:
        raise ModelError(str(exc)) from exc


def _load_proxy(name: str, document: bytes) -> Proxy:
    if len(document) > MAX_MODEL_BYTES:
        raise ModelError(f"{name}: the proxy object exceeds the size limit")
    try:
        loaded = yaml.safe_load(document.decode("utf-8"))
    except (UnicodeError, yaml.YAMLError) as exc:
        raise ModelError(f"{name}: the proxy object is not valid YAML: {exc}") from exc

    data = _mapping(loaded, name)
    _only_keys(
        data,
        {
            "schema",
            "name",
            "hostnames",
            "listen",
            "routes",
            "backends",
            "allow_from",
            "maintenance",
            "unavailable",
        },
        name,
    )

    if data.get("schema") != 1:
        raise ModelError(f"{name}.schema must be 1")
    if _required_string(data, "name", name) != name:
        raise ModelError(f"{name}.name must match the file it is written in")
    if not NAME.match(name):
        raise ModelError(f"{name} is not a usable object name")

    hostnames = data.get("hostnames")
    if not isinstance(hostnames, list) or not hostnames:
        raise ModelError(f"{name}.hostnames must list at least one hostname")
    for hostname in hostnames:
        if not isinstance(hostname, str) or not HOSTNAME.match(hostname):
            raise ModelError(f"{name}.hostnames contains something that is not a hostname")
    if len(set(hostnames)) != len(hostnames):
        raise ModelError(f"{name}.hostnames lists the same hostname twice")

    listen = _listen(data.get("listen"), f"{name}.listen")

    backends_raw = _mapping(data.get("backends"), f"{name}.backends")
    if not backends_raw:
        raise ModelError(f"{name}.backends must define at least one backend")
    backends = {
        key: _backend(key, value, f"{name}.backends.{key}") for key, value in backends_raw.items()
    }
    for key in backends:
        if not NAME.match(key):
            raise ModelError(f"{name}.backends.{key} is not a usable backend name")

    routes_raw = data.get("routes")
    if not isinstance(routes_raw, list) or not routes_raw:
        raise ModelError(f"{name}.routes must list at least one route")
    routes = tuple(
        _route(item, f"{name}.routes[{index}]", set(backends))
        for index, item in enumerate(routes_raw)
    )
    paths = [(route.path, route.match) for route in routes]
    if len(set(paths)) != len(paths):
        raise ModelError(f"{name}.routes matches the same path twice")

    #
    # Every pool has to be reachable. A backend nothing routes to is either a
    # leftover from an edit or a route somebody forgot to add, and generating
    # configuration for it would hide both.
    #
    used = {route.backend for route in routes}
    unused = sorted(set(backends) - used)
    if unused:
        raise ModelError(f"{name}.backends defines backends no route uses: {', '.join(unused)}")

    allow_from = _allow_from(data.get("allow_from", []), name)
    maintenance = _maintenance(data.get("maintenance"), f"{name}.maintenance")
    unavailable = _unavailable(data.get("unavailable"), f"{name}.unavailable")

    return Proxy(
        name=name,
        hostnames=tuple(hostnames),
        listen=listen,
        routes=routes,
        backends=backends,
        allow_from=tuple(allow_from),
        maintenance=maintenance,
        unavailable=unavailable,
    )


def _maintenance(value: Any, location: str) -> Maintenance | None:
    if value is None:
        return None
    data = _mapping(value, location)
    _only_keys(data, {"message"}, location)
    return Maintenance(message=_message(data, location))


def _message(data: Mapping[str, Any], location: str) -> str:
    message = data.get("message")
    if not isinstance(message, str) or not MESSAGE.match(message):
        raise ModelError(
            f"{location}.message must be a line of readable text, "
            f"up to 200 characters, without quotes, backslashes or $"
        )
    unknown = sorted({found for found in PLACEHOLDER.findall(message) if found != URL_PLACEHOLDER})
    if unknown:
        raise ModelError(
            f"{location}.message uses something this version does not fill in: "
            f"{', '.join(unknown)}. The only one is {URL_PLACEHOLDER}"
        )
    return message


def _unavailable(value: Any, location: str) -> Unavailable | None:
    if value is None:
        return None
    data = _mapping(value, location)
    _only_keys(data, {"message"}, location)
    return Unavailable(message=_message(data, location))


def is_range(entry: str) -> bool:
    """Whether an `allow_from` entry is a literal address or range.

    Decided by trying to parse it, not by looking for a slash: a bare address is
    a range of one, and a name can never parse as either.
    """

    try:
        ipaddress.ip_network(entry, strict=False)
    except ValueError:
        return False
    return True


def _allow_from(value: Any, name: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ModelError(f"{name}.allow_from must list group names, addresses or ranges")

    entries: list[str] = []
    for entry in value:
        if not isinstance(entry, str) or not entry:
            raise ModelError(f"{name}.allow_from contains something that is not a name or range")
        if is_range(entry):
            network = ipaddress.ip_network(entry, strict=False)
            if network.prefixlen == 0:
                #
                # A range that means everywhere is an allowlist that allows
                # everything, which is worse than none: it reads as a
                # restriction and enforces nothing.
                #
                raise ModelError(f"{name}.allow_from may not allow an entire address family")
            entries.append(str(network))
            continue
        if not NAME.match(entry):
            raise ModelError(
                f"{name}.allow_from contains {entry!r}, which is neither a group name nor an "
                f"address or range"
            )
        entries.append(entry)

    if len(set(entries)) != len(entries):
        raise ModelError(f"{name}.allow_from names the same group or range twice")
    return tuple(entries)


def _listen(value: Any, location: str) -> Listen:
    data = _mapping(value, location)
    _only_keys(
        data, {"protocol", "vip", "source", "certificate", "redirect_http", "hsts"}, location
    )
    protocol = _string(data, "protocol", location, PROTOCOLS)
    vip = data.get("vip")
    if vip is not None and (not isinstance(vip, str) or not NAME.match(vip)):
        raise ModelError(f"{location}.vip must name one of the cluster's VIPs")
    #
    # The address this object leaves from, when it should not be the one the
    # VIP pairs with. Named rather than written, like every other address.
    #
    source = data.get("source")
    if source is not None and (not isinstance(source, str) or not NAME.match(source)):
        raise ModelError(f"{location}.source must name one of the cluster's source addresses")
    certificate = data.get("certificate")
    redirect = _boolean(data, "redirect_http", location, default=False)

    if protocol == "https":
        if not isinstance(certificate, str) or not certificate:
            raise ModelError(f"{location}.certificate is required for https")
    elif certificate is not None:
        raise ModelError(f"{location}.certificate is only meaningful for https")

    #
    # Redirecting to https from a listener that has no https is a promise the
    # object cannot keep, and it would generate a redirect loop rather than an
    # error somebody could read.
    #
    if redirect and protocol != "https":
        raise ModelError(f"{location}.redirect_http requires protocol: https")

    hsts = _hsts(data.get("hsts"), f"{location}.hsts")
    if hsts is not None and protocol != "https":
        raise ModelError(f"{location}.hsts requires protocol: https")

    return Listen(
        protocol=protocol,
        vip=vip,
        source=source,
        certificate=certificate,
        redirect_http=redirect,
        hsts=hsts,
    )


def _hsts(value: Any, location: str) -> Hsts | None:
    if value is None:
        return None
    data = _mapping(value, location)
    _only_keys(data, {"max_age", "include_subdomains"}, location)
    max_age = data.get("max_age")
    if not isinstance(max_age, int) or isinstance(max_age, bool) or not 0 < max_age <= MAX_HSTS_AGE:
        raise ModelError(f"{location}.max_age must be a number of seconds up to {MAX_HSTS_AGE}")
    return Hsts(
        max_age=max_age,
        include_subdomains=_boolean(data, "include_subdomains", location, default=False),
    )
