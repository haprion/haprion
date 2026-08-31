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
BALANCE = ("roundrobin", "leastconn")
HEALTH_TYPES = ("disabled", "tcp", "http")
MATCH_MODES = ("exact", "prefix")
VERIFY_MODES = ("system", "none")


class ModelError(ConfigError):
    """A proxy object cannot be understood.

    A `ConfigError`, so it carries exit code 65 - "the input is wrong" - and is
    reported the same way as every other refusal on the publishing path.
    """


@dataclass(frozen=True, slots=True)
class Server:
    host: str
    port: int


@dataclass(frozen=True, slots=True)
class Health:
    """How a backend member is decided to be usable.

    `disabled` is spelled out rather than being the absence of the section. A
    pool with no health checking is a decision somebody made, and it should read
    like one in a diff.
    """

    type: str
    path: str | None = None


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


@dataclass(frozen=True, slots=True)
class Listen:
    protocol: str
    certificate: str | None = None
    redirect_http: bool = False


@dataclass(frozen=True, slots=True)
class Proxy:
    name: str
    hostnames: tuple[str, ...]
    listen: Listen
    routes: tuple[Route, ...]
    backends: Mapping[str, Backend]


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
    _only_keys(data, {"host", "port"}, location)
    host = _required_string(data, "host", location)
    port = data.get("port")
    #
    # A bool is an int in Python, and `port: true` would otherwise be port 1.
    # The same check the worker's payload validation makes, for the same reason.
    #
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise ModelError(f"{location}.port must be a port number")
    return Server(host=host, port=port)


def _health(value: Any, location: str) -> Health:
    data = _mapping(value, location)
    _only_keys(data, {"type", "path"}, location)
    kind = _string(data, "type", location, HEALTH_TYPES)
    path = data.get("path")
    if kind == "http":
        if not isinstance(path, str) or not ROUTE_PATH.match(path):
            raise ModelError(f"{location}.path must be an absolute path for an http health check")
        return Health(type=kind, path=path)
    if path is not None:
        raise ModelError(f"{location}.path is only meaningful for an http health check")
    return Health(type=kind)


def _backend(name: str, value: Any, location: str) -> Backend:
    data = _mapping(value, location)
    _only_keys(data, {"balance", "servers", "health", "tls"}, location)
    balance = _string(data, "balance", location, BALANCE)

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

    return Backend(
        name=name,
        balance=balance,
        servers=members,
        health=_health(data.get("health", {"type": "disabled"}), f"{location}.health"),
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
    _only_keys(data, {"schema", "name", "hostnames", "listen", "routes", "backends"}, name)

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

    return Proxy(
        name=name, hostnames=tuple(hostnames), listen=listen, routes=routes, backends=backends
    )


def _listen(value: Any, location: str) -> Listen:
    data = _mapping(value, location)
    _only_keys(data, {"protocol", "certificate", "redirect_http"}, location)
    protocol = _string(data, "protocol", location, PROTOCOLS)
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

    return Listen(protocol=protocol, certificate=certificate, redirect_http=redirect)
