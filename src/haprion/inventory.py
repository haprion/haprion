"""Derive the small, read-only proxy inventory from a published release.

The web application must not read a cluster repository.  That rule matters as
much for an inventory as it does for a deployment: a work tree can contain a
half-written managed configuration, while the UI needs to describe what was
actually published.  This module consequently accepts a tree of committed
files, as returned by :func:`haprion.repo_snapshot.read_tree_files`, and
never opens paths itself.

HAProxy's grammar is intentionally broader than the inventory needs to be.
The parser below is deliberately narrow: it recognises frontends and listens,
their ``bind`` lines, host ACLs and backend references.  Unknown directives are
left alone rather than guessed at.  A future generator can add richer metadata
without teaching the web process to interpret HAProxy configuration.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime

from haprion.deploy_plan import ReleaseTarget
from haprion.reservations import (
    RESERVATIONS_PATH,
    ReservationError,
    Reservations,
    load_reservations,
)

_SECTION = re.compile(r"^(?:frontend|listen)\s+(?P<name>\S+)(?:\s|$)")
_OTHER_SECTION = re.compile(
    r"^(?:global|defaults|backend|resolvers|mailers|userlist|peers|ring|cache|program|crt-store|fcgi-app)(?:\s|$)",
    re.IGNORECASE,
)
_BIND_PORT = re.compile(r"(?::|^)(?P<port>[1-9][0-9]{0,4})(?:-[0-9]{1,5})?$")
#
# Two spellings, and both are real configuration on this machine.
#
# `hdr(host) -i a b c` is what a hand-written frontend uses, and what this
# parser was built for. `req.hdr(host),field(1,:),lower -m str <host>` is what
# the generator writes - the converters strip a port and fold the case before
# the comparison, which the `-i` form cannot do.
#
# Reading only the first meant the inventory found no hostnames at all in
# anything this project generates. Nothing failed: the listing simply said "No
# hostname rule", and every managed object stayed in the undeployed list for
# ever, because the check that would have taken it out compares hostnames.
#
_HOST_ACL = re.compile(
    r"\bhdr\(host\)(?:,[^\s]+)?\s+(?:-i|-m\s+str)\s+(?P<hosts>[^#]+)",
    re.IGNORECASE,
)
_BACKEND = re.compile(r"^(?:default_backend|use_backend)\s+(?P<name>\S+)(?:\s|$)")
_MODE_TCP = re.compile(r"^mode\s+tcp(?:\s|$)", re.IGNORECASE)
_SSL = re.compile(r"(?:^|\s)ssl(?:\s|$)", re.IGNORECASE)


class InventoryError(ValueError):
    """A published tree cannot be represented faithfully as an inventory."""


@dataclass(slots=True)
class _Proxy:
    name: str
    source: str
    bind_ports: set[int] = field(default_factory=set)
    hostnames: set[str] = field(default_factory=set)
    backends: set[str] = field(default_factory=set)
    tcp: bool = False
    ssl: bool = False


def _source_for(path: str) -> str | None:
    if path == "core/haproxy.cfg" or path.startswith("core/conf.d/"):
        return "core"
    if path.startswith("managed/generated/"):
        return "managed"
    if path.startswith("manual/conf.d/"):
        return "manual"
    return None


def _configuration_files(files: Mapping[str, bytes]) -> Iterable[tuple[str, str]]:
    """The committed HAProxy fragments that form the published configuration."""

    for path in sorted(files):
        source = _source_for(path)
        if source is None or (path != "core/haproxy.cfg" and not path.endswith(".cfg")):
            continue
        try:
            yield source, files[path].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise InventoryError(f"published configuration file is not UTF-8: {path}") from exc


def _port(token: str) -> int | None:
    """One numeric TCP port from a HAProxy bind address, when it has one."""

    candidate = token.rsplit(",", 1)[-1]
    match = _BIND_PORT.search(candidate)
    if match is None:
        return None
    value = int(match.group("port"))
    return value if value <= 65535 else None


def _bind_ports(line: str) -> set[int]:
    fields = line.split()
    if len(fields) < 2 or fields[0].lower() != "bind":
        return set()
    ports: set[int] = set()
    for endpoint in fields[1].split(","):
        port = _port(endpoint)
        if port is not None:
            ports.add(port)
    return ports


def _hostnames(line: str) -> set[str]:
    match = _HOST_ACL.search(line)
    if match is None:
        return set()
    values: set[str] = set()
    for hostname in match.group("hosts").split():
        # ACL conditions follow the hostname list.  They are not hostnames and
        # stopping here prevents a malformed line from becoming UI metadata.
        if hostname.lower() in {"if", "unless"}:
            break
        if 0 < len(hostname) <= 253:
            values.add(hostname)
    return values


def _parse(files: Mapping[str, bytes]) -> list[_Proxy]:
    proxies: list[_Proxy] = []
    names: set[str] = set()

    for source, content in _configuration_files(files):
        current: _Proxy | None = None
        for original in content.splitlines():
            line = original.strip()
            if not line or line.startswith("#"):
                continue

            section = _SECTION.match(line)
            if section is not None:
                name = section.group("name")
                if len(name) > 247:
                    raise InventoryError(f"frontend name is too long for inventory: {name!r}")
                if name in names:
                    raise InventoryError(f"published configuration defines frontend {name!r} twice")
                current = _Proxy(name=name, source=source)
                proxies.append(current)
                names.add(name)
                continue

            # A new HAProxy top-level section ends the current frontend/listen.
            # Do not infer this from indentation: HAProxy permits directives
            # without it, and a valid unindented ``bind`` must still be read.
            if _OTHER_SECTION.match(line) is not None:
                current = None
            if current is None:
                continue

            current.bind_ports.update(_bind_ports(line))
            current.hostnames.update(_hostnames(line))
            backend = _BACKEND.match(line)
            if backend is not None:
                current.backends.add(backend.group("name"))
            current.tcp = current.tcp or _MODE_TCP.match(line) is not None
            current.ssl = current.ssl or _SSL.search(line) is not None

    return proxies


def _proxy_document(proxy: _Proxy) -> dict[str, object]:
    if proxy.tcp:
        protocol = "tcp"
    elif proxy.ssl or 443 in proxy.bind_ports:
        protocol = "https"
    else:
        protocol = "http"
    return {
        "id": f"proxy:{proxy.name}",
        "name": proxy.name,
        "managed": proxy.source == "managed",
        "source": proxy.source,
        "protocol": protocol,
        "enabled": True,
        "hostnames": sorted(proxy.hostnames),
        "bind_ports": sorted(proxy.bind_ports),
        "backend_count": len(proxy.backends),
        #
        # The names as well as the count, because a count cannot be looked up.
        # A reader that wants what a pool actually did - its counters on the
        # runtime socket, its rows in a metric table - needs the name HAProxy
        # knows it by, and until now that name existed only inside the stored
        # object. A proxy nobody wrote here has no stored object at all, so
        # everything derived from one silently skipped it.
        #
        "backends": sorted(proxy.backends),
    }


def _reservations(files: Mapping[str, bytes]) -> Reservations:
    """What the published tree says the handwritten half has claimed.

    Read rather than assumed empty. The publishing path reads this same file to
    refuse an object claiming a reserved name or port, and two readers with two
    answers is the drift this project keeps finding: an operator asking the
    inventory what is reserved, right after a publish was refused for claiming
    something reserved, would be told nothing is.

    A file that cannot be read is an `InventoryError` rather than an empty
    answer, for the same reason - the tree cannot be described faithfully, and
    both callers already report that as a failed inventory rather than as an
    inventory saying nothing is reserved.
    """

    try:
        return load_reservations(files.get(RESERVATIONS_PATH, b"{}"))
    except ReservationError as exc:
        raise InventoryError(f"published {RESERVATIONS_PATH} cannot be read: {exc}") from exc


def _reservations_document(reservations: Reservations) -> dict[str, object]:
    #
    # Two lists, where the file has one. `tcp_ports` keeps exactly the meaning
    # it had before an entry could carry an address - a port claimed on every
    # one of them - so a reader written against the v1 contract still gets a
    # true answer, and `tcp_listeners` is added beside it rather than changing
    # what an existing field holds.
    #
    return {
        "hostnames": sorted(reservations.hostnames),
        "tcp_ports": sorted(reservations.tcp_ports),
        "tcp_listeners": [
            f"{address}:{port}" for address, port in sorted(reservations.tcp_listeners)
        ],
    }


def inventory_result(
    files: Mapping[str, bytes],
    target: ReleaseTarget | None,
    *,
    generated_at: datetime | None = None,
) -> dict[str, object]:
    """Return the frozen ``haprion-inventory`` result for one published tree.

    No RELEASE stamp means no configuration has been published yet.  Returning
    a valid empty result makes that state explicit without treating a new
    cluster as a broken one; importantly it still never falls back to the
    repository's working tree.
    """

    timestamp = generated_at or datetime.now(UTC)
    result: dict[str, object] = {
        "version": target.version if target is not None else None,
        "hash": target.hash if target is not None else None,
        "generated_at": timestamp.isoformat().replace("+00:00", "Z"),
        "proxies": [],
        "reservations": _reservations_document(Reservations()),
    }
    if target is not None:
        result["proxies"] = [_proxy_document(proxy) for proxy in _parse(files)]
        result["reservations"] = _reservations_document(_reservations(files))
    return result
