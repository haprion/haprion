"""Server names the management host cannot resolve (Fas 18 finding 72, 26-10-17).

A pool member written as a name is resolved by HAProxy on each node when it
starts, and a name no node resolves stops the deploy on the first node: the
manager validates with `-dr`, which leaves names unresolved, because the
manager's resolver is not the nodes'. So a typo in a server name was found by
the deploy, on a node, long after it was typed.

This says it where it is typed and where it is published, as a warning and
never a refusal: the nodes may resolve names the manager does not, and the
node's own check before it switches stays the gate. The editor asks through
the resolve service (`resolve_socket`), the publish with the resolver of the
host it runs on - the same answer, from the same resolver.

A dns pool's names are not here: they are looked up when the object is saved
and the address is stored beside the name (B261), and an address is written.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable, Iterable

from haprion.proxy_model import Proxy

#
# Whether one name resolves to any address at all, by some resolver. Several
# addresses are fine here: HAProxy takes one, as the operating system orders
# them, which is a dns pool's problem and not a pool member's.
#
type Resolves = Callable[[str], bool]


def first_address(host: str) -> str | None:
    """One address the name gives by the resolver of this host, or None when it gives none."""

    try:
        found = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError):
        return None
    addresses = sorted({str(entry[4][0]) for entry in found})
    return addresses[0] if addresses else None


def resolves(host: str) -> bool:
    """By the resolver of this host."""

    return first_address(host) is not None


def _is_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def names(proxies: Iterable[Proxy]) -> list[str]:
    """Every server written as a name, once each, in the order they appear."""

    found: list[str] = []
    for proxy in proxies:
        for backend in proxy.backends.values():
            for server in backend.servers:
                if server.address is not None or _is_address(server.host):
                    continue
                if server.host not in found:
                    found.append(server.host)
    return found


def unresolved(proxies: Iterable[Proxy], resolve: Resolves | None = None) -> list[str]:
    """The servers' names that do not resolve, in the order they appear; by this host's resolver."""

    ask = resolve or resolves
    return [name for name in names(proxies) if not ask(name)]


def warning(name: str) -> str:
    """What is said about one: the same sentence in the editor, the job and the terminal."""

    return (
        f"{name} cannot be resolved from the manager; a node that cannot resolve it either "
        "stops the deploy"
    )
