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

import socket
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass

from haprion import address_ranges, labels
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
        address_ranges.plain_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def names(proxies: Iterable[Proxy]) -> list[str]:
    """Every server written as a name, once each, in the order they appear."""

    #
    # A dict keeps the order and finds a name again at once; a list's `in` made
    # this quadratic in the servers of a publish (B483).
    #
    found: dict[str, None] = {}
    for proxy in proxies:
        for backend in proxy.backends.values():
            for server in backend.servers:
                if server.address is not None or _is_address(server.host):
                    continue
                found.setdefault(server.host)
    return list(found)


#
# How long one publish spends looking names up, all of them together. It runs
# under the cluster's lock, and a resolver that does not answer costs its own
# timeout per name - seconds each - however large the publish (B483). The
# system's cache (systemd-resolved on Ubuntu) keeps no failed answer, so it
# does not help there. A name not reached in time is said, as a name that does
# not resolve is: the node's own check before it switches stays the gate. One
# lookup already under way is not cut, so the time can run over by one
# resolver timeout.
#
LOOKUP_SECONDS = 10.0


@dataclass(frozen=True)
class Lookups:
    """The names that did not resolve, and those the time ran out before."""

    unresolved: list[str]
    unasked: list[str]


def lookups(
    proxies: Iterable[Proxy],
    resolve: Resolves | None = None,
    *,
    seconds: float | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> Lookups:
    """The servers' names by this host's resolver, in the order they appear, within `seconds`."""

    ask = resolve or resolves
    every = names(proxies)
    until = clock() + (LOOKUP_SECONDS if seconds is None else seconds)
    unresolved: list[str] = []
    for index, name in enumerate(every):
        if clock() > until:
            return Lookups(unresolved, every[index:])
        if not ask(name):
            unresolved.append(name)
    return Lookups(unresolved, [])


def unresolved(proxies: Iterable[Proxy], resolve: Resolves | None = None) -> list[str]:
    """The servers' names that do not resolve, in the order they appear; by this host's resolver."""

    return lookups(proxies, resolve, seconds=float("inf")).unresolved


def unasked_warning(unasked: Sequence[str]) -> str:
    """What is said about names not looked up in time: one sentence for all of them."""

    shown = ", ".join(unasked[:5]) + (", ..." if len(unasked) > 5 else "")
    return (
        f"{labels.counted(len(unasked), 'server name was', 'server names were')} not looked up "
        f"({shown}): the manager's resolver took more than {LOOKUP_SECONDS:.0f} s. "
        "If the nodes cannot find one, the deploy stops"
    )


def warning(name: str) -> str:
    """What is said about one: the same sentence in the editor, the job and the terminal."""

    return (
        f"{name} is not in DNS as the manager sees it. If the nodes cannot find it either, "
        "the deploy stops"
    )
