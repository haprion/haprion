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

import queue
import socket
import threading
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
# not resolve is: the node's own check before it switches stays the gate.
#
# The names are asked several at a time: a name the cache does not hold took
# 11.5 ms (median of 40 on a manager, 26-11-06), so one at a time a first import
# of a few thousand names would have spent the ten seconds with the resolver
# working. The askers are daemon threads, so a lookup still waiting when the
# time is up holds neither the lock nor the helper's exit.
#
LOOKUP_SECONDS = 10.0
LOOKUP_THREADS = 16


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
    threads: int = LOOKUP_THREADS,
) -> Lookups:
    """The servers' names by this host's resolver, in the order they appear, within `seconds`."""

    ask = resolve or resolves
    every = names(proxies)
    until = clock() + (LOOKUP_SECONDS if seconds is None else seconds)
    waiting: queue.SimpleQueue[str] = queue.SimpleQueue()
    for name in every:
        waiting.put(name)
    answered: dict[str, bool] = {}
    changed = threading.Condition()

    def asker() -> None:
        try:
            while clock() <= until:
                try:
                    name = waiting.get_nowait()
                except queue.Empty:
                    return
                try:
                    found = ask(name)
                except Exception:  # noqa: BLE001 - any failure of the resolver is a name it did not resolve
                    #
                    # A resolver that fails is a name it did not resolve, not
                    # a name the time ran out before.
                    #
                    found = False
                with changed:
                    answered[name] = found
                    changed.notify_all()
        finally:
            with changed:
                changed.notify_all()

    askers = [threading.Thread(target=asker, daemon=True) for _ in range(min(threads, len(every)))]
    for thread in askers:
        thread.start()
    with changed:
        while len(answered) < len(every) and any(thread.is_alive() for thread in askers):
            left = until - clock()
            if left <= 0:
                break
            changed.wait(min(left, 0.5))
        seen = dict(answered)
    return Lookups(
        [name for name in every if name in seen and not seen[name]],
        [name for name in every if name not in seen],
    )


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


#
# Sentences said one by one before the rest is counted: a resolver that knows
# none of a large import's names would otherwise bury every other warning.
#
SAID_ONE_BY_ONE = 5


def warnings(unresolved: Sequence[str]) -> list[str]:
    """`warning` for the first few names, then one sentence for all the others."""

    said = [warning(name) for name in unresolved[:SAID_ONE_BY_ONE]]
    rest = unresolved[SAID_ONE_BY_ONE:]
    if rest:
        shown = ", ".join(rest[:SAID_ONE_BY_ONE]) + (", ..." if len(rest) > SAID_ONE_BY_ONE else "")
        said.append(
            f"{labels.counted(len(rest), 'more server name is', 'more server names are')} "
            f"not in DNS as the manager sees it ({shown}). "
            "If the nodes cannot find them either, the deploy stops"
        )
    return said
