"""Which route one request path takes on a stored object, and what its server is given.

The question *Test a path* answers on an object's page and
`haprion-objects --path` answers in the terminal (B496, 7): one function, so
the two cannot say different things about the same object.

The answer comes from `route_match`, the reference model the generator writes
its file order from and that `test_generate_behaviour` holds against a running
HAProxy. It explains path routing and nothing else. A rule, the WAF, the
servers' health and the balancing can still change what a real request meets,
and the answer never names a server, since the balancing chooses one.

Two things on the object itself can change the answer for every path, and the
answer says so rather than ignore them: the maintenance page, which answers
before routing, and advanced config that rewrites or answers a request in the
pool.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from haprion import advanced as advanced_config
from haprion.proxy_model import ModelError, Route, advanced_placement, load_proxy
from haprion.route_match import order_routes, rewrite, select

#
# A request target as a browser sends it: a path, perhaps a query. Bounded so
# the field cannot carry a page of text into a sentence on the page.
#
LONGEST_TARGET = 2048

#
# `http-request` actions in a pool that change what the server is given, or
# answer instead of it. A pool's advanced config holding one of these may make
# the routed answer untrue for some paths, and the answer says so (B496, 7).
#
PATH_ACTIONS = frozenset(
    {
        "set-path",
        "set-pathq",
        "replace-path",
        "replace-pathq",
        "set-uri",
        "replace-uri",
        "set-query",
        "redirect",
        "return",
        "deny",
        "tarpit",
        "reject",
        "silent-drop",
    }
)

MAINTENANCE_NOTE = "the maintenance page answers every path while it is on"
ADVANCED_NOTE = "advanced config may answer or rewrite this path"


class PathRefused(ValueError):
    """The question cannot be asked of this object or with this path; the text says why."""


@dataclass(frozen=True, slots=True)
class PathAnswer:
    """What one path meets. `route` None is a path no route claims."""

    target: str
    route: Route | None
    sent: str | None
    """What the server is given; None where nothing is forwarded."""

    notes: tuple[str, ...] = ()

    @property
    def sentence(self) -> str:
        """The answer in one line, as the page and the terminal both say it."""

        route = self.route
        if route is None:
            return "No route matches: the request reaches no pool"
        if route.redirect is not None:
            return f"Redirect {route.redirect.status} to {route.redirect.location}"
        exact = " (exact)" if route.match == "exact" else ""
        return f"Route {route.path}{exact} · pool {route.backend} · the server gets {self.sent}"


def checked_target(target: str) -> str:
    """The path as asked, or `PathRefused` with what is wrong with it."""

    if not target.startswith("/"):
        raise PathRefused("A path starts with /, such as /api/users?limit=10")
    if len(target) > LONGEST_TARGET:
        raise PathRefused(f"A path is at most {LONGEST_TARGET} characters")
    if any(
        character.isspace() or ord(character) < 0x20 or ord(character) == 0x7F
        for character in target
    ):
        raise PathRefused("A path has no spaces or control characters; write a space as %20")
    if "#" in target:
        raise PathRefused("A browser does not send what follows #; leave it out")
    return target


def answer(name: str, document: str, target: str) -> PathAnswer:
    """Which route `target` takes on the object stored as `document`.

    `PathRefused` when the path is not one a client sends, the object is not
    an http or https proxy, or the document cannot be read as a proxy.
    """

    asked = checked_target(target)
    try:
        proxy = load_proxy(name, document.encode())
    except ModelError as exc:
        raise PathRefused(f"{name} cannot be read: {exc}") from exc
    if proxy.listen.protocol not in ("http", "https"):
        raise PathRefused("Only an http or https proxy routes by path")

    route = select(order_routes(proxy.routes), asked)
    sent = rewrite(route, asked) if route is not None and route.redirect is None else None
    notes: list[str] = []
    if proxy.maintenance is not None:
        notes.append(MAINTENANCE_NOTE)
    if _advanced_touches_the_path(name, document):
        notes.append(ADVANCED_NOTE)
    return PathAnswer(target=asked, route=route, sent=sent, notes=tuple(notes))


def _advanced_touches_the_path(name: str, document: str) -> bool:
    try:
        placement = advanced_placement(name, document.encode())
    except ModelError:
        return False
    if placement is None:
        return False
    return any(_rewrites(line) for line in placement.backend if line.fate == "placed")


def _rewrites(line: advanced_config.Line) -> bool:
    words: Sequence[str] = advanced_config.words(line.text)
    return len(words) >= 2 and words[0] == "http-request" and words[1] in PATH_ACTIONS
