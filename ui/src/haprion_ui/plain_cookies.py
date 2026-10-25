"""The sign-in cookies' plain names, for an instance without Secure (review 26-10-24, 09-06).

The session cookie and the login form's cookie carry the `__Host-` prefix: a
browser then takes them only with Secure, Path=/ and no Domain, so a sibling
domain cannot plant one beside them - it could, before, set a login cookie of
its own with `Domain=<parent>` and post a sign-in into an account it holds.

A browser refuses a `__Host-` cookie without Secure, and `cookie_secure = false`
exists so that an instance on plain HTTP is usable at all. There, and only
there, this middleware gives the two cookies their plain names on the wire and
the prefixed names inside, so every reader and writer in the application uses
one name whatever the setting.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any

from haprion_ui import auth

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
App = Callable[[Scope, Receive, Send], Awaitable[None]]

PREFIX = "__Host-"
RENAMED = tuple(
    name.removeprefix(PREFIX) for name in (auth.SESSION_COOKIE, auth.PRE_SESSION_COOKIE)
)


def inward(header: str) -> str:
    """A request's Cookie header with the plain names given their prefix."""

    pairs = []
    for pair in header.split(";"):
        name, separator, value = pair.strip().partition("=")
        if name.startswith(PREFIX) and name.removeprefix(PREFIX) in RENAMED:
            continue
        pairs.append(f"{PREFIX}{name}{separator}{value}" if name in RENAMED else pair.strip())
    return "; ".join(pair for pair in pairs if pair)


def outward(header: str) -> str:
    """A Set-Cookie header with a prefixed name given its plain one."""

    for name in RENAMED:
        if header.startswith(f"{PREFIX}{name}="):
            return header.removeprefix(PREFIX)
    return header


class PlainCookieNames:
    def __init__(self, app: App) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        scope = dict(scope)
        scope["headers"] = [
            (key, inward(value.decode("latin-1")).encode("latin-1") if key == b"cookie" else value)
            for key, value in scope["headers"]
        ]

        async def sending(message: Message) -> None:
            if message["type"] == "http.response.start":
                message = dict(message)
                message["headers"] = [
                    (
                        key,
                        outward(value.decode("latin-1")).encode("latin-1")
                        if key == b"set-cookie"
                        else value,
                    )
                    for key, value in message["headers"]
                ]
            await send(message)

        await self.app(scope, receive, sending)
