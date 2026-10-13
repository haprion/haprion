"""The headers every answer of this interface carries, set in one place.

Cache: every page is drawn for one signed-in person and shows nodes,
addresses, logs and diagnostics. Which of them a browser or a proxy kept was
left to each route, and only three said (review 26-10-13, S1). So `no-store`
on everything but the static assets, which carry nothing of anyone's.

Content-Security-Policy: every script and stylesheet is a file of this
interface, so the browser is told to run nothing else - no inline script, no
inline style, no plugin, no other origin, and no framing (review 26-10-13,
S2). What the markup once did inline it now asks for by attribute
(`static/page.js`). `form-action` is left out on purpose: signing out posts a
form whose answer redirects to the identity provider's end-session page, and
the browser holds that redirect to `form-action` as well.

A route that sets either header itself keeps its own. Pure ASGI rather than
`BaseHTTPMiddleware`, as `timing`, so a streamed export is passed on as it
comes.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

CACHED_PREFIXES = ("/static/",)
NO_STORE = (b"cache-control", b"no-store")
CONTENT_POLICY = (
    b"content-security-policy",
    b"default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
)


class PageHeadersMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        wanted = [CONTENT_POLICY]
        if not str(scope.get("path", "")).startswith(CACHED_PREFIXES):
            wanted.append(NO_STORE)

        async def stamped(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                present = {name.lower() for name, _ in headers}
                headers.extend(header for header in wanted if header[0] not in present)
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, stamped)
