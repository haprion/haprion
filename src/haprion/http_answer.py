"""Reading an HTTP answer the way the engine's clients all do.

The OIDC client and the NDES fetch ask a server outside the manager. Two rules
hold for both, and live here once:

- A redirect is an answer, not an instruction: it is refused, not followed.
- A broken answer is no answer. A status line that is not one, or a body cut
  short, is an `http.client.HTTPException`, not an `OSError` (review
  2026-10-29, C01), and a bounded read returns what came before the
  connection closed as if it were all - so the body is read to its end.
"""

from __future__ import annotations

import http.client
import time
import urllib.request
from typing import Any

#
# What a request or a read raises when the server did not answer whole.
#
BROKEN = (OSError, http.client.HTTPException)
CHUNK = 16 * 1024


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect is an answer, not an instruction: it is refused, not followed."""

    def redirect_request(self, *_: Any, **__: Any) -> None:
        return None


def read_body(stream: Any, limit: int, *, deadline: float | None = None) -> bytes:
    """The body to its end, or `limit + 1` bytes when it is longer.

    `http.client.IncompleteRead` when the connection closed before the length
    the answer gave. With a `deadline` (`time.monotonic()`), `TimeoutError`
    once it has passed: a socket's timeout bounds one read, and a server that
    sends a byte at a time never lets one run out. Each read is then at most
    one from the socket (`read1`), so the deadline is looked at between them.
    """

    chunks: list[bytes] = []
    size = 0
    read = stream.read if deadline is None else stream.read1
    while size <= limit:
        if deadline is not None and time.monotonic() > deadline:
            raise TimeoutError("the answer took longer than it may")
        chunk: bytes = read(min(CHUNK, limit + 1 - size))
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
    remaining = getattr(stream, "length", None)
    if size <= limit and isinstance(remaining, int) and remaining > 0:
        raise http.client.IncompleteRead(b"".join(chunks), remaining)
    return b"".join(chunks)


def said(error: BaseException) -> str:
    """An exception's own words, or its name when it has none."""

    return str(error) or type(error).__name__
