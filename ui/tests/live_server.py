"""The interface served on a port for a browser test, without a race for the port.

Picking a free port and binding it later left a window another test process
could bind it in: `[Errno 98] address already in use` and "the test server did
not start" under the gate's eight processes (26-11-07, certificate page). The
socket is bound here, on a port the kernel chooses, and handed to uvicorn bound.
"""

from __future__ import annotations

import socket
import threading
import unittest
from typing import Any

import uvicorn


def serve(test: unittest.TestCase, app: Any) -> int:
    """Start `app` for the length of `test`; the port, once the server answers."""

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    test.addCleanup(listener.close)
    listener.bind(("127.0.0.1", 0))
    server = uvicorn.Server(uvicorn.Config(app, log_level="warning"))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
    thread.start()
    test.addCleanup(thread.join, 5)
    test.addCleanup(setattr, server, "should_exit", True)
    for _ in range(200):
        if server.started:
            break
        threading.Event().wait(0.05)
    else:
        test.fail("the test server did not start")
    port: int = listener.getsockname()[1]
    return port
