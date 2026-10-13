"""A request waiting on the database holds up nobody else's (review 26-10-13, K1).

The handlers read the database with the synchronous pool. Written `async def`,
one waiting for a connection or a lock waited on the event loop itself, and
every other request - another tab's refresh, a sign-in - waited with it.
"""

from __future__ import annotations

import ast
import asyncio
import time
import unittest
from dataclasses import replace
from typing import Any
from unittest import mock

import httpx

from haprion_ui import auth, views
from tests.test_login import LoginTestCase, configuration

#
# The one coroutine the router keeps: reading a form, which the handlers ask
# the loop for from their thread.
#
ALLOWED = {"_read_form"}


class NoHandlerWaitsOnTheLoop(unittest.TestCase):
    def test_the_router_has_no_coroutine_but_the_form_reader(self) -> None:
        source = views.__file__
        with open(source, encoding="utf-8") as file:
            tree = ast.parse(file.read())
        found = {node.name for node in ast.walk(tree) if isinstance(node, ast.AsyncFunctionDef)}
        self.assertEqual(found - ALLOWED, set())


class ASlowWrite(LoginTestCase):
    def test_does_not_stop_the_event_loop(self) -> None:
        client = self.client(replace(configuration(), management_writes=True))
        self.sign_in(client)
        cookies = dict(client.cookies)
        token = auth.csrf_token(client.cookies[auth.SESSION_COOKIE])

        def slow(*_args: Any, **_kwargs: Any) -> None:
            time.sleep(0.3)

        async def run() -> tuple[httpx.Response, float]:
            loop = asyncio.get_running_loop()
            gaps: list[float] = []
            stop = asyncio.Event()

            async def heartbeat() -> None:
                last = loop.time()
                while not stop.is_set():
                    await asyncio.sleep(0.01)
                    now = loop.time()
                    gaps.append(now - last)
                    last = now

            transport = httpx.ASGITransport(app=client.app)
            async with httpx.AsyncClient(
                transport=transport, base_url="https://manager.example.com", cookies=cookies
            ) as http:
                beat = asyncio.create_task(heartbeat())
                answer = await http.post(
                    "/settings/status-access",
                    data={"csrf_token": token, "networks": "192.0.2.10\n"},
                )
                stop.set()
                await beat
            return answer, max(gaps)

        with mock.patch("haprion_ui.db.set_status_access", side_effect=slow):
            answer, worst = asyncio.run(run())

        self.assertEqual(answer.status_code, 303)
        self.assertLess(worst, 0.15, "the loop stood still while the write waited")


if __name__ == "__main__":
    unittest.main()
