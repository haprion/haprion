"""Where a page's time goes (`timing`): header, log line, and what is counted."""

from __future__ import annotations

import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context

from fastapi import FastAPI
from fastapi.responses import PlainTextResponse
from fastapi.testclient import TestClient

from haproxy_ui import timing


def application() -> FastAPI:
    app = FastAPI()

    @app.get("/page")
    def page() -> PlainTextResponse:
        current = timing.current()
        if current is None:
            raise AssertionError("no timing in a request")
        current.add_query(0.020)
        current.add_query(0.010)
        timing.rendered(lambda: time.sleep(0.005))
        return PlainTextResponse("ok")

    @app.get("/static/app.css")
    def asset() -> PlainTextResponse:
        return PlainTextResponse("", status_code=200)

    app.add_middleware(timing.TimingMiddleware)
    return app


class EveryResponseSaysWhereItsTimeWent(unittest.TestCase):
    def test_header_and_log_line(self) -> None:
        with self.assertLogs("haproxy_ui.timing", "INFO") as logged:
            response = TestClient(application()).get("/page?q=secret")
        header = response.headers["server-timing"]
        self.assertIn('db;dur=30.0;desc="2 queries"', header)
        self.assertRegex(header, r"render;dur=\d+\.\d")
        self.assertRegex(header, r"total;dur=\d+\.\d")
        [line] = logged.output
        self.assertRegex(line, r"timing GET /page 200 total=\d+ms db=30ms/2 render=\d+ms")
        # What was searched for is not a timing.
        self.assertNotIn("secret", line)

    def test_assets_are_left_alone(self) -> None:
        with self.assertNoLogs("haproxy_ui.timing", "INFO"):
            response = TestClient(application()).get("/static/app.css")
        self.assertNotIn("server-timing", response.headers)

    def test_outside_a_request_nothing_is_counted(self) -> None:
        self.assertIsNone(timing.current())
        self.assertEqual(timing.rendered(lambda: 7), 7)


class AReadInAnotherThreadCountsWithItsPage(unittest.TestCase):
    def test_a_copied_context_adds_to_the_same_request(self) -> None:
        def run() -> None:
            current = timing.current()
            if current is None:
                raise AssertionError("the thread lost the request's timing")
            current.add_query(0.001)

        measured = timing.Timing()
        token = timing._CURRENT.set(measured)
        try:
            context = copy_context()
            with ThreadPoolExecutor(max_workers=2) as threads:
                list(threads.map(lambda _: context.copy().run(run), range(4)))
        finally:
            timing._CURRENT.reset(token)
        self.assertEqual(measured.queries, 4)
