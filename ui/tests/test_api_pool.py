"""A read holds one pool connection at a time (review 26-11-01, c-P2-2).

The pool has six, and three API calls may run at once so that the pages keep
theirs. A route that takes a second connection while it holds one makes that
promise empty: three calls each holding one and waiting for another use all
six, and nothing moves until the pool's own timeout.
"""

from __future__ import annotations

import tempfile
import traceback
import unittest
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from typing import Any
from unittest import mock

from haprion_ui.config import TrafficLogs
from haprion_ui.traffic_logs import Reading
from tests.test_api_clusters_objects import ReadingTestCase
from tests.test_editor_page import EditorTestCase
from tests.test_login import configuration
from tests.test_waf_page import CATALOG, LOGGING, finding, objects


def forbid_nesting(case: Any) -> list[str]:
    """Make the test's pool refuse a connection asked for while one is held.

    Returns the list that fills with where each refused request was made from.
    A route that nests then answers 500 and the list names the line.
    """

    pool = case.pool
    held = {"depth": 0}
    nested: list[str] = []

    @contextmanager
    def connection() -> Any:
        if held["depth"]:
            frames = [
                f"{Path(frame.filename).name}:{frame.lineno}"
                for frame in traceback.extract_stack()
                if "haprion_ui/" in frame.filename and "tests" not in frame.filename
            ]
            nested.append(" > ".join(frames[-3:]))
            raise AssertionError("a connection was asked for while one is held")
        held["depth"] += 1
        try:
            yield pool
        except Exception:
            pool.rollback()
            raise
        finally:
            held["depth"] -= 1

    pool.connection = connection
    return nested


def with_traffic_log(case: Any) -> None:
    """Make the test's clients read a configuration with the traffic log on, which is where the reads nest."""

    directory = tempfile.TemporaryDirectory()
    case.addCleanup(directory.cleanup)
    log = TrafficLogs(enabled=True, directory=Path(directory.name), max_lines=500)
    original = case.client

    def client(config: Any = None) -> Any:
        return original(replace(config or configuration(), traffic_logs=log))

    case.client = client


class TheDashboardReads(ReadingTestCase):
    """`/clusters`, `/clusters/{c}` and `/attention` with nothing about them replaced."""

    def setUp(self) -> None:
        super().setUp()
        for target, value in (
            ("haprion_ui.db.waf_findings", []),
            ("haprion_ui.db.deploys_carrying", {}),
            ("haprion_ui.waf_work.settled_drafts", []),
        ):
            patch = mock.patch(target, return_value=value)
            patch.start()
            self.addCleanup(patch.stop)

    def test_none_takes_a_second_connection_while_it_holds_one(self) -> None:
        nested = forbid_nesting(self)
        with_traffic_log(self)
        client = self.client(replace(configuration(), clusters=("alpha", "beta")))
        headers = {"Authorization": f"Bearer {self.issue()}"}
        for path in ("/clusters", "/clusters/alpha", "/attention"):
            with self.subTest(path=path):
                response = client.get("/api/v1" + path, headers=headers)
                self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(nested, [])


class ThePagesToo(EditorTestCase):
    """The pages read through the same functions, and held two connections the same way."""

    def setUp(self) -> None:
        super().setUp()
        for target, value in (
            ("haprion_ui.db.waf_findings", [finding()]),
            ("haprion_ui.db.waf_verdicts", {("alpha", "shop"): (14, 3)}),
            ("haprion_ui.db.waf_request_count", 1297),
            ("haprion_ui.db.waf_counted", {}),
            ("haprion_ui.db.cluster_objects", objects(LOGGING)),
            ("haprion.crs.installed_catalog", CATALOG),
            ("haprion_ui.traffic_logs.read_database", Reading((), (), 0, False)),
        ):
            patch = mock.patch(target, return_value=value)
            patch.start()
            self.addCleanup(patch.stop)

    def test_none_takes_a_second_connection_while_it_holds_one(self) -> None:
        nested = forbid_nesting(self)
        with_traffic_log(self)
        client = self.editor()
        for path in ("/", "/logs", "/waf", "/waf?view=exceptions", "/clusters/busy"):
            with self.subTest(path=path):
                response = client.get(path)
                self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertEqual(nested, [])


if __name__ == "__main__":
    unittest.main()
