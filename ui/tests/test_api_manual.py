"""The manual's API section names calls that exist (B416): its examples are read here, not trusted.

A documented path that no route answers is a user's first call failing, and
nothing else would notice when a route is renamed.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path
from typing import Any

from starlette.routing import Match

from haprion_ui.api import PREFIX, build_api
from tests.test_login import configuration
from tests.test_route_roles import routes

ROOT = Path(__file__).resolve().parents[2]
API_SOURCE = ROOT / "ui/src/haprion_ui/api"


def section() -> str:
    text = (ROOT / "docs/user-manual.md").read_text()
    found = re.search(r"^## The API\n(.*?)^## ", text, re.MULTILINE | re.DOTALL)
    if found is None:
        raise AssertionError("the manual has no '## The API' section")
    return found.group(1)


def answered(path: str, api_routes: list[Any]) -> bool:
    scope = {"type": "http", "path": path, "method": "GET"}
    return any(route.matches(scope)[0] is Match.FULL for route in api_routes)


class TheManualNamesRealCalls(unittest.TestCase):
    def setUp(self) -> None:
        self.routes = routes(build_api(configuration()).routes, [])
        self.text = section()

    def test_every_example_calls_a_route_that_exists(self) -> None:
        urls = re.findall(r"https://mgr\.example\.com(/api/v1/[^\s'\"\\]*)", self.text)
        self.assertGreaterEqual(len(urls), 4)
        for url in urls:
            with self.subTest(url=url):
                self.assertTrue(answered(url.removeprefix(PREFIX), self.routes), url)

    def test_every_path_in_the_table_is_a_route(self) -> None:
        rows = re.findall(r"^\| `(/[^|]*?)` .*\|$", self.text, re.MULTILINE)
        paths = [
            path
            for row in rows
            for path in re.findall(r"`?(/[^`,]+)`?", row.replace("…", "/clusters/{cluster}"))
        ]
        self.assertGreaterEqual(len(paths), 12)
        listed = {route.path for route in self.routes}
        for path in paths:
            with self.subTest(path=path):
                self.assertIn(path.strip(), listed)

    def test_every_error_code_in_the_table_is_one_the_api_answers(self) -> None:
        codes = re.findall(r"^\| \d{3} \| `([a-z_]+)` \|", self.text, re.MULTILINE)
        self.assertGreaterEqual(len(codes), 6)
        source = "\n".join(path.read_text() for path in API_SOURCE.glob("*.py"))
        for code in codes:
            with self.subTest(code=code):
                self.assertIn(f'"{code}"', source)


if __name__ == "__main__":
    unittest.main()
