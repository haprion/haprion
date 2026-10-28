"""Every page goes through the feature switches, wherever its module is (K1, 26-10-21)."""

from __future__ import annotations

import unittest
from typing import Any

from haprion_ui.access import hidden_by_a_switch
from haprion_ui.app import create_app
from tests.test_login import configuration

#
# Outside the pages: what a probe, the browser's assets and the framework ask.
#
UNGUARDED = {"/healthz", "/static"}


def routes(found: list[Any], guarded: bool, out: list[tuple[str, bool]]) -> None:
    for route in found:
        inner = getattr(route, "original_router", None)
        if inner is not None:
            through = [*(getattr(route, "dependencies", None) or ()), *inner.dependencies]
            routes(
                inner.routes,
                guarded or any(d.dependency is hidden_by_a_switch for d in through),
                out,
            )
            continue
        own = any(d.dependency is hidden_by_a_switch for d in getattr(route, "dependencies", ()))
        out.append((str(getattr(route, "path", "")), guarded or own))


class EveryPageIsBehindTheSwitches(unittest.TestCase):
    def test_no_page_skips_hidden_by_a_switch(self) -> None:
        found: list[tuple[str, bool]] = []
        routes(create_app(configuration()).routes, False, found)
        pages = [(path, guarded) for path, guarded in found if path not in UNGUARDED]
        self.assertGreater(len(pages), 100)
        self.assertEqual([path for path, guarded in pages if not guarded], [])


if __name__ == "__main__":
    unittest.main()
