from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any
from unittest import mock

from haproxy_ui.db import ClusterObjects, ClusterStatus
from tests.test_login import LoginTestCase, configuration

OBSERVED = datetime(2026, 9, 3, 9, 0, tzinfo=UTC)

CHECKED = """schema: 1
name: shop
hostnames:
- shop.example.com
listen:
  protocol: http
routes:
- path: /
  backend: web
backends:
  web:
    health:
      type: http
      path: /
    servers:
    - host: 192.0.2.10
      port: 8080
"""

UNCHECKED = CHECKED.replace("    health:\n      type: http\n      path: /\n", "")


def objects(document: str) -> ClusterObjects:
    return ClusterObjects(
        cluster="alpha",
        observed_at=OBSERVED,
        outcome="done",
        result={
            "commit": "a" * 40,
            "objects": [
                {
                    "name": "shop",
                    "document": document,
                    "readable": True,
                    "protocol": "http",
                    "hostnames": ["shop.example.com"],
                }
            ],
        },
        warnings=[],
        error=None,
        poll_error=None,
    )


def status(*members: tuple[str, str]) -> ClusterStatus:
    return ClusterStatus(
        cluster="alpha",
        observed_at=OBSERVED,
        outcome="done",
        result={
            "nodes": [
                {
                    "node": "node1",
                    "status": {
                        "servers": [
                            {"backend": "mgd-shop-web", "server": server, "status": state}
                            for server, state in members
                        ]
                    },
                }
            ]
        },
        warnings=[],
        error=None,
        poll_error=None,
    )


class TheHealthColumn(LoginTestCase):
    """What the listing says about an object's servers, without probing.

    The column reads the poller's newest status reading. A probe would be an
    SSH operation per row on every page load; this is the verdict the nodes
    already reached, and it is the same reading the dashboard draws.
    """

    def page(self, document: str, reading: ClusterStatus | None) -> Any:
        client = self.client(replace(configuration(), clusters=("alpha",)))
        self.sign_in(client)
        with (
            mock.patch("haproxy_ui.db.cluster_objects", return_value=[objects(document)]),
            mock.patch(
                "haproxy_ui.db.cluster_statuses", return_value=[] if reading is None else [reading]
            ),
        ):
            return client.get("/proxies")

    def test_the_column_is_there_and_a_checked_pool_that_is_up_is_green(self) -> None:
        page = self.page(CHECKED, status(("a", "UP"), ("b", "UP")))

        self.assertEqual(page.status_code, 200)
        self.assertIn("<th>Health</th>", page.text)
        self.assertIn("status-dot status-healthy", page.text)
        self.assertIn("2/2 up", page.text)

    def test_a_member_that_is_down_is_amber_and_says_how_many(self) -> None:
        page = self.page(CHECKED, status(("a", "UP"), ("b", "DOWN")))

        self.assertIn("status-dot status-warning", page.text)
        self.assertIn("1/2 up", page.text)

    def test_an_object_with_no_check_is_unlit_even_when_the_nodes_report_it_up(self) -> None:
        page = self.page(UNCHECKED, status(("a", "UP")))

        self.assertIn("status-dot status-off", page.text)
        self.assertIn("No check", page.text)
        #
        # Narrowed to the cell on purpose: the read-only badge in the page
        # heading carries a green dot of its own, and asserting on the class
        # alone would pass whatever the column did.
        #
        self.assertNotIn('class="pool-health" title="Every member is up', page.text)

    def test_a_checked_object_nobody_has_reported_on_is_grey(self) -> None:
        page = self.page(CHECKED, None)

        self.assertIn("status-dot status-unknown", page.text)
        self.assertIn("Not reported", page.text)


if __name__ == "__main__":
    unittest.main()
