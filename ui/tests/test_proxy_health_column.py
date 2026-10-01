from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any
from unittest import mock

from haproxy_ui.db import ClusterInventory, ClusterObjects, ClusterStatus
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
                    #
                    # What the objects helper reports (B222); the listing no
                    # longer reads the document to find out.
                    #
                    "health_checked": document == CHECKED,
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

    def test_the_column_is_there_and_a_checked_backend_that_is_up_is_green(self) -> None:
        page = self.page(CHECKED, status(("a", "UP"), ("b", "UP")))

        self.assertEqual(page.status_code, 200)
        self.assertIn(">Health</a></th>", page.text)
        self.assertIn("status-dot status-healthy", page.text)
        self.assertIn("2/2 up", page.text)

    def test_a_member_that_is_down_is_amber_and_says_how_many(self) -> None:
        page = self.page(CHECKED, status(("a", "UP"), ("b", "DOWN")))

        self.assertIn("status-dot status-warning", page.text)
        self.assertIn("1/2 up", page.text)

    def test_an_object_with_no_check_is_grey_even_when_the_nodes_report_it_up(self) -> None:
        page = self.page(UNCHECKED, status(("a", "UP")))

        self.assertIn("status-dot status-unknown", page.text)
        self.assertNotIn("No check", page.text)
        #
        # Narrowed to the cell on purpose: the read-only badge in the page
        # heading carries a green dot of its own, and asserting on the class
        # alone would pass whatever the column did.
        #
        self.assertNotIn('status-dot status-healthy" aria-hidden', page.text)
        self.assertIn("This object defines no health check", page.text)

    def test_a_checked_object_nobody_has_reported_on_is_grey(self) -> None:
        page = self.page(CHECKED, None)

        self.assertIn("status-dot status-unknown", page.text)
        self.assertIn("No node reported servers", page.text)


if __name__ == "__main__":
    unittest.main()


class WhatCountsAsServed(LoginTestCase):
    """Served is what the nodes report, not what the release contains.

    The published inventory is the *released* configuration, so an object was
    counted as served the moment it was published while the nodes went on
    serving the release they had. That is the whole stretch the badge exists to
    describe, and it was the one stretch the badge never appeared in.
    """

    def page(self, *, reported: tuple[str, ...] | None) -> Any:
        client = self.client(replace(configuration(), clusters=("alpha",)))
        self.sign_in(client)
        #
        # The release contains it either way: this is a published object that
        # the nodes may or may not have pulled.
        #
        published = ClusterInventory(
            cluster="alpha",
            observed_at=OBSERVED,
            outcome="done",
            result={
                "version": "v9",
                "proxies": [
                    {
                        "name": "mgd-main-http",
                        "protocol": "http",
                        "managed": True,
                        "enabled": True,
                        "hostnames": ["shop.example.com"],
                        "ports": [80],
                        "backend_count": 1,
                    }
                ],
            },
            warnings=[],
            error=None,
            poll_error=None,
        )
        nodes: list[Any] = []
        if reported is not None:
            nodes = [
                {
                    "node": "node-a",
                    "status": {
                        "servers": [
                            {"backend": f"mgd-{name}-web", "server": "s1", "status": "no check"}
                            for name in reported
                        ]
                    },
                }
            ]
        reading = ClusterStatus(
            cluster="alpha",
            observed_at=OBSERVED,
            outcome="done",
            result={"nodes": nodes},
            warnings=[],
            error=None,
            poll_error=None,
        )
        with (
            mock.patch("haproxy_ui.db.cluster_objects", return_value=[objects(CHECKED)]),
            mock.patch("haproxy_ui.db.cluster_inventories", return_value=[published]),
            mock.patch("haproxy_ui.db.cluster_statuses", return_value=[reading]),
        ):
            return client.get("/proxies")

    def test_published_but_not_on_the_nodes_is_inactive(self) -> None:
        #
        # The node answered, and said nothing about this object. That is an
        # answer: it does not have it.
        #
        body = self.page(reported=("something-else",)).text

        self.assertIn("Inactive · deploy to add", body)

    def test_a_node_reporting_it_makes_it_active(self) -> None:
        body = self.page(reported=("shop",)).text

        self.assertNotIn("Inactive · deploy to add", body)

    def test_a_server_nobody_checks_still_says_the_node_has_it(self) -> None:
        #
        # Verified against HAProxy 3.4.4 on this machine: an unchecked server is
        # reported with `no check` where a verdict would be, so an object with
        # no health check is still visibly on the node.
        #
        body = self.page(reported=("shop",)).text

        self.assertNotIn("Inactive · deploy to add", body)
        #
        # And it is not counted as a member that is down.
        #
        self.assertNotIn("0/1 up", body)

    def test_a_cluster_no_node_has_answered_falls_back_to_the_release(self) -> None:
        #
        # Silence is not "nothing is served". The hostname match is the best
        # answer there is, and it says this object is in the release.
        #
        body = self.page(reported=None).text

        self.assertNotIn("Inactive · deploy to add", body)
