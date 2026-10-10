"""Servers in drain or maintenance on the dashboard (26-10-10).

A server counts once however many nodes hold it, under the object that owns its
backend; the line names three objects and says how many more, linked to each
object's *Servers* card for an admin and as a bare count for a reader.
"""

from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any
from unittest import mock

from haprion_ui import demo, held_servers, views
from haprion_ui.db import ClusterStatus
from tests.test_login import configuration
from tests.test_object_page import DraftReading

OBSERVED = datetime(2026, 10, 10, 12, 0, tzinfo=UTC)


def server(
    backend: str, name: str, *, status: str = "UP", admin: str | None = "ready"
) -> dict[str, Any]:
    row: dict[str, Any] = {"backend": backend, "server": name, "status": status}
    if admin is not None:
        row["admin"] = admin
    return row


def reading(*nodes: list[dict[str, Any]], cluster: str = "alpha") -> ClusterStatus:
    return ClusterStatus(
        cluster=cluster,
        observed_at=OBSERVED,
        outcome="done",
        result={
            "nodes": [
                {"name": f"node-{index}", "status": {"servers": servers}}
                for index, servers in enumerate(nodes)
            ]
        },
        warnings=[],
        error=None,
        poll_error=None,
    )


class TheCount(unittest.TestCase):
    def test_a_server_held_on_both_nodes_counts_once(self) -> None:
        held = held_servers.held_backends(
            [
                reading(
                    [server("web", "s1", admin="drain"), server("web", "s2")],
                    [server("web", "s1", admin="drain"), server("web", "s2", admin="maint")],
                )
            ],
            cluster="alpha",
        )

        self.assertEqual({"web": {"s1", "s2"}}, held)

    def test_a_failed_check_is_not_somebodys_choice(self) -> None:
        held = held_servers.held_backends(
            [
                reading(
                    [
                        server("web", "s1", status="DOWN"),
                        server("web", "s2", status="MAINT (resolution)", admin=None),
                    ]
                )
            ],
            cluster="alpha",
        )

        self.assertEqual({}, held)

    def test_an_older_node_is_read_from_the_status_column(self) -> None:
        held = held_servers.held_backends(
            [reading([server("web", "s1", status="DRAIN", admin=None)])], cluster="alpha"
        )

        self.assertEqual({"web": {"s1"}}, held)

    def test_another_clusters_reading_is_not_counted(self) -> None:
        held = held_servers.held_backends(
            [reading([server("web", "s1", admin="drain")], cluster="beta")], cluster="alpha"
        )

        self.assertEqual({}, held)

    def test_the_servers_are_counted_under_the_object_owning_each_backend(self) -> None:
        found = held_servers.by_object(
            {"web": {"s1"}, "mgd-shop": {"s1", "s2"}, "api": {"s3"}},
            {"web": "shop", "mgd-shop": "shop", "api": "admin-web"},
        )

        if found is None:
            self.fail("nothing held")
        self.assertEqual(
            [("admin-web", 1, True), ("shop", 3, True)],
            [(item.name, item.servers, item.owned) for item in found.objects],
        )
        self.assertEqual(4, found.total)

    def test_a_backend_no_object_claims_is_still_listed(self) -> None:
        found = held_servers.by_object({"left-over": {"s1"}}, {})

        if found is None:
            self.fail("nothing held")
        self.assertEqual(
            [("left-over", False)], [(item.name, item.owned) for item in found.objects]
        )

    def test_three_are_named_and_the_rest_counted(self) -> None:
        found = held_servers.by_object({name: {"s1"} for name in ("a", "b", "c", "d", "e")}, {})

        if found is None:
            self.fail("nothing held")
        self.assertEqual(["a", "b", "c"], [item.name for item in found.shown])
        self.assertEqual(["d", "e"], [item.name for item in found.rest])

    def test_nothing_held_is_nothing_to_say(self) -> None:
        self.assertIsNone(held_servers.by_object({}, {}))


class TheDashboard(DraftReading):
    def setUp(self) -> None:
        super().setUp()
        patch = mock.patch("haprion_ui.db.recent_jobs", return_value=[])
        patch.start()
        self.addCleanup(patch.stop)

    def page(self, *, role: str = "admin") -> str:
        self.account = replace(self.account, role=role)
        client = self.client(
            replace(
                configuration(),
                demo_fixture=True,
                management_writes=True,
                clusters=demo.CLUSTERS,
            )
        )
        self.sign_in(client)
        return str(client.get("/").text)

    def test_an_admin_is_linked_to_the_objects_servers(self) -> None:
        self.assertIn(
            '1 server in drain/maintenance: <a href="/proxies/edge-demo/public-web#servers"',
            self.page(),
        )

    def test_a_reader_is_told_how_many_without_a_link(self) -> None:
        page = self.page(role="reader")

        self.assertIn("1 server in drain/maintenance</span>", page)
        self.assertNotIn("public-web#servers", page)

    def test_the_objects_are_not_read_where_nothing_is_held(self) -> None:
        with mock.patch("haprion_ui.views.read_source") as read:
            found = views._held_servers(
                mock.Mock(), configuration(), ["alpha"], [reading([server("web", "s1")])]
            )

        self.assertEqual({}, found)
        read.assert_not_called()

    def test_more_than_three_blocking_objects_are_counted(self) -> None:
        counts = {name: 1 for name in ("api", "docs", "public-web", "shop", "staging")}
        with mock.patch("haprion_ui.blocked.cluster_counts", return_value=counts):
            page = self.page()

        self.assertIn('<span title="shop, staging">+2 more</span>', page)
        self.assertNotIn("edge-demo/shop#blocked", page)


if __name__ == "__main__":
    unittest.main()
