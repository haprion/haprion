"""The object page's Servers card and its buttons (Fas 20, B263).

Three things are pinned here. What a node says about a server is read with
drain and maintenance first, because `show stat` says DOWN for a drained
server whose check fails. A server taken out on purpose is not a fault, so
the listing's lamp does not turn amber for it. And the buttons queue exactly
the job the worker runs, for an admin, with the servers named by address.
"""

from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any
from unittest import mock
from uuid import uuid4

from haproxy_mgmt.proxy_model import load_proxy

from haproxy_ui import auth, db, demo, health, server_card
from haproxy_ui.db import ClusterStatus
from tests.test_login import configuration
from tests.test_object_page import DraftReading
from tests.test_queue_route import queued

OBSERVED = datetime(2026, 10, 9, 12, 0, tzinfo=UTC)

DOCUMENT = """schema: 1
name: shop
hostnames:
  - shop.example.com
listen:
  protocol: https
  certificate: shop-example-com
routes:
  - path: /
    backend: web
backends:
  web:
    balance: roundrobin
    health:
      type: tcp
    servers:
      - host: 192.0.2.12
        port: 8080
      - host: 192.0.2.10
        port: 8080
        weight: 50
      - host: 192.0.2.11
        port: 8080
        backup: true
"""


def member(server: str, status: str, admin: str | None = None, scur: int = 0) -> dict[str, Any]:
    row: dict[str, Any] = {
        "backend": "web",
        "server": server,
        "status": status,
        "counters": {"scur": scur},
    }
    if admin is not None:
        row["admin"] = admin
    return row


def reading(*nodes: tuple[str, list[dict[str, Any]]], cluster: str = "alpha") -> ClusterStatus:
    return ClusterStatus(
        cluster=cluster,
        observed_at=OBSERVED,
        outcome="done",
        result={
            "nodes": [
                {"name": name, "status": {"servers": servers, "vip": {"owner": index == 0}}}
                for index, (name, servers) in enumerate(nodes)
            ]
        },
        warnings=[],
        error=None,
        poll_error=None,
    )


class TheCard(unittest.TestCase):
    def setUp(self) -> None:
        self.proxy = load_proxy("shop", DOCUMENT.encode())

    def build(
        self, *nodes: tuple[str, list[dict[str, Any]]], current: bool = True
    ) -> server_card.ServerCard:
        card = server_card.build(self.proxy, [reading(*nodes)], cluster="alpha", current=current)
        if card is None:
            self.fail("an https object with servers has a card")
        return card

    def test_one_row_per_server_in_alphabetical_order_with_its_weight(self) -> None:
        card = self.build(("node-a", []))

        self.assertEqual(
            [row.shown for row in card.rows],
            ["192.0.2.10:8080", "192.0.2.11:8080", "192.0.2.12:8080"],
        )
        self.assertEqual([row.weight for row in card.rows], [50, 1, 1])
        self.assertEqual([row.backup for row in card.rows], [False, True, False])
        self.assertEqual(card.rows[0].target, "web/192.0.2.10:8080")

    def test_a_drained_server_whose_check_fails_reads_drained(self) -> None:
        """`show stat` says DOWN; the admin state is what somebody set."""

        card = self.build(
            ("node-a", [member("s1", "DOWN", "drain"), member("s2", "UP", "ready", scur=4)]),
            ("node-b", [member("s1", "MAINT", "maint"), member("s2", "DOWN", "ready", scur=1)]),
        )
        rows = {row.shown: row for row in card.rows}

        self.assertEqual(card.nodes, ("node-a", "node-b"))
        drained = rows["192.0.2.12:8080"].cells
        self.assertEqual((drained[0].label, drained[0].tone), ("DRAIN", "warning"))
        self.assertEqual((drained[1].label, drained[1].tone), ("MAINT", "unknown"))
        second = rows["192.0.2.10:8080"]
        self.assertEqual([cell.label for cell in second.cells], ["UP", "DOWN"])
        self.assertEqual(second.sessions, 5)

    def test_an_older_node_is_read_from_its_status_column(self) -> None:
        card = self.build(("node-a", [member("s1", "DRAIN"), member("s2", "MAINT (resolution)")]))
        rows = {row.shown: row for row in card.rows}

        self.assertEqual(rows["192.0.2.12:8080"].cells[0].label, "DRAIN")
        #
        # A failed name resolution is HAProxy's verdict, not anybody's choice.
        #
        self.assertEqual(rows["192.0.2.10:8080"].cells[0].tone, "unknown")
        self.assertNotEqual(rows["192.0.2.10:8080"].cells[0].label, "MAINT")

    def test_a_server_the_node_did_not_report_is_a_dash(self) -> None:
        card = self.build(("node-a", [member("s1", "UP")]))
        rows = {row.shown: row for row in card.rows}

        self.assertEqual(rows["192.0.2.11:8080"].cells[0].label, "—")
        self.assertIsNone(rows["192.0.2.11:8080"].sessions)

    def test_nothing_is_drawn_from_positions_the_nodes_may_not_run(self) -> None:
        """An undeployed edit can reorder the pool; `s1` is then another server."""

        card = self.build(("node-a", [member("s1", "DOWN", "drain", scur=7)]), current=False)

        self.assertTrue(all(cell.label == "—" for row in card.rows for cell in row.cells))
        self.assertTrue(all(row.sessions is None for row in card.rows))

    def test_a_sourced_object_reads_backup_where_the_vip_is_not(self) -> None:
        """26-10-09 in production: the other node's check cannot bind the address.

        It said DOWN, which read as a node in trouble; it is a node whose check
        has nothing to send from.
        """

        nodes = (
            ("node-a", [member("s1", "UP"), member("s2", "UP")]),
            ("node-b", [member("s1", "DOWN"), member("s2", "DOWN", "drain")]),
        )
        rows = server_card.build(
            self.proxy, [reading(*nodes)], cluster="alpha", current=True, sourced=True
        )
        if rows is None:
            self.fail("an https object with servers has a card")
        found = {row.shown: [cell.label for cell in row.cells] for row in rows.rows}

        self.assertEqual(found["192.0.2.12:8080"], ["UP", "BACKUP"])
        # Its drain is set on every node, and said on every node.
        self.assertEqual(found["192.0.2.10:8080"], ["UP", "DRAIN"])

    def test_an_object_without_a_source_keeps_each_nodes_check(self) -> None:
        card = self.build(("node-a", [member("s1", "UP")]), ("node-b", [member("s1", "DOWN")]))
        rows = {row.shown: row for row in card.rows}

        self.assertEqual([cell.label for cell in rows["192.0.2.12:8080"].cells], ["UP", "DOWN"])

    def test_two_pools_name_the_pool_on_each_row(self) -> None:
        proxy = load_proxy(
            "shop",
            DOCUMENT.replace(
                "routes:\n  - path: /\n    backend: web\n",
                "routes:\n  - path: /\n    backend: web\n  - path: /api\n    backend: api\n",
            )
            .replace(
                "backends:\n",
                "backends:\n  api:\n    balance: roundrobin\n    health:\n      type: tcp\n    servers:\n      - host: 192.0.2.20\n        port: 9000\n",
            )
            .encode(),
        )
        card = server_card.build(proxy, [], cluster="alpha", current=True)

        if card is None:
            self.fail("an object with two pools has a card")
        self.assertEqual(card.pools, ("api", "web"))
        self.assertEqual(card.rows[0].shown, "api/192.0.2.20:9000")

    def test_a_dns_object_has_no_card(self) -> None:
        proxy = load_proxy(
            "resolver",
            b"schema: 1\nname: resolver\nlisten: {protocol: dns, port: 53}\nbackend: resolver\n"
            b"backends:\n  resolver:\n    balance: roundrobin\n"
            b"    servers: [{host: 192.0.2.53, port: 53}]\n    health: {type: dns}\n",
        )

        self.assertIsNone(server_card.build(proxy, [], cluster="alpha", current=True))


class TheLamp(unittest.TestCase):
    """A server taken out on purpose is not a fault (B263)."""

    def lamp(self, *servers: dict[str, Any]) -> health.ObjectHealth:
        return health.object_health(
            [reading(("node-a", list(servers)))],
            cluster="alpha",
            obj="shop",
            owners={"web": "shop"},
        )

    def test_a_drained_server_does_not_turn_the_lamp_amber(self) -> None:
        lamp = self.lamp(member("s1", "UP"), member("s2", "DOWN", "drain"))

        self.assertEqual(lamp.tone, "healthy")
        self.assertIn("1 drained or in maintenance", lamp.detail)

    def test_every_server_held_is_said_as_such(self) -> None:
        lamp = self.lamp(member("s1", "MAINT", "maint"), member("s2", "DRAIN"))

        self.assertEqual((lamp.tone, lamp.label), ("warning", "Held"))

    def test_a_failed_resolution_is_still_a_fault(self) -> None:
        lamp = self.lamp(member("s1", "UP"), member("s2", "MAINT (resolution)"))

        self.assertEqual(lamp.tone, "warning")

    def test_the_editor_card_does_not_call_a_drained_server_failing(self) -> None:
        found = health.backend_health(
            [reading(("node-a", [member("s1", "DOWN", "drain")]))],
            cluster="alpha",
            obj="shop",
            backend="web",
        )

        self.assertEqual(found.failing, ())


KEY = str(uuid4())


class TheButtons(DraftReading):
    def setUp(self) -> None:
        super().setUp()
        self.queued: list[dict[str, Any]] = []
        self.audited: list[dict[str, Any]] = []

        def queue(_c: object, **fields: Any) -> db.Job:
            self.queued.append(fields)
            return queued(operation="server_state", cluster="edge-demo")

        def audit(_c: object, **fields: Any) -> None:
            self.audited.append(fields)

        for patch in (
            mock.patch("haproxy_ui.db.queue_job", side_effect=queue),
            mock.patch("haproxy_ui.db.record_audit_event", side_effect=audit),
            mock.patch("haproxy_ui.db.recent_jobs", return_value=[]),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def writing_client(self, *, role: str = "admin") -> Any:
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
        return client

    def post(self, client: Any, **fields: Any) -> Any:
        form: dict[str, Any] = {
            "idempotency_key": KEY,
            auth.CSRF_FIELD: auth.csrf_token(client.cookies[auth.SESSION_COOKIE]),
            "state": "drain",
            "server": ["web/192.0.2.10:8080", "web/192.0.2.12:8080"],
        }
        form.update(fields)
        return client.post(
            "/proxies/edge-demo/public-web/servers", data=form, follow_redirects=False
        )

    def test_the_page_draws_each_node_and_the_buttons(self) -> None:
        page = self.writing_client().get("/proxies/edge-demo/public-web")

        self.assertEqual(page.status_code, 200)
        self.assertIn("<h3>Servers</h3>", page.text)
        self.assertIn(">edge-a</th>", page.text)
        self.assertIn('value="web/192.0.2.12:8080"', page.text)
        self.assertIn("DRAIN", page.text)
        self.assertIn('name="state" value="maint"', page.text)

    def test_a_job_in_flight_replaces_the_buttons(self) -> None:
        running = replace(queued(operation="deploy", cluster="edge-demo"), state="running")
        with mock.patch("haproxy_ui.db.recent_jobs", return_value=[running]):
            page = self.writing_client().get("/proxies/edge-demo/public-web")

        self.assertIn('data-busy="edge-demo"', page.text)
        self.assertNotIn('name="state" value="drain"', page.text)

    def test_the_ticked_servers_are_queued_by_address(self) -> None:
        answer = self.post(self.writing_client())

        self.assertEqual(answer.status_code, 303)
        self.assertEqual(answer.headers["location"], "/proxies/edge-demo/public-web")
        self.assertEqual(len(self.queued), 1)
        self.assertEqual(self.queued[0]["operation"], "server_state")
        self.assertEqual(self.queued[0]["cluster"], "edge-demo")
        self.assertEqual(
            self.queued[0]["payload"],
            {
                "object": "public-web",
                "servers": ["web/192.0.2.10:8080", "web/192.0.2.12:8080"],
                "state": "drain",
            },
        )
        queued_audit = [entry for entry in self.audited if entry["action"] == "queue_job"]
        self.assertEqual(queued_audit[0]["detail"]["state"], "drain")

    def test_no_server_ticked_queues_nothing(self) -> None:
        answer = self.post(self.writing_client(), server=[])

        self.assertEqual(answer.headers["location"], "/proxies/edge-demo/public-web?servers=none")
        self.assertEqual(self.queued, [])

    def test_a_busy_cluster_is_said_on_the_page(self) -> None:
        client = self.writing_client()
        with mock.patch("haproxy_ui.db.queue_job", side_effect=db.ClusterBusy()):
            answer = self.post(client)

        self.assertEqual(answer.headers["location"], "/proxies/edge-demo/public-web?servers=busy")
        page = client.get(answer.headers["location"])
        self.assertIn("A job is already running for this cluster", page.text)

    def test_a_state_the_worker_does_not_run_is_refused(self) -> None:
        answer = self.post(self.writing_client(), state="disable")

        self.assertEqual(answer.status_code, 400)
        self.assertEqual(self.queued, [])

    def test_only_an_admin_may_press_them(self) -> None:
        answer = self.post(self.writing_client(role="operator"))

        self.assertEqual(answer.status_code, 403)
        self.assertEqual(self.queued, [])

    def test_a_forged_request_is_refused(self) -> None:
        answer = self.post(self.writing_client(), **{auth.CSRF_FIELD: "forged"})

        self.assertEqual(answer.status_code, 403)
        self.assertEqual(self.queued, [])

    def test_a_cluster_not_configured_is_not_found(self) -> None:
        client = self.writing_client()
        form = {
            "idempotency_key": KEY,
            auth.CSRF_FIELD: auth.csrf_token(client.cookies[auth.SESSION_COOKIE]),
            "state": "drain",
            "server": ["web/192.0.2.10:8080"],
        }
        answer = client.post("/proxies/gamma/public-web/servers", data=form)

        self.assertEqual(answer.status_code, 404)
        self.assertEqual(self.queued, [])


if __name__ == "__main__":
    unittest.main()
