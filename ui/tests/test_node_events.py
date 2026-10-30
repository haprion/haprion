"""Events → Nodes: what the nodes did on their own, between two readings (26-10-12)."""

from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest import mock

from haprion_ui import node_events, views
from haprion_ui.db import NodeEvent
from tests.test_login import LoginTestCase

AT = datetime(2026, 10, 12, 20, 40, 0, tzinfo=UTC)


def server(backend: str, name: str, status: str, **fields: Any) -> dict[str, Any]:
    return {"backend": backend, "server": name, "status": status, **fields}


def node(name: str, *, owner: bool | None, servers: list[dict[str, Any]], ok: bool = True) -> Any:
    status: dict[str, Any] = {"servers": servers}
    if owner is not None:
        status["vip"] = {"owner": owner}
    return {"name": name, "status_ok": ok, "status": status if ok else None}


def reading(*nodes: Any) -> dict[str, Any]:
    return {"nodes": list(nodes)}


def compared(before: dict[str, Any], after: dict[str, Any]) -> list[node_events.Change]:
    _, state, _ = node_events.compare({}, node_events.observe(before))
    changes, _, _ = node_events.compare(state, node_events.observe(after))
    return changes


class WhatChanged(unittest.TestCase):
    def test_a_first_reading_is_a_starting_point_and_says_nothing(self) -> None:
        changes, state, gone = node_events.compare(
            {},
            node_events.observe(
                reading(node("node-a", owner=True, servers=[server("shop", "s1", "DOWN")]))
            ),
        )

        self.assertEqual((changes, gone), ([], []))
        self.assertEqual(state[("server", "shop/s1")], "down")
        self.assertEqual(state[("vip", "")], "node-a")

    def test_a_server_going_down_is_dated_by_haproxys_own_count(self) -> None:
        changes = compared(
            reading(node("node-a", owner=True, servers=[server("shop", "s1", "UP")])),
            reading(
                node(
                    "node-a",
                    owner=True,
                    servers=[
                        server(
                            "shop",
                            "s1",
                            "DOWN",
                            last_change_sec=12,
                            check_status="L7TOUT",
                            check_code="",
                        )
                    ],
                )
            ),
        )

        (change,) = changes
        self.assertEqual(
            (change.event, change.node, change.subject, change.seconds_ago),
            ("server_down", "node-a", "shop/s1", 12),
        )
        self.assertEqual(change.detail, {"check_status": "L7TOUT"})

    def test_only_the_vip_holder_speaks_for_the_servers(self) -> None:
        """The standby's check leaves from an address it does not have (B94)."""

        changes = compared(
            reading(
                node("node-a", owner=True, servers=[server("shop", "s1", "UP")]),
                node("node-b", owner=False, servers=[server("shop", "s1", "UP")]),
            ),
            reading(
                node("node-a", owner=True, servers=[server("shop", "s1", "UP")]),
                node("node-b", owner=False, servers=[server("shop", "s1", "DOWN")]),
            ),
        )

        self.assertEqual(changes, [])

    def test_the_vip_moving_is_one_event_and_the_servers_stay_as_they_were(self) -> None:
        changes = compared(
            reading(
                node("node-a", owner=True, servers=[server("shop", "s1", "UP")]),
                node("node-b", owner=False, servers=[server("shop", "s1", "DOWN")]),
            ),
            reading(
                node("node-a", owner=False, servers=[server("shop", "s1", "DOWN")]),
                node("node-b", owner=True, servers=[server("shop", "s1", "UP")]),
            ),
        )

        (change,) = changes
        self.assertEqual(
            (change.event, change.node, change.detail), ("vip_moved", "node-b", {"from": "node-a"})
        )

    def test_a_node_that_stops_answering_and_comes_back(self) -> None:
        up = reading(
            node("node-a", owner=True, servers=[server("shop", "s1", "UP")]),
            node("node-b", owner=False, servers=[]),
        )
        silent = reading(
            node("node-a", owner=True, servers=[server("shop", "s1", "UP")]),
            node("node-b", owner=None, servers=[], ok=False),
        )

        self.assertEqual([c.event for c in compared(up, silent)], ["node_silent"])
        _, answered, _ = node_events.compare({}, node_events.observe(up))
        _, gone_quiet, _ = node_events.compare(answered, node_events.observe(silent))
        back, _, _ = node_events.compare(gone_quiet, node_events.observe(up))
        self.assertEqual([c.event for c in back], ["node_back"])

    def test_a_node_that_has_not_answered_yet_is_joining_and_its_first_answer_says_nothing(
        self,
    ) -> None:
        """B329: a node added was logged as answering again minutes later, though it never had."""

        up = reading(
            node("node-a", owner=True, servers=[]),
            node("node-b", owner=False, servers=[]),
        )
        silent = reading(
            node("node-a", owner=True, servers=[]),
            node("node-b", owner=None, servers=[], ok=False),
        )
        first, state, _ = node_events.compare({}, node_events.observe(silent))
        again, state, _ = node_events.compare(state, node_events.observe(silent))
        self.assertEqual((first, again), ([], []))
        self.assertEqual(node_events.joining(state), {"node-b"})
        answered, state, _ = node_events.compare(state, node_events.observe(up))
        self.assertEqual((answered, node_events.joining(state)), ([], frozenset()))
        quiet, _, _ = node_events.compare(state, node_events.observe(silent))
        self.assertEqual([c.event for c in quiet], ["node_silent"])

    def test_a_node_taken_out_and_added_again_is_joining_not_silent(self) -> None:
        """Review 2026-10-30, E7: the state of a node that left must not be inherited."""

        both = reading(
            node("node-a", owner=True, servers=[]),
            node("node-b", owner=False, servers=[]),
        )
        without = reading(node("node-a", owner=True, servers=[]))
        silent = reading(
            node("node-a", owner=True, servers=[]),
            node("node-b", owner=None, servers=[], ok=False),
        )
        _, state, _ = node_events.compare({}, node_events.observe(both))
        _, kept, gone = node_events.compare(state, node_events.observe(without))
        self.assertEqual(gone, [("node", "node-b")])
        remaining = {key: value for key, value in state.items() if key not in gone}
        changes, again, _ = node_events.compare(remaining, node_events.observe(silent))
        self.assertEqual(changes, [])
        self.assertEqual(node_events.joining(again), {"node-b"})

    def test_a_reading_without_a_node_list_forgets_no_node(self) -> None:
        _, state, _ = node_events.compare(
            {}, node_events.observe(reading(node("node-a", owner=True, servers=[])))
        )
        _, _, gone = node_events.compare(state, node_events.observe({}))
        self.assertEqual(gone, [])

    def test_a_held_server_keeps_its_state_and_says_nothing(self) -> None:
        changes = compared(
            reading(node("node-a", owner=True, servers=[server("shop", "s1", "UP")])),
            reading(
                node("node-a", owner=True, servers=[server("shop", "s1", "MAINT", admin="maint")])
            ),
        )

        self.assertEqual(changes, [])

    def test_a_server_the_holder_no_longer_lists_is_forgotten(self) -> None:
        _, state, _ = node_events.compare(
            {},
            node_events.observe(
                reading(node("node-a", owner=True, servers=[server("shop", "s1", "UP")]))
            ),
        )
        _, _, gone = node_events.compare(
            state, node_events.observe(reading(node("node-a", owner=True, servers=[])))
        )

        self.assertEqual(gone, [("server", "shop/s1")])

    def test_a_silent_holder_forgets_no_server(self) -> None:
        _, state, _ = node_events.compare(
            {},
            node_events.observe(
                reading(node("node-a", owner=True, servers=[server("shop", "s1", "UP")]))
            ),
        )
        changes, _, gone = node_events.compare(
            state,
            node_events.observe(reading(node("node-a", owner=None, servers=[], ok=False))),
        )

        self.assertEqual(([c.event for c in changes], gone), (["node_silent"], []))

    def test_a_status_with_a_step_count_is_read_by_its_first_word(self) -> None:
        changes = compared(
            reading(node("node-a", owner=True, servers=[server("shop", "s1", "UP")])),
            reading(node("node-a", owner=True, servers=[server("shop", "s1", "UP 1/3")])),
        )

        self.assertEqual(changes, [])


class TheSentences(unittest.TestCase):
    def test_each_event_reads_as_a_sentence(self) -> None:
        self.assertEqual(
            node_events.described("server_down", "shop/s1", {"check_status": "L7TOUT"}, "node-a"),
            "Server s1 in shop went down · no answer in time",
        )
        self.assertEqual(
            node_events.described("server_up", "shop/s1", {}, "node-a"),
            "Server s1 in shop came back up",
        )
        self.assertEqual(
            node_events.described("vip_moved", "", {"from": "node-a"}, "node-b"),
            "The VIP moved to node-b from node-a",
        )
        self.assertEqual(
            node_events.described("node_silent", "node-b", {}, "node-b"), "node-b stopped reporting its status"
        )

    def test_every_event_the_table_allows_has_a_sentence(self) -> None:
        versions = Path(__file__).resolve().parents[1] / "migrations" / "versions"
        migration = "\n".join(path.read_text() for path in sorted(versions.glob("[0-9]*.py")))
        for event in node_events.EVENTS:
            with self.subTest(event):
                self.assertIn(f"'{event}'", migration)
                self.assertNotEqual(node_events.described(event, "a/b", {}, "n"), event)


def row(**fields: Any) -> NodeEvent:
    values: dict[str, Any] = {
        "id": 1,
        "at": AT,
        "cluster": "alpha",
        "node": "node-a",
        "event": "server_down",
        "subject": "shop/s1",
        "detail": {},
    }
    values.update(fields)
    return NodeEvent(**values)


class ThePage(LoginTestCase):
    def test_both_roles_read_it_and_only_an_admin_has_audit(self) -> None:
        for role in ("admin", "reader"):
            with self.subTest(role):
                self.account = replace(self.account, role=role)
                client = self.client()
                self.sign_in(client)
                with mock.patch("haprion_ui.db.node_event_page", return_value=[row()]):
                    page = client.get("/jobs?view=nodes").text

                self.assertIn("Server s1 in shop went down", page)
                self.assertIn('href="/jobs?view=nodes" class="is-current"', page)
                self.assertEqual('href="/jobs?view=audit"' in page, role == "admin")

    def test_a_page_that_is_not_a_number_is_the_first_page(self) -> None:
        # Review 26-10-13, K2.
        client = self.client()
        self.sign_in(client)
        for asked in ("²", "-1", "", "9" * 5000):
            with (
                self.subTest(asked=asked[:8]),
                mock.patch("haprion_ui.db.node_event_page", return_value=[]),
                mock.patch("haprion_ui.db.node_event_count", return_value=120),
            ):
                answer = client.get("/jobs", params={"view": "nodes", "page": asked})
                self.assertEqual(answer.status_code, 200)

    def test_pages_and_dates_are_asked_of_the_database(self) -> None:
        client = self.client()
        self.sign_in(client)
        with (
            mock.patch("haprion_ui.db.node_event_page", return_value=[]) as listed,
            mock.patch("haprion_ui.db.node_event_count", return_value=120),
        ):
            page = client.get("/jobs?view=nodes&size=25&page=2&from=26-10-01%2000:00").text

        self.assertEqual(listed.call_args.kwargs["offset"], 25)
        self.assertEqual(listed.call_args.kwargs["limit"], 25)
        self.assertIsNotNone(listed.call_args.kwargs["since"])
        self.assertIn("26–50 of 120", page)
        self.assertIn('<option value="25" selected>', page)

    def test_a_heading_sorts_in_the_database(self) -> None:
        client = self.client()
        self.sign_in(client)
        with mock.patch("haprion_ui.db.node_event_page", return_value=[]) as listed:
            client.get("/jobs?view=nodes&sort=node")
            by_node = dict(listed.call_args.kwargs)

        self.assertEqual((by_node["order"], by_node["descending"]), ("node", False))

    def test_a_servers_row_links_to_the_object_that_owns_its_pool(self) -> None:
        rows = node_events.rows([row()], {"alpha": {"shop": "webshop"}})

        self.assertEqual(rows[0].obj, "webshop")
        self.assertEqual(node_events.rows([row(event="vip_moved", subject="")], {})[0].obj, "")

    def test_the_page_and_the_retention_keep_the_same_90_days(self) -> None:
        script = (
            Path(__file__).resolve().parents[2] / "install/platform/bin/haprion-retention"
        ).read_text()

        self.assertIn(f"NODE_EVENT_KEEP_DAYS={views.NODE_EVENT_KEEP_DAYS}\n", script)
        self.assertEqual(views.NODE_EVENT_KEEP_DAYS, 90)


if __name__ == "__main__":
    unittest.main()
