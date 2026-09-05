"""What one status reading becomes, and what a failed write must not cost.

Three promises are checked here, and each has a reason outside this file.
B94 says a standby's pool verdict is not a measurement, so it is not stored as
one. The phase gate says missing stats data must not affect reachability, so a
sample that cannot be written is a log line and not a failed pass. And the
counters' null-versus-zero distinction, which the node script and the reader
both keep, has to survive being written to a column.
"""

from __future__ import annotations

import unittest
from typing import Any

from haproxy_ui import db, metrics, poller


def node(name: str, *, owner: bool | None, frontends: Any = None, servers: Any = None) -> dict:
    return {
        "name": name,
        "reachable": True,
        "status_ok": True,
        "status": {
            "node": name,
            "vip": {"address": "192.0.2.10", "interface": "eth0", "owner": owner},
            "runtime": {"version": "3.4.4", "uptime_sec": 900},
            "frontends": frontends,
            "servers": servers,
        },
    }


LISTENER = {
    "frontend": "mgd-vip-https",
    "status": "OPEN",
    "counters": {"req_tot": 41, "econ": None},
}
MEMBER = {
    "backend": "mgd-site-web",
    "server": "s1",
    "status": "UP",
    "check_status": "L7OK",
    "check_code": "200",
    "counters": {"stot": 7},
}


class WhatOneReadingIsWorthKeeping(unittest.TestCase):
    def samples(self, *nodes: dict) -> tuple[list, list]:
        return metrics.samples({"nodes": list(nodes)})

    def test_every_node_contributes_its_listeners(self) -> None:
        """A standby's zero is a measurement, and the expected one."""

        listeners, _ = self.samples(
            node("a", owner=True, frontends=[LISTENER]),
            node("b", owner=False, frontends=[{**LISTENER, "counters": {"req_tot": 0}}]),
        )
        self.assertEqual([entry.node for entry in listeners], ["a", "b"])
        self.assertEqual(listeners[0].counters["req_tot"], 41)
        self.assertEqual(listeners[1].counters["req_tot"], 0)
        self.assertIs(listeners[1].owns_vip, False)

    def test_only_the_vip_owner_contributes_pool_members(self) -> None:
        """B94: the standby's check is answered to whoever holds the address."""

        _, members = self.samples(
            node("a", owner=True, servers=[MEMBER]),
            node("b", owner=False, servers=[{**MEMBER, "status": "DOWN", "check_status": "L4CON"}]),
        )
        self.assertEqual([entry.node for entry in members], ["a"])
        self.assertEqual(members[0].status, "UP")

    def test_a_node_that_cannot_say_who_holds_the_address_contributes_none(self) -> None:
        """Not knowing the owner is not knowing whether the verdict means anything."""

        _, members = self.samples(node("a", owner=None, servers=[MEMBER]))
        self.assertEqual(members, [])

    def test_a_counter_that_is_not_a_number_is_left_out_rather_than_zeroed(self) -> None:
        listeners, _ = self.samples(node("a", owner=True, frontends=[LISTENER]))
        self.assertEqual(listeners[0].counters, {"req_tot": 41})
        self.assertNotIn("econ", listeners[0].counters)

    def test_the_runtime_uptime_rides_along_so_a_reload_can_be_told_apart(self) -> None:
        """A reload resets the counters and the uptime in the same instant."""

        listeners, members = self.samples(
            node("a", owner=True, frontends=[LISTENER], servers=[MEMBER])
        )
        self.assertEqual(listeners[0].uptime_sec, 900)
        self.assertEqual(members[0].uptime_sec, 900)

    def test_a_node_that_reported_no_listeners_is_not_an_error(self) -> None:
        """An older status script says nothing, and that is not a zero either."""

        listeners, members = self.samples(node("a", owner=True))
        self.assertEqual((listeners, members), ([], []))


class WhatIsWritten(unittest.TestCase):
    class Cursor:
        def __init__(self, calls: list) -> None:
            self.calls = calls

        def __enter__(self) -> Any:
            return self

        def __exit__(self, *_: object) -> None:
            return None

        def executemany(self, statement: str, rows: list) -> None:
            self.calls.append((statement, rows))

    class Connection:
        def __init__(self) -> None:
            self.calls: list = []

        def cursor(self, **_: object) -> Any:
            return WhatIsWritten.Cursor(self.calls)

    def write(self, result: dict) -> list:
        connection = self.Connection()
        db.record_metric_samples(connection, cluster="alpha", result=result)
        return connection.calls

    def statements(self, result: dict) -> list[str]:
        """The composed SQL as text, which is what the server is actually sent."""

        return [str(statement) for statement, _ in self.write(result)]

    def test_the_reading_never_carries_its_own_timestamp(self) -> None:
        """`observed_at` is the database's, so a poll cannot look fresher."""

        for statement in self.statements({"nodes": [node("a", owner=True, frontends=[LISTENER])]}):
            self.assertNotIn("observed_at", statement)

    def test_every_column_is_named_one_at_a_time(self) -> None:
        """A statement naming the table alone widens the next time one is added."""

        statement = self.statements({"nodes": [node("a", owner=True, frontends=[LISTENER])]})[0]
        for name in ("cluster", "node", "frontend", "owns_vip", *metrics.METRIC_COUNTERS):
            with self.subTest(column=name):
                self.assertIn(f"Identifier('{name}')", statement)

    def test_a_missing_counter_is_written_as_null(self) -> None:
        calls = self.write({"nodes": [node("a", owner=True, frontends=[LISTENER])]})
        row = calls[0][1][0]
        self.assertEqual(row["req_tot"], 41)
        self.assertIsNone(row["econ"])
        for name in metrics.METRIC_COUNTERS:
            self.assertIn(name, row)

    def test_nothing_to_write_is_no_statement_at_all(self) -> None:
        self.assertEqual(self.write({"nodes": []}), [])

    def test_the_rows_are_appended_and_never_replaced(self) -> None:
        """A sample says what was true then; rewriting it destroys the point."""

        for statement in self.statements(
            {"nodes": [node("a", owner=True, frontends=[LISTENER], servers=[MEMBER])]}
        ):
            self.assertIn("insert into", statement)
            self.assertNotIn("on conflict", statement)
            self.assertNotIn("update", statement)


class WhenTheSampleCannotBeWritten(unittest.TestCase):
    """The phase gate: missing stats data does not affect reachability."""

    class FailingPool:
        def connection(self) -> Any:
            raise RuntimeError("no partition of metric_listener for 2026-11-05")

    def test_the_pass_survives_a_write_that_failed(self) -> None:
        source = poller.Source(
            "status",
            lambda *_: None,
            lambda *_, **__: None,
            sample=lambda *_, **__: 0,
        )
        with self.assertLogs("haproxy_ui.poller", level="WARNING") as logged:
            poller._sample(self.FailingPool(), source, cluster="alpha", result={"nodes": []})
        self.assertIn("samples not written", logged.output[0])
        self.assertIn("no partition", logged.output[0])


if __name__ == "__main__":
    unittest.main()
