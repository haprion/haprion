"""What one status reading becomes, and what a failed write must not cost.

Three promises are checked here, and each has a reason outside this file.
B94 says a standby's backend verdict is not a measurement, so it is not stored as
one. The phase gate says missing stats data must not affect reachability, so a
sample that cannot be written is a log line and not a failed pass. And the
counters' null-versus-zero distinction, which the node script and the reader
both keep, has to survive being written to a column.
"""

from __future__ import annotations

import unittest
from typing import Any

from haproxy_ui import db, metrics, poller


def node(
    name: str, *, owner: bool | None, frontends: Any = None, servers: Any = None
) -> dict[str, Any]:
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


DNS_LISTENER = {
    "version": "2.1.2-1pdns.trixie",
    "active": True,
    "counters": {
        "uptime_sec": 40,
        "pools": [
            {"pool": "resolver", "queries": 9, "tcp_queries": 2, "refused": 1, "answered": 7},
            {"pool": "", "queries": 3, "tcp_queries": 0, "refused": 0, "answered": 3},
        ],
        "servers": [
            {
                "pool": "resolver",
                "server": "s1",
                "status": "UP",
                "queries": 8,
                "answered": 7,
                "latency_us": 350,
            },
            {
                "pool": "resolver",
                "server": "s2",
                "status": "DOWN",
                "queries": None,
                "answered": -1,
                "latency_us": None,
            },
        ],
    },
}


def dns_node(name: str, *, owner: bool | None, listener: Any = DNS_LISTENER) -> dict[str, Any]:
    found = node(name, owner=owner, frontends=[], servers=[])
    found["status"]["dns_listener"] = listener
    return found


class WhatADnsListenerIsWorthKeeping(unittest.TestCase):
    """dnsdist's counters as backend rows (Fas 19a B4): the pool's own and each server's."""

    def members(self, *nodes: dict[str, Any]) -> list[metrics.MemberSample]:
        return metrics.samples({"nodes": list(nodes)})[1]

    def test_the_pool_is_its_own_row_and_each_server_one_more(self) -> None:
        members = self.members(dns_node("node-a", owner=True))

        self.assertEqual(
            [(sample.backend, sample.member, sample.status) for sample in members],
            [("resolver", "BACKEND", None), ("resolver", "s1", "UP"), ("resolver", "s2", "DOWN")],
        )
        self.assertEqual(
            dict(members[0].counters),
            {"dns_queries": 9, "dns_tcp": 2, "dns_refused": 1, "dns_answered": 7},
        )
        self.assertEqual(
            dict(members[1].counters),
            {"dns_queries": 8, "dns_answered": 7, "dns_latency_us": 350},
        )

    def test_what_the_node_could_not_count_is_left_out_not_zeroed(self) -> None:
        self.assertEqual(dict(self.members(dns_node("node-a", owner=True))[2].counters), {})

    def test_the_uptime_is_dnsdists_and_not_haproxys(self) -> None:
        """dnsdist restarts with its configuration; HAProxy reloads apart from it."""

        members = self.members(dns_node("node-a", owner=True))
        self.assertEqual({sample.uptime_sec for sample in members}, {40})

    def test_only_the_address_holder_counts_as_for_haproxy(self) -> None:
        self.assertEqual(self.members(dns_node("node-b", owner=False)), [])
        self.assertEqual(self.members(dns_node("node-b", owner=None)), [])

    def test_a_listener_that_could_not_be_read_or_an_older_node_gives_nothing(self) -> None:
        for listener in (
            {"version": "2.1.2", "active": False, "counters": None},
            {"version": None, "active": False},
            None,
        ):
            with self.subTest(listener=listener):
                self.assertEqual(
                    self.members(dns_node("node-a", owner=True, listener=listener)), []
                )

    def test_the_columns_written_are_haproxy_s_and_dnsdist_s(self) -> None:
        statement = db._sample_insert(
            "metric_backend_member",
            ("node", "backend", "member", "check_status", "check_code"),
            (*metrics.METRIC_COUNTERS, *metrics.DNS_COUNTERS, metrics.DNS_LATENCY),
        ).as_string(None)
        for name in (*metrics.DNS_COUNTERS, metrics.DNS_LATENCY):
            self.assertIn(f'"{name}"', statement)


class WhatOneReadingIsWorthKeeping(unittest.TestCase):
    def samples(
        self, *nodes: dict[str, Any]
    ) -> tuple[list[metrics.FrontendSample], list[metrics.MemberSample]]:
        return metrics.samples({"nodes": list(nodes)})

    def test_every_node_contributes_its_frontends(self) -> None:
        """A standby's zero is a measurement, and the expected one."""

        frontends, _ = self.samples(
            node("a", owner=True, frontends=[LISTENER]),
            node("b", owner=False, frontends=[{**LISTENER, "counters": {"req_tot": 0}}]),
        )
        self.assertEqual([entry.node for entry in frontends], ["a", "b"])
        self.assertEqual(frontends[0].counters["req_tot"], 41)
        self.assertEqual(frontends[1].counters["req_tot"], 0)
        self.assertIs(frontends[1].owns_vip, False)

    def test_only_the_vip_owner_contributes_backend_members(self) -> None:
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
        frontends, _ = self.samples(node("a", owner=True, frontends=[LISTENER]))
        self.assertEqual(frontends[0].counters, {"req_tot": 41})
        self.assertNotIn("econ", frontends[0].counters)

    def test_the_runtime_uptime_rides_along_so_a_reload_can_be_told_apart(self) -> None:
        """A reload resets the counters and the uptime in the same instant."""

        frontends, members = self.samples(
            node("a", owner=True, frontends=[LISTENER], servers=[MEMBER])
        )
        self.assertEqual(frontends[0].uptime_sec, 900)
        self.assertEqual(members[0].uptime_sec, 900)

    def test_a_node_that_reported_no_frontends_is_not_an_error(self) -> None:
        """An older status script says nothing, and that is not a zero either."""

        frontends, members = self.samples(node("a", owner=True))
        self.assertEqual((frontends, members), ([], []))


class WhatIsWritten(unittest.TestCase):
    class Cursor:
        def __init__(self, calls: list[tuple[object, list[Any]]]) -> None:
            self.calls = calls

        def __enter__(self) -> Any:
            return self

        def __exit__(self, *_: object) -> None:
            return None

        def executemany(self, statement: object, rows: list[Any]) -> None:
            self.calls.append((statement, rows))

    class Connection:
        def __init__(self) -> None:
            self.calls: list[tuple[object, list[Any]]] = []

        def cursor(self, **_: object) -> Any:
            return WhatIsWritten.Cursor(self.calls)

    def write(self, result: dict[str, Any]) -> list[tuple[object, list[Any]]]:
        connection = self.Connection()
        db.record_metric_samples(
            connection,  # type: ignore[arg-type]
            cluster="alpha",
            result=result,
        )
        return connection.calls

    def statements(self, result: dict[str, Any]) -> list[str]:
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
            raise RuntimeError("no partition of metric_frontend for 2026-11-05")

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
