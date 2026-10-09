"""What a node says about its own pool members, and what the reader believes.

The runtime's verdict is the answer to "is my health check working" - HAProxy
has been running the checks, from the node, against the servers the node was
told about. Two things have to hold for that answer to be usable: a node that
said nothing must not read as a node with no servers, and a row that cannot be
attributed to a member must not be attributed to one.
"""

from __future__ import annotations

import unittest

from haproxy_mgmt.cluster_status import FrontendTraffic, ServerHealth, parse_status


def envelope(status: object) -> dict[str, object]:
    return {
        "schema_version": 1,
        "ok": True,
        "outcome": "done",
        "operation": "status",
        "cluster": "alpha",
        "request_id": "01JQ0000000000000000000000",
        "result": {
            "nodes": [
                {
                    "name": "node-a",
                    "mgmt_host": "node-a.example.com",
                    "reachable": True,
                    "status_ok": True,
                    "status": status,
                    "error": None,
                }
            ],
            "summary": {"vip_state": "single_owner", "vip_owners": ["node-a"]},
        },
        "warnings": [],
        "error": None,
    }


def node_status(**extra: object) -> dict[str, object]:
    status: dict[str, object] = {
        "schema_version": 1,
        "node": "node-a",
        "cluster": "alpha",
        "haproxy": {"active": True},
        "keepalived": {"active": True, "state": "MASTER"},
        "vip": {"address": "192.0.2.10", "interface": "eth0", "owner": True},
        "ip_nonlocal_bind": True,
        "release": None,
        "config_validation": {"ok": True},
        "stats_ok": True,
        "runtime": {"version": "3.4.4", "uptime_sec": 10},
        "certificates": [],
    }
    status.update(extra)
    return status


class WhatTheNodeSaidAboutItsServers(unittest.TestCase):
    def servers(self, **extra: object) -> tuple[ServerHealth, ...] | None:
        return parse_status(envelope(node_status(**extra))).nodes[0].servers

    def first_server(self, **extra: object) -> ServerHealth:
        servers = self.servers(**extra)
        assert servers, "the node reported no servers"
        return servers[0]

    def test_a_node_that_said_nothing_is_not_a_node_without_servers(self) -> None:
        """The distinction the whole field exists for.

        A node running an older status script, or one whose runtime socket
        could not be read, has to arrive as "unknown" - reported as "no members
        are up" it would send somebody looking for a fault that is not there.
        """

        self.assertIsNone(self.servers())
        self.assertIsNone(self.servers(servers=None))

    def test_a_node_with_no_members_answers_an_empty_list(self) -> None:
        self.assertEqual(self.servers(servers=[]), ())

    def test_a_row_without_a_pool_and_a_member_is_dropped(self) -> None:
        rows = [
            {"backend": "mgd-site-web", "status": "UP"},
            {"server": "s1", "status": "UP"},
            {"backend": "mgd-site-web", "server": "s1", "status": "UP"},
        ]
        self.assertEqual([entry.server for entry in self.servers(servers=rows) or ()], ["s1"])

    def test_the_row_is_carried_as_the_node_wrote_it(self) -> None:
        rows = [
            {
                "backend": "mgd-site-web",
                "server": "s1",
                "status": "DOWN",
                "check_status": "L7STS",
                "check_code": "404",
                "check_duration_ms": 3,
                "last_change_sec": 41,
            }
        ]
        self.assertEqual(
            self.servers(servers=rows),
            (
                ServerHealth(
                    backend="mgd-site-web",
                    server="s1",
                    status="DOWN",
                    check_status="L7STS",
                    check_code="404",
                    check_duration_ms=3,
                    last_change_sec=41,
                ),
            ),
        )

    def test_a_count_that_is_not_a_count_is_dropped_rather_than_shown(self) -> None:
        """`true` is an integer in Python, and would be printed as a duration."""

        rows = [
            {
                "backend": "mgd-site-web",
                "server": "s1",
                "status": "UP",
                "check_duration_ms": True,
                "last_change_sec": "41",
            }
        ]
        member = self.first_server(servers=rows)
        self.assertIsNone(member.check_duration_ms)
        self.assertIsNone(member.last_change_sec)

    def test_a_member_carries_its_counters_too(self) -> None:
        """The same columns, on the row that says whether the pool was used."""

        rows = [
            {
                "backend": "mgd-site-web",
                "server": "s1",
                "status": "UP",
                "counters": {"stot": 7, "econ": 0, "req_tot": None},
            }
        ]
        self.assertEqual((self.first_server(servers=rows)).counters, {"stot": 7, "econ": 0})

    def test_drain_and_maintenance_are_read_beside_the_check(self) -> None:
        """B263: a drained server whose check fails says DOWN in `status`."""

        def server(**row: object) -> ServerHealth:
            return self.first_server(
                servers=[{"backend": "web", "server": "s1", "status": "DOWN", **row}]
            )

        drained = server(admin="drain", weight=50)
        self.assertEqual((drained.admin, drained.weight), ("drain", 50))
        self.assertTrue(drained.held)
        self.assertFalse(server(admin="ready").held)
        #
        # A word the node does not send is no answer, and an older node's
        # status column is read instead.
        #
        self.assertIsNone(server(admin="disabled").admin)
        self.assertIsNone(server().admin)
        self.assertTrue(server(status="MAINT").held)
        self.assertFalse(server(status="MAINT (resolution)").held)


class WhatTheNodeSaidAboutItsListeners(unittest.TestCase):
    """A frontend has no verdict, only what arrived.

    It is read at all because a pool with three green servers and a listener
    that never received the request cannot be told apart from the server rows -
    which is exactly how a site answered 503 with everything UP.
    """

    def frontends(self, **extra: object) -> tuple[FrontendTraffic, ...] | None:
        return parse_status(envelope(node_status(**extra))).nodes[0].frontends

    def first_frontend(self, **extra: object) -> FrontendTraffic:
        frontends = self.frontends(**extra)
        assert frontends, "the node reported no listeners"
        return frontends[0]

    def test_a_node_that_said_nothing_is_not_a_node_without_listeners(self) -> None:
        self.assertIsNone(self.frontends())
        self.assertIsNone(self.frontends(frontends=None))

    def test_a_node_with_no_listeners_answers_an_empty_tuple(self) -> None:
        self.assertEqual(self.frontends(frontends=[]), ())

    def test_a_row_without_a_name_is_dropped(self) -> None:
        rows = [{"status": "OPEN"}, {"frontend": "mgd-vip-int-https", "status": "OPEN"}]
        self.assertEqual(
            self.frontends(frontends=rows),
            (FrontendTraffic(frontend="mgd-vip-int-https", status="OPEN"),),
        )

    def test_the_counters_arrive_under_haproxys_own_names(self) -> None:
        rows = [{"frontend": "f", "status": "OPEN", "counters": {"req_tot": 41, "hrsp_5xx": 2}}]
        listener = self.first_frontend(frontends=rows)
        self.assertEqual(listener.counters, {"req_tot": 41, "hrsp_5xx": 2})

    def test_a_counter_that_is_not_a_number_is_left_out_rather_than_zeroed(self) -> None:
        """The distinction the counters exist for.

        A listener that received nothing reports `0`; a column that does not
        apply, or a node that did not report it, is absent. Carried as zero,
        the second would read as the first - and a zero nobody measured is the
        answer that sends somebody looking at the wrong listener.
        """

        rows = [
            {
                "frontend": "f",
                "counters": {"req_tot": 0, "econ": None, "hrsp_5xx": "2", "scur": True},
            }
        ]
        counters = (self.first_frontend(frontends=rows)).counters
        self.assertEqual(counters, {"req_tot": 0})
        self.assertIsNone(counters.get("econ"))

    def test_counters_that_are_not_a_mapping_are_no_counters_at_all(self) -> None:
        rows = [{"frontend": "f", "counters": ["req_tot", 41]}]
        self.assertEqual((self.first_frontend(frontends=rows)).counters, {})


class WhetherAMemberIsTakingTraffic(unittest.TestCase):
    def member(self, status: str | None) -> ServerHealth:
        return ServerHealth(
            backend="mgd-site-web",
            server="s1",
            status=status,
            check_status=None,
            check_code=None,
            check_duration_ms=None,
            last_change_sec=None,
        )

    def test_up_and_no_check_are_both_taking_traffic(self) -> None:
        """A member nobody asked to check is not a member that failed one."""

        self.assertTrue(self.member("UP").up)
        self.assertTrue(self.member("UP 1/3").up)
        self.assertTrue(self.member("no check").up)

    def test_everything_else_is_not(self) -> None:
        for status in ("DOWN", "DOWN 1/2", "MAINT", "DRAIN", "NOLB", None, ""):
            with self.subTest(status=status):
                self.assertFalse(self.member(status).up)


if __name__ == "__main__":
    unittest.main()
