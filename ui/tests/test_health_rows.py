"""One health table: the nodes' reading, with a test's answers written into it."""

from __future__ import annotations

import unittest

from haprion.cluster_status import ServerHealth

from haprion_ui.health import BackendHealth, NodeMembers
from haprion_ui.health_rows import health_rows
from haprion_ui.probe import NodeReport, ProbeReport, Reached


def reported(*servers: tuple[str, str]) -> BackendHealth:
    return BackendHealth(
        backend="mgd-shop-web",
        nodes=(
            NodeMembers(
                node="node-a",
                members=tuple(
                    ServerHealth(
                        backend="mgd-shop-web",
                        server=name,
                        status=status,
                        check_status="L7OK",
                        check_code="200",
                        check_duration_ms=4,
                        last_change_sec=60,
                    )
                    for name, status in servers
                ),
                said=True,
            ),
        ),
        observed_at=None,
        addresses=("198.51.100.10:8080", "198.51.100.11:8080"),
    )


def tested(*results: tuple[str, bool], node: str = "node-a") -> ProbeReport:
    return ProbeReport(
        ran=True,
        source="192.0.2.25",
        nodes=(
            NodeReport(
                node=node,
                reachable=True,
                error=None,
                results=tuple(
                    Reached(
                        host=address.split(":")[0],
                        port=int(address.split(":")[1]),
                        ok=ok,
                        status=200 if ok else None,
                        error=None if ok else "refused",
                        ms=3,
                    )
                    for address, ok in results
                ),
                source_held=True,
            ),
        ),
    )


class TheNodesReadingAlone(unittest.TestCase):
    def test_each_member_is_a_row_under_the_address_it_was_written_as(self) -> None:
        rows = health_rows(reported(("s1", "UP"), ("s2", "DOWN")), None)

        self.assertEqual(
            [(row.server, row.up) for row in rows],
            [
                ("198.51.100.10:8080", True),
                ("198.51.100.11:8080", False),
            ],
        )
        self.assertFalse(any(row.tested for row in rows))


class TheLamp(unittest.TestCase):
    def test_a_server_without_a_check_is_not_green(self) -> None:
        """Usable, but nothing said it answers."""

        rows = health_rows(reported(("s1", "no check"), ("s2", "UP")), None)

        self.assertEqual([row.tone for row in rows], ["unknown", "healthy"])

    def test_a_down_server_is_red(self) -> None:
        self.assertEqual(health_rows(reported(("s1", "DOWN")), None)[0].tone, "critical")


class ATestWritesIntoTheSameRows(unittest.TestCase):
    def test_a_tested_server_replaces_its_row_rather_than_adding_one(self) -> None:
        rows = health_rows(
            reported(("s1", "DOWN"), ("s2", "UP")), tested(("198.51.100.10:8080", True))
        )

        self.assertEqual(len(rows), 2)
        first = rows[0]
        self.assertEqual((first.server, first.up, first.tested), ("198.51.100.10:8080", True, True))
        self.assertTrue(first.last.endswith("· tested"))
        self.assertFalse(rows[1].tested)

    def test_a_server_the_nodes_do_not_know_yet_gets_a_row(self) -> None:
        rows = health_rows(reported(("s1", "UP")), tested(("198.51.100.20:8080", False)))

        self.assertEqual([row.server for row in rows], ["198.51.100.10:8080", "198.51.100.20:8080"])
        self.assertEqual(rows[1].state, "DOWN")

    def test_a_test_without_a_deployed_backend_is_the_whole_table(self) -> None:
        rows = health_rows(None, tested(("198.51.100.10:8080", True)))

        self.assertEqual([(row.node, row.state) for row in rows], [("node-a", "UP")])


class ADrainIsAChoice(unittest.TestCase):
    """7-9: red in the editor's rows, yellow on the server card, for one server."""

    def test_the_editor_colours_a_drain_as_the_card_does(self) -> None:
        (row,) = health_rows(reported(("s1", "DRAIN")), None)

        self.assertEqual((row.state, row.tone), ("DRAIN", "warning"))
