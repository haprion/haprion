from __future__ import annotations

import unittest
from dataclasses import dataclass
from typing import Any

from haproxy_ui import health


@dataclass
class Reading:
    cluster: str
    result: dict[str, Any]


def node(name: str, *members: tuple[str, str, str]) -> dict[str, Any]:
    return {
        "node": name,
        "status": {
            "servers": [
                {"backend": backend, "server": server, "status": state}
                for backend, server, state in members
            ]
        },
    }


def reading(*nodes: dict[str, Any], cluster: str = "alpha") -> list[Reading]:
    return [Reading(cluster=cluster, result={"nodes": list(nodes)})]


class TheLampInTheListing(unittest.TestCase):
    """One object's pools, rolled up to what a row can show.

    The states are five and not two, and the two quiet ones carry most of the
    care: an object with no health check is unlit, and a check nothing has
    reported on is grey. Green is reserved for a check that ran and passed.
    """

    def test_every_member_up_is_green(self) -> None:
        rows = reading(node("n1", ("mgd-shop-web", "a", "UP"), ("mgd-shop-web", "b", "UP")))
        lamp = health.object_health(rows, cluster="alpha", obj="shop")
        self.assertEqual(lamp.tone, "healthy")
        self.assertEqual(lamp.label, "2/2 up")

    def test_one_member_down_is_a_warning_and_not_a_failure(self) -> None:
        rows = reading(node("n1", ("mgd-shop-web", "a", "UP"), ("mgd-shop-web", "b", "DOWN")))
        lamp = health.object_health(rows, cluster="alpha", obj="shop")
        self.assertEqual(lamp.tone, "warning")
        self.assertIn("1 of 2", lamp.detail)

    def test_no_member_up_is_red(self) -> None:
        rows = reading(node("n1", ("mgd-shop-web", "a", "DOWN")))
        self.assertEqual(health.object_health(rows, cluster="alpha", obj="shop").tone, "critical")

    def test_a_member_down_on_one_node_only_is_still_a_warning(self) -> None:
        #
        # The traffic that lands on the second node does not reach it. Averaging
        # the two nodes into "up" would hide exactly that.
        #
        rows = reading(
            node("n1", ("mgd-shop-web", "a", "UP")),
            node("n2", ("mgd-shop-web", "a", "DOWN")),
        )
        lamp = health.object_health(rows, cluster="alpha", obj="shop")
        self.assertEqual(lamp.tone, "warning")
        self.assertIn("across 2 nodes", lamp.detail)

    def test_nothing_reported_is_grey_and_never_green(self) -> None:
        lamp = health.object_health(reading(node("n1")), cluster="alpha", obj="shop")
        self.assertEqual(lamp.tone, "unknown")
        self.assertEqual(lamp.label, "Not reported")

    def test_an_object_with_no_health_check_is_unlit(self) -> None:
        #
        # HAProxy reports an unchecked server as up, so the reading below would
        # otherwise be green - a reachability nothing measured.
        #
        rows = reading(node("n1", ("mgd-shop-web", "a", "UP")))
        lamp = health.object_health(rows, cluster="alpha", obj="shop", checked=False)
        self.assertEqual(lamp.tone, "off")
        self.assertEqual(lamp.label, "No check")

    def test_a_document_that_cannot_be_read_is_not_an_object_without_a_check(self) -> None:
        self.assertIsNone(health.has_health_check("not: [a document"))
        self.assertFalse(health.has_health_check("backends:\n  web:\n    servers: []\n"))
        self.assertTrue(
            health.has_health_check("backends:\n  web:\n    health:\n      type: http\n")
        )

    def test_a_check_written_down_as_disabled_is_no_check(self) -> None:
        #
        # The model spells the decision out rather than leaving it as an absent
        # section, and the lamp reports on whether something is checking.
        #
        self.assertFalse(
            health.has_health_check("backends:\n  web:\n    health:\n      type: disabled\n")
        )

    def test_a_longer_object_name_keeps_its_own_servers(self) -> None:
        #
        # `mgd-shop-web` is object `shop` pool `web`, and equally what object
        # `shop-web` would be called. A prefix test alone lends one object's
        # members to the other.
        #
        rows = reading(node("n1", ("mgd-shop-web-pool", "a", "DOWN")))
        mine = health.object_health(rows, cluster="alpha", obj="shop", others=("shop", "shop-web"))
        theirs = health.object_health(
            rows, cluster="alpha", obj="shop-web", others=("shop", "shop-web")
        )
        self.assertEqual(mine.tone, "unknown")
        self.assertEqual(theirs.tone, "critical")

    def test_another_cluster_is_not_this_one(self) -> None:
        rows = reading(node("n1", ("mgd-shop-web", "a", "UP")), cluster="beta")
        self.assertEqual(health.object_health(rows, cluster="alpha", obj="shop").tone, "unknown")


if __name__ == "__main__":
    unittest.main()
