from __future__ import annotations

import unittest
from dataclasses import dataclass
from typing import Any

from haproxy_ui import health


@dataclass
class Reading:
    cluster: str
    result: dict[str, Any]


def node(
    name: str, *members: tuple[str, str, str], holds_vip: bool | None = None
) -> dict[str, Any]:
    status: dict[str, Any] = {
        "servers": [
            {"backend": backend, "server": server, "status": state}
            for backend, server, state in members
        ]
    }
    if holds_vip is not None:
        status["vip"] = {"owner": holds_vip}
    return {"node": name, "status": status}


def reading(*nodes: dict[str, Any], cluster: str = "alpha") -> list[Reading]:
    return [Reading(cluster=cluster, result={"nodes": list(nodes)})]


class TheCardNamesWhatTheAuthorWrote(unittest.TestCase):
    """`s1` is the generator's name for a position, not something anybody typed.

    It is right in the configuration and in the logs, and wrong on a card read
    by the person who wrote the address it stands for.
    """

    def pool(self, *addresses: str) -> health.PoolHealth:
        return health.PoolHealth(
            backend="mgd-shop-web", nodes=(), observed_at=None, addresses=addresses
        )

    def test_a_runtime_name_resolves_to_the_address_in_that_position(self) -> None:
        pool = self.pool("198.51.100.10:8080", "198.51.100.11:8080")

        self.assertEqual(pool.address("s1"), "198.51.100.10:8080")
        self.assertEqual(pool.address("s2"), "198.51.100.11:8080")

    def test_a_name_beyond_the_pool_resolves_to_nothing(self) -> None:
        #
        # A pool edited since the deploy has more names than addresses, and a
        # guess there would put one member's address beside another.
        #
        pool = self.pool("198.51.100.10:8080")

        self.assertEqual(pool.address("s2"), "")
        self.assertEqual(pool.address("BACKEND"), "")
        self.assertEqual(pool.address("sx"), "")


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

    def test_the_pools_own_summary_row_is_not_a_server(self) -> None:
        #
        # `show stat` emits a BACKEND pseudo-row per proxy and the node reports
        # it beside the real ones. Counted, it made one server behind a
        # two-node cluster read as 4 - and put a row called BACKEND in a list
        # of servers.
        #
        rows = reading(
            node("n1", ("mgd-shop-web", "s1", "UP"), ("mgd-shop-web", "BACKEND", "UP")),
            node("n2", ("mgd-shop-web", "s1", "UP"), ("mgd-shop-web", "BACKEND", "UP")),
        )
        lamp = health.object_health(rows, cluster="alpha", obj="shop")
        self.assertEqual(lamp.label, "1/1 up")
        self.assertEqual(lamp.tone, "healthy")

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
        #
        # One server, so the count stays 1 - and amber rather than red, because
        # the pool is still serving from the node that can reach it. The node
        # that cannot is named, since that is where somebody would start.
        #
        self.assertEqual(lamp.label, "0/1 up")
        self.assertIn("reported down by n2", lamp.detail)

    def test_nothing_reported_is_grey_and_never_green(self) -> None:
        lamp = health.object_health(reading(node("n1")), cluster="alpha", obj="shop")
        self.assertEqual(lamp.tone, "unknown")
        self.assertEqual(lamp.label, "")

    def test_an_object_with_no_health_check_is_unlit(self) -> None:
        #
        # HAProxy reports an unchecked server as up, so the reading below would
        # otherwise be green - a reachability nothing measured.
        #
        rows = reading(node("n1", ("mgd-shop-web", "a", "UP")))
        lamp = health.object_health(rows, cluster="alpha", obj="shop", checked=False)
        self.assertEqual(lamp.tone, "unknown")
        self.assertEqual(lamp.label, "")

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


class OnlyTheNodeThatCarriesTheAddressAnswers(unittest.TestCase):
    """A pool that leaves from a source address has one node that can say.

    Both nodes run the same configuration and both run the check. The one that
    does not carry the address binds it anyway - the kernel allows it - fails
    to route, and reports the pool down. That is HAProxy telling the truth
    about the binding and a lie about the pool, and it turned one healthy
    server into `0/1 up`.
    """

    def cluster(self) -> list[Reading]:
        return reading(
            node("node-a", ("mgd-shop-web", "s1", "UP"), holds_vip=True),
            node("node-b", ("mgd-shop-web", "s1", "DOWN"), holds_vip=False),
        )

    def test_the_node_without_the_address_does_not_vote(self) -> None:
        lamp = health.object_health(self.cluster(), cluster="alpha", obj="shop", sourced=True)

        self.assertEqual(lamp.label, "1/1 up")
        self.assertEqual(lamp.tone, "healthy")
        self.assertIn("one node", lamp.detail)

    def test_without_a_source_every_node_still_counts(self) -> None:
        #
        # No source means every node leaves from its own address and every node
        # can genuinely answer, so a member down on one of them is a real
        # fault - and hiding it would be the opposite mistake.
        #
        lamp = health.object_health(self.cluster(), cluster="alpha", obj="shop", sourced=False)

        self.assertEqual(lamp.tone, "warning")
        self.assertIn("reported down by node-b", lamp.detail)

    def test_a_node_that_says_nothing_about_the_address_is_kept(self) -> None:
        rows = reading(
            node("node-a", ("mgd-shop-web", "s1", "UP"), holds_vip=True),
            node("node-b", ("mgd-shop-web", "s1", "DOWN")),
        )

        self.assertEqual(
            health.object_health(rows, cluster="alpha", obj="shop", sourced=True).tone, "warning"
        )


class WhetherAnObjectLeavesFromASource(unittest.TestCase):
    def test_a_named_source_is_one(self) -> None:
        document = "listen:\n  vip: main\n  source: office\n"

        self.assertTrue(
            health.leaves_from_source(document, default_vip="main", vip_sources={"main": ""})
        )

    def test_the_vip_carries_one_when_the_object_names_none(self) -> None:
        document = "listen:\n  vip: main\n"

        self.assertTrue(
            health.leaves_from_source(
                document, default_vip="other", vip_sources={"main": "192.0.2.25"}
            )
        )
        self.assertFalse(
            health.leaves_from_source(document, default_vip="other", vip_sources={"main": ""})
        )

    def test_an_object_naming_no_vip_takes_the_default(self) -> None:
        document = "listen:\n  protocol: http\n"

        self.assertTrue(
            health.leaves_from_source(
                document, default_vip="main", vip_sources={"main": "192.0.2.25"}
            )
        )

    def test_a_document_that_cannot_be_read_claims_no_source(self) -> None:
        #
        # The safe direction: keeping every node is one row too many, while
        # dropping one on a guess hides the half of the cluster that is fine.
        #
        self.assertFalse(
            health.leaves_from_source("not: [a document", default_vip="main", vip_sources={})
        )


class AnUncheckedServerIsNotADownOne(unittest.TestCase):
    """`no check` is what HAProxy reports where a verdict would be.

    Measured against 3.4.4 on this machine, not assumed. Counting it as "not
    up" turned a check that exists in the document but not yet on the nodes -
    added and not deployed - into a red lamp saying the pool was down.
    """

    def test_it_is_skipped_rather_than_counted_either_way(self) -> None:
        rows = reading(node("node-a", ("mgd-shop-web", "s1", "no check")))

        lamp = health.object_health(rows, cluster="alpha", obj="shop")

        self.assertEqual(lamp.tone, "unknown")
        self.assertEqual(lamp.total, 0)

    def test_a_checked_server_beside_it_still_counts(self) -> None:
        rows = reading(
            node(
                "node-a",
                ("mgd-shop-web", "s1", "UP"),
                ("mgd-shop-web", "s2", "no check"),
            )
        )

        lamp = health.object_health(rows, cluster="alpha", obj="shop")

        self.assertEqual(lamp.label, "1/1 up")
        self.assertEqual(lamp.tone, "healthy")
