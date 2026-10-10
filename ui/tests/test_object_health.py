from __future__ import annotations

import unittest
from dataclasses import dataclass
from typing import Any

from haproxy_ui import health


@dataclass
class Reading:
    cluster: str
    result: dict[str, Any]


OWNERS = {"web": "shop", "backend": "shop-web"}


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

    def backend(self, *addresses: str) -> health.BackendHealth:
        return health.BackendHealth(backend="web", nodes=(), observed_at=None, addresses=addresses)

    def test_a_runtime_name_resolves_to_the_address_in_that_position(self) -> None:
        backend = self.backend("198.51.100.10:8080", "198.51.100.11:8080")

        self.assertEqual(backend.address("s1"), "198.51.100.10:8080")
        self.assertEqual(backend.address("s2"), "198.51.100.11:8080")

    def test_a_name_beyond_the_backend_resolves_to_nothing(self) -> None:
        #
        # A backend edited since the deploy has more names than addresses, and a
        # guess there would put one member's address beside another.
        #
        backend = self.backend("198.51.100.10:8080")

        self.assertEqual(backend.address("s2"), "")
        self.assertEqual(backend.address("BACKEND"), "")
        self.assertEqual(backend.address("sx"), "")


class TheLampInTheListing(unittest.TestCase):
    """One object's backends, rolled up to what a row can show.

    The states are five and not two, and the two quiet ones carry most of the
    care: an object with no health check is unlit, and a check nothing has
    reported on is grey. Green is reserved for a check that ran and passed.
    """

    def test_every_member_up_is_green(self) -> None:
        rows = reading(node("n1", ("web", "a", "UP"), ("web", "b", "UP")))
        lamp = health.object_health(rows, cluster="alpha", obj="shop", owners=OWNERS)
        self.assertEqual(lamp.tone, "healthy")
        self.assertEqual(lamp.label, "2/2 up")

    def test_one_member_down_is_a_warning_and_not_a_failure(self) -> None:
        rows = reading(node("n1", ("web", "a", "UP"), ("web", "b", "DOWN")))
        lamp = health.object_health(rows, cluster="alpha", obj="shop", owners=OWNERS)
        self.assertEqual(lamp.tone, "warning")
        self.assertIn("1 of 2", lamp.detail)

    def test_no_member_up_is_red(self) -> None:
        rows = reading(node("n1", ("web", "a", "DOWN")))
        self.assertEqual(
            health.object_health(rows, cluster="alpha", obj="shop", owners=OWNERS).tone, "critical"
        )

    def test_the_backends_own_summary_row_is_not_a_server(self) -> None:
        #
        # `show stat` emits a BACKEND pseudo-row per proxy and the node reports
        # it beside the real ones. Counted, it made one server behind a
        # two-node cluster read as 4 - and put a row called BACKEND in a list
        # of servers.
        #
        rows = reading(
            node("n1", ("web", "s1", "UP"), ("web", "BACKEND", "UP")),
            node("n2", ("web", "s1", "UP"), ("web", "BACKEND", "UP")),
        )
        lamp = health.object_health(rows, cluster="alpha", obj="shop", owners=OWNERS)
        self.assertEqual(lamp.label, "1/1 up")
        self.assertEqual(lamp.tone, "healthy")

    def test_a_member_down_on_one_node_only_is_still_a_warning(self) -> None:
        #
        # The traffic that lands on the second node does not reach it. Averaging
        # the two nodes into "up" would hide exactly that.
        #
        rows = reading(
            node("n1", ("web", "a", "UP")),
            node("n2", ("web", "a", "DOWN")),
        )
        lamp = health.object_health(rows, cluster="alpha", obj="shop", owners=OWNERS)
        self.assertEqual(lamp.tone, "warning")
        #
        # One server, so the count stays 1 - and amber rather than red, because
        # the backend is still serving from the node that can reach it. The node
        # that cannot is named, since that is where somebody would start.
        #
        self.assertEqual(lamp.label, "0/1 up")
        self.assertIn("reported down by n2", lamp.detail)

    def test_nothing_reported_is_grey_and_never_green(self) -> None:
        lamp = health.object_health(reading(node("n1")), cluster="alpha", obj="shop", owners=OWNERS)
        self.assertEqual(lamp.tone, "unknown")
        self.assertEqual(lamp.label, "")

    def test_an_object_with_no_health_check_is_unlit(self) -> None:
        #
        # HAProxy reports an unchecked server as up, so the reading below would
        # otherwise be green - a reachability nothing measured.
        #
        rows = reading(node("n1", ("web", "a", "UP")))
        lamp = health.object_health(rows, cluster="alpha", obj="shop", checked=False, owners=OWNERS)
        self.assertEqual(lamp.tone, "unknown")
        self.assertEqual(lamp.label, "")

    def test_a_longer_object_name_keeps_its_own_servers(self) -> None:
        #
        # A backend belongs to the object the objects helper names, never to
        # one whose name it happens to start with.
        #
        rows = reading(node("n1", ("backend", "a", "DOWN")))
        mine = health.object_health(
            rows, cluster="alpha", obj="shop", others=("shop", "shop-web"), owners=OWNERS
        )
        theirs = health.object_health(
            rows, cluster="alpha", obj="shop-web", others=("shop", "shop-web"), owners=OWNERS
        )
        self.assertEqual(mine.tone, "unknown")
        self.assertEqual(theirs.tone, "critical")

    def test_another_cluster_is_not_this_one(self) -> None:
        rows = reading(node("n1", ("web", "a", "UP")), cluster="beta")
        self.assertEqual(
            health.object_health(rows, cluster="alpha", obj="shop", owners=OWNERS).tone, "unknown"
        )


if __name__ == "__main__":
    unittest.main()


class OnlyTheNodeThatCarriesTheAddressAnswers(unittest.TestCase):
    """A backend that leaves from a source address has one node that can say.

    Both nodes run the same configuration and both run the check. The one that
    does not carry the address binds it anyway - the kernel allows it - fails
    to route, and reports the backend down. That is HAProxy telling the truth
    about the binding and a lie about the backend, and it turned one healthy
    server into `0/1 up`.
    """

    def cluster(self) -> list[Reading]:
        return reading(
            node("node-a", ("web", "s1", "UP"), holds_vip=True),
            node("node-b", ("web", "s1", "DOWN"), holds_vip=False),
        )

    def test_the_node_without_the_address_does_not_vote(self) -> None:
        lamp = health.object_health(
            self.cluster(), cluster="alpha", obj="shop", sourced=True, owners=OWNERS
        )

        self.assertEqual(lamp.label, "1/1 up")
        self.assertEqual(lamp.tone, "healthy")
        self.assertIn("one node", lamp.detail)

    def test_without_a_source_every_node_still_counts(self) -> None:
        #
        # No source means every node leaves from its own address and every node
        # can genuinely answer, so a member down on one of them is a real
        # fault - and hiding it would be the opposite mistake.
        #
        lamp = health.object_health(
            self.cluster(), cluster="alpha", obj="shop", sourced=False, owners=OWNERS
        )

        self.assertEqual(lamp.tone, "warning")
        self.assertIn("reported down by node-b", lamp.detail)

    def test_a_node_that_says_nothing_about_the_address_is_kept(self) -> None:
        rows = reading(
            node("node-a", ("web", "s1", "UP"), holds_vip=True),
            node("node-b", ("web", "s1", "DOWN")),
        )

        self.assertEqual(
            health.object_health(
                rows, cluster="alpha", obj="shop", sourced=True, owners=OWNERS
            ).tone,
            "warning",
        )


class AnUncheckedServerIsNotADownOne(unittest.TestCase):
    """`no check` is what HAProxy reports where a verdict would be.

    Measured against 3.4.4 on this machine, not assumed. Counting it as "not
    up" turned a check that exists in the document but not yet on the nodes -
    added and not deployed - into a red lamp saying the backend was down.
    """

    def test_it_is_skipped_rather_than_counted_either_way(self) -> None:
        rows = reading(node("node-a", ("web", "s1", "no check")))

        lamp = health.object_health(rows, cluster="alpha", obj="shop", owners=OWNERS)

        self.assertEqual(lamp.tone, "unknown")
        self.assertEqual(lamp.total, 0)

    def test_a_checked_server_beside_it_still_counts(self) -> None:
        rows = reading(
            node(
                "node-a",
                ("web", "s1", "UP"),
                ("web", "s2", "no check"),
            )
        )

        lamp = health.object_health(rows, cluster="alpha", obj="shop", owners=OWNERS)

        self.assertEqual(lamp.label, "1/1 up")
        self.assertEqual(lamp.tone, "healthy")


class HaproxysCodesAsSentences(unittest.TestCase):
    """The machine's language on a page built for people.

    `L6RSP` cost an evening once. The sentence is what the cell shows and the
    code stays as its title, so somebody can still search for it.
    """

    def test_a_passing_check_says_what_the_server_answered(self) -> None:
        self.assertEqual(health.check_phrase("L7OK", "200"), "answered 200")

    def test_a_layer_six_refusal_names_the_layer_a_person_can_act_on(self) -> None:
        self.assertEqual(health.check_phrase("L6RSP"), "TLS: the answer was not valid")

    def test_a_code_nobody_has_translated_is_shown_as_it_stands(self) -> None:
        """Worse than a code is a sentence this file invented for one."""

        self.assertEqual(health.check_phrase("L5WAT", "7"), "L5WAT 7")

    def test_nothing_stays_nothing(self) -> None:
        self.assertEqual(health.check_phrase(""), "")


class TheStateOfEachObjectOnTheNodes(unittest.TestCase):
    """Read from the status document, never derived a second time here.

    The engine compares two release manifests and puts the answer in the
    status. A web layer that worked it out again would be the second reader
    that eventually disagrees with the first - which is the drift that made
    the comparison necessary, back when the listing and the object page each
    read the job history their own way.
    """

    def rows(self, objects: Any, cluster: str = "alpha") -> list[Reading]:
        return [Reading(cluster=cluster, result={"nodes": [], "objects": objects})]

    def test_each_object_carries_its_own_state(self) -> None:
        rows = self.rows(
            {
                "shop": {"state": "current", "parts": []},
                "intranet": {"state": "changed", "parts": ["routing"]},
            }
        )

        self.assertEqual(
            health.object_states(rows, cluster="alpha"),
            {"shop": "current", "intranet": "changed"},
        )

    def test_another_clusters_reading_is_not_borrowed(self) -> None:
        rows = self.rows({"shop": {"state": "current"}}, cluster="beta")

        self.assertEqual(health.object_states(rows, cluster="alpha"), {})

    def test_a_status_without_the_comparison_says_nothing(self) -> None:
        """Every release published before manifests existed looks like this."""

        rows = [Reading(cluster="alpha", result={"nodes": []})]

        self.assertEqual(health.object_states(rows, cluster="alpha"), {})

    def test_an_entry_that_is_not_a_state_is_left_out(self) -> None:
        rows = self.rows({"shop": {"state": 7}, "intranet": "current"})

        self.assertEqual(health.object_states(rows, cluster="alpha"), {})
