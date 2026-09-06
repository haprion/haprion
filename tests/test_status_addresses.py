"""What the manager makes of the three address measurements a node reports.

The node measures; this decides what the measurements mean for a deploy. The
question is only ever "does this node carry the address list its release
publishes", and the third answer - nobody measured it - has to survive as its
own answer. A node that cannot be asked must not be counted as verified, and a
release that publishes no list must not read as an instruction to empty the
node's.
"""

from __future__ import annotations

import unittest

from haproxy_mgmt.cluster_status import parse_status

PUBLISHED = "a1" * 32
OTHER = "b2" * 32


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


def node_status(keepalived: object) -> dict[str, object]:
    return {
        "schema_version": 1,
        "node": "node-a",
        "cluster": "alpha",
        "haproxy": {"active": True},
        "keepalived": keepalived,
        "vip": {"address": "192.0.2.10", "interface": "eth0", "owner": True},
        "ip_nonlocal_bind": True,
        "release": None,
        "config_validation": {"ok": True},
        "stats_ok": True,
        "runtime": {"version": "3.4.4", "uptime_sec": 10},
        "certificates": [],
    }


def addresses(**fields: object) -> dict[str, object]:
    reported: dict[str, object] = {
        "published": True,
        "published_sha256": PUBLISHED,
        "installed": True,
        "installed_sha256": PUBLISHED,
        "included": True,
    }
    reported.update(fields)
    return {"active": True, "state": "MASTER", "addresses": reported}


class WhatTheAddressMeasurementsMean(unittest.TestCase):
    def node(self, keepalived: object):
        return parse_status(envelope(node_status(keepalived))).nodes[0]

    def test_the_published_list_carried_by_the_node_is_current(self) -> None:
        self.assertIs(self.node(addresses()).addresses_current, True)

    def test_a_different_list_from_the_one_published_is_behind(self) -> None:
        node = self.node(addresses(installed_sha256=OTHER))

        self.assertIs(node.addresses_current, False)

    def test_a_release_that_publishes_no_list_leaves_the_node_current(self) -> None:
        """Not managed from here is not the same as wrong.

        A cluster whose repository predates the generated address list must not
        be reconciled forever over a file it never publishes.
        """

        node = self.node(
            addresses(
                published=False, published_sha256=None, installed=False, installed_sha256=None
            )
        )

        self.assertIs(node.addresses_current, True)

    def test_a_published_list_the_node_never_installed_is_behind(self) -> None:
        node = self.node(addresses(installed=False, installed_sha256=None))

        self.assertIs(node.addresses_current, False)

    def test_a_file_that_could_not_be_read_is_unknown_and_not_behind(self) -> None:
        """`installed` is None only when the node could not tell.

        Behind is a measured answer that a deploy repairs. Unknown is the
        absence of an answer, and the difference is what keeps an unverifiable
        node from being reported as verified.
        """

        node = self.node(addresses(installed=None, installed_sha256=None))

        self.assertIsNone(node.addresses_current)

    def test_a_node_that_reported_no_addresses_at_all_is_unknown(self) -> None:
        """An older status script, which says nothing rather than saying none."""

        node = self.node({"active": True, "state": "MASTER"})

        self.assertIsNone(node.addresses_current)
        self.assertIsNone(node.addresses_included)

    def test_the_include_is_reported_and_never_folded_into_the_comparison(self) -> None:
        """The include line is a person's step, one node at a time.

        The node deploy exits 0 without it, so a deploy that treated it as a
        target would try forever to reach a state only a human can put it in.
        """

        node = self.node(addresses(included=False))

        self.assertIs(node.addresses_current, True)
        self.assertIs(node.addresses_included, False)


if __name__ == "__main__":
    unittest.main()
