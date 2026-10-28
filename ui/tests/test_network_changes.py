"""What a saved network description changes, and who it reaches (B277)."""

from __future__ import annotations

import unittest
from types import SimpleNamespace
from typing import Any
from unittest import mock

from haprion_ui import views
from haprion_ui.network import NetworkChange, Usage, changes
from haprion_ui.templates import TEMPLATES

PUBLISHED: dict[str, Any] = {
    "default_vip": "web",
    "vips": [
        {"name": "web", "address": "192.0.2.10", "source": "192.0.2.11", "tls": None},
        {"name": "mail", "address": "192.0.2.20", "source": None, "tls": None},
    ],
    "sources": [{"name": "egress-2", "address": "192.0.2.30"}],
    "groups": [{"name": "office", "members": ["198.51.100.0/24"]}],
}
USE = Usage(
    vips={"web": ("admin", "shop"), "mail": ("smtp",)},
    sources={"192.0.2.30": ("billing",)},
    groups={"office": ("admin",)},
)


def saved(**overrides: Any) -> dict[str, Any]:
    return {**PUBLISHED, **overrides}


def found(document: dict[str, Any]) -> dict[str, NetworkChange]:
    return {change.label: change for change in changes(PUBLISHED, document, USE)}


class EachKindOfChange(unittest.TestCase):
    def test_nothing_changed_is_nothing(self) -> None:
        self.assertEqual(changes(PUBLISHED, saved(), USE), ())

    def test_a_vip_changed_three_ways_is_one_line_with_its_users(self) -> None:
        document = saved(
            vips=[
                {"name": "web", "address": "192.0.2.12", "source": "192.0.2.13", "tls": "modern"},
                PUBLISHED["vips"][1],
            ]
        )

        change = found(document)["VIP web"]

        self.assertEqual(change.what, "address changed, source changed, TLS policy changed")
        self.assertEqual(change.users, ("admin", "shop"))
        self.assertFalse(change.refused)

    def test_a_new_default_is_said_on_the_vip_that_becomes_it(self) -> None:
        self.assertEqual(found(saved(default_vip="mail"))["VIP mail"].what, "made the default")

    def test_removing_what_is_used_is_marked_and_adding_has_no_users(self) -> None:
        document = saved(
            vips=[PUBLISHED["vips"][0], {"name": "api", "address": "192.0.2.40"}],
            sources=[],
            groups=[],
        )

        result = found(document)

        self.assertTrue(result["VIP mail"].refused)
        self.assertEqual(result["VIP api"].what, "added")
        self.assertEqual(result["VIP api"].users, ())
        self.assertTrue(result["Source egress-2"].refused)
        self.assertEqual(result["Source egress-2"].match, "192.0.2.30")
        self.assertTrue(result["Group office"].refused)

    def test_http3_turned_on_is_said_and_absent_is_off(self) -> None:
        document = saved(vips=[{**PUBLISHED["vips"][0], "http3": True}, PUBLISHED["vips"][1]])

        self.assertEqual(found(document)["VIP web"].what, "HTTP/3 turned on")
        self.assertEqual(
            changes(
                saved(vips=[{**PUBLISHED["vips"][0], "http3": False}, PUBLISHED["vips"][1]]),
                PUBLISHED,
                USE,
            ),
            (),
        )

    def test_a_source_moved_and_a_group_widened(self) -> None:
        document = saved(
            sources=[{"name": "egress-2", "address": "192.0.2.31"}],
            groups=[{"name": "office", "members": ["198.51.100.0/24", "203.0.113.0/24"]}],
        )

        result = found(document)

        self.assertEqual(result["Source egress-2"].what, "address changed")
        self.assertEqual(result["Source egress-2"].users, ("billing",))
        self.assertEqual(result["Group office"].what, "members changed")
        self.assertEqual(result["Group office"].users, ("admin",))


class TheLineUnderTheRow(unittest.TestCase):
    def line(self, change: NetworkChange) -> str:
        macro = TEMPLATES.env.get_template("_network-change.html").module.network_change  # type: ignore[attr-defined]
        return str(macro(change, "alpha"))

    def test_one_user_is_named_and_more_are_a_count_into_the_listing(self) -> None:
        one = self.line(NetworkChange("group", "office", "members changed", ("admin",), "office"))
        many = self.line(
            NetworkChange("source", "egress-2", "address changed", ("a", "b"), "192.0.2.30")
        )

        self.assertIn('<a href="/proxies/alpha/admin">admin</a>', one)
        self.assertIn('href="/proxies?cluster=alpha&amp;source=192.0.2.30">2 proxies</a>', many)

    def test_a_removal_in_use_says_the_publish_is_refused(self) -> None:
        text = self.line(NetworkChange("vip", "mail", "removed", ("smtp",), "mail", True))

        self.assertIn("(publish will be refused)", text)


OBJECT = """schema: 1
name: {name}
hostnames: [{name}.example.com]
listen:
  protocol: http
  vip: {vip}
routes:
  - path: /
    backend: web
backends:
  web:
    balance: roundrobin
    servers:
      - host: 192.0.2.50
        port: 8080
"""


class TheUsersAreThoseThePublishLeaves(unittest.TestCase):
    """26-10-11: moving the object off a removed VIP in the same publish clears the warning."""

    READING = {
        "default_vip": "web",
        "ownership_vip": "",
        "vips": [
            {"name": "web", "address": "192.0.2.10", "source": None, "tls": None},
            {"name": "old", "address": "192.0.2.20", "source": None, "tls": None},
        ],
        "sources": [],
        "groups": [],
    }
    SAVED_NETWORK = (
        "vips:\n  web:\n    address: 192.0.2.10\n  new:\n    address: 192.0.2.30\n"
        "default_vip: web\n"
    )

    def changes_with(self, saved_objects: list[Any]) -> dict[str, Any]:
        reading = SimpleNamespace(cluster="alpha", outcome="done", result=self.READING)
        state: Any = SimpleNamespace(
            stored=[SimpleNamespace(name="admin", document=OBJECT.format(name="admin", vip="old"))]
        )
        with mock.patch.object(views, "read_source", return_value=((), [reading])):
            found = views._network_changes(
                mock.Mock(), mock.Mock(), "alpha", self.SAVED_NETWORK, state, saved_objects
            )
        return {change.label: change for change in found}

    def test_an_object_still_on_the_removed_vip_is_named_and_refused(self) -> None:
        removed = self.changes_with([])["VIP old"]

        self.assertEqual(removed.users, ("admin",))
        self.assertTrue(removed.refused)

    def test_an_object_moved_off_it_in_the_same_publish_clears_it(self) -> None:
        moved = SimpleNamespace(
            object_id="admin",
            yaml=OBJECT.format(name="admin", vip="new"),
            deleted=False,
            replaces=None,
        )

        result = self.changes_with([moved])

        self.assertEqual(result["VIP old"].users, ())
        self.assertFalse(result["VIP old"].refused)
        self.assertEqual(result["VIP new"].what, "added")

    def test_an_object_removed_in_the_same_publish_clears_it_too(self) -> None:
        gone = SimpleNamespace(object_id="admin", yaml="", deleted=True, replaces=None)

        self.assertFalse(self.changes_with([gone])["VIP old"].refused)


if __name__ == "__main__":
    unittest.main()
