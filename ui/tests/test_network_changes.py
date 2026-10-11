"""What a saved network description changes, and who it reaches (B277)."""

from __future__ import annotations

import unittest
from typing import Any

from haprion_ui.network import NetworkChange, Usage, changes
from haprion_ui.views import TEMPLATES

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
        self.assertIn('href="/proxies?cluster=alpha&amp;source=192.0.2.30">2 objects</a>', many)

    def test_a_removal_in_use_says_the_publish_is_refused(self) -> None:
        text = self.line(NetworkChange("vip", "mail", "removed", ("smtp",), "mail", True))

        self.assertIn("(publish will be refused)", text)


if __name__ == "__main__":
    unittest.main()
