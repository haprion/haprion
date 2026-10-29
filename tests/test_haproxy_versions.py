"""Which nodes run an older HAProxy than they should (Fas 16 punkt 3b)."""

from __future__ import annotations

import itertools
import shutil
import subprocess
import unittest

from haprion.haproxy_versions import (
    against_carried,
    compare,
    node_package_standing,
    notes,
    package_notes,
    upstream,
)


class TheUpstreamPart(unittest.TestCase):
    def test_a_package_version_is_compared_by_its_upstream_release(self) -> None:
        self.assertEqual(upstream("3.4.6-1ppa1~resolute"), "3.4.6")
        self.assertEqual(upstream("3.2.9"), "3.2.9")
        for value in (None, "", "dev", 3):
            with self.subTest(value=value):
                self.assertIsNone(upstream(value))


class TheNotes(unittest.TestCase):
    def test_one_version_and_an_older_validator_say_nothing(self) -> None:
        self.assertEqual(notes({"a": "3.4.6-1", "b": "3.4.6-1"}, "3.4.4-1"), {})

    def test_a_node_behind_the_cluster_s_newest_is_named(self) -> None:
        self.assertEqual(
            notes({"a": "3.4.6-1", "b": "3.4.4-1", "c": "3.4.10-1"}),
            {"a": "Older than 3.4.10", "b": "Older than 3.4.10"},
        )

    def test_a_validator_newer_than_the_nodes_is_named_on_each(self) -> None:
        self.assertEqual(
            notes({"a": "3.4.4-1", "b": "3.4.4-1"}, "3.4.6-1ppa1~resolute"),
            {"a": "Manager validates with 3.4.6", "b": "Manager validates with 3.4.6"},
        )

    def test_a_node_whose_version_is_unknown_is_not_judged(self) -> None:
        self.assertEqual(notes({"a": "3.4.6-1", "b": None}, None), {})


#
# Versions as the nodes report them - a PPA's, PowerDNS's, Ubuntu's security
# revisions, ours - and the corners of dpkg's order: epochs, `~`, `+`, a
# letter against nothing, a revision against none.
#
VERSIONS = (
    "3.4.6-1ppa1~resolute",
    "3.4.6-1ppa2~resolute",
    "3.4.7-1ppa1~resolute",
    "3.4.6-1ppa1",
    "3.0.13-0ubuntu3.4",
    "3.0.13-0ubuntu3.5",
    "3.0.13-0ubuntu3.10",
    "2.1.2-1pdns.ubuntu26.04",
    "2.1.10-1pdns.ubuntu26.04",
    "0.9.0-4",
    "0.9.0-10",
    "1:2.0",
    "2.0-1",
    "2.0~rc1-1",
    "2.0-1~bpo1",
    "1.0",
    "1.0a",
    "1.0+b1",
    "1.0.0",
    "1.0-0",
)


DPKG = shutil.which("dpkg") or ""


def dpkg_order(left: str, right: str) -> int:
    """The reference: what `dpkg --compare-versions` says of the pair."""

    def holds(relation: str) -> bool:
        return (
            subprocess.run(  # the installed dpkg, versions from this file
                [DPKG, "--compare-versions", left, relation, right], check=False
            ).returncode
            == 0
        )

    return -1 if holds("lt") else 1 if holds("gt") else 0


class DpkgOrder(unittest.TestCase):
    """26-10-09: a security update often changes only the revision."""

    @unittest.skipUnless(DPKG, "dpkg is not installed where the tests run")
    def test_every_pair_is_ordered_as_dpkg_orders_it(self) -> None:
        for left, right in itertools.product(VERSIONS, VERSIONS):
            with self.subTest(left=left, right=right):
                self.assertEqual(compare(left, right), dpkg_order(left, right))

    def test_the_epoch_is_what_comes_before_the_first_colon(self) -> None:
        """Review 26-10-29: an upstream version with a colon of its own took the epoch with it."""

        self.assertEqual(compare("1:1.0:2-1", "2.0-1"), 1)
        self.assertEqual(compare("1:1.0:2-1", "1:1.0:10-1"), -1)

    def test_a_revision_alone_orders_them(self) -> None:
        self.assertEqual(compare("3.0.13-0ubuntu3.4", "3.0.13-0ubuntu3.10"), -1)
        self.assertEqual(compare("3.4.6-1ppa2~resolute", "3.4.6-1ppa1~resolute"), 1)


class ThePackageNotes(unittest.TestCase):
    def test_a_node_a_day_behind_its_partner_is_named_per_package(self) -> None:
        found = package_notes(
            {
                "a": {"keepalived": "2.3.4-1", "openssl": "3.5.5-1ubuntu3.10", "dnsdist": None},
                "b": {"keepalived": "2.3.3-1", "openssl": "3.5.5-1ubuntu3.7", "dnsdist": "2.1.2"},
            }
        )

        self.assertEqual(
            found,
            {"b": ["keepalived older than 2.3.4-1", "OpenSSL older than 3.5.5-1ubuntu3.10"]},
        )

    def test_a_node_from_before_the_field_is_not_judged(self) -> None:
        self.assertEqual(package_notes({"a": {"keepalived": "2.3.4-1"}, "b": None}), {})

    def test_a_process_already_behind_does_not_say_its_package_too(self) -> None:
        said = notes(
            {"a": "3.4.7-1ppa1~resolute", "b": "3.4.6-1ppa1~resolute"},
            None,
            {
                "a": {"haproxy": "3.4.7-1ppa1~resolute", "keepalived": "2.3.4-1"},
                "b": {"haproxy": "3.4.6-1ppa1~resolute", "keepalived": "2.3.3-1"},
            },
        )

        self.assertEqual(said, {"b": "Older than 3.4.7 · keepalived older than 2.3.4-1"})

    def test_a_rebuild_of_the_same_release_shows_in_the_package_only(self) -> None:
        said = notes(
            {"a": "3.4.6-1ppa2~resolute", "b": "3.4.6-1ppa1~resolute"},
            None,
            {"a": {"haproxy": "3.4.6-1ppa2~resolute"}, "b": {"haproxy": "3.4.6-1ppa1~resolute"}},
        )

        self.assertEqual(said, {"b": "HAProxy package older than 3.4.6-1ppa2~resolute"})


class ANodeAgainstTheCarriedPackage(unittest.TestCase):
    CARRIED = "0.99.6+git20261029120000.0123456789ab"

    def test_the_same_version_says_nothing(self) -> None:
        self.assertIsNone(against_carried({"version": self.CARRIED}, self.CARRIED))

    def test_older_and_newer_are_ordered_as_dpkg_orders_them(self) -> None:
        older = "0.99.5+git20261028210223.49d2aeb20207"
        newer = "0.99.10+git20261101090000.89abcdef0123"
        self.assertEqual(against_carried({"version": older}, self.CARRIED), (older, -1))
        self.assertEqual(against_carried({"version": newer}, self.CARRIED), (newer, 1))

    def test_a_node_reporting_no_version_runs_an_older_package(self) -> None:
        self.assertEqual(against_carried({"node_api": 1}, self.CARRIED), (None, -1))
        self.assertEqual(against_carried(None, self.CARRIED), (None, -1))

    def test_nothing_is_said_without_a_carried_version_or_an_installed_package(self) -> None:
        self.assertIsNone(against_carried({"version": self.CARRIED}, None))
        self.assertIsNone(against_carried(None, None))
        self.assertIsNone(against_carried({"version": None}, self.CARRIED))


class HowANodePackageStands(unittest.TestCase):
    """Review 26-10-29, AA03: one reading for the dashboard, `haprion-status` and the check.

    Each read `configured` its own way, and the check not at all: a package
    dpkg did not configure, at the right version, passed it unsaid.
    """

    CARRIED = "0.99.6+git20261029120000.0123456789ab"

    def test_a_package_dpkg_did_not_configure_comes_before_its_version(self) -> None:
        older = "0.99.5+git20261028210223.49d2aeb20207"
        for version in (self.CARRIED, older):
            with self.subTest(version=version):
                standing = node_package_standing(
                    {"version": version, "configured": False}, self.CARRIED
                )
                self.assertIsNotNone(standing)
                if standing is not None:
                    self.assertEqual(
                        (standing.kind, standing.installed), ("not configured", version)
                    )
        self.assertEqual(
            node_package_standing({"version": self.CARRIED, "configured": False}, None),
            node_package_standing({"version": self.CARRIED, "configured": False}, self.CARRIED),
        )

    def test_otherwise_it_is_the_order_against_the_carried_package(self) -> None:
        older = "0.99.5+git20261028210223.49d2aeb20207"
        newer = "0.99.10+git20261101090000.89abcdef0123"
        for installation, expected in (
            ({"version": older, "configured": True}, ("older", older)),
            ({"version": newer}, ("newer", newer)),
            ({"node_api": 1}, ("older", None)),
        ):
            with self.subTest(installation=installation):
                standing = node_package_standing(installation, self.CARRIED)
                self.assertEqual(
                    (standing.kind, standing.installed) if standing else None, expected
                )
        unsaid: tuple[dict[str, object], ...] = (
            {"version": self.CARRIED},
            {"version": None, "configured": False},
        )
        for same in unsaid:
            with self.subTest(installation=same):
                self.assertIsNone(node_package_standing(same, self.CARRIED))


if __name__ == "__main__":
    unittest.main()
