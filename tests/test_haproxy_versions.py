"""Which nodes run an older HAProxy than they should (Fas 16 punkt 3b)."""

from __future__ import annotations

import itertools
import shutil
import subprocess
import unittest

from haprion.haproxy_versions import compare, notes, package_notes, upstream


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
            {"a": "Behind 3.4.10", "b": "Behind 3.4.10"},
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
            {"b": ["keepalived behind 2.3.4-1", "OpenSSL behind 3.5.5-1ubuntu3.10"]},
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

        self.assertEqual(said, {"b": "Behind 3.4.7 · keepalived behind 2.3.4-1"})

    def test_a_rebuild_of_the_same_release_shows_in_the_package_only(self) -> None:
        said = notes(
            {"a": "3.4.6-1ppa2~resolute", "b": "3.4.6-1ppa1~resolute"},
            None,
            {"a": {"haproxy": "3.4.6-1ppa2~resolute"}, "b": {"haproxy": "3.4.6-1ppa1~resolute"}},
        )

        self.assertEqual(said, {"b": "HAProxy package behind 3.4.6-1ppa2~resolute"})


if __name__ == "__main__":
    unittest.main()
