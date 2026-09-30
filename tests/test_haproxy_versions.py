"""Which nodes run an older HAProxy than they should (Fas 16 punkt 3b)."""

from __future__ import annotations

import unittest

from haproxy_mgmt.haproxy_versions import notes, upstream


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


if __name__ == "__main__":
    unittest.main()
