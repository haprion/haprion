"""The shared version-history read model.

The number an operator cares about is not in the listing: it is how many saved
versions are newer than the published one. That is derived here, once, for both
`haproxy-list --json` and the interface's helper - so these tests are where a
wrong derivation is caught before two readers disagree about whether a cluster
has anything waiting to go out.
"""

from __future__ import annotations

import unittest
from datetime import UTC, datetime

from haproxy_mgmt.deploy_plan import ReleaseTarget
from haproxy_mgmt.history import history_result, summary_line
from haproxy_mgmt.version_history import LIST_LIMIT, VersionSummary

WHEN = datetime(2026, 8, 29, 12, 0, tzinfo=UTC)


def versions(count: int, *, top: int | None = None) -> tuple[VersionSummary, ...]:
    """`count` versions, newest first, numbered down from `top`."""

    highest = top if top is not None else count
    return tuple(
        VersionSummary(
            version=highest - offset,
            commit=f"{highest - offset:040d}",
            date="2026-01-02 03:04",
            created_at="2026-01-02T03:04:05+00:00",
            comment=f"Change {highest - offset}",
        )
        for offset in range(count)
    )


def commit_of(version: int) -> str:
    return f"{version:040d}"


class PublishedMarkingTests(unittest.TestCase):
    def test_the_published_version_is_marked_by_hash_not_by_number(self) -> None:
        #
        # After a history reset an old number can name a different commit. The
        # hash is what the nodes were actually given, so it is what decides.
        #
        target = ReleaseTarget(version=2, hash="f" * 40)
        result = history_result(versions(3), target, generated_at=WHEN)

        self.assertEqual([row["current"] for row in result["versions"]], [True, False, False])
        self.assertIsNone(result["unpublished"])
        self.assertIn("older than this listing", summary_line(result))

    def test_the_newest_saved_version_is_the_current_one_not_the_published_one(self) -> None:
        #
        # The frozen schema's `current` is "what a publish would build on". A
        # cluster with unpublished work has a current version that is not live,
        # and conflating the two would tell an operator the opposite.
        #
        result = history_result(
            versions(3), ReleaseTarget(version=1, hash=commit_of(1)), generated_at=WHEN
        )

        self.assertEqual(result["current_version"], 3)
        self.assertEqual(result["published_version"], 1)
        self.assertTrue(result["versions"][0]["current"])

    def test_a_published_release_inside_the_listing_is_marked_once(self) -> None:
        result = history_result(
            versions(3), ReleaseTarget(version=2, hash=commit_of(2)), generated_at=WHEN
        )

        self.assertEqual(result["unpublished"], 1)
        self.assertEqual(result["published_version"], 2)
        self.assertEqual(result["current_version"], 3)
        self.assertEqual(result["total_versions"], 3)

    def test_the_newest_version_being_published_counts_nothing_as_waiting(self) -> None:
        result = history_result(
            versions(3), ReleaseTarget(version=3, hash=commit_of(3)), generated_at=WHEN
        )

        self.assertEqual(result["unpublished"], 0)
        self.assertIn("is the newest saved", summary_line(result))


class EmptyAndBoundaryTests(unittest.TestCase):
    def test_nothing_published_leaves_every_saved_version_waiting(self) -> None:
        result = history_result(versions(2), None, generated_at=WHEN)

        self.assertIsNone(result["published_version"])
        self.assertIsNone(result["published_hash"])
        self.assertEqual(result["unpublished"], 2)
        self.assertEqual(summary_line(result), "No version has been published yet.")

    def test_a_repository_without_a_single_version_is_a_result_not_an_error(self) -> None:
        result = history_result((), None, generated_at=WHEN)

        self.assertEqual(result["versions"], [])
        self.assertIsNone(result["current_version"])
        self.assertEqual(result["total_versions"], 0)
        self.assertIsNone(result["unpublished"])
        self.assertFalse(result["truncated"])

    def test_a_full_listing_says_it_may_not_be_the_whole_history(self) -> None:
        full = history_result(versions(LIST_LIMIT, top=40), None, generated_at=WHEN)
        short = history_result(versions(LIST_LIMIT - 1, top=40), None, generated_at=WHEN)

        self.assertTrue(full["truncated"])
        self.assertFalse(short["truncated"])

    def test_the_timestamp_is_the_z_form_the_other_helpers_emit(self) -> None:
        result = history_result((), None, generated_at=WHEN)

        self.assertEqual(result["generated_at"], "2026-08-29T12:00:00Z")


if __name__ == "__main__":
    unittest.main()
