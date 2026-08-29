from __future__ import annotations

import unittest
from datetime import UTC, datetime, timedelta

from haproxy_ui.db import ClusterHistory
from haproxy_ui.history import build_history_overview

NOW = datetime(2026, 8, 29, 10, 0, tzinfo=UTC)


def reading(
    *,
    cluster: str = "alpha",
    age_seconds: int = 15,
    outcome: str = "done",
    poll_error: str | None = None,
    published: int | None = 12,
    unpublished: int | None = 0,
    versions: list[dict[str, object]] | None = None,
    truncated: bool = False,
) -> ClusterHistory:
    rows = (
        versions
        if versions is not None
        else [
            {
                "version": 12,
                "hash": "a" * 40,
                "created_at": "2026-08-28T14:02:11+00:00",
                "comment": "Add a maintenance backend",
                "current": True,
            },
            {
                "version": 11,
                "hash": "b" * 40,
                "created_at": "2026-08-27T09:41:00+00:00",
                "comment": "Initial managed configuration",
                "current": False,
            },
        ]
    )
    return ClusterHistory(
        cluster=cluster,
        observed_at=NOW - timedelta(seconds=age_seconds),
        outcome=outcome,
        result={
            "published_version": published,
            "published_hash": None
            if published is None
            else {12: "a" * 40, 11: "b" * 40}.get(published, "f" * 40),
            "current_version": 12,
            "total_versions": 12,
            "unpublished": unpublished,
            "truncated": truncated,
            "versions": rows,
        },
        warnings=[],
        error=None,
        poll_error=poll_error,
    )


def overview(row: ClusterHistory, clusters: tuple[str, ...] = ("alpha",)):
    return build_history_overview(clusters, (row,), now=NOW, stale_after=timedelta(minutes=2))


class PublishedStateTests(unittest.TestCase):
    def test_a_published_newest_version_reads_as_nothing_waiting(self) -> None:
        cluster = overview(reading()).clusters[0]

        self.assertEqual(cluster.label, "Published")
        self.assertEqual(cluster.tone, "healthy")
        self.assertEqual(cluster.published, "v12")
        self.assertEqual(cluster.unpublished, 0)
        self.assertTrue(cluster.versions[0].published)

    def test_saved_but_unpublished_versions_are_a_warning_with_a_count(self) -> None:
        cluster = overview(reading(published=11, unpublished=1)).clusters[0]

        self.assertEqual(cluster.label, "1 unpublished")
        self.assertEqual(cluster.tone, "warning")
        self.assertEqual(cluster.published, "v11")
        self.assertEqual(cluster.detail, "Published is v11 · 12 saved versions")

    def test_a_published_release_outside_the_listing_is_not_called_current(self) -> None:
        #
        # `unpublished` is null when the published commit is not among the shown
        # versions. Rendering that as "0 waiting" would be the reassuring guess.
        #
        cluster = overview(reading(published=3, unpublished=None)).clusters[0]

        self.assertEqual(cluster.tone, "warning")
        self.assertEqual(cluster.label, "Published is older")
        self.assertIn("not in this listing", cluster.detail)

    def test_nothing_published_is_unknown_rather_than_healthy_or_broken(self) -> None:
        cluster = overview(reading(published=None, unpublished=2)).clusters[0]

        self.assertEqual(cluster.tone, "unknown")
        self.assertEqual(cluster.published, "—")
        self.assertEqual(cluster.label, "Nothing published")


class FreshnessAndFailureTests(unittest.TestCase):
    def test_a_stale_listing_is_never_presented_as_current(self) -> None:
        cluster = overview(reading(age_seconds=600)).clusters[0]

        self.assertTrue(cluster.stale)
        self.assertEqual(cluster.label, "Stale data")
        self.assertEqual(cluster.tone, "warning")

    def test_a_poll_failure_and_a_helper_failure_are_told_apart(self) -> None:
        poll = overview(reading(poll_error="sudo refused")).clusters[0]
        helper = overview(reading(outcome="failed")).clusters[0]

        self.assertEqual(poll.label, "Collection unavailable")
        self.assertEqual(helper.label, "History unavailable")
        self.assertEqual((poll.tone, helper.tone), ("critical", "critical"))

    def test_a_cluster_without_a_row_yet_is_shown_as_waiting_not_as_broken(self) -> None:
        view = build_history_overview(
            ("alpha", "beta"), (reading(),), now=NOW, stale_after=timedelta(minutes=2)
        )
        beta = view.clusters[1]

        self.assertEqual(beta.cluster, "beta")
        self.assertEqual(beta.label, "No history yet")
        self.assertEqual(beta.tone, "unknown")
        self.assertEqual(beta.age_label, "Never")

    def test_a_cached_cluster_that_is_no_longer_configured_is_still_shown(self) -> None:
        view = build_history_overview((), (reading(),), now=NOW, stale_after=timedelta(minutes=2))

        self.assertEqual(len(view.clusters), 1)
        self.assertFalse(view.clusters[0].configured)


class RenderingTests(unittest.TestCase):
    def test_versions_are_labelled_and_commits_shortened_for_reading(self) -> None:
        version = overview(reading()).clusters[0].versions[0]

        self.assertEqual(version.version, "v12")
        self.assertEqual(version.commit, "a" * 12)
        self.assertEqual(version.comment, "Add a maintenance backend")
        self.assertEqual(version.date, "2026-08-28 14:02")
        self.assertTrue(version.current)

    def test_a_version_without_a_number_is_dropped_rather_than_guessed(self) -> None:
        cluster = overview(
            reading(versions=[{"hash": "c" * 40, "created_at": "2026-08-01T09:00:00+00:00"}])
        ).clusters[0]

        self.assertEqual(cluster.versions, ())

    def test_an_empty_comment_is_named_rather_than_left_blank(self) -> None:
        cluster = overview(
            reading(versions=[{"version": 4, "hash": "d" * 40, "created_at": "x", "comment": ""}])
        ).clusters[0]

        self.assertEqual(cluster.versions[0].comment, "(no comment)")

    def test_the_totals_count_clusters_and_everything_waiting(self) -> None:
        view = build_history_overview(
            ("alpha", "beta"),
            (
                reading(published=11, unpublished=1),
                reading(cluster="beta", published=None, unpublished=3),
            ),
            now=NOW,
            stale_after=timedelta(minutes=2),
        )

        self.assertEqual(view.cluster_count, 2)
        self.assertEqual(view.published_count, 1)
        self.assertEqual(view.waiting_count, 4)

    def test_the_card_states_the_saved_count_rather_than_restating_the_badge(self) -> None:
        #
        # The badge already says "Published" and the row inside the table marks
        # which version it is. A sentence repeating either spends space without
        # adding anything, so it carries the one fact neither of them shows.
        #
        cluster = overview(reading()).clusters[0]

        self.assertEqual(cluster.label, "Published")
        self.assertEqual(cluster.detail, "12 saved versions")
        self.assertEqual(cluster.total, 12)

    def test_a_single_saved_version_is_not_pluralised(self) -> None:
        row = reading(published=None, unpublished=1)
        row.result["total_versions"] = 1
        cluster = overview(row).clusters[0]

        self.assertEqual(cluster.detail, "1 saved version, none published")

    def test_a_truncated_listing_says_so(self) -> None:
        self.assertTrue(overview(reading(truncated=True)).clusters[0].truncated)


if __name__ == "__main__":
    unittest.main()
