"""What the backup page says, and which quiet states it refuses to render calmly.

The state worth testing hardest is the one that looks fine: a node that reports
no error, holds no archive, and would render as an ordinary row. It is the worst
state on the page, and the tests below pin it as such.
"""

from __future__ import annotations

import unittest
from datetime import UTC, datetime, timedelta

from haproxy_ui.backups import build_backup_overview
from haproxy_ui.db import ClusterBackups

NOW = datetime(2026, 8, 29, 10, 0, tzinfo=UTC)
STALE_AFTER = timedelta(minutes=2)


def archives(count: int = 3, *, newest_hours_ago: int = 5) -> list[dict[str, object]]:
    newest = NOW - timedelta(hours=newest_hours_ago)
    return [
        {
            "version": (newest - timedelta(days=day)).strftime("%Y-%m-%d_%H-%M-%S"),
            "created_at": (newest - timedelta(days=day)).isoformat().replace("+00:00", "Z"),
            "size_bytes": 28672,
            "latest": day == 0,
        }
        for day in range(count)
    ]


def node(
    name: str = "node-a",
    *,
    available: bool = True,
    backups: list[dict[str, object]] | None = None,
    error: str | None = None,
) -> dict[str, object]:
    listed = archives() if backups is None else backups
    return {
        "name": name,
        "available": available,
        "latest_version": listed[0]["version"] if listed else None,
        "backups": listed,
        "error": {"message": error} if error else None,
    }


def reading(
    *,
    cluster: str = "alpha",
    age_seconds: int = 15,
    outcome: str = "done",
    poll_error: str | None = None,
    nodes: list[dict[str, object]] | None = None,
    limit: int | None = 10,
) -> ClusterBackups:
    return ClusterBackups(
        cluster=cluster,
        observed_at=NOW - timedelta(seconds=age_seconds),
        outcome=outcome,
        result={"limit": limit, "nodes": [node(), node("node-b")] if nodes is None else nodes},
        warnings=[],
        error=None,
        poll_error=poll_error,
    )


def overview(*readings: ClusterBackups, clusters: tuple[str, ...] = ("alpha",)):
    return build_backup_overview(clusters, readings, now=NOW, stale_after=STALE_AFTER)


class NodeStateTests(unittest.TestCase):
    def test_a_node_holding_nothing_is_as_serious_as_one_that_cannot_be_read(self) -> None:
        #
        # No error, no archives, a row that renders fine. It is the state the
        # page exists to catch, so it is not allowed to look ordinary.
        #
        empty = overview(reading(nodes=[node("node-a", backups=[])])).clusters[0].nodes[0]
        unreadable = (
            overview(reading(nodes=[node("node-b", available=False, error="permission denied")]))
            .clusters[0]
            .nodes[0]
        )

        self.assertEqual(empty.tone, "critical")
        self.assertEqual(empty.label, "No backups")
        self.assertEqual(unreadable.tone, "critical")
        self.assertEqual(unreadable.detail, "permission denied")

    def test_a_missed_run_warns_and_a_week_without_one_does_not(self) -> None:
        overdue = (
            overview(reading(nodes=[node(backups=archives(newest_hours_ago=40))]))
            .clusters[0]
            .nodes[0]
        )
        abandoned = (
            overview(reading(nodes=[node(backups=archives(newest_hours_ago=24 * 9))]))
            .clusters[0]
            .nodes[0]
        )

        self.assertEqual(overdue.tone, "warning")
        self.assertEqual(overdue.label, "Backup overdue")
        self.assertEqual(abandoned.tone, "critical")
        self.assertEqual(abandoned.label, "Stale backups")

    def test_age_is_measured_from_the_archive_not_from_the_name(self) -> None:
        #
        # `latest_version` names an archive and the timestamp lives on the
        # entry. A node must not be reported as fresh on the strength of a name.
        #
        listing = node(backups=archives(newest_hours_ago=24 * 4))
        listing["latest_version"] = NOW.strftime("%Y-%m-%d_%H-%M-%S")

        view = overview(reading(nodes=[listing])).clusters[0].nodes[0]

        self.assertEqual(view.tone, "warning")
        self.assertEqual(view.age_label, "4d ago")

    def test_a_healthy_node_says_how_much_it_is_keeping(self) -> None:
        view = overview(reading(nodes=[node(backups=archives(4))])).clusters[0].nodes[0]

        self.assertEqual(view.tone, "healthy")
        self.assertEqual(view.count, 4)
        self.assertEqual(view.detail, "4 archives kept")
        self.assertEqual(view.total_size, "112 KiB")


class ClusterBadgeTests(unittest.TestCase):
    def test_the_worst_node_decides_the_badge_and_is_named(self) -> None:
        cluster = overview(reading(nodes=[node("node-a"), node("node-b", backups=[])])).clusters[0]

        self.assertEqual(cluster.tone, "critical")
        self.assertEqual(cluster.label, "node-b: no backups")

    def test_a_cluster_backed_up_everywhere_says_so_once(self) -> None:
        cluster = overview(reading()).clusters[0]

        self.assertEqual(cluster.tone, "healthy")
        self.assertEqual(cluster.label, "Current")

    def test_a_partial_listing_is_rendered_rather_than_discarded(self) -> None:
        #
        # Partial means one node answered and another did not. That is exactly
        # what the page is for, so it must not become an empty card.
        #
        cluster = overview(
            reading(
                outcome="partial",
                nodes=[node("node-a"), node("node-b", available=False, error="host unreachable")],
            )
        ).clusters[0]

        self.assertEqual(len(cluster.nodes), 2)
        self.assertEqual(cluster.tone, "critical")
        self.assertEqual(cluster.nodes[0].tone, "healthy")

    def test_a_failed_read_and_a_failed_poll_are_told_apart(self) -> None:
        failed = overview(reading(outcome="failed")).clusters[0]
        unpolled = overview(reading(poll_error="sudo refused")).clusters[0]

        self.assertEqual(failed.label, "Backups unavailable")
        self.assertEqual(unpolled.label, "Collection unavailable")

    def test_old_data_is_marked_stale_before_it_is_believed(self) -> None:
        cluster = overview(reading(age_seconds=600)).clusters[0]

        self.assertTrue(cluster.stale)
        self.assertEqual(cluster.label, "Stale data")

    def test_a_configured_cluster_without_a_reading_still_renders(self) -> None:
        view = build_backup_overview(
            ("alpha", "beta"), (reading(),), now=NOW, stale_after=STALE_AFTER
        )

        self.assertEqual([cluster.cluster for cluster in view.clusters], ["alpha", "beta"])
        self.assertEqual(view.clusters[1].label, "No backup data yet")

    def test_a_reading_for_a_cluster_no_longer_configured_is_still_shown(self) -> None:
        view = build_backup_overview(
            (), (reading(cluster="beta"),), now=NOW, stale_after=STALE_AFTER
        )

        self.assertEqual(view.clusters[0].cluster, "beta")
        self.assertFalse(view.clusters[0].configured)


class ArchiveListingTests(unittest.TestCase):
    def test_archives_are_listed_newest_first_across_the_nodes(self) -> None:
        cluster = overview(
            reading(
                nodes=[
                    node("node-a", backups=archives(2, newest_hours_ago=30)),
                    node("node-b", backups=archives(2, newest_hours_ago=5)),
                ]
            )
        ).clusters[0]
        versions = [archive.version for archive in cluster.archives]

        self.assertEqual(versions, sorted(versions, reverse=True))
        self.assertEqual(cluster.archives[0].node, "node-b")

    def test_a_node_at_the_limit_marks_the_listing_as_shortened(self) -> None:
        #
        # A node that returned exactly the number asked for probably has older
        # archives; one that returned fewer is showing its whole retention.
        #
        full = overview(reading(nodes=[node(backups=archives(10))], limit=10)).clusters[0]
        partial = overview(reading(nodes=[node(backups=archives(3))], limit=10)).clusters[0]

        self.assertTrue(full.truncated)
        self.assertFalse(partial.truncated)

    def test_an_archive_without_a_timestamp_still_lists(self) -> None:
        listing = [{"version": "2026-08-29_05-00-00", "size_bytes": 4096, "latest": True}]
        cluster = overview(reading(nodes=[node(backups=listing)])).clusters[0]

        self.assertEqual(cluster.archives[0].taken, "2026-08-29_05-00-00")
        self.assertEqual(cluster.archives[0].age_label, "—")
        self.assertEqual(cluster.nodes[0].label, "Undated")


class CountTests(unittest.TestCase):
    def test_only_a_node_with_a_recent_archive_counts_as_backed_up(self) -> None:
        view = overview(
            reading(
                nodes=[
                    node("node-a"),
                    node("node-b", backups=archives(newest_hours_ago=24 * 10)),
                    node("node-c", backups=[]),
                ]
            )
        )

        self.assertEqual(view.node_count, 3)
        self.assertEqual(view.protected_count, 1)


if __name__ == "__main__":
    unittest.main()
