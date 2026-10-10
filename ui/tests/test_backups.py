"""What the backup page says, and which quiet states it refuses to render calmly.

The state worth testing hardest is the one that looks fine: a node that reports
no error, holds no archive, and would render as an ordinary row. It is the worst
state on the page, and the tests below pin it as such.
"""

from __future__ import annotations

import unittest
from datetime import UTC, datetime, timedelta
from typing import Any

from haprion_ui.backups import BackupOverview, ScheduleView, build_backup_overview
from haprion_ui.db import ClusterBackups

NOW = datetime(2026, 8, 29, 10, 0, tzinfo=UTC)
STALE_AFTER = timedelta(minutes=2)


def archives(count: int = 3, *, newest_hours_ago: int = 5) -> list[dict[str, Any]]:
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
    backups: list[dict[str, Any]] | None = None,
    error: str | None = None,
    retained_count: int | None = None,
) -> dict[str, object]:
    listed = archives() if backups is None else backups
    return {
        "name": name,
        "available": available,
        "latest_version": listed[0]["version"] if listed else None,
        "retained_count": len(listed) if retained_count is None else retained_count,
        "retained_size_bytes": sum(int(item["size_bytes"]) for item in listed),
        "backups": listed,
        "error": {"message": error} if error else None,
    }


def schedule(**changes: object) -> dict[str, object]:
    return {
        "unit": "haprion-state-backup.timer",
        "known": True,
        "enabled": True,
        "active": True,
        "calendar": "*-*-* 05:00:00",
        "next_run": (NOW + timedelta(hours=19)).isoformat().replace("+00:00", "Z"),
        "last_run": (NOW - timedelta(hours=5)).isoformat().replace("+00:00", "Z"),
        "last_result": "success",
        "scheduled": True,
        **changes,
    }


def reading(
    *,
    cluster: str = "alpha",
    age_seconds: int = 15,
    outcome: str = "done",
    poll_error: str | None = None,
    nodes: list[dict[str, object]] | None = None,
    limit: int | None = 14,
    timer: dict[str, object] | None = None,
) -> ClusterBackups:
    return ClusterBackups(
        cluster=cluster,
        observed_at=NOW - timedelta(seconds=age_seconds),
        outcome=outcome,
        result={
            "limit": limit,
            "schedule": timer,
            "nodes": [node(), node("node-b")] if nodes is None else nodes,
        },
        warnings=[],
        error=None,
        poll_error=poll_error,
    )


def overview(*readings: ClusterBackups, clusters: tuple[str, ...] = ("alpha",)) -> BackupOverview:
    return build_backup_overview(clusters, readings, now=NOW, stale_after=STALE_AFTER)


def timer_of(view: BackupOverview, index: int = 0) -> ScheduleView:
    """The schedule, or a failure that names what was missing."""

    schedule = view.clusters[index].schedule
    if schedule is None:
        raise AssertionError("the overview carries no schedule")
    return schedule


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

    def state_under(self, calendar: str, hours: int, **timer: object) -> tuple[str, str]:
        found = (
            overview(
                reading(
                    nodes=[node(backups=archives(newest_hours_ago=hours))],
                    timer=schedule(calendar=calendar, **timer),
                )
            )
            .clusters[0]
            .nodes[0]
        )
        return found.label, found.tone

    def test_a_weekly_schedule_working_as_asked_is_current(self) -> None:
        """Review 2026-09-28 F03: three days into a Monday-only week read as overdue."""

        self.assertEqual(self.state_under("Mon *-*-* 05:00:00", 24 * 3), ("Current", "healthy"))
        self.assertEqual(self.state_under("Mon *-*-* 05:00:00", 24 * 7), ("Current", "healthy"))
        self.assertEqual(
            self.state_under("Mon *-*-* 05:00:00", 24 * 8), ("Backup overdue", "warning")
        )
        self.assertEqual(
            self.state_under("Mon *-*-* 05:00:00", 24 * 15), ("Stale backups", "critical")
        )

    def test_a_weekly_schedule_is_judged_by_its_longest_gap(self) -> None:
        self.assertEqual(self.state_under("Mon,Thu *-*-* 05:00:00", 24 * 4), ("Current", "healthy"))
        self.assertEqual(
            self.state_under("Mon,Thu *-*-* 05:00:00", 24 * 5), ("Backup overdue", "warning")
        )

    def test_a_monthly_schedule_working_as_asked_is_current(self) -> None:
        self.assertEqual(self.state_under("*-*-01 05:00:00", 24 * 8), ("Current", "healthy"))
        self.assertEqual(self.state_under("*-*-01 05:00:00", 24 * 30), ("Current", "healthy"))
        self.assertEqual(
            self.state_under("*-*-01 05:00:00", 24 * 32), ("Backup overdue", "warning")
        )
        self.assertEqual(
            self.state_under("*-*-01 05:00:00", 24 * 63), ("Stale backups", "critical")
        )

    def test_a_schedule_that_is_off_holds_the_archives_to_a_daily_run(self) -> None:
        self.assertEqual(
            self.state_under("Mon *-*-* 05:00:00", 40, enabled=False),
            ("Backup overdue", "warning"),
        )

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

    def test_only_a_proven_short_listing_is_marked_as_shortened(self) -> None:
        full = overview(
            reading(nodes=[node(backups=archives(14), retained_count=14)], limit=14)
        ).clusters[0]
        partial = overview(
            reading(nodes=[node(backups=archives(10), retained_count=14)], limit=10)
        ).clusters[0]

        self.assertFalse(full.truncated)
        self.assertTrue(partial.truncated)
        self.assertEqual(full.retained_count, 14)
        self.assertEqual(full.shown_count, 14)
        self.assertEqual(partial.retained_count, 14)
        self.assertEqual(partial.shown_count, 10)

    def test_the_list_pages_ten_archives_per_node(self) -> None:
        cluster = overview(
            reading(
                nodes=[
                    node("node-a", backups=archives(21)),
                    node("node-b", backups=archives(12, newest_hours_ago=6)),
                ],
                limit=None,
            )
        ).clusters[0]
        pages = [archive.page for archive in cluster.archives]

        self.assertFalse(cluster.truncated)
        self.assertEqual(cluster.page_count, 3)
        self.assertEqual(cluster.deepest, 21)
        # Each page is one contiguous block, in order.
        self.assertEqual(pages, sorted(pages))
        first = [archive for archive in cluster.archives if archive.page == 0]
        self.assertEqual(
            [sum(archive.node == name for archive in first) for name in ("node-a", "node-b")],
            [10, 10],
        )
        self.assertTrue(all(archive.node == "node-a" for archive in cluster.archives[-1:]))
        # Newest first within a page, across both nodes.
        versions = [archive.version for archive in first]
        self.assertEqual(versions, sorted(versions, reverse=True))

    def test_a_node_s_rank_follows_the_archive_name_not_the_listing_order(self) -> None:
        listing = list(reversed(archives(11)))
        cluster = overview(reading(nodes=[node(backups=listing)], limit=None)).clusters[0]
        oldest = min(archive.version for archive in cluster.archives)

        self.assertEqual(
            [archive.page for archive in cluster.archives if archive.version == oldest], [1]
        )

    def test_ten_or_fewer_per_node_is_one_page(self) -> None:
        cluster = overview(
            reading(nodes=[node(backups=archives(10)), node("node-b", backups=archives(10))])
        ).clusters[0]

        self.assertEqual(cluster.page_count, 1)
        self.assertEqual({archive.page for archive in cluster.archives}, {0})

    def test_an_archive_without_a_timestamp_still_lists(self) -> None:
        listing = [{"version": "2026-08-29_05-00-00", "size_bytes": 4096, "latest": True}]
        cluster = overview(reading(nodes=[node(backups=listing)])).clusters[0]

        self.assertEqual(cluster.archives[0].taken, "2026-08-29_05-00-00")
        self.assertEqual(cluster.archives[0].age_label, "—")
        self.assertEqual(cluster.nodes[0].label, "Undated")


class ScheduleTests(unittest.TestCase):
    def test_each_cluster_carries_its_own_running_timer(self) -> None:
        view = build_backup_overview(
            ("alpha", "beta"),
            (
                reading(cluster="alpha", timer=schedule()),
                reading(cluster="beta", timer=schedule()),
            ),
            now=NOW,
            stale_after=STALE_AFTER,
        )
        schedule_view = timer_of(view)
        second = timer_of(view, 1)

        self.assertEqual(schedule_view.tone, "healthy")
        self.assertEqual(schedule_view.label, "Scheduled")
        self.assertEqual(schedule_view.calendar, "*-*-* 05:00:00")
        self.assertIn("5h ago", schedule_view.last_run)
        #
        # A run that has not happened yet carries no age. `relative_age` clamps
        # the future to "Just now", which would say the next run just did.
        #
        self.assertNotIn("(", schedule_view.next_run)
        self.assertEqual(second.label, "Scheduled")

    def test_the_line_reports_the_newest_archive_not_the_timer_s_last_trigger(self) -> None:
        """*Back up now* never fires the timer, so the trigger would lag the nodes."""

        view = timer_of(
            overview(
                reading(
                    nodes=[node("node-a", backups=archives(newest_hours_ago=1))],
                    timer=schedule(),
                )
            )
        )
        self.assertIn("1h ago", view.last_run)
        self.assertNotIn("5h ago", view.last_run)

    def test_an_installation_without_a_timer_shows_no_schedule(self) -> None:
        self.assertIsNone(overview(reading()).clusters[0].schedule)

    def test_a_timer_that_fires_into_a_failing_run_is_critical(self) -> None:
        #
        # Nothing else on the page would show this: the archives simply stop
        # getting newer, which reads as an old backup rather than a broken one.
        #
        schedule_view = timer_of(overview(reading(timer=schedule(last_result="exit-code"))))

        self.assertEqual(schedule_view.tone, "critical")
        self.assertEqual(schedule_view.label, "Last run failed")

    def test_a_missing_timer_and_a_disabled_one_are_worded_differently(self) -> None:
        missing = timer_of(overview(reading(timer=schedule(known=False, enabled=False))))
        disabled = timer_of(overview(reading(timer=schedule(enabled=False))))
        fresh = timer_of(
            overview(reading(timer=schedule(enabled=False, active=False, scheduled=False)))
        )

        self.assertEqual(missing.label, "Timer missing")
        self.assertEqual(disabled.label, "Disabled")
        # Nobody has set this cluster's time yet: a warning with a form, not a fault.
        self.assertEqual((fresh.label, fresh.tone), ("Not scheduled", "warning"))
        #
        # A disabled timer still reports the elapse it would have had. Showing
        # it would promise a run that is not going to happen.
        #
        self.assertEqual(disabled.next_run, "—")

    def test_the_calendar_is_said_in_words_and_split_back_into_the_form(self) -> None:
        for calendar, readable, frequency in (
            ("*-*-* 05:00:00", "Every day at 05:00", "daily"),
            ("Mon,Wed,Fri *-*-* 22:30:00", "Every Monday, Wednesday and Friday at 22:30", "weekly"),
            ("Sun *-*-* 03:00:00", "Every Sunday at 03:00", "weekly"),
            ("Mon,Tue,Wed,Thu,Fri *-*-* 05:00:00", "Every weekday at 05:00", "weekly"),
            ("*-*-01 04:15:00", "On day 1 of every month at 04:15", "monthly"),
        ):
            with self.subTest(calendar=calendar):
                view = timer_of(overview(reading(timer=schedule(calendar=calendar, retention=30))))
                self.assertEqual(view.readable, readable)
                self.assertEqual(view.frequency, frequency)
                self.assertEqual(view.time, calendar[-8:-3])
                self.assertEqual(view.retention, 30)
        weekly = timer_of(overview(reading(timer=schedule(calendar="Mon,Fri *-*-* 22:30:00"))))
        self.assertEqual(weekly.weekdays, ("Mon", "Fri"))
        monthly = timer_of(overview(reading(timer=schedule(calendar="*-*-07 04:15:00"))))
        self.assertEqual(monthly.day_of_month, 7)

    def test_a_hand_written_calendar_is_shown_as_it_is(self) -> None:
        """One edited on the manager is not translated into a shape it does not have."""

        view = timer_of(overview(reading(timer=schedule(calendar="Mon..Fri *-*-* 05:00:00"))))
        self.assertEqual(view.readable, "Mon..Fri *-*-* 05:00:00")
        self.assertEqual(view.frequency, "daily")
        self.assertIsNone(view.retention)

    def test_a_cluster_whose_poll_failed_does_not_borrow_another_schedule(self) -> None:
        view = build_backup_overview(
            ("alpha", "beta"),
            (
                reading(cluster="alpha", outcome="failed", nodes=[], timer=None),
                reading(cluster="beta", timer=schedule()),
            ),
            now=NOW,
            stale_after=STALE_AFTER,
        )
        self.assertIsNone(view.clusters[0].schedule)
        self.assertEqual(timer_of(view, 1).label, "Scheduled")


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
