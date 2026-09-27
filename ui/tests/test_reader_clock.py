"""Every time on the interface in the reader's clock (B189, §16.4 U2).

The host's zone stays the default - the poller, the worker and an account that
has chosen nothing read the clock `journalctl` keeps - and an account's zone is
set for one request at a time.
"""

from __future__ import annotations

import contextvars
import os
import time
import unittest
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from haproxy_ui import metrics
from haproxy_ui.backups import build_backup_overview
from tests.test_backups import STALE_AFTER, reading, schedule, timer_of

# A September moment: New York on EDT (-4), the host on CEST (+2).
MOMENT = datetime(2026, 9, 8, 12, 0, tzinfo=UTC)


def read_in[T](zone: str | None, draw: Callable[[], T]) -> T:
    """Draw as a reader on `zone` would see it, without leaving the zone set."""

    def run() -> T:
        metrics.read_in(zone)
        return draw()

    return contextvars.copy_context().run(run)


class HostZone(unittest.TestCase):
    def host_zone(self, name: str) -> None:
        """Run as if the machine stood somewhere in particular.

        Without it a runner on UTC would compare UTC with UTC and prove nothing.
        """

        previous = os.environ.get("TZ")
        os.environ["TZ"] = name
        time.tzset()

        def restore() -> None:
            if previous is None:
                del os.environ["TZ"]
            else:
                os.environ["TZ"] = previous
            time.tzset()

        self.addCleanup(restore)


class TheReadersClock(HostZone):
    def setUp(self) -> None:
        self.host_zone("Europe/Stockholm")

    def test_nobody_s_zone_is_the_host_s(self) -> None:
        self.assertEqual(read_in(None, lambda: metrics.shown(MOMENT)).hour, 14)

    def test_a_chosen_zone_is_the_one_shown(self) -> None:
        shown = read_in("America/New_York", lambda: metrics.shown(MOMENT))

        self.assertEqual(shown.hour, 8)
        self.assertEqual(shown.tzname(), "EDT")

    def test_a_zone_the_host_does_not_know_is_the_host_s(self) -> None:
        self.assertEqual(read_in("Nowhere/Atlantis", lambda: metrics.shown(MOMENT)).hour, 14)

    def test_a_typed_time_is_read_in_the_clock_it_was_shown_in(self) -> None:
        typed = datetime(2026, 9, 8, 8, 0)

        self.assertEqual(read_in("America/New_York", lambda: metrics.wall(typed)), MOMENT)
        self.assertEqual(read_in(None, lambda: metrics.wall(typed)), MOMENT - timedelta(hours=6))

    def test_setting_a_zone_in_one_context_leaves_this_one_alone(self) -> None:
        read_in("America/New_York", lambda: None)

        self.assertEqual(metrics.shown(MOMENT).hour, 14)


class TheBackupSchedule(HostZone):
    """The timer runs on the manager's clock; a reader elsewhere sees both."""

    def setUp(self) -> None:
        self.host_zone("Europe/Stockholm")

    def schedule(self, zone: str | None, **changes: object):
        return read_in(
            zone,
            lambda: timer_of(
                build_backup_overview(
                    ("alpha",),
                    (reading(timer=schedule(**changes)),),
                    now=MOMENT,
                    stale_after=STALE_AFTER,
                )
            ),
        )

    def test_a_reader_on_the_manager_s_clock_sees_it_as_before(self) -> None:
        self.assertEqual(self.schedule(None).reader_time, "")

    def test_a_zone_that_reads_the_same_adds_nothing(self) -> None:
        self.assertEqual(self.schedule("Europe/Berlin").reader_time, "")

    def test_a_reader_elsewhere_gets_the_same_moment_in_their_clock(self) -> None:
        view = self.schedule("America/New_York")

        self.assertEqual(view.time, "05:00")
        self.assertEqual(view.reader_time, "23:00 EDT")

    def test_the_difference_follows_daylight_saving_on_the_day(self) -> None:
        # 2026-11-02: Stockholm is back on CET, New York is back on EST too.
        view = read_in(
            "America/New_York",
            lambda: timer_of(
                build_backup_overview(
                    ("alpha",),
                    (reading(timer=schedule()),),
                    now=datetime(2026, 11, 2, 12, 0, tzinfo=UTC),
                    stale_after=STALE_AFTER,
                )
            ),
        )

        self.assertEqual(view.reader_time, "23:00 EST")

    def test_an_unscheduled_cluster_converts_nothing(self) -> None:
        view = self.schedule("America/New_York", scheduled=False, enabled=False)

        self.assertEqual(view.readable, "No schedule set")
        self.assertEqual(view.reader_time, "")

    def test_a_hand_written_calendar_with_no_real_time_converts_nothing(self) -> None:
        view = self.schedule("America/New_York", calendar="*-*-* 29:00:00")

        self.assertEqual(view.reader_time, "")


if __name__ == "__main__":
    unittest.main()
