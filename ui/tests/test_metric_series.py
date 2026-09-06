"""Cumulative readings turned into what happened between them.

The whole difficulty is that HAProxy's counters climb from process start and
drop to zero when it restarts, so the only thing with meaning is a difference -
and a difference across a restart has none. What this pins down is that the
unknown stays unknown: a gap must not be drawn as a quiet minute, because a
flat line is a claim and "I cannot tell" is not.
"""

from __future__ import annotations

import unittest
from datetime import UTC, datetime, timedelta

from haproxy_ui import metrics

START = datetime(2026, 9, 5, 20, 0, tzinfo=UTC)


def sample(
    seconds: int, *, uptime: int | None, node: str | None = None, **counters: int | None
) -> metrics.Sample:
    return metrics.Sample(
        observed_at=START + timedelta(seconds=seconds),
        member="BACKEND",
        uptime_sec=uptime,
        node=node,
        counters=dict.fromkeys(metrics.METRIC_COUNTERS) | counters,
    )


class WhatHappenedInBetween(unittest.TestCase):
    def test_a_difference_is_what_is_reported(self) -> None:
        found = metrics.intervals(
            [sample(0, uptime=100, req_tot=10), sample(20, uptime=120, req_tot=17)]
        )
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].counters["req_tot"], 7)
        self.assertFalse(found[0].restarted)
        self.assertEqual(found[0].seconds, 20)

    def test_nothing_happening_is_zero_and_says_so(self) -> None:
        found = metrics.intervals(
            [sample(0, uptime=100, req_tot=10), sample(20, uptime=120, req_tot=10)]
        )
        self.assertEqual(found[0].counters["req_tot"], 0)

    def test_a_restart_is_read_from_the_uptime(self) -> None:
        """Not from the counter, which cannot say which process it came from."""

        found = metrics.intervals(
            [sample(0, uptime=900, req_tot=4000), sample(20, uptime=8, req_tot=12)]
        )
        self.assertTrue(found[0].restarted)
        self.assertIsNone(found[0].counters["req_tot"])

    def test_the_new_process_total_is_not_the_interval(self) -> None:
        """12 requests are real, but they are not what happened in this interval.

        The events before the restart were counted by a process that is gone.
        Reporting the survivor's total would understate a busy minute as a
        quiet one, on exactly the minute somebody is investigating.
        """

        found = metrics.intervals(
            [sample(0, uptime=900, req_tot=4000), sample(20, uptime=8, req_tot=12)]
        )
        self.assertIsNone(found[0].counters["req_tot"])

    def test_a_counter_that_fell_is_refused_even_without_an_uptime(self) -> None:
        """An older node reports no uptime; a fall is still not a negative rate."""

        found = metrics.intervals(
            [sample(0, uptime=None, req_tot=4000), sample(20, uptime=None, req_tot=12)]
        )
        self.assertFalse(found[0].restarted)
        self.assertIsNone(found[0].counters["req_tot"])

    def test_a_counter_the_node_did_not_report_stays_unknown(self) -> None:
        found = metrics.intervals([sample(0, uptime=100), sample(20, uptime=120, req_tot=5)])
        self.assertIsNone(found[0].counters["req_tot"])

    def test_samples_out_of_order_are_put_back_before_subtracting(self) -> None:
        found = metrics.intervals(
            [sample(20, uptime=120, req_tot=17), sample(0, uptime=100, req_tot=10)]
        )
        self.assertEqual(found[0].counters["req_tot"], 7)

    def test_the_address_moving_is_not_a_busy_interval(self) -> None:
        """The failure the uptime cannot catch.

        Members are recorded only from the node holding the VIP, so the series
        changes author at a failover - and the node taking over has usually
        been up longer than the one it replaced. Higher uptime and higher
        counters is what a healthy interval looks like, so nothing but the node
        itself says that 9000 is node-b's lifetime rather than 8000 requests.
        """

        found = metrics.intervals(
            [
                sample(0, uptime=100, node="node-a", req_tot=1000),
                sample(20, uptime=90000, node="node-b", req_tot=9000),
            ]
        )
        self.assertTrue(found[0].handed_over)
        self.assertFalse(found[0].restarted)
        self.assertIsNone(found[0].counters["req_tot"])

    def test_the_same_node_still_subtracts(self) -> None:
        found = metrics.intervals(
            [
                sample(0, uptime=100, node="node-a", req_tot=10),
                sample(20, uptime=120, node="node-a", req_tot=17),
            ]
        )
        self.assertFalse(found[0].handed_over)
        self.assertEqual(found[0].counters["req_tot"], 7)

    def test_rows_from_before_the_node_was_carried_are_unchanged(self) -> None:
        """Samples written before the column was read back have no node.

        Two unknowns are not a change of node. Refusing them would turn every
        older interval into a hole, which is a different lie from the one this
        prevents.
        """

        found = metrics.intervals(
            [sample(0, uptime=100, req_tot=10), sample(20, uptime=120, req_tot=17)]
        )
        self.assertFalse(found[0].handed_over)
        self.assertEqual(found[0].counters["req_tot"], 7)

    def test_a_window_that_changed_node_has_no_total(self) -> None:
        """And the card says which of the two reasons it was."""

        card = metrics.pool_traffic(
            "be_alpha",
            [
                sample(0, uptime=100, node="node-a", req_tot=1000),
                sample(20, uptime=90000, node="node-b", req_tot=9000),
                sample(40, uptime=90020, node="node-b", req_tot=9100),
            ],
        )
        self.assertTrue(card.handed_over)
        self.assertFalse(card.restarted)
        self.assertEqual(dict(card.totals).get("Requests"), None)

    def test_one_sample_is_no_interval_at_all(self) -> None:
        self.assertEqual(metrics.intervals([sample(0, uptime=100, req_tot=1)]), [])
        self.assertEqual(metrics.intervals([]), [])


class TotallingAWindow(unittest.TestCase):
    def window(self) -> list[metrics.Interval]:
        return metrics.intervals(
            [
                sample(0, uptime=100, req_tot=10),
                sample(20, uptime=120, req_tot=17),
                sample(40, uptime=140, req_tot=20),
            ]
        )

    def test_a_whole_window_has_a_total(self) -> None:
        self.assertEqual(metrics.totalled(self.window(), "req_tot"), 10)

    def test_a_window_with_a_gap_has_none(self) -> None:
        """Not "sum what is known": that number reads as the window's traffic.

        Somebody comparing two windows would be comparing one that counted
        everything against one that quietly skipped a restart.
        """

        broken = metrics.intervals(
            [
                sample(0, uptime=100, req_tot=10),
                sample(20, uptime=5, req_tot=3),
                sample(40, uptime=25, req_tot=9),
            ]
        )
        self.assertIsNone(metrics.totalled(broken, "req_tot"))

    def test_an_empty_window_totals_zero_rather_than_unknown(self) -> None:
        """Nothing to subtract is not the same as something unsubtractable."""

        self.assertEqual(metrics.totalled([], "req_tot"), 0)


class DrawingTheShape(unittest.TestCase):
    def test_a_gap_is_drawn_as_a_gap(self) -> None:
        """Joining across it draws a straight line through the unknown.

        And a straight line reads as the calmest stretch of the window, which
        is the opposite of what a restart in the middle of it means.
        """

        paths, _ = metrics.spark_paths([1, 2, None, 4, 5], width=100, height=20)
        self.assertEqual(len(paths), 2)
        self.assertTrue(all(path.startswith("M") for path in paths))

    def test_a_single_known_point_draws_nothing(self) -> None:
        """One point is not a line, and a dot would suggest a reading."""

        paths, _ = metrics.spark_paths([None, 7, None], width=100, height=20)
        self.assertEqual(paths, [])

    def test_an_empty_window_is_flat_on_the_baseline(self) -> None:
        paths, peak = metrics.spark_paths([0, 0, 0], width=100, height=20)
        self.assertEqual(peak, 0)
        self.assertEqual(paths, ["M0.0 20.0 L50.0 20.0 L100.0 20.0"])

    def test_the_peak_touches_the_top(self) -> None:
        paths, peak = metrics.spark_paths([0, 10], width=100, height=20)
        self.assertEqual(peak, 10)
        self.assertEqual(paths, ["M0.0 20.0 L100.0 0.0"])


class WhetherTheWindowSaysAnything(unittest.TestCase):
    def traffic(self, *samples: metrics.Sample) -> metrics.PoolTraffic:
        return metrics.pool_traffic("mgd-site-web", list(samples))

    def test_no_samples_is_not_observed_rather_than_quiet(self) -> None:
        """An object never deployed has no reading, which is not "no traffic"."""

        card = self.traffic()
        self.assertFalse(card.measured)
        self.assertFalse(card.quiet)

    def test_a_measured_nothing_says_so_once(self) -> None:
        """Rather than as a flat line, a peak of zero and six zeros."""

        card = self.traffic(
            sample(0, uptime=100, **dict.fromkeys(metrics.METRIC_COUNTERS, 0)),
            sample(20, uptime=120, **dict.fromkeys(metrics.METRIC_COUNTERS, 0)),
        )
        self.assertTrue(card.measured)
        self.assertTrue(card.quiet)

    def test_a_window_with_a_hole_is_not_quiet(self) -> None:
        """A different sentence: nothing happened, versus we cannot say."""

        card = self.traffic(
            sample(0, uptime=900, **dict.fromkeys(metrics.METRIC_COUNTERS, 0)),
            sample(20, uptime=4, **dict.fromkeys(metrics.METRIC_COUNTERS, 0)),
        )
        self.assertTrue(card.measured)
        self.assertFalse(card.quiet)
        self.assertTrue(card.restarted)


class WhichWindowIsAsked(unittest.TestCase):
    def test_nothing_asked_is_a_day(self) -> None:
        """ "Is this normal" needs a normal, and an hour is too short to have one."""

        self.assertEqual(metrics.window(None).key, "24h")
        self.assertEqual(metrics.window("").key, "24h")

    def test_a_key_that_no_longer_exists_is_the_default_and_not_an_error(self) -> None:
        """It arrives in a bookmark, and a 400 turns a stale link into a fault."""

        self.assertEqual(metrics.window("90d").key, "24h")

    def test_every_window_lands_between_sixty_and_two_hundred_buckets(self) -> None:
        """Fewer and the shape is a guess; more and they are thinner than the line."""

        for entry in metrics.WINDOWS:
            with self.subTest(window=entry.key):
                buckets = entry.span / entry.bucket
                self.assertGreaterEqual(buckets, 60)
                self.assertLessEqual(buckets, 200)

    def test_a_bucket_hides_no_restart_it_contains(self) -> None:
        """The reason a bucket carries the lowest uptime inside it.

        A process can restart between two kept readings and climb back past
        the earlier one before the next is taken. Compared on the readings
        alone the uptime only rose, and the busiest hour of the window would
        be reported as its quietest.
        """

        earlier = metrics.Sample(
            observed_at=START,
            member="BACKEND",
            uptime_sec=3000,
            counters={"req_tot": 900},
        )
        later = metrics.Sample(
            observed_at=START + timedelta(minutes=10),
            member="BACKEND",
            uptime_sec=3600,
            floor_uptime_sec=20,
            counters={"req_tot": 1500},
        )
        found = metrics.intervals([earlier, later])
        self.assertTrue(found[0].restarted)
        self.assertIsNone(found[0].counters["req_tot"])


class LocatingTheShapeInTime(unittest.TestCase):
    """Without labels a reader can see that something happened, not when.

    Which is the question a month-long window is opened with - was that spike
    ten days ago or twenty - and a shape alone cannot answer it.
    """

    def found(self, count: int) -> list[metrics.Interval]:
        return metrics.intervals(
            [sample(step * 600, uptime=100 + step * 600, req_tot=step) for step in range(count)]
        )

    def test_the_labels_span_the_whole_line(self) -> None:
        ticks = metrics.spark_ticks(self.found(50), fmt="%H:%M")
        self.assertEqual(ticks[0][0], 0.0)
        self.assertEqual(ticks[-1][0], 100.0)

    def test_a_label_names_a_moment_that_was_measured(self) -> None:
        """Not one computed from the span, which a short history would invent."""

        ticks = metrics.spark_ticks(self.found(50), fmt="%H:%M")
        measured = {interval.ended_at.strftime("%H:%M") for interval in self.found(50)}
        for _, label in ticks:
            self.assertIn(label, measured)

    def test_a_window_shorter_than_the_labels_asks_for_fewer(self) -> None:
        ticks = metrics.spark_ticks(self.found(4), fmt="%H:%M")
        self.assertEqual(len(ticks), 3)

    def test_a_line_that_cannot_be_drawn_has_no_labels(self) -> None:
        self.assertEqual(metrics.spark_ticks([], fmt="%H:%M"), [])

    def test_each_window_says_what_one_point_covers(self) -> None:
        """`peak 104` means nothing until it says per what."""

        for entry in metrics.WINDOWS:
            with self.subTest(window=entry.key):
                self.assertTrue(entry.bucket_label)
                self.assertTrue(entry.tick)


if __name__ == "__main__":
    unittest.main()
