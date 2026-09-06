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

    def test_a_window_that_changed_node_counts_the_rest_of_itself(self) -> None:
        """The card keeps the 100 it saw, says which reason cost it the rest.

        The handover interval is missing from the figure; node-b's own 100 is
        not, and an operator asking whether the pool went quiet after a
        failover is asking about exactly that.
        """

        card = metrics.pool_traffic(
            "be_alpha",
            [
                sample(0, uptime=100, node="node-a", req_tot=1000),
                sample(20, uptime=90000, node="node-b", req_tot=9000),
                sample(40, uptime=90020, node="node-b", req_tot=9100),
            ],
            start=START,
            end=START + timedelta(seconds=40),
            bucket=timedelta(seconds=20),
        )
        self.assertTrue(card.handed_over)
        self.assertFalse(card.restarted)
        requests = next(total for total in card.totals if total.label == "Requests")
        self.assertEqual(requests.value, 100)
        self.assertFalse(requests.whole)
        self.assertEqual(card.coverage, 50)

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
        total = metrics.totalled(self.window(), "req_tot")
        self.assertEqual(total.value, 10)
        self.assertTrue(total.whole)
        self.assertEqual(total.coverage, 100)

    def test_a_window_with_a_gap_still_says_what_it_counted(self) -> None:
        """The part that was measured is given, and it says how much that was.

        Withholding it answers a month containing one reload with nothing at
        all. What the earlier version was right about is that the bare number
        would be read as the window's traffic - so the coverage travels with
        it and the figure is a floor, stated as one.
        """

        broken = metrics.intervals(
            [
                sample(0, uptime=100, req_tot=10),
                sample(20, uptime=5, req_tot=3),
                sample(40, uptime=25, req_tot=9),
            ]
        )
        total = metrics.totalled(broken, "req_tot")
        self.assertEqual(total.value, 6)
        self.assertFalse(total.whole)
        self.assertEqual(total.coverage, 50)

    def test_a_counter_the_node_never_reported_does_not_speak_for_the_window(self) -> None:
        """It stars its own figure; it does not make the card claim a hole.

        An earlier version took the card's coverage as the lowest across every
        counter, so a column the node does not report announced 0% beside a
        figure that covered half the window.
        """

        card = metrics.pool_traffic(
            "be_alpha",
            [
                sample(0, uptime=100, node="node-a", req_tot=10),
                sample(20, uptime=120, node="node-a", req_tot=17),
            ],
            start=START,
            end=START + timedelta(seconds=20),
            bucket=timedelta(seconds=10),
        )
        self.assertEqual(card.coverage, 100)
        unreported = next(total for total in card.totals if total.label == "4xx")
        self.assertFalse(unreported.whole)
        self.assertEqual(unreported.coverage, 0)

    def test_coverage_is_time_rather_than_a_count_of_intervals(self) -> None:
        """Two short holes in a long window are not half of it missing."""

        broken = metrics.intervals(
            [
                sample(0, uptime=100, req_tot=10),
                sample(900, uptime=1000, req_tot=910),
                sample(910, uptime=5, req_tot=3),
            ]
        )
        total = metrics.totalled(broken, "req_tot")
        self.assertEqual(total.value, 900)
        self.assertEqual(total.coverage, 98)

    def test_a_partial_window_never_rounds_up_to_whole(self) -> None:
        """99.6% is not 100, and the figure that says so is the one people trust."""

        readings = [sample(0, uptime=100, req_tot=0)]
        for step in range(1, 251):
            readings.append(sample(step * 10, uptime=100 + step * 10, req_tot=step))
        readings.append(sample(2520, uptime=5, req_tot=1))
        total = metrics.totalled(metrics.intervals(readings), "req_tot")
        self.assertFalse(total.whole)
        self.assertEqual(total.coverage, 99)

    def test_an_empty_window_totals_zero_rather_than_unknown(self) -> None:
        """Nothing to subtract is not the same as something unsubtractable."""

        total = metrics.totalled([], "req_tot")
        self.assertEqual(total.value, 0)
        self.assertTrue(total.whole)


class DrawingTheShape(unittest.TestCase):
    """The line is drawn on the window's own scale, not on the readings'."""

    def drawn(
        self, values: list[int | None], *, span: timedelta = timedelta(seconds=40)
    ) -> tuple[list[str], list[metrics.Point], int]:
        """One interval per value, ten seconds each, into a window of `span`.

        Built as intervals rather than as readings because this is what the
        drawing is handed. Going through `samples` would make one unreported
        reading remove the two differences it sits between, which is a fact
        about `intervals` and is pinned there.
        """

        found = [
            metrics.Interval(
                started_at=START + timedelta(seconds=step * 10),
                ended_at=START + timedelta(seconds=(step + 1) * 10),
                counters=dict.fromkeys(metrics.METRIC_COUNTERS) | {"req_tot": value},
                restarted=False,
            )
            for step, value in enumerate(values)
        ]
        return metrics.spark(
            found,
            width=100,
            height=20,
            start=START,
            end=START + span,
        )

    def test_a_gap_is_drawn_as_a_gap(self) -> None:
        """Joining across it draws a straight line through the unknown.

        And a straight line reads as the calmest stretch of the window, which
        is the opposite of what a restart in the middle of it means.
        """

        paths, _, _ = self.drawn([1, 2, None, 4, 5], span=timedelta(seconds=60))
        self.assertEqual(len(paths), 2)
        self.assertTrue(all(path.startswith("M") for path in paths))

    def test_a_single_known_point_draws_nothing(self) -> None:
        """One point is not a line, and a dot would suggest a reading."""

        paths, points, _ = self.drawn([None, 7, None])
        self.assertEqual(paths, [])
        self.assertEqual(len(points), 1)

    def test_an_empty_window_is_flat_on_the_baseline(self) -> None:
        paths, _, peak = self.drawn([0, 0, 0], span=timedelta(seconds=30))
        self.assertEqual(peak, 0)
        self.assertEqual(paths, ["M33.3 20.0 L66.7 20.0 L100.0 20.0"])

    def test_the_peak_touches_the_top(self) -> None:
        paths, _, peak = self.drawn([0, 10], span=timedelta(seconds=20))
        self.assertEqual(peak, 10)
        self.assertEqual(paths, ["M50.0 20.0 L100.0 0.0"])

    def test_a_reading_sits_where_its_moment_sits(self) -> None:
        """A day of samples in a month-long window fills the last of it.

        Not the whole card. The shape is read against the axis, and a scale
        that stretches to whatever data arrived makes two windows of the same
        pool incomparable.
        """

        paths, points, _ = self.drawn([1, 1], span=timedelta(seconds=200))
        self.assertEqual(paths, ["M5.0 0.0 L10.0 0.0"])
        self.assertEqual([round(point.x, 1) for point in points], [5.0, 10.0])

    def test_a_point_says_the_moment_and_every_figure(self) -> None:
        """Including the ones the line does not draw, and the ones unmeasured."""

        _, points, _ = self.drawn([3, None])
        self.assertEqual(len(points), 1)
        self.assertIn("Requests 3", points[0].reading)
        self.assertIn("Connection errors not measured", points[0].reading)
        self.assertIn(points[0].at.strftime("%y-%m-%d %H:%M:%S"), points[0].reading)

    def test_a_point_writes_its_moment_the_agreed_way(self) -> None:
        """`yy-mm-dd hh:mm:ss`, 24-hour: fixed width and read the same by anyone."""

        _, points, _ = self.drawn([1, 1])
        self.assertRegex(points[0].reading, r"^\d\d-\d\d-\d\d \d\d:\d\d:\d\d · ")


class WhetherTheWindowSaysAnything(unittest.TestCase):
    def traffic(self, *samples: metrics.Sample) -> metrics.PoolTraffic:
        return metrics.pool_traffic(
            "mgd-site-web",
            list(samples),
            start=START,
            end=START + timedelta(minutes=1),
            bucket=timedelta(seconds=10),
        )

    def test_no_samples_is_not_observed_rather_than_quiet(self) -> None:
        """An object never deployed has no reading, which is not "no traffic"."""

        card = self.traffic()
        self.assertFalse(card.measured)

    def test_a_window_of_zeroes_is_measured(self) -> None:
        """Counted nothing, as opposed to having nothing to count."""

        card = self.traffic(
            sample(0, uptime=100, **dict.fromkeys(metrics.METRIC_COUNTERS, 0)),
            sample(20, uptime=120, **dict.fromkeys(metrics.METRIC_COUNTERS, 0)),
        )
        self.assertTrue(card.measured)

    def test_a_window_with_a_hole_is_still_a_window(self) -> None:
        """Measured, and its figures marked rather than withheld."""

        card = self.traffic(
            sample(0, uptime=900, **dict.fromkeys(metrics.METRIC_COUNTERS, 0)),
            sample(20, uptime=4, **dict.fromkeys(metrics.METRIC_COUNTERS, 0)),
        )
        self.assertTrue(card.measured)
        self.assertTrue(card.restarted)
        self.assertEqual(card.coverage, 0)
        self.assertTrue(all(not total.whole for total in card.totals))


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

    def ticks(self, span: timedelta) -> list[tuple[float, str]]:
        return metrics.spark_ticks(start=START, end=START + span, fmt="%H:%M")

    def test_the_labels_span_the_whole_window(self) -> None:
        found = self.ticks(timedelta(hours=4))
        self.assertEqual(found[0][0], 0.0)
        self.assertEqual(found[-1][0], 100.0)

    def test_a_label_names_the_window_rather_than_the_readings(self) -> None:
        """The axis is the scale, so it spans the window whatever arrived.

        The labels used to be taken from the intervals, which meant a 30-day
        view holding one day of samples wrote the same date at both ends -
        true about the data and wrong about the axis.
        """

        found = self.ticks(timedelta(hours=4))
        self.assertEqual(found[0][1], START.strftime("%H:%M"))
        self.assertEqual(found[-1][1], (START + timedelta(hours=4)).strftime("%H:%M"))

    def test_the_labels_are_evenly_spaced(self) -> None:
        found = self.ticks(timedelta(hours=4))
        steps = {
            round(later[0] - earlier[0], 6)
            for earlier, later in zip(found, found[1:], strict=False)
        }
        self.assertEqual(len(steps), 1)

    def test_a_window_with_no_span_has_no_labels(self) -> None:
        self.assertEqual(self.ticks(timedelta(0)), [])

    def test_each_window_says_what_one_point_covers(self) -> None:
        """`peak 104` means nothing until it says per what."""

        for entry in metrics.WINDOWS:
            with self.subTest(window=entry.key):
                self.assertTrue(entry.bucket_label)
                self.assertTrue(entry.tick)


if __name__ == "__main__":
    unittest.main()
