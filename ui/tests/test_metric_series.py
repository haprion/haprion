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
    seconds: int,
    *,
    uptime: int | None,
    node: str | None = None,
    fill: int | None = None,
    **counters: int | None,
) -> metrics.Sample:
    return metrics.Sample(
        observed_at=START + timedelta(seconds=seconds),
        member="BACKEND",
        uptime_sec=uptime,
        node=node,
        counters=dict.fromkeys(metrics.METRIC_COUNTERS, fill) | counters,
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

    def test_the_new_process_total_is_what_it_counted_and_no_more(self) -> None:
        """12 requests are real, and they are part of this interval.

        This used to report nothing at all, on the grounds that the survivor's
        total is not the interval's traffic. True, and the alternative was
        worse: discarding it threw away as much traffic as the bucket was wide,
        so the same reload subtracted a minute from the hour view and six hours
        from the month - and the month then showed less than the day.

        Measured on the live cluster 2026-09-06: one reload, 31 381 requests
        over 24 hours against 18 702 over 30 days. What the process running now
        has counted since it started is a measurement; the seconds before it
        are what is unknown, and the interval stays marked for them.
        """

        found = metrics.intervals(
            [sample(0, uptime=900, req_tot=4000), sample(20, uptime=8, req_tot=12)]
        )
        self.assertEqual(found[0].counters["req_tot"], 12)
        self.assertTrue(found[0].restarted)

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

    def test_the_address_moving_costs_the_seconds_it_took(self) -> None:
        """The failure the uptime cannot catch.

        Members are recorded from the node holding the VIP, so the series
        changes author at a failover - and the node taking over has usually
        been up longer than the one it replaced. Higher uptime and higher
        counters is what a healthy interval looks like, so nothing but the node
        itself says that 9000 is node-b's lifetime rather than 8000 requests.

        Each node is differenced against itself, so the pair never forms. One
        sample each is one interval short on both sides, and the seconds
        between them are time nobody observed rather than a refused reading
        that costs the buckets around it.
        """

        found = metrics.intervals(
            [
                sample(0, uptime=100, node="node-a", req_tot=1000),
                sample(20, uptime=90000, node="node-b", req_tot=9000),
            ]
        )
        self.assertEqual(len(found), 1)
        self.assertTrue(found[0].handed_over)
        self.assertIsNone(found[0].counters["req_tot"])
        self.assertEqual(found[0].seconds, 20)

    def test_a_stray_sample_from_the_standby_node_costs_nothing(self) -> None:
        """The hour that read 1 % on the live cluster, 2026-09-06.

        The standby wrote four samples inside an hour the active node measured
        end to end. Ordered by time and paired as neighbours, those rows broke
        the active node's series into refused differences spanning the whole
        hour; paired per node they form no interval and the active series runs
        through them.
        """

        found = metrics.intervals(
            [
                sample(0, uptime=100, node="node-a", req_tot=1000),
                sample(20, uptime=90000, node="node-b", req_tot=9000),
                sample(40, uptime=140, node="node-a", req_tot=1400),
            ]
        )
        self.assertEqual([interval.counters["req_tot"] for interval in found], [400])
        self.assertEqual(found[0].seconds, 40)

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
        """The card keeps the 100 it saw, and the handover costs its own time.

        The stretch between the two nodes' readings is missing from the figure;
        node-b's own 100 is not, and an operator asking whether the backend went
        quiet after a failover is asking about exactly that.
        """

        card = metrics.backend_traffic(
            "be_alpha",
            metrics.intervals(
                [
                    sample(0, uptime=100, node="node-a", req_tot=1000),
                    sample(20, uptime=90000, node="node-b", req_tot=9000),
                    sample(40, uptime=90020, node="node-b", req_tot=9100),
                ]
            ),
            start=START,
            end=START + timedelta(seconds=40),
            bucket=timedelta(seconds=20),
        )
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
        #
        # Six across the whole interval, and three the new process counted
        # before the reading that closed the restart's own interval.
        #
        self.assertEqual(total.value, 9)
        self.assertFalse(total.whole)
        self.assertEqual(total.coverage, 50)

    def test_a_counter_the_node_never_reported_does_not_speak_for_the_window(self) -> None:
        """It stars its own figure; it does not make the card claim a hole.

        An earlier version took the card's coverage as the lowest across every
        counter, so a column the node does not report announced 0% beside a
        figure that covered half the window.
        """

        card = metrics.backend_traffic(
            "be_alpha",
            metrics.intervals(
                [
                    sample(0, uptime=100, node="node-a", req_tot=10),
                    sample(20, uptime=120, node="node-a", req_tot=17),
                ]
            ),
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
        self.assertEqual(total.value, 903)
        self.assertEqual(total.coverage, 98)

    def test_a_reload_does_not_qualify_an_otherwise_complete_window(self) -> None:
        """A restart costs seconds; a card that flags them tells people to
        distrust a figure that is right.

        This is a traffic card, not an availability monitor. Below 95 % the
        figure is qualified - above it, the reader is told nothing, because
        there is nothing worth saying.
        """

        readings = [sample(0, uptime=100, req_tot=0)]
        for step in range(1, 251):
            readings.append(sample(step * 10, uptime=100 + step * 10, req_tot=step))
        readings.append(sample(2520, uptime=5, req_tot=1))
        total = metrics.totalled(metrics.intervals(readings), "req_tot")
        self.assertEqual(total.coverage, 99)
        self.assertTrue(total.whole)

    def test_a_window_missing_more_than_a_twentieth_is_still_qualified(self) -> None:
        """The threshold is a threshold, not an amnesty."""

        readings = [sample(0, uptime=100, req_tot=0)]
        for step in range(1, 11):
            readings.append(sample(step * 10, uptime=100 + step * 10, req_tot=step))
        readings.append(sample(120, uptime=5, req_tot=1))
        total = metrics.totalled(metrics.intervals(readings), "req_tot")
        self.assertLess(total.coverage, 95)
        self.assertFalse(total.whole)

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
            bucket=timedelta(seconds=10),
        )

    def test_a_gap_is_drawn_as_a_gap(self) -> None:
        """Joining across it draws a straight line through the unknown.

        And a straight line reads as the calmest stretch of the window, which
        is the opposite of what a restart in the middle of it means.
        """

        paths, _, _ = self.drawn([1, 2, None, 4, 5], span=timedelta(seconds=60))
        self.assertEqual(len(paths), 2)
        self.assertTrue(all(path.startswith("M") for path in paths))
        self.assertTrue(paths[0].endswith("L33.3 12.0"))
        self.assertTrue(paths[1].startswith("M50.0 4.0"))

    def test_a_single_known_bucket_occupies_its_whole_width(self) -> None:
        """A bucket is an interval, not a point at its left edge."""

        paths, points, _ = self.drawn([None, 7, None])
        self.assertEqual(paths[0], "M25.0 2.5 L50.0 2.5")
        self.assertEqual([point.value for point in points if point.measured], [0, 7, 0])

    def test_an_empty_window_is_flat_on_the_baseline(self) -> None:
        paths, _, peak = self.drawn([0, 0, 0], span=timedelta(seconds=30))
        self.assertEqual(peak, 0)
        self.assertEqual(
            paths,
            ["M0.0 20.0 L33.3 20.0 L33.3 20.0 L66.7 20.0 L66.7 20.0 L100.0 20.0"],
        )

    def test_a_peak_already_round_touches_the_top(self) -> None:
        paths, _, peak = self.drawn([0, 10], span=timedelta(seconds=20))
        self.assertEqual(peak, 10)
        self.assertEqual(paths, ["M0.0 20.0 L50.0 20.0 L50.0 0.0 L100.0 0.0"])

    def test_a_peak_that_is_not_round_stops_below_it(self) -> None:
        """Which is the point of a ceiling: the height of the line means something.

        Against its own maximum the line touched the top whatever it measured,
        so three requests a minute and three thousand drew the same picture.
        """

        paths, _, peak = self.drawn([0, 7], span=timedelta(seconds=20))
        self.assertEqual(peak, 7)
        self.assertEqual(metrics.ceiling_for(peak), 8)
        self.assertEqual(paths, ["M0.0 20.0 L50.0 20.0 L50.0 2.5 L100.0 2.5"])

    def test_a_reading_sits_where_its_moment_sits(self) -> None:
        """The shape is read against the axis, not stretched to fill the card."""

        _, points, _ = self.drawn([1, 1], span=timedelta(seconds=200))
        placed = {round(point.x, 1): point for point in points if point.measured}
        self.assertEqual(sorted(placed), [2.5, 7.5])

    def test_a_bucket_without_a_reading_rests_on_the_baseline(self) -> None:
        """One line across the whole window, on the maintainer's call.

        A month-long view that drew only where the poller has history gives a
        short scribble in one corner, and a trend is read off a continuous
        line. The cost is that the line cannot separate no traffic from no
        poller - which is why the point still knows.
        """

        paths, points, _ = self.drawn([5, 5], span=timedelta(seconds=100))
        self.assertEqual(len(paths), 1)
        self.assertEqual(len(points), 10)
        self.assertEqual(sum(1 for point in points if point.measured), 2)
        #
        # One unbroken run: the two measured buckets and then the baseline all
        # the way to the window's end, rather than a line that stops.
        #
        self.assertTrue(paths[0].startswith("M0.0 "))
        self.assertTrue(paths[0].endswith("L100.0 20.0"))

    def test_the_buckets_do_not_move_with_the_window(self) -> None:
        """The bug that drew a different sawtooth on every page load.

        The reader's SQL bins rows on a fixed grid (`date_bin` from
        2000-01-01). The drawing binned them from the window's own start, which
        moves with `now`, so the two sat a fraction of a bucket apart: some
        buckets held two readings and their neighbours none. Same readings,
        same buckets, wherever the window happens to begin.
        """

        found = [
            metrics.Interval(
                started_at=START + timedelta(seconds=step * 10),
                ended_at=START + timedelta(seconds=(step + 1) * 10),
                counters=dict.fromkeys(metrics.METRIC_COUNTERS) | {"req_tot": 5},
                restarted=False,
            )
            for step in range(6)
        ]
        moments = []
        for drift in (timedelta(0), timedelta(seconds=3), timedelta(seconds=7)):
            _, points, _ = metrics.spark(
                found,
                width=100,
                height=20,
                start=START - timedelta(seconds=30) + drift,
                end=START + timedelta(seconds=60) + drift,
                bucket=timedelta(seconds=10),
            )
            moments.append([point.at for point in points if point.measured])
        self.assertEqual(moments[0], moments[1])
        self.assertEqual(moments[1], moments[2])
        self.assertEqual(len(moments[0]), 6)

    def test_traffic_is_shared_over_the_time_it_covers(self) -> None:
        """A reading answers for the stretch since the last one, not for a point.

        A poll that arrives late covers two buckets, and dropping its whole
        count on the one it landed in leaves a hole beside a spike - both
        invented. The total across the window is what must survive.
        """

        found = [
            metrics.Interval(
                started_at=START,
                ended_at=START + timedelta(seconds=30),
                counters=dict.fromkeys(metrics.METRIC_COUNTERS) | {"req_tot": 30},
                restarted=False,
            )
        ]
        grid = metrics.bucketed(
            found,
            start=START,
            end=START + timedelta(seconds=30),
            bucket=timedelta(seconds=10),
        )
        self.assertEqual([entry.counters["req_tot"] for entry in grid], [10, 10, 10])

    def test_a_bucket_nobody_sampled_says_so_on_hover(self) -> None:
        """Drawn at zero, and never claiming zero was measured."""

        _, points, _ = self.drawn([5], span=timedelta(seconds=50))
        empty = [point for point in points if not point.measured]
        self.assertTrue(empty)
        self.assertTrue(all("no reading" in point.reading for point in empty))
        self.assertRegex(empty[0].reading, r"^\d\d-\d\d-\d\d \d\d:\d\d:\d\d · no reading$")

    def test_an_unmeasurable_reading_is_still_a_gap(self) -> None:
        """Narrower than an empty bucket, and the one coverage is counted from.

        Something was measured across it and could not be turned into a rate.
        That is a different and more suspicious thing than a stretch nobody
        sampled, so the line breaks here where it rests on the baseline there.
        """

        paths, points, _ = self.drawn([1, 1, None, 1, 1], span=timedelta(seconds=60))
        self.assertEqual(len(paths), 2)
        self.assertTrue(paths[0].endswith("L33.3 10.0"))
        self.assertTrue(paths[1].startswith("M50.0 10.0"))
        gap = next(point for point in points if point.value == 0 and point.measured)
        self.assertRegex(gap.reading, r"^\d\d-\d\d-\d\d \d\d:\d\d:\d\d · data gap$")
        self.assertNotIn("not measured", gap.reading)

    def test_a_point_says_the_moment_and_every_figure(self) -> None:
        """Including the ones the line does not draw, and the ones unmeasured."""

        _, points, _ = self.drawn([3, None])
        counted = next(point for point in points if point.value == 3)
        self.assertIn("Requests 3", counted.reading)
        self.assertIn("Connection errors not measured", counted.reading)
        self.assertIn(metrics.shown(counted.at).strftime("%y-%m-%d %H:%M:%S"), counted.reading)

    def test_a_point_writes_its_moment_the_agreed_way(self) -> None:
        """`yy-mm-dd hh:mm:ss`, 24-hour: fixed width and read the same by anyone."""

        _, points, _ = self.drawn([1, 1])
        for point in points:
            self.assertRegex(point.reading, r"^\d\d-\d\d-\d\d \d\d:\d\d:\d\d · ")


class WhatABucketCouldSee(unittest.TestCase):
    """A bucket answers from the part of itself that was measured.

    The behaviour this replaces made a bucket all or nothing: a single interval
    that could not be differenced marked every bucket it touched unknown, so a
    ten-second reload drew a two-hour hole in the 7-day view. The width of a gap
    is the only thing it says, and that one said something false.
    """

    def spans(
        self, values: list[int | None], *, bucket: int = 60, span: int = 0
    ) -> list[metrics.Bucket]:
        """One ten-second interval per value, into buckets of `bucket` seconds.

        `span` is the window, which is not the same as the stretch the intervals
        cover: only whole buckets are kept, so a window that stops where the
        readings stop has no whole bucket in it at all.
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
        return metrics.bucketed(
            found,
            start=START,
            end=START + timedelta(seconds=span or 10 * len(values)),
            bucket=timedelta(seconds=bucket),
        )

    def test_a_short_unmeasurable_stretch_no_longer_voids_the_bucket(self) -> None:
        """Ten seconds of a minute cost ten seconds, not the minute."""

        grid = self.spans([10, 10, 10, 10, 10, None])

        self.assertEqual(len(grid), 1)
        self.assertIsNotNone(grid[0].counters["req_tot"])

    def test_what_was_seen_is_scaled_to_the_part_of_the_bucket_it_answers_for(self) -> None:
        """Fifty requests over fifty seconds is a minute of sixty, not of fifty.

        Only observed traffic is summed and only observed time divides it, which
        is what keeps one bucket comparable with the next. It is not an estimate
        of the missing ten seconds - it is this bucket's measured rate, stated
        over the bucket's own length.
        """

        grid = self.spans([10, 10, 10, 10, 10, None])

        self.assertEqual(grid[0].counters["req_tot"], 60)
        self.assertAlmostEqual(grid[0].covered["req_tot"], 50 / 60)

    def test_a_bucket_measured_over_too_little_of_itself_is_still_a_gap(self) -> None:
        """Past some point what was seen is too small a corner to speak for the hour."""

        grid = self.spans([10, 10, None, None, None, None])

        self.assertIsNone(grid[0].counters["req_tot"])

    def test_a_bucket_history_only_reaches_into_is_not_a_gap(self) -> None:
        """Unobservable is not unmeasured.

        A series that begins halfway through a bucket was never owed a reading
        for the first half. Counting that as missing would call the first and
        last bucket of every card a gap, and scaling across it would double the
        figure for time the series does not cover.
        """

        grid = self.spans([10, 10], span=60)

        self.assertEqual(grid[0].counters["req_tot"], 20)
        self.assertEqual(grid[0].covered["req_tot"], 1.0)

    def test_a_partly_measured_bucket_is_marked_and_says_how_much(self) -> None:
        """The line stays continuous; the reader is still told which buckets."""

        _paths, points, _peak = metrics.spark(
            [
                metrics.Interval(
                    started_at=START + timedelta(seconds=step * 10),
                    ended_at=START + timedelta(seconds=(step + 1) * 10),
                    counters=dict.fromkeys(metrics.METRIC_COUNTERS) | {"req_tot": value},
                    restarted=False,
                )
                for step, value in enumerate([10, 10, 10, 10, 10, None])
            ],
            width=100,
            height=20,
            start=START,
            end=START + timedelta(seconds=60),
            bucket=timedelta(seconds=60),
        )

        self.assertTrue(points[0].partial)
        self.assertEqual(points[0].covered, 83)
        self.assertIn("measured over 83%", points[0].reading)

    def test_a_gap_says_whether_anything_at_all_was_seen(self) -> None:
        """ "Nothing" and "not enough" send an operator to different places."""

        _paths, points, _peak = metrics.spark(
            [
                metrics.Interval(
                    started_at=START + timedelta(seconds=step * 10),
                    ended_at=START + timedelta(seconds=(step + 1) * 10),
                    counters=dict.fromkeys(metrics.METRIC_COUNTERS) | {"req_tot": value},
                    restarted=False,
                )
                for step, value in enumerate([10, None, None, None, None, None])
            ],
            width=100,
            height=20,
            start=START,
            end=START + timedelta(seconds=60),
            bucket=timedelta(seconds=60),
        )

        self.assertIn("data gap", points[0].reading)
        self.assertIn("only 17% of it was measured", points[0].reading)


class MarkingOffAStretch(unittest.TestCase):
    """Two clicks make a range, a third clears it, and the marks live in the URL."""

    BUCKET = timedelta(minutes=10)

    def marked(self, since: object = None, until: object = None) -> metrics.Selection:
        return metrics.selection(
            None if since is None else str(since),
            None if until is None else str(until),
            start=START,
            end=START + timedelta(days=1),
            bucket=self.BUCKET,
        )

    def stamp(self, minutes: int) -> int:
        return int((START + timedelta(minutes=minutes)).timestamp())

    def test_one_click_marks_an_end_and_leaves_the_range_open(self) -> None:
        chosen = self.marked(self.stamp(30))

        self.assertTrue(chosen.started)
        self.assertFalse(chosen.complete)

    def test_the_second_click_closes_the_range_around_both_buckets(self) -> None:
        """Including the bucket clicked last, whole - it was pointed at."""

        chosen = self.marked(self.stamp(30), self.stamp(50))

        self.assertIsNotNone(chosen.since)
        self.assertIsNotNone(chosen.until)
        self.assertEqual(
            chosen.counted(START, START)[1] - chosen.counted(START, START)[0], timedelta(minutes=30)
        )

    def test_a_range_dragged_backwards_is_still_a_range(self) -> None:
        """The eye moves in both directions and the drawing says nothing about order."""

        forwards = self.marked(self.stamp(30), self.stamp(50))
        backwards = self.marked(self.stamp(50), self.stamp(30))

        self.assertEqual((backwards.since, backwards.until), (forwards.since, forwards.until))

    def test_a_click_inside_a_bucket_marks_the_bucket(self) -> None:
        """A range is only ever as fine as what the drawing can show."""

        since, until = self.marked(self.stamp(34), self.stamp(34)).counted(START, START)

        self.assertEqual(until - since, self.BUCKET)

    def test_marks_outside_the_window_clear_rather_than_fail(self) -> None:
        """A bookmark that outlived its window is not an error the reader made."""

        self.assertFalse(self.marked(int((START - timedelta(days=2)).timestamp())).started)
        self.assertFalse(self.marked("yesterday").started)
        self.assertFalse(self.marked(None, None).complete)

    def test_a_half_marked_range_still_counts_the_whole_window(self) -> None:
        """One click has not asked a question yet."""

        chosen = self.marked(self.stamp(30))
        end = START + timedelta(days=1)

        self.assertEqual(chosen.counted(START, end), (START, end))

    def test_three_clicks_mark_close_and_clear(self) -> None:
        base = {"traffic": "24h"}
        first = metrics.link_to(base, metrics.Selection(), self.stamp(30))
        second = metrics.link_to(base, self.marked(self.stamp(30)), self.stamp(50))
        third = metrics.link_to(base, self.marked(self.stamp(30), self.stamp(50)), self.stamp(20))

        self.assertEqual(first, f"?traffic=24h&from={self.stamp(30)}")
        self.assertEqual(second, f"?traffic=24h&from={self.stamp(30)}&to={self.stamp(50)}")
        self.assertEqual(third, "?traffic=24h")

    def test_the_window_a_range_was_marked_in_travels_with_it(self) -> None:
        """A range means something different on another window, so it keeps its own."""

        self.assertIn("traffic=7d", metrics.link_to({"traffic": "7d"}, metrics.Selection(), 1))
        self.assertEqual(
            metrics.link_clear({"traffic": "7d", "from": "1", "to": "2"}), "?traffic=7d"
        )

    def test_a_marked_bucket_is_marked_on_the_drawing(self) -> None:
        found = [
            metrics.Interval(
                started_at=START + timedelta(seconds=step * 10),
                ended_at=START + timedelta(seconds=(step + 1) * 10),
                counters=dict.fromkeys(metrics.METRIC_COUNTERS) | {"req_tot": 1},
                restarted=False,
            )
            for step in range(6)
        ]
        _paths, points, _peak = metrics.spark(
            found,
            width=100,
            height=20,
            start=START,
            end=START + timedelta(seconds=60),
            bucket=timedelta(seconds=20),
            chosen=metrics.Selection(
                since=START + timedelta(seconds=20), until=START + timedelta(seconds=40)
            ),
        )

        self.assertEqual([point.selected for point in points], [False, True, False])


class TheScaleBesideTheLine(unittest.TestCase):
    """Two guides, and both of them round enough to read without arithmetic."""

    def test_a_ceiling_is_the_round_number_at_or_above_the_peak(self) -> None:
        self.assertEqual(metrics.ceiling_for(74), 80)
        self.assertEqual(metrics.ceiling_for(10), 10)
        self.assertEqual(metrics.ceiling_for(1240), 2000)
        self.assertEqual(metrics.ceiling_for(3), 3)

    def test_a_single_request_is_not_halved(self) -> None:
        """A midpoint of half a request is not a quantity anybody counted."""

        self.assertEqual(metrics.ceiling_for(1), 2)

    def test_an_empty_window_has_no_ceiling_and_no_guides(self) -> None:
        """Two zeroes across an empty card are furniture rather than a scale."""

        self.assertEqual(metrics.ceiling_for(0), 0)
        self.assertEqual(metrics.levels_for(0, height=64), ())

    def test_the_guides_are_the_ceiling_its_half_and_the_floor(self) -> None:
        top, middle, floor = metrics.levels_for(80, height=64)
        self.assertEqual((top.label, top.y, top.share), ("80", 0.0, 0.0))
        self.assertEqual((middle.label, middle.y, middle.share), ("40", 32.0, 50.0))
        self.assertEqual((floor.label, floor.y, floor.share), ("0", 64.0, 100.0))

    def test_the_floor_is_labelled_even_though_the_line_rests_on_it(self) -> None:
        """Left out at first as labelling the obvious; on a real card the scale
        read as one that had been cut off - two numbers in mid-air with nothing
        underneath to measure them against."""

        self.assertEqual(
            [level.label for level in metrics.levels_for(6, height=64)], ["6", "3", "0"]
        )


class WhetherTheWindowSaysAnything(unittest.TestCase):
    def traffic(self, *samples: metrics.Sample) -> metrics.BackendTraffic:
        return metrics.backend_traffic(
            "mgd-site-web",
            metrics.intervals(list(samples)),
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
            sample(0, uptime=100, fill=0),
            sample(20, uptime=120, fill=0),
        )
        self.assertTrue(card.measured)

    def test_a_window_with_a_hole_is_still_a_window(self) -> None:
        """Measured, and its figures marked rather than withheld."""

        card = self.traffic(
            sample(0, uptime=900, fill=0),
            sample(20, uptime=4, fill=0),
        )
        self.assertTrue(card.measured)
        self.assertTrue(card.restarted)
        #
        # Nothing was seen whole here, and the figures say so even though the
        # new process's own count is carried: coverage is what was seen from
        # end to end, not whether a number could be produced.
        #
        self.assertEqual(card.coverage, 0)
        self.assertTrue(all(not total.whole for total in card.totals))


class TheFiguresAreNotTheDrawing(unittest.TestCase):
    """Changing the graph's buckets cannot change the window's counters."""

    def test_a_sql_measurement_replaces_only_the_downsampled_figures(self) -> None:
        drawing = [
            sample(0, uptime=100, req_tot=10),
            sample(20, uptime=120, req_tot=17),
        ]
        measured = metrics.BackendMeasurement(
            intervals=3269,
            started_at=START,
            ended_at=START + timedelta(hours=24),
            totals=tuple(
                metrics.Total(label=label, value=34601, counted_sec=86400, span_sec=86400)
                for _name, label in metrics.CARD_COUNTERS
            ),
            restarted=True,
            handed_over=False,
            coverage=99,
        )

        card = metrics.backend_traffic(
            "mgd-site-web",
            metrics.intervals(drawing),
            start=START,
            end=START + timedelta(hours=24),
            bucket=timedelta(hours=6),
            measurement=measured,
        )

        drawn_total = metrics.totalled(metrics.intervals(drawing), "req_tot")
        self.assertEqual(card.totals[0].value, 34601)
        self.assertNotEqual(card.totals[0].value, drawn_total.value)
        self.assertEqual(card.intervals, 3269)
        self.assertEqual(card.coverage, 99)
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
        #
        # Seen, and therefore marked: the bucket's floor is what shows the
        # restart the two readings hid. What is carried is the 1500 the process
        # running at the end of the bucket had counted - which is this bucket's
        # traffic since it started, and the reason the busiest hour is no
        # longer reported as the quietest.
        #
        self.assertTrue(found[0].restarted)
        self.assertEqual(found[0].counters["req_tot"], 1500)


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
        #
        # Converted to the reader's clock, which is a separate question from
        # which moments the axis spans. See `TheTimesAreTheReadersOwn`.
        #
        self.assertEqual(found[0][1], metrics.shown(START).strftime("%H:%M"))
        self.assertEqual(found[-1][1], metrics.shown(START + timedelta(hours=4)).strftime("%H:%M"))

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


class TheTimesAreTheReadersOwn(unittest.TestCase):
    """Stored in UTC, shown in the clock the person is holding.

    The card printed UTC, so an operator on CEST read 12:27 for something that
    happened at 14:27 - two hours from the journal, from `systemctl`, and from
    the deploy they were trying to line it up against. A traffic dip that
    cannot be matched to the event that caused it is a card that sends somebody
    to the wrong minute.
    """

    def test_a_moment_is_converted_rather_than_relabelled(self) -> None:
        at = datetime(2026, 9, 6, 12, 32, tzinfo=UTC)

        self.assertEqual(metrics.shown(at), at.astimezone())
        self.assertEqual(metrics.shown(at).utcoffset(), at.astimezone().utcoffset())

    def test_the_axis_labels_carry_the_conversion(self) -> None:
        at = datetime(2026, 9, 6, 12, 32, tzinfo=UTC)
        ticks = metrics.spark_ticks(start=at, end=at + timedelta(hours=1), fmt="%H:%M")

        self.assertEqual(ticks[0][1], at.astimezone().strftime("%H:%M"))

    def test_the_hover_carries_it_too(self) -> None:
        """The two are read together; one of them in UTC would be worse than both."""

        at = datetime(2026, 9, 6, 12, 32, tzinfo=UTC)

        self.assertIn(at.astimezone().strftime("%H:%M"), metrics.unread_at(at))
        self.assertIn(at.astimezone().strftime("%H:%M"), metrics.reading_at(at, {"req_tot": 5}))


class OneScaleAcrossSeveralCards(unittest.TestCase):
    """The comparison view's claim: two cards can be held against each other.

    That is only true while they are drawn against the same ceiling. Against
    its own maximum every line touches the top of its card, so a backend serving
    three requests and one serving three thousand draw the same picture - which
    is exactly what a page comparing backends must not do.
    """

    WINDOW = timedelta(seconds=40)

    def series(self, values: list[int | None]) -> list[metrics.Interval]:
        return [
            metrics.Interval(
                started_at=START + timedelta(seconds=step * 10),
                ended_at=START + timedelta(seconds=(step + 1) * 10),
                counters=dict.fromkeys(metrics.METRIC_COUNTERS) | {"req_tot": value},
                restarted=False,
            )
            for step, value in enumerate(values)
        ]

    def ceiling(self, *series: list[int | None]) -> int:
        return metrics.shared_ceiling(
            [self.series(values) for values in series],
            start=START,
            end=START + self.WINDOW,
            bucket=timedelta(seconds=10),
        )

    def card(self, values: list[int | None], *, ceiling: int | None) -> metrics.BackendTraffic:
        return metrics.backend_traffic(
            "backend",
            [],
            start=START,
            end=START + self.WINDOW,
            bucket=timedelta(seconds=10),
            ceiling=ceiling,
            measurement=metrics.BackendMeasurement(
                intervals=len(values),
                started_at=START,
                ended_at=START + self.WINDOW,
                totals=(),
                restarted=False,
                handed_over=False,
                coverage=100,
            ),
        )

    def test_the_ceiling_covers_the_busiest_series(self) -> None:
        self.assertEqual(self.ceiling([1, 2, 3], [10, 400, 7]), 400)

    def test_a_quiet_series_alone_keeps_its_own_ceiling(self) -> None:
        """Sharing a scale must not inflate a page that has only one card."""

        self.assertEqual(self.ceiling([1, 2, 3]), 3)

    def test_nothing_measured_anywhere_has_no_ceiling(self) -> None:
        """No traffic has no scale to divide; `0` alone is furniture."""

        self.assertEqual(self.ceiling([], []), 0)

    def test_a_given_ceiling_is_what_the_levels_are_drawn_from(self) -> None:
        card = self.card([1], ceiling=400)

        self.assertEqual([level.label for level in card.levels], ["400", "200", "0"])

    def test_without_one_a_card_still_scales_to_itself(self) -> None:
        """The object page passes no ceiling and must be untouched by this."""

        found = self.series([1, 2, 3])
        paths, _points, peak = metrics.spark(
            found,
            width=100,
            height=20,
            start=START,
            end=START + self.WINDOW,
            bucket=timedelta(seconds=10),
        )

        self.assertEqual(peak, 3)
        self.assertTrue(paths)

    def test_the_peak_reported_is_the_series_own_not_the_shared_one(self) -> None:
        """So a reader can tell a flat line from a card with nothing on it."""

        found = self.series([1, 2, 3])
        _paths, _points, peak = metrics.spark(
            found,
            width=100,
            height=20,
            start=START,
            end=START + self.WINDOW,
            bucket=timedelta(seconds=10),
            ceiling=400,
        )

        self.assertEqual(peak, 3)

    def test_a_quiet_series_is_drawn_low_against_a_shared_ceiling(self) -> None:
        """The stated cost of sharing: quiet really does look quiet."""

        found = self.series([1])
        _paths, points, _peak = metrics.spark(
            found,
            width=100,
            height=20,
            start=START,
            end=START + self.WINDOW,
            bucket=timedelta(seconds=10),
            ceiling=400,
        )
        plotted = next(point for point in points if point.value == 1)

        self.assertGreater(plotted.y, 19.0)
