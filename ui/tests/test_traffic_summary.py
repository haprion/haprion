"""The dashboard's traffic row: figures as a tile prints them, and a dash for no readings."""

from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from unittest import mock

from haproxy_ui import traffic_summary
from haproxy_ui.metrics import SUMMARY_COUNTERS, BackendMeasurement, Total
from tests.test_login import LoginTestCase, configuration

END = datetime(2026, 10, 1, 12, tzinfo=UTC)


def measured(
    span: timedelta, values: tuple[int, int, int], *, counted: float | None = None
) -> BackendMeasurement:
    seconds = span.total_seconds()
    return BackendMeasurement(
        intervals=10,
        started_at=END - span,
        ended_at=END,
        totals=tuple(
            Total(label, value, seconds if counted is None else counted, seconds)
            for (_name, label), value in zip(SUMMARY_COUNTERS, values, strict=True)
        ),
        restarted=False,
        handed_over=False,
        coverage=100,
    )


NOTHING = BackendMeasurement(
    intervals=0,
    started_at=None,
    ended_at=None,
    totals=tuple(Total(label, 0, 0.0, 0.0) for _name, label in SUMMARY_COUNTERS),
    restarted=False,
    handed_over=False,
    coverage=100,
)


class TheFigures(unittest.TestCase):
    def test_counts_bytes_and_rates_at_three_figures(self) -> None:
        self.assertEqual(
            [traffic_summary.count(v) for v in (950, 12_345, 4_560_000, 1_200_000_000)],
            ["950", "12.3k", "4.6M", "1.2B"],
        )
        self.assertEqual(traffic_summary.size(3_400_000_000), "3.4 GB")
        self.assertEqual(traffic_summary.size(41_200_000_000), "41 GB")
        self.assertEqual(traffic_summary.size(512), "512 B")
        self.assertEqual(traffic_summary.bitrate(0, 300), "0 bit/s")
        # Bits, because a link is sized in them: 9.25 MB over five minutes.
        self.assertEqual(traffic_summary.bitrate(9_250_000, 300), "247 kbit/s")
        self.assertEqual(traffic_summary.bitrate(121_000_000, 300), "3.2 Mbit/s")
        self.assertEqual(traffic_summary.milliseconds(38), "38 ms")
        self.assertEqual(traffic_summary.milliseconds(12_500), "12.5 s")

    def test_the_row_reads_the_day_and_the_last_minutes_apart(self) -> None:
        row = traffic_summary.row(
            measured(timedelta(hours=24), (1_234_567, 3_400_000_000, 41_200_000_000)),
            measured(timedelta(minutes=5), (3_612, 9_250_000, 121_000_000)),
            (48_211, 38, 412),
        )
        self.assertEqual(row.requests, "1.2M")
        self.assertEqual(row.request_rate, "12/s")
        self.assertEqual((row.inbound, row.outbound), ("247 kbit/s", "3.2 Mbit/s"))
        self.assertEqual((row.inbound_day, row.outbound_day), ("3.4 GB", "41 GB"))
        self.assertEqual((row.response_median, row.response_p95), ("38 ms", "412 ms"))
        self.assertFalse(row.day_partial)

    def test_no_readings_is_a_dash_not_nought(self) -> None:
        row = traffic_summary.row(NOTHING, NOTHING, None)
        self.assertEqual(
            (row.requests, row.inbound, row.outbound, row.response_median),
            (traffic_summary.DASH,) * 4,
        )
        self.assertEqual((row.request_rate, row.inbound_day, row.response_p95), ("", "", ""))
        empty_log = traffic_summary.row(NOTHING, NOTHING, (0, None, None))
        self.assertEqual(empty_log.response_median, traffic_summary.DASH)

    def test_a_day_missing_part_of_itself_says_so(self) -> None:
        day = measured(timedelta(hours=24), (100, 1000, 1000), counted=3600.0)
        row = traffic_summary.row(day, NOTHING)
        self.assertTrue(row.day_partial)
        self.assertEqual(row.requests, "100")

    def test_a_slow_poll_gets_three_readings(self) -> None:
        self.assertEqual(traffic_summary.recent_window(20), timedelta(minutes=5))
        self.assertEqual(traffic_summary.recent_window(300), timedelta(minutes=15))


class TheClusterHeader(LoginTestCase):
    def test_each_cluster_header_carries_its_own_traffic_and_the_log_is_not_asked_while_off(
        self,
    ) -> None:
        asked: list[object] = []

        def summary(
            _connection: object, *, clusters: object, since: datetime, until: datetime
        ) -> BackendMeasurement:
            asked.append(clusters)
            if until - since > timedelta(hours=1):
                return measured(timedelta(hours=24), (1_234_567, 3_400_000_000, 41_200_000_000))
            return measured(timedelta(minutes=5), (3_612, 9_250_000, 121_000_000))

        with (
            mock.patch("haproxy_ui.db.read_traffic_summary", side_effect=summary),
            mock.patch("haproxy_ui.db.read_response_times") as responses,
        ):
            client = self.client(replace(configuration(), clusters=("alpha",)))
            self.assertEqual(self.sign_in(client).status_code, 303)
            page = client.get("/").text

        self.assertIn('<dl class="cluster-traffic" aria-label="Traffic through alpha">', page)
        self.assertIn("<dt>Requests 24 h</dt><dd>1.2M</dd>", page)
        self.assertIn("<dt>In</dt><dd>247 kbit/s</dd>", page)
        self.assertIn("<dt>Out</dt><dd>3.2 Mbit/s</dd>", page)
        self.assertIn(f"<dt>Response</dt><dd>{traffic_summary.DASH}</dd>", page)
        self.assertNotIn("<span>Requests 24 h</span>", page, "no row of tiles any more")
        self.assertTrue(all(clusters == ["alpha"] for clusters in asked), "one cluster at a time")
        responses.assert_not_called()


if __name__ == "__main__":
    unittest.main()
