"""One reading of a node's log forwarding queues, for the terminal and the interface (B289)."""

from __future__ import annotations

import unittest

from haprion.log_forwarding import (
    QUEUE_WARNING,
    STATS_STALE_SECONDS,
    problems,
    status_line,
    unreached,
)


def reading(age: int | None = 30, **receivers: tuple[int | None, int]) -> dict[str, object]:
    return {
        "stats_age_sec": age,
        "receivers": [
            {"name": name, "queued": queued, "dropped_last_hour": dropped}
            for name, (queued, dropped) in receivers.items()
        ],
    }


class WhatIsWrong(unittest.TestCase):
    def test_a_node_that_forwards_nowhere_or_keeps_up_has_nothing(self) -> None:
        self.assertEqual(problems(None), [])
        self.assertEqual(problems(reading(graylog=(12, 0))), [])

    def test_a_drop_is_critical_and_a_long_queue_a_warning(self) -> None:
        found = problems(reading(graylog=(QUEUE_WARNING, 0), loki=(5, 32947)))

        self.assertEqual(
            [(item.severity, item.receiver) for item in found],
            [("critical", "loki"), ("warning", "graylog")],
        )
        self.assertIn("32 947 lines dropped in the last hour", found[0].message)
        self.assertIn("10 000 lines queued", found[1].message)

    def test_statistics_that_stopped_are_said_once(self) -> None:
        for age in (None, STATS_STALE_SECONDS + 60):
            with self.subTest(age=age):
                found = problems(reading(age, graylog=(None, 0), loki=(None, 0)))
                self.assertEqual(len(found), 1)
                self.assertIn("no queue statistics", found[0].message)


class WhyAReceiverIsNotReached(unittest.TestCase):
    def unreached(self, queued: int) -> dict[str, object]:
        found = reading(graylog=(queued, 0))
        receivers = found["receivers"]
        assert isinstance(receivers, list)
        receivers[0]["last_error"] = {"reason": "Connection timed out", "age_sec": 40}
        return found

    def test_the_reason_goes_with_a_long_queue(self) -> None:
        found = problems(self.unreached(QUEUE_WARNING))

        self.assertEqual(
            found[0].message, "traffic log to graylog: 10 000 lines queued (Connection timed out)"
        )

    def test_a_reason_alone_is_not_a_problem_here(self) -> None:
        """A few lines that never leave are the poller's to time (forward_waiting_since)."""

        self.assertEqual(problems(self.unreached(3)), [])

    def test_the_terminal_says_it(self) -> None:
        self.assertEqual(
            status_line(self.unreached(3)), "graylog 3 queued, not reached: Connection timed out"
        )

    def test_a_node_that_does_not_report_it_reads_as_before(self) -> None:
        self.assertIsNone(unreached({"name": "graylog", "queued": 3}))
        self.assertIsNone(unreached({"name": "graylog", "last_error": {"reason": ""}}))


class TheTerminalLine(unittest.TestCase):
    def test_each_receiver_and_its_queue(self) -> None:
        self.assertIsNone(status_line(None))
        self.assertEqual(
            status_line(reading(graylog=(7052, 32947), loki=(None, 0))),
            "graylog 7 052 queued, 32 947 DROPPED in the last hour; loki queue unknown",
        )

    def test_the_status_command_prints_it(self) -> None:
        import io

        from haprion.cli import status

        node = {
            "name": "node-a",
            "mgmt_host": "node-a.example.com",
            "reachable": True,
            "status_ok": True,
            "status": {
                "haproxy": {"active": True},
                "keepalived": {"active": True, "state": "MASTER"},
                "vip": {"owner": True},
                "stats_ok": True,
                "log_forwarding": reading(graylog=(0, 0)),
            },
        }
        out = io.StringIO()
        status._render({"cluster": "alpha", "result": {"nodes": [node], "summary": {}}}, out)

        self.assertIn("  Log forward:  graylog 0 queued\n", out.getvalue())


if __name__ == "__main__":
    unittest.main()
