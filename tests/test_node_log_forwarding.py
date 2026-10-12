"""A node's log forwarding queues, from rsyslog's statistics to the status (B289).

The reader is extracted from `install/node/haprion-node-status` verbatim and run
against files written here, as `test_node_resources` does: the script is
installed on the nodes rather than imported. The statistics lines are the form
rsyslog 8.2512's impstats wrote in the measurement of 26-10-12.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any

SCRIPT = Path(__file__).resolve().parents[1] / "install" / "node" / "haprion-node-status"
READER = re.compile(
    r"^#\n# rsyslog's forwarding to the cluster's external receivers.*?(?=^def read_server_state_unapplied)",
    re.DOTALL | re.MULTILINE,
)
NOW = time.mktime((2026, 10, 12, 9, 30, 0, 0, 0, -1))

FORWARD = """\
if ($programname == "haproxy-traffic" and $msg startswith " {") then {
    action(type="omfwd"
           name="haprion-graylog"
           target="192.0.2.20")
    action(type="omfwd"
           name="haprion-loki"
           target="192.0.2.21")
}
"""


def line(seconds_ago: int, name: str, **counters: int) -> str:
    stamp = time.strftime("%a %b %d %H:%M:%S %Y", time.localtime(NOW - seconds_ago))
    return f"{stamp}: " + json.dumps({"name": name, "origin": "core.queue", **counters})


class ReaderCase(unittest.TestCase):
    """The reader, extracted and run against a directory of this test's own."""

    read: Any

    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        found = READER.search(SCRIPT.read_text())
        assert found, "the reader is no longer where the test extracts it from"
        namespace: dict[str, Any] = {
            "Path": lambda name: self.root / str(name).lstrip("/"),
            "os": os,
            "re": re,
            "time": time,
            "json": json,
        }
        exec(found.group(0), namespace)  # noqa: S102 - the file under test, read from disk
        self.read = namespace["read_log_forwarding"]
        (self.root / "etc/rsyslog.d/haprion").mkdir(parents=True)
        (self.root / "var/log/haprion").mkdir(parents=True)

    def forward(self, text: str = FORWARD) -> None:
        (self.root / "etc/rsyslog.d/haprion/forward.conf").write_text(text)

    def stats(self, *lines: str) -> None:
        (self.root / "var/log/haprion/rsyslog-stats.json").write_text("\n".join(lines) + "\n")


class TheNodeReadsItsForwardingQueues(ReaderCase):
    def test_a_node_that_forwards_nowhere_says_nothing(self) -> None:
        self.assertIsNone(self.read(now=NOW))

    def test_the_queue_is_the_newest_minute_and_the_drops_the_last_hour(self) -> None:
        self.forward()
        self.stats(
            line(4000, "haprion-graylog queue[DA]", size=99, **{"discarded.full": 500}),
            line(120, "haprion-graylog queue[DA]", size=6000, **{"discarded.full": 12979}),
            line(120, "haprion-graylog queue", size=700, **{"discarded.full": 0}),
            line(60, "haprion-graylog queue[DA]", size=6221, **{"discarded.full": 19968}),
            line(60, "haprion-graylog queue", size=831, **{"discarded.full": 0}),
            line(60, "haprion-graylog", processed=0, suspended=0),
            line(60, "haprion-loki queue", size=0, **{"discarded.full": 0}),
            line(60, "haprion-loki queue[DA]", size=0, **{"discarded.full": 0}),
            line(60, "main Q", size=3, **{"discarded.full": 7}),
            "not a statistics line",
        )

        self.assertEqual(
            self.read(now=NOW),
            {
                "stats_age_sec": 60,
                "receivers": [
                    {"name": "graylog", "queued": 7052, "dropped_last_hour": 32947},
                    {"name": "loki", "queued": 0, "dropped_last_hour": 0},
                ],
            },
        )

    def test_without_statistics_the_receivers_are_named_and_nothing_is_claimed(self) -> None:
        self.forward()

        self.assertEqual(
            self.read(now=NOW),
            {
                "stats_age_sec": None,
                "receivers": [
                    {"name": "graylog", "queued": None, "dropped_last_hour": 0},
                    {"name": "loki", "queued": None, "dropped_last_hour": 0},
                ],
            },
        )

    def test_a_receiver_the_file_no_longer_names_is_not_reported(self) -> None:
        self.forward(FORWARD.replace('name="haprion-loki"', 'name="haprion-elastic"'))
        self.stats(line(60, "haprion-loki queue", size=40, **{"discarded.full": 3}))

        names = [item["name"] for item in self.read(now=NOW)["receivers"]]

        self.assertEqual(names, ["elastic", "graylog"])


#
# forward.conf as rsyslog_forward renders it, one parameter a line, and
# rsyslog's own lines as a node's journal held them (26-10-12).
#
FORWARD_WITH_PORTS = """\
if ($programname == "haproxy-traffic" and $msg startswith " {") then {
    action(type="omfwd"
           name="haprion-graylog"
           target="192.0.2.20"
           port="1514"
           protocol="tcp")
    action(type="omfwd"
           name="haprion-loki"
           target="192.0.2.21"
           port="6514"
           protocol="tcp")
}
"""
TIMED_OUT = (
    "cannot connect to 192.0.2.20:1514 (took 133.34 seconds): Connection timed out "
    "[v8.2512.0 try https://www.rsyslog.com/e/2027 ]"
)
RESUMED = (
    "action 'haprion-graylog' resumed (module 'builtin:omfwd') "
    "[v8.2512.0 try https://www.rsyslog.com/e/2359 ]"
)
STARTED = (
    '[origin software="rsyslogd" swVersion="8.2512.0" x-pid="604501" '
    'x-info="https://www.rsyslog.com"] start'
)


class TheNodeSaysWhyAReceiverIsNotReached(ReaderCase):
    def errors(self, *journal: tuple[int, str]) -> dict[str, Any]:
        self.forward(FORWARD_WITH_PORTS)
        entries = [(NOW - seconds_ago, message) for seconds_ago, message in journal]
        return {
            item["name"]: item.get("last_error")
            for item in self.read(now=NOW, journal=entries)["receivers"]
        }

    def test_the_newest_failure_names_the_reason_and_its_age(self) -> None:
        refused = TIMED_OUT.replace(
            "(took 133.34 seconds): Connection timed out", "(took 0.00 seconds): Connection refused"
        )
        found = self.errors((300, TIMED_OUT), (40, refused), (40, "rsyslogd: " + refused))

        self.assertEqual(found["graylog"], {"reason": "Connection refused", "age_sec": 40})
        self.assertIsNone(found["loki"])

    def test_a_receiver_that_resumed_since_has_no_error(self) -> None:
        self.assertIsNone(self.errors((300, TIMED_OUT), (100, RESUMED))["graylog"])

    def test_a_failure_after_resuming_counts_again(self) -> None:
        found = self.errors((300, RESUMED), (100, TIMED_OUT))

        self.assertEqual(found["graylog"], {"reason": "Connection timed out", "age_sec": 100})

    def test_a_restart_of_rsyslog_clears_what_the_old_one_said(self) -> None:
        self.assertIsNone(self.errors((300, TIMED_OUT), (200, STARTED))["graylog"])

    def test_a_failure_older_than_ten_minutes_is_not_news(self) -> None:
        self.assertIsNone(self.errors((601, TIMED_OUT))["graylog"])
        self.assertIsNotNone(self.errors((599, TIMED_OUT))["graylog"])

    def test_another_address_or_port_is_another_receiver(self) -> None:
        other = TIMED_OUT.replace("192.0.2.20:1514", "192.0.2.20:6514")

        self.assertEqual(self.errors((60, other)), {"graylog": None, "loki": None})

    def test_without_ports_in_the_file_the_journal_is_not_read(self) -> None:
        self.forward()

        def journal_read() -> list[tuple[float, str]]:
            raise AssertionError("the journal was read")

        self.read.__globals__["read_rsyslog_journal"] = journal_read
        self.assertNotIn("last_error", self.read(now=NOW)["receivers"][0])


if __name__ == "__main__":
    unittest.main()
