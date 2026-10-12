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


class TheNodeReadsItsForwardingQueues(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
