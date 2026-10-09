"""A node's CPU and memory, from the node's files to the status command (B239).

The reader is extracted from `install/node/haprion-node-status` verbatim and run
against files written here, as `test_node_runtime_stat` does with the stat
parser: the script is installed on the nodes rather than imported, so a test
that reimplemented the reading would prove nothing about what the nodes run.
"""

from __future__ import annotations

import io
import os
import re
import tempfile
import unittest
from pathlib import Path
from typing import Any

from haproxy_mgmt import node_resources
from haproxy_mgmt.cli import status

SCRIPT = Path(__file__).resolve().parents[1] / "install" / "node" / "haprion-node-status"
READER = re.compile(r"^def read_resources\(\):.*?(?=^#\n# A directive)", re.DOTALL | re.MULTILINE)

STAT = "cpu  1000 10 200 8000 300 0 40 50 7 0\ncpu0 1000 10 200 8000 300 0 40 50 7 0\nintr 1 2 3\n"
MEMINFO = "MemTotal:         910336 kB\nMemFree:           39936 kB\nMemAvailable:     589824 kB\n"


class TheNodeReadsItsOwnFiles(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        (self.root / "proc").mkdir()
        found = READER.search(SCRIPT.read_text())
        assert found, "the reader is no longer where the test extracts it from"
        namespace: dict[str, Any] = {
            "Path": lambda name: self.root / str(name).lstrip("/"),
            "os": os,
        }
        exec(found.group(0), namespace)  # noqa: S102 - the file under test, read from disk
        self.read = namespace["read_resources"]
        self.summary = namespace["memory_summary"]

    def write(self, name: str, text: str) -> None:
        (self.root / "proc" / name).write_text(text)

    def test_counters_sizes_and_load_are_read(self) -> None:
        self.write("stat", STAT)
        self.write("meminfo", MEMINFO)
        self.write("loadavg", "0.08 0.15 0.16 1/150 3050390\n")

        resources = self.read()

        # user nice system idle iowait irq softirq steal; guest is in user.
        self.assertEqual(resources["cpu"], {"total": 9600, "idle": 8300})
        self.assertEqual(resources["memory"], {"total_kb": 910336, "available_kb": 589824})
        self.assertEqual(resources["load"], 0.08)
        self.assertEqual(resources["cpus"], os.cpu_count())
        # The node's own output and the status command say the same thing.
        self.assertEqual(self.summary(resources["memory"]), node_resources.memory_line(resources))

    def test_a_file_that_cannot_be_read_is_null_not_zero(self) -> None:
        self.write("meminfo", "MemTotal: 910336 kB\n")  # no MemAvailable

        resources = self.read()

        self.assertIsNone(resources["cpu"])
        self.assertIsNone(resources["memory"])
        self.assertIsNone(resources["load"])
        self.assertEqual(self.summary(resources["memory"]), "unknown")


def reading(total: int, idle: int) -> dict[str, Any]:
    return {"cpu": {"total": total, "idle": idle}, "memory": None, "load": None, "cpus": 1}


class TheFigures(unittest.TestCase):
    def test_cpu_is_the_share_between_two_readings(self) -> None:
        self.assertEqual(node_resources.cpu_percent(reading(1000, 900), reading(3000, 2400)), 25)

    def test_cpu_needs_two_readings_that_move_forward(self) -> None:
        self.assertIsNone(node_resources.cpu_percent(None, reading(3000, 2400)))
        # A node restarted in between starts its counters again.
        self.assertIsNone(node_resources.cpu_percent(reading(5000, 4000), reading(3000, 2400)))
        self.assertIsNone(node_resources.cpu_percent(reading(3000, 2400), reading(3000, 2400)))

    def test_memory_is_what_a_new_process_could_not_have(self) -> None:
        resources = {"memory": {"total_kb": 1000, "available_kb": 350}}
        self.assertEqual(node_resources.memory_percent(resources), 65)
        self.assertIsNone(node_resources.memory_percent({"memory": None}))
        self.assertIsNone(
            node_resources.memory_percent({"memory": {"total_kb": 0, "available_kb": 0}})
        )


class TheStatusCommand(unittest.TestCase):
    def render(self, node_status: dict[str, Any]) -> str:
        envelope = {
            "cluster": "alpha",
            "result": {
                "nodes": [
                    {
                        "name": "node-a",
                        "mgmt_host": "node-a.example.com",
                        "reachable": True,
                        "status_ok": True,
                        "status": node_status,
                    }
                ],
                "summary": {"vip_state": "single_owner", "release_state": "converged"},
            },
        }
        writer = io.StringIO()
        status._render(envelope, writer)
        return writer.getvalue()

    def node(self, **extra: Any) -> dict[str, Any]:
        return {
            "haproxy": {"active": True},
            "keepalived": {"active": True, "state": "MASTER"},
            "vip": {"owner": True},
            "stats_ok": True,
            **extra,
        }

    def test_memory_and_load_are_shown_when_the_node_reports_them(self) -> None:
        shown = self.render(
            self.node(
                resources={
                    "cpu": {"total": 9600, "idle": 8300},
                    "memory": {"total_kb": 910336, "available_kb": 589824},
                    "load": 0.08,
                    "cpus": 1,
                }
            )
        )

        self.assertIn("  Memory:       35 % used (313 of 889 MB)\n", shown)
        self.assertIn("  Load:         0.08 on 1 CPU, last minute\n", shown)

    def test_a_node_from_before_says_nothing_about_them(self) -> None:
        shown = self.render(self.node())

        self.assertNotIn("Memory:", shown)
        self.assertNotIn("Load:", shown)


if __name__ == "__main__":
    unittest.main()
