"""What the GitHub workflows run on (B336, 26-10-20).

`ubuntu-latest` moves between Ubuntu versions on GitHub's schedule, so a gate
that passed one day ran on another distribution the next. Every job names the
distribution the product supports and the manager runs, so the gate, the
builds and the database's PostgreSQL are the ones an installation gets.
"""

from __future__ import annotations

import unittest
from pathlib import Path

import yaml

WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"
RUNNER = "ubuntu-26.04"


class EveryJobNamesItsDistribution(unittest.TestCase):
    def test_no_job_runs_on_a_moving_image(self) -> None:
        paths = sorted(WORKFLOWS.glob("*.yml"))
        self.assertTrue(paths)
        for path in paths:
            for name, job in yaml.safe_load(path.read_text())["jobs"].items():
                with self.subTest(workflow=path.name, job=name):
                    self.assertEqual(job.get("runs-on"), RUNNER)


if __name__ == "__main__":
    unittest.main()
