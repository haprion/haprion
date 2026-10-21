"""What the GitHub workflows run on (B336, 26-10-20), and how they fetch.

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


class EveryDownloadIsRetried(unittest.TestCase):
    def test_every_apt_step_retries_a_failed_fetch(self) -> None:
        # One 503 from Launchpad failed a pull request's whole run (26-10-21);
        # apt retries with a growing pause when it is told to.
        for path in sorted(WORKFLOWS.glob("*.yml")):
            for name, job in yaml.safe_load(path.read_text())["jobs"].items():
                for step in job.get("steps", []):
                    script = step.get("run", "")
                    if "apt-get" not in script:
                        continue
                    with self.subTest(workflow=path.name, job=name, step=step.get("name")):
                        self.assertIn("Acquire::Retries=", script)


if __name__ == "__main__":
    unittest.main()
