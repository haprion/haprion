"""The platform steps' database probes write for a cluster no installation has.

`haprion-backup restore` runs 03-verify on the restored database. Its probes
wrote jobs for a fixed cluster, `alpha`, and a dump taken while a job waited on a
cluster of that name made one active job per cluster refuse them: the allowed
writes failed, the restore left the services stopped, and a refusal could have
passed for the wrong reason (measured 26-11-06 in the install test).
"""

from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parents[2]
SCRIPTS = (BASE / "install/platform/03-verify", BASE / "install/platform/07-platform-services")
BASELINE = BASE / "ui/migrations/versions/0115_baseline.py"
#
# Where a probe names a cluster: the second value of a job row, and the
# search index's column.
#
JOB_ROW = re.compile(r"insert into job \(operation, cluster[^)]*\)\s+values \('[^']*', '([^']*)'")
COLUMN = re.compile(r"cluster = '([^']*)'")
SEARCH_ROW = re.compile(r"insert into search_entry \(cluster[^)]*\)\s+values \('([^']*)'")


def made_by(line: str) -> str:
    """The name the script's own line makes, run as the script runs it."""

    return subprocess.run(  # noqa: S603 - a fixed shell, the line under test
        ["/bin/bash", "-c", f'{line}; printf %s "$PROBE_CLUSTER"'],
        check=True,
        capture_output=True,
        text=True,
    ).stdout


class TheProbesNameNoClusterThatCanExist(unittest.TestCase):
    def test_every_cluster_a_probe_writes_for_is_the_probe_cluster(self) -> None:
        for script in SCRIPTS:
            text = "\n".join(
                line
                for line in script.read_text().splitlines()
                if not line.lstrip().startswith("#")
            )
            named = [
                *JOB_ROW.findall(text),
                *COLUMN.findall(text),
                *SEARCH_ROW.findall(text),
            ]
            with self.subTest(script=script.name):
                self.assertTrue(named)
                self.assertEqual(set(named), {"${PROBE_CLUSTER}"})

    def test_the_probe_cluster_has_the_shape_a_job_row_takes(self) -> None:
        shape = re.search(r"job_cluster_shape CHECK \(.*?cluster ~ '([^']+)'", BASELINE.read_text())
        if shape is None:
            self.fail("job_cluster_shape is not in the baseline")
        for script in SCRIPTS:
            (line,) = [
                line
                for line in script.read_text().splitlines()
                if line.startswith("PROBE_CLUSTER=")
            ]
            made, again = (made_by(line) for _ in range(2))
            with self.subTest(script=script.name):
                self.assertRegex(made, shape.group(1))
                self.assertNotEqual(made, again)


if __name__ == "__main__":
    unittest.main()
