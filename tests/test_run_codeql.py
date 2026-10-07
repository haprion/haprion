"""`tools/run-codeql` keeps the results and not the databases (2026-10-07).

The databases are a step towards the SARIF: nothing reads them afterwards, and
left behind they grew to 38 GB over 222 runs. A stand-in for the CodeQL binary
builds a database and then fails the analysis, which is the case a cleanup
written for the happy path would miss.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
SCRIPT = BASE / "tools" / "run-codeql"

STAND_IN = """#!/bin/sh
if [ "$1" = database ] && [ "$2" = create ]; then
    mkdir -p "$3/python"
    echo data > "$3/python/db"
    exit 0
fi
exit 3
"""


class RunCodeqlTests(unittest.TestCase):
    def test_a_failed_analysis_leaves_no_database_behind(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            codeql = root / "codeql"
            codeql.write_text(STAND_IN, encoding="utf-8")
            codeql.chmod(0o755)
            output = root / "result"

            run = subprocess.run(
                [str(SCRIPT), str(output)],
                env={**os.environ, "CODEQL_BIN": str(codeql)},
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(run.returncode, 3, run.stderr)
            self.assertTrue(output.is_dir())
            self.assertFalse((output / "database").exists())

    def test_an_output_inside_the_repository_is_refused(self) -> None:
        run = subprocess.run(
            [str(SCRIPT), str(BASE / "codeql-out")],
            env={**os.environ, "CODEQL_BIN": "true"},
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(run.returncode, 64)
        self.assertFalse((BASE / "codeql-out").exists())


if __name__ == "__main__":
    unittest.main()
