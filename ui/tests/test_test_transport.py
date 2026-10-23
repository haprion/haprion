"""The test client loads without a warning (review 2026-10-20).

Starlette 1.x warned on every UI test run that its test client was built on
the old `httpx`; the warning sat in the gate's output, read by nobody. A
warning at this import is now a failing test, whatever it says.
"""

from __future__ import annotations

import subprocess
import sys
import unittest


class TheTestClient(unittest.TestCase):
    def test_it_imports_without_a_warning(self) -> None:
        done = subprocess.run(  # this interpreter, a fixed statement
            [sys.executable, "-W", "error", "-c", "import fastapi.testclient"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(done.returncode, 0, done.stderr)
