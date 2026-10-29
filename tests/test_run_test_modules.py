from __future__ import annotations

import json
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
RUNNER = BASE / "tools" / "run_test_modules.py"

PASSING = """\
import unittest

class T(unittest.TestCase):
    def test_ok(self) -> None:
        pass

    @unittest.skip("not here")
    def test_skipped(self) -> None:
        pass
"""

FAILING = """\
import unittest

class T(unittest.TestCase):
    def test_wrong(self) -> None:
        self.assertEqual("seen", "expected")
"""


class RunTestModulesTests(unittest.TestCase):
    """The gate's suites pass through this runner; a failure it hides is a green gate."""

    def suite(self, root: Path, modules: dict[str, str]) -> Path:
        tests = root / "tests"
        tests.mkdir()
        for name, text in modules.items():
            (tests / name).write_text(text, encoding="utf-8")
        return tests

    def execute(
        self, tests: Path, durations: Path, jobs: int = 2, *extra: str
    ) -> subprocess.CompletedProcess[str]:
        command = f"{shlex.quote(sys.executable)} -m unittest discover -s tests -v"
        return subprocess.run(
            [sys.executable, str(RUNNER), "--durations", str(durations), "--jobs", str(jobs)]
            + [*extra, "--suite", "demo", str(tests), command],
            text=True,
            capture_output=True,
            check=False,
        )

    def test_a_failing_module_fails_the_run_and_shows_its_output(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            tests = self.suite(
                root,
                {
                    "test_a.py": PASSING,
                    "test_b.py": FAILING,
                    "test_c.py": "import no_such_module\n",
                },
            )
            result = self.execute(tests, root / "durations.json")
        self.assertEqual(result.returncode, 1)
        self.assertIn("'seen' != 'expected'", result.stdout)
        self.assertIn("No module named 'no_such_module'", result.stdout)
        self.assertIn("failed: demo/test_b.py, demo/test_c.py", result.stderr)
        self.assertIn("demo: 4 tests, 1 skipped, 3 modules", result.stdout)

    def test_a_module_that_does_not_finish_fails_and_is_named(self) -> None:
        """Review 26-10-25, 5-03: a hanging test stood the gate still and named nothing."""

        hanging = (
            "import subprocess, sys, time, unittest\n"
            "class T(unittest.TestCase):\n"
            "    def test_hang(self) -> None:\n"
            "        subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
            "        time.sleep(60)\n"
        )
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            tests = self.suite(root, {"test_a.py": PASSING, "test_hang.py": hanging})
            durations = root / "durations.json"
            durations.write_text(json.dumps({"demo/test_hang.py": 0.1, "demo/test_a.py": 0.1}))
            result = self.execute(tests, durations, 2, "--floor", "2")
        self.assertEqual(result.returncode, 1)
        self.assertIn("stopped after 2 s: a test in it did not finish", result.stdout)
        self.assertIn("failed: demo/test_hang.py", result.stderr)

    def test_a_module_that_leaves_a_temporary_file_fails_and_names_it(self) -> None:
        leaking = (
            "import os, tempfile, unittest\n"
            "class T(unittest.TestCase):\n"
            "    def test_leak(self) -> None:\n"
            "        tempfile.mkdtemp(prefix='forgotten-')\n"
            "        os.close(tempfile.mkstemp(prefix='.org.chromium.Chromium.')[0])\n"
        )
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            tests = self.suite(root, {"test_a.py": PASSING, "test_leak.py": leaking})
            result = self.execute(tests, root / "durations.json")
        self.assertEqual(result.returncode, 1)
        self.assertIn("left in its temporary directory: forgotten-", result.stdout)
        # Chromium's own shared memory is not the test's to clean up.
        self.assertNotIn(".org.chromium.Chromium.", result.stdout)
        self.assertIn("failed: demo/test_leak.py", result.stderr)

    def test_a_module_that_leaves_a_file_open_fails(self) -> None:
        leaving = (
            "import unittest\n"
            "class T(unittest.TestCase):\n"
            "    def test_open(self) -> None:\n"
            "        open(__file__).read()\n"
        )
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            tests = self.suite(root, {"test_a.py": PASSING, "test_open.py": leaving})
            result = self.execute(tests, root / "durations.json")
        self.assertEqual(result.returncode, 1)
        self.assertIn("ResourceWarning: unclosed file", result.stdout)
        self.assertIn("failed: demo/test_open.py", result.stderr)

    def test_a_module_that_keeps_a_file_open_until_it_exits_fails(self) -> None:
        """Review 26-10-29, C02: what is let go after the run was never warned about."""

        #
        # With a thread still blocked in accept(), which was measured to keep
        # Python from saying anything at exit.
        #
        keeping = (
            "import socket, threading, unittest\n"
            "KEPT = []\n"
            "class T(unittest.TestCase):\n"
            "    @classmethod\n"
            "    def setUpClass(cls) -> None:\n"
            "        cls.stream = open(__file__)\n"
            "        cls.listener = socket.socket()\n"
            "        cls.listener.bind(('127.0.0.1', 0))\n"
            "        cls.listener.listen(1)\n"
            "        threading.Thread(target=cls.listener.accept, daemon=True).start()\n"
            "    def test_kept(self) -> None:\n"
            "        KEPT.append(open(__file__))\n"
        )
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            tests = self.suite(root, {"test_a.py": PASSING, "test_kept.py": keeping})
            result = self.execute(tests, root / "durations.json")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("left open after its tests ran", result.stdout)
        self.assertEqual(result.stdout.count("tests/test_kept.py\n"), 2, result.stdout)
        self.assertIn("-> socket:[", result.stdout)
        self.assertIn("failed: demo/test_kept.py", result.stderr)

    def test_every_module_discover_would_find_is_run(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            # unittest's default pattern is test*.py, not test_*.py.
            tests = self.suite(root, {"test_a.py": PASSING, "testb.py": PASSING})
            (tests / "helper.py").write_text(FAILING, encoding="utf-8")
            result = self.execute(tests, root / "durations.json")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("demo: 4 tests, 2 skipped, 2 modules", result.stdout)

    def test_the_slowest_module_last_time_starts_first(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            tests = self.suite(root, {"test_a.py": PASSING, "test_b.py": PASSING})
            durations = root / "durations.json"
            durations.write_text(
                json.dumps({"demo/test_a.py": 1.0, "demo/test_b.py": 9.0, "other/test_x.py": 3.0}),
                encoding="utf-8",
            )
            result = self.execute(tests, durations, jobs=1)
            kept = json.loads(durations.read_text(encoding="utf-8"))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        lines = [line for line in result.stdout.splitlines() if line.startswith("ok")]
        self.assertIn("test_b.py", lines[0])
        self.assertIn("test_a.py", lines[1])
        # Another suite's timings survive a run of this one alone.
        self.assertEqual(kept["other/test_x.py"], 3.0)
        self.assertEqual(set(kept), {"demo/test_a.py", "demo/test_b.py", "other/test_x.py"})


if __name__ == "__main__":
    unittest.main()
