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
LEFT_OPEN = BASE / "tools" / "unittest_left_open.py"

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

    def test_a_module_that_reads_this_machine_s_configuration_fails(self) -> None:
        """Review 26-10-29, A09: a test that passes on the manager by reading its policy."""

        #
        # A missing file is the same failure: the opening is refused before it
        # is tried, and so is one a broad handler swallows.
        #
        reading = (
            "import unittest\n"
            "class T(unittest.TestCase):\n"
            "    def test_read(self) -> None:\n"
            "        try:\n"
            "            open('/etc/haprion/runtime-policy.yaml').close()\n"
            "        except Exception:\n"
            "            pass\n"
        )
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            tests = self.suite(root, {"test_a.py": PASSING, "test_read.py": reading})
            result = self.execute(tests, root / "durations.json")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("reached for this machine's configuration", result.stdout)
        self.assertIn("/etc/haprion/runtime-policy.yaml", result.stdout)
        self.assertIn("failed: demo/test_read.py", result.stderr)

    def test_a_module_that_looks_at_this_machine_s_configuration_fails(self) -> None:
        """Review 26-10-29, CC01/AA08: a stat, an existence or access check gave no audit event."""

        looking = (
            "import os, pathlib, unittest\n"
            "class T(unittest.TestCase):\n"
            "    def test_exists(self) -> None:\n"
            "        pathlib.Path('/etc/haprion/runtime-policy.yaml').exists()\n"
            "    def test_access(self) -> None:\n"
            "        os.access('/etc/haprion/ui.toml', os.R_OK)\n"
            "    def test_link(self) -> None:\n"
            "        os.path.lexists('/etc/haprion/registry')\n"
            "    def test_symlink(self) -> None:\n"
            "        pathlib.Path('/etc/haprion/keys').is_symlink()\n"
            "    def test_readlink(self) -> None:\n"
            "        try:\n"
            "            os.readlink('/etc/haprion/current')\n"
            "        except OSError:\n"
            "            pass\n"
            "    def test_relative(self) -> None:\n"
            "        os.chdir('/etc')\n"
            "        try:\n"
            "            os.path.isdir('haprion/ui-secrets')\n"
            "        finally:\n"
            "            os.chdir('/')\n"
            "    def test_made(self) -> None:\n"
            "        try:\n"
            "            os.mkdir('/etc/haprion/made')\n"
            "        except OSError:\n"
            "            pass\n"
        )
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            tests = self.suite(root, {"test_a.py": PASSING, "test_look.py": looking})
            result = self.execute(tests, root / "durations.json")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        for path in (
            "runtime-policy.yaml",
            "ui.toml",
            "registry",
            "keys",
            "current",
            "ui-secrets",
            "made",
        ):
            self.assertIn(f"/etc/haprion/{path}\n", result.stdout)
        self.assertIn("failed: demo/test_look.py", result.stderr)

    def test_a_path_there_resolved_but_not_read_passes(self) -> None:
        # As the policy loader resolves a policy's default directories.
        resolving = (
            "import os, pathlib, unittest\n"
            "class T(unittest.TestCase):\n"
            "    def test_resolve(self) -> None:\n"
            "        pathlib.Path('/etc/haprion/ndes-profiles').resolve()\n"
            "        os.path.realpath('/etc/haprion/no-such/file')\n"
        )
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            tests = self.suite(root, {"test_resolve.py": resolving})
            result = self.execute(tests, root / "durations.json")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_a_file_held_in_a_reference_cycle_fails_the_module(self) -> None:
        """Review 26-10-29, CC03: collected after unittest's filter, it was closed in silence."""

        cycle = (
            "import unittest\n"
            "class Holder:\n"
            "    pass\n"
            "class T(unittest.TestCase):\n"
            "    def test_cycle(self) -> None:\n"
            "        held = Holder()\n"
            "        held.me = held\n"
            "        held.stream = open(__file__)\n"
        )
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            tests = self.suite(root, {"test_a.py": PASSING, "test_cycle.py": cycle})
            result = self.execute(tests, root / "durations.json")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("ResourceWarning: unclosed file", result.stdout)
        self.assertIn("failed: demo/test_cycle.py", result.stderr)

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


class TargetedRunTests(unittest.TestCase):
    """Review 26-10-29, CC04: `tools/unittest_left_open.py tests.<module>` alone is the gate too."""

    def run_module(self, text: str, *pass_fds: int) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "tests").mkdir()
            (root / "tests" / "test_one.py").write_text(text, encoding="utf-8")
            return subprocess.run(
                [sys.executable, str(LEFT_OPEN), "discover", "-s", "tests", "-p", "test_one.py"],
                cwd=root,
                text=True,
                capture_output=True,
                check=False,
                pass_fds=pass_fds,
            )

    def test_what_the_run_was_started_with_is_not_left_open_by_it(self) -> None:
        # A terminal, an editor or a CI agent hands down more than 0-2.
        with open(__file__, encoding="utf-8") as inherited:
            result = self.run_module(PASSING, inherited.fileno())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("left open", result.stderr)

    def test_a_resource_warning_fails_the_run(self) -> None:
        warned = (
            "import unittest\n"
            "class T(unittest.TestCase):\n"
            "    def setUp(self) -> None:\n"
            "        self.stream = open(__file__)\n"
            "        self.addCleanup(self.noop)\n"
            "    def noop(self) -> None:\n"
            "        pass\n"
            "    def test_one(self) -> None:\n"
            "        self.assertTrue(self.stream.readable())\n"
        )
        result = self.run_module(warned)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("ResourceWarning: unclosed file", result.stderr)
        self.assertIn("something the run opened was left to the garbage collector", result.stderr)

    def test_a_resource_warning_at_import_fails_the_run(self) -> None:
        # Before unittest's own filter, which would show it, is in place.
        imported = "import unittest\nopen(__file__)\n" + PASSING.split("\n", 1)[1]
        result = self.run_module(imported)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("something the run opened was left to the garbage collector", result.stderr)


class EveryRunGoesThroughTheGateTests(unittest.TestCase):
    """Review 26-10-29, CC02: the database tests and the run without HAProxy bypassed it."""

    SCRIPTS = ("run-tests", "ui/run-tests", "ui/tools/test-database")

    def test_no_script_runs_plain_unittest(self) -> None:
        for name in self.SCRIPTS:
            for number, line in enumerate((BASE / name).read_text().splitlines(), 1):
                with self.subTest(script=name, line=number):
                    if "-m unittest" in line:
                        # A pool suite's command, which the runner rewrites (gated()).
                        self.assertIn("--suite", line)

    def test_each_script_names_the_gate(self) -> None:
        for name in self.SCRIPTS:
            with self.subTest(script=name):
                text = (BASE / name).read_text()
                self.assertTrue(
                    "tools/unittest_left_open.py" in text or "tools/run_test_modules.py" in text
                )


if __name__ == "__main__":
    unittest.main()
