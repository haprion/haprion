"""Every apt-get the product runs on a host waits for the package lock (26-10-08).

Ubuntu's unattended upgrades hold the lock for minutes, on a fresh VM's first
boot above all, and node preparation stopped on it once - `Could not get lock
/var/lib/dpkg/lock-frontend` - half-way through. `apt-get install` waits with
apt's own `DPkg::Lock::Timeout`; `apt-get update` takes the lists lock, which
that option does not cover (apt 3.2 gave up after 0.008 s, review 26-10-08 F1),
and is asked again while the lock is all that stops it. Both are run here as
the installers and the restore agent run them, against an apt-get that says
the lock is held.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any

from haprion import restore_agent

ROOT = Path(__file__).resolve().parents[1]
LIB = ROOT / "install" / "node-lib.sh"
SHELL = (LIB, ROOT / "install" / "04-node-prepare")
LOCKED = "E: Could not get lock /var/lib/apt/lists/lock. It is held by process 812 (apt-get)"
#
# The one `apt-get update` the shell has, inside `apt_update`.
#
SHELL_UPDATE = 'if output="$(apt-get -o Acquire::Retries=3 update -q 2>&1)"; then'
#
# apt-get run as a command - at the start of one, after `$(`, a pipe or an
# environment assignment - and not named in a message.
#
COMMAND = re.compile(r"(?:^\s*|[;&|(]\s*|\b[A-Z_]+=\S+\s+)apt-get\s")


class EveryAptGetWaits(unittest.TestCase):
    def test_in_the_node_preparation(self) -> None:
        for path in SHELL:
            calls = [
                line.strip()
                for line in path.read_text().splitlines()
                if COMMAND.search(line) and not line.lstrip().startswith("#")
            ]
            with self.subTest(path=path.name):
                self.assertTrue(calls)
                for line in calls:
                    if line == SHELL_UPDATE:
                        continue
                    self.assertNotIn(" update", line, "apt-get update goes through apt_update")
                    self.assertIn('apt-get "${APT_WAIT[@]}"', line)

    def test_the_install_wait_is_apts_own_option(self) -> None:
        source = LIB.read_text()
        self.assertIn("APT_LOCK_SECONDS=600", source)
        self.assertIn('APT_WAIT=(-o "DPkg::Lock::Timeout=${APT_LOCK_SECONDS}")', source)

    def test_in_the_restore_agent(self) -> None:
        source = Path(restore_agent.__file__).read_text()
        calls = re.findall(r'\[\s*"apt-get",[^\]]*\]', source)

        self.assertEqual(restore_agent.APT_WAIT, ("-o", "DPkg::Lock::Timeout=600"))
        self.assertTrue(calls)
        for call in calls:
            if '"update"' in call:
                self.assertEqual(call.count('"update"'), 1)
                self.assertNotIn("*APT_WAIT", call)
            else:
                self.assertIn("*APT_WAIT", call)
        self.assertEqual(source.count('"update"'), 1, "every update goes through _apt_update")


class TheShellUpdateWaitsForTheListsLock(unittest.TestCase):
    """`apt_update` from `install/node-lib.sh`, with an apt-get that is locked out at first."""

    def setUp(self) -> None:
        self.work = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.work)
        self.calls = self.work / "calls"

    def apt_get(self, locked: int, *, then: str = "ok") -> None:
        script = self.work / "apt-get"
        script.write_text(
            "#!/bin/bash\n"
            f'echo "$*" >> "{self.calls}"\n'
            f'n=$(wc -l < "{self.calls}")\n'
            f'if (( n <= {locked} )); then echo "{LOCKED}" >&2; exit 100; fi\n'
            + ("exit 0\n" if then == "ok" else f'echo "{then}" >&2; exit 100\n')
        )
        script.chmod(0o755)

    def run_update(self, seconds: int = 600) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # fixed interpreter, the repository's library
            [
                "/bin/bash",
                "-c",
                f'source "$0"; APT_LOCK_PAUSE=0; APT_LOCK_SECONDS={seconds}; apt_update',
                str(LIB),
            ],
            capture_output=True,
            text=True,
            check=False,
            env={**os.environ, "PATH": f"{self.work}:{os.environ['PATH']}"},
        )

    def asked(self) -> int:
        return len(self.calls.read_text().splitlines()) if self.calls.exists() else 0

    def test_it_asks_again_until_the_lock_is_free(self) -> None:
        self.apt_get(locked=2)
        completed = self.run_update()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(self.asked(), 3)

    def test_another_failure_is_not_waited_for(self) -> None:
        self.apt_get(locked=0, then="E: The repository does not have a Release file.")
        completed = self.run_update()
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(self.asked(), 1)
        self.assertIn("Release file", completed.stderr)

    def test_the_lock_is_given_up_on_after_the_wait(self) -> None:
        self.apt_get(locked=100)
        completed = self.run_update(seconds=0)
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(self.asked(), 1)
        self.assertIn("Could not get lock", completed.stderr)


class Answers:
    """A host whose apt-get answers in turn, and a clock that moves with each pause."""

    def __init__(self, *answers: tuple[int, str]) -> None:
        self.answers = list(answers)
        self.argv: list[list[str]] = []
        self.now = 0.0
        self.pauses: list[float] = []

    def run(self, argv: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        self.argv.append(argv)
        code, stderr = self.answers.pop(0)
        return subprocess.CompletedProcess(argv, code, "", stderr)

    def sleep(self, seconds: float) -> None:
        self.pauses.append(seconds)
        self.now += seconds

    def clock(self) -> float:
        return self.now


class TheRestoreAgentUpdateWaitsForTheListsLock(unittest.TestCase):
    def update(self, host: Answers) -> subprocess.CompletedProcess[str]:
        return restore_agent._apt_update(
            host,  # type: ignore[arg-type]
            sleep=host.sleep,
            clock=host.clock,
        )

    def test_it_asks_again_until_the_lock_is_free(self) -> None:
        host = Answers((100, LOCKED), (100, LOCKED), (0, ""))
        self.assertEqual(self.update(host).returncode, 0)
        self.assertEqual(len(host.argv), 3)
        self.assertEqual(host.pauses, [restore_agent.APT_LOCK_PAUSE] * 2)
        self.assertEqual(host.argv[0], ["apt-get", "-o", "Acquire::Retries=3", "update"])

    def test_another_failure_is_not_waited_for(self) -> None:
        host = Answers((100, "E: The repository does not have a Release file."))
        self.assertEqual(self.update(host).returncode, 100)
        self.assertEqual(host.pauses, [])

    def test_the_lock_is_given_up_on_after_the_wait(self) -> None:
        tries = int(restore_agent.APT_LOCK_SECONDS / restore_agent.APT_LOCK_PAUSE) + 1
        host = Answers(*[(100, LOCKED)] * (tries + 5))
        completed = self.update(host)
        self.assertEqual(completed.returncode, 100)
        self.assertEqual(len(host.argv), tries)
        self.assertGreaterEqual(host.now, restore_agent.APT_LOCK_SECONDS)


if __name__ == "__main__":
    unittest.main()
