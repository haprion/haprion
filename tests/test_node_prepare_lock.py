"""Step 4 waits for a running deploy instead of racing it (B447, N03).

`haprion-pull-deploy` restarts rsyslog and the log sockets, as step 4 does when
it holds the log socket; between the one's stop and the other's start rsyslog
makes `/var/lib/haproxy/dev/log` itself and systemd cannot bind over it. Both
take `/run/haprion-deploy.lock`; the deploy refuses when it is held, step 4
waits for it.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

INSTALL = Path(__file__).resolve().parents[1] / "install"
NODE_PREPARE = INSTALL / "04-node-prepare"
LIB = INSTALL / "node-lib.sh"


def function(script: str, name: str) -> str:
    found = re.search(rf"^{name}\(\) \{{\n.*?^\}}\n", script, re.MULTILINE | re.DOTALL)
    assert found is not None, f"04-node-prepare has no {name}"
    return found.group(0)


class StepFourWaitsForTheDeploy(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="deploy-lock-"))
        self.addCleanup(shutil.rmtree, self.root, True)
        self.lock = self.root / "haprion-deploy.lock"
        self.script = NODE_PREPARE.read_text(encoding="utf-8")

    def hold(self, seconds: float) -> subprocess.Popen[bytes]:
        holder = subprocess.Popen(  # fixed binaries, a scratch file
            ["/usr/bin/flock", str(self.lock), "/bin/sleep", str(seconds)]
        )
        self.addCleanup(holder.wait)
        self.addCleanup(holder.kill)
        for _ in range(100):
            if self.lock.exists():
                break
            time.sleep(0.02)
        time.sleep(0.2)
        return holder

    def run_step(self, wait: int) -> subprocess.CompletedProcess[str]:
        program = "\n".join(
            (
                f"source {LIB}",
                f'DEPLOY_LOCK="{self.lock}"',
                f"DEPLOY_LOCK_WAIT={wait}",
                function(self.script, "wait_for_deploy"),
                "wait_for_deploy",
                "echo through",
            )
        )
        return subprocess.run(  # fixed interpreter, the step's own function
            ["/bin/bash", "-c", program],
            env={**os.environ},
            capture_output=True,
            text=True,
            check=False,
        )

    def test_a_free_lock_is_taken_without_a_word(self) -> None:
        done = self.run_step(5)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertNotIn("waiting", done.stdout)
        self.assertIn("through", done.stdout)

    def test_a_deploy_in_progress_is_waited_out(self) -> None:
        self.hold(1.5)
        done = self.run_step(20)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("waiting for a running deploy", done.stdout)
        self.assertIn("through", done.stdout)

    def test_a_deploy_that_does_not_end_stops_the_step_with_a_reason(self) -> None:
        self.hold(4)
        done = self.run_step(1)
        self.assertEqual(done.returncode, 1)
        self.assertIn("a deploy has held", done.stderr)
        self.assertNotIn("through", done.stdout)

    def test_the_wait_comes_before_the_step_changes_anything(self) -> None:
        self.assertLess(
            self.script.index("\nwait_for_deploy\n"), self.script.index('step "Service accounts"')
        )
        self.assertIn('DEPLOY_LOCK="/run/haprion-deploy.lock"', self.script)
        deploy = (INSTALL / "node" / "haprion-pull-deploy").read_text(encoding="utf-8")
        self.assertIn("exec 9>/run/haprion-deploy.lock", deploy)


if __name__ == "__main__":
    unittest.main()
