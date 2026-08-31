"""Running a command the way a claimed job has to be run.

These use real subprocesses on purpose. Process groups, signals and pipe
buffering are precisely the parts that behave differently from how they read,
and a mocked Popen would agree with whatever this module happened to do.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
import unittest
import unittest.mock

from haproxy_ui import execution

PYTHON = sys.executable


def script(source: str) -> list[str]:
    return [PYTHON, "-c", source]


class RunningToCompletion(unittest.TestCase):
    def test_stdin_carries_the_request_and_stdout_comes_back(self) -> None:
        completed = execution.run(
            script("import sys; sys.stdout.write(sys.stdin.read().upper())"),
            request="the request",
            timeout_seconds=30,
            still_ours=lambda: True,
        )

        self.assertEqual(completed.ending, "finished")
        self.assertEqual(completed.exit_code, 0)
        self.assertEqual(completed.stdout, "THE REQUEST")

    def test_a_failing_command_is_an_ending_of_finished_with_its_exit_code(self) -> None:
        #
        # "Finished" is about who decided to stop, not about whether the work
        # went well. A command that ran and failed is the operation's answer, and
        # collapsing it into the same bucket as a killed one would lose the
        # difference between a bad deploy and an interrupted one.
        #
        completed = execution.run(
            script("import sys; sys.stderr.write('no'); sys.exit(3)"),
            request="",
            timeout_seconds=30,
            still_ours=lambda: True,
        )

        self.assertEqual(completed.ending, "finished")
        self.assertEqual(completed.exit_code, 3)
        self.assertEqual(completed.stderr, "no")

    def test_output_larger_than_a_pipe_buffer_does_not_deadlock(self) -> None:
        #
        # The reason communicate runs in its own thread. A command that writes
        # more than the pipe holds blocks until somebody reads, and a loop that
        # polls without reading waits for a child that is waiting for it.
        #
        completed = execution.run(
            script("import sys; sys.stdout.write('x' * 400000)"),
            request="",
            timeout_seconds=30,
            still_ours=lambda: True,
        )

        self.assertEqual(completed.ending, "finished")
        self.assertEqual(len(completed.stdout), 400000)

    def test_stdout_beyond_the_contract_limit_is_drained_but_not_retained(self) -> None:
        completed = execution.run(
            script(f"import sys; sys.stdout.write('x' * ({execution.STDOUT_LIMIT} + 1))"),
            request="",
            timeout_seconds=30,
            still_ours=lambda: True,
        )

        self.assertEqual(completed.ending, "finished")
        self.assertEqual(completed.stdout_error, "too_large")
        self.assertEqual(len(completed.stdout), execution.STDOUT_LIMIT)

    def test_stdout_must_be_utf8(self) -> None:
        completed = execution.run(
            script("import os; os.write(1, bytes((255,)))"),
            request="",
            timeout_seconds=30,
            still_ours=lambda: True,
        )

        self.assertEqual(completed.stdout_error, "invalid_utf8")

    def test_stderr_keeps_both_ends_with_an_explicit_marker(self) -> None:
        completed = execution.run(
            script("import sys; sys.stderr.write('first\\n' + 'x' * 90000 + '\\nlast')"),
            request="",
            timeout_seconds=30,
            still_ours=lambda: True,
        )

        self.assertLessEqual(len(completed.stderr.encode("utf-8")), 65536)
        self.assertTrue(completed.stderr.startswith("first"))
        self.assertTrue(completed.stderr.endswith("last"))
        self.assertIn("diagnostics truncated", completed.stderr)


class StoppingWhatItStarted(unittest.TestCase):
    def setUp(self) -> None:
        execution.TICK_SECONDS = 0.05
        execution.GRACE_SECONDS = 2.0
        self.addCleanup(setattr, execution, "TICK_SECONDS", 5.0)
        self.addCleanup(setattr, execution, "GRACE_SECONDS", 10.0)

    def test_a_lost_lease_ends_the_run(self) -> None:
        started = time.monotonic()
        completed = execution.run(
            script("import time; time.sleep(30)"),
            request="",
            timeout_seconds=30,
            still_ours=lambda: False,
        )

        self.assertEqual(completed.ending, "lease_lost")
        self.assertLess(time.monotonic() - started, 10)

    def test_a_command_that_outlives_its_timeout_is_stopped(self) -> None:
        completed = execution.run(
            script("import time; time.sleep(30)"),
            request="",
            timeout_seconds=0.1,
            still_ours=lambda: True,
        )

        self.assertEqual(completed.ending, "timeout")

    def test_a_child_of_the_command_is_stopped_too(self) -> None:
        #
        # The whole reason for the new session. A deploy's real work happens in
        # an SSH child, and a child that survives the worker's kill keeps writing
        # to a cluster this worker no longer owns.
        #
        source = (
            "import os, sys, time\n"
            "read, write = os.pipe()\n"
            "if os.fork() == 0:\n"
            "    os.close(read)\n"
            "    os.write(write, str(os.getpid()).encode())\n"
            "    time.sleep(30)\n"
            "    sys.exit(0)\n"
            "os.close(write)\n"
            "sys.stdout.write(os.read(read, 32).decode())\n"
            "sys.stdout.flush()\n"
            "time.sleep(30)\n"
        )
        completed = execution.run(
            script(source), request="", timeout_seconds=0.5, still_ours=lambda: True
        )
        child = int(completed.stdout.strip())

        self.assertEqual(completed.ending, "timeout")
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                os.kill(child, 0)
            except ProcessLookupError:
                break
            time.sleep(0.05)
        else:
            os.kill(child, signal.SIGKILL)
            self.fail("the grandchild outlived the process group it was started in")

    def test_a_lease_check_error_stops_the_process_before_it_escapes(self) -> None:
        def unavailable() -> bool:
            raise RuntimeError("database unavailable")

        started = time.monotonic()
        with self.assertRaisesRegex(RuntimeError, "database unavailable"):
            execution.run(
                script("import time; time.sleep(30)"),
                request="",
                timeout_seconds=30,
                still_ours=unavailable,
            )

        self.assertLess(time.monotonic() - started, 10)


class TheEnvironmentIsBuiltByName(unittest.TestCase):
    def test_a_variable_the_worker_holds_is_not_inherited(self) -> None:
        os.environ["HAPROXY_UI_TEST_LEAK"] = "visible"
        self.addCleanup(os.environ.pop, "HAPROXY_UI_TEST_LEAK", None)

        completed = execution.run(
            script("import os, sys; sys.stdout.write(os.environ.get('HAPROXY_UI_TEST_LEAK', '-'))"),
            request="",
            timeout_seconds=30,
            still_ours=lambda: True,
        )

        self.assertEqual(completed.stdout, "-")


if __name__ == "__main__":
    unittest.main()


class WhenTheGroupIsBeyondOurPrivilege(unittest.TestCase):
    """The helper runs as root; the worker does not, and holds no CAP_KILL.

    Measured on 2026-08-31: `killpg(group, 0)` against a group whose remaining
    members are root's raises `PermissionError`, not `ProcessLookupError`. The
    worker read that as an error it had no answer for and died with exit 1,
    which systemd then restarted into a second attempt on the same job.

    These use mocks rather than a real root process, because a test that needs
    root to run is a test that does not run.
    """

    def test_permission_denied_means_the_group_is_still_there(self) -> None:
        def denied(_group: int, _signal: int) -> None:
            raise PermissionError(1, "Operation not permitted")

        with unittest.mock.patch.object(execution.os, "killpg", denied):
            self.assertTrue(execution._group_exists(4242))

    def test_a_group_that_cannot_be_signalled_is_reported_not_raised(self) -> None:
        def denied(_group: int, _signal: int) -> None:
            raise PermissionError(1, "Operation not permitted")

        finished = subprocess.Popen(script("pass"))  # noqa: S603 - a fixed argv, no shell
        finished.wait()

        with (
            unittest.mock.patch.object(execution.os, "killpg", denied),
            self.assertLogs(execution.logger, level="ERROR") as logged,
        ):
            execution._stop(finished, finished.pid)

        self.assertIn("beyond this worker's privilege", "\n".join(logged.output))
