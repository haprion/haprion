"""What every command's calling half does the same way.

Both cases here are regressions that had already shipped: four commands had
their own copy of this, and the copies swallowed cluster-config's diagnosis and
exited 1 where the shell commands exited 64.
"""

from __future__ import annotations

import io
import os
import stat
import tempfile
import unittest
from collections.abc import Iterator
from contextlib import contextmanager, redirect_stdout
from pathlib import Path
from unittest import mock

from haproxy_mgmt.cli import caller

#
# Stands in for cluster-config: answers on stdout, diagnoses on stderr, and
# exits 64 for a cluster it does not know - measured from the real one.
#
STUB = """#!/bin/sh
if [ "$2" = "alpha" ]; then
    echo /configs/haproxy/alpha
    exit 0
fi
echo "ERROR: unknown cluster '$2'. Valid clusters: alpha, beta" >&2
exit 64
"""


@contextmanager
def silenced_stderr() -> Iterator[None]:
    """Hide the real file descriptor 2, not `sys.stderr`.

    The child writes to the inherited descriptor, which is the whole point of
    the case below - so nothing at the Python level can catch it, and letting it
    through would print an error into a passing test run.
    """

    saved = os.dup(2)
    with open(os.devnull, "wb") as sink:
        os.dup2(sink.fileno(), 2)
        try:
            yield
        finally:
            os.dup2(saved, 2)
            os.close(saved)


class ConfigPathTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        stub = Path(self.directory.name) / "cluster-config"
        stub.write_text(STUB)
        stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
        patched = mock.patch.object(caller, "CLUSTER_CONFIG", str(stub))
        patched.start()
        self.addCleanup(patched.stop)

    def test_a_known_cluster_answers_with_its_repository(self) -> None:
        self.assertEqual(caller.config_path("alpha"), Path("/configs/haproxy/alpha"))

    def test_an_unknown_cluster_passes_the_exit_code_through_and_says_nothing(self) -> None:
        #
        # Silence here is the point. cluster-config has already named the valid
        # clusters on the inherited stderr; a second sentence would replace that
        # with less, which is exactly what the captured copies did.
        #
        shown = io.StringIO()
        with self.assertRaises(SystemExit) as raised, redirect_stdout(shown), silenced_stderr():
            caller.config_path("gamma")

        self.assertEqual(raised.exception.code, 64)
        self.assertEqual(shown.getvalue(), "")

    def test_a_missing_helper_is_not_mistaken_for_an_unknown_cluster(self) -> None:
        absent = str(Path(self.directory.name) / "gone")
        with (
            mock.patch.object(caller, "CLUSTER_CONFIG", absent),
            self.assertRaises(FileNotFoundError),
        ):
            caller.config_path("alpha")


class UsageTests(unittest.TestCase):
    def test_usage_goes_to_stdout_and_exits_sixty_four(self) -> None:
        shown = io.StringIO()
        with self.assertRaises(SystemExit) as raised, redirect_stdout(shown):
            caller.usage("Usage:\n  haproxy-list -c <cluster>\n")

        self.assertEqual(raised.exception.code, caller.USAGE_EXIT)
        self.assertEqual(shown.getvalue(), "Usage:\n  haproxy-list -c <cluster>\n")

    def test_a_usage_string_without_a_final_newline_gets_one(self) -> None:
        shown = io.StringIO()
        with self.assertRaises(SystemExit), redirect_stdout(shown):
            caller.usage("Usage:\n  haproxy-history-reset -c <cluster>")

        self.assertTrue(shown.getvalue().endswith("<cluster>\n"))


if __name__ == "__main__":
    unittest.main()
