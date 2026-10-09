"""What every command's calling half does the same way.

Both cases here are regressions that had already shipped: four commands had
their own copy of this, and the copies swallowed cluster-config's diagnosis and
exited 1 where the shell commands exited 64.
"""

from __future__ import annotations

import io
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from haproxy_mgmt.cli import caller


def cluster_config(argv: list[str]) -> int:
    """Stands in for haprion-cluster-config: stdout, stderr, 64 for an unknown cluster."""

    if argv[1] == "alpha":
        print("/configs/haproxy/alpha")
        return 0
    print("ERROR: unknown cluster 'gamma'. Valid clusters: alpha, beta", file=sys.stderr)
    return 64


class ConfigPathTests(unittest.TestCase):
    def setUp(self) -> None:
        patched = mock.patch("haproxy_mgmt.cli.cluster_config.main", cluster_config)
        patched.start()
        self.addCleanup(patched.stop)

    def test_a_known_cluster_answers_with_its_repository(self) -> None:
        self.assertEqual(caller.config_path("alpha"), Path("/configs/haproxy/alpha"))

    def test_an_unknown_cluster_passes_the_exit_code_through_and_says_nothing(self) -> None:
        #
        # Silence here is the point. cluster-config has already named the valid
        # clusters on stderr; a second sentence would replace that with less,
        # which is exactly what the captured copies did.
        #
        shown, diagnosed = io.StringIO(), io.StringIO()
        with (
            self.assertRaises(SystemExit) as raised,
            redirect_stdout(shown),
            redirect_stderr(diagnosed),
        ):
            caller.config_path("gamma")

        self.assertEqual(raised.exception.code, 64)
        self.assertEqual(shown.getvalue(), "")
        self.assertIn("Valid clusters: alpha, beta", diagnosed.getvalue())

    def test_it_asks_the_command_itself_rather_than_an_installed_wrapper(self) -> None:
        """B266: the hand-installed cluster-config wrapper is gone."""

        self.assertFalse(hasattr(caller, "CLUSTER_CONFIG"))


class UsageTests(unittest.TestCase):
    def test_usage_goes_to_stdout_and_exits_sixty_four(self) -> None:
        shown = io.StringIO()
        with self.assertRaises(SystemExit) as raised, redirect_stdout(shown):
            caller.usage("Usage:\n  haprion-list -c <cluster>\n")

        self.assertEqual(raised.exception.code, caller.USAGE_EXIT)
        self.assertEqual(shown.getvalue(), "Usage:\n  haprion-list -c <cluster>\n")

    def test_a_usage_string_without_a_final_newline_gets_one(self) -> None:
        shown = io.StringIO()
        with self.assertRaises(SystemExit), redirect_stdout(shown):
            caller.usage("Usage:\n  haprion-history-reset -c <cluster>")

        self.assertTrue(shown.getvalue().endswith("<cluster>\n"))


if __name__ == "__main__":
    unittest.main()
