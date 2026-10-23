"""The root tools' `--json` answers a refusal too (Fas 23 review, second pass, F1).

Not as root, or without the installation's database file: the one document
of the command's contract on stdout, not an empty string.
"""

from __future__ import annotations

import contextlib
import io
import json
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from haprion import exit_codes

from haprion_ui import admin, profile_apply, settings_tool


def run(main: Any, argv: list[str]) -> tuple[int, str]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        code = main(argv)
    return code, out.getvalue()


class TheRootToolsAnswer(unittest.TestCase):
    def test_not_as_root_is_the_contract_s_refusal(self) -> None:
        with mock.patch("os.geteuid", return_value=1000):
            for main, argv, operation in (
                (admin.main, ["apply", "accounts.yaml", "--json"], "user_apply"),
                (settings_tool.main, ["apply", "settings.yaml", "--json"], "settings_apply"),
                (profile_apply.main, ["apply", "profiles.yaml", "--json"], "profiles_apply"),
                (profile_apply.main, ["remove", "dns", "cf-main", "--json"], "profiles_apply"),
            ):
                with self.subTest(operation=operation, argv=argv):
                    code, out = run(main, argv)
                    self.assertEqual(code, exit_codes.NOT_ROOT)
                    answer = json.loads(out)
                    self.assertEqual((answer["operation"], answer["ok"]), (operation, False))
                    self.assertEqual(answer["error"]["code"], "not_root")
                    self.assertIn("sudo", answer["error"]["message"])

    def test_without_the_installation_s_database_file(self) -> None:
        with (
            mock.patch("os.geteuid", return_value=0),
            mock.patch.object(
                admin,
                "load_environment",
                side_effect=admin.AdminError(
                    "cannot read", code="dependency_unavailable", exit_code=exit_codes.CONFIG
                ),
            ),
        ):
            code, out = run(admin.main, ["apply", "accounts.yaml", "--json"])

        self.assertEqual(code, exit_codes.CONFIG)
        answer = json.loads(out)
        self.assertEqual(answer["error"]["code"], "dependency_unavailable")
        self.assertIn("cannot read", answer["error"]["message"])

    def test_the_installation_s_database_file_is_the_installation_s_fault(self) -> None:
        """Review 2026-10-22, 4-9: every failure was `refused`, and this one exited 64."""

        with (
            mock.patch.object(admin, "ADMIN_CONFIG_DIRECTORY", Path("/nonexistent")),
            self.assertRaises(admin.AdminError) as raised,
        ):
            admin.load_environment()

        self.assertEqual(
            (raised.exception.code, raised.exception.exit_code),
            ("dependency_unavailable", exit_codes.CONFIG),
        )

    def test_a_command_without_a_contract_prints_no_document(self) -> None:
        with mock.patch("os.geteuid", return_value=1000):
            code, out = run(settings_tool.main, ["show", "--json"])

        self.assertEqual((code, out), (77, ""))
