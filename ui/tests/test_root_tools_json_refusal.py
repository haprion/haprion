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
from types import SimpleNamespace
from typing import Any
from unittest import mock

import psycopg
from haprion import exit_codes

from haprion_ui import (
    admin,
    config,
    job_wait,
    profile_apply,
    settings_apply,
    settings_tool,
    tool_answer,
)
from tests.contract_schema import assert_contract


def run(main: Any, argv: list[str]) -> tuple[int, str]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        code = main(argv)
    return code, out.getvalue()


class TheRootToolsAnswer(unittest.TestCase):
    def test_not_as_root_is_the_contract_s_refusal(self) -> None:
        with mock.patch("os.geteuid", return_value=1000):
            for main, argv, operation, schema in (
                (admin.main, ["apply", "accounts.yaml", "--json"], "user_apply", "user-apply"),
                (
                    settings_tool.main,
                    ["apply", "settings.yaml", "--json"],
                    "settings_apply",
                    "settings-apply",
                ),
                (
                    profile_apply.main,
                    ["apply", "profiles.yaml", "--json"],
                    "profiles_apply",
                    "profiles-apply",
                ),
                (
                    profile_apply.main,
                    ["remove", "dns", "cf-main", "--json"],
                    "profiles_apply",
                    "profiles-apply",
                ),
            ):
                with self.subTest(operation=operation, argv=argv):
                    code, out = run(main, argv)
                    self.assertEqual(code, exit_codes.NOT_ROOT)
                    answer = assert_contract(f"haprion-{schema}", out)
                    self.assertEqual((answer["operation"], answer["ok"]), (operation, False))
                    self.assertEqual(answer["error"]["code"], "not_root")
                    self.assertIn("sudo", answer["error"]["message"])

    def test_a_file_that_is_not_there_is_not_found_by_every_apply(self) -> None:
        """Review 26-10-30, E4: the engine's applies say 66 `not_found`; so do these."""

        missing = "/nonexistent/file.yaml"
        with (
            mock.patch("os.geteuid", return_value=0),
            mock.patch.object(
                admin, "load_environment", return_value=admin.Environment("test", "test")
            ),
            mock.patch.object(config, "load", return_value=SimpleNamespace()),
        ):
            for main, argv in (
                (admin.main, ["apply", missing, "--json"]),
                (settings_tool.main, ["apply", missing, "--json"]),
                (profile_apply.main, ["apply", missing, "--json"]),
            ):
                with self.subTest(argv=argv[0], tool=main.__module__):
                    code, out = run(main, argv)
                    self.assertEqual(code, exit_codes.NOT_FOUND)
                    self.assertEqual(json.loads(out)["error"]["code"], "not_found")

    def test_a_mistyped_call_exits_usage_like_the_engine_s(self) -> None:
        """Review 26-10-30, E8: argparse's own 2 is in no table."""

        from haprion_ui import export_tool

        for main in (admin.main, settings_tool.main, profile_apply.main, export_tool.main):
            with (
                self.subTest(tool=main.__module__),
                mock.patch("sys.stderr", new_callable=io.StringIO),
                self.assertRaises(SystemExit) as stopped,
            ):
                main(["--no-such-flag"])
            self.assertEqual(stopped.exception.code, exit_codes.USAGE)

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


class ADatabaseErrorIsToldApart(unittest.TestCase):
    """Review 26-10-24, 07-07: every database error was `bad_input`, even after work was done."""

    def test_the_database_s_own_rules_are_a_refusal_and_the_rest_the_installation_s(self) -> None:
        for error, expected in (
            (psycopg.errors.RaiseException("the last active admin"), exit_codes.REFUSED),
            (psycopg.errors.UniqueViolation("already there"), exit_codes.REFUSED),
            (psycopg.errors.UndefinedColumn("no column"), exit_codes.UNAVAILABLE),
            (psycopg.errors.InsufficientPrivilege("denied"), exit_codes.UNAVAILABLE),
            (psycopg.OperationalError("server closed"), exit_codes.UNAVAILABLE),
        ):
            with self.subTest(error=type(error).__name__):
                code, exit_code = tool_answer.database_failure(error)
                self.assertEqual(exit_code, expected)
                self.assertEqual(
                    code,
                    "bad_input" if expected == exit_codes.REFUSED else "dependency_unavailable",
                )

    def test_profiles_lost_after_the_first_was_applied_is_partial(self) -> None:
        changes = tuple(
            profile_apply.Change(profile_apply.DNS, name, "create", 1) for name in ("one", "two")
        )
        jobs = iter((SimpleNamespace(id=41), psycopg.OperationalError("server closed")))

        def queue(*_args: Any, **_kwargs: Any) -> Any:
            job = next(jobs)
            if isinstance(job, Exception):
                raise job
            return job

        with (
            mock.patch("os.geteuid", return_value=0),
            mock.patch.object(profile_apply, "read_file", return_value={}),
            mock.patch.object(
                config,
                "load",
                return_value=SimpleNamespace(dns_profiles_public_key="k"),
            ),
            mock.patch.object(profile_apply, "read_public_key"),
            mock.patch.object(profile_apply, "load_environment"),
            mock.patch.object(profile_apply, "connect", return_value=mock.MagicMock()),
            mock.patch.object(profile_apply, "KINDS", ()),
            mock.patch.object(profile_apply, "plan", return_value=profile_apply.Plan(changes, ())),
            mock.patch.object(profile_apply, "confirmed_servers", return_value=[]),
            mock.patch.object(profile_apply, "actor_name", return_value="admin"),
            mock.patch.object(profile_apply, "_queue", side_effect=queue),
            mock.patch.object(job_wait, "finished", return_value=("done", None)),
        ):
            code, out = run(profile_apply.main, ["apply", "profiles.yaml", "--json"])

        self.assertEqual(code, exit_codes.PARTIAL)
        answer = json.loads(out)
        self.assertEqual(answer["outcome"], "partial")
        self.assertEqual([entry["profile"] for entry in answer["result"]["jobs"]], ["one"])
        self.assertEqual(answer["warnings"][0]["code"], "dependency_unavailable")

    def test_settings_lost_after_they_were_saved_is_partial(self) -> None:
        wanted = SimpleNamespace(status_access=None, features={"node_backups": True}, oidc=None)

        def apply_features(*_args: Any, queued: list[Any], **_kwargs: Any) -> dict[str, bool]:
            queued.append(SimpleNamespace(id=42, cluster="alpha"))
            return {"node_backups": True}

        with (
            mock.patch("os.geteuid", return_value=0),
            mock.patch.object(settings_apply, "read_file", return_value=wanted),
            mock.patch.object(config, "load"),
            mock.patch.object(settings_tool, "load_environment"),
            mock.patch.object(settings_tool, "connect", return_value=mock.MagicMock()),
            mock.patch.object(settings_tool, "actor_name", return_value="admin"),
            mock.patch.object(settings_tool, "_readings"),
            mock.patch.object(settings_apply, "apply_features", side_effect=apply_features),
            mock.patch.object(
                job_wait,
                "finished",
                side_effect=psycopg.OperationalError("server closed"),
            ),
        ):
            code, out = run(settings_tool.main, ["apply", "settings.yaml", "--json"])

        self.assertEqual(code, exit_codes.PARTIAL)
        answer = json.loads(out)
        self.assertEqual(answer["outcome"], "partial")
        self.assertEqual(answer["result"]["features"], {"node_backups": True})
        self.assertEqual(answer["warnings"][0]["code"], "dependency_unavailable")
