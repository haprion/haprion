"""`haprion-user`: one exit code and one sentence for each kind of refusal (review 26-10-30, E3).

A name that is taken or the last admin is refused (65) whichever verb meets it,
an account that is not there is not found (66), and 64 stays for a request that
is itself wrong. The database's own guard is faked here; the real trigger is
held in test_database_integration.
"""

from __future__ import annotations

import contextlib
import io
import unittest
from collections.abc import Callable
from typing import Any
from unittest import mock

from haprion import exit_codes

from haprion_ui import admin, db

LAST = "the last active admin cannot be demoted, disabled or deleted"


class Cursor:
    def __init__(self, found: bool) -> None:
        self.found = found
        self.sql = ""

    def __enter__(self) -> Cursor:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def execute(self, sql: str, *_: object) -> None:
        self.sql = sql

    def fetchone(self) -> tuple[Any, ...] | None:
        if not self.found:
            return None
        if "select role, source" in self.sql:
            return ("admin", "local")
        return ("local",) if "select source" in self.sql else (1,)


class Connection:
    def __init__(self, found: bool) -> None:
        self.found = found

    def __enter__(self) -> Connection:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def cursor(self, **_: object) -> Cursor:
        return Cursor(self.found)

    def commit(self) -> None:
        return None


class TheExits(unittest.TestCase):
    def run_tool(self, argv: list[str], *, found: bool = True, **refusing: Any) -> tuple[int, str]:
        err = io.StringIO()
        with contextlib.ExitStack() as stack:
            for patch in (
                mock.patch("os.geteuid", return_value=0),
                mock.patch.object(admin, "load_environment"),
                mock.patch.object(admin, "connect", return_value=Connection(found)),
                mock.patch.object(admin, "_audit"),
                mock.patch.object(admin, "read_new_password", return_value="long enough pw"),
                contextlib.redirect_stderr(err),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                stack.enter_context(patch)
            for name, effect in refusing.items():
                stack.enter_context(mock.patch.object(db, name, side_effect=effect))
            code = admin.main(argv)
        return code, err.getvalue().strip()

    def test_the_last_admin_is_refused_the_same_way_by_every_verb(self) -> None:
        guard = db.LastAdmin()
        answers = {
            "role": self.run_tool(["role", "admin", "reader"], set_role=guard),
            "disable": self.run_tool(["disable", "admin"], set_disabled=guard),
            "delete": self.run_tool(["delete", "admin", "--yes"], delete_account=guard),
            "break-glass": self.run_tool(["break-glass", "admin", "--off"], set_break_glass=guard),
        }

        for verb, (code, message) in answers.items():
            with self.subTest(verb):
                self.assertEqual(code, exit_codes.REFUSED)
                self.assertIn(LAST, message)

    def test_an_account_that_is_not_there_is_not_found_by_every_verb(self) -> None:
        for argv in (
            ["disable", "ghost"],
            ["enable", "ghost"],
            ["delete", "ghost", "--yes"],
            ["role", "ghost", "reader"],
            ["revoke", "ghost"],
            ["reset", "ghost"],
            ["break-glass", "ghost"],
        ):
            with self.subTest(argv[0]):
                code, message = self.run_tool(argv, found=False)
                self.assertEqual(code, exit_codes.NOT_FOUND)
                self.assertIn("no such account: ghost", message)

    def test_a_name_that_is_taken_is_refused(self) -> None:
        code, message = self.run_tool(
            ["add", "admin", "--role", "admin"], create_account=lambda *_a, **_k: False
        )

        self.assertEqual(code, exit_codes.REFUSED)
        self.assertIn("an account named admin already exists", message)

    def test_a_request_that_is_itself_wrong_stays_a_usage_error(self) -> None:
        code, _ = self.run_tool(["add", "ada admin", "--role", "admin"])

        self.assertEqual(code, exit_codes.USAGE)

    def test_the_one_off_verbs_write_through_the_db_functions(self) -> None:
        calls: list[str] = []

        def note(name: str) -> Callable[..., int]:
            def call(*_a: object, **_k: object) -> int:
                calls.append(name)
                return 0

            return call

        self.run_tool(["disable", "admin"], set_disabled=note("disable"))
        self.run_tool(["reset", "admin"], reset_password=note("reset"))
        self.run_tool(["revoke", "admin"], revoke_sessions_for_user=note("revoke"))
        self.run_tool(["delete", "admin", "--yes"], delete_account=note("delete"))

        self.assertEqual(calls, ["disable", "reset", "revoke", "delete"])


if __name__ == "__main__":
    unittest.main()
