"""``haprion-user apply`` without a database: the file and the plan (Fas 23, B293).

The writes are held against the real schema in `test_database_integration`
(`TheAccountsFromAFile`); this holds what is decided before anything is
written, and the answer's shape against the fixture the contract suite
validates against `schemas/v1/haprion-user-apply`.
"""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from haprion_ui import account_apply, auth, db, tool_answer
from haprion_ui.account_apply import ApplyError, Stored, Wanted
from tests.contract_schema import assert_contract

FIXTURE = Path(__file__).resolve().parents[2] / "fixtures/haprion-user-apply/valid/done.json"


def stored(name: str, role: str = "admin", **fields: object) -> Stored:
    values: dict[str, object] = {
        "id": 1,
        "username": name,
        "role": role,
        "disabled": False,
        "source": "local",
        "break_glass": False,
        "password_hash": auth.hash_password("stored password"),
    }
    values.update(fields)
    return Stored(**values)  # type: ignore[arg-type]


class TheFile(unittest.TestCase):
    def write(self, text: str, mode: int = 0o600) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "accounts.yaml"
        path.write_text(text)
        path.chmod(mode)
        return path

    def test_a_good_file_is_read(self) -> None:
        wanted = account_apply.read_file(
            self.write("accounts:\n  - {username: admin, role: admin, password: long enough pw}\n")
        )

        self.assertEqual(
            [(w.username, w.role, w.password) for w in wanted],
            [("admin", "admin", "long enough pw")],
        )

    def test_what_the_file_refuses(self) -> None:
        for text, said in (
            ("users: []\n", "one key, accounts"),
            ("accounts:\n  - {username: a, role: owner}\n", "role must be"),
            ("accounts:\n  - {username: a, role: admin, colour: red}\n", "unknown field"),
            (
                "accounts:\n  - {username: a, role: admin}\n  - {username: A, role: reader}\n",
                "twice",
            ),
            ("accounts:\n  - {username: a, role: admin, password: short}\n", "at least"),
            ("accounts:\n  - {username: a, role: admin, disabled: 'no'}\n", "true or false"),
        ):
            with self.subTest(said), self.assertRaises(ApplyError) as raised:
                account_apply.read_file(self.write(text))
            self.assertIn(said, str(raised.exception))

    def test_passwords_in_a_file_others_may_read_are_refused(self) -> None:
        text = "accounts:\n  - {username: a, role: admin, password: long enough pw}\n"

        with self.assertRaises(ApplyError) as raised:
            account_apply.read_file(self.write(text, mode=0o640))

        self.assertIn("0600", str(raised.exception))
        account_apply.read_file(self.write(text.replace(", password: long enough pw", ""), 0o644))


class ThePlan(unittest.TestCase):
    def test_a_matching_password_is_no_change(self) -> None:
        plan = account_apply.plan(
            [Wanted("admin", "admin", password="stored password")], [stored("admin")], prune=False
        )

        self.assertTrue(plan.empty)
        self.assertEqual(plan.unchanged, ("admin",))

    def test_only_what_differs_is_named(self) -> None:
        plan = account_apply.plan(
            [Wanted("admin", "reader", break_glass=False, disabled=True, password="new password!")],
            [stored("admin")],
            prune=False,
        )

        ((_, _, fields),) = plan.updated
        self.assertEqual(fields, ("role", "password", "disabled"))

    def test_a_new_account_needs_a_password(self) -> None:
        with self.assertRaises(ApplyError):
            account_apply.plan([Wanted("new", "reader")], [], prune=False)

    def test_a_provider_account_takes_only_disabled(self) -> None:
        provider = stored("sso", role="reader", source="oidc", password_hash=None)

        disabled = account_apply.plan(
            [Wanted("sso", "reader", disabled=True)], [provider], prune=False
        )
        self.assertEqual(disabled.updated[0][2], ("disabled",))
        moved = account_apply.plan([Wanted("sso", "admin", disabled=True)], [provider], prune=False)
        self.assertEqual(moved.updated[0][2], ("disabled",))
        self.assertTrue(account_apply.plan([Wanted("sso", "admin")], [provider], prune=False).empty)
        for refused in (
            Wanted("sso", "reader", password="a password"),
            Wanted("sso", "reader", break_glass=True),
        ):
            with self.assertRaises(ApplyError):
                account_apply.plan([refused], [provider], prune=False)

    def test_prune_takes_local_accounts_only(self) -> None:
        plan = account_apply.plan(
            [Wanted("admin", "admin")],
            [stored("admin"), stored("old"), stored("sso", source="oidc", password_hash=None)],
            prune=True,
        )

        self.assertEqual([row.username for row in plan.deleted], ["old"])


class TheSessionsItEnded(unittest.TestCase):
    def test_a_write_returns_how_many_sessions_its_changes_ended(self) -> None:
        """Review 26-10-30, R4: the count was in the audit rows only."""

        the_plan = account_apply.plan(
            [
                Wanted("admin", "admin", break_glass=False),
                Wanted("operator", "reader", disabled=True),
            ],
            [stored("admin", break_glass=True), stored("operator", id=2)],
            prune=False,
        )
        with (
            mock.patch.object(db, "set_break_glass", return_value=2),
            mock.patch.object(db, "set_disabled", return_value=1),
            mock.patch.object(db, "set_role"),
            mock.patch.object(db, "record_audit_event"),
        ):
            ended = account_apply.write(mock.Mock(), the_plan, actor="admin")

        self.assertEqual(ended, 3)
        self.assertEqual(
            account_apply.summary(the_plan, check=False, sessions_ended=ended)["sessions_ended"], 3
        )


class TheAnswer(unittest.TestCase):
    def test_it_has_the_shape_the_contract_holds(self) -> None:
        plan = account_apply.plan(
            [Wanted("admin", "reader")], [stored("admin"), stored("operator")], prune=False
        )
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = tool_answer.done(
                account_apply.OPERATION, account_apply.summary(plan, check=False)
            )
        self.assertEqual(code, 0)
        answer = assert_contract("haprion-user-apply", out.getvalue())
        fixture = json.loads(FIXTURE.read_text())

        self.assertEqual(set(answer["result"]), set(fixture["result"]))
        self.assertEqual(answer["operation"], fixture["operation"])
        self.assertEqual(set(answer["result"]["updated"][0]), {"username", "fields"})


if __name__ == "__main__":
    unittest.main()
