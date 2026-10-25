"""Settings -> Users: accounts written from the web (Fas 13, §16.4 U4, B189).

Held here: admin only, behind the tab's gate; the session is the proof and no
second password is asked (2026-09-27); Save writes the role and a new
password together; the admin's own account is refused; the last active admin
is the database's to refuse; each change is the CLI's verb with the CLI's
audit name and `via: web`.
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any
from unittest import mock

from fastapi.testclient import TestClient

from haprion_ui import auth, db
from haprion_ui.db import AccountRow
from tests.test_login import LoginTestCase, configuration

NEW = "another sufficiently long password"


def row(username: str, *, role: str = "reader", **fields: Any) -> AccountRow:
    values: dict[str, Any] = {
        "id": {"operator": 1, "alice": 2, "bob": 3}.get(username, 9),
        "username": username,
        "role": role,
        "disabled": False,
        "sessions": 1,
        "last_sign_in": datetime(2026, 9, 26, 8, 0, tzinfo=UTC),
        "locked": False,
    }
    values.update(fields)
    return AccountRow(**values)


class SettingsUsers(LoginTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.rows = {
            "alice": row("alice", role="admin"),
            "bob": row("bob", locked=True),
            "operator": row("operator", role="admin"),
        }
        self.calls: list[tuple[str, dict[str | int, Any]]] = []
        self.audit_details: list[tuple[str, dict[str, Any]]] = []

        def record(name: str, result: Any = None) -> Callable[..., Any]:
            def call(_c: object, *args: Any, **kwargs: Any) -> Any:
                fields: dict[str | int, Any] = {}
                fields.update(kwargs)
                fields.update(enumerate(args))
                self.calls.append((name, fields))
                return result

            return call

        def audit(_c: object, *, action: str, detail: Any = None, **_: Any) -> None:
            self.audit.append(action)
            self.audit_details.append((action, dict(detail or {})))

        patches = [
            mock.patch(
                "haprion_ui.db.account_rows",
                side_effect=lambda _c, **_: [self.rows[name] for name in sorted(self.rows)],
            ),
            mock.patch(
                "haprion_ui.db.account_row",
                side_effect=lambda _c, name, **_: self.rows.get(name.lower()),
            ),
            mock.patch("haprion_ui.db.create_account", side_effect=record("create", True)),
            mock.patch("haprion_ui.db.set_role", side_effect=record("role")),
            mock.patch("haprion_ui.db.set_disabled", side_effect=record("disabled", 2)),
            mock.patch("haprion_ui.db.reset_password", side_effect=record("password", 1)),
            mock.patch("haprion_ui.db.revoke_sessions_for_user", side_effect=record("revoke", 3)),
            mock.patch("haprion_ui.db.unlock_account", side_effect=record("unlock")),
            mock.patch("haprion_ui.db.set_break_glass", side_effect=record("break_glass")),
            mock.patch("haprion_ui.db.delete_account", side_effect=record("delete", True)),
            mock.patch("haprion_ui.db.record_audit_event", side_effect=audit),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)

    def admin(self) -> TestClient:
        client = self.client(replace(configuration(), management_writes=True))
        self.assertEqual(self.sign_in(client).status_code, 303)
        return client

    def post(self, client: TestClient, path: str, **fields: str) -> Any:
        token = client.cookies[auth.SESSION_COOKIE]
        data = {auth.CSRF_FIELD: auth.csrf_token(token), **fields}
        return client.post(path, data=data, follow_redirects=False)

    # - the list ---------------------------------------------------------

    def test_the_card_lists_every_account_alphabetically_with_whole_rows_linked(self) -> None:
        whole = self.admin().get("/settings").text
        page = whole[whole.index("users-table") :]

        self.assertLess(page.index(">alice<"), page.index(">bob<"))
        self.assertLess(page.index(">bob<"), page.index(">operator<"))
        self.assertIn('<tr data-href="/settings/users/bob">', page)
        self.assertIn("Locked", page)
        self.assertIn('href="/settings/new-user"', whole)

    def test_every_column_sorts_and_a_second_click_turns_it_round(self) -> None:
        early, late = datetime(2026, 9, 1, tzinfo=UTC), datetime(2026, 9, 20, tzinfo=UTC)
        self.rows = {
            "alice": row("alice", role="admin", sessions=0, last_sign_in=early),
            "bob": row("bob", locked=True, sessions=3, last_sign_in=None),
            "carol": row("carol", disabled=True, sessions=0, last_sign_in=late),
            "operator": row("operator", role="admin", sessions=1, last_sign_in=late),
        }
        client = self.admin()

        def order(sort: str) -> list[str]:
            page = client.get(f"/settings?sort={sort}").text
            page = page[page.index("<tbody>") :]
            return sorted(self.rows, key=lambda name: page.index(f">{name}<"))

        for sort, names in (
            ("nonsense", ["alice", "bob", "carol", "operator"]),
            ("name", ["alice", "bob", "carol", "operator"]),
            ("-name", ["operator", "carol", "bob", "alice"]),
            ("role", ["alice", "operator", "bob", "carol"]),
            ("state", ["carol", "bob", "alice", "operator"]),
            ("-state", ["alice", "operator", "bob", "carol"]),
            ("sessions", ["bob", "operator", "alice", "carol"]),
            ("signin", ["carol", "operator", "alice", "bob"]),
            ("-signin", ["alice", "carol", "operator", "bob"]),
            ("nonsense", ["alice", "carol", "operator", "bob"]),
        ):
            with self.subTest(sort=sort):
                self.assertEqual(order(sort), names)

        page = client.get("/settings?sort=signin").text
        self.assertIn('href="/settings?sort=-signin#users"', page)
        self.assertIn('href="/settings?sort=sessions#users"', page)
        self.assertIn('aria-sort="descending"', page)

    def test_the_chosen_order_is_kept_when_the_page_is_opened_again(self) -> None:
        client = self.admin()

        client.get("/settings?sort=-name")
        page = client.get("/settings").text
        page = page[page.index("<tbody>") :]
        self.assertLess(page.index(">operator<"), page.index(">alice<"))

    def test_a_reader_and_an_installation_without_writes_get_no_users(self) -> None:
        self.account = replace(self.account, role="reader")
        client = self.client(replace(configuration(), management_writes=True))
        self.sign_in(client)
        self.assertEqual(client.get("/settings/users/bob").status_code, 403)

        self.account = replace(self.account, role="admin")
        client = self.client()
        self.sign_in(client)
        self.assertEqual(client.get("/settings/users/bob").status_code, 404)

    # - changes ----------------------------------------------------------

    def test_each_action_is_the_cli_verb_with_its_audit_name(self) -> None:
        client = self.admin()
        for action, fields, done, call, audit in (
            ("save", {"role": "admin"}, "role", "role", "role_changed"),
            (
                "save",
                {"role": "reader", "new_password": NEW, "repeat_password": NEW},
                "password",
                "password",
                "password_reset",
            ),
            ("disable", {}, "disable", "disabled", "account_disabled"),
            ("revoke", {}, "revoke", "revoke", "sessions_revoked"),
            ("unlock", {}, "unlock", "unlock", "throttle_cleared"),
        ):
            with self.subTest(action=action, done=done):
                response = self.post(client, "/settings/users/bob", action=action, **fields)

                self.assertEqual(response.status_code, 303)
                self.assertEqual(response.headers["location"], f"/settings/users/bob?done={done}")
                self.assertEqual(self.calls[-1][0], call)
                name, detail = self.audit_details[-1]
                self.assertEqual(name, audit)
                self.assertEqual((detail["account"], detail["via"]), ("bob", "web"))
        self.assertIn("Unlocked.", client.get("/settings/users/bob?done=unlock").text)

    def test_enable_is_offered_for_a_disabled_account(self) -> None:
        self.rows["bob"] = row("bob", disabled=True)
        client = self.admin()

        self.assertIn('value="enable"', client.get("/settings/users/bob").text)
        self.assertEqual(self.post(client, "/settings/users/bob", action="enable").status_code, 303)
        self.assertEqual(self.calls[-1], ("disabled", {"user_id": 3, "disabled": False}))

    def test_save_writes_the_role_and_the_password_together(self) -> None:
        client = self.admin()

        response = self.post(
            client,
            "/settings/users/bob",
            action="save",
            role="admin",
            new_password=NEW,
            repeat_password=NEW,
        )

        self.assertEqual(response.headers["location"], "/settings/users/bob?done=saved_password")
        self.assertEqual([name for name, _ in self.calls], ["role", "password"])
        self.assertEqual(self.audit[-2:], ["role_changed", "password_reset"])
        page = client.get("/settings/users/bob").text
        self.assertIn('value="save"', page)
        self.assertIn(">Save</button>", page)
        self.assertIn('href="/settings">Back</a>', page)
        self.assertNotIn("Change role", page)

    def test_no_second_password_is_asked(self) -> None:
        client = self.admin()
        attempts = len(self.attempts)

        self.assertNotIn("your_password", client.get("/settings/users/bob").text)
        self.assertNotIn("your_password", client.get("/settings/new-user").text)
        self.assertEqual(self.post(client, "/settings/users/bob", action="revoke").status_code, 303)
        self.assertEqual(len(self.attempts), attempts)

    def test_the_admin_s_own_account_is_the_account_menu_s(self) -> None:
        client = self.admin()

        self.assertIn('href="/account/password"', client.get("/settings/users/operator").text)
        response = self.post(client, "/settings/users/operator", action="save", role="reader")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.calls, [])

    def test_the_last_active_admin_is_refused_with_a_sentence(self) -> None:
        client = self.admin()
        with mock.patch("haprion_ui.db.set_role", side_effect=db.LastAdmin()):
            response = self.post(
                client,
                "/settings/users/alice",
                action="save",
                role="reader",
                new_password=NEW,
                repeat_password=NEW,
            )

        self.assertEqual(response.status_code, 409)
        self.assertIn(
            "The last active admin cannot be demoted, disabled or deleted.", response.text
        )
        self.assertNotIn("role_changed", self.audit)
        self.assertNotIn("password_reset", self.audit)

    def test_mistakes_in_the_form_are_refused_before_anything_is_written(self) -> None:
        client = self.admin()
        for fields, sentence in (
            ({"action": "save", "role": "reader"}, "Nothing to save"),
            ({"action": "save", "role": "root"}, "Choose a role."),
            (
                {
                    "action": "save",
                    "role": "reader",
                    "new_password": "short",
                    "repeat_password": "short",
                },
                "at least",
            ),
            (
                {"action": "save", "role": "reader", "new_password": NEW, "repeat_password": "x"},
                "do not match",
            ),
            ({"action": "enable"}, "already enabled"),
        ):
            with self.subTest(fields=fields):
                response = self.post(client, "/settings/users/bob", **fields)
                self.assertEqual(response.status_code, 400)
                self.assertIn(sentence, response.text)
        self.assertEqual(self.calls, [])

    def test_an_unknown_action_or_account_is_refused(self) -> None:
        client = self.admin()

        self.assertEqual(self.post(client, "/settings/users/bob", action="role").status_code, 400)
        self.assertEqual(
            self.post(client, "/settings/users/nobody", action="revoke").status_code, 404
        )
        self.assertEqual(client.get("/settings/users/nobody").status_code, 404)

    def test_a_forged_form_is_refused(self) -> None:
        client = self.admin()

        response = self.post(client, "/settings/users/bob", action="revoke", csrf_token="forged")
        self.assertEqual(response.status_code, 403)

    # - adding -----------------------------------------------------------

    def test_a_password_an_admin_sets_is_hashed_holding_no_connection(self) -> None:
        """Review 26-10-24, 09-02: Argon2 ran inside a pool connection."""

        client = self.admin()
        held: list[int] = []
        real_connection, real_hash = self.pool.connection, auth.hash_password

        @contextmanager
        def counted() -> Any:
            held.append(1)
            try:
                with real_connection() as connection:
                    yield connection
            finally:
                held.pop()

        def hash_password(password: str) -> str:
            self.assertEqual(held, [], "the password was hashed inside a connection")
            return real_hash(password)

        with (
            mock.patch.object(self.pool, "connection", counted),
            mock.patch.object(auth, "hash_password", hash_password),
        ):
            for path, fields in (
                ("/settings/new-user", {"username": "carol", "role": "reader"}),
                ("/settings/users/bob", {"action": "save", "role": "reader"}),
            ):
                with self.subTest(path):
                    response = self.post(
                        client, path, new_password=NEW, repeat_password=NEW, **fields
                    )
                    self.assertEqual(response.status_code, 303)

    def test_an_account_is_added_with_the_cli_s_audit_name(self) -> None:
        client = self.admin()

        response = self.post(
            client,
            "/settings/new-user",
            username="carol",
            role="reader",
            new_password=NEW,
            repeat_password=NEW,
        )

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/settings#users")
        name, fields = self.calls[-1]
        self.assertEqual((name, fields["username"], fields["role"]), ("create", "carol", "reader"))
        self.assertTrue(auth.verify_password(fields["password_hash"], NEW))
        self.assertEqual(
            self.audit_details[-1],
            ("account_created", {"account": "carol", "role": "reader", "via": "web"}),
        )

    def test_a_name_a_version_could_not_record_is_refused_before_anything_is_written(
        self,
    ) -> None:
        # Review 2026-09-29 F1: the name is what a version records as who
        # published it, so it must be able to stand there.
        client = self.admin()
        for username in ("ada\u00a0admin", "ada\u200badmin", " ada"):
            with self.subTest(username=username):
                response = self.post(
                    client,
                    "/settings/new-user",
                    username=username,
                    role="admin",
                    new_password=NEW,
                    repeat_password=NEW,
                )
                self.assertEqual(response.status_code, 400)
                self.assertIn("invisible characters", response.text)
        self.assertNotIn("create", [name for name, _ in self.calls])
        self.assertNotIn("account_created", self.audit)

    def test_a_taken_name_is_refused_and_the_form_keeps_what_was_typed(self) -> None:
        client = self.admin()
        with mock.patch("haprion_ui.db.create_account", return_value=False):
            response = self.post(
                client,
                "/settings/new-user",
                username="alice",
                role="admin",
                new_password=NEW,
                repeat_password=NEW,
            )

        self.assertEqual(response.status_code, 409)
        self.assertIn("already exists", response.text)
        self.assertIn('value="alice"', response.text)
        self.assertNotIn(NEW, response.text)
        self.assertNotIn("account_created", self.audit)

    # - break-glass, deletion and the provider's accounts (0041, B195-B197) ----

    def test_save_marks_and_unmarks_break_glass(self) -> None:
        client = self.admin()

        marked = self.post(
            client, "/settings/users/bob", action="save", role="reader", break_glass="on"
        )
        self.assertEqual(marked.headers["location"], "/settings/users/bob?done=break_glass")
        self.assertEqual(self.calls[-1], ("break_glass", {"user_id": 3, "break_glass": True}))
        self.assertEqual(
            self.audit_details[-1],
            ("break_glass_changed", {"account": "bob", "via": "web", "break_glass": True}),
        )

        self.rows["bob"] = row("bob", break_glass=True)
        page = client.get("/settings/users/bob").text
        self.assertIn('name="break_glass" value="on" checked', page)
        self.assertIn('Reader<span class="users-you">break-glass</span>', page)
        unmarked = self.post(client, "/settings/users/bob", action="save", role="reader")
        self.assertEqual(unmarked.status_code, 303)
        self.assertEqual(self.calls[-1], ("break_glass", {"user_id": 3, "break_glass": False}))

    def test_the_list_says_which_accounts_are_break_glass_or_the_provider_s(self) -> None:
        self.rows["alice"] = row("alice", role="admin", break_glass=True)
        self.rows["bob"] = row("bob", source="oidc")
        page = self.admin().get("/settings").text

        self.assertIn('alice<span class="users-you">break-glass</span>', page)
        self.assertIn('bob<span class="users-you">SSO</span>', page)

    def test_delete_asks_first_then_removes_and_returns_to_the_list(self) -> None:
        client = self.admin()
        self.assertIn(
            'href="/settings/users/bob/delete">Delete…</a>', client.get("/settings/users/bob").text
        )

        question = client.get("/settings/users/bob/delete")
        self.assertEqual(question.status_code, 200)
        self.assertIn('name="action" value="delete"', question.text)
        self.assertIn("Jobs and the audit trail keep the name.", question.text)

        response = self.post(client, "/settings/users/bob", action="delete")
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/settings#users")
        self.assertEqual(self.calls[-1], ("delete", {"user_id": 3}))
        self.assertEqual(
            self.audit_details[-1],
            (
                "account_deleted",
                {"account": "bob", "via": "web", "role": "reader", "source": "local"},
            ),
        )

    def test_one_s_own_account_is_not_deleted_from_here(self) -> None:
        client = self.admin()
        self.assertEqual(
            client.get("/settings/users/operator/delete", follow_redirects=False).status_code, 303
        )
        response = self.post(client, "/settings/users/operator", action="delete")
        self.assertEqual(response.status_code, 400)
        self.assertNotIn("delete", [name for name, _ in self.calls])

    def test_the_database_s_refusals_to_delete_are_sentences(self) -> None:
        client = self.admin()
        for error, sentence in (
            (db.LastAdmin(), "The last active admin cannot be demoted, disabled or deleted."),
            (
                db.NoBreakGlass(),
                "Sign-in through the provider is on and needs an active break-glass admin.",
            ),
        ):
            with (
                self.subTest(error=type(error).__name__),
                mock.patch("haprion_ui.db.delete_account", side_effect=error),
            ):
                response = self.post(client, "/settings/users/alice", action="delete")
                self.assertEqual(response.status_code, 409)
                self.assertIn(sentence, response.text)
        self.assertNotIn("account_deleted", self.audit)

    def test_a_provider_account_has_no_role_or_password_form(self) -> None:
        self.rows["bob"] = row("bob", source="oidc")
        client = self.admin()
        page = client.get("/settings/users/bob").text

        self.assertIn('Reader<span class="users-you">SSO</span>', page)
        self.assertNotIn('name="new_password"', page)
        self.assertNotIn('name="break_glass"', page)
        self.assertIn(">End sessions</button>", page)
        self.assertIn("Delete…", page)
        response = self.post(
            client, "/settings/users/bob", action="save", role="admin", break_glass="on"
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("The provider sets this account", response.text)
        self.assertEqual(self.calls, [])
