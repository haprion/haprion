"""An account's own password, changed from the account menu (§16.4 U3)."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import replace
from typing import Any
from unittest import mock

from fastapi.testclient import TestClient

from haprion_ui import auth
from tests.test_login import PASSWORD, LoginTestCase

NEW = "another sufficiently long password"


class OwnPasswordTestCase(LoginTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.changed: list[dict[str, Any]] = []
        patch = mock.patch("haprion_ui.db.change_password", side_effect=self._change)
        patch.start()
        self.addCleanup(patch.stop)

    def _change(self, _c: object, *, user_id: int, password_hash: str, keep: bytes) -> int:
        self.account = replace(self.account, password_hash=password_hash)
        others = [digest for digest in self.sessions if digest != keep]
        for digest in others:
            del self.sessions[digest]
        self.changed.append({"user_id": user_id, "keep": keep})
        return len(others)

    def signed_in(self) -> TestClient:
        client = self.client()
        self.assertEqual(self.sign_in(client).status_code, 303)
        return client

    def submit(
        self,
        client: TestClient,
        *,
        current: str = PASSWORD,
        new: str = NEW,
        repeat: str | None = None,
        csrf: str | None = None,
    ) -> Any:
        token = client.cookies[auth.SESSION_COOKIE]
        return client.post(
            "/account/password",
            data={
                "current_password": current,
                "new_password": new,
                "repeat_password": new if repeat is None else repeat,
                auth.CSRF_FIELD: auth.csrf_token(token) if csrf is None else csrf,
            },
            follow_redirects=False,
        )


class ChangingOnesOwnPassword(OwnPasswordTestCase):
    def test_the_account_menu_leads_to_the_form(self) -> None:
        client = self.signed_in()

        self.assertIn('href="/account/password"', client.get("/").text)
        page = client.get("/account/password")
        self.assertEqual(page.status_code, 200)
        self.assertIn('name="current_password"', page.text)
        self.assertIn('autocomplete="current-password"', page.text)

    def test_the_right_password_changes_it_and_ends_only_the_other_sessions(self) -> None:
        elsewhere = self.signed_in()
        client = self.signed_in()

        response = self.submit(client)

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/account/password?changed=1")
        password_hash = self.account.password_hash
        if password_hash is None:
            raise AssertionError("the account was left without a password")
        self.assertTrue(auth.verify_password(password_hash, NEW))
        self.assertIn("password_changed", self.audit)
        self.assertIn("Password changed.", client.get("/account/password?changed=1").text)
        self.assertEqual(elsewhere.get("/", follow_redirects=False).headers["location"], "/login")
        self.assertEqual(
            self.changed[-1]["keep"], auth.token_hash(client.cookies[auth.SESSION_COOKIE])
        )

    def test_a_wrong_current_password_is_a_failed_sign_in_and_changes_nothing(self) -> None:
        client = self.signed_in()
        before = self.account.password_hash

        response = self.submit(client, current="not the password at all")

        self.assertEqual(response.status_code, 400)
        self.assertIn("The current password is not correct.", response.text)
        self.assertEqual(self.attempts[-1], ("operator", self.attempts[-1][1], False))
        self.assertIn("password_change_failed", self.audit)
        self.assertEqual(self.account.password_hash, before)
        self.assertEqual(self.changed, [])

    def test_a_throttled_name_is_not_tried_even_with_the_right_password(self) -> None:
        client = self.signed_in()
        self.failures = 99

        response = self.submit(client)

        self.assertEqual(response.status_code, 400)
        self.assertIn("Too many failed attempts.", response.text)
        self.assertFalse(self.attempts[-1][2])
        self.assertEqual(self.changed, [])

    def test_a_bad_new_password_is_refused_before_the_current_one_is_tried(self) -> None:
        client = self.signed_in()
        attempts = len(self.attempts)
        for new, repeat, sentence in (
            ("short", "short", "at least 8 characters"),
            (NEW, NEW + "x", "The two new passwords do not match."),
        ):
            with self.subTest(sentence=sentence):
                response = self.submit(client, new=new, repeat=repeat)

                self.assertEqual(response.status_code, 400)
                self.assertIn(sentence, response.text)
        self.assertEqual(len(self.attempts), attempts)
        self.assertEqual(self.changed, [])

    def test_no_password_is_echoed_back(self) -> None:
        client = self.signed_in()

        for response in (
            self.submit(client, current="wrong-but-long-guess"),
            self.submit(client, repeat=NEW + "x"),
        ):
            for secret in ("wrong-but-long-guess", NEW, PASSWORD):
                self.assertNotIn(secret, response.text)

    def test_a_reader_may_change_their_own_password(self) -> None:
        self.account = replace(self.account, role="reader")
        client = self.signed_in()

        self.assertEqual(self.submit(client).status_code, 303)

    def test_a_forged_form_is_refused(self) -> None:
        client = self.signed_in()

        self.assertEqual(self.submit(client, csrf="forged").status_code, 403)
        self.assertEqual(self.changed, [])

    def test_signed_out_is_sent_to_sign_in(self) -> None:
        client = self.client()

        for response in (
            client.get("/account/password", follow_redirects=False),
            client.post("/account/password", data={}, follow_redirects=False),
        ):
            self.assertEqual(response.headers["location"], "/login")


class ThePasswordHashesHoldNoConnection(OwnPasswordTestCase):
    """Review 26-10-24, 09-02: Argon2 ran inside a pool connection, throttled or not."""

    def counting(self) -> list[int]:
        held: list[int] = []
        real = self.pool.connection

        @contextmanager
        def counted() -> Any:
            held.append(1)
            try:
                with real() as connection:
                    yield connection
            finally:
                held.pop()

        patch = mock.patch.object(self.pool, "connection", counted)
        patch.start()
        self.addCleanup(patch.stop)
        return held

    def test_neither_the_check_nor_the_new_hash_runs_inside_a_connection(self) -> None:
        client = self.signed_in()
        held = self.counting()
        real_verify, real_hash = auth.verify_password, auth.hash_password
        hashed: list[str] = []

        def verify(password_hash: str, password: str) -> bool:
            self.assertEqual(held, [], "the current password was checked inside a connection")
            return real_verify(password_hash, password)

        def hash_password(password: str) -> str:
            self.assertEqual(held, [], "the new password was hashed inside a connection")
            hashed.append(password)
            return real_hash(password)

        with (
            mock.patch.object(auth, "verify_password", verify),
            mock.patch.object(auth, "hash_password", hash_password),
        ):
            response = self.submit(client)

        self.assertEqual(response.status_code, 303)
        self.assertEqual(hashed, [NEW])

    def test_a_throttled_attempt_hashes_nothing(self) -> None:
        client = self.signed_in()
        self.failures = 99
        with (
            mock.patch.object(auth, "verify_password") as verify,
            mock.patch.object(auth, "burn_absent_user_time") as burn,
            mock.patch.object(auth, "hash_password") as hashed,
        ):
            response = self.submit(client)

        self.assertEqual(response.status_code, 400)
        verify.assert_not_called()
        burn.assert_not_called()
        hashed.assert_not_called()

    def test_when_the_hashing_is_full_nothing_is_tried_or_counted(self) -> None:
        client = self.signed_in()
        attempts = len(self.attempts)
        for _ in range(auth.HASHING_AT_ONCE):
            auth.HASHING.acquire()
        try:
            with mock.patch.object(auth, "HASHING_WAIT_SECONDS", 0.05):
                response = self.submit(client)
        finally:
            for _ in range(auth.HASHING_AT_ONCE):
                auth.HASHING.release()

        self.assertEqual(response.status_code, 503)
        self.assertIn("Try again in a moment", response.text)
        self.assertEqual(len(self.attempts), attempts)
        self.assertEqual(self.changed, [])
