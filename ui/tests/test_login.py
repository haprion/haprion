"""The login flow as HTTP: cookies, CSRF, the throttle, and what is not revealed.

The database is replaced rather than mocked in detail. Every statement these
handlers issue lives in `haproxy_ui.db`, so substituting those functions leaves
the whole of the flow under test - the order of the checks, what is written to
the audit trail, which cookie is set with which flags - and removes only the
part that needs PostgreSQL. The SQL itself is covered where it belongs, by the
privilege suite that runs against the real database.
"""

from __future__ import annotations

import re
import unittest
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest import mock

from fastapi.testclient import TestClient

from haproxy_ui import auth
from haproxy_ui.app import create_app
from haproxy_ui.config import Config, Database, Listen, Poller, Throttle
from haproxy_ui.config import Session as SessionPolicy
from haproxy_ui.db import Account, AuthenticatedSession

PASSWORD = "a sufficiently long password"

#
# Every rendered form carries a fresh CSRF token, so two responses that must be
# identical are identical everywhere except there. Masking it is what lets the
# comparison be exact rather than approximate.
#
CSRF_VALUE = re.compile(r'value="[0-9a-f]{64}"')


def without_csrf(text: str) -> str:
    return CSRF_VALUE.sub('value="..."', text)


def configuration(*, cookie_secure: bool = True, max_failures: int = 3) -> Config:
    return Config(
        database=Database(name="haproxy_ui_test", socket_directory="/var/run/postgresql"),
        listen=Listen(host="127.0.0.1", port=8080),
        management_writes=False,
        session=SessionPolicy(
            inactivity_minutes=600, absolute_hours=168, cookie_secure=cookie_secure
        ),
        throttle=Throttle(max_failures=max_failures, window_minutes=15),
        clusters=(),
        poller=Poller(interval_seconds=60),
    )


class FakePool:
    """Hands out a connection object that records commits and does nothing else."""

    def __init__(self) -> None:
        self.commits = 0

    @contextmanager
    def connection(self) -> Any:
        yield self

    def commit(self) -> None:
        self.commits += 1

    def open(self, **_: object) -> None:
        return None

    def close(self) -> None:
        return None


class LoginTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.account = Account(
            id=1,
            username="operator",
            role="admin",
            disabled=False,
            password_hash=auth.hash_password(PASSWORD),
        )
        self.pool = FakePool()
        self.sessions: dict[bytes, AuthenticatedSession] = {}
        self.attempts: list[tuple[str, str, bool]] = []
        self.audit: list[str] = []
        self.failures = 0

        self.patches = [
            mock.patch("haproxy_ui.db.pool", return_value=self.pool),
            mock.patch("haproxy_ui.db.account_by_username", side_effect=self._account),
            mock.patch("haproxy_ui.db.record_login_attempt", side_effect=self._attempt),
            mock.patch("haproxy_ui.db.failures_since_last_success", side_effect=self._failures),
            mock.patch("haproxy_ui.db.create_session", side_effect=self._create_session),
            mock.patch("haproxy_ui.db.session_by_hash", side_effect=self._session),
            mock.patch("haproxy_ui.db.touch_session"),
            mock.patch("haproxy_ui.db.revoke_session", side_effect=self._revoke),
            mock.patch("haproxy_ui.db.record_audit_event", side_effect=self._audit_event),
            mock.patch("haproxy_ui.db.cluster_statuses", return_value=[]),
        ]
        for patch in self.patches:
            patch.start()
        self.addCleanup(lambda: [patch.stop() for patch in self.patches])

    # - the fake database -------------------------------------------------

    def _account(self, _connection: object, username: str) -> Account | None:
        return self.account if username.lower() == "operator" else None

    def _attempt(self, _c: object, *, username: str, client_ip: str, succeeded: bool) -> None:
        self.attempts.append((username, client_ip, succeeded))

    def _failures(self, _c: object, **_: object) -> int:
        return self.failures

    def _create_session(
        self, _c: object, *, token_hash: bytes, user_id: int, expires_at: datetime
    ) -> None:
        now = datetime.now(UTC)
        self.sessions[token_hash] = AuthenticatedSession(
            token_hash=token_hash,
            user_id=user_id,
            username=self.account.username,
            role=self.account.role,
            disabled=self.account.disabled,
            created_at=now,
            last_seen_at=now,
            expires_at=expires_at,
            revoked_at=None,
        )

    def _session(self, _c: object, token_hash: bytes) -> AuthenticatedSession | None:
        return self.sessions.get(token_hash)

    def _revoke(self, _c: object, token_hash: bytes) -> None:
        self.sessions.pop(token_hash, None)

    def _audit_event(self, _c: object, *, action: str, **_: object) -> None:
        self.audit.append(action)

    # - helpers -----------------------------------------------------------

    def client(self, config: Config | None = None) -> TestClient:
        client = TestClient(
            create_app(config or configuration()), base_url="https://manager.example.com"
        )
        client.__enter__()
        self.addCleanup(client.__exit__, None, None, None)
        return client

    def sign_in(
        self, client: TestClient, *, username: str = "operator", password: str = PASSWORD
    ) -> Any:
        page = client.get("/login")
        token = auth.csrf_token(client.cookies[auth.PRE_SESSION_COOKIE])
        self.assertIn("Sign in", page.text)
        return client.post(
            "/login",
            data={"username": username, "password": password, auth.CSRF_FIELD: token},
            follow_redirects=False,
        )


class SigningIn(LoginTestCase):
    def test_a_correct_password_signs_in_and_sets_the_session_cookie(self) -> None:
        client = self.client()
        response = self.sign_in(client)
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/")
        self.assertIn(auth.SESSION_COOKIE, client.cookies)
        self.assertEqual(self.attempts[-1][2], True)
        self.assertIn("login", self.audit)

    def test_the_cookie_is_httponly_secure_and_lax(self) -> None:
        client = self.client()
        header = self.sign_in(client).headers["set-cookie"]
        #
        # Read off the header rather than from configuration, because these three
        # flags are the entire defence for a token that is otherwise a bearer
        # credential: unreadable to script, never sent in clear, not attached to
        # a cross-site form post.
        #
        self.assertIn("HttpOnly", header)
        self.assertIn("Secure", header)
        self.assertIn("SameSite=lax", header.replace("samesite", "SameSite"))

    def test_the_landing_page_names_the_account_after_signing_in(self) -> None:
        client = self.client()
        self.sign_in(client)
        page = client.get("/")
        self.assertEqual(page.status_code, 200)
        self.assertIn("operator", page.text)
        self.assertIn("admin", page.text)
        self.assertIn("Dashboard", page.text)
        self.assertIn("Read-only mode", page.text)

    def test_static_design_assets_are_local_and_served(self) -> None:
        client = self.client()
        page = client.get("/login")
        self.assertIn('href="https://manager.example.com/static/app.css"', page.text)
        self.assertIn('src="https://manager.example.com/static/theme.js"', page.text)
        self.assertNotIn("cdn", page.text.lower())
        stylesheet = client.get("/static/app.css")
        script = client.get("/static/theme.js")
        self.assertEqual(stylesheet.status_code, 200)
        self.assertEqual(script.status_code, 200)
        self.assertIn("--healthy", stylesheet.text)
        self.assertIn("localStorage", script.text)

    def test_signing_in_over_plain_http_omits_secure_only_when_configured(self) -> None:
        client = TestClient(
            create_app(configuration(cookie_secure=False)), base_url="http://localhost"
        )
        with client:
            client.get("/login")
            token = auth.csrf_token(client.cookies[auth.PRE_SESSION_COOKIE])
            response = client.post(
                "/login",
                data={"username": "operator", "password": PASSWORD, auth.CSRF_FIELD: token},
                follow_redirects=False,
            )
        self.assertNotIn("Secure", response.headers["set-cookie"])


class RefusingToSignIn(LoginTestCase):
    def test_a_wrong_password_is_refused_and_recorded(self) -> None:
        client = self.client()
        response = self.sign_in(client, password="wrong")
        self.assertEqual(response.status_code, 401)
        self.assertNotIn(auth.SESSION_COOKIE, client.cookies)
        self.assertEqual(self.attempts[-1][2], False)
        self.assertIn("login_failed", self.audit)

    def test_an_unknown_account_answers_exactly_as_a_wrong_password_does(self) -> None:
        #
        # The two responses are compared, not merely each checked for failure.
        # Any difference between them - wording, status, a header - is a way to
        # ask this form which usernames exist.
        #
        wrong = self.sign_in(self.client(), password="wrong")
        unknown = self.sign_in(self.client(), username="nobody")
        self.assertEqual(wrong.status_code, unknown.status_code)
        self.assertEqual(without_csrf(wrong.text), without_csrf(unknown.text))

    def test_a_disabled_account_cannot_sign_in_with_the_right_password(self) -> None:
        self.account = Account(
            id=1,
            username="operator",
            role="admin",
            disabled=True,
            password_hash=self.account.password_hash,
        )
        response = self.sign_in(self.client())
        self.assertEqual(response.status_code, 401)
        self.assertNotIn(auth.SESSION_COOKIE, self.client().cookies)

    def test_a_post_without_a_csrf_token_is_not_a_login(self) -> None:
        client = self.client()
        client.get("/login")
        response = client.post(
            "/login",
            data={"username": "operator", "password": PASSWORD},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(auth.SESSION_COOKIE, client.cookies)
        #
        # Nothing was attempted: a forged post must not be able to spend a
        # victim's throttle budget either.
        #
        self.assertEqual(self.attempts, [])

    def test_a_csrf_token_from_another_visitor_is_refused(self) -> None:
        client = self.client()
        client.get("/login")
        response = client.post(
            "/login",
            data={
                "username": "operator",
                "password": PASSWORD,
                auth.CSRF_FIELD: auth.csrf_token(auth.new_session_token()),
            },
            follow_redirects=False,
        )
        self.assertNotIn(auth.SESSION_COOKIE, client.cookies)
        self.assertEqual(response.status_code, 200)


class Throttling(LoginTestCase):
    def test_the_correct_password_is_refused_once_the_limit_is_reached(self) -> None:
        #
        # The point of the throttle, stated as a test: past the limit the right
        # password stops working, and it stops working without the account being
        # looked at.
        #
        self.failures = 3
        with mock.patch("haproxy_ui.db.account_by_username") as lookup:
            response = self.sign_in(self.client(configuration(max_failures=3)))
            lookup.assert_not_called()
        self.assertEqual(response.status_code, 401)
        self.assertEqual(self.attempts[-1][2], False)

    def test_a_throttled_answer_is_indistinguishable_from_a_wrong_password(self) -> None:
        wrong = self.sign_in(self.client(), password="wrong")
        self.failures = 99
        throttled = self.sign_in(self.client())
        self.assertEqual(wrong.status_code, throttled.status_code)
        self.assertEqual(without_csrf(wrong.text), without_csrf(throttled.text))

    def test_the_client_address_comes_from_the_forwarded_header(self) -> None:
        client = self.client()
        client.get("/login")
        token = auth.csrf_token(client.cookies[auth.PRE_SESSION_COOKIE])
        client.post(
            "/login",
            data={"username": "operator", "password": "wrong", auth.CSRF_FIELD: token},
            headers={"X-Forwarded-For": "198.51.100.7"},
            follow_redirects=False,
        )
        self.assertEqual(self.attempts[-1][1], "198.51.100.7")

    def test_an_unparseable_forwarded_address_does_not_break_the_login_path(self) -> None:
        client = self.client()
        client.get("/login")
        token = auth.csrf_token(client.cookies[auth.PRE_SESSION_COOKIE])
        response = client.post(
            "/login",
            data={"username": "operator", "password": "wrong", auth.CSRF_FIELD: token},
            headers={"X-Forwarded-For": "not-an-address"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(self.attempts[-1][1], "127.0.0.1")


class SessionsAndSigningOut(LoginTestCase):
    def test_the_landing_page_redirects_to_the_form_when_signed_out(self) -> None:
        response = self.client().get("/", follow_redirects=False)
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/login")

    def test_an_unknown_cookie_is_not_a_session(self) -> None:
        client = self.client()
        client.cookies.set(auth.SESSION_COOKIE, auth.new_session_token())
        response = client.get("/", follow_redirects=False)
        self.assertEqual(response.status_code, 303)

    def test_signing_out_revokes_the_session_and_clears_the_cookie(self) -> None:
        client = self.client()
        self.sign_in(client)
        token = client.cookies[auth.SESSION_COOKIE]
        page = client.get("/")
        csrf = auth.csrf_token(token)
        self.assertIn(csrf, page.text)

        response = client.post("/logout", data={auth.CSRF_FIELD: csrf}, follow_redirects=False)
        self.assertEqual(response.status_code, 303)
        self.assertEqual(self.sessions, {})
        self.assertIn("logout", self.audit)
        self.assertEqual(client.get("/", follow_redirects=False).status_code, 303)

    def test_signing_out_without_a_token_leaves_the_session_alone(self) -> None:
        #
        # A cross-site post must not be able to log an operator out mid-incident.
        #
        client = self.client()
        self.sign_in(client)
        client.post("/logout", data={}, follow_redirects=False)
        self.assertEqual(len(self.sessions), 1)
        self.assertEqual(client.get("/", follow_redirects=False).status_code, 200)

    def test_a_session_that_has_gone_inactive_is_not_accepted(self) -> None:
        client = self.client()
        self.sign_in(client)
        stale = datetime.now(UTC) - timedelta(hours=11)
        for digest, session in list(self.sessions.items()):
            self.sessions[digest] = replace(session, last_seen_at=stale)
        self.assertEqual(client.get("/", follow_redirects=False).status_code, 303)


if __name__ == "__main__":
    unittest.main()
