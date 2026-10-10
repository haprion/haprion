"""What the authentication primitives must and must not do."""

from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta

from haprion_ui import auth
from haprion_ui.config import Session as SessionPolicy
from haprion_ui.db import AuthenticatedSession

POLICY = SessionPolicy(inactivity_minutes=600, absolute_hours=168, cookie_secure=True)


def session(**overrides: object) -> AuthenticatedSession:
    now = datetime.now(UTC)
    values: dict[str, object] = {
        "token_hash": b"\x00" * 32,
        "user_id": 1,
        "username": "operator",
        "role": "admin",
        "disabled": False,
        "created_at": now - timedelta(minutes=5),
        "last_seen_at": now - timedelta(minutes=1),
        "expires_at": now + timedelta(hours=1),
        "revoked_at": None,
    }
    values.update(overrides)
    return AuthenticatedSession(**values)  # type: ignore[arg-type]


class PasswordTests(unittest.TestCase):
    def test_the_hash_is_argon2id_and_matches_the_column_constraint(self) -> None:
        #
        # The database CHECK requires this prefix. A hash that does not carry it
        # cannot be stored, so a change of algorithm has to be a deliberate
        # migration rather than a library default that moved.
        #
        self.assertTrue(auth.hash_password("a long enough password").startswith("$argon2id$"))

    def test_the_same_password_hashes_differently_every_time(self) -> None:
        first = auth.hash_password("a long enough password")
        self.assertNotEqual(first, auth.hash_password("a long enough password"))
        self.assertTrue(auth.verify_password(first, "a long enough password"))

    def test_a_wrong_password_is_rejected(self) -> None:
        stored = auth.hash_password("a long enough password")
        self.assertFalse(auth.verify_password(stored, "not the password"))

    def test_a_malformed_hash_is_a_refusal_and_not_an_exception(self) -> None:
        #
        # A row whose hash cannot be parsed is a broken account. The honest
        # answer on the login path is "no", not a stack trace.
        #
        self.assertFalse(auth.verify_password("not-a-hash", "anything"))
        self.assertFalse(auth.verify_password("", "anything"))

    def test_an_enormous_password_is_refused_rather_than_hashed(self) -> None:
        with self.assertRaises(auth.PasswordTooLong):
            auth.hash_password("x" * (auth.MAX_PASSWORD_BYTES + 1))
        stored = auth.hash_password("a long enough password")
        self.assertFalse(auth.verify_password(stored, "x" * (auth.MAX_PASSWORD_BYTES + 1)))

    def test_the_absent_user_path_answers_without_raising(self) -> None:
        auth.burn_absent_user_time("whatever was typed")
        auth.burn_absent_user_time("x" * (auth.MAX_PASSWORD_BYTES * 2))


class TokenTests(unittest.TestCase):
    def test_tokens_are_unique_and_hash_to_the_stored_width(self) -> None:
        tokens = {auth.new_session_token() for _ in range(64)}
        self.assertEqual(len(tokens), 64)
        self.assertEqual(len(auth.token_hash(next(iter(tokens)))), 32)

    def test_the_csrf_token_is_bound_to_its_session(self) -> None:
        mine, theirs = auth.new_session_token(), auth.new_session_token()
        self.assertTrue(auth.csrf_token_is_valid(mine, auth.csrf_token(mine)))
        #
        # The property that matters: holding a valid token for some session does
        # not let you post to another one.
        #
        self.assertFalse(auth.csrf_token_is_valid(mine, auth.csrf_token(theirs)))

    def test_an_absent_or_empty_csrf_token_is_not_valid(self) -> None:
        token = auth.new_session_token()
        self.assertFalse(auth.csrf_token_is_valid(token, None))
        self.assertFalse(auth.csrf_token_is_valid(token, ""))

    def test_a_token_outside_the_format_is_refused_rather_than_raising(self) -> None:
        """CR-05: `å` made `compare_digest` raise, which was a 500 for a bad field."""

        token = auth.new_session_token()
        good = auth.csrf_token(token)
        for submitted in ("å", "x" * 64, good + "x", "å" * 64, "\ud800", good[:-1] + "é"):
            with self.subTest(submitted=submitted):
                self.assertFalse(auth.csrf_token_is_valid(token, submitted))
        self.assertTrue(auth.csrf_token_is_valid(token, good))


class SessionPolicyTests(unittest.TestCase):
    def test_a_fresh_session_is_usable(self) -> None:
        self.assertTrue(auth.evaluate_session(session(), POLICY).usable)

    def test_no_session_is_not_an_error(self) -> None:
        verdict = auth.evaluate_session(None, POLICY)
        self.assertFalse(verdict.usable)
        self.assertEqual(verdict.reason, "no_session")

    def test_a_revoked_session_is_refused(self) -> None:
        verdict = auth.evaluate_session(session(revoked_at=datetime.now(UTC)), POLICY)
        self.assertEqual(verdict.reason, "revoked")

    def test_a_disabled_account_cannot_use_a_live_session(self) -> None:
        #
        # Disabling an account has to end access now, not at the next login.
        # The check is here rather than in SQL so it applies to a session that
        # was already open when the account was disabled.
        #
        self.assertEqual(
            auth.evaluate_session(session(disabled=True), POLICY).reason, "account_disabled"
        )

    def test_the_absolute_limit_ends_a_session_however_active_it_is(self) -> None:
        now = datetime.now(UTC)
        verdict = auth.evaluate_session(
            session(expires_at=now - timedelta(seconds=1), last_seen_at=now), POLICY
        )
        self.assertEqual(verdict.reason, "expired")

    def test_inactivity_ends_a_session_that_has_not_reached_its_limit(self) -> None:
        now = datetime.now(UTC)
        verdict = auth.evaluate_session(
            session(
                last_seen_at=now - timedelta(minutes=POLICY.inactivity_minutes + 1),
                expires_at=now + timedelta(days=3),
            ),
            POLICY,
        )
        self.assertEqual(verdict.reason, "inactive")

    def test_the_shortest_allowed_timeout_keeps_an_active_session(self) -> None:
        """Review 2026-09-28 F08: a request every 20 seconds, a one-minute timeout.

        The same rule the page applies - evaluate, then touch once the clock is
        older than the touch interval - walked for five minutes. With a
        one-minute touch interval the clock was never written before the
        session had already expired.
        """

        from dataclasses import replace

        from haprion_ui.views import touch_after

        policy = SessionPolicy(inactivity_minutes=1, absolute_hours=168, cookie_secure=True)
        start = datetime.now(UTC)
        current = session(last_seen_at=start, expires_at=start + timedelta(hours=1))
        for step in range(15):
            moment = start + timedelta(seconds=20 * step)
            with self.subTest(seconds=20 * step):
                self.assertTrue(auth.evaluate_session(current, policy, now=moment).usable)
            if moment - current.last_seen_at > touch_after(policy.inactivity_minutes):
                current = replace(current, last_seen_at=moment)

    def test_the_default_timeout_keeps_the_one_minute_touch(self) -> None:
        from haprion_ui.views import TOUCH_AFTER, touch_after

        self.assertEqual(touch_after(600), TOUCH_AFTER)
        self.assertEqual(touch_after(1), timedelta(seconds=30))

    def test_the_issued_expiry_follows_the_configured_lifetime(self) -> None:
        now = datetime.now(UTC)
        self.assertEqual(
            auth.absolute_expiry(POLICY, now=now), now + timedelta(hours=POLICY.absolute_hours)
        )

    def test_a_sign_in_through_the_provider_takes_the_shorter_limit(self) -> None:
        # B203: the provider's groups are not asked about again until the next one.
        now = datetime(2026, 9, 28, 12, 0, tzinfo=UTC)
        self.assertEqual(
            auth.absolute_expiry(POLICY, now=now, through_provider=True), now + timedelta(hours=10)
        )
        short = replace(POLICY, absolute_hours=2)
        self.assertEqual(
            auth.absolute_expiry(short, now=now, through_provider=True), now + timedelta(hours=2)
        )


if __name__ == "__main__":
    unittest.main()
