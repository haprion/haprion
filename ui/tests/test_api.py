"""The API's tokens and answers (B416): who may call, and what a refusal looks like."""

from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest import mock

from fastapi.testclient import TestClient

from haprion_ui import api_tokens, db
from haprion_ui.api import caller
from tests.test_login import LoginTestCase, configuration

NOW = datetime(2026, 10, 31, 12, 0, tzinfo=UTC)


def a_token(**changes: Any) -> db.ApiToken:
    token = db.ApiToken(
        id=7,
        name="monitoring",
        level="read",
        clusters=[],
        objects=[],
        sources=[],
        prefix="hap_abcdefgh",
        created_at=NOW - timedelta(days=1),
        created_by="admin",
        expires_at=NOW + timedelta(days=364),
        revoked_at=None,
        revoked_by=None,
        last_used_at=None,
        last_used_from=None,
    )
    return replace(token, **changes)


class TheSecret(unittest.TestCase):
    def test_a_new_secret_has_the_marker_and_its_shape(self) -> None:
        secret = api_tokens.new_secret()
        self.assertTrue(secret.startswith("hap_"))
        self.assertEqual(api_tokens.bearer_secret(f"Bearer {secret}"), secret)
        self.assertEqual(api_tokens.shown_prefix(secret), secret[:12])
        self.assertEqual(len(api_tokens.secret_hash(secret)), 32)
        self.assertNotEqual(api_tokens.new_secret(), secret)

    def test_a_header_that_cannot_hold_a_secret_is_none_before_any_lookup(self) -> None:
        secret = api_tokens.new_secret()
        for header in (
            None,
            "",
            secret,
            f"Basic {secret}",
            "Bearer ",
            f"Bearer {secret[:-1]}",
            f"Bearer {secret}x",
            "Bearer hap_" + "å" * 43,
        ):
            with self.subTest(header=header):
                self.assertIsNone(api_tokens.bearer_secret(header))
        self.assertEqual(api_tokens.bearer_secret(f"bearer  {secret} "), secret)


class TheToken(unittest.TestCase):
    def test_each_way_to_fail_has_its_reason(self) -> None:
        cases = {
            "unknown": None,
            "revoked": a_token(revoked_at=NOW, revoked_by="admin"),
            "expired": a_token(expires_at=NOW),
            "outside_sources": a_token(sources=["192.0.2.0/24"]),
        }
        for reason, token in cases.items():
            with self.subTest(reason=reason):
                verdict = api_tokens.evaluate(token, now=NOW, source="198.51.100.7")
                self.assertEqual((verdict.usable, verdict.reason), (False, reason))

    def test_a_token_is_usable_from_its_sources_and_before_its_end(self) -> None:
        token = a_token(sources=["192.0.2.0/24", "2001:db8::/32"])
        for source in ("192.0.2.9", "2001:db8::1"):
            with self.subTest(source=source):
                self.assertTrue(api_tokens.evaluate(token, now=NOW, source=source).usable)

    def test_write_reaches_every_level_and_the_others_only_their_own(self) -> None:
        self.assertTrue(api_tokens.reaches("write", "read"))
        self.assertTrue(api_tokens.reaches("write", "block"))
        self.assertTrue(api_tokens.reaches("block", "block"))
        self.assertFalse(api_tokens.reaches("block", "read"))
        self.assertFalse(api_tokens.reaches("read", "block"))
        self.assertFalse(api_tokens.reaches("read", "write"))
        self.assertFalse(api_tokens.reaches("block", "write"))

    def test_the_scope_names_clusters_and_for_a_block_token_objects(self) -> None:
        anywhere = a_token()
        self.assertTrue(api_tokens.covers(anywhere, "alpha", "shop"))
        one = a_token(level="block", clusters=["alpha"], objects=["shop"])
        self.assertTrue(api_tokens.covers(one, "alpha"))
        self.assertTrue(api_tokens.covers(one, "alpha", "shop"))
        self.assertFalse(api_tokens.covers(one, "alpha", "intranet"))
        self.assertFalse(api_tokens.covers(one, "beta"))

    def test_names_days_and_sources_are_checked_before_the_table_is(self) -> None:
        for name in ("docker1-fail2ban", "a", "a" * 64):
            with self.subTest(name=name):
                self.assertEqual(api_tokens.name_problem(name), "")
        for name in ("", "-a", "a-", "A", "a_b", "a" * 65, "a b"):
            with self.subTest(name=name):
                self.assertNotEqual(api_tokens.name_problem(name), "")
        self.assertEqual(api_tokens.days_problem(730), "")
        self.assertNotEqual(api_tokens.days_problem(731), "")
        self.assertNotEqual(api_tokens.days_problem(0), "")
        self.assertEqual(api_tokens.sources_problem(["192.0.2.0/24", "2001:db8::1"]), "")
        self.assertNotEqual(api_tokens.sources_problem(["192.0.2.0/33"]), "")

    def test_a_token_ending_within_thirty_days_or_ended_needs_attention(self) -> None:
        self.assertFalse(api_tokens.ends_soon(a_token(), NOW))
        self.assertTrue(api_tokens.ends_soon(a_token(expires_at=NOW + timedelta(days=30)), NOW))
        self.assertTrue(api_tokens.ends_soon(a_token(expires_at=NOW - timedelta(days=1)), NOW))
        revoked = a_token(expires_at=NOW + timedelta(days=3), revoked_at=NOW, revoked_by="admin")
        self.assertFalse(api_tokens.ends_soon(revoked, NOW))


class ApiTestCase(LoginTestCase):
    """The application with a table of tokens in memory, by secret."""

    def setUp(self) -> None:
        super().setUp()
        self.tokens: dict[bytes, db.ApiToken] = {}
        self.touched: list[tuple[int, str]] = []
        for patch in (
            mock.patch("haprion_ui.db.api_token_by_hash", side_effect=self._token),
            mock.patch("haprion_ui.db.touch_api_token", side_effect=self._touch),
            mock.patch("haprion_ui.db.cluster_list", return_value=("alpha", "beta")),
            mock.patch.object(caller, "FAILURES", caller.Failures()),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def _token(self, _c: object, token_hash: bytes) -> db.ApiToken | None:
        return self.tokens.get(token_hash)

    def _touch(self, _c: object, token_id: int, source: str) -> None:
        self.touched.append((token_id, source))

    def issue(self, **changes: Any) -> str:
        secret = api_tokens.new_secret()
        changes.setdefault("expires_at", datetime.now(UTC) + timedelta(days=30))
        self.tokens[api_tokens.secret_hash(secret)] = a_token(**changes)
        return secret

    def api(self) -> Any:
        return self.client(replace(configuration(), clusters=("alpha", "beta")))


class TheApiAnswers(ApiTestCase):
    def test_a_call_without_a_valid_token_is_one_401_whatever_the_reason(self) -> None:
        client = self.api()
        revoked = self.issue(revoked_at=NOW, revoked_by="admin")
        expired = self.issue(expires_at=NOW - timedelta(days=1))
        elsewhere = self.issue(sources=["192.0.2.0/24"])
        headers: list[dict[str, str]] = [
            {},
            {"Authorization": "Bearer nonsense"},
            {"Authorization": f"Bearer {api_tokens.new_secret()}"},
            {"Authorization": f"Bearer {revoked}"},
            {"Authorization": f"Bearer {expired}"},
            {"Authorization": f"Bearer {elsewhere}"},
        ]
        bodies = set()
        reasons = []
        for header in headers:
            with self.subTest(header=header), self.assertLogs("haprion_ui.api") as logged:
                response = client.get("/api/v1/clusters", headers=header)
                reasons.append(logged.output[0].split("refused: ")[1])
                self.assertEqual(response.status_code, 401)
                self.assertEqual(
                    response.headers["www-authenticate"], 'Bearer error="invalid_token"'
                )
                body = response.json()
                self.assertEqual((body["ok"], body["outcome"]), (False, "blocked"))
                self.assertEqual(body["error"]["code"], "unauthorized")
                bodies.add((body["error"]["message"], body["operation"]))
        self.assertEqual(len(bodies), 1)
        self.assertEqual(
            reasons,
            [
                "missing",
                "malformed",
                "unknown",
                "revoked (token monitoring)",
                "expired (token monitoring)",
                "outside_sources (token monitoring)",
            ],
        )
        self.assertEqual(self.touched, [])

    def test_a_valid_token_is_answered_in_the_envelope_and_its_use_noted(self) -> None:
        client = self.api()
        secret = self.issue()
        response = client.get("/api/v1/clusters", headers={"Authorization": f"Bearer {secret}"})
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(
            (body["ok"], body["outcome"], body["operation"]), (True, "done", "cluster_list")
        )
        self.assertEqual([c["name"] for c in body["result"]["clusters"]], ["alpha", "beta"])
        self.assertEqual(self.touched, [(7, "127.0.0.1")])

    def test_a_token_sees_only_the_clusters_it_names(self) -> None:
        client = self.api()
        secret = self.issue(clusters=["beta"])
        response = client.get("/api/v1/clusters", headers={"Authorization": f"Bearer {secret}"})
        self.assertEqual([c["name"] for c in response.json()["result"]["clusters"]], ["beta"])

    def test_a_level_that_does_not_reach_is_a_403(self) -> None:
        client = self.api()
        secret = self.issue(level="block")
        response = client.get("/api/v1/clusters", headers={"Authorization": f"Bearer {secret}"})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["error"]["code"], "forbidden")

    def test_a_token_reads_itself_but_never_its_hash(self) -> None:
        client = self.api()
        secret = self.issue(level="block", objects=["shop"])
        response = client.get("/api/v1/token", headers={"Authorization": f"Bearer {secret}"})
        self.assertEqual(response.status_code, 200)
        shown = response.json()["result"]["token"]
        self.assertEqual(
            (shown["name"], shown["level"], shown["objects"]), ("monitoring", "block", ["shop"])
        )
        self.assertNotIn(secret, response.text)
        self.assertNotIn("hash", response.text)

    def test_ten_tokens_that_are_not_valid_close_the_source_for_a_minute(self) -> None:
        client = self.api()
        good = self.issue()
        with self.assertLogs("haprion_ui.api"):
            for _ in range(caller.FAILURES_PER_MINUTE):
                self.assertEqual(client.get("/api/v1/token").status_code, 401)
        refused = client.get("/api/v1/token", headers={"Authorization": f"Bearer {good}"})
        self.assertEqual(refused.status_code, 429)
        self.assertEqual(refused.headers["retry-after"], "60")
        self.assertEqual(refused.json()["error"]["code"], "rate_limited")

    def test_the_failure_count_forgets_after_its_window(self) -> None:
        failures = caller.Failures(limit=2, window=60)
        failures.note("192.0.2.1", now=100)
        failures.note("192.0.2.1", now=110)
        self.assertTrue(failures.refused("192.0.2.1", now=150))
        self.assertFalse(failures.refused("192.0.2.1", now=171))
        self.assertFalse(failures.refused("192.0.2.2", now=150))

    def test_the_schema_is_for_a_valid_token_only(self) -> None:
        client = self.api()
        with self.assertLogs("haprion_ui.api"):
            self.assertEqual(client.get("/api/v1/openapi.json").status_code, 401)
        secret = self.issue()
        schema = client.get("/api/v1/openapi.json", headers={"Authorization": f"Bearer {secret}"})
        self.assertEqual(schema.status_code, 200)
        self.assertIn("/clusters", schema.json()["paths"])
        self.assertNotIn("/openapi.json", schema.json()["paths"])

    def test_a_path_or_a_body_the_api_does_not_know_is_answered_as_json(self) -> None:
        client = self.api()
        secret = self.issue()
        missing = client.get("/api/v1/nothing", headers={"Authorization": f"Bearer {secret}"})
        self.assertEqual(missing.status_code, 404)
        self.assertEqual(missing.json()["error"]["code"], "not_found")
        wrong = client.post("/api/v1/clusters", headers={"Authorization": f"Bearer {secret}"})
        self.assertEqual(wrong.status_code, 405)
        self.assertEqual(wrong.json()["error"]["code"], "method_not_allowed")

    def test_a_failure_of_this_side_is_a_500_in_the_envelope_and_a_logged_traceback(self) -> None:
        client = self.api()
        client = TestClient(
            client.app, base_url=str(client.base_url), raise_server_exceptions=False
        )
        secret = self.issue()
        with (
            mock.patch("haprion_ui.db.cluster_list", side_effect=RuntimeError("boom")),
            self.assertLogs("haprion_ui.api", "ERROR") as logged,
        ):
            response = client.get("/api/v1/clusters", headers={"Authorization": f"Bearer {secret}"})
        self.assertEqual(response.status_code, 500)
        body = response.json()
        self.assertEqual((body["outcome"], body["error"]["code"]), ("failed", "internal_error"))
        self.assertNotIn("boom", response.text)
        self.assertIn("RuntimeError: boom", "\n".join(logged.output))
