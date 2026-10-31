"""Settings -> API tokens (B416): the list, the form, the one showing of a secret, revoke and remove."""

from __future__ import annotations

import html
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest import mock

from fastapi.testclient import TestClient

from haprion_ui import api_tokens, attention, auth, db
from tests.test_api import a_token
from tests.test_login import LoginTestCase, configuration

NOW = datetime.now(UTC)


class TokensPage(LoginTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.tokens: list[db.ApiToken] = []
        self.made: list[dict[str, Any]] = []
        self.audit_details: list[tuple[str, dict[str, Any]]] = []
        self.revoked: list[str] = []
        self.deleted: list[str] = []

        def create(_c: object, **values: Any) -> db.ApiToken:
            self.made.append(values)
            return a_token(
                name=values["name"],
                level=values["level"],
                clusters=list(values["clusters"]),
                objects=list(values["objects"]),
                sources=list(values["sources"]),
                prefix=values["prefix"],
                expires_at=NOW + timedelta(days=values["days"]),
            )

        def revoke(_c: object, name: str, *, by: str) -> bool:
            self.revoked.append(name)
            return True

        def delete(_c: object, name: str) -> bool:
            self.deleted.append(name)
            return True

        def record(_c: object, *, action: str, detail: Any = None, **_: Any) -> None:
            self.audit.append(action)
            self.audit_details.append((action, dict(detail or {})))

        for patch in (
            mock.patch("haprion_ui.db.api_tokens", side_effect=lambda _c: list(self.tokens)),
            mock.patch("haprion_ui.db.create_api_token", side_effect=create),
            mock.patch("haprion_ui.db.revoke_api_token", side_effect=revoke),
            mock.patch("haprion_ui.db.delete_api_token", side_effect=delete),
            mock.patch("haprion_ui.db.record_audit_event", side_effect=record),
            mock.patch(
                "haprion_ui.external_blocking.blocking_objects",
                side_effect=lambda _r, cluster: ("shop", "store") if cluster == "alpha" else (),
            ),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def admin(self) -> TestClient:
        client = self.client(
            replace(configuration(), management_writes=True, clusters=("alpha", "beta"))
        )
        self.assertEqual(self.sign_in(client).status_code, 303)
        self.audit_details.clear()
        return client

    def post(self, client: TestClient, path: str, **fields: Any) -> Any:
        token = client.cookies[auth.SESSION_COOKIE]
        data = {auth.CSRF_FIELD: auth.csrf_token(token), **fields}
        return client.post(path, data=data, follow_redirects=False)

    def fill(self, **changes: Any) -> dict[str, Any]:
        return {"name": "monitoring", "level": "read", "days": "365", **changes}


class TheList(TokensPage):
    def test_tokens_are_listed_by_name_with_their_state_and_the_row_s_own_button(self) -> None:
        self.tokens = [
            a_token(name="zeta", prefix="hap_Zeta0000", expires_at=NOW + timedelta(days=200)),
            a_token(
                name="alpha-block",
                level="block",
                clusters=["alpha"],
                objects=["shop"],
                sources=["192.0.2.0/24"],
                expires_at=NOW + timedelta(days=10),
                last_used_at=NOW - timedelta(hours=1),
                last_used_from="192.0.2.9",
            ),
            a_token(name="gone", revoked_at=NOW - timedelta(days=1), revoked_by="admin"),
            a_token(name="late", expires_at=NOW - timedelta(days=2)),
        ]
        page = self.admin().get("/settings/api-tokens").text

        names = [
            page.index(f"<strong>{name}</strong>")
            for name in ("alpha-block", "gone", "late", "zeta")
        ]
        self.assertEqual(names, sorted(names))
        self.assertIn("alpha · shop", page)
        # Review 26-10-31, P3-4: the prefix tells which token a found one is.
        self.assertIn('data-label="Prefix" class="api-token-prefix">hap_Zeta0000</td>', page)
        self.assertEqual(page.count("hap_abcdefgh"), 3)
        self.assertIn("192.0.2.0/24", page)
        self.assertIn("Anywhere", page)
        self.assertIn("Never", page)
        self.assertIn("192.0.2.9", page)
        self.assertEqual(page.count("status-badge-healthy"), 2)
        self.assertEqual(page.count("status-badge-unknown"), 1)
        self.assertEqual(page.count("status-badge-critical"), 1)
        # The end is marked for the token ending in 10 days and the one that has ended.
        self.assertEqual(page.count("warning-text"), 2)
        self.assertEqual(page.count("/settings/api-tokens/alpha-block/revoke"), 1)
        self.assertEqual(page.count("/settings/api-tokens/zeta/revoke"), 1)
        self.assertEqual(page.count("/settings/api-tokens/gone/remove"), 1)
        self.assertEqual(page.count("/settings/api-tokens/late/remove"), 1)
        self.assertNotIn("/settings/api-tokens/gone/revoke", page)
        self.assertIn('href="/settings/api-tokens/new">Add token</a>', page)

    def test_without_tokens_the_page_says_so(self) -> None:
        self.assertIn("No API token", self.admin().get("/settings/api-tokens").text)

    def test_settings_leads_to_the_page_with_the_counts(self) -> None:
        self.tokens = [
            a_token(name="one"),
            a_token(name="two", expires_at=NOW + timedelta(days=3)),
            a_token(name="three", revoked_at=NOW, revoked_by="admin"),
        ]
        card = self.admin().get("/settings").text.split('id="api-tokens"', 1)[1]
        card = card.split("</section>", 1)[0]

        self.assertIn("<h3>API tokens</h3>", card)
        self.assertIn('href="/settings/api-tokens">Edit</a>', card)
        self.assertIn(">2</td>", card)
        self.assertIn('<span class="warning-text">1</span>', card)

    def test_a_reader_is_refused_every_page(self) -> None:
        self.account = replace(self.account, role="reader")
        client = self.client(replace(configuration(), management_writes=True))
        self.sign_in(client)
        for path in ("", "/new", "/monitoring/revoke"):
            with self.subTest(path):
                self.assertEqual(client.get("/settings/api-tokens" + path).status_code, 403)


class MakingATokenOnThePage(TokensPage):
    def test_the_form_offers_the_clusters_and_the_proxies_that_block(self) -> None:
        page = self.admin().get("/settings/api-tokens/new").text

        for value in ("alpha", "beta", "shop", "store"):
            self.assertIn(f'value="{value}"', page)
        for level in api_tokens.LEVELS:
            self.assertIn(f'name="level" value="{level}"', page)
        self.assertIn('<option value="365" selected>365 days</option>', page)

    def test_without_a_proxy_to_choose_the_block_level_is_not_offered(self) -> None:
        """Review 26-10-31, P3-8: the level was offered, and could not be filled in."""

        with mock.patch("haprion_ui.external_blocking.blocking_objects", return_value=()):
            page = self.admin().get("/settings/api-tokens/new").text
            refused = self.post(
                self.admin(), "/settings/api-tokens/new", **self.fill(level="block")
            )

        for level in api_tokens.LEVELS:
            self.assertEqual(f'name="level" value="{level}"' in page, level != "block", level)
        self.assertNotIn("data-for-level", page)
        # Still refused if it is sent, and the form then shows the level it can offer.
        self.assertEqual(refused.status_code, 400)
        self.assertIn("A block token names the proxies it may block on.", refused.text)
        self.assertNotIn('name="level" value="block"', refused.text)
        self.assertIn('name="level" value="read" checked', refused.text)

    def test_the_secret_is_shown_once_and_kept_nowhere_else(self) -> None:
        response = self.post(
            self.admin(),
            "/settings/api-tokens/new",
            **self.fill(
                name="docker1-fail2ban",
                level="block",
                clusters=["alpha"],
                objects=["shop"],
                sources="192.0.2.0/24\n198.51.100.7",
                days="90",
            ),
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["cache-control"], "no-store")
        (values,) = self.made
        secret = html.unescape(response.text).split("<code>", 1)[1].split("</code>", 1)[0]
        self.assertRegex(secret, api_tokens.SECRET_SHAPE.pattern)
        self.assertEqual(values["token_hash"], api_tokens.secret_hash(secret))
        self.assertEqual(values["prefix"], secret[:12])
        self.assertEqual(
            (values["clusters"], values["objects"], values["days"], values["created_by"]),
            (("alpha",), ("shop",), 90, "operator"),
        )
        self.assertEqual(values["sources"], ("192.0.2.0/24", "198.51.100.7/32"))
        self.assertIn("will not be shown again", response.text)
        self.assertNotIn("location", response.headers)
        # The record names the token and its reach, never the secret.
        ((action, detail),) = self.audit_details
        self.assertEqual(action, "api_token_created")
        self.assertEqual(
            (detail["name"], detail["level"], detail["clusters"], detail["objects"], detail["via"]),
            ("docker1-fail2ban", "block", ["alpha"], ["shop"], "web"),
        )
        self.assertNotIn(secret, repr(self.audit_details))
        self.assertNotIn(secret[4:], repr(self.made[0]))
        self.assertEqual(self.pool.commits >= 1, True)

    def test_each_refusal_keeps_what_was_typed_and_writes_nothing(self) -> None:
        cases: dict[str, dict[str, Any]] = {
            "The name must be 1 to 64 lowercase": {"name": "Not Valid"},
            "The level must be read, block or write.": {"level": "admin"},
            "gamma is not a cluster": {"clusters": ["gamma"]},
            "Proxies can only be chosen for a block token.": {"objects": ["shop"]},
            "ghost is not a proxy with dynamic blocking": {"level": "block", "objects": ["ghost"]},
            "A block token names the proxies it may block on.": {"level": "block", "objects": []},
            "is not an address or a network": {"sources": "not-an-address"},
            "host bits": {"sources": "192.0.2.5/24"},
            "The validity must be between 1 and 730 days.": {"days": "731"},
            "The validity must be a number of days.": {"days": "soon"},
        }
        client = self.admin()
        for expected, changes in cases.items():
            with self.subTest(expected):
                response = self.post(client, "/settings/api-tokens/new", **self.fill(**changes))
                self.assertEqual(response.status_code, 400)
                self.assertIn(expected, html.unescape(response.text))
        self.assertEqual(self.made, [])
        self.assertEqual(self.audit_details, [])

    def test_a_proxy_must_be_in_one_of_the_chosen_clusters(self) -> None:
        response = self.post(
            self.admin(),
            "/settings/api-tokens/new",
            **self.fill(level="block", clusters=["beta"], objects=["shop"]),
        )
        self.assertEqual(response.status_code, 400)

    def test_a_taken_name_is_refused_and_the_form_is_drawn_again(self) -> None:
        with mock.patch("haprion_ui.db.create_api_token", side_effect=db.TokenNameTaken("x")):
            response = self.post(self.admin(), "/settings/api-tokens/new", **self.fill())

        self.assertEqual(response.status_code, 409)
        self.assertIn("A token named monitoring already exists.", response.text)
        self.assertIn('value="monitoring"', response.text)
        self.assertEqual(self.audit_details, [])

    def test_a_post_with_another_session_s_token_does_nothing(self) -> None:
        client = self.admin()
        response = client.post(
            "/settings/api-tokens/new",
            data={auth.CSRF_FIELD: auth.csrf_token(auth.new_session_token()), **self.fill()},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.made, [])


class RevokingAndRemoving(TokensPage):
    def test_revoke_asks_first_and_then_ends_the_token(self) -> None:
        self.tokens = [a_token(name="monitoring", level="read")]
        client = self.admin()

        question = client.get("/settings/api-tokens/monitoring/revoke")
        self.assertEqual(question.status_code, 200)
        self.assertIn('action="/settings/api-tokens/monitoring/revoke"', question.text)
        self.assertEqual(self.revoked, [])

        response = self.post(client, "/settings/api-tokens/monitoring/revoke")

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/settings/api-tokens")
        self.assertEqual(self.revoked, ["monitoring"])
        ((action, detail),) = self.audit_details
        self.assertEqual(
            (action, detail["name"], detail["level"]), ("api_token_revoked", "monitoring", "read")
        )

    def test_an_unknown_or_revoked_token_is_not_revoked_again(self) -> None:
        self.tokens = [a_token(name="old", revoked_at=NOW, revoked_by="admin")]
        client = self.admin()

        self.assertEqual(client.get("/settings/api-tokens/nobody/revoke").status_code, 404)
        self.assertEqual(self.post(client, "/settings/api-tokens/nobody/revoke").status_code, 404)
        again = self.post(client, "/settings/api-tokens/old/revoke")
        self.assertEqual(again.status_code, 409)
        self.assertIn("old is already revoked.", again.text)
        self.assertEqual((self.revoked, self.audit_details), ([], []))

    def test_a_revoked_token_is_removed_with_its_audit_event(self) -> None:
        self.tokens = [a_token(name="old", revoked_at=NOW, revoked_by="admin")]
        response = self.post(self.admin(), "/settings/api-tokens/old/remove")

        self.assertEqual(response.status_code, 303)
        self.assertEqual(self.deleted, ["old"])
        self.assertEqual([action for action, _ in self.audit_details], ["api_token_removed"])

    def test_a_token_in_use_is_not_removed(self) -> None:
        self.tokens = [a_token(name="live")]
        with mock.patch("haprion_ui.db.delete_api_token", side_effect=db.TokenInUse("live")):
            response = self.post(self.admin(), "/settings/api-tokens/live/remove")

        self.assertEqual(response.status_code, 409)
        self.assertIn("live is still in use; revoke it first.", response.text)
        self.assertEqual(self.audit_details, [])

    def test_a_post_with_another_session_s_token_does_nothing(self) -> None:
        self.tokens = [a_token(name="monitoring")]
        client = self.admin()
        other = auth.csrf_token(auth.new_session_token())
        for action in ("revoke", "remove"):
            response = client.post(
                f"/settings/api-tokens/monitoring/{action}",
                data={auth.CSRF_FIELD: other},
                follow_redirects=False,
            )
            self.assertEqual(response.status_code, 403)
        self.assertEqual((self.revoked, self.deleted), ([], []))


class NeedsAttention(TokensPage):
    def test_a_token_ending_soon_or_ended_is_a_row_and_a_revoked_one_is_not(self) -> None:
        rows = [
            a_token(name="fine", expires_at=NOW + timedelta(days=200)),
            a_token(name="soon", expires_at=NOW + timedelta(days=12, hours=1)),
            a_token(name="today", expires_at=NOW + timedelta(hours=5)),
            a_token(name="ended", expires_at=NOW - timedelta(days=2)),
            a_token(
                name="revoked",
                expires_at=NOW - timedelta(days=2),
                revoked_at=NOW,
                revoked_by="admin",
            ),
        ]
        items = attention.from_api_tokens(rows, now=NOW)

        self.assertEqual(
            [(item.subject, item.message, item.variant) for item in items],
            [
                ("ended", f"expired {items[0].message.split()[-1]}", "ended"),
                ("soon", "expires in 12 days", "ending"),
                ("today", "expires within a day", "ending"),
            ],
        )
        self.assertTrue(all(item.link == "/settings/api-tokens" for item in items))
        self.assertTrue(all(item.page == "Settings" and item.needs_writes for item in items))
        # An acknowledged warning does not hide the day the token stops working.
        self.assertNotEqual(
            attention.from_api_tokens(
                [a_token(name="x", expires_at=NOW + timedelta(days=1))], now=NOW
            )[0].key,
            attention.from_api_tokens(
                [a_token(name="x", expires_at=NOW - timedelta(days=1))], now=NOW
            )[0].key,
        )

    def test_the_dashboard_lists_it_and_leads_to_the_page(self) -> None:
        self.tokens = [a_token(name="soon", expires_at=NOW + timedelta(days=5, hours=1))]
        page = self.admin().get("/").text

        self.assertIn("soon · expires in 5 days", page)
        self.assertIn('href="/settings/api-tokens"', page)
