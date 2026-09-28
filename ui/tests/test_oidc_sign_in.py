"""Signing in through the provider, and out again (Fas 13 part 4, O5; B195-B199).

Held here: the button appears only while sign-in through the provider is on;
while it is on a password signs in a break-glass account only, refused exactly
as a wrong password is; a sign-in is bound to the browser that started it and
used once; the role comes from the groups at every sign-in, and neither group
is a refusal; an account is found by the provider identity, created when the
installation says so, bound once when an admin prepared it, and never taken
over by name; Test sign-in makes no session; signing out at the provider when
chosen; an account the provider owns has no password to change here.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any
from unittest import mock
from urllib.parse import parse_qs, urlsplit

from fastapi.testclient import TestClient

from haproxy_ui import auth, db, oidc_web
from haproxy_ui.db import Account
from haproxy_ui.views import SIGN_IN_FAILED
from tests.test_login import PASSWORD, LoginTestCase, configuration
from tests.test_settings_oidc import ISSUER, provider

DISCOVERED = {
    "issuer": ISSUER,
    "authorization_endpoint": "https://id.example.com/application/o/authorize/",
    "token_endpoint": "https://id.example.com/application/o/token/",
    "jwks_uri": "https://id.example.com/application/o/manager/jwks/",
    "userinfo_endpoint": None,
    "end_session_endpoint": "https://id.example.com/application/o/manager/end-session/",
    "auth_methods": ["client_secret_basic"],
    "algorithms": ["RS256"],
}


class SigningInThroughTheProvider(LoginTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.account = replace(self.account, break_glass=True)
        self.provider = provider(
            enabled=True,
            issuer=ISSUER,
            client_id="haproxy-manager",
            client_secret_sealed=b"x",
            key_id="0123456789abcdef",
            admin_group="haproxy-admins",
            reader_group="haproxy-readers",
            button_text="Sign in with authentik",
            revision=2,
            verified_revision=2,
        )
        self.started: list[dict[str, Any]] = []
        self.pending: dict[str, db.OidcLogin] = {}
        self.exchanged: dict[str, Any] = {
            "issuer": ISSUER,
            "subject": "sub-1",
            "username": "alice",
            "groups": ["haproxy-admins"],
            "id_token": "header.payload.signature",
            "userinfo": "userinfo used",
        }
        self.by_identity: dict[tuple[str, str], Account] = {}
        self.created: list[dict[str, Any]] = []
        self.bound: list[dict[str, Any]] = []
        self.roles: list[tuple[int, str]] = []
        self.audit_details: list[tuple[str, dict[str, Any]]] = []

        def start(_c: object, **fields: Any) -> None:
            self.started.append(fields)
            self.pending[fields["state"]] = db.OidcLogin(
                nonce=fields["nonce"],
                verifier=fields["verifier"],
                mode=fields["mode"],
                pre_session_hash=fields["pre_session_hash"],
            )

        def use(_c: object, *, state: str, **_: Any) -> db.OidcLogin | None:
            return self.pending.pop(state, None)

        def ask(action: str, _provider: db.OidcProvider, **fields: Any) -> dict[str, Any]:
            self.asked = (action, fields)
            return DISCOVERED if action == "discover" else self.exchanged

        def create(_c: object, **fields: Any) -> bool:
            self.created.append(fields)
            account = Account(
                id=7,
                username=fields["username"],
                role=fields["role"],
                disabled=False,
                password_hash=None,
                source="oidc",
                oidc_issuer=fields["issuer"],
            )
            self.by_identity[(fields["issuer"], fields["subject"])] = account
            self.account = account
            return True

        def audit(_c: object, *, action: str, detail: Any = None, **_: Any) -> None:
            self.audit.append(action)
            self.audit_details.append((action, dict(detail or {})))

        for patch in (
            mock.patch("haproxy_ui.db.start_oidc_login", side_effect=start),
            mock.patch("haproxy_ui.db.use_oidc_login", side_effect=use),
            mock.patch("haproxy_ui.oidc_web.ask", side_effect=ask),
            mock.patch(
                "haproxy_ui.db.account_by_oidc",
                side_effect=lambda _c, *, issuer, subject: self.by_identity.get((issuer, subject)),
            ),
            mock.patch("haproxy_ui.db.create_oidc_account", side_effect=create),
            mock.patch(
                "haproxy_ui.db.bind_oidc_account",
                side_effect=lambda _c, **fields: self.bound.append(fields) or True,
            ),
            mock.patch(
                "haproxy_ui.db.set_role",
                side_effect=lambda _c, *, user_id, role: self.roles.append((user_id, role)),
            ),
            mock.patch("haproxy_ui.db.record_audit_event", side_effect=audit),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def go(self, client: TestClient) -> str:
        """Press the button; answer the state the provider was sent."""

        client.get("/login")
        response = client.get("/login/oidc", follow_redirects=False)
        self.assertEqual(response.status_code, 303, response.text)
        query = parse_qs(urlsplit(response.headers["location"]).query)
        return query["state"][0]

    def back(self, client: TestClient, state: str, **extra: str) -> Any:
        return client.get(
            "/login/oidc/callback",
            params={"state": state, "code": "code-1", **extra},
            follow_redirects=False,
        )

    # - the page ------------------------------------------------------------

    def test_the_button_is_there_only_while_it_is_on(self) -> None:
        client = self.client()
        self.assertIn('href="/login/oidc">Sign in with authentik</a>', client.get("/login").text)
        self.provider = replace(self.provider, enabled=False)
        self.assertNotIn("/login/oidc", client.get("/login").text)

    def test_while_on_a_password_signs_in_a_break_glass_account_only(self) -> None:
        self.account = replace(self.account, break_glass=False)
        response = self.sign_in(self.client())
        self.assertEqual(response.status_code, 401)
        self.assertEqual(self.attempts[-1][2], False)

        self.provider = replace(self.provider, local_login="all")
        self.assertEqual(self.sign_in(self.client()).status_code, 303)

        self.provider = replace(self.provider, local_login="break_glass_only")
        self.account = replace(self.account, break_glass=True)
        self.assertEqual(self.sign_in(self.client()).status_code, 303)

    def test_held_back_reads_exactly_as_a_wrong_password(self) -> None:
        self.account = replace(self.account, break_glass=False)
        held = self.sign_in(self.client())
        wrong = self.sign_in(self.client(), password="not the password")
        self.assertEqual((held.status_code, wrong.status_code), (401, 401))
        self.assertIn(SIGN_IN_FAILED, held.text)
        self.assertIn(SIGN_IN_FAILED, wrong.text)

    # - the round trip ------------------------------------------------------

    def test_the_button_sends_the_browser_with_pkce_state_and_nonce(self) -> None:
        client = self.client()
        client.get("/login")
        response = client.get("/login/oidc", follow_redirects=False)
        location = urlsplit(response.headers["location"])
        query = parse_qs(location.query)

        self.assertEqual(location.path, "/application/o/authorize/")
        self.assertEqual(query["code_challenge_method"], ["S256"])
        self.assertEqual(query["redirect_uri"], ["https://manager.example.com/login/oidc/callback"])
        started = self.started[-1]
        self.assertEqual(query["state"], [started["state"]])
        self.assertEqual(query["nonce"], [started["nonce"]])
        self.assertEqual(started["mode"], "sign_in")
        self.assertEqual(
            started["pre_session_hash"], auth.token_hash(client.cookies[auth.PRE_SESSION_COOKIE])
        )

    def test_the_button_never_sends_the_browsers_own_cookie_back(self) -> None:
        client = self.client()
        client.cookies.set(auth.PRE_SESSION_COOKIE, "planted", path="/login")
        response = client.get("/login/oidc", follow_redirects=False)

        self.assertEqual(response.status_code, 303)
        self.assertNotIn("planted", response.headers["set-cookie"])
        self.assertNotEqual(self.started[-1]["pre_session_hash"], auth.token_hash("planted"))

    def test_a_first_sign_in_creates_the_account_and_a_session(self) -> None:
        client = self.client()
        response = self.back(client, self.go(client))

        self.assertEqual(response.status_code, 303, response.text)
        self.assertEqual(response.headers["location"], "/")
        self.assertEqual(
            self.created[-1],
            {"username": "alice", "role": "admin", "issuer": ISSUER, "subject": "sub-1"},
        )
        self.assertEqual(len(self.sessions), 1)
        self.assertIsNone(next(iter(self.id_tokens.values())))
        action, detail = self.audit_details[-1]
        self.assertEqual((action, detail["via"], detail["role"]), ("login", "oidc", "admin"))
        self.assertEqual((self.attempts[-1][0], self.attempts[-1][2]), ("alice", True))

    def test_the_answer_must_come_back_to_the_browser_that_asked(self) -> None:
        state = self.go(self.client())
        other = self.client()
        other.get("/login")
        response = self.back(other, state)
        self.assertEqual(response.status_code, 401)
        self.assertIn("started in another browser", response.text)
        self.assertEqual(self.sessions, {})

    def test_a_state_is_used_once(self) -> None:
        client = self.client()
        state = self.go(client)
        self.back(client, state)
        client.cookies.clear()
        client.get("/login")
        again = self.back(client, state)
        self.assertEqual(again.status_code, 401)
        self.assertIn("expired or was already used", again.text)

    def test_the_provider_s_no_is_its_own_sentence(self) -> None:
        client = self.client()
        response = self.back(
            client, self.go(client), error="access_denied", error_description="User denied"
        )
        self.assertEqual(response.status_code, 401)
        self.assertIn("The provider did not sign you in: User denied", response.text)

    def test_neither_group_is_a_refusal(self) -> None:
        self.exchanged["groups"] = ["somebody-else"]
        client = self.client()
        response = self.back(client, self.go(client))
        self.assertEqual(response.status_code, 401)
        self.assertIn("neither group", response.text)
        self.assertEqual(self.created, [])
        self.assertEqual(self.audit_details[-1][1]["reason"], "no_group")

    def test_a_reader_group_gives_reader(self) -> None:
        self.exchanged["groups"] = ["haproxy-readers"]
        client = self.client()
        self.back(client, self.go(client))
        self.assertEqual(self.created[-1]["role"], "reader")

    def test_a_local_account_of_the_same_name_is_never_taken_over(self) -> None:
        self.exchanged["username"] = "operator"
        client = self.client()
        response = self.back(client, self.go(client))
        self.assertEqual(response.status_code, 401)
        self.assertIn("An account named operator already exists here.", response.text)
        self.assertEqual((self.created, self.bound), ([], []))

    def test_a_prepared_provider_account_is_bound_once(self) -> None:
        prepared = Account(
            id=5, username="alice", role="reader", disabled=False, password_hash=None, source="oidc"
        )

        def named(_c: object, username: str) -> Account | None:
            return prepared if username == "alice" else None

        def bind(_c: object, **fields: Any) -> bool:
            self.bound.append(fields)
            self.by_identity[(ISSUER, "sub-1")] = replace(prepared, oidc_issuer=ISSUER)
            self.account = self.by_identity[(ISSUER, "sub-1")]
            return True

        with (
            mock.patch("haproxy_ui.db.account_by_username", side_effect=named),
            mock.patch("haproxy_ui.db.bind_oidc_account", side_effect=bind),
        ):
            client = self.client()
            response = self.back(client, self.go(client))

        self.assertEqual(response.status_code, 303, response.text)
        self.assertEqual(self.bound[-1], {"user_id": 5, "issuer": ISSUER, "subject": "sub-1"})
        self.assertEqual(self.roles, [(5, "admin")])

    def test_without_auto_create_an_unknown_name_is_refused(self) -> None:
        self.provider = replace(self.provider, auto_create=False)
        client = self.client()
        response = self.back(client, self.go(client))
        self.assertEqual(response.status_code, 401)
        self.assertIn("There is no account here for alice.", response.text)

    def test_the_role_follows_the_groups_at_every_sign_in(self) -> None:
        self.by_identity[(ISSUER, "sub-1")] = Account(
            id=9, username="alice", role="admin", disabled=False, password_hash=None, source="oidc"
        )
        self.account = self.by_identity[(ISSUER, "sub-1")]
        self.exchanged["groups"] = ["haproxy-readers"]
        client = self.client()
        self.back(client, self.go(client))
        self.assertEqual(self.roles, [(9, "reader")])
        self.assertIn("role_changed", self.audit)

    def test_a_disabled_account_is_refused(self) -> None:
        self.by_identity[(ISSUER, "sub-1")] = Account(
            id=9, username="alice", role="admin", disabled=True, password_hash=None, source="oidc"
        )
        client = self.client()
        response = self.back(client, self.go(client))
        self.assertEqual(response.status_code, 401)
        self.assertEqual(self.sessions, {})

    # - out again -----------------------------------------------------------

    def test_provider_sign_out_sends_the_browser_to_the_provider(self) -> None:
        self.provider = replace(self.provider, logout_mode="provider")
        client = self.client()
        self.back(client, self.go(client))
        self.assertEqual(next(iter(self.id_tokens.values())), "header.payload.signature")

        token = client.cookies[auth.SESSION_COOKIE]
        response = client.post(
            "/logout", data={auth.CSRF_FIELD: auth.csrf_token(token)}, follow_redirects=False
        )
        location = urlsplit(response.headers["location"])
        query = parse_qs(location.query)
        self.assertEqual(location.path, "/application/o/manager/end-session/")
        self.assertEqual(query["id_token_hint"], ["header.payload.signature"])
        self.assertEqual(query["post_logout_redirect_uri"], ["https://manager.example.com/login"])
        self.assertEqual(self.sessions, {})

    def test_app_sign_out_stays_here(self) -> None:
        client = self.client()
        self.back(client, self.go(client))
        token = client.cookies[auth.SESSION_COOKIE]
        response = client.post(
            "/logout", data={auth.CSRF_FIELD: auth.csrf_token(token)}, follow_redirects=False
        )
        self.assertEqual(response.headers["location"], "/login")

    def test_a_provider_account_has_no_password_to_change(self) -> None:
        client = self.client()
        self.back(client, self.go(client))
        page = client.get("/").text
        self.assertNotIn('href="/account/password"', page)
        self.assertEqual(client.get("/account/password").status_code, 404)

    def test_an_unreachable_provider_is_a_sentence_on_the_login_page(self) -> None:
        client = self.client()
        with mock.patch(
            "haproxy_ui.oidc_web.ask",
            side_effect=oidc_web.OidcUnavailable("The OIDC helper is not installed here."),
        ):
            response = client.get("/login/oidc", follow_redirects=False)

        self.assertIn(
            "Sign-in through the provider is not available: The OIDC helper is not installed here.",
            response.text,
        )
        self.assertEqual(self.started, [])

    # - Test sign-in --------------------------------------------------------

    def test_test_sign_in_against_an_unreachable_provider_is_a_sentence(self) -> None:
        client = self.client(replace(configuration(), management_writes=True))
        self.sign_in(client, password=PASSWORD)
        token = client.cookies[auth.SESSION_COOKIE]
        with mock.patch(
            "haproxy_ui.oidc_web.ask",
            side_effect=oidc_web.OidcRefused("bad_input", "No issuer is set."),
        ):
            response = client.post(
                "/settings/oidc",
                data={auth.CSRF_FIELD: auth.csrf_token(token), "action": "test"},
                follow_redirects=False,
            )

        self.assertEqual(response.status_code, 409)
        self.assertIn(
            "Sign-in through the provider is not available: No issuer is set.", response.text
        )
        self.assertEqual(self.started, [])

    def test_test_sign_in_shows_what_came_back_and_makes_no_session(self) -> None:
        self.exchanged["claims"] = {"sub": "sub-1", "groups": ["haproxy-admins"]}
        client = self.client(replace(configuration(), management_writes=True))
        self.sign_in(client, password=PASSWORD)
        token = client.cookies[auth.SESSION_COOKIE]
        started = client.post(
            "/settings/oidc",
            data={auth.CSRF_FIELD: auth.csrf_token(token), "action": "test"},
            follow_redirects=False,
        )
        self.assertEqual(started.status_code, 303, started.text)
        self.assertEqual(self.started[-1]["mode"], "test")
        self.assertEqual(self.started[-1]["pre_session_hash"], auth.token_hash(token))
        state = parse_qs(urlsplit(started.headers["location"]).query)["state"][0]
        sessions_before = dict(self.sessions)

        page = self.back(client, state)
        self.assertEqual(page.status_code, 200, page.text)
        self.assertIn("alice would sign in as admin.", page.text)
        self.assertIn("&#34;groups&#34;", page.text)
        self.assertEqual(self.asked[1]["claims"], True)
        self.assertEqual(self.sessions, sessions_before)
        self.assertEqual(self.created, [])

    def test_test_sign_in_says_so_when_a_local_account_holds_the_name(self) -> None:
        # The real sign-in refuses this name (above); the test said "would sign
        # in as admin" for it until 2026-09-28.
        self.exchanged["username"] = "operator"
        client = self.client(replace(configuration(), management_writes=True))
        self.sign_in(client, password=PASSWORD)
        token = client.cookies[auth.SESSION_COOKIE]
        started = client.post(
            "/settings/oidc",
            data={auth.CSRF_FIELD: auth.csrf_token(token), "action": "test"},
            follow_redirects=False,
        )
        state = parse_qs(urlsplit(started.headers["location"]).query)["state"][0]

        page = self.back(client, state)
        self.assertEqual(page.status_code, 200, page.text)
        self.assertIn(
            "operator would be refused: An account named operator already exists here.",
            page.text,
        )
        self.assertNotIn("would sign in as", page.text)
        self.assertEqual((self.created, self.bound), ([], []))

    def test_a_prepared_account_can_be_added_without_a_password(self) -> None:
        client = self.client(replace(configuration(), management_writes=True))
        self.sign_in(client, password=PASSWORD)
        token = client.cookies[auth.SESSION_COOKIE]
        self.assertIn('name="provider_account"', client.get("/settings/new-user").text)
        response = client.post(
            "/settings/new-user",
            data={
                auth.CSRF_FIELD: auth.csrf_token(token),
                "username": "bob",
                "role": "reader",
                "provider_account": "on",
            },
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303, response.text)
        self.assertEqual(
            self.created[-1], {"username": "bob", "role": "reader", "issuer": None, "subject": None}
        )
