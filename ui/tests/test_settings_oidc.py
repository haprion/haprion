"""Settings -> Users -> OIDC configuration (Fas 13 part 4, O4; B197-B199).

Held here: admin only, behind the tab's gate; the secret is sealed in the
request that typed it and never drawn again; a changed issuer or client needs
the secret typed again; Verify goes through the helper and records the
revision it passed; saving while sign-in through the provider is on verifies
first and saves as verified; turning on is the database's to refuse, as a
sentence; each change is audited without the secret.
"""

from __future__ import annotations

import tempfile
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest import mock

from fastapi.testclient import TestClient
from haproxy_mgmt import oidc
from haproxy_mgmt.dns_profile_keys import read_private_key, write_key_pair

from haproxy_ui import auth, db, oidc_web
from tests.test_login import LoginTestCase, configuration

ISSUER = "https://id.example.com/application/o/manager/"


def provider(**fields: Any) -> db.OidcProvider:
    values: dict[str, Any] = {
        "enabled": False,
        "issuer": None,
        "client_id": None,
        "client_secret_sealed": None,
        "key_id": None,
        "auth_method": "client_secret_basic",
        "scopes": "openid profile email",
        "username_claim": "preferred_username",
        "groups_claim": "groups",
        "admin_group": None,
        "reader_group": None,
        "auto_create": True,
        "button_text": "Sign in with SSO",
        "prompt_login": False,
        "logout_mode": "app",
        "local_login": "break_glass_only",
        "ca_pem": None,
        "revision": 0,
        "verified_revision": None,
        "updated_at": datetime(2026, 9, 27, tzinfo=UTC),
        "updated_by": None,
    }
    values.update(fields)
    return db.OidcProvider(**values)


FORM = {
    "issuer": ISSUER,
    "client_id": "haproxy-manager",
    "client_secret": "a secret typed once",
    "auth_method": "client_secret_basic",
    "scopes": "openid profile email",
    "username_claim": "preferred_username",
    "groups_claim": "groups",
    "admin_group": "haproxy-admins",
    "reader_group": "",
    "button_text": "Sign in with authentik",
    "logout_mode": "app",
    "local_login": "break_glass_only",
    "auto_create": "on",
}


class SettingsOidc(LoginTestCase):
    def setUp(self) -> None:
        super().setUp()
        keys = Path(tempfile.mkdtemp(prefix="oidc-web-keys-"))
        self.public = write_key_pair(keys / "k.key", keys / "k.pub")
        self.private = read_private_key(keys / "k.key", require_secure=False)
        self.public_path = keys / "k.pub"
        self.provider = provider()
        self.saved: list[dict[str, Any]] = []
        self.audit_details: list[tuple[str, dict[str, Any]]] = []
        self.answer: Any = {
            "ok": True,
            "checks": [{"name": "discovery", "ok": True, "message": "fine"}],
        }

        def save(
            _c: object, *, settings: dict[str, Any], actor: str, verified: bool = False
        ) -> None:
            self.saved.append({**settings, "_verified": verified, "_actor": actor})

        def audit(_c: object, *, action: str, detail: Any = None, **_: Any) -> None:
            self.audit.append(action)
            self.audit_details.append((action, dict(detail or {})))

        def ask(action: str, current: db.OidcProvider, **_: Any) -> Any:
            if isinstance(self.answer, Exception):
                raise self.answer
            self.asked = (action, current)
            return self.answer

        for patch in (
            mock.patch("haproxy_ui.db.save_oidc_provider", side_effect=save),
            mock.patch("haproxy_ui.db.record_oidc_verified", return_value=True),
            mock.patch("haproxy_ui.db.set_oidc_enabled"),
            mock.patch("haproxy_ui.db.record_audit_event", side_effect=audit),
            mock.patch("haproxy_ui.oidc_web.ask", side_effect=ask),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def admin(self, *, installed: bool = True) -> TestClient:
        settings = replace(
            configuration(),
            management_writes=True,
            oidc_public_key=self.public_path if installed else None,
        )
        client = self.client(settings)
        self.assertEqual(self.sign_in(client).status_code, 303)
        return client

    def post(self, client: TestClient, **fields: str) -> Any:
        token = client.cookies[auth.SESSION_COOKIE]
        data = {auth.CSRF_FIELD: auth.csrf_token(token), **fields}
        return client.post("/settings/oidc", data=data, follow_redirects=False)

    def test_the_users_card_leads_here_and_names_the_provider(self) -> None:
        self.provider = provider(issuer=ISSUER, enabled=True)
        page = self.admin().get("/settings").text
        self.assertIn('href="/settings/oidc">OIDC configuration</a>', page)
        self.assertIn(f"SSO on · {ISSUER}", page)

    def test_a_reader_is_refused(self) -> None:
        self.account = replace(self.account, role="reader")
        client = self.client(replace(configuration(), management_writes=True))
        self.sign_in(client)
        self.assertEqual(client.get("/settings/oidc").status_code, 403)

    def test_the_page_shows_the_redirect_uri_and_never_the_secret(self) -> None:
        self.provider = provider(issuer=ISSUER, client_id="c", client_secret_sealed=b"sealed")
        page = self.admin().get("/settings/oidc").text
        self.assertIn("https://manager.example.com/login/oidc/callback", page)
        self.assertIn("Set — type to replace", page)
        self.assertNotIn("sealed", page)

    def test_without_the_helper_the_page_says_so(self) -> None:
        page = self.admin(installed=False).get("/settings/oidc").text
        self.assertIn("The OIDC helper is not installed here. Run platform step 17.", page)

    def test_save_seals_the_secret_for_the_issuer_and_client(self) -> None:
        response = self.post(self.admin(), action="save", **FORM)

        self.assertEqual(response.status_code, 303, response.text)
        saved = self.saved[-1]
        self.assertEqual(saved["issuer"], ISSUER)
        self.assertEqual(saved["key_id"], self.public.key_id)
        self.assertEqual(
            oidc.open_client_secret(
                self.private,
                saved["client_secret_sealed"],
                issuer=ISSUER,
                client_id="haproxy-manager",
            ),
            "a secret typed once",
        )
        action, detail = self.audit_details[-1]
        self.assertEqual(action, "oidc_configured")
        self.assertTrue(detail["secret_replaced"])
        self.assertNotIn("a secret typed once", repr(self.audit_details))

    def test_a_changed_issuer_needs_the_secret_again(self) -> None:
        self.provider = provider(
            issuer="https://old.example.com/",
            client_id="haproxy-manager",
            client_secret_sealed=b"x",
        )
        response = self.post(self.admin(), action="save", **{**FORM, "client_secret": ""})
        self.assertEqual(response.status_code, 400)
        self.assertIn("Type the client secret", response.text)
        self.assertEqual(self.saved, [])

    def test_the_same_issuer_and_client_keep_the_secret(self) -> None:
        self.provider = provider(
            issuer=ISSUER, client_id="haproxy-manager", client_secret_sealed=b"x"
        )
        self.post(self.admin(), action="save", **{**FORM, "client_secret": ""})
        self.assertNotIn("client_secret_sealed", self.saved[-1])

    def test_mistakes_are_sentences_and_nothing_is_saved(self) -> None:
        client = self.admin()
        for fields, sentence in (
            ({"issuer": "http://id.example.com/"}, "https URL"),
            ({"scopes": "profile email"}, "must include openid"),
            ({"groups_claim": "a b"}, "dotted path"),
            ({"admin_group": "", "reader_group": ""}, "admins, readers or both"),
            ({"ca_pem": "not a certificate"}, "not a PEM certificate"),
        ):
            with self.subTest(fields=fields):
                response = self.post(client, action="save", **{**FORM, **fields})
                self.assertEqual(response.status_code, 400)
                self.assertIn(sentence, response.text)
        self.assertEqual(self.saved, [])

    def test_while_on_a_save_is_verified_first_and_saved_as_verified(self) -> None:
        self.provider = provider(
            issuer=ISSUER, client_id="haproxy-manager", client_secret_sealed=b"x", enabled=True
        )
        client = self.admin()

        self.post(client, action="save", **FORM)
        self.assertTrue(self.saved[-1]["_verified"])
        self.assertEqual(self.asked[0], "verify")
        self.assertEqual(self.asked[1].button_text, "Sign in with authentik")

        self.answer = {
            "ok": False,
            "checks": [{"name": "client", "ok": False, "message": "refused"}],
        }
        response = self.post(client, action="save", **{**FORM, "button_text": "Other"})
        self.assertEqual(response.status_code, 400)
        self.assertIn("did not pass Verify", response.text)
        self.assertEqual(len(self.saved), 1)

    def test_verify_shows_each_check_and_records_the_revision(self) -> None:
        self.provider = provider(
            issuer=ISSUER, client_id="c", client_secret_sealed=b"x", revision=4
        )
        response = self.post(self.admin(), action="verify")

        self.assertEqual(response.status_code, 200)
        self.assertIn("Verified.", response.text)
        db.record_oidc_verified.assert_called_once()  # type: ignore[attr-defined]
        self.assertEqual(db.record_oidc_verified.call_args.kwargs, {"revision": 4})  # type: ignore[attr-defined]
        self.assertEqual(self.audit_details[-1][1]["ok"], True)

    def test_a_failed_verify_records_nothing_and_says_which_check(self) -> None:
        self.provider = provider(issuer=ISSUER, client_id="c", client_secret_sealed=b"x")
        self.answer = {
            "ok": False,
            "checks": [
                {"name": "client", "ok": False, "message": "the provider refused the client"}
            ],
        }
        response = self.post(self.admin(), action="verify")
        self.assertEqual(response.status_code, 409)
        self.assertIn("the provider refused the client", response.text)
        db.record_oidc_verified.assert_not_called()  # type: ignore[attr-defined]

    def test_an_absent_helper_is_a_sentence(self) -> None:
        self.provider = provider(issuer=ISSUER, client_id="c", client_secret_sealed=b"x")
        self.answer = oidc_web.OidcUnavailable("The OIDC helper is not installed here.")
        response = self.post(self.admin(), action="verify")
        self.assertEqual(response.status_code, 409)
        self.assertIn("The OIDC helper is not installed here.", response.text)

    def test_turning_on_is_the_database_s_to_refuse(self) -> None:
        self.provider = provider(issuer=ISSUER)
        client = self.admin()
        with mock.patch(
            "haproxy_ui.db.set_oidc_enabled",
            side_effect=db.ProviderRefused("Verify the settings first."),
        ):
            response = self.post(client, action="on")
        self.assertEqual(response.status_code, 409)
        self.assertIn("Verify the settings first.", response.text)

        response = self.post(client, action="on")
        self.assertEqual(response.headers["location"], "/settings/oidc?done=on")
        self.assertEqual(self.audit[-1], "oidc_enabled")
