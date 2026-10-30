"""`haprion-user list`, `haprion-settings show` and `haprion-profiles list` answer in the contract.

They wrote a bare JSON object with no envelope, no operation and nothing on a
refusal, so a script reading `--json` got another shape than every other
command (review 26-10-30, E12, B409). Each answers with the engine's envelope
and holds `schemas/v1`, on a refusal too.
"""

from __future__ import annotations

import contextlib
import dataclasses
import io
import json
import unittest
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any
from unittest import mock

from haprion import exit_codes

from haprion_ui import admin, config, db, profile_apply, settings_tool
from tests.contract_schema import assert_contract

NOW = datetime(2026, 10, 30, tzinfo=UTC)


def run(main: Any, argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


class AsRoot(unittest.TestCase):
    def setUp(self) -> None:
        for patch in (
            mock.patch("os.geteuid", return_value=0),
            mock.patch.object(admin, "load_environment"),
            mock.patch.object(admin, "connect", return_value=contextlib.nullcontext()),
            mock.patch.object(settings_tool, "connect", return_value=contextlib.nullcontext()),
            mock.patch.object(profile_apply, "connect", return_value=contextlib.nullcontext()),
            mock.patch.object(settings_tool, "load_environment"),
            mock.patch.object(profile_apply, "load_environment"),
        ):
            patch.start()
            self.addCleanup(patch.stop)


class TheUserList(AsRoot):
    def test_it_answers_in_the_contract(self) -> None:
        rows = [
            db.AccountRow(1, "admin", "admin", False, 2, NOW, False, "local", True),
            db.AccountRow(2, "carol", "reader", True, 0, None, False, "oidc", False),
        ]
        with (
            mock.patch.object(db, "account_rows", return_value=rows),
            mock.patch.object(admin, "sign_in_throttle", return_value=config.Throttle(10, 15)),
            mock.patch.object(admin, "connect") as connect,
        ):
            connect.return_value.__enter__.return_value.cursor.return_value.__enter__.return_value = mock.Mock(
                fetchall=lambda: [("admin", NOW.date())]
            )
            code, out, _ = run(admin.main, ["list", "--json"])

        self.assertEqual(code, 0)
        answer = assert_contract("haprion-user-list", out)
        self.assertEqual(
            [(a["username"], a["kind"]) for a in answer["result"]["accounts"]],
            [("admin", "break-glass"), ("carol", "sso")],
        )

    def test_a_refusal_is_a_document_too(self) -> None:
        with mock.patch("os.geteuid", return_value=1000):
            code, out, _ = run(admin.main, ["list", "--json"])

        self.assertEqual(code, exit_codes.NOT_ROOT)
        self.assertEqual(assert_contract("haprion-user-list", out)["error"]["code"], "not_root")


class TheSettingsShow(AsRoot):
    def test_it_answers_in_the_contract(self) -> None:
        provider = SimpleNamespace(
            enabled=False,
            verified=False,
            client_secret_sealed=None,
            issuer=None,
            client_id=None,
            auth_method="client_secret_basic",
            scopes="openid",
            username_claim="email",
            groups_claim="groups",
            admin_group=None,
            reader_group=None,
            button_text="Sign in",
            prompt_login=False,
            logout_mode="local",
            local_login="always",
            ca_pem=None,
        )
        switch = SimpleNamespace(enabled=True)
        with (
            mock.patch.object(
                db, "status_access", return_value=[SimpleNamespace(network="192.0.2.10/32")]
            ),
            mock.patch.object(db, "feature_switches", return_value={"waf_engine": switch}),
            mock.patch.object(db, "oidc_provider", return_value=provider),
        ):
            code, out, _ = run(settings_tool.main, ["show", "--json"])

        self.assertEqual(code, 0)
        answer = assert_contract("haprion-settings-show", out)
        self.assertEqual(answer["result"]["features"], {"waf_engine": True})
        self.assertEqual(answer["result"]["status_access"], ["192.0.2.10/32"])

    def test_a_refusal_is_a_document_too(self) -> None:
        with mock.patch("os.geteuid", return_value=1000):
            code, out, _ = run(settings_tool.main, ["show", "--json"])

        self.assertEqual(code, exit_codes.NOT_ROOT)
        self.assertEqual(assert_contract("haprion-settings-show", out)["error"]["code"], "not_root")


class TheProfilesList(AsRoot):
    def test_it_answers_in_the_contract(self) -> None:
        def row(identifier: str, provider: str, **fields: Any) -> Any:
            return SimpleNamespace(id=identifier, provider_id=provider, revision=2, **fields)

        kinds = (
            dataclasses.replace(
                profile_apply.DNS, listed=lambda _c: [row("cf-main", "cloudflare")]
            ),
            dataclasses.replace(
                profile_apply.NDES,
                listed=lambda _c: [row("corp-ca", "ndes", endpoint="https://ndes.example.com/")],
            ),
        )
        with mock.patch.object(profile_apply, "KINDS", kinds):
            code, out, _ = run(profile_apply.main, ["list", "--json"])

        self.assertEqual(code, 0)
        answer = assert_contract("haprion-profiles-list", out)
        self.assertEqual(answer["result"]["ndes"][0]["endpoint"], "https://ndes.example.com/")

    def test_a_refusal_is_a_document_too(self) -> None:
        with mock.patch("os.geteuid", return_value=1000):
            code, out, _ = run(profile_apply.main, ["list", "--json"])

        self.assertEqual(code, exit_codes.NOT_ROOT)
        self.assertEqual(assert_contract("haprion-profiles-list", out)["error"]["code"], "not_root")

    def test_the_text_listing_is_unchanged(self) -> None:
        row: Any = SimpleNamespace(id="cf-main", provider_id="cloudflare", revision=2)
        kinds = (
            dataclasses.replace(profile_apply.DNS, listed=lambda _c: [row]),
            dataclasses.replace(profile_apply.NDES, listed=lambda _c: []),
        )
        with mock.patch.object(profile_apply, "KINDS", kinds):
            code, out, _ = run(profile_apply.main, ["list"])

        self.assertEqual(code, 0)
        self.assertIn("cf-main", out)
        self.assertRaises(json.JSONDecodeError, json.loads, out)


if __name__ == "__main__":
    unittest.main()
