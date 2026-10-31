"""`haprion-api-token` (B416): the same rules and words as Settings -> API tokens, in the contract."""

from __future__ import annotations

import contextlib
import html
import io
import json
import os
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from unittest import mock

from haprion import exit_codes

from haprion_ui import api_token_tool, api_tokens, config, db
from tests.contract_schema import assert_contract
from tests.test_api import a_token
from tests.test_api_tokens_page import TokensPage
from tests.test_login import configuration

NOW = datetime.now(UTC)


def run(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = api_token_tool.main(argv)
    return code, out.getvalue(), err.getvalue()


class AsRoot(TokensPage):
    """The page's fake table, read and written by the command instead."""

    def setUp(self) -> None:
        super().setUp()
        self.connection = mock.MagicMock()
        for patch in (
            mock.patch("os.geteuid", return_value=0),
            mock.patch.dict(os.environ, {"SUDO_USER": "ops"}),
            mock.patch.object(api_token_tool, "load_environment"),
            mock.patch.object(api_token_tool, "connect", return_value=self.connection),
            mock.patch.object(
                config, "load", return_value=replace(configuration(), clusters=("alpha", "beta"))
            ),
            mock.patch("haprion_ui.db.cluster_list", return_value=None),
            mock.patch("haprion_ui.db.cluster_objects", return_value=[]),
        ):
            patch.start()
            self.addCleanup(patch.stop)
        self.connection.__enter__.return_value = self.connection


class Adding(AsRoot):
    def test_the_secret_is_the_only_thing_on_standard_output(self) -> None:
        code, out, err = run(
            [
                "add",
                "docker1-fail2ban",
                "--level",
                "block",
                "--cluster",
                "alpha",
                "--object",
                "shop",
                "--source",
                "192.0.2.0/24",
                "--days",
                "90",
            ]
        )

        self.assertEqual(code, 0, err)
        secret = out.strip()
        self.assertRegex(secret, api_tokens.SECRET_SHAPE.pattern)
        self.assertNotIn(secret, err)
        (values,) = self.made
        self.assertEqual(values["token_hash"], api_tokens.secret_hash(secret))
        self.assertEqual((values["created_by"], values["days"]), ("ops", 90))
        ((action, detail),) = [e for e in self.audit_details if e[0] != "login"]
        self.assertEqual(
            (action, detail["via"], detail["name"]),
            ("api_token_created", "cli", "docker1-fail2ban"),
        )
        self.assertNotIn(secret, repr(self.audit_details))
        self.connection.commit.assert_called_once()

    def test_json_carries_the_secret_in_the_contract(self) -> None:
        code, out, _ = run(["add", "monitoring", "--level", "read", "--json"])

        answer = assert_contract("haprion-api-token", out)
        self.assertEqual(code, 0)
        result = answer["result"]
        self.assertEqual((result["action"], result["token"]["name"]), ("add", "monitoring"))
        self.assertTrue(result["secret"].startswith(result["token"]["prefix"]))
        self.assertEqual(self.made[0]["days"], api_tokens.DEFAULT_DAYS)

    def test_a_taken_name_is_refused_with_the_contract_s_code(self) -> None:
        with mock.patch("haprion_ui.db.create_api_token", side_effect=db.TokenNameTaken("x")):
            code, out, _ = run(["add", "monitoring", "--level", "read", "--json"])

        self.assertEqual(code, exit_codes.REFUSED)
        error = assert_contract("haprion-api-token", out)["error"]
        self.assertEqual(error["code"], "already_exists")
        self.assertNotIn("secret", out)

    def test_not_as_root_is_the_contract_s_refusal(self) -> None:
        with mock.patch("os.geteuid", return_value=1000):
            code, out, _ = run(["list", "--json"])

        self.assertEqual(code, exit_codes.NOT_ROOT)
        self.assertEqual(assert_contract("haprion-api-token", out)["error"]["code"], "not_root")


class ListingRevokingRemoving(AsRoot):
    def test_the_list_never_carries_a_secret_or_a_hash(self) -> None:
        self.tokens = [
            a_token(name="monitoring"),
            a_token(name="old", revoked_at=NOW, revoked_by="admin"),
            a_token(name="late", expires_at=NOW - timedelta(days=1)),
        ]
        code, out, _ = run(["list", "--json"])

        self.assertEqual(code, 0)
        listed = assert_contract("haprion-api-token", out)["result"]["tokens"]
        self.assertEqual(
            [(t["name"], t["state"]) for t in listed],
            [("monitoring", "active"), ("old", "revoked"), ("late", "expired")],
        )
        self.assertNotIn("hash", out)

    def test_the_list_as_a_table_and_when_empty(self) -> None:
        code, out, _ = run(["list"])
        self.assertEqual(code, 0)
        self.assertIn("no API tokens", out)
        self.tokens = [a_token(name="monitoring", prefix="hap_Monitor0")]
        _, out, _ = run(["list"])
        self.assertIn("monitoring", out)
        self.assertIn("All", out)
        header, row = out.splitlines()[:2]
        self.assertEqual(header.split()[:3], ["NAME", "PREFIX", "LEVEL"])
        self.assertEqual(row.split()[:3], ["monitoring", "hap_Monitor0", "read"])

    def test_revoke_and_remove_write_what_the_page_writes(self) -> None:
        self.tokens = [a_token(name="monitoring")]
        code, out, _ = run(["revoke", "monitoring", "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(
            assert_contract("haprion-api-token", out)["result"],
            {"action": "revoke", "name": "monitoring"},
        )

        self.tokens = [a_token(name="monitoring", revoked_at=NOW, revoked_by="ops")]
        code, out, _ = run(["remove", "monitoring", "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(assert_contract("haprion-api-token", out)["result"]["action"], "remove")
        self.assertEqual(
            [a for a, _ in self.audit_details if a.startswith("api_token")],
            ["api_token_revoked", "api_token_removed"],
        )

    def test_an_unknown_token_is_not_found_and_an_active_one_is_not_removed(self) -> None:
        code, out, _ = run(["revoke", "nobody", "--json"])
        self.assertEqual(code, exit_codes.NOT_FOUND)
        self.assertEqual(assert_contract("haprion-api-token", out)["error"]["code"], "not_found")

        self.tokens = [a_token(name="live")]
        with mock.patch("haprion_ui.db.delete_api_token", side_effect=db.TokenInUse("live")):
            code, _, err = run(["remove", "live"])
        self.assertEqual(code, exit_codes.REFUSED)
        self.assertIn("live is still in use; revoke it first.", err)


class PageAndCommandRefuseAlike(AsRoot):
    """The same input is refused in the same words, whichever way it comes in."""

    CASES = (
        (["Not Valid", "--level", "read"], {"name": "Not Valid"}),
        (["monitoring", "--level", "read", "--days", "731"], {"days": "731"}),
        (["monitoring", "--level", "read", "--days", "0"], {"days": "0"}),
        (
            ["monitoring", "--level", "read", "--source", "not-an-address"],
            {"sources": "not-an-address"},
        ),
        (
            ["monitoring", "--level", "read", "--source", "192.0.2.5/24"],
            {"sources": "192.0.2.5/24"},
        ),
        (["monitoring", "--level", "read", "--cluster", "gamma"], {"clusters": ["gamma"]}),
        (["monitoring", "--level", "read", "--object", "shop"], {"objects": ["shop"]}),
        (
            ["monitoring", "--level", "block", "--object", "ghost"],
            {"level": "block", "objects": ["ghost"]},
        ),
        (["monitoring", "--level", "block"], {"level": "block", "objects": []}),
    )

    def test_each_case(self) -> None:
        client = self.admin()
        for argv, fields in self.CASES:
            with self.subTest(argv):
                code, _, err = run(["add", *argv])
                self.assertEqual(code, exit_codes.REFUSED)
                message = err.strip().removeprefix("ERROR: ")
                response = self.post(client, "/settings/api-tokens/new", **self.fill(**fields))
                self.assertEqual(response.status_code, 400)
                self.assertIn(message, html.unescape(response.text))
        self.assertEqual(self.made, [])

    def test_a_name_taken_reads_alike(self) -> None:
        with mock.patch("haprion_ui.db.create_api_token", side_effect=db.TokenNameTaken("x")):
            _, _, err = run(["add", "monitoring", "--level", "read"])
            response = self.post(self.admin(), "/settings/api-tokens/new", **self.fill())
        self.assertIn(err.strip().removeprefix("ERROR: "), response.text)

    def test_revoking_and_removing_read_alike(self) -> None:
        self.tokens = [a_token(name="old", revoked_at=NOW, revoked_by="admin")]
        client = self.admin()
        for action in ("revoke", "remove"):
            with self.subTest(action):
                name = "old" if action == "revoke" else "nobody"
                _, _, err = run([action, name])
                response = self.post(client, f"/settings/api-tokens/{name}/{action}")
                self.assertIn(err.strip().removeprefix("ERROR: "), response.text)


class TheContractHoldsTheTool(AsRoot):
    def test_the_help_of_every_verb_offers_json(self) -> None:
        for verb in ("add", "list", "revoke", "remove"):
            with self.subTest(verb), contextlib.suppress(SystemExit):
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    api_token_tool.main([verb, "--help"])
                self.assertIn("--json", out.getvalue())
        self.assertEqual(json.loads(run(["list", "--json"])[1])["operation"], "api_token")
