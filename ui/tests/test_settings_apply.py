"""``haprion-settings apply`` without a database: the file and the answer (Fas 23, B293).

The writes are held against the real schema in `test_database_integration`
(`TheSettingsFromAFile`); this holds what the file may say, and the answer's
shape against the fixture the contract suite validates against
`schemas/v1/haprion-settings-apply`.
"""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from haprion import oidc

from haprion_ui import (
    config,
    db,
    feature_switch,
    oidc_web,
    settings_apply,
    settings_tool,
    tool_answer,
)
from haprion_ui.settings_apply import ApplyError, Outcome

FIXTURE = Path(__file__).resolve().parents[2] / "fixtures/haprion-settings-apply/valid/done.json"


def answered(write: Callable[[], int]) -> tuple[int, dict[str, Any]]:
    """What a tool printed with `--json`, through the engine's envelope (4-9)."""

    with contextlib.redirect_stdout(io.StringIO()) as out:
        code = write()
    return code, json.loads(out.getvalue())


class TheFile(unittest.TestCase):
    def write(self, text: str, mode: int = 0o600) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "settings.yaml"
        path.write_text(text)
        path.chmod(mode)
        return path

    def test_a_good_file_is_read_and_a_section_left_out_is_left_alone(self) -> None:
        wanted = settings_apply.read_file(
            self.write(
                "status_access: [192.0.2.10, 198.51.100.0/24]\nfeatures:\n  waf_engine: false\n"
            )
        )

        self.assertEqual(wanted.status_access, ("192.0.2.10/32", "198.51.100.0/24"))
        self.assertEqual(wanted.features, {"waf_engine": False})
        self.assertIsNone(wanted.oidc)

    def test_an_empty_list_switches_status_off(self) -> None:
        self.assertEqual(
            settings_apply.read_file(self.write("status_access: []\n")).status_access, ()
        )

    def test_what_the_file_refuses(self) -> None:
        for text, said in (
            ("{}\n", "holds status_access"),
            ("colours: true\n", "unknown section"),
            ("status_access: [192.0.2.1/24]\n", "host bits"),
            ("features:\n  dark_mode: true\n", "no feature dark_mode"),
            ("features:\n  waf_engine: 'yes'\n", "true or false"),
            ("oidc:\n  issuer: https://idp.example.com\n  colour: red\n", "unknown field"),
            ("oidc:\n  enabled: 'on'\n", "true or false"),
            ("oidc:\n  client_id: 7\n", "must be text"),
            ("oidc:\n  auto_create: false\n", "auto_create is gone"),
        ):
            with self.subTest(said), self.assertRaises(ApplyError) as raised:
                settings_apply.read_file(self.write(text))
            self.assertIn(said, str(raised.exception))

    def test_a_client_secret_others_may_read_is_refused(self) -> None:
        text = "oidc:\n  client_secret: the secret\n"

        with self.assertRaises(ApplyError) as raised:
            settings_apply.read_file(self.write(text, mode=0o640))

        self.assertIn("0600", str(raised.exception))
        settings_apply.read_file(self.write("oidc:\n  enabled: false\n", mode=0o644))


def stored_provider() -> db.OidcProvider:
    return db.OidcProvider(
        enabled=False,
        issuer="https://idp.example.com/realms/main",
        client_id="haprion",
        client_secret_sealed=b"sealed",
        key_id="k1",
        auth_method="client_secret_basic",
        scopes="openid",
        username_claim="preferred_username",
        groups_claim="groups",
        admin_group="admins",
        reader_group=None,
        button_text="Sign in",
        prompt_login=False,
        logout_mode="app",
        local_login="break_glass_only",
        ca_pem=None,
        revision=3,
        verified_revision=3,
        updated_at=datetime.now(UTC),
        updated_by="admin",
    )


def a_ca_pem() -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Example CA")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


class TheIdentity(unittest.TestCase):
    def test_the_issuer_is_compared_as_it_is_stored(self) -> None:
        self.assertEqual(
            settings_apply._identity(
                {"issuer": " https://idp.example.com/realms/main "}, stored_provider()
            ),
            ("https://idp.example.com/realms/main", "haprion", None),
        )

    def test_a_new_ca_is_a_new_identity_and_a_blank_one_is_none(self) -> None:
        stored = stored_provider()

        self.assertEqual(settings_apply._identity({"ca_pem": " X \n"}, stored)[2], "X")
        self.assertIsNone(settings_apply._identity({"ca_pem": "  "}, stored)[2])

    def test_a_file_with_a_new_ca_and_the_secret_replaces_the_secret(self) -> None:
        """Review 26-10-30, E3: the secret in the file was dropped, and the save refused."""

        pem = a_ca_pem()
        with (
            mock.patch.object(db, "oidc_provider", return_value=stored_provider()),
            mock.patch.object(
                oidc_web, "read_public_key", return_value=mock.Mock(key_id="0123456789abcdef")
            ),
            mock.patch.object(oidc, "seal_client_secret", return_value=b"sealed-again"),
        ):
            answer = settings_apply.apply_oidc(
                object(),
                {"ca_pem": pem, "client_secret": "the secret"},
                actor="admin",
                check=True,
                public_key=Path("/nonexistent/public.pem"),
                replace_secret=False,
                piped_secret=None,
            )

        assert answer is not None  # noqa: S101 - the file changes the CA
        self.assertEqual(answer["sealing"], "replaced")
        self.assertIn("client_secret", answer["fields"])
        self.assertIn("ca_pem", answer["fields"])


class TheSessionsItEnded(unittest.TestCase):
    def test_turning_sign_in_off_says_how_many_sessions_ended(self) -> None:
        """Review 26-10-30, R4: the count was in the audit row only."""

        with (
            mock.patch.object(
                db, "oidc_provider", return_value=replace(stored_provider(), enabled=True)
            ),
            mock.patch.object(db, "set_oidc_enabled", return_value=3),
            mock.patch.object(db, "record_audit_event"),
        ):
            answer = settings_apply.apply_oidc(
                mock.Mock(),
                {"enabled": False},
                actor="admin",
                check=False,
                public_key=None,
                replace_secret=False,
                piped_secret=None,
            )

        assert answer is not None  # noqa: S101 - the file turns it off
        self.assertEqual(answer["sessions_ended"], 3)


class TheColoursSwitch(unittest.TestCase):
    """Review 26-10-30, E2 (B410): the switch is never locked, whatever the cluster count."""

    def readings(self, count: int) -> feature_switch.Readings:
        return feature_switch.Readings(
            backup_overview=lambda: None,
            objects=lambda: [],
            restore_waiting=lambda: False,
        )

    def test_it_can_be_turned_on_with_seven_clusters(self) -> None:
        row = SimpleNamespace(enabled=False, remembered={})
        with (
            mock.patch.object(db, "feature_switches", return_value={"cluster_colours": row}),
            mock.patch.object(db, "set_feature_switch", return_value=True),
            mock.patch.object(db, "record_audit_event"),
        ):
            flipped = settings_apply.apply_features(
                object(), {"cluster_colours": True}, actor="t", readings=self.readings(7)
            )

        self.assertEqual(flipped, {"cluster_colours": True})


class TheRunThatSavedAndStopped(unittest.TestCase):
    """Review 26-10-30, E5: Verify failing after the commit is `partial`, with what was saved."""

    def test_a_failed_verify_after_the_commit_is_partial_and_names_what_was_saved(self) -> None:
        provider = SimpleNamespace(
            enabled=False,
            verified=False,
            issuer="https://idp.example.com",
            revision=3,
            client_secret_sealed=b"x",
            client_id="c",
            ca_pem=None,
        )
        commits: list[int] = []
        connection = mock.MagicMock()
        connection.__enter__.return_value = connection
        connection.commit.side_effect = lambda: commits.append(1)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "settings.yaml")
            path.write_text(
                "status_access: [192.0.2.10]\n"
                "oidc:\n  enabled: true\n  interface_url: https://mgr.example.com\n"
            )
            path.chmod(0o600)
            out = io.StringIO()
            with (
                mock.patch("os.geteuid", return_value=0),
                mock.patch.object(
                    config, "load", return_value=SimpleNamespace(oidc_public_key=None)
                ),
                mock.patch.object(settings_tool, "load_environment"),
                mock.patch.object(settings_tool, "connect", return_value=connection),
                mock.patch.object(db, "status_access", return_value=[]),
                mock.patch.object(db, "set_status_access"),
                mock.patch.object(db, "record_audit_event"),
                mock.patch.object(db, "oidc_provider", return_value=provider),
                mock.patch.object(db, "record_oidc_verified", return_value=False),
                mock.patch.object(
                    settings_apply,
                    "verify_with_helper",
                    return_value=(False, [], "the provider refused the client"),
                ),
                contextlib.redirect_stdout(out),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                code = settings_tool.main(["apply", str(path), "--json"])

        answer = json.loads(out.getvalue())
        self.assertEqual((code, answer["outcome"]), (69, "partial"))
        self.assertEqual(answer["result"]["status_access"]["added"], ["192.0.2.10/32"])
        self.assertIn("did not pass Verify", answer["warnings"][0]["message"])
        self.assertTrue(commits)


class TheAnswer(unittest.TestCase):
    def test_it_has_the_shape_the_contract_holds(self) -> None:
        outcome = Outcome(
            status_access={"added": ["192.0.2.10/32"], "removed": []},
            features={"waf_engine": True},
            oidc={
                "fields": ["button_text"],
                "enabled": None,
                "sealing": "kept",
                "sessions_ended": 0,
            },
        )
        code, answer = answered(
            lambda: tool_answer.done(
                settings_apply.OPERATION, settings_apply.summary(outcome, check=False)
            )
        )
        self.assertEqual(code, 0)
        fixture = json.loads(FIXTURE.read_text())

        self.assertEqual(set(answer), set(fixture))
        self.assertEqual(answer["result"], fixture["result"])
        self.assertEqual(answer["operation"], fixture["operation"])

    def test_a_kept_secret_alone_is_no_change(self) -> None:
        outcome = Outcome(oidc={"fields": [], "enabled": None, "sealing": "kept"})

        self.assertFalse(outcome.changed)


if __name__ == "__main__":
    unittest.main()
