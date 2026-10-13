"""``haprion-settings apply`` without a database: the file and the answer (Fas 23, B293).

The writes are held against the real schema in `test_database_integration`
(`TheSettingsFromAFile`); this holds what the file may say, and the answer's
shape against the fixture the contract suite validates against
`schemas/v1/haprion-settings-apply`.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

from haprion_ui import db, settings_apply
from haprion_ui.settings_apply import ApplyError, Outcome

FIXTURE = Path(__file__).resolve().parents[2] / "fixtures/haprion-settings-apply/valid/done.json"


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


class TheIdentity(unittest.TestCase):
    def test_the_issuer_is_compared_as_it_is_stored(self) -> None:
        stored = db.OidcProvider(
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

        self.assertEqual(
            settings_apply._identity({"issuer": " https://idp.example.com/realms/main "}, stored),
            ("https://idp.example.com/realms/main", "haprion"),
        )


class TheAnswer(unittest.TestCase):
    def test_it_has_the_shape_the_contract_holds(self) -> None:
        outcome = Outcome(
            status_access={"added": ["192.0.2.10/32"], "removed": []},
            features={"waf_engine": True},
            oidc={"fields": ["button_text"], "enabled": None, "sealing": "kept"},
        )
        answer = settings_apply.envelope(settings_apply.summary(outcome, check=False), None)
        fixture = json.loads(FIXTURE.read_text())

        self.assertEqual(set(answer), set(fixture))
        self.assertEqual(answer["result"], fixture["result"])
        self.assertEqual(answer["operation"], fixture["operation"])

    def test_a_kept_secret_alone_is_no_change(self) -> None:
        outcome = Outcome(oidc={"fields": [], "enabled": None, "sealing": "kept"})

        self.assertFalse(outcome.changed)


if __name__ == "__main__":
    unittest.main()
