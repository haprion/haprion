"""haprion-blocklist-apply-helper: the box held to its list, the definition root keeps (B500)."""

from __future__ import annotations

import base64
import io
import json
from typing import Any

import yaml

from haprion import blocklist_store, blocklists, exit_codes
from haprion.cli import blocklist_apply_helper
from haprion.dns_profile_keys import generate, render_private_key
from tests.contract_schema import assert_contract
from tests.test_cert_publish import Fixture

SECRET = "tok"  # noqa: S105 - a test value, sealed and opened in memory


class ApplyFixture(Fixture):
    def setUp(self) -> None:
        super().setUp()
        private, self.public = generate()
        self.private_path = self.root / "profile.key"
        self.private_path.write_text(render_private_key(private), encoding="utf-8")
        self.private_path.chmod(0o600)
        profiles = self.root / "profiles"
        profiles.mkdir(mode=0o700)
        self.policy_path = self.write_config({})
        document = yaml.safe_load(self.policy_path.read_text(encoding="utf-8"))
        document["acme"] = {
            "dns_profiles": {"directory": str(profiles), "private_keys": [str(self.private_path)]}
        }
        self.policy_path.write_text(yaml.safe_dump(document), encoding="utf-8")
        self.lists = self.root / "blocklists"
        self.lists.mkdir(mode=0o700)
        self.state = self.root / "state"
        self.state.mkdir()
        self.started = 0

    def sealed(self, revision: int = 2, **fields: object) -> str:
        """The box for the request's own list and source, unless a field says otherwise."""

        base: dict[str, object] = {
            "name": "crowdsec",
            "url": "https://example.com/list.txt",
            "every_hours": 24,
            "authorization": "bearer",
        }
        item = blocklists.definition(**{**base, **fields})  # type: ignore[arg-type]
        box = blocklist_store.seal_secret(
            self.public, definition=item, revision=revision, secret=SECRET
        )
        return base64.b64encode(box).decode("ascii")

    def request(self, **overrides: object) -> str:
        parameters: dict[str, object] = {
            "name": "crowdsec",
            "revision": 2,
            "secret_revision": 2,
            "url": "https://example.com/list.txt",
            "every_hours": 24,
            "authorization": "bearer",
            "username": "",
            "description": "CrowdSec raw IP list",
            "excepts": ["192.0.2.10", "partner-sites"],
            "key_id": self.public.key_id,
            "ciphertext": self.sealed(),
            **overrides,
        }
        parameters = {key: value for key, value in parameters.items() if value is not None}
        return json.dumps(
            {
                "schema_version": 1,
                "operation": "blocklist_apply",
                "cluster": None,
                "request_id": "ffffffff-ffff-4fff-8fff-ffffffffffff",
                "parameters": parameters,
            }
        )

    def starter(self) -> bool:
        self.started += 1
        return True

    def invoke(self, request: str) -> tuple[int, dict[str, Any], str]:
        output, errors = io.StringIO(), io.StringIO()
        code = blocklist_apply_helper.main(
            [],
            policy_path=self.policy_path,
            input_stream=io.BytesIO(request.encode("utf-8")),
            output_stream=output,
            error_stream=errors,
            require_secure=False,
            require_root=False,
            directory=self.lists,
            state=self.state,
            starter=self.starter,
        )
        document = assert_contract("haprion-blocklist-apply", output.getvalue())
        return code, document, errors.getvalue()


class Applying(ApplyFixture):
    def test_the_definition_and_its_secret_are_written_and_a_pass_started(self) -> None:
        code, document, errors = self.invoke(self.request())

        self.assertEqual(code, 0, errors)
        self.assertEqual(
            document["result"], {"name": "crowdsec", "revision": 2, "refresh_started": True}
        )
        (stored,) = blocklist_store.read_all(directory=self.lists)
        self.assertEqual(stored.secret, SECRET)
        self.assertEqual(stored.definition.excepts, ("192.0.2.10/32", "partner-sites"))
        self.assertEqual(self.started, 1)

    def test_a_list_without_authorization_needs_no_box(self) -> None:
        code, _, errors = self.invoke(
            self.request(authorization="none", key_id=None, ciphertext=None)
        )

        self.assertEqual(code, 0, errors)
        (stored,) = blocklist_store.read_all(directory=self.lists)
        self.assertEqual(stored.secret, "")

    def test_a_box_sealed_for_another_list_is_blocked_and_nothing_written(self) -> None:
        code, document, _ = self.invoke(self.request(ciphertext=self.sealed(name="other")))

        self.assertEqual(code, exit_codes.BLOCKED)
        self.assertEqual(document["error"]["code"], "binding_mismatch")
        self.assertEqual(blocklist_store.read_all(directory=self.lists), ())
        self.assertEqual(self.started, 0)

    def test_a_save_that_left_the_secret_alone_is_written_at_the_jobs_revision(self) -> None:
        # A box sealed at revision 1, the row at revision 2: an Except line was added (BL01).
        code, document, errors = self.invoke(
            self.request(revision=2, secret_revision=1, ciphertext=self.sealed(revision=1))
        )

        self.assertEqual(code, 0, errors)
        self.assertEqual(document["result"]["revision"], 2)
        (stored,) = blocklist_store.read_all(directory=self.lists)
        self.assertEqual((stored.revision, stored.secret_revision, stored.secret), (2, 1, SECRET))

    def test_a_box_older_than_the_secret_revision_is_blocked(self) -> None:
        code, document, _ = self.invoke(
            self.request(revision=3, secret_revision=3, ciphertext=self.sealed(revision=2))
        )

        self.assertEqual(code, exit_codes.BLOCKED)
        self.assertEqual(document["error"]["code"], "binding_mismatch")
        self.assertEqual(blocklist_store.read_all(directory=self.lists), ())

    def test_a_box_kept_across_a_new_url_is_blocked_and_nothing_written(self) -> None:
        # The web kept the box while the URL changed: root refuses to send it to the new host (BL02).
        code, document, _ = self.invoke(
            self.request(
                revision=3,
                secret_revision=1,
                url="https://attacker.example.net/list.txt",
                ciphertext=self.sealed(revision=1),
            )
        )

        self.assertEqual(code, exit_codes.BLOCKED)
        self.assertEqual(document["error"]["code"], "binding_mismatch")
        self.assertIn("type it again", document["error"]["message"])
        self.assertEqual(blocklist_store.read_all(directory=self.lists), ())
        self.assertEqual(self.started, 0)

    def test_a_secret_revision_ahead_of_the_revision_is_refused(self) -> None:
        code, document, _ = self.invoke(self.request(revision=2, secret_revision=3))

        self.assertEqual(code, exit_codes.REFUSED)
        self.assertEqual(document["error"]["code"], "bad_input")

    def test_an_older_revision_than_the_written_one_is_refused(self) -> None:
        self.invoke(self.request(revision=3, secret_revision=3, ciphertext=self.sealed(revision=3)))

        code, document, _ = self.invoke(self.request())

        self.assertEqual(code, exit_codes.CONFIG)
        self.assertIn("older", document["error"]["message"])

    def test_authorization_without_a_box_is_refused(self) -> None:
        code, document, _ = self.invoke(self.request(ciphertext=None))

        self.assertEqual(code, exit_codes.REFUSED)
        self.assertEqual(document["error"]["code"], "bad_input")

    def test_fields_the_rules_refuse_are_refused(self) -> None:
        for override in (
            {"url": "http://example.com/"},
            {"every_hours": 2},
            {"name": "Bad"},
            {"excepts": ["192.0.2.1/24"]},
            {"ciphertext": "not base64!"},
            {"key_id": "short"},
        ):
            with self.subTest(override=override):
                code, document, _ = self.invoke(self.request(**override))
                self.assertEqual(code, exit_codes.REFUSED)
                self.assertEqual(document["error"]["code"], "bad_input")

    def test_remove_deletes_the_definition_and_the_last_good_list(self) -> None:
        self.invoke(self.request())
        blocklist_store.keep(
            "crowdsec", blocklists.parse(b"192.0.2.0/24\n").networks, directory=self.state
        )

        code, document, _ = self.invoke(
            json.dumps(
                {
                    "schema_version": 1,
                    "operation": "blocklist_apply",
                    "cluster": None,
                    "request_id": "ffffffff-ffff-4fff-8fff-ffffffffffff",
                    "parameters": {"name": "crowdsec", "revision": 3, "remove": True},
                }
            )
        )

        self.assertEqual(code, 0)
        self.assertTrue(document["result"]["removed"])
        self.assertEqual(blocklist_store.read_all(directory=self.lists), ())
        self.assertIsNone(blocklist_store.kept("crowdsec", directory=self.state))
