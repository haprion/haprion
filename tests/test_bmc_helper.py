"""The BMC helpers as their sockets reach them: a request in, a contract answer out (B526, B536)."""

from __future__ import annotations

import base64
import io
import json
import uuid
from typing import Any

from haprion import bmc_targets
from haprion.cli import bmc_helper
from tests.contract_schema import assert_contract
from tests.test_bmc_redfish import PASSWORD, WRONG
from tests.test_bmc_targets import LOCAL, TargetCase
from tests.test_cert_export import DEVICE


class HelperCase(TargetCase):
    def ask(self, operation: str, parameters: dict[str, Any]) -> tuple[int, dict[str, Any], str]:
        request = {
            "schema_version": 1,
            "operation": operation,
            "cluster": None,
            "request_id": str(uuid.uuid4()),
            "parameters": parameters,
        }
        out, errors = io.StringIO(), io.StringIO()
        entry = bmc_helper.main if operation == "bmc" else bmc_helper.install_main
        code = entry(
            [],
            input_stream=io.BytesIO(json.dumps(request).encode()),
            output_stream=out,
            error_stream=errors,
            require_root=False,
            require_secure=False,
            root=self.root_side(),
        )
        command = "haprion-bmc" if operation == "bmc" else "haprion-bmc-install"
        return code, assert_contract(command, out.getvalue()), errors.getvalue()

    def account(self) -> dict[str, Any]:
        return {
            "key_id": self.public.key_id,
            "ciphertext_base64": base64.b64encode(self.sealed()).decode(),
        }

    def target(self, **extra: Any) -> dict[str, Any]:
        return {"id": DEVICE, "address": LOCAL, "port": self.bmc.port, **self.account(), **extra}


class TheWebsHelper(HelperCase):
    def test_check_says_what_the_bmc_serves_and_writes_nothing(self) -> None:
        self.ask("bmc", {"action": "remove", "id": DEVICE})

        code, answer, journal = self.ask("bmc", {"action": "check", **self.target()})

        self.assertEqual(code, 0)
        result = answer["result"]
        self.assertEqual(result["served_sha256"], self.old)
        self.assertEqual((result["model"], result["firmware"]), ("X13SCL-IF", "01.09.06"))
        self.assertEqual(result["subject"], "bmc-old.example")
        self.assertIsNone(self.registry().certificates[DEVICE].bmc)
        self.assertNotIn(PASSWORD, json.dumps(answer) + journal)

    def test_save_writes_what_was_confirmed_and_keeps_the_account(self) -> None:
        self.ask("bmc", {"action": "remove", "id": DEVICE})

        code, answer, journal = self.ask(
            "bmc", {"action": "save", "fingerprint_sha256": self.old, **self.target()}
        )

        self.assertEqual(code, 0)
        self.assertEqual(answer["result"]["fingerprint_sha256"], self.old)
        self.assertEqual(self.pinned(), self.old)
        self.assertEqual(
            bmc_targets.read_account(
                DEVICE, directory=self.root / "accounts", require_secure=False
            )[0],
            self.public.key_id,
        )
        self.assertIn(f"bmc: save {DEVICE}", journal)
        self.assertNotIn(PASSWORD, journal)

    def test_save_of_a_certificate_the_bmc_no_longer_serves_writes_nothing(self) -> None:
        self.ask("bmc", {"action": "remove", "id": DEVICE})

        code, answer, _journal = self.ask(
            "bmc", {"action": "save", "fingerprint_sha256": "0" * 64, **self.target()}
        )

        self.assertNotEqual(code, 0)
        self.assertEqual(answer["error"]["code"], "expected_target_changed")
        self.assertIsNone(self.registry().certificates[DEVICE].bmc)
        self.assertFalse((self.root / "accounts" / f"{DEVICE}.json").exists())

    def test_remove_takes_the_target_and_the_account_and_leaves_the_mark(self) -> None:
        code, answer, _journal = self.ask("bmc", {"action": "remove", "id": DEVICE})

        self.assertEqual((code, answer["result"]), (0, {"id": DEVICE, "removed": True}))
        self.assertEqual(
            self.registered()[DEVICE], {"source": {"kind": "import"}, "exportable": True}
        )
        self.assertFalse((self.root / "accounts" / f"{DEVICE}.json").exists())

    def test_a_certificate_that_is_not_exportable_has_no_bmc(self) -> None:
        other = next(name for name in self.registered() if name != DEVICE)

        code, answer, _journal = self.ask("bmc", {"action": "remove", "id": other})

        self.assertNotEqual(code, 0)
        self.assertEqual(answer["error"]["code"], "not_exportable")

    def test_a_wrong_password_is_said_as_the_bmc_said_it(self) -> None:
        box = bmc_targets.seal_account(
            self.public, certificate_id=DEVICE, address=LOCAL, username="svc-app", password=WRONG
        )
        code, answer, _journal = self.ask(
            "bmc",
            {
                "action": "check",
                **self.target(ciphertext_base64=base64.b64encode(box).decode()),
            },
        )
        self.assertNotEqual(code, 0)
        self.assertEqual(answer["error"]["code"], "bmc_login_refused")

    def test_the_web_cannot_ask_for_an_install(self) -> None:
        code, answer, _journal = self.ask("bmc", {"action": "install", "id": DEVICE})
        self.assertNotEqual(code, 0)
        self.assertEqual(answer["error"]["code"], "bad_input")


class TheWorkersHelper(HelperCase):
    def test_install_now_installs_and_answers_the_attempt(self) -> None:
        code, answer, journal = self.ask("bmc_install", {"id": DEVICE, "by": "install_now"})

        self.assertEqual(code, 0)
        result = answer["result"]
        self.assertEqual((result["outcome"], result["fingerprint_sha256"]), ("done", self.current))
        self.assertEqual(self.pinned(), self.current)
        self.assertIn(f"bmc_install: install {DEVICE}: done", journal)

    def test_a_refused_install_is_a_failed_answer_in_the_bmcs_words(self) -> None:
        self.bmc.upload_answer = (
            400,
            {
                "error": {
                    "@Message.ExtendedInfo": [{"Message": "SSL certificate validation failed."}]
                }
            },
        )
        code, answer, _journal = self.ask("bmc_install", {"id": DEVICE, "by": "install_now"})

        self.assertNotEqual(code, 0)
        self.assertEqual(answer["error"]["code"], "bmc_refused")
        self.assertIn("SSL certificate validation failed.", answer["error"]["message"])
        self.assertEqual(self.state().attempt.outcome, "failed")  # type: ignore[union-attr]

    def test_the_timer_is_the_only_installer_that_is_not_asked(self) -> None:
        code, answer, _journal = self.ask("bmc_install", {"id": DEVICE, "by": "timer"})
        self.assertNotEqual(code, 0)
        self.assertEqual(answer["error"]["code"], "bad_input")
