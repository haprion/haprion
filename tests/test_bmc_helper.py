"""The BMC helpers as their sockets reach them: a request in, a contract answer out (B526, B536)."""

from __future__ import annotations

import base64
import io
import json
import uuid
from pathlib import Path
from typing import Any
from unittest import mock

from haprion import bmc_socket, bmc_targets, exit_codes, helper_socket
from haprion.cli import bmc_helper
from tests.contract_schema import assert_contract
from tests.test_bmc_redfish import PASSWORD, USER, WRONG
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
        self.assertIs(result["may_upload"], True)
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
        #
        # The user the page shows is the one root opened from the box.
        #
        self.assertEqual(answer["result"]["username"], USER)
        self.assertEqual(self.registry().certificates[DEVICE].bmc.username, USER)
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

    def test_save_and_remove_wait_for_no_install_and_change_nothing_under_one(self) -> None:
        """An install ends by writing its target back: under it, a save or a removal would be undone."""

        before = self.registry().certificates[DEVICE].bmc
        with bmc_targets.install_lock(self.root / "state"):
            for parameters in (
                {"action": "remove", "id": DEVICE},
                {"action": "save", "fingerprint_sha256": self.old, **self.target()},
            ):
                with self.subTest(action=parameters["action"]):
                    code, answer, _journal = self.ask("bmc", parameters)
                    self.assertEqual(code, exit_codes.BLOCKED)
                    self.assertEqual(
                        (answer["outcome"], answer["error"]["code"]), ("blocked", "bmc_busy")
                    )
        self.assertEqual(self.registry().certificates[DEVICE].bmc, before)
        self.assertEqual(self.bmc.requests, [])

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

    def test_an_install_behind_another_is_blocked_before_anything_is_sent(self) -> None:
        with bmc_targets.install_lock(self.root / "state"):
            code, answer, _journal = self.ask("bmc_install", {"id": DEVICE, "by": "install_now"})

        self.assertEqual(code, exit_codes.BLOCKED)
        self.assertEqual((answer["outcome"], answer["error"]["code"]), ("blocked", "bmc_busy"))
        self.assertEqual(self.bmc.requests, [])

    def test_the_request_the_worker_builds_is_the_one_the_helper_takes(self) -> None:
        request = bmc_helper.build_install_request(
            str(uuid.uuid4()), certificate_id=DEVICE, by="save"
        )
        out = io.StringIO()
        code = bmc_helper.install_main(
            [],
            input_stream=io.BytesIO(request.encode()),
            output_stream=out,
            error_stream=io.StringIO(),
            require_root=False,
            require_secure=False,
            root=self.root_side(),
        )

        self.assertEqual(code, 0)
        self.assertEqual(
            assert_contract("haprion-bmc-install", out.getvalue())["result"]["by"], "save"
        )

    def test_the_timer_is_the_only_installer_that_is_not_asked(self) -> None:
        code, answer, _journal = self.ask("bmc_install", {"id": DEVICE, "by": "timer"})
        self.assertNotEqual(code, 0)
        self.assertEqual(answer["error"]["code"], "bad_input")


class TheWebsClient(HelperCase):
    """`bmc_socket`: what the web sends over `bmc.sock`, and how it says what came back."""

    def through_the_helper(self) -> Any:
        """`helper_socket.ask` answered by the helper itself, as the socket unit would."""

        def answer(request: dict[str, Any], **_options: Any) -> bytes:
            out = io.StringIO()
            bmc_helper.main(
                [],
                input_stream=io.BytesIO(json.dumps(request).encode()),
                output_stream=out,
                error_stream=io.StringIO(),
                require_root=False,
                require_secure=False,
                root=self.root_side(),
            )
            return out.getvalue().encode()

        return mock.patch.object(helper_socket, "ask", side_effect=answer)

    def test_check_save_and_remove_as_the_web_asks_them(self) -> None:
        box = self.sealed()
        with self.through_the_helper():
            bmc_socket.ask("remove", DEVICE)
            checked = bmc_socket.ask(
                "check",
                DEVICE,
                address=LOCAL,
                port=self.bmc.port,
                key_id=self.public.key_id,
                ciphertext=box,
            )
            saved = bmc_socket.ask(
                "save",
                DEVICE,
                address=LOCAL,
                port=self.bmc.port,
                fingerprint_sha256=checked["served_sha256"],
                key_id=self.public.key_id,
                ciphertext=box,
            )
            self.assertEqual((saved["fingerprint_sha256"], saved["username"]), (self.old, USER))
            with self.assertRaises(bmc_socket.BmcAskError) as refused:
                bmc_socket.ask(
                    "save",
                    DEVICE,
                    address=LOCAL,
                    port=self.bmc.port,
                    fingerprint_sha256="0" * 64,
                    key_id=self.public.key_id,
                    ciphertext=box,
                )
            self.assertEqual(refused.exception.code, "expected_target_changed")
            self.assertEqual(bmc_socket.ask("remove", DEVICE), {"id": DEVICE, "removed": True})

    def test_a_service_asked_and_then_silent_is_told_from_one_never_asked(self) -> None:
        for error, code in (
            (helper_socket.HelperUnavailable("not running"), "unavailable"),
            (helper_socket.HelperBusy("busy"), "unavailable"),
            (helper_socket.HelperSilent("did not answer"), "unanswered"),
        ):
            with (
                self.subTest(error=type(error).__name__),
                mock.patch.object(helper_socket, "ask", side_effect=error),
                self.assertRaises(bmc_socket.BmcAskError) as caught,
            ):
                bmc_socket.ask("remove", DEVICE)
            self.assertEqual(caught.exception.code, code)

    def test_an_answer_about_another_certificate_is_no_answer(self) -> None:
        document = {"outcome": "done", "result": {"id": "other.example", "removed": True}}
        with (
            mock.patch.object(helper_socket, "ask", return_value=json.dumps(document).encode()),
            self.assertRaises(bmc_socket.BmcAskError) as caught,
        ):
            bmc_socket.ask("remove", DEVICE)
        self.assertEqual(caught.exception.code, "unavailable")

    def test_systemd_ends_the_helper_before_the_web_stops_waiting(self) -> None:
        unit = (
            Path(__file__).resolve().parents[1]
            / "install/platform/examples/haprion-bmc-helper@.service.example"
        ).read_text()
        self.assertIn("Type=exec", unit)
        seconds = int(unit.split("\nRuntimeMaxSec=", 1)[1].split("\n", 1)[0])
        self.assertLess(seconds, bmc_socket.TIMEOUT_SECONDS)
