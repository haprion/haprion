"""The receiver helper: the interface's request across the boundary, and nothing more.

What `add` and `remove` do to the machine is `test_cert_receiver`'s. What is
measured here is the request's shape, that the key arrives as text and not as
a path, that the answer carries the layers and the instructions the command
prints, and that the sudoers rule names the helper without arguments.
"""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any
from unittest import mock

import yaml

from haprion import cert_receiver, exit_codes
from haprion.cli import cert_receiver_helper
from haprion.envelope import new_request_id
from tests.contract_schema import assert_contract
from tests.test_cert_receiver import KEY, ReceiverFixture


class HelperFixture(ReceiverFixture):
    def run_helper(
        self, parameters: dict[str, Any], *, operation: str = "cert_receiver", **options: Any
    ) -> tuple[int, dict[str, Any] | None, str]:
        request = json.dumps(
            {
                "schema_version": 1,
                "operation": operation,
                "cluster": options.pop("cluster", None),
                "request_id": new_request_id(),
                "parameters": parameters,
            }
        )
        out, err = io.StringIO(), io.StringIO()
        code = cert_receiver_helper.main(
            options.pop("argv", []),
            policy_path=self.policy_path,
            input_stream=io.BytesIO(request.encode("utf-8")),
            output_stream=out,
            error_stream=err,
            require_secure=False,
            require_root=False,
            tools=self.tools,
            locations=self.locations,
            lock_path=self.root / "cert-publish.lock",
        )
        raw = out.getvalue()
        if raw.strip():
            assert_contract("haprion-cert-receiver", raw)
        return code, (json.loads(raw) if raw.strip() else None), err.getvalue()


class AddingThroughTheHelper(HelperFixture):
    def test_rsync_with_a_pasted_key_registers_and_answers_with_instructions(self) -> None:
        with (
            mock.patch.object(cert_receiver, "account_exists", return_value=False),
            mock.patch.object(cert_receiver, "_own"),
        ):
            code, document, _ = self.run_helper(
                {
                    "receiver": "lb-02.example.net",
                    "action": "add",
                    "transport": "rsync",
                    "public_key": KEY + "\n",
                }
            )

        self.assertEqual(code, 0)
        assert document is not None
        self.assertEqual(document["outcome"], "done")
        result = document["result"]
        self.assertEqual(result["action"], "added")
        self.assertEqual(
            [layer["layer"] for layer in result["layers"]],
            ["account", "directory", "lock", "registry"],
        )
        self.assertTrue(
            any(
                "rsync -rt --no-owner --no-group --chmod=D700,F600 crx-lb-02-example-net@" in line
                for line in result["instructions"]
            )
        )
        self.assertIn("mgr.example.net", " ".join(result["instructions"]))
        self.assertEqual(self.registered()["lb-02.example.net"]["transport"], "rsync")
        self.assertIn(KEY, self.keys_file().read_text(encoding="ascii"))

    def test_https_takes_the_allowlist_and_no_key(self) -> None:
        with mock.patch.object(cert_receiver, "_own"):
            code, document, _ = self.run_helper(
                {
                    "receiver": "192.0.2.9",
                    "action": "add",
                    "transport": "https",
                    "allow": ["192.0.2.9/32"],
                    "secret_hash": cert_receiver.secret_hash("receiver password"),
                }
            )

        self.assertEqual(code, 0)
        assert document is not None
        self.assertEqual(document["outcome"], "done")
        self.assertEqual(self.registered()["192.0.2.9"]["allow"], ["192.0.2.9/32"])
        # B306: the helper is given the hash and never answers with a password.
        self.assertNotIn("password", document["result"])

    def test_a_new_secret_takes_the_receiver_and_the_hash_only(self) -> None:
        for extra in ({}, {"secret_hash": cert_receiver.secret_hash("x"), "transport": "https"}):
            with self.subTest(extra=extra):
                code, document, _ = self.run_helper(
                    {"receiver": "192.0.2.9", "action": "secret", **extra}
                )
                self.assertEqual(code, 65)
                assert document is not None
                self.assertEqual(document["error"]["code"], "bad_input")

    def test_a_new_key_takes_the_receiver_and_the_pasted_key_only(self) -> None:
        """26-10-18: the interface's *Replace SSH key*, through the helper."""

        new_key = KEY.replace("AAAAIB5s", "AAAAIB6t")
        self.add()
        code, document, _ = self.run_helper(
            {"receiver": "lb-02.example.net", "action": "key", "public_key": new_key + "\n"}
        )
        self.assertEqual(code, 0)
        assert document is not None
        self.assertEqual(document["result"]["action"], "key")
        self.assertIn(new_key, self.keys_file().read_text(encoding="ascii"))
        for extra in ({}, {"public_key": new_key, "transport": "rsync"}):
            with self.subTest(extra=extra):
                code, document, _ = self.run_helper(
                    {"receiver": "lb-02.example.net", "action": "key", **extra}
                )
                self.assertEqual(code, 65)
                assert document is not None
                self.assertEqual(document["error"]["code"], "bad_input")

    def test_the_command_s_refusals_come_back_as_the_envelope_s_failure(self) -> None:
        code, document, errors = self.run_helper(
            {"receiver": "lb-02.example.net", "action": "add", "transport": "rsync"}
        )

        self.assertEqual(code, 64)
        assert document is not None
        self.assertEqual(document["outcome"], "failed")
        self.assertEqual(document["error"]["code"], "bad_input")
        self.assertIn("public-key is required", errors)
        self.assertEqual(self.registered(), {})

    def test_a_key_that_is_a_path_is_not_read(self) -> None:
        """The interface pastes text. A path is not a key, and the helper does not open it."""

        code, document, _ = self.run_helper(
            {
                "receiver": "lb-02.example.net",
                "action": "add",
                "transport": "rsync",
                "public_key": str(self.key_file),
            }
        )

        self.assertEqual(code, 64)
        assert document is not None
        self.assertEqual(document["error"]["code"], "bad_input")
        self.assertEqual(self.registered(), {})


class RemovingThroughTheHelper(HelperFixture):
    def test_a_receiver_nothing_names_is_taken_away(self) -> None:
        with (
            mock.patch.object(cert_receiver, "account_exists", return_value=False),
            mock.patch.object(cert_receiver, "_own"),
        ):
            self.add(public_key=KEY, owner=None)
        with mock.patch.object(cert_receiver, "account_exists", return_value=True):
            code, document, _ = self.run_helper(
                {"receiver": "lb-02.example.net", "action": "remove"}
            )

        self.assertEqual(code, 0)
        assert document is not None
        self.assertEqual(document["result"]["action"], "removed")
        self.assertEqual(self.registered(), {})
        self.assertTrue(self.runner.ran("userdel crx-lb-02-example-net"))

    def test_a_removal_that_left_the_account_is_partial(self) -> None:
        """Review 26-10-24, 13-02: `partial` beside exit 0 crashed in the envelope."""

        with (
            mock.patch.object(cert_receiver, "account_exists", return_value=False),
            mock.patch.object(cert_receiver, "_own"),
        ):
            self.add(public_key=KEY, owner=None)
        self.runner.failures["userdel"] = (8, "userdel: user is currently used by process 1")
        with mock.patch.object(cert_receiver, "account_exists", return_value=True):
            code, document, _ = self.run_helper(
                {"receiver": "lb-02.example.net", "action": "remove"}
            )

        self.assertEqual(code, exit_codes.PARTIAL)
        assert document is not None
        self.assertEqual(document["outcome"], "partial")
        self.assertEqual(document["warnings"][0]["code"], "account_failed")
        self.assertEqual(self.registered(), {})

    def test_a_removal_takes_no_transport_or_key(self) -> None:
        code, document, errors = self.run_helper(
            {"receiver": "lb-02.example.net", "action": "remove", "transport": "rsync"}
        )

        self.assertEqual(code, 65)
        assert document is not None
        self.assertEqual(document["error"]["code"], "bad_input")
        self.assertIn("takes no transport", errors)

    def test_a_receiver_a_certificate_still_names_is_refused(self) -> None:
        with (
            mock.patch.object(cert_receiver, "account_exists", return_value=False),
            mock.patch.object(cert_receiver, "_own"),
        ):
            self.add(public_key=KEY, owner=None)
        document = self.root / "certificates.yaml"
        raw = yaml.safe_load(document.read_text())
        raw["certificates"]["keeper.example"]["receivers"] = ["lb-02.example.net"]
        document.write_text(yaml.safe_dump(raw), encoding="utf-8")

        code, answer, _ = self.run_helper({"receiver": "lb-02.example.net", "action": "remove"})

        self.assertEqual(code, 64)
        assert answer is not None
        self.assertEqual(answer["error"]["code"], "receiver_in_use")
        self.assertIn("lb-02.example.net", self.registered())


class TheBoundary(HelperFixture):
    def test_no_command_line_arguments_are_accepted(self) -> None:
        code, document, errors = self.run_helper(
            {"receiver": "x", "action": "remove"}, argv=["--policy", "/etc/passwd"]
        )
        self.assertEqual(code, 64)
        self.assertIsNone(document)
        self.assertIn("no command-line arguments", errors)

    def test_a_request_naming_a_cluster_is_refused(self) -> None:
        code, _, errors = self.run_helper({"receiver": "x", "action": "remove"}, cluster="alpha")
        self.assertEqual(code, 64)
        self.assertIn("acts on no cluster", errors)

    def test_an_unknown_parameter_is_refused(self) -> None:
        code, _, errors = self.run_helper({"receiver": "x", "action": "remove", "path": "/srv"})
        self.assertEqual(code, 65)
        self.assertIn("unknown field", errors)

    def test_an_id_that_is_not_one_is_refused_before_anything_is_read(self) -> None:
        code, document, _ = self.run_helper({"receiver": "../etc", "action": "remove"})
        self.assertEqual(code, 65)
        assert document is not None
        self.assertEqual(document["error"]["code"], "bad_input")

    def test_the_sudoers_example_grants_nothing_and_the_socket_unit_runs_the_helper(self) -> None:
        """B163: reached over a socket, so the rule is absent and the unit names the path."""

        examples = Path(__file__).resolve().parents[1] / "install/platform/examples"
        rules = (examples / "haprion-worker.sudoers.example").read_text(encoding="utf-8")
        service = (examples / "haprion-cert-receiver-helper@.service.example").read_text(
            encoding="utf-8"
        )
        self.assertNotIn(cert_receiver_helper.HELPER, rules)
        self.assertIn(f"ExecStart={cert_receiver_helper.HELPER}\n", service)
        self.assertIn("StandardInput=socket", service)

    def test_build_request_is_what_the_helper_accepts(self) -> None:
        request = cert_receiver_helper.build_request(
            "r1", receiver="lb-02.example.net", action="add", transport="sftp", public_key=KEY
        )
        parsed = json.loads(request)
        self.assertEqual(parsed["cluster"], None)
        self.assertEqual(parsed["operation"], "cert_receiver")
        self.assertEqual(
            set(parsed["parameters"]), {"receiver", "action", "transport", "public_key"}
        )
