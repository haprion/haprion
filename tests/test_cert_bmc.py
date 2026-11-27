"""`haprion-cert-bmc`: the BMC page's work in the terminal, through the helpers' own code (B526, B536)."""

from __future__ import annotations

import io
from typing import Any
from unittest import mock

from haprion import exit_codes
from haprion.cli import cert_bmc
from tests.contract_schema import assert_contract
from tests.test_bmc_helper import HelperCase
from tests.test_bmc_redfish import PASSWORD, USER, WRONG
from tests.test_bmc_targets import LOCAL
from tests.test_cert_export import DEVICE


class TheCommand(HelperCase):
    def cert_bmc(self, *argv: str, password: str = PASSWORD, euid: int = 0) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with mock.patch("os.geteuid", return_value=euid):
            code = cert_bmc.main(
                list(argv),
                stream_out=out,
                stream_err=err,
                stream_in=io.StringIO(password + "\n"),
                root=self.root_side(),
            )
        return code, out.getvalue(), err.getvalue()

    def where(self) -> list[str]:
        return ["--address", LOCAL, "--port", str(self.bmc.port), "--user", USER]

    def test_check_shows_the_fingerprint_as_a_bmc_page_does_and_changes_nothing(self) -> None:
        self.cert_bmc("remove", DEVICE)

        code, out, _err = self.cert_bmc("check", DEVICE, *self.where())

        self.assertEqual(code, 0)
        colons = ":".join(self.old[index : index + 2] for index in range(0, 64, 2)).upper()
        self.assertIn(f"SHA-256   {colons}", out)
        self.assertIn("may upload certificates", out)
        self.assertNotIn(PASSWORD, out)
        self.assertIsNone(self.registry().certificates[DEVICE].bmc)

    def test_save_takes_the_fingerprint_as_shown_and_installs_as_the_page_does(self) -> None:
        self.cert_bmc("remove", DEVICE)
        colons = ":".join(self.old[index : index + 2] for index in range(0, 64, 2)).upper()

        code, out, _err = self.cert_bmc("save", DEVICE, *self.where(), "--sha256", colons, "--json")

        self.assertEqual(code, 0, out + _err)
        result = assert_contract("haprion-bmc", out)["result"]
        self.assertEqual((result["install"]["outcome"], result["install"]["by"]), ("done", "save"))
        target = self.registry().certificates[DEVICE].bmc
        assert target is not None
        #
        # Pinned to what it serves now: the certificate just installed.
        #
        self.assertEqual((target.fingerprint_sha256, target.username), (self.current, USER))

        code, out, _err = self.cert_bmc("install", DEVICE, "--json")

        self.assertEqual(code, 0)
        result = assert_contract("haprion-bmc-install", out)["result"]
        self.assertEqual((result["outcome"], result["by"]), ("done", "install_now"))

    def test_a_save_whose_install_failed_says_the_target_stands(self) -> None:
        self.cert_bmc("remove", DEVICE)
        self.bmc.upload_answer = (
            400,
            {
                "error": {
                    "@Message.ExtendedInfo": [{"Message": "SSL certificate validation failed."}]
                }
            },
        )

        code, out, _err = self.cert_bmc(
            "save", DEVICE, *self.where(), "--sha256", self.old, "--json"
        )

        self.assertNotEqual(code, 0)
        document = assert_contract("haprion-bmc", out)
        self.assertEqual(document["error"]["code"], "bmc_refused")
        self.assertIn("saved", document["error"]["message"])
        self.assertEqual(document["error"]["details"]["saved"]["fingerprint_sha256"], self.old)
        self.assertIsNotNone(self.registry().certificates[DEVICE].bmc)

    def test_each_answer_is_the_helpers_document(self) -> None:
        code, out, _err = self.cert_bmc("check", DEVICE, *self.where(), "--json")
        self.assertEqual(code, 0)
        self.assertEqual(assert_contract("haprion-bmc", out)["result"]["served_sha256"], self.old)

        code, out, _err = self.cert_bmc("remove", DEVICE, "--json")
        self.assertEqual(code, 0)
        self.assertEqual(
            assert_contract("haprion-bmc", out)["result"], {"id": DEVICE, "removed": True}
        )

    def test_a_wrong_password_is_said_as_the_bmc_said_it(self) -> None:
        code, out, _err = self.cert_bmc("check", DEVICE, *self.where(), "--json", password=WRONG)
        self.assertNotEqual(code, 0)
        self.assertEqual(assert_contract("haprion-bmc", out)["error"]["code"], "bmc_login_refused")

    def test_the_call_is_judged_before_root_is_asked_for(self) -> None:
        cases: list[tuple[list[str], str, int]] = [
            (["install", "Bad ID!"], "bad_input", exit_codes.USAGE),
            (
                ["check", DEVICE, "--address", "bmc 01", "--user", USER],
                "bad_input",
                exit_codes.USAGE,
            ),
            (
                ["save", DEVICE, *self.where(), "--sha256", "abc"],
                "bad_input",
                exit_codes.USAGE,
            ),
            (["remove", DEVICE], "not_root", exit_codes.NOT_ROOT),
        ]
        for argv, said, exit_code in cases:
            with self.subTest(argv=argv):
                code, out, _err = self.cert_bmc(*argv, "--json", euid=1000)
                schema = "haprion-bmc-install" if argv[0] == "install" else "haprion-bmc"
                document: dict[str, Any] = assert_contract(schema, out)
                self.assertEqual((code, document["error"]["code"]), (exit_code, said))
        self.assertEqual(self.bmc.requests, [])
