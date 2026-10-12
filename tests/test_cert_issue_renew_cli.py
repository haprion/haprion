"""``haprion-cert-issue --renew`` (Fas 23): the terminal's *Renew* for a certbot row.

The round itself is `cert_issue.renew`, held in its own tests; this holds that
the command asks for it with the certificate alone and answers in the contract.
"""

from __future__ import annotations

import io
import unittest
from typing import Any
from unittest import mock

from haprion.cert_issue import IssueError
from haprion.cli import cert_issue
from tests.contract_schema import assert_contract


class TheRenewFlag(unittest.TestCase):
    def run_command(self, *argv: str) -> tuple[int, str, list[dict[str, Any]]]:
        asked: list[dict[str, Any]] = []

        def renew(**kwargs: Any) -> Any:
            asked.append(kwargs)
            raise IssueError("not_registered", "example.com is not in the registry", exit_code=65)

        out = io.StringIO()
        with (
            mock.patch.object(cert_issue, "renew", side_effect=renew),
            mock.patch.object(cert_issue, "load_policy", return_value=object()),
            mock.patch.object(cert_issue, "load_runtime_config", return_value=object()),
        ):
            code = cert_issue.main(
                list(argv), output_stream=out, error_stream=io.StringIO(), require_root=False
            )
        return code, out.getvalue(), asked

    def test_renew_asks_for_the_round_with_the_certificate_alone(self) -> None:
        code, out, asked = self.run_command("--domain", "example.com", "--renew", "--json")

        self.assertEqual(code, 65)
        self.assertEqual([call["certificate_id"] for call in asked], ["example.com"])
        self.assertEqual(
            assert_contract("haprion-cert-issue", out)["error"]["code"], "not_registered"
        )

    def test_a_renewal_takes_nothing_else(self) -> None:
        code, out, asked = self.run_command(
            "--domain", "example.com", "--renew", "--cluster", "alpha", "--json"
        )

        self.assertEqual((code, asked), (64, []))
        assert_contract("haprion-cert-issue", out)
