"""`--json` answers a refusal too (Fas 23 review, second pass, F1).

A command a playbook reads with `stdout | from_json` must print its one
document when it stops early - not as root, a policy it cannot read, a helper
that never answered - not leave stdout empty for a template error to report.
"""

from __future__ import annotations

import io
import subprocess
import unittest
from pathlib import Path

from haprion.cli import cert_delete, cert_target, state_backup
from tests.contract_schema import assert_contract


def silent(argv: list[str], _request: str) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(argv, 1, "", "sudo: a password is required\n")


class EveryRefusalIsADocument(unittest.TestCase):
    def test_state_backup(self) -> None:
        for require_root, code in ((True, 77), (False, 68)):
            with self.subTest(code=code):
                out = io.StringIO()
                returned = state_backup.main(
                    ["-c", "alpha", "--json"],
                    output_stream=out,
                    error_stream=io.StringIO(),
                    require_root=require_root,
                    policy_path=Path("/nonexistent/policy.yaml"),
                )
                self.assertEqual(returned, code)
                self.assertEqual(assert_contract("haprion-backup-run", out.getvalue())["ok"], False)

    def test_the_certificate_clients_without_a_helper_answer(self) -> None:
        for main, argv, schema in (
            (cert_delete.main, ["x.example.com", "--json"], "haprion-cert-delete"),
            (
                cert_target.main,
                ["add", "x.example.com", "--cluster", "alpha", "--json"],
                "haprion-cert-target",
            ),
        ):
            with self.subTest(schema):
                out = io.StringIO()
                returned = main(argv, run=silent, stream_out=out, stream_err=io.StringIO())
                self.assertEqual(returned, 1)
                answer = assert_contract(schema, out.getvalue())
                self.assertIn("password", answer["error"]["message"])
