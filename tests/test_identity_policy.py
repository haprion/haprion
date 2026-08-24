from __future__ import annotations

import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from haproxy_mgmt.cli.render_sysusers import main as render_sysusers_main
from haproxy_mgmt.config import ConfigError
from haproxy_mgmt.identity_policy import load_identity_policy, render_sysusers

BASE = Path(__file__).resolve().parents[1]


class IdentityPolicyTests(unittest.TestCase):
    def write_policy(self, directory: Path, content: str) -> Path:
        path = directory / "identity-policy.yaml"
        path.write_text(content, encoding="utf-8")
        return path

    def test_generic_example_and_rendered_membership(self):
        policy = load_identity_policy(
            BASE / "examples" / "identity-policy.yaml", require_secure=False
        )
        self.assertEqual(policy.account("worker"), "svc-worker")
        rendered = render_sysusers(policy)
        self.assertIn("g svc-mgmt -\n", rendered)
        self.assertIn('u! svc-web - "HAProxy Manager web service"', rendered)
        self.assertIn("m svc-worker svc-mgmt\n", rendered)
        self.assertNotIn("m svc-web svc-mgmt", rendered)
        self.assertNotIn("m svc-poller svc-mgmt", rendered)

    def test_unknown_role_lookup_is_rejected(self):
        policy = load_identity_policy(
            BASE / "examples" / "identity-policy.yaml", require_secure=False
        )
        with self.assertRaisesRegex(ConfigError, "unknown application role"):
            policy.account("operator")

    def test_missing_unknown_duplicate_and_reserved_accounts_are_rejected(self):
        invalid = (
            (
                "schema_version: 1\naccount_prefix: svc-\nconfig_group: svc-mgmt\nroles:\n"
                "  web: svc-web\n  worker: svc-worker\n",
                "missing role",
            ),
            (
                "schema_version: 1\naccount_prefix: svc-\nconfig_group: svc-mgmt\nroles:\n"
                "  web: svc-web\n  worker: svc-worker\n  poller: svc-poller\n  extra: svc-app\n",
                "unknown field",
            ),
            (
                "schema_version: 1\naccount_prefix: svc-\nconfig_group: svc-mgmt\nroles:\n"
                "  web: svc-app\n  worker: svc-app\n  poller: svc-poller\n",
                "all be distinct",
            ),
            (
                "schema_version: 1\naccount_prefix: svc-\nconfig_group: svc-mgmt\nroles:\n"
                "  web: root\n  worker: svc-worker\n  poller: svc-poller\n",
                "reserved account",
            ),
            (
                "schema_version: true\naccount_prefix: svc-\nconfig_group: svc-mgmt\nroles:\n"
                "  web: svc-web\n  worker: svc-worker\n  poller: svc-poller\n",
                "schema_version",
            ),
            (
                "schema_version: 1\naccount_prefix: svc-\nconfig_group: sudo\nroles:\n"
                "  web: svc-web\n  worker: svc-worker\n  poller: svc-poller\n",
                "account_prefix",
            ),
        )
        for content, message in invalid:
            with tempfile.TemporaryDirectory() as raw:
                path = self.write_policy(Path(raw), content)
                with (
                    self.subTest(message=message),
                    self.assertRaisesRegex(ConfigError, message),
                ):
                    load_identity_policy(path, require_secure=False)

    def test_cli_renders_and_reports_invalid_policy(self):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = render_sysusers_main(
                ["--policy", str(BASE / "examples" / "identity-policy.yaml")],
                require_secure=False,
            )
        self.assertEqual((code, stderr.getvalue()), (0, ""))
        self.assertEqual(
            stdout.getvalue(),
            render_sysusers(
                load_identity_policy(
                    BASE / "examples" / "identity-policy.yaml", require_secure=False
                )
            ),
        )

        with tempfile.TemporaryDirectory() as raw:
            path = self.write_policy(Path(raw), "schema_version: 2\n")
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                code = render_sysusers_main(["--policy", str(path)], require_secure=False)
        self.assertEqual(code, 65)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("ERROR:", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
