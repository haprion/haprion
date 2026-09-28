"""The renewal timer reconstructs profile environments per lineage."""

from __future__ import annotations

import unittest
from unittest import mock

import yaml

from haproxy_mgmt import cert_issue, dns_profiles, dns_provider_catalog
from haproxy_mgmt.cli import cert_renew
from haproxy_mgmt.config import load_policy, load_runtime_config
from haproxy_mgmt.dns_profile_keys import generate, render_private_key
from tests.test_cert_publish import Fixture


class RenewalInvocations(Fixture):
    def setUp(self) -> None:
        super().setUp()
        self.profile_dir = self.root / "profiles"
        self.profile_dir.mkdir(mode=0o700)
        policy_path = self.write_config(
            {
                "example.com": {
                    "source": {"kind": "acme", "dns_profile": "aws-main"},
                    "clusters": ["alpha"],
                },
                "legacy.example": {
                    "source": {"kind": "acme"},
                    "clusters": ["alpha"],
                },
            }
        )
        private, public = generate()
        private_path = self.root / "profile.key"
        private_path.write_text(render_private_key(private), encoding="utf-8")
        private_path.chmod(0o600)
        document = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
        document["acme"] = {
            "certbot": "/opt/certbot/bin/certbot",
            "dns_profiles": {
                "directory": str(self.profile_dir),
                "private_keys": [str(private_path)],
            },
        }
        policy_path.write_text(yaml.safe_dump(document), encoding="utf-8")
        self.policy = load_policy(policy_path, require_secure=False)
        self.runtime = load_runtime_config(self.policy, require_secure=False)
        ciphertext = dns_profiles.seal_profile(
            public,
            profile_id="aws-main",
            provider_id="route53",
            revision=1,
            fields={"access_key_id": "AKIAEXAMPLE", "secret_access_key": "secret-value"},
        )
        opened = dns_profiles.open_profile(
            private,
            ciphertext,
            profile_id="aws-main",
            provider_id="route53",
            revision=1,
        )
        dns_profiles.materialize(
            self.policy.acme.dns_profiles,
            opened,
            require_secure=False,  # type: ignore[union-attr]
        )
        self.renewal = self.root / "renewal"
        self.renewal.mkdir()
        for lineage in ("example.com", "legacy.example", "orphan.example"):
            (self.renewal / f"{lineage}.conf").write_text(
                "[renewalparams]\nauthenticator = dns-cloudflare\n", encoding="utf-8"
            )

    def test_each_lineage_is_bounded_and_only_route53_gets_its_environment(self) -> None:
        commands = cert_renew.invocations(
            self.policy,
            self.runtime,
            renewal_directory=self.renewal,
            binary="/new/certbot",
            dry_run=True,
            run_deploy_hooks=True,
            require_secure=False,
        )

        self.assertEqual(
            [command.lineage for command in commands],
            [
                "example.com",
                "legacy.example",
                "orphan.example",
            ],
        )
        profiled = commands[0]
        self.assertEqual(
            profiled.environment["AWS_SHARED_CREDENTIALS_FILE"],
            str(self.profile_dir / "aws-main"),
        )
        self.assertIn("secret-value", profiled.redactions)
        self.assertEqual(profiled.arguments[0], "/new/certbot")
        self.assertIn("--cert-name", profiled.arguments)
        self.assertIn("--dry-run", profiled.arguments)
        self.assertIn("--run-deploy-hooks", profiled.arguments)
        self.assertNotIn("AWS_SHARED_CREDENTIALS_FILE", commands[1].environment)
        self.assertNotIn("AWS_SHARED_CREDENTIALS_FILE", commands[2].environment)

    def test_the_nightly_renewal_waits_as_long_as_the_profile_s_provider(self) -> None:
        #
        # Route53's own wait is short, so the budget is made to depend on it
        # visibly: the profiled lineage must carry what its provider asks for.
        #
        with mock.patch.object(cert_issue, "certbot_timeout", lambda seconds: 5000 + seconds):
            commands = cert_renew.invocations(
                self.policy, self.runtime, renewal_directory=self.renewal, require_secure=False
            )
        route53 = dns_provider_catalog.provider_by_id("route53").propagation_seconds
        self.assertEqual(commands[0].timeout, 5000 + route53)
        self.assertEqual(commands[1].timeout, cert_issue.CERTBOT_TIMEOUT)

    def test_scrubbing_is_literal_and_longest_first(self) -> None:
        self.assertEqual(
            cert_renew._scrub("secret-value and secret", ("secret", "secret-value")),
            "[redacted] and [redacted]",
        )


if __name__ == "__main__":
    unittest.main()
