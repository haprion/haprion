"""The renewal timer reconstructs profile environments per lineage."""

from __future__ import annotations

import contextlib
import io
import unittest
from dataclasses import replace
from typing import Any
from unittest import mock

import yaml

from haprion import cert_issue, dns_profiles, dns_provider_catalog
from haprion.cli import cert_renew
from haprion.config import ConfigError, load_policy, load_runtime_config
from haprion.dns_profile_keys import generate, render_private_key
from tests.test_cert_publish import Fixture


def _commands(*args: Any, **kwargs: Any) -> tuple[cert_renew.RenewalInvocation, ...]:
    renewals = cert_renew.invocations(*args, **kwargs)
    assert renewals.problems == ()  # every lineage here can be prepared
    return renewals.commands


class TheHelp(unittest.TestCase):
    def test_it_says_the_ndes_certificates_are_renewed_too(self) -> None:
        """Review 26-10-24, 16-09: someone after an NDES renewal passed the command by."""

        shown = io.StringIO()
        with contextlib.redirect_stdout(shown), self.assertRaises(SystemExit):
            cert_renew.main(["--help"])
        help_text = " ".join(shown.getvalue().split())
        self.assertIn("every certbot lineage that is due, then every NDES certificate", help_text)
        self.assertIn("NDES", cert_renew.__doc__ or "")


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
        assert self.policy.acme is not None and self.policy.acme.dns_profiles is not None
        dns_profiles.materialize(self.policy.acme.dns_profiles, opened, require_secure=False)
        self.renewal = self.root / "renewal"
        self.renewal.mkdir()
        for lineage in ("example.com", "legacy.example", "orphan.example"):
            (self.renewal / f"{lineage}.conf").write_text(
                "[renewalparams]\nauthenticator = dns-cloudflare\n", encoding="utf-8"
            )

    def test_each_lineage_is_bounded_and_only_route53_gets_its_environment(self) -> None:
        commands = _commands(
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
            commands = _commands(
                self.policy, self.runtime, renewal_directory=self.renewal, require_secure=False
            )
        route53 = dns_provider_catalog.provider_by_id("route53").propagation_seconds
        self.assertEqual(commands[0].timeout, 5000 + route53)
        self.assertEqual(commands[1].timeout, cert_issue.CERTBOT_TIMEOUT)

    def test_a_host_where_certbot_never_issued_has_nothing_to_renew(self) -> None:
        """A new manager has no renewal directory; the setup step's dry run
        and the nightly timer stopped on it (26-10-14)."""

        commands = _commands(
            self.policy,
            self.runtime,
            renewal_directory=self.root / "absent",
            require_secure=False,
        )
        self.assertEqual(commands, ())

    def test_one_lineage_that_cannot_be_prepared_spares_the_others_and_ndes(self) -> None:
        """Logic review 26-10-22, L3: one unreadable DNS profile stopped the
        whole pass before certbot ran for any lineage and before NDES."""

        (self.profile_dir / "aws-main").unlink()
        ran: list[str] = []

        def certbot(arguments: tuple[str, ...], **_: object) -> mock.Mock:
            ran.append(arguments[arguments.index("--cert-name") + 1])
            return mock.Mock(returncode=0, stdout="", stderr="")

        errors = io.StringIO()
        with (
            mock.patch("os.geteuid", return_value=0),
            mock.patch.object(cert_renew, "load_policy", return_value=self.policy),
            mock.patch.object(cert_renew, "load_runtime_config", return_value=self.runtime),
            mock.patch.object(cert_renew, "RENEWAL_DIRECTORY", self.renewal),
            mock.patch("subprocess.run", side_effect=certbot),
            mock.patch.object(cert_renew, "renew_ndes", return_value=False) as ndes,
            contextlib.redirect_stderr(errors),
        ):
            code = cert_renew.main([])

        self.assertEqual(ran, ["legacy.example", "orphan.example"])
        ndes.assert_called_once()
        self.assertEqual(code, 1)
        self.assertIn("'example.com' could not be prepared", errors.getvalue())

    def test_no_registry_still_stops_the_pass(self) -> None:
        renewals = None
        with self.assertRaises(ConfigError):
            renewals = cert_renew.invocations(
                self.policy,
                replace(self.runtime, registry=None),
                renewal_directory=self.renewal,
                require_secure=False,
            )
        self.assertIsNone(renewals)

    def test_scrubbing_is_literal_and_longest_first(self) -> None:
        self.assertEqual(
            cert_renew._scrub("secret-value and secret", ("secret", "secret-value")),
            "[redacted] and [redacted]",
        )


if __name__ == "__main__":
    unittest.main()
