"""Issuing: what reaches certbot, what the registry gets, and the order of the three.

certbot is a stand-in that records its arguments and writes a real key and
certificate where certbot would, so the publish that follows runs the real
checks. What is held here: the argument list is built from the request and
the policy alone; a wildcard needs DNS-01; a failed certbot leaves the
registry untouched and returns certbot's own words; a successful one adds
exactly one entry, keeps the others and the file's ownership and mode, and
is followed by a publish to exactly the named targets and a rollout of the
named clusters.
"""

from __future__ import annotations

import io
import json
import os
import stat
import tempfile
import unittest
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any
from unittest import mock

import yaml

from haprion import cert_issue, cert_pending, dns_provider_catalog, exit_codes, ui_interface
from haprion.cert_issue import CertbotResult, IssueError, certbot_arguments, parse_domain
from haprion.cli import cert_issue as command
from haprion.cli import cert_issue_helper, cert_renew
from haprion.config import load_policy, load_runtime_config
from tests.contract_schema import assert_contract
from tests.test_cert_publish import Fixture, issue


class FakeCertbot:
    """Writes a lineage where certbot would and remembers what it was told."""

    def __init__(self, live: Path, *, returncode: int = 0, output: str = "") -> None:
        self.live = live
        self.returncode = returncode
        self.output = output
        self.calls: list[list[str]] = []
        self.environments: list[dict[str, str]] = []
        self.timeouts: list[int] = []

    def __call__(
        self, arguments: Sequence[str], environment: Mapping[str, str], timeout: int
    ) -> CertbotResult:
        self.calls.append(list(arguments))
        self.environments.append(dict(environment))
        self.timeouts.append(timeout)
        if self.returncode == 0:
            name = arguments[list(arguments).index("--cert-name") + 1]
            issue(self.live / name, name)
        return CertbotResult(self.returncode, self.output)


class IssueFixture(Fixture):
    def policy_with_acme(self, certificates: dict[str, dict[str, object]]) -> Path:
        policy_path = self.write_config(certificates)
        document = yaml.safe_load(policy_path.read_text())
        document["acme"] = {
            "dns_cloudflare_credentials": str(self.root / "cloudflare.ini"),
            "webroot": str(self.root / "webroot"),
        }
        policy_path.write_text(yaml.safe_dump(document))
        self.registry_path = self.root / "certificates.yaml"
        self.registry_path.chmod(0o640)
        return policy_path

    def run_issue(
        self, policy_path: Path, *argv: str, certbot: FakeCertbot | None = None
    ) -> tuple[int, str, str, list[str]]:
        out, err = io.StringIO(), io.StringIO()
        deployed: list[str] = []

        def deployer(cluster: str) -> int:
            deployed.append(cluster)
            return 0

        code = command.main(
            list(argv),
            policy_path=policy_path,
            output_stream=out,
            error_stream=err,
            require_secure=False,
            require_root=False,
            certbot=certbot or FakeCertbot(self.live),
            deployer=deployer,
            live=self.live,
            store=self.store,
            lock_path=self.lock,
        )
        return code, out.getvalue(), err.getvalue(), deployed


class TheRequest(unittest.TestCase):
    def test_domain_forms(self) -> None:
        self.assertEqual(parse_domain("example.com"), ("example.com", ("example.com",), False))
        self.assertEqual(
            parse_domain("*.example.com"),
            ("example.com", ("*.example.com", "example.com"), True),
        )
        for bad in ("Example.com", "example", "-x.example.com", "*.*.example.com", "a b.com", ""):
            with self.assertRaises(IssueError, msg=bad):
                parse_domain(bad)


class WhatReachesCertbot(IssueFixture):
    def test_the_argument_list_is_fixed_and_the_policy_supplies_the_secret_paths(self) -> None:
        policy_path = self.policy_with_acme(
            {"example.net": {"source": {"kind": "acme"}, "clusters": ["alpha"]}}
        )
        policy = load_policy(policy_path, require_secure=False)
        runtime = load_runtime_config(policy, require_secure=False)
        request = cert_issue.build_request(
            domain="*.example.com",
            method="dns-01",
            clusters=["alpha"],
            receivers=[],
            runtime=runtime,
        )

        arguments = certbot_arguments(request, policy)

        self.assertEqual(
            arguments,
            [
                "/usr/bin/certbot",
                "certonly",
                "--non-interactive",
                "--no-directory-hooks",
                "--cert-name",
                "example.com",
                "--key-type",
                "ecdsa",
                "--dns-cloudflare",
                "--dns-cloudflare-credentials",
                str(self.root / "cloudflare.ini"),
                "--dns-cloudflare-propagation-seconds",
                "30",
                "-d",
                "*.example.com",
                "-d",
                "example.com",
            ],
        )
        http = cert_issue.build_request(
            domain="www.example.com",
            method="http-01",
            clusters=["alpha"],
            receivers=[],
            runtime=runtime,
        )
        self.assertIn("--webroot", certbot_arguments(http, policy))
        self.assertIn(str(self.root / "webroot"), certbot_arguments(http, policy))

    def test_an_exportable_certificate_is_one_name_no_target_and_an_rsa_key(self) -> None:
        """B255: it goes to a BMC or a printer, and several take no EC key."""

        policy_path = self.policy_with_acme(
            {"example.net": {"source": {"kind": "acme"}, "clusters": ["alpha"]}}
        )
        policy = load_policy(policy_path, require_secure=False)
        runtime = load_runtime_config(policy, require_secure=False)
        request = cert_issue.build_request(
            domain="bmc01.example.com",
            method="dns-01",
            clusters=[],
            receivers=[],
            runtime=runtime,
            exportable=True,
        )
        arguments = certbot_arguments(request, policy)

        self.assertTrue(request.exportable)
        self.assertEqual(arguments[arguments.index("--key-type") + 1], "rsa")
        self.assertEqual(arguments[arguments.index("--rsa-key-size") + 1], "2048")
        for domain, clusters in (("*.example.com", []), ("bmc01.example.com", ["alpha"])):
            with self.subTest(domain=domain, clusters=clusters), self.assertRaises(IssueError):
                cert_issue.build_request(
                    domain=domain,
                    method="dns-01",
                    clusters=clusters,
                    receivers=[],
                    runtime=runtime,
                    exportable=True,
                )

    def test_the_binary_comes_from_the_policy_and_leads_the_command(self) -> None:
        policy_path = self.policy_with_acme(
            {"example.net": {"source": {"kind": "acme"}, "clusters": ["alpha"]}}
        )
        document = yaml.safe_load(policy_path.read_text())
        document["acme"]["certbot"] = "/opt/example-certbot/venv/bin/certbot"
        policy_path.write_text(yaml.safe_dump(document))
        policy = load_policy(policy_path, require_secure=False)
        runtime = load_runtime_config(policy, require_secure=False)
        request = cert_issue.build_request(
            domain="www.example.com",
            method="http-01",
            clusters=["alpha"],
            receivers=[],
            runtime=runtime,
        )
        arguments = certbot_arguments(request, policy)
        self.assertEqual(arguments[0], "/opt/example-certbot/venv/bin/certbot")
        self.assertEqual(arguments[1], "certonly")

    def test_a_method_without_its_setting_is_refused_by_name(self) -> None:
        policy_path = self.write_config(
            {"example.net": {"source": {"kind": "acme"}, "clusters": ["alpha"]}}
        )
        code, out, err, _ = self.run_issue(
            policy_path, "--domain", "www.example.com", "--method", "http-01", "--cluster", "alpha"
        )
        self.assertEqual(code, 78)
        self.assertIn("acme.webroot", err)

    def test_a_materialized_profile_selects_the_plugin_file_and_propagation(self) -> None:
        policy_path = self.policy_with_acme(
            {"example.net": {"source": {"kind": "acme"}, "clusters": ["alpha"]}}
        )
        document = yaml.safe_load(policy_path.read_text())
        profile_dir = self.root / "profiles"
        profile_dir.mkdir()
        document["acme"]["dns_profiles"] = {
            "directory": str(profile_dir),
            "private_keys": [str(self.root / "unused.key")],
        }
        policy_path.write_text(yaml.safe_dump(document))
        policy = load_policy(policy_path, require_secure=False)
        assert policy.acme is not None and policy.acme.dns_profiles is not None
        from haprion.dns_profiles import OpenedProfile, materialize

        materialize(
            policy.acme.dns_profiles,
            OpenedProfile(
                profile_id="cf-main",
                provider_id="cloudflare",
                schema_version=1,
                key_id="0123456789abcdef",
                revision=1,
                fields={"api_token": "token-example"},
                credentials="dns_cloudflare_api_token = token-example\n",
            ),
            require_secure=False,
        )
        certbot = FakeCertbot(self.live)

        code, _, errors, _ = self.run_issue(
            policy_path,
            "--domain",
            "new.example",
            "--method",
            "dns-01",
            "--dns-profile",
            "cf-main",
            "--cluster",
            "alpha",
            "--json",
            certbot=certbot,
        )

        self.assertEqual(code, 0, errors)
        arguments = certbot.calls[0]
        self.assertIn("--dns-cloudflare", arguments)
        self.assertIn("--dns-cloudflare-credentials", arguments)
        self.assertIn(str(profile_dir / "cf-main"), arguments)
        self.assertIn("--dns-cloudflare-propagation-seconds", arguments)
        registry = yaml.safe_load(self.registry_path.read_text())
        self.assertEqual(
            registry["certificates"]["new.example"]["source"]["dns_profile"], "cf-main"
        )

    def test_a_slow_provider_gets_its_wait_plus_the_work_around_it(self) -> None:
        #
        # Loopia waits 900 seconds for propagation. Under the old fixed 600
        # certbot was killed during the wait, every time.
        #
        policy_path = self.policy_with_acme(
            {"example.net": {"source": {"kind": "acme"}, "clusters": ["alpha"]}}
        )
        document = yaml.safe_load(policy_path.read_text())
        profile_dir = self.root / "profiles"
        profile_dir.mkdir()
        document["acme"]["dns_profiles"] = {
            "directory": str(profile_dir),
            "private_keys": [str(self.root / "unused.key")],
        }
        policy_path.write_text(yaml.safe_dump(document))
        policy = load_policy(policy_path, require_secure=False)
        assert policy.acme is not None and policy.acme.dns_profiles is not None
        from haprion.dns_profiles import OpenedProfile, materialize

        fields = {"user": "user@loopiaapi", "password": "example"}
        materialize(
            policy.acme.dns_profiles,
            OpenedProfile(
                profile_id="loopia-main",
                provider_id="loopia",
                schema_version=1,
                key_id="0123456789abcdef",
                revision=1,
                fields=fields,
                credentials=dns_provider_catalog.render_credentials(
                    dns_provider_catalog.provider_by_id("loopia"), fields
                ),
            ),
            require_secure=False,
        )
        certbot = FakeCertbot(self.live)

        code, _, errors, _ = self.run_issue(
            policy_path,
            "--domain",
            "new.example",
            "--method",
            "dns-01",
            "--dns-profile",
            "loopia-main",
            "--cluster",
            "alpha",
            "--json",
            certbot=certbot,
        )

        self.assertEqual(code, 0, errors)
        self.assertEqual(certbot.timeouts, [900 + cert_issue.CERTBOT_WORK_SECONDS])

    def test_every_catalogue_provider_s_wait_fits_inside_its_budget(self) -> None:
        for provider in dns_provider_catalog.load_catalog():
            with self.subTest(provider=provider.id):
                budget = cert_issue.certbot_timeout(provider.propagation_seconds)
                self.assertGreaterEqual(
                    budget - provider.propagation_seconds, cert_issue.CERTBOT_WORK_SECONDS
                )
                self.assertLessEqual(budget, cert_issue.longest_certbot_timeout())

    def test_http_01_keeps_the_standing_budget(self) -> None:
        policy_path = self.policy_with_acme(
            {"example.net": {"source": {"kind": "acme"}, "clusters": ["alpha"]}}
        )
        certbot = FakeCertbot(self.live)
        code, _, errors, _ = self.run_issue(
            policy_path, "--domain", "www.example.com", "--method", "http-01",
            "--cluster", "alpha", "--json", certbot=certbot,
        )  # fmt: skip
        self.assertEqual(code, 0, errors)
        self.assertEqual(certbot.timeouts, [cert_issue.CERTBOT_TIMEOUT])

    def test_profile_secrets_are_removed_from_certbot_diagnostics(self) -> None:
        policy_path = self.policy_with_acme(
            {"example.net": {"source": {"kind": "acme"}, "clusters": ["alpha"]}}
        )
        document = yaml.safe_load(policy_path.read_text())
        profile_dir = self.root / "profiles"
        profile_dir.mkdir()
        document["acme"]["dns_profiles"] = {
            "directory": str(profile_dir),
            "private_keys": [str(self.root / "unused.key")],
        }
        policy_path.write_text(yaml.safe_dump(document))
        policy = load_policy(policy_path, require_secure=False)
        assert policy.acme is not None and policy.acme.dns_profiles is not None
        from haprion.dns_profiles import OpenedProfile, materialize

        materialize(
            policy.acme.dns_profiles,
            OpenedProfile(
                "cf-main",
                "cloudflare",
                1,
                "0123456789abcdef",
                1,
                {"api_token": "token-example"},
                "dns_cloudflare_api_token = token-example\n",
            ),
            require_secure=False,
        )
        certbot = FakeCertbot(self.live, returncode=1, output="provider rejected token-example")

        code, out, errors, _ = self.run_issue(
            policy_path,
            "--domain",
            "new.example",
            "--method",
            "dns-01",
            "--dns-profile",
            "cf-main",
            "--cluster",
            "alpha",
            "--json",
            certbot=certbot,
        )

        self.assertEqual(code, 1)
        self.assertNotIn("token-example", out + errors)
        self.assertIn("[redacted]", out)

    def test_refusals_before_certbot_is_called(self) -> None:
        policy_path = self.policy_with_acme(
            {"example.net": {"source": {"kind": "acme"}, "clusters": ["alpha"]}}
        )
        certbot = FakeCertbot(self.live)
        cases = [
            (
                ["--domain", "*.example.com", "--method", "http-01", "--cluster", "alpha"],
                "wildcard",
            ),
            (["--domain", "example.com", "--method", "dns-01"], "at least one target"),
            (
                ["--domain", "example.com", "--method", "dns-01", "--cluster", "gamma"],
                "unknown cluster",
            ),
            (
                ["--domain", "example.com", "--method", "dns-01", "--receiver", "lb-99"],
                "unregistered",
            ),
            (
                ["--domain", "example.net", "--method", "dns-01", "--cluster", "alpha"],
                "already in the registry",
            ),
            (
                ["--domain", "example.com", "--method", "tls-alpn", "--cluster", "alpha"],
                "method must be",
            ),
        ]
        for argv, expected in cases:
            code, _, err, deployed = self.run_issue(policy_path, *argv, "--json", certbot=certbot)
            self.assertEqual(code, 64, argv)
            self.assertIn(expected, err, argv)
            self.assertEqual(deployed, [])
        self.assertEqual(certbot.calls, [], "nothing may reach certbot for a refused request")

        code, out, _, _ = self.run_issue(policy_path, "--domain", "x.example.com")
        self.assertEqual(code, 64)
        self.assertIn("Usage:", out)


class WhenCertbotFails(IssueFixture):
    def test_its_words_are_the_error_and_the_registry_is_untouched(self) -> None:
        policy_path = self.policy_with_acme(
            {"example.net": {"source": {"kind": "acme"}, "clusters": ["alpha"]}}
        )
        before = self.registry_path.read_bytes()
        certbot = FakeCertbot(
            self.live,
            returncode=1,
            output="Error creating TXT record: the token does not have permission for this zone",
        )

        code, out, err, deployed = self.run_issue(
            policy_path,
            "--domain",
            "example.com",
            "--method",
            "dns-01",
            "--cluster",
            "alpha",
            "--json",
            certbot=certbot,
        )

        self.assertEqual(code, 1)
        document = json.loads(out)
        self.assertEqual(document["outcome"], "failed")
        self.assertEqual(document["error"]["code"], "certbot_failed")
        #
        # The output is evidence, not the sentence: it lives whole under
        # `diagnostics`, where the interface reads a compiler's answer from,
        # and the message says only what certbot's exit was.
        #
        self.assertEqual(document["error"]["message"], "certbot exited 1 after 0s")
        details = document["error"]["details"]
        self.assertIn("the token does not have permission", details["diagnostics"])
        self.assertEqual(details["certbot_exit_code"], 1)
        self.assertIn("the token does not have permission", err)
        self.assertEqual(self.registry_path.read_bytes(), before)
        self.assertEqual(deployed, [])
        self.assertEqual(list(self.dist.iterdir()), [])


class WhenCertbotSucceeds(IssueFixture):
    def test_registry_publish_and_rollout_in_that_order(self) -> None:
        issue(self.live / "example.net", "example.net")
        policy_path = self.policy_with_acme(
            {"example.net": {"source": {"kind": "acme"}, "clusters": ["alpha"]}}
        )
        self.registry_path.chmod(0o640)
        mode_before = stat.S_IMODE(self.registry_path.stat().st_mode)
        certbot = FakeCertbot(self.live)

        code, out, err, deployed = self.run_issue(
            policy_path,
            "--domain",
            "*.example.com",
            "--method",
            "dns-01",
            "--cluster",
            "alpha",
            "--receiver",
            "lb-01",
            "--json",
            certbot=certbot,
        )

        self.assertEqual(code, 0, err)
        document = json.loads(out)
        self.assertEqual(document["operation"], "cert_issue")
        self.assertEqual(document["outcome"], "done")
        result = document["result"]
        self.assertEqual(result["id"], "example.com")
        self.assertEqual(result["domains"], ["*.example.com", "example.com"])
        self.assertEqual(result["targets"], {"clusters": ["alpha"], "receivers": ["lb-01"]})
        self.assertIsInstance(result["total_seconds"], float)
        self.assertGreaterEqual(result["total_seconds"], result["certbot_seconds"])

        # The registry: one entry added, the existing one kept, the file's mode kept.
        registry = yaml.safe_load(self.registry_path.read_text())
        self.assertEqual(
            registry["certificates"]["example.com"],
            {"source": {"kind": "acme"}, "clusters": ["alpha"], "receivers": ["lb-01"]},
        )
        self.assertIn("example.net", registry["certificates"])
        self.assertIn("lb-01", registry["receivers"])
        self.assertEqual(stat.S_IMODE(self.registry_path.stat().st_mode), mode_before)
        self.assertTrue(self.registry_path.read_text().startswith("# The certificate registry"))

        # Published to exactly the named targets; the pre-existing certificate untouched.
        self.assertEqual(self.held(), {"alpha": ["example.com.pem"]})
        held = self.receiver_dir / "example.com"
        self.assertEqual([p.name for p in self.receiver_dir.iterdir()], ["example.com"])
        self.assertEqual(sorted(p.name for p in held.iterdir()), ["fullchain.pem", "privkey.pem"])
        [published] = result["publish"]["certificates"]
        self.assertEqual(published["status"], "published")
        self.assertEqual(deployed, ["alpha"])

        # The engine reads the rewritten registry the same way it read the written one.
        runtime = load_runtime_config(
            load_policy(policy_path, require_secure=False), require_secure=False
        )
        self.assertEqual(runtime.clusters["alpha"].certificate_ids, ("example.net", "example.com"))

    def test_a_registry_that_cannot_take_the_entry_says_certbot_already_issued(self) -> None:
        """The one failure that leaves something behind. Seen in production as
        a sandbox that opened the registry file but not its directory, so the
        temporary beside it could not be created - and as a raw traceback."""

        issue(self.live / "example.net", "example.net")
        policy_path = self.policy_with_acme(
            {"example.net": {"source": {"kind": "acme"}, "clusters": ["alpha"]}}
        )
        self.registry_path.chmod(0o640)
        certbot = FakeCertbot(self.live)
        real_mkstemp = tempfile.mkstemp

        def refused(*args: Any, **kwargs: Any) -> tuple[int, str]:
            if str(kwargs.get("dir")) == str(self.registry_path.parent):
                raise OSError(30, "Read-only file system")
            made: tuple[int, str] = real_mkstemp(*args, **kwargs)
            return made

        with mock.patch.object(tempfile, "mkstemp", refused):
            code, out, err, deployed = self.run_issue(
                policy_path,
                "--domain",
                "www.example.com",
                "--method",
                "dns-01",
                "--cluster",
                "alpha",
                "--json",
                certbot=certbot,
            )

        self.assertEqual(code, 78, err)
        document = json.loads(out)
        self.assertEqual(document["outcome"], "failed")
        self.assertEqual(document["error"]["code"], "dependency_unavailable")
        self.assertIn("certbot issued 'www.example.com'", document["error"]["message"])
        self.assertIn("Register the lineage by hand", document["error"]["message"])
        self.assertTrue((self.live / "www.example.com").exists())
        self.assertNotIn("www.example.com", self.registry_path.read_text())
        self.assertEqual(deployed, [])

    def test_a_due_note_that_cannot_be_written_is_said(self) -> None:
        """Review 26-10-24, 13-06: the publish's warning reaches the answer."""

        issue(self.live / "example.net", "example.net")
        policy_path = self.policy_with_acme(
            {"example.net": {"source": {"kind": "acme"}, "clusters": ["alpha"]}}
        )
        with mock.patch.object(cert_pending.Ledger, "keep", side_effect=OSError("disk full")):
            code, out, err, _ = self.run_issue(
                policy_path,
                "--domain",
                "www.example.com",
                "--method",
                "dns-01",
                "--cluster",
                "alpha",
                "--json",
            )

        self.assertEqual(code, 0, err)
        document = assert_contract("haprion-cert-issue", out)
        self.assertEqual(document["outcome"], "done")
        self.assertEqual(
            [warning["code"] for warning in document["warnings"]], ["pending_unrecorded"]
        )

    def test_an_entry_registered_while_certbot_ran_is_not_written_over(self) -> None:
        """Review 26-10-24, 08-06: the ID is checked again under the registry's lock."""

        issue(self.live / "example.net", "example.net")
        policy_path = self.policy_with_acme(
            {"example.net": {"source": {"kind": "acme"}, "clusters": ["alpha"]}}
        )
        self.registry_path.chmod(0o640)
        imported = {"source": {"kind": "import"}, "clusters": ["alpha"]}

        registry_path = self.registry_path

        class ImportMeanwhile(FakeCertbot):
            def __call__(
                self, arguments: Sequence[str], environment: Mapping[str, str], timeout: int
            ) -> CertbotResult:
                registry = yaml.safe_load(registry_path.read_text())
                registry["certificates"]["www.example.com"] = imported
                registry_path.write_text(yaml.safe_dump(registry))
                return super().__call__(arguments, environment, timeout)

        code, out, err, deployed = self.run_issue(
            policy_path,
            "--domain",
            "www.example.com",
            "--method",
            "dns-01",
            "--cluster",
            "alpha",
            "--json",
            certbot=ImportMeanwhile(self.live),
        )

        document = assert_contract("haprion-cert-issue", out)
        self.assertEqual(document["outcome"], "blocked", err)
        self.assertEqual(document["error"]["code"], "already_exists")
        # Review 26-10-25, 1-04: not "register it by hand", which would write over it.
        self.assertIn(
            "sudo certbot delete --cert-name www.example.com", document["error"]["message"]
        )
        self.assertNotIn("by hand", document["error"]["message"])
        self.assertEqual(code, exit_codes.BLOCKED)
        registry = yaml.safe_load(self.registry_path.read_text())
        self.assertEqual(registry["certificates"]["www.example.com"], imported)
        self.assertEqual(deployed, [])

    def test_an_interface_certificate_for_another_name_never_reaches_certbot(self) -> None:
        """Review 26-10-24, 15-03: certbot issued it, then the install refused the name."""

        policy_path = self.policy_with_acme(
            {"example.net": {"source": {"kind": "acme"}, "clusters": ["alpha"]}}
        )
        config = self.root / "ui-tls.conf"
        config.write_text(
            f"TLS_CERT={self.root / 'ui.crt'}\nTLS_KEY={self.root / 'ui.key'}\n"
            "SERVER_NAME=mgr.example.net\n"
        )
        certbot = FakeCertbot(self.live)
        with mock.patch.object(ui_interface, "UI_TLS_CONFIG", config):
            code, out, _, _ = self.run_issue(
                policy_path,
                "--domain",
                "www.example.com",
                "--method",
                "dns-01",
                "--interface",
                "--json",
                certbot=certbot,
            )

        self.assertEqual(code, exit_codes.USAGE)
        document = assert_contract("haprion-cert-issue", out)
        self.assertEqual(document["error"]["code"], "bad_input")
        self.assertIn("mgr.example.net", document["error"]["message"])
        self.assertEqual(certbot.calls, [])

    def test_an_existing_lineage_is_not_issued_again(self) -> None:
        issue(self.live / "example.com", "example.com")
        policy_path = self.policy_with_acme(
            {"example.net": {"source": {"kind": "acme"}, "clusters": ["alpha"]}}
        )
        certbot = FakeCertbot(self.live)

        code, _, err, _ = self.run_issue(
            policy_path,
            "--domain",
            "example.com",
            "--method",
            "dns-01",
            "--cluster",
            "alpha",
            certbot=certbot,
        )

        self.assertEqual(code, 64)
        self.assertIn("already has a lineage", err)
        self.assertEqual(certbot.calls, [])

    def test_not_root(self) -> None:
        policy_path = self.policy_with_acme(
            {"example.net": {"source": {"kind": "acme"}, "clusters": ["alpha"]}}
        )
        out = io.StringIO()
        with mock.patch.object(os, "geteuid", return_value=1000):
            code = command.main(
                ["--domain", "example.com", "--method", "dns-01", "--cluster", "alpha", "--json"],
                policy_path=policy_path,
                output_stream=out,
                error_stream=io.StringIO(),
            )
        self.assertEqual(code, 77)
        self.assertEqual(json.loads(out.getvalue())["error"]["code"], "not_root")


if __name__ == "__main__":
    unittest.main()


class RenewingALineage(IssueFixture):
    """C9c: the round again, forced, for a lineage the registry holds."""

    def renewal_conf(self, lineage: str, authenticator: str = "dns-cloudflare") -> Path:
        directory = self.root / "renewal"
        directory.mkdir(exist_ok=True)
        conf = directory / f"{lineage}.conf"
        conf.write_text(f"version = 2.0\n[renewalparams]\nauthenticator = {authenticator}\n")
        return directory

    def test_certbot_renew_is_forced_and_the_certificate_published_again(self) -> None:
        issue(self.live / "example.net", "example.net")
        policy_path = self.policy_with_acme(
            {"example.net": {"source": {"kind": "acme"}, "clusters": ["alpha"]}}
        )
        renewal = self.renewal_conf("example.net", "webroot")
        certbot = FakeCertbot(self.live)
        deployed: list[str] = []

        def deploy(cluster: str) -> int:
            deployed.append(cluster)
            return 0

        policy = load_policy(policy_path, require_secure=False)
        runtime = load_runtime_config(policy, require_secure=False)

        result = cert_issue.renew(
            certificate_id="example.net",
            policy=policy,
            runtime=runtime,
            certbot=certbot,
            deployer=deploy,
            live=self.live,
            store=self.store,
            lock_path=self.lock,
            renewal_directory=renewal,
            require_secure=False,
        )

        [call] = certbot.calls
        self.assertEqual(
            call[1:],
            [
                "-q",
                "renew",
                "--no-random-sleep-on-renew",
                "--cert-name",
                "example.net",
                "--force-renewal",
            ],
        )
        self.assertTrue(result.renewed)
        self.assertEqual(result.request.method, "http-01")
        self.assertEqual(result.request.domains, ("example.net",))
        self.assertEqual(result.request.clusters, ("alpha",))
        self.assertEqual(deployed, ["alpha"])
        document = result.as_dict()
        self.assertTrue(document["renewed"])
        self.assertEqual(document["lineage"], "example.net")
        registry = yaml.safe_load(self.registry_path.read_text())
        self.assertEqual(list(registry["certificates"]), ["example.net"])

    def test_what_is_refused(self) -> None:
        issue(self.live / "example.net", "example.net")
        policy_path = self.policy_with_acme(
            {
                "example.net": {"source": {"kind": "acme"}, "clusters": ["alpha"]},
                "imported.example": {"source": {"kind": "import"}, "clusters": ["alpha"]},
            }
        )
        (self.store / "imported.example").mkdir()
        renewal = self.root / "renewal"
        renewal.mkdir()
        policy = load_policy(policy_path, require_secure=False)
        runtime = load_runtime_config(policy, require_secure=False)
        certbot = FakeCertbot(self.live)
        for certificate_id, code in (
            ("nobody.example", "not_registered"),
            ("imported.example", "not_acme"),
            ("example.net", "no_lineage"),
        ):
            with (
                self.subTest(certificate_id=certificate_id),
                self.assertRaises(IssueError) as caught,
            ):
                cert_issue.renew(
                    certificate_id=certificate_id,
                    policy=policy,
                    runtime=runtime,
                    certbot=certbot,
                    live=self.live,
                    store=self.store,
                    lock_path=self.lock,
                    renewal_directory=renewal,
                    require_secure=False,
                )
            self.assertEqual(caught.exception.code, code)
        self.assertEqual(certbot.calls, [])

    def test_the_helper_takes_renew_and_nothing_else_beside_the_name(self) -> None:
        issue(self.live / "example.net", "example.net")
        policy_path = self.policy_with_acme(
            {"example.net": {"source": {"kind": "acme"}, "clusters": ["alpha"]}}
        )
        renewal = self.renewal_conf("example.net")
        certbot = FakeCertbot(self.live)

        def helper(parameters: dict[str, Any]) -> tuple[int, str, str]:
            out, err = io.StringIO(), io.StringIO()
            request = json.dumps(
                {
                    "schema_version": 1,
                    "operation": "cert_issue",
                    "cluster": None,
                    "request_id": "ffffffff-ffff-4fff-8fff-ffffffffffff",
                    "parameters": parameters,
                }
            )
            code = cert_issue_helper.main(
                [],
                policy_path=policy_path,
                input_stream=io.BytesIO(request.encode()),
                output_stream=out,
                error_stream=err,
                require_secure=False,
                require_root=False,
                certbot=certbot,
                deployer=lambda cluster: 0,
                live=self.live,
                store=self.store,
                lock_path=self.lock,
                renewal_directory=renewal,
            )
            return code, out.getvalue(), err.getvalue()

        code, out, err = helper({"domain": "example.net", "renew": True})
        self.assertEqual(code, 0, err)
        document = assert_contract("haprion-cert-issue", out)
        self.assertTrue(document["result"]["renewed"])
        self.assertEqual(document["result"]["method"], "dns-01")
        self.assertEqual(
            json.loads(
                cert_issue_helper.build_request("r", domain="example.net", method="", renew=True)
            )["parameters"],
            {"domain": "example.net", "renew": True},
        )

        code, out, err = helper({"domain": "example.net", "renew": True, "method": "dns-01"})
        self.assertEqual(code, 65)
        self.assertIn("nothing else", err)
        code, out, err = helper({"domain": "example.net", "renew": "yes"})
        self.assertEqual(code, 65)

    def test_the_command_renews_one_lineage_now(self) -> None:
        issue(self.live / "example.net", "example.net")
        policy_path = self.policy_with_acme(
            {"example.net": {"source": {"kind": "acme"}, "clusters": ["alpha"]}}
        )
        renewal = self.renewal_conf("example.net")
        certbot = FakeCertbot(self.live)
        err = io.StringIO()
        real = cert_issue.renew

        def in_the_fixture(**options: Any) -> Any:
            """The engine as the command calls it, with the fixture's paths."""

            options["deployer"] = lambda cluster: 0
            return real(
                **options,
                certbot=certbot,
                live=self.live,
                store=self.store,
                lock_path=self.lock,
                renewal_directory=renewal,
                require_secure=False,
            )

        with (
            mock.patch("haprion.cli.cert_renew.os.geteuid", return_value=0),
            mock.patch("haprion.cli.cert_renew.cert_issue.renew", in_the_fixture),
            mock.patch(
                "haprion.cli.cert_renew.load_policy",
                lambda p: load_policy(p, require_secure=False),
            ),
            mock.patch(
                "haprion.cli.cert_renew.load_runtime_config",
                lambda p: load_runtime_config(p, require_secure=False),
            ),
            mock.patch("sys.stderr", err),
        ):
            code = cert_renew.main(["--policy", str(policy_path), "--acme-now", "example.net"])
        self.assertIn("acme: example.net:", err.getvalue())
        self.assertEqual(len(certbot.calls), 1)
        self.assertIn("--force-renewal", certbot.calls[0])
        self.assertEqual(code, 0, err.getvalue())
