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
import unittest
from collections.abc import Sequence
from pathlib import Path
from unittest import mock

import yaml

from haproxy_mgmt import cert_issue
from haproxy_mgmt.cert_issue import CertbotResult, IssueError, certbot_arguments, parse_domain
from haproxy_mgmt.cli import cert_issue as command
from haproxy_mgmt.config import load_policy, load_runtime_config
from tests.test_cert_publish import Fixture, issue


class FakeCertbot:
    """Writes a lineage where certbot would and remembers what it was told."""

    def __init__(self, live: Path, *, returncode: int = 0, output: str = "") -> None:
        self.live = live
        self.returncode = returncode
        self.output = output
        self.calls: list[list[str]] = []

    def __call__(self, arguments: Sequence[str]) -> CertbotResult:
        self.calls.append(list(arguments))
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

    def test_a_method_without_its_setting_is_refused_by_name(self) -> None:
        policy_path = self.write_config(
            {"example.net": {"source": {"kind": "acme"}, "clusters": ["alpha"]}}
        )
        code, out, err, _ = self.run_issue(
            policy_path, "--domain", "www.example.com", "--method", "http-01", "--cluster", "alpha"
        )
        self.assertEqual(code, 78)
        self.assertIn("acme.webroot", err)

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
        self.assertEqual([p.name for p in self.dist.iterdir()], ["example.com.pem"])
        self.assertEqual(
            sorted(p.name for p in self.receiver_dir.iterdir()), ["fullchain.pem", "privkey.pem"]
        )
        [published] = result["publish"]["certificates"]
        self.assertEqual(published["status"], "published")
        self.assertEqual(deployed, ["alpha"])

        # The engine reads the rewritten registry the same way it read the written one.
        runtime = load_runtime_config(
            load_policy(policy_path, require_secure=False), require_secure=False
        )
        self.assertEqual(runtime.clusters["alpha"].certificate_ids, ("example.net", "example.com"))

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
