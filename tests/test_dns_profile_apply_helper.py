"""The DNS profile helper: binding, root-only files and refusal surface."""

from __future__ import annotations

import io
import json
import stat
import unittest
from pathlib import Path
from typing import Any

import yaml

from haprion import dns_profiles, exit_codes
from haprion.cli import dns_profile_apply_helper
from haprion.config import PathPolicy
from haprion.dns_profile_keys import generate, render_private_key
from tests.test_cert_publish import Fixture


class ApplyFixture(Fixture):
    def setUp(self) -> None:
        super().setUp()
        private, public = generate()
        self.private_path = self.root / "profile.key"
        self.private_path.write_text(render_private_key(private), encoding="utf-8")
        self.private_path.chmod(0o600)
        self.profile_dir = self.root / "profiles"
        self.profile_dir.mkdir(mode=0o700)
        self.policy_path = self.write_config({})
        document = yaml.safe_load(self.policy_path.read_text(encoding="utf-8"))
        document["acme"] = {
            "dns_profiles": {
                "directory": str(self.profile_dir),
                "private_keys": [str(self.private_path)],
            }
        }
        self.policy_path.write_text(yaml.safe_dump(document), encoding="utf-8")
        self.ciphertext = dns_profiles.seal_profile(
            public,
            profile_id="cf-main",
            provider_id="cloudflare",
            revision=2,
            fields={"api_token": "token-example"},
        )
        self.key_id = public.key_id

    def request(self, **overrides: object) -> str:
        parameters = {
            "profile": "cf-main",
            "provider": "cloudflare",
            "profile_schema_version": 1,
            "key_id": self.key_id,
            "revision": 2,
            "ciphertext": __import__("base64").b64encode(self.ciphertext).decode("ascii"),
            **overrides,
        }
        return json.dumps(
            {
                "schema_version": 1,
                "operation": "dns_profile_apply",
                "cluster": None,
                "request_id": "ffffffff-ffff-4fff-8fff-ffffffffffff",
                "parameters": parameters,
            },
            separators=(",", ":"),
        )

    def invoke(
        self,
        request: str,
        *,
        argv: list[str] | None = None,
        renewal_directory: Path | None = None,
    ) -> tuple[int, dict[str, Any], str]:
        output, errors = io.StringIO(), io.StringIO()
        code = dns_profile_apply_helper.main(
            argv or [],
            policy_path=self.policy_path,
            input_stream=io.BytesIO(request.encode("utf-8")),
            output_stream=output,
            error_stream=errors,
            require_secure=False,
            require_root=False,
            renewal_directory=renewal_directory or self.root / "renewal",
        )
        document = json.loads(output.getvalue()) if output.getvalue() else {}
        return code, document, errors.getvalue()


class Applying(ApplyFixture):
    def test_validated_credentials_and_metadata_are_replaced_atomically(self) -> None:
        code, document, errors = self.invoke(self.request())

        self.assertEqual(code, 0, errors)
        self.assertEqual(document["outcome"], "done")
        self.assertEqual(document["result"]["plugin"], "dns-cloudflare")
        credentials = self.profile_dir / "cf-main"
        metadata = self.profile_dir / ".cf-main.profile.json"
        self.assertEqual(credentials.read_text(), "dns_cloudflare_api_token = token-example\n")
        self.assertEqual(stat.S_IMODE(credentials.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(metadata.stat().st_mode), 0o600)
        acme = yaml_policy(self.policy_path).acme
        assert acme is not None and acme.dns_profiles is not None
        materialized = dns_profiles.read_materialized(
            acme.dns_profiles,
            require_secure=False,
            profile_id="cf-main",
        )
        self.assertEqual(materialized.provider.id, "cloudflare")

    def test_moved_and_stale_ciphertexts_are_blocked_without_values_in_the_answer(self) -> None:
        cases = (
            ({"profile": "cf-other"}, "another profile"),
            ({"revision": 3}, "older revision"),
        )
        for override, expected in cases:
            with self.subTest(expected=expected):
                code, document, errors = self.invoke(self.request(**override))
                self.assertEqual(code, exit_codes.BLOCKED)
                self.assertEqual(document["outcome"], "blocked")
                answer = json.dumps(document) + errors
                self.assertIn(expected, answer)
                self.assertNotIn("token-example", answer)

    def test_arguments_and_bad_base64_are_refused_before_materialization(self) -> None:
        code, document, errors = self.invoke(self.request(), argv=["--policy", "/etc/passwd"])
        self.assertEqual(code, 64)
        self.assertEqual(document, {})
        self.assertIn("no command-line arguments", errors)

        code, document, _ = self.invoke(self.request(ciphertext="not base64"))
        self.assertEqual(code, 65)
        self.assertEqual(document["outcome"], "failed")
        self.assertFalse((self.profile_dir / "cf-main").exists())

    def test_the_sudoers_rule_names_exactly_the_no_argument_helper(self) -> None:
        example = (
            Path(__file__).resolve().parents[1]
            / "install/platform/examples/haprion-worker.sudoers.example"
        ).read_text(encoding="utf-8")
        self.assertIn(f'{dns_profile_apply_helper.HELPER} ""', example)

    def test_remove_is_idempotent_and_makes_the_profile_unusable_first(self) -> None:
        code, _, errors = self.invoke(self.request())
        self.assertEqual(code, 0, errors)

        code, document, errors = self.invoke(self.request(remove=True))
        self.assertEqual(code, 0, errors)
        self.assertTrue(document["result"]["removed"])
        self.assertFalse((self.profile_dir / "cf-main").exists())
        self.assertFalse((self.profile_dir / ".cf-main.profile.json").exists())

        code, document, errors = self.invoke(self.request(remove=True))
        self.assertEqual(code, 0, errors)
        self.assertEqual(document["outcome"], "done")

    def test_remove_is_blocked_by_an_exact_renewal_reference(self) -> None:
        code, _, errors = self.invoke(self.request())
        self.assertEqual(code, 0, errors)
        renewal = self.root / "renewal"
        renewal.mkdir()
        (renewal / "example.com.conf").write_text(
            renewal_conf("example.com", self.profile_dir / "cf-main"), encoding="utf-8"
        )

        code, document, _ = self.invoke(self.request(remove=True), renewal_directory=renewal)
        self.assertEqual(code, 65)
        self.assertEqual(document["error"]["code"], "profile_in_use")
        self.assertIn("example.com", document["error"]["message"])
        self.assertTrue((self.profile_dir / "cf-main").exists())

    def test_remove_reads_certbot_lineages_that_point_elsewhere(self) -> None:
        code, _, errors = self.invoke(self.request())
        self.assertEqual(code, 0, errors)
        renewal = self.root / "renewal"
        renewal.mkdir()
        (renewal / "other.example.conf").write_text(
            renewal_conf("other.example", self.root / "elsewhere.ini"), encoding="utf-8"
        )

        code, document, errors = self.invoke(self.request(remove=True), renewal_directory=renewal)
        self.assertEqual(code, 0, errors)
        self.assertTrue(document["result"]["removed"])
        self.assertFalse((self.profile_dir / "cf-main").exists())

    def test_remove_is_blocked_by_a_registry_source_reference(self) -> None:
        code, _, errors = self.invoke(self.request())
        self.assertEqual(code, 0, errors)
        registry_path = self.root / "certificates.yaml"
        registry = yaml.safe_load(registry_path.read_text(encoding="utf-8"))
        registry["certificates"] = {
            "example.com": {
                "source": {"kind": "acme", "dns_profile": "cf-main"},
                "clusters": [],
            }
        }
        registry_path.write_text(yaml.safe_dump(registry), encoding="utf-8")

        code, document, _ = self.invoke(self.request(remove=True))
        self.assertEqual(code, 65)
        self.assertEqual(document["error"]["code"], "profile_in_use")
        self.assertIn("example.com", document["error"]["message"])
        self.assertTrue((self.profile_dir / "cf-main").exists())


def renewal_conf(lineage: str, credentials: Path) -> str:
    """A renewal conf as certbot writes it: lineage paths above the section."""

    return (
        f"version = 5.8.0\n"
        f"archive_dir = /etc/letsencrypt/archive/{lineage}\n"
        f"cert = /etc/letsencrypt/live/{lineage}/cert.pem\n"
        f"privkey = /etc/letsencrypt/live/{lineage}/privkey.pem\n"
        f"chain = /etc/letsencrypt/live/{lineage}/chain.pem\n"
        f"fullchain = /etc/letsencrypt/live/{lineage}/fullchain.pem\n"
        f"[renewalparams]\n"
        f"account = 97fd02a3f6b1cef3fd33c95a583abc17\n"
        f"key_type = ecdsa\n"
        f"authenticator = dns-cloudflare\n"
        f"dns_cloudflare = True\n"
        f"dns_cloudflare_propagation_seconds = 30\n"
        f"dns_cloudflare_credentials = {credentials}\n"
        f"server = https://acme-v02.api.letsencrypt.org/directory\n"
    )


def yaml_policy(path: Path) -> PathPolicy:
    from haprion.config import load_policy

    return load_policy(path, require_secure=False)


if __name__ == "__main__":
    unittest.main()
