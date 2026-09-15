"""NDES ciphertext binding, secret isolation and atomic root materialization."""

from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

import yaml

from haproxy_mgmt import dns_profiles, ndes_profiles
from haproxy_mgmt.cli import ndes_profile_apply_helper
from haproxy_mgmt.config import DnsProfilesPolicy, NdesPolicy
from haproxy_mgmt.dns_profile_keys import generate, render_private_key
from haproxy_mgmt.dns_profiles import ProfileError

ENDPOINT = "https://ca.example.com/certsrv/mscep/mscep.dll"


class NdesProfiles(unittest.TestCase):
    def setUp(self) -> None:
        self.private, self.public = generate()
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        profiles = self.root / "profiles"
        profiles.mkdir(mode=0o700)
        self.policy = NdesPolicy(
            ENDPOINT,
            self.root / "ca.crt",
            self.root / "ca.crt",
            self.root / "client",
            self.root / "state",
            DnsProfilesPolicy(profiles, (self.root / "private.key",)),
        )
        self.ciphertext = ndes_profiles.seal_profile(
            self.public,
            profile_id="internal-ca",
            endpoint=ENDPOINT,
            challenge="example-challenge",
            revision=2,
        )

    def opened(self) -> ndes_profiles.OpenedProfile:
        return ndes_profiles.open_profile(
            self.private, self.ciphertext, profile_id="internal-ca", revision=2
        )

    def test_sealed_secret_is_absent_from_ciphertext_request_and_repr(self) -> None:
        opened = self.opened()
        self.assertEqual(opened.challenge, "example-challenge")
        self.assertNotIn("example-challenge", repr(opened))
        self.assertNotIn(b"example-challenge", self.ciphertext)
        request = ndes_profiles.build_request(
            "ffffffff-ffff-4fff-8fff-ffffffffffff",
            profile_id=opened.profile_id,
            schema_version=1,
            key_id=opened.key_id,
            revision=2,
            ciphertext=self.ciphertext,
        )
        self.assertNotIn("example-challenge", request)

    def test_key_profile_revision_and_provider_type_are_bound(self) -> None:
        other, _ = generate()
        for key, profile, revision in (
            (other, "internal-ca", 2),
            (self.private, "other-ca", 2),
            (self.private, "internal-ca", 3),
        ):
            with (
                self.subTest(profile=profile, revision=revision),
                self.assertRaises(ProfileError) as caught,
            ):
                ndes_profiles.open_profile(
                    key, self.ciphertext, profile_id=profile, revision=revision
                )
            self.assertNotIn("example-challenge", str(caught.exception))
        dns = dns_profiles.seal_profile(
            self.public,
            profile_id="internal-ca",
            provider_id="cloudflare",
            revision=2,
            fields={"api_token": "example-value"},
        )
        with self.assertRaises(ProfileError):
            ndes_profiles.open_profile(self.private, dns, profile_id="internal-ca", revision=2)
        with self.assertRaises(ProfileError):
            dns_profiles.open_profile(
                self.private,
                self.ciphertext,
                profile_id="internal-ca",
                provider_id="cloudflare",
                revision=2,
            )

    def test_endpoint_and_printablestring_validation_never_echo_the_value(self) -> None:
        for endpoint in (
            "http://ca.example.com/mscep.dll",
            "https://example-value@ca.example.com/",
            "https://ca.example.com/?challenge=example-value",
            "https://ca.example.com:bad/",
        ):
            with self.subTest(endpoint=endpoint), self.assertRaises(ProfileError) as caught:
                ndes_profiles.check_endpoint(endpoint)
            self.assertNotIn("example-value", str(caught.exception))
        for challenge in ("", "example-value\n", "example-value_", "é", "a" * 4097):
            with self.subTest(length=len(challenge)), self.assertRaises(ProfileError):
                ndes_profiles.check_challenge(challenge)

    def test_atomic_record_has_protected_mode_and_refuses_rollback(self) -> None:
        opened = self.opened()
        ndes_profiles.materialize(self.policy, opened, require_secure=False)
        path = ndes_profiles.record_path(self.policy, opened.profile_id)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(
            ndes_profiles.resolve(self.policy, opened.profile_id, require_secure=False), opened
        )
        for altered in (
            replace(opened, revision=1),
            replace(opened, challenge="different-example"),
        ):
            with self.assertRaises(ProfileError):
                ndes_profiles.materialize(self.policy, altered, require_secure=False)
        self.assertEqual(
            ndes_profiles.resolve(self.policy, opened.profile_id, require_secure=False), opened
        )
        self.assertEqual(len(list(self.policy.profiles.directory.iterdir())), 1)

    def test_endpoint_must_match_protected_policy(self) -> None:
        with self.assertRaises(ProfileError):
            ndes_profiles.materialize(
                self.policy,
                replace(self.opened(), endpoint="https://other.example.com/mscep.dll"),
                require_secure=False,
            )
        self.assertFalse(ndes_profiles.record_path(self.policy, "internal-ca").exists())

    def test_symlink_and_oversized_records_are_refused(self) -> None:
        target = self.root / "other"
        target.write_text("example-value")
        link = self.policy.profiles.directory / "internal-ca.json"
        link.symlink_to(target)
        with self.assertRaises(ProfileError):
            ndes_profiles.resolve(self.policy, "internal-ca", require_secure=False)
        link.unlink()
        link.write_bytes(b"x" * (ndes_profiles.MAX_RECORD + 1))
        with self.assertRaises(ProfileError):
            ndes_profiles.resolve(self.policy, "internal-ca", require_secure=False)

    def test_helper_applies_a_box_and_returns_only_binding(self) -> None:
        private_path = self.policy.profiles.private_keys[0]
        private_path.write_text(render_private_key(self.private))
        os.chmod(private_path, 0o600)
        config = {
            "schema_version": 1,
            "cluster_file": str(self.root / "clusters.yaml"),
            "config_root": str(self.root / "config"),
            "publish_root": str(self.root / "publish"),
            "validation_certs_root": str(self.root / "validation"),
            "ndes": {
                "endpoint": ENDPOINT,
                "tls_ca": str(self.policy.tls_ca),
                "issuing_ca": str(self.policy.issuing_ca),
                "client_root": str(self.policy.client_root),
                "state_root": str(self.policy.state_root),
                "profiles": {
                    "directory": str(self.policy.profiles.directory),
                    "private_keys": [str(private_path)],
                },
            },
        }
        path = self.root / "runtime.yaml"
        path.write_text(yaml.safe_dump(config))
        request = ndes_profiles.build_request(
            "ffffffff-ffff-4fff-8fff-ffffffffffff",
            profile_id="internal-ca",
            schema_version=1,
            key_id=self.public.key_id,
            revision=2,
            ciphertext=self.ciphertext,
        )
        output, errors = io.StringIO(), io.StringIO()
        code = ndes_profile_apply_helper.main(
            [],
            policy_path=path,
            input_stream=io.BytesIO(request.encode()),
            output_stream=output,
            error_stream=errors,
            require_root=False,
            require_secure=False,
        )
        self.assertEqual(code, 0, errors.getvalue())
        doc = json.loads(output.getvalue())
        self.assertEqual(doc["outcome"], "done")
        self.assertEqual(set(doc["result"]), {"profile", "provider", "key_id", "revision"})
        self.assertNotIn("example-challenge", output.getvalue() + errors.getvalue())
