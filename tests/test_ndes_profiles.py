"""NDES ciphertext binding, secret isolation and atomic root materialization."""

from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from typing import Any

import yaml

from haprion import dns_profiles, ndes_profiles
from haprion.cli import ndes_profile_apply_helper
from haprion.config import (
    SYSTEM_TRUST,
    ConfigError,
    DnsProfilesPolicy,
    NdesPolicy,
    NdesServer,
    load_policy,
)
from haprion.dns_profile_keys import generate, render_private_key
from haprion.dns_profiles import ProfileError

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
            (NdesServer(ENDPOINT, self.root / "ca.crt", self.root / "ca.crt"),),
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
                "tls_ca": str(self.policy.servers[0].tls_ca),
                "issuing_ca": str(self.policy.servers[0].issuing_ca),
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


class NdesProfileRemoval(NdesProfiles):
    def _helper(self, request: str) -> tuple[int, dict[str, Any], str]:
        output, errors = io.StringIO(), io.StringIO()
        code = ndes_profile_apply_helper.main(
            [],
            policy_path=self.root / "runtime.yaml",
            input_stream=io.BytesIO(request.encode()),
            output_stream=output,
            error_stream=errors,
            require_root=False,
            require_secure=False,
        )
        return code, json.loads(output.getvalue()), errors.getvalue()

    def _policy_file(self) -> None:
        private_path = self.policy.profiles.private_keys[0]
        private_path.write_text(render_private_key(self.private))
        os.chmod(private_path, 0o600)
        self.policy.state_root.mkdir(mode=0o700)
        (self.root / "runtime.yaml").write_text(
            yaml.safe_dump(
                {
                    "schema_version": 1,
                    "cluster_file": str(self.root / "clusters.yaml"),
                    "config_root": str(self.root / "config"),
                    "publish_root": str(self.root / "publish"),
                    "validation_certs_root": str(self.root / "validation"),
                    "ndes": {
                        "endpoint": ENDPOINT,
                        "tls_ca": str(self.policy.servers[0].tls_ca),
                        "issuing_ca": str(self.policy.servers[0].issuing_ca),
                        "client_root": str(self.policy.client_root),
                        "state_root": str(self.policy.state_root),
                        "profiles": {
                            "directory": str(self.policy.profiles.directory),
                            "private_keys": [str(private_path)],
                        },
                    },
                }
            )
        )

    def _request(self, *, remove: bool) -> str:
        return ndes_profiles.build_request(
            "ffffffff-ffff-4fff-8fff-ffffffffffff",
            profile_id="internal-ca",
            schema_version=1,
            key_id=self.public.key_id,
            revision=2,
            ciphertext=self.ciphertext,
            remove=remove,
        )

    def test_remove_flag_is_absent_unless_asked_and_must_be_boolean(self) -> None:
        self.assertNotIn("remove", json.loads(self._request(remove=False))["parameters"])
        self.assertIs(json.loads(self._request(remove=True))["parameters"]["remove"], True)
        self._policy_file()
        broken = json.loads(self._request(remove=True))
        broken["parameters"]["remove"] = "yes"
        code, doc, _ = self._helper(json.dumps(broken))
        self.assertEqual(code, 65)
        self.assertEqual(doc["error"]["code"], "bad_input")

    def test_helper_removes_the_record_and_a_retry_is_idempotent(self) -> None:
        self._policy_file()
        code, doc, errors = self._helper(self._request(remove=False))
        self.assertEqual(code, 0, errors)
        record = ndes_profiles.record_path(self.policy, "internal-ca")
        self.assertTrue(record.exists())
        code, doc, errors = self._helper(self._request(remove=True))
        self.assertEqual(code, 0, errors)
        self.assertEqual(doc["result"]["removed"], True)
        self.assertFalse(record.exists())
        self.assertNotIn("example-challenge", json.dumps(doc) + errors)
        code, doc, _ = self._helper(self._request(remove=True))
        self.assertEqual(code, 0)

    def test_removal_is_refused_while_an_enrollment_is_pending(self) -> None:
        self._policy_file()
        self._helper(self._request(remove=False))
        request_dir = self.policy.state_root / "abc123"
        request_dir.mkdir(mode=0o700)
        (request_dir / "request.json").write_text(
            json.dumps({"certificate": "web-cert", "profile": "internal-ca"})
        )
        os.chmod(request_dir / "request.json", 0o600)
        code, doc, _ = self._helper(self._request(remove=True))
        self.assertEqual(code, 65)
        self.assertEqual(doc["error"]["code"], "profile_in_use")
        self.assertIn("web-cert", doc["error"]["message"])
        self.assertTrue(ndes_profiles.record_path(self.policy, "internal-ca").exists())
        # A request bound to another profile is no objection; an unreadable one is.
        (request_dir / "request.json").write_text(
            json.dumps({"certificate": "web-cert", "profile": "other"})
        )
        self.assertEqual(
            ndes_profiles.pending_requests(self.policy, "internal-ca", require_secure=False), ()
        )
        (request_dir / "request.json").write_text("{broken")
        self.assertEqual(
            ndes_profiles.pending_requests(self.policy, "internal-ca", require_secure=False),
            ("abc123",),
        )

    def test_removal_is_refused_while_the_registry_names_the_profile(self) -> None:
        self._policy_file()
        self._helper(self._request(remove=False))
        registry = self.root / "certificates.yaml"
        registry.write_text(
            yaml.safe_dump(
                {
                    "schema_version": 1,
                    "certificates": {
                        "webserver1-scep": {
                            "source": {"kind": "import", "ndes_profile": "internal-ca"}
                        },
                        "by-hand": {"source": {"kind": "import"}},
                    },
                }
            )
        )
        config = yaml.safe_load((self.root / "runtime.yaml").read_text())
        config["certificate_registry"] = str(registry)
        (self.root / "runtime.yaml").write_text(yaml.safe_dump(config))
        code, doc, _ = self._helper(self._request(remove=True))
        self.assertEqual(code, 65)
        self.assertEqual(doc["error"]["code"], "profile_in_use")
        self.assertIn("webserver1-scep", doc["error"]["message"])
        self.assertNotIn("by-hand", doc["error"]["message"])


class TheServersInThePolicy(unittest.TestCase):
    """B385: each NDES server confirmed for itself; the form before it read as one."""

    def load(self, ndes: dict[str, object]) -> NdesPolicy:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            path = root / "runtime.yaml"
            path.write_text(
                yaml.safe_dump(
                    {
                        "schema_version": 1,
                        "cluster_file": str(root / "clusters.yaml"),
                        "config_root": str(root / "config"),
                        "publish_root": str(root / "publish"),
                        "validation_certs_root": str(root / "validation"),
                        "ndes": {
                            **ndes,
                            "client_root": "/opt/haprion-scep/current",
                            "state_root": "/etc/haprion/ndes-requests",
                            "profiles": {
                                "directory": "/etc/haprion/ndes-profiles",
                                "private_keys": ["/etc/haprion/ui-secrets/0123456789abcdef.key"],
                            },
                        },
                    }
                )
            )
            policy = load_policy(path, require_secure=False).ndes
        assert policy is not None
        return policy

    def test_the_form_before_it_is_one_server(self) -> None:
        policy = self.load(
            {
                "endpoint": ENDPOINT,
                "tls_ca": "/etc/haprion/tls.pem",
                "issuing_ca": "/etc/haprion/ca.pem",
            }
        )
        self.assertEqual(
            policy.servers,
            (NdesServer(ENDPOINT, Path("/etc/haprion/ca.pem"), Path("/etc/haprion/tls.pem")),),
        )

    def test_several_servers_and_the_system_store_when_none_is_named(self) -> None:
        other = "https://ca2.example.com/certsrv/mscep/mscep.dll"
        policy = self.load(
            {
                "servers": [
                    {"endpoint": ENDPOINT, "issuing_ca": "/etc/haprion/ndes-ca/a.pem"},
                    {"endpoint": other, "issuing_ca": "/etc/haprion/ndes-ca/b.pem"},
                ]
            }
        )
        self.assertEqual([server.endpoint for server in policy.servers], [ENDPOINT, other])
        self.assertEqual(policy.servers[0].tls_ca, SYSTEM_TRUST)
        self.assertEqual(policy.server(other), policy.servers[1])
        self.assertIsNone(policy.server("https://ca3.example.com/certsrv/mscep/mscep.dll"))

    def test_both_forms_an_address_twice_and_an_empty_list_are_refused(self) -> None:
        server: dict[str, object] = {"endpoint": ENDPOINT, "issuing_ca": "/etc/haprion/ca.pem"}
        cases: list[tuple[dict[str, object], str]] = [
            ({"servers": [server], "endpoint": ENDPOINT}, "not beside it"),
            ({"servers": [server, server]}, "names an address twice"),
            ({"servers": []}, "non-empty list"),
            ({"servers": [{**server, "port": 443}]}, "port"),
        ]
        for ndes, said in cases:
            with self.subTest(said=said), self.assertRaisesRegex(ConfigError, said):
                self.load(ndes)
