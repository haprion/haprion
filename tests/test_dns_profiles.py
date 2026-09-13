"""A sealed provider profile: what binds it, and what opens it."""

from __future__ import annotations

import json
import unittest

from haproxy_mgmt.dns_profile_keys import generate, seal
from haproxy_mgmt.dns_profiles import (
    ProfileError,
    build_request,
    open_profile,
    seal_profile,
    secret_values,
)
from haproxy_mgmt.dns_provider_catalog import provider_by_id

FIELDS = {"api_token": "token-example"}


class SealingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.private_key, self.public_key = generate()
        self.ciphertext = seal_profile(
            self.public_key,
            profile_id="cf-main",
            provider_id="cloudflare",
            revision=2,
            fields=FIELDS,
        )

    def test_a_profile_round_trips_with_its_rendered_credentials(self) -> None:
        opened = open_profile(
            self.private_key,
            self.ciphertext,
            profile_id="cf-main",
            provider_id="cloudflare",
            revision=2,
        )
        self.assertEqual(opened.revision, 2)
        self.assertEqual(opened.key_id, self.public_key.key_id)
        self.assertEqual(opened.credentials, "dns_cloudflare_api_token = token-example\n")
        self.assertNotIn(b"token-example", self.ciphertext)

    def test_a_newer_revision_satisfies_an_older_job_but_not_the_reverse(self) -> None:
        opened = open_profile(
            self.private_key,
            self.ciphertext,
            profile_id="cf-main",
            provider_id="cloudflare",
            revision=1,
        )
        self.assertEqual(opened.revision, 2)
        with self.assertRaisesRegex(ProfileError, "older revision"):
            open_profile(
                self.private_key,
                self.ciphertext,
                profile_id="cf-main",
                provider_id="cloudflare",
                revision=3,
            )

    def test_every_binding_is_held(self) -> None:
        other_private, _ = generate()
        cases = [
            ("another key", dict(key=other_private), "not sealed against key"),
            ("another profile", dict(profile_id="cf-other"), "another profile"),
            ("another provider", dict(provider_id="hetzner"), "another provider"),
        ]
        for label, override, expected in cases:
            with self.subTest(label=label):
                key = override.pop("key", self.private_key)
                arguments = {"profile_id": "cf-main", "provider_id": "cloudflare", "revision": 2}
                arguments.update(override)
                with self.assertRaisesRegex(ProfileError, expected) as caught:
                    open_profile(key, self.ciphertext, **arguments)
                self.assertNotIn("token-example", str(caught.exception))

    def test_a_forged_box_with_the_wrong_shape_or_key_id_is_refused(self) -> None:
        forged = dict(
            json.loads(
                '{"schema_version":1,"profile_id":"cf-main","provider_id":"cloudflare",'
                '"key_id":"0000000000000000","revision":2,"fields":{"api_token":"x-example"}}'
            )
        )
        box = seal(self.public_key, json.dumps(forged).encode())
        with self.assertRaisesRegex(ProfileError, "names another key"):
            open_profile(
                self.private_key, box, profile_id="cf-main", provider_id="cloudflare", revision=2
            )
        forged["key_id"] = self.public_key.key_id
        forged["fields"] = {"api_token": "x-example\nextra = line"}
        box = seal(self.public_key, json.dumps(forged).encode())
        with self.assertRaisesRegex(ProfileError, "surrounding space or line breaks"):
            open_profile(
                self.private_key, box, profile_id="cf-main", provider_id="cloudflare", revision=2
            )
        with self.assertRaisesRegex(ProfileError, "not a JSON document"):
            open_profile(
                self.private_key,
                seal(self.public_key, b"\xff\xfe"),
                profile_id="cf-main",
                provider_id="cloudflare",
                revision=2,
            )

    def test_sealing_refuses_bad_ids_providers_and_fields_before_sealing(self) -> None:
        with self.assertRaisesRegex(ProfileError, "profile id"):
            seal_profile(
                self.public_key,
                profile_id="Bad Id",
                provider_id="cloudflare",
                revision=1,
                fields=FIELDS,
            )
        with self.assertRaisesRegex(ProfileError, "unknown provider"):
            seal_profile(
                self.public_key, profile_id="x", provider_id="example", revision=1, fields=FIELDS
            )
        with self.assertRaisesRegex(ProfileError, "revision"):
            seal_profile(
                self.public_key, profile_id="x", provider_id="cloudflare", revision=0, fields=FIELDS
            )
        with self.assertRaisesRegex(ProfileError, "api_token is required"):
            seal_profile(
                self.public_key,
                profile_id="x",
                provider_id="cloudflare",
                revision=1,
                fields={"api_token": ""},
            )

    def test_secret_values_lists_only_secret_fields_that_have_a_value(self) -> None:
        provider = provider_by_id("rfc2136")
        values = secret_values(
            provider, {"server": "192.0.2.53", "name": "acme", "secret": "YWJj", "algorithm": ""}
        )
        self.assertEqual(values, ("YWJj",))

    def test_the_request_carries_the_box_and_its_binding_and_no_cluster(self) -> None:
        request = json.loads(
            build_request(
                "ffffffff-ffff-4fff-8fff-ffffffffffff",
                profile_id="cf-main",
                provider_id="cloudflare",
                key_id=self.public_key.key_id,
                revision=2,
                ciphertext=self.ciphertext,
            )
        )
        self.assertIsNone(request["cluster"])
        self.assertEqual(request["operation"], "dns_profile_apply")
        self.assertEqual(request["parameters"]["profile"], "cf-main")
        self.assertNotIn("token-example", json.dumps(request))


if __name__ == "__main__":
    unittest.main()
