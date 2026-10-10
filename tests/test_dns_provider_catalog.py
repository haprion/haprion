"""The provider catalogue, its lock boundary, and credentials adapters."""

from __future__ import annotations

import json
import re
import tomllib
import unittest
from pathlib import Path

from haprion.dns_provider_catalog import (
    CredentialField,
    DNSProvider,
    ProviderCatalogError,
    load_catalog,
    load_full_catalog,
    provider_by_id,
    render_credentials,
)

ROOT = Path(__file__).resolve().parents[1]
INI_LINE = re.compile(r"^[A-Za-z0-9_]+ = .+$")

SERVICE_ACCOUNT = json.dumps(
    {
        "type": "service_account",
        "project_id": "project-example",
        "private_key_id": "key-example",
        "private_key": "private-key-example\n",
        "client_email": "svc-app@project-example.iam.gserviceaccount.com",
    }
)


def sample_value(field: CredentialField) -> object:
    """A value that satisfies the field's own validation, never a real one."""
    if field.kind == "choice":
        return field.choices[0]
    if field.kind == "list":
        return ["example.com:/subscriptions/subscription-example/resourceGroups/dns-example"]
    if field.kind == "json":
        return SERVICE_ACCOUNT
    return {
        "ip_address": "192.0.2.53",
        "base64": "YWJj",
        "url": "https://api.example.net/",
        "email": "admin@example.com",
        "uuid": "12345678-1234-4123-8123-123456789abc",
        None: f"{field.id}-example",
    }[field.validation]


def sample_values(provider: DNSProvider) -> dict[str, object]:
    values = {field.id: sample_value(field) for field in provider.fields}
    for identifier in provider.exactly_one_of[1:]:
        del values[identifier]
    return values


def requirement_name(requirement: str) -> str:
    """The distribution name a requirement line starts with."""

    found = re.match(r"^[A-Za-z0-9._-]+", requirement)
    assert found, f"not a requirement: {requirement!r}"
    return found.group()


class CatalogueContractTests(unittest.TestCase):
    def test_the_lock_is_covered_exactly_by_offered_and_not_offered(self) -> None:
        lock = tomllib.loads((ROOT / "certbot" / "uv.lock").read_text())
        project = tomllib.loads((ROOT / "certbot" / "pyproject.toml").read_text())
        direct = {requirement_name(item).lower() for item in project["project"]["dependencies"]}
        locked = {package["name"] for package in lock["package"]}
        catalog = load_full_catalog()

        offered = {provider.package for provider in catalog.providers}
        excluded = {item.package for item in catalog.not_offered}
        self.assertEqual(len(catalog.providers), 80)
        self.assertEqual(direct - {"certbot"}, offered | excluded)
        self.assertTrue(offered <= locked)

    def test_every_provider_names_a_distinct_plugin_and_a_delivery(self) -> None:
        for provider in load_catalog():
            with self.subTest(provider=provider.id):
                if provider.credentials_flag is not None:
                    self.assertTrue(provider.credentials_flag.startswith(f"--{provider.plugin}-"))
                    self.assertIsNone(provider.credentials_env)
                else:
                    self.assertEqual(provider.credentials_env, "AWS_SHARED_CREDENTIALS_FILE")
                    self.assertEqual(provider.adapter, "aws-shared-credentials")

    def test_the_catalogue_states_evidence_without_upgrading_a_mock_to_live(self) -> None:
        self.assertEqual(provider_by_id("azure").verification, "integration-tested")
        self.assertEqual(provider_by_id("cloudflare").verification, "live-verified")
        # First Domains logs in to its provider inside _setup_credentials, so the
        # offline verifier cannot prove more than the package for it.
        self.assertEqual(provider_by_id("firstdomains").verification, "packaged")
        others = {
            provider.verification
            for provider in load_catalog()
            if provider.id not in {"azure", "cloudflare", "firstdomains"}
        }
        self.assertEqual(others, {"loaded"})

    def test_every_secret_field_holds_secret_shaped_material(self) -> None:
        public = re.compile(r"(username|^user$|email|endpoint|url|_id$|^id$|zone|scope|^service$)")
        private = re.compile(r"(password|secret|token|totp|_json$)")
        for provider in load_catalog():
            for field in provider.fields:
                with self.subTest(provider=provider.id, field=field.id):
                    if public.search(field.id):
                        self.assertFalse(field.secret, "a public identifier marked secret")
                    elif private.search(field.id):
                        self.assertTrue(field.secret, "secret-looking field not marked secret")

    def test_an_unknown_provider_is_a_refusal(self) -> None:
        with self.assertRaisesRegex(ProviderCatalogError, "unknown provider"):
            provider_by_id("example")


class CredentialsRenderingTests(unittest.TestCase):
    def test_every_provider_renders_from_its_own_template(self) -> None:
        for provider in load_catalog():
            with self.subTest(provider=provider.id):
                rendered = render_credentials(provider, sample_values(provider))
                self.assertTrue(rendered.endswith("\n"))
                if provider.adapter == "ini":
                    lines = rendered.splitlines()
                    if provider.ini_section is not None:
                        self.assertEqual(lines.pop(0), f"[{provider.ini_section}]")
                    keys = [line.split(" = ", 1)[0] for line in lines]
                    self.assertTrue(all(INI_LINE.fullmatch(line) for line in lines))
                    self.assertEqual(
                        keys,
                        [
                            field.key
                            for field in provider.fields
                            if field.id not in provider.exactly_one_of[1:]
                        ],
                    )

    def test_cloudflare_is_the_plain_ini_reference(self) -> None:
        rendered = render_credentials(provider_by_id("cloudflare"), {"api_token": "token-example"})
        self.assertEqual(rendered, "dns_cloudflare_api_token = token-example\n")

    def test_optional_fields_are_written_only_when_given(self) -> None:
        provider = provider_by_id("rfc2136")
        base = {
            "server": "192.0.2.53",
            "name": "acme-key",
            "secret": "YWJj",
        }
        self.assertEqual(
            render_credentials(provider, {**base, "algorithm": ""}),
            "dns_rfc2136_server = 192.0.2.53\n"
            "dns_rfc2136_name = acme-key\n"
            "dns_rfc2136_secret = YWJj\n",
        )
        self.assertTrue(
            render_credentials(provider, {**base, "algorithm": "HMAC-SHA256"}).endswith(
                "dns_rfc2136_algorithm = HMAC-SHA256\n"
            )
        )
        with self.assertRaisesRegex(ProviderCatalogError, "offered choices"):
            render_credentials(provider, {**base, "algorithm": "HMAC-SHA2"})
        with self.assertRaisesRegex(ProviderCatalogError, "IPv4 or IPv6"):
            render_credentials(provider, {**base, "server": "ns.example.com"})
        with self.assertRaisesRegex(ProviderCatalogError, "base64"):
            render_credentials(provider, {**base, "secret": "not base64!"})
        with self.assertRaisesRegex(ProviderCatalogError, "is required"):
            render_credentials(provider, {**base, "name": ""})

    def test_exactly_one_of_is_enforced(self) -> None:
        provider = provider_by_id("cloudns")
        with self.assertRaisesRegex(ProviderCatalogError, "exactly one of"):
            render_credentials(provider, {"auth_password": "secret-example"})
        with self.assertRaisesRegex(ProviderCatalogError, "exactly one of"):
            render_credentials(
                provider,
                {"auth_id": "1", "sub_auth_id": "2", "auth_password": "secret-example"},
            )
        self.assertEqual(
            render_credentials(provider, {"sub_auth_user": "svc-app", "auth_password": "pw-ex"}),
            "dns_cloudns_sub_auth_user = svc-app\ndns_cloudns_auth_password = pw-ex\n",
        )

    def test_a_sectioned_ini_file_carries_its_header(self) -> None:
        rendered = render_credentials(
            provider_by_id("spaceship"), {"api_key": "key-example", "api_secret": "secret-example"}
        )
        self.assertEqual(
            rendered, "[spaceship]\napi_key = key-example\napi_secret = secret-example\n"
        )

    def test_route53_renders_an_aws_shared_credentials_file_for_the_environment(self) -> None:
        provider = provider_by_id("route53")
        self.assertIsNone(provider.credentials_flag)
        rendered = render_credentials(
            provider, {"access_key_id": "AKIAEXAMPLE", "secret_access_key": "secret-example"}
        )
        self.assertEqual(
            rendered,
            "[default]\naws_access_key_id = AKIAEXAMPLE\naws_secret_access_key = secret-example\n",
        )

    def test_google_accepts_only_a_service_account_key(self) -> None:
        provider = provider_by_id("google")
        rendered = render_credentials(provider, {"service_account_json": SERVICE_ACCOUNT})
        self.assertEqual(json.loads(rendered)["type"], "service_account")
        self.assertIn('"private_key": "private-key-example\\n"', rendered)
        for bad in ('{"type": "authorized_user"}', "[]", "not json", '{"type": "service_account"}'):
            with self.subTest(bad=bad), self.assertRaises(ProviderCatalogError):
                render_credentials(provider, {"service_account_json": bad})

    def test_azure_renders_the_plugin_s_service_principal_format(self) -> None:
        rendered = render_credentials(
            provider_by_id("azure"),
            {
                "client_id": "client-example",
                "client_secret": "secret-example",
                "tenant_id": "tenant-example",
                "zone_mappings": [
                    "example.com:/subscriptions/subscription-example/resourceGroups/dns-example",
                    "example.net:/subscriptions/subscription-example/resourceGroups/dns-example",
                ],
            },
        )
        self.assertEqual(
            rendered,
            "dns_azure_sp_client_id = client-example\n"
            "dns_azure_sp_client_secret = secret-example\n"
            "dns_azure_tenant_id = tenant-example\n"
            "dns_azure_zone1 = example.com:/subscriptions/subscription-example/"
            "resourceGroups/dns-example\n"
            "dns_azure_zone2 = example.net:/subscriptions/subscription-example/"
            "resourceGroups/dns-example\n",
        )

    def test_values_cannot_add_lines_fields_or_mappings_and_are_never_echoed(self) -> None:
        provider = provider_by_id("azure")
        good: dict[str, object] = {
            "client_id": "client-example",
            "client_secret": "secret-example",
            "tenant_id": "tenant-example",
            "zone_mappings": [
                "example.com:/subscriptions/subscription-example/resourceGroups/dns-example"
            ],
        }
        bad_cases = [
            {**good, "client_secret": "secret-example\nextra = exposed"},
            {**good, "extra": "value"},
            {**good, "zone_mappings": ["example.com:dns-example"]},
        ]
        for supplied in bad_cases:
            with self.subTest(supplied=set(supplied)):
                with self.assertRaises(ProviderCatalogError) as caught:
                    render_credentials(provider, supplied)
                self.assertNotIn("secret-example", str(caught.exception))
        for provider in load_catalog():
            values = sample_values(provider)
            secret = next((field for field in provider.fields if field.secret), None)
            if secret is None or secret.kind != "text":
                continue
            with self.subTest(provider=provider.id):
                with self.assertRaises(ProviderCatalogError) as caught:
                    render_credentials(provider, {**values, secret.id: "leak-example\nx = y"})
                self.assertNotIn("leak-example", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
