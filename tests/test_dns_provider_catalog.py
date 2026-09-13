"""The provider catalogue, its lock boundary, and credentials adapters."""

from __future__ import annotations

import tomllib
import unittest
from pathlib import Path

from haproxy_mgmt.dns_provider_catalog import (
    ProviderCatalogError,
    load_catalog,
    provider_by_id,
    render_credentials,
)

ROOT = Path(__file__).resolve().parents[1]


class CatalogueContractTests(unittest.TestCase):
    def test_every_offered_provider_is_installed_by_the_locked_project(self) -> None:
        lock = tomllib.loads((ROOT / "certbot" / "uv.lock").read_text())
        locked = {package["name"] for package in lock["package"]}
        providers = load_catalog()

        self.assertEqual([provider.id for provider in providers], ["azure", "cloudflare"])
        for provider in providers:
            with self.subTest(provider=provider.id):
                self.assertIn(provider.package, locked)

    def test_the_catalogue_states_evidence_without_upgrading_a_mock_to_live(self) -> None:
        self.assertEqual(provider_by_id("azure").verification, "loaded")
        self.assertEqual(provider_by_id("cloudflare").verification, "live-verified")

    def test_an_unknown_provider_is_a_refusal(self) -> None:
        with self.assertRaisesRegex(ProviderCatalogError, "unknown provider"):
            provider_by_id("example")


class CredentialsRenderingTests(unittest.TestCase):
    def test_cloudflare_is_the_plain_ini_reference(self) -> None:
        rendered = render_credentials(provider_by_id("cloudflare"), {"api_token": "token-example"})
        self.assertEqual(rendered, "dns_cloudflare_api_token = token-example\n")

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


if __name__ == "__main__":
    unittest.main()
