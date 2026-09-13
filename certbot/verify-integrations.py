#!/usr/bin/env python3
"""Exercise catalogue adapters through their installed Certbot plugins.

This script is deliberately run by the newly built Certbot environment, not by
the application's test environment.  That makes the locked plugin and its real
SDK dependencies the system under test while every provider network operation
remains a local mock.
"""

from __future__ import annotations

import importlib.metadata
import json
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock


def verify_azure(source_root: Path) -> None:
    sys.path.insert(0, str(source_root))
    from azure.mgmt.dns.models import RecordSet, TxtRecord

    from haproxy_mgmt.dns_provider_catalog import provider_by_id, render_credentials

    provider = provider_by_id("azure")
    entrypoints = [
        entrypoint
        for entrypoint in importlib.metadata.entry_points(group="certbot.plugins")
        if entrypoint.name == provider.plugin
    ]
    if len(entrypoints) != 1:
        raise RuntimeError("Azure must provide exactly one Certbot entrypoint")
    authenticator_class = entrypoints[0].load()

    with tempfile.TemporaryDirectory(prefix="haproxy-azure-integration-") as raw:
        credentials_path = Path(raw) / "credentials.ini"
        credentials_path.write_text(
            render_credentials(
                provider,
                {
                    "client_id": "11111111-1111-1111-1111-111111111111",
                    "client_secret": "integration-test-value-not-a-secret",
                    "tenant_id": "22222222-2222-2222-2222-222222222222",
                    "zone_mappings": [
                        "example.com:/subscriptions/"
                        "33333333-3333-3333-3333-333333333333/"
                        "resourceGroups/dns-example"
                    ],
                },
            ),
            encoding="utf-8",
        )
        credentials_path.chmod(0o600)
        config = SimpleNamespace(
            dns_azure_config=str(credentials_path),
            dns_azure_credentials=None,
            dns_azure_ttl=120,
            dns_azure_propagation_seconds=0,
            namespace=SimpleNamespace(dns_azure_config=str(credentials_path)),
        )
        authenticator = authenticator_class(config, provider.plugin)
        credential = object()
        client = MagicMock()
        authenticator._get_azure_credentials = MagicMock(return_value=credential)
        authenticator._get_azure_client = MagicMock(return_value=client)

        client.record_sets.get.return_value = RecordSet(
            etag="etag-before", txt_records=[TxtRecord(value=["foreign-value"])]
        )
        authenticator._setup_credentials()
        authenticator._perform(
            "www.example.com", "_acme-challenge.www.example.com", "validation-value"
        )

        auth = authenticator._get_azure_credentials.call_args.args
        if auth[:4] != (
            "11111111-1111-1111-1111-111111111111",
            "integration-test-value-not-a-secret",
            None,
            "22222222-2222-2222-2222-222222222222",
        ):
            raise RuntimeError("Azure did not parse the rendered service-principal fields")
        if authenticator._get_azure_client.call_args.args != (
            "33333333-3333-3333-3333-333333333333",
            credential,
        ):
            raise RuntimeError("Azure did not select the rendered subscription")
        created = client.record_sets.create_or_update.call_args.kwargs
        values = {record.value[0] for record in created["parameters"].txt_records}
        if (
            created["resource_group_name"] != "dns-example"
            or created["zone_name"] != "example.com"
            or created["relative_record_set_name"] != "_acme-challenge.www"
            or created["record_type"] != "TXT"
            or created["if_match"] != "etag-before"
            or values != {"foreign-value", "validation-value"}
        ):
            raise RuntimeError("Azure did not create the expected conditional TXT update")

        client.record_sets.get.return_value = RecordSet(
            etag="etag-after",
            txt_records=[
                TxtRecord(value=["foreign-value"]),
                TxtRecord(value=["validation-value"]),
            ],
        )
        authenticator._cleanup(
            "www.example.com", "_acme-challenge.www.example.com", "validation-value"
        )
        cleaned = client.record_sets.create_or_update.call_args.kwargs
        remaining = {record.value[0] for record in cleaned["parameters"].txt_records}
        if remaining != {"foreign-value"} or client.record_sets.delete.called:
            raise RuntimeError("Azure cleanup did not preserve an unrelated TXT value")


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: verify-integrations.py SOURCE_ROOT REPORT", file=sys.stderr)
        return 2
    source_root = Path(sys.argv[1]).resolve(strict=True)
    report_path = Path(sys.argv[2])
    checks = {"azure-renderer-plugin-sdk": lambda: verify_azure(source_root)}
    passed: list[str] = []
    failed: list[str] = []
    for name, check in checks.items():
        try:
            check()
            passed.append(name)
        except Exception as exc:  # noqa: BLE001 - the failure type is installation evidence
            failed.append(f"{name}: {type(exc).__name__}: {exc}")
    report_path.write_text(
        json.dumps({"passed": passed, "failed": failed}, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return bool(failed)


if __name__ == "__main__":
    raise SystemExit(main())
