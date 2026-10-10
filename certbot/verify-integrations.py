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
import os
import re
import socket
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

LEVELS = ("packaged", "loaded", "integration-tested", "live-verified")
NETWORK_AT_SETUP = {"firstdomains"}
PACKAGE_NAME = re.compile(r"[-_.]+")


def normalized(name: str) -> str:
    return PACKAGE_NAME.sub("-", name).lower()


def entrypoint_for(provider: object) -> importlib.metadata.EntryPoint:
    """The one certbot entrypoint the catalogue names, from the package it names."""
    matches = [
        entrypoint
        for entrypoint in importlib.metadata.entry_points(group="certbot.plugins")
        if entrypoint.name == provider.plugin
    ]
    if len(matches) != 1:
        raise RuntimeError(f"{provider.id} must provide exactly one certbot entrypoint")
    if normalized(matches[0].dist.name) != provider.package:
        raise RuntimeError(f"{provider.id} entrypoint comes from {matches[0].dist.name}")
    return matches[0]


def sample_value(field: object) -> object:
    """A value that satisfies the field's own validation, never a real one."""
    if field.kind == "choice":
        return field.choices[0]
    if field.kind == "list":
        return ["example.com:/subscriptions/subscription-example/resourceGroups/dns-example"]
    if field.kind == "json":
        return service_account_json()
    return {
        "ip_address": "192.0.2.53",
        "base64": "c2VjcmV0LWV4YW1wbGU=",
        "url": "https://api.example.net/",
        "email": "admin@example.com",
        "uuid": "12345678-1234-4123-8123-123456789abc",
        None: f"{field.id}-example",
    }[field.validation]


def service_account_json() -> str:
    """A syntactically complete service-account key with a throwaway RSA key."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    pem = (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        .private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        .decode()
    )
    return json.dumps(
        {
            "type": "service_account",
            "project_id": "project-example",
            "private_key_id": "key-example",
            "private_key": pem,
            "client_email": "svc-app@project-example.iam.gserviceaccount.com",
            "client_id": "123456789012345678901",
            "token_uri": "https://oauth2.googleapis.com/token",
        }
    )


def forbid_network() -> None:
    """Every check runs offline; a plugin that reaches out fails instead of passing quietly."""

    def refuse(*args: object, **kwargs: object) -> object:
        raise RuntimeError("network access is not available during integration verification")

    socket.socket = refuse  # type: ignore[misc, assignment]
    socket.create_connection = refuse  # type: ignore[assignment]
    socket.getaddrinfo = refuse  # type: ignore[assignment]


class _Config:
    """Just enough of certbot's namespace for a plugin to read its own options."""

    def __init__(self, plugin: str, values: dict[str, object]) -> None:
        self._prefix = plugin.replace("-", "_") + "_"
        self._values = values

    def __getattr__(self, name: str) -> object:
        if name.startswith("_"):
            raise AttributeError(name)
        return self._values.get(name)

    def to_dict(self) -> dict[str, object]:
        return dict(self._values)


def verify_loaded(source_root: Path, provider_id: str) -> None:
    """The rendered file passes the installed plugin's own credential setup."""
    sys.path.insert(0, str(source_root))
    from haprion.dns_provider_catalog import provider_by_id, render_credentials

    provider = provider_by_id(provider_id)
    authenticator_class = entrypoint_for(provider).load()
    values = {field.id: sample_value(field) for field in provider.fields}
    for identifier in provider.exactly_one_of[1:]:
        del values[identifier]
    with tempfile.TemporaryDirectory(prefix="haproxy-provider-loaded-") as raw:
        path = Path(raw) / "credentials"
        path.write_text(render_credentials(provider, values), encoding="utf-8")
        path.chmod(0o600)
        if provider.adapter == "aws-shared-credentials":
            _verify_aws(path)
            return
        if provider.adapter == "google-service-account":
            _verify_google(path)
            return
        prefix = provider.plugin.replace("-", "_") + "_"
        option = provider.delivery.removeprefix("flag:").replace("-", "_")
        namespace: dict[str, object] = {
            f"{prefix}{option}": str(path),
            f"{prefix}propagation_seconds": provider.propagation_seconds,
            # a plugin that is also an installer wants certbot's directories
            "backup_dir": str(Path(raw) / "backups"),
            "work_dir": raw,
            "config_dir": raw,
            "logs_dir": raw,
            "strict_permissions": False,
        }
        config = _Config(provider.plugin, namespace)
        authenticator = authenticator_class(config, provider.plugin)
        authenticator._setup_credentials()
        if provider.id == "spaceship":
            from certbot_dns_spaceship.client import SpaceshipClient

            client = SpaceshipClient(str(path))
            if client.api_key != values["api_key"] or client.api_secret != values["api_secret"]:
                raise RuntimeError("Spaceship did not read the rendered section")


def _verify_aws(path: Path) -> None:
    import botocore.session

    previous = os.environ.get("AWS_SHARED_CREDENTIALS_FILE")
    os.environ["AWS_SHARED_CREDENTIALS_FILE"] = str(path)
    try:
        credentials = botocore.session.Session().get_credentials()
    finally:
        if previous is None:
            del os.environ["AWS_SHARED_CREDENTIALS_FILE"]
        else:
            os.environ["AWS_SHARED_CREDENTIALS_FILE"] = previous
    if credentials is None or credentials.access_key != "access_key_id-example":
        raise RuntimeError("botocore did not read the rendered shared credentials file")


def _verify_google(path: Path) -> None:
    from google.oauth2 import service_account

    credentials = service_account.Credentials.from_service_account_file(str(path))
    if credentials.service_account_email != "svc-app@project-example.iam.gserviceaccount.com":
        raise RuntimeError("google-auth did not read the rendered service account key")


def verify_azure(source_root: Path) -> None:
    sys.path.insert(0, str(source_root))
    from azure.mgmt.dns.models import RecordSet, TxtRecord

    from haprion.dns_provider_catalog import provider_by_id, render_credentials

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
    forbid_network()
    sys.path.insert(0, str(source_root))
    from haprion.dns_provider_catalog import load_catalog

    checks: dict[str, Callable[[], None]] = {
        "azure-renderer-plugin-sdk": lambda: verify_azure(source_root)
    }
    for provider in load_catalog():
        if provider.adapter == "azure-service-principal":
            continue  # covered end to end by the SDK check above
        if provider.id in NETWORK_AT_SETUP:
            continue  # the plugin talks to its provider before any challenge; not provable offline
        checks[f"{provider.id}-loaded"] = lambda provider_id=provider.id: verify_loaded(
            source_root, provider_id
        )
    passed: list[str] = []
    failed: list[str] = []
    for name, check in checks.items():
        try:
            check()
            passed.append(name)
        except Exception as exc:  # noqa: BLE001 - the failure type is installation evidence
            failed.append(f"{name}: {type(exc).__name__}: {exc}")
    # A catalogue may not claim more than this run proved.
    for provider in load_catalog():
        claimed = LEVELS.index(provider.verification)
        proved = 0
        if f"{provider.id}-loaded" in passed:
            proved = 1
        if provider.id == "azure" and "azure-renderer-plugin-sdk" in passed:
            proved = 2
        if provider.id == "cloudflare" and proved >= 1:
            proved = 3  # live issuance evidence is held outside this environment
        if claimed > proved:
            failed.append(f"{provider.id}: claims {provider.verification} beyond the evidence")
    report_path.write_text(
        json.dumps({"passed": passed, "failed": failed}, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return bool(failed)


if __name__ == "__main__":
    raise SystemExit(main())
