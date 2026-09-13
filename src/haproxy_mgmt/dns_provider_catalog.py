"""The curated DNS provider contract and credentials-file rendering.

The lock answers what is installed.  This catalogue answers what the product
offers and exactly which structured values may become a plugin file.  It is
deliberately data plus named adapters: no form value can become a package,
plugin, option, file path, or INI key.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from importlib.resources import files
from typing import Any, Literal

import yaml

PROVIDER_ID = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
FIELD_ID = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
PACKAGE = re.compile(r"^[a-z0-9][a-z0-9.-]+$")
PLUGIN = re.compile(r"^[a-z0-9][a-z0-9-]+$")
ZONE_MAPPING = re.compile(
    r"^[A-Za-z0-9.-]+:/subscriptions/[^/\s]+/resourceGroups/[^/\s]+"
    r"(?:/providers/Microsoft\.Network/dnsZones/[A-Za-z0-9.-]+)?$"
)
MAX_VALUE = 4096


class ProviderCatalogError(ValueError):
    """The catalogue or submitted field shape is not one we support."""


@dataclass(frozen=True)
class CredentialField:
    id: str
    label: str
    kind: Literal["text", "list"]
    required: bool
    secret: bool
    key: str | None


@dataclass(frozen=True)
class DNSProvider:
    id: str
    name: str
    tier: Literal["core", "community"]
    package: str
    plugin: str
    adapter: Literal["ini", "azure-service-principal"]
    documentation: str
    propagation_seconds: int
    verification: Literal["packaged", "loaded", "integration-tested", "live-verified"]
    fields: tuple[CredentialField, ...]


def _mapping(value: object, location: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ProviderCatalogError(f"{location} must be a mapping")
    return value


def _exact(mapping: Mapping[str, object], expected: set[str], location: str) -> None:
    unknown = set(mapping) - expected
    missing = expected - set(mapping)
    if unknown or missing:
        raise ProviderCatalogError(
            f"{location} has unknown fields {sorted(unknown)} and missing fields {sorted(missing)}"
        )


def _text(value: object, location: str, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_VALUE:
        raise ProviderCatalogError(f"{location} must be a non-empty string")
    if value != value.strip() or "\n" in value or "\r" in value:
        raise ProviderCatalogError(f"{location} may not contain surrounding space or line breaks")
    if pattern is not None and pattern.fullmatch(value) is None:
        raise ProviderCatalogError(f"{location} has an invalid value")
    return value


def _field(value: object, location: str) -> CredentialField:
    row = _mapping(value, location)
    required = {"id", "label", "kind", "required", "secret"}
    optional = {"key"}
    unknown = set(row) - required - optional
    missing = required - set(row)
    if unknown or missing:
        raise ProviderCatalogError(
            f"{location} has unknown fields {sorted(unknown)} and missing fields {sorted(missing)}"
        )
    identifier = _text(row["id"], f"{location}.id", FIELD_ID)
    kind = row["kind"]
    if kind not in {"text", "list"}:
        raise ProviderCatalogError(f"{location}.kind is not supported")
    if type(row["required"]) is not bool or type(row["secret"]) is not bool:
        raise ProviderCatalogError(f"{location} booleans must be booleans")
    key = row.get("key")
    if key is not None:
        key = _text(key, f"{location}.key", FIELD_ID)
    return CredentialField(
        id=identifier,
        label=_text(row["label"], f"{location}.label"),
        kind=kind,
        required=row["required"],
        secret=row["secret"],
        key=key,
    )


def load_catalog() -> tuple[DNSProvider, ...]:
    document = yaml.safe_load(files("haproxy_mgmt").joinpath("dns-providers.yaml").read_text())
    root = _mapping(document, "catalogue")
    _exact(root, {"schema_version", "providers"}, "catalogue")
    if root["schema_version"] != 1 or type(root["schema_version"]) is not int:
        raise ProviderCatalogError("catalogue.schema_version must be 1")
    if not isinstance(root["providers"], list) or not root["providers"]:
        raise ProviderCatalogError("catalogue.providers must be a non-empty list")

    providers: list[DNSProvider] = []
    expected = {
        "id",
        "name",
        "tier",
        "package",
        "plugin",
        "adapter",
        "documentation",
        "propagation_seconds",
        "verification",
        "fields",
    }
    for index, value in enumerate(root["providers"]):
        location = f"catalogue.providers[{index}]"
        row = _mapping(value, location)
        _exact(row, expected, location)
        fields_value = row["fields"]
        if not isinstance(fields_value, list) or not fields_value:
            raise ProviderCatalogError(f"{location}.fields must be a non-empty list")
        credential_fields = tuple(
            _field(field, f"{location}.fields[{field_index}]")
            for field_index, field in enumerate(fields_value)
        )
        field_ids = [field.id for field in credential_fields]
        if len(field_ids) != len(set(field_ids)):
            raise ProviderCatalogError(f"{location} has duplicate field IDs")
        tier = row["tier"]
        adapter = row["adapter"]
        verification = row["verification"]
        if tier not in {"core", "community"}:
            raise ProviderCatalogError(f"{location}.tier is not supported")
        if adapter not in {"ini", "azure-service-principal"}:
            raise ProviderCatalogError(f"{location}.adapter is not supported")
        if verification not in {"packaged", "loaded", "integration-tested", "live-verified"}:
            raise ProviderCatalogError(f"{location}.verification is not supported")
        if adapter == "ini" and any(
            field.kind != "text" or field.key is None for field in credential_fields
        ):
            raise ProviderCatalogError(f"{location} INI fields must be keyed text fields")
        if adapter == "azure-service-principal" and [
            (field.id, field.kind) for field in credential_fields
        ] != [
            ("client_id", "text"),
            ("client_secret", "text"),
            ("tenant_id", "text"),
            ("zone_mappings", "list"),
        ]:
            raise ProviderCatalogError(f"{location} has the wrong fields for its Azure adapter")
        propagation = row["propagation_seconds"]
        if type(propagation) is not int or not 10 <= propagation <= 600:
            raise ProviderCatalogError(f"{location}.propagation_seconds must be between 10 and 600")
        providers.append(
            DNSProvider(
                id=_text(row["id"], f"{location}.id", PROVIDER_ID),
                name=_text(row["name"], f"{location}.name"),
                tier=tier,
                package=_text(row["package"], f"{location}.package", PACKAGE),
                plugin=_text(row["plugin"], f"{location}.plugin", PLUGIN),
                adapter=adapter,
                documentation=_text(row["documentation"], f"{location}.documentation"),
                propagation_seconds=propagation,
                verification=verification,
                fields=credential_fields,
            )
        )
    ids = [provider.id for provider in providers]
    if ids != sorted(ids) or len(ids) != len(set(ids)):
        raise ProviderCatalogError("providers must have unique IDs in alphabetical order")
    return tuple(providers)


def provider_by_id(identifier: str) -> DNSProvider:
    for provider in load_catalog():
        if provider.id == identifier:
            return provider
    raise ProviderCatalogError(f"unknown provider: {identifier!r}")


def _values(
    provider: DNSProvider, supplied: Mapping[str, object]
) -> dict[str, str | tuple[str, ...]]:
    fields = {field.id: field for field in provider.fields}
    if set(supplied) != set(fields):
        raise ProviderCatalogError("credential fields do not match the provider template")
    result: dict[str, str | tuple[str, ...]] = {}
    for identifier, field in fields.items():
        value = supplied[identifier]
        if field.kind == "text":
            result[identifier] = _text(value, f"field {identifier}")
        elif isinstance(value, list) and value:
            result[identifier] = tuple(
                _text(item, f"field {identifier}[{index}]") for index, item in enumerate(value)
            )
        else:
            raise ProviderCatalogError(f"field {identifier} must be a non-empty list")
    return result


def render_credentials(provider: DNSProvider, supplied: Mapping[str, object]) -> str:
    values = _values(provider, supplied)
    if provider.adapter == "ini":
        lines: list[str] = []
        for field in provider.fields:
            if field.key is None:  # held by catalogue validation; keeps this boundary total
                raise ProviderCatalogError(f"field {field.id} has no INI key")
            lines.append(f"{field.key} = {values[field.id]}\n")
        return "".join(lines)
    if provider.adapter == "azure-service-principal":
        zones = values["zone_mappings"]
        if not isinstance(zones, tuple) or any(
            ZONE_MAPPING.fullmatch(item) is None for item in zones
        ):
            raise ProviderCatalogError("field zone_mappings has an invalid value")
        lines = [
            f"dns_azure_sp_client_id = {values['client_id']}",
            f"dns_azure_sp_client_secret = {values['client_secret']}",
            f"dns_azure_tenant_id = {values['tenant_id']}",
        ]
        lines.extend(f"dns_azure_zone{index} = {zone}" for index, zone in enumerate(zones, 1))
        return "\n".join(lines) + "\n"
    raise ProviderCatalogError(f"unsupported adapter: {provider.adapter}")
