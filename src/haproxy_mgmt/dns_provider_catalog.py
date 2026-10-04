"""The curated DNS provider contract and credentials-file rendering.

The lock answers what is installed.  This catalogue answers what the product
offers and exactly which structured values may become a plugin file.  It is
deliberately data plus named adapters: no form value can become a package,
plugin, option, file path, or INI key.

Every offered provider records how the root helper hands the rendered file to
certbot (``delivery``): a plugin flag such as ``--dns-cloudflare-credentials``,
or an environment variable for a plugin that reads its own SDK's configuration.
Plugins that are locked but cannot be described by this contract are listed
under ``not_offered`` with the reason, so a lock refresh cannot drop or add a
provider silently.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import re
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from importlib.resources import files
from typing import Any, Literal
from urllib.parse import urlsplit

from haproxy_mgmt import safe_yaml

PROVIDER_ID = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
FIELD_ID = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
INI_KEY = re.compile(r"^[a-z][A-Za-z0-9_]{0,63}$")
PACKAGE = re.compile(r"^[a-z0-9][a-z0-9.-]+$")
PLUGIN = re.compile(r"^[a-z0-9][a-z0-9-]+$")
DELIVERY = re.compile(r"^(flag:[a-z][a-z0-9-]{0,31}|env:[A-Z][A-Z0-9_]{0,63})$")
EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
ZONE_MAPPING = re.compile(
    r"^[A-Za-z0-9.-]+:/subscriptions/[^/\s]+/resourceGroups/[^/\s]+"
    r"(?:/providers/Microsoft\.Network/dnsZones/[A-Za-z0-9.-]+)?$"
)
MAX_VALUE = 4096
MAX_JSON_VALUE = 16384
MIN_PROPAGATION = 10
MAX_PROPAGATION = 900

ADAPTERS = ("ini", "azure-service-principal", "aws-shared-credentials", "google-service-account")
KINDS = ("text", "list", "choice", "json")
VALIDATIONS = ("ip_address", "base64", "url", "email", "uuid")
VERIFICATIONS = ("packaged", "loaded", "integration-tested", "live-verified")
SERVICE_ACCOUNT_KEYS = {"type", "project_id", "private_key", "client_email"}


class ProviderCatalogError(ValueError):
    """The catalogue or submitted field shape is not one we support."""


@dataclass(frozen=True)
class CredentialField:
    id: str
    label: str
    kind: Literal["text", "list", "choice", "json"]
    required: bool
    secret: bool
    key: str | None
    validation: Literal["ip_address", "base64", "url", "email", "uuid"] | None
    choices: tuple[str, ...]


@dataclass(frozen=True)
class DNSProvider:
    id: str
    name: str
    tier: Literal["core", "community"]
    package: str
    plugin: str
    adapter: Literal[
        "ini", "azure-service-principal", "aws-shared-credentials", "google-service-account"
    ]
    delivery: str
    documentation: str
    propagation_seconds: int
    propagation_minimum: int
    verification: Literal["packaged", "loaded", "integration-tested", "live-verified"]
    fields: tuple[CredentialField, ...]
    ini_section: str | None
    exactly_one_of: tuple[str, ...]

    @property
    def credentials_flag(self) -> str | None:
        """The certbot flag the helper passes the rendered file with, if any."""
        if self.delivery.startswith("flag:"):
            return f"--{self.plugin}-{self.delivery.removeprefix('flag:')}"
        return None

    @property
    def credentials_env(self) -> str | None:
        """The environment variable the helper points at the rendered file, if any."""
        if self.delivery.startswith("env:"):
            return self.delivery.removeprefix("env:")
        return None


@dataclass(frozen=True)
class NotOffered:
    package: str
    reason: str


@dataclass(frozen=True)
class Catalog:
    providers: tuple[DNSProvider, ...]
    not_offered: tuple[NotOffered, ...]


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


def _shape(
    mapping: Mapping[str, object], required: set[str], optional: set[str], location: str
) -> None:
    unknown = set(mapping) - required - optional
    missing = required - set(mapping)
    if unknown or missing:
        raise ProviderCatalogError(
            f"{location} has unknown fields {sorted(unknown)} and missing fields {sorted(missing)}"
        )


def _text(
    value: object, location: str, pattern: re.Pattern[str] | None = None, limit: int = MAX_VALUE
) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise ProviderCatalogError(f"{location} must be a non-empty string")
    if value != value.strip() or "\n" in value or "\r" in value:
        raise ProviderCatalogError(f"{location} may not contain surrounding space or line breaks")
    if pattern is not None and pattern.fullmatch(value) is None:
        raise ProviderCatalogError(f"{location} has an invalid value")
    return value


def _bool(value: object, location: str) -> bool:
    if type(value) is not bool:
        raise ProviderCatalogError(f"{location} must be a boolean")
    return value


def _field(value: object, location: str) -> CredentialField:
    row = _mapping(value, location)
    _shape(
        row,
        {"id", "label", "kind", "required", "secret"},
        {"key", "validation", "choices"},
        location,
    )
    kind = row["kind"]
    if kind not in KINDS:
        raise ProviderCatalogError(f"{location}.kind is not supported")
    key = row.get("key")
    if key is not None:
        key = _text(key, f"{location}.key", INI_KEY)
    validation = row.get("validation")
    if validation is not None and validation not in VALIDATIONS:
        raise ProviderCatalogError(f"{location}.validation is not supported")
    choices_value = row.get("choices", [])
    if not isinstance(choices_value, list) or (kind == "choice") != bool(choices_value):
        raise ProviderCatalogError(f"{location}.choices belong to choice fields only")
    choices = tuple(
        _text(item, f"{location}.choices[{index}]") for index, item in enumerate(choices_value)
    )
    if len(choices) != len(set(choices)):
        raise ProviderCatalogError(f"{location}.choices must be unique")
    if validation is not None and kind != "text":
        raise ProviderCatalogError(f"{location}.validation applies to text fields only")
    return CredentialField(
        id=_text(row["id"], f"{location}.id", FIELD_ID),
        label=_text(row["label"], f"{location}.label"),
        kind=kind,
        required=_bool(row["required"], f"{location}.required"),
        secret=_bool(row["secret"], f"{location}.secret"),
        key=key,
        validation=validation,
        choices=choices,
    )


def _adapter_shape(provider: str, adapter: str, fields: tuple[CredentialField, ...]) -> None:
    shape = [(field.id, field.kind) for field in fields]
    if adapter == "ini":
        if any(field.kind not in {"text", "choice"} or field.key is None for field in fields):
            raise ProviderCatalogError(f"{provider} INI fields must be keyed text or choice fields")
    elif adapter == "azure-service-principal":
        expected = [
            ("client_id", "text"),
            ("client_secret", "text"),
            ("tenant_id", "text"),
            ("zone_mappings", "list"),
        ]
        if shape != expected:
            raise ProviderCatalogError(f"{provider} has the wrong fields for its Azure adapter")
    elif adapter == "aws-shared-credentials":
        if shape != [("access_key_id", "text"), ("secret_access_key", "text")]:
            raise ProviderCatalogError(f"{provider} has the wrong fields for its AWS adapter")
    elif adapter == "google-service-account" and shape != [("service_account_json", "json")]:
        raise ProviderCatalogError(f"{provider} has the wrong fields for its Google adapter")
    if adapter != "ini" and any(not field.required for field in fields):
        raise ProviderCatalogError(f"{provider} adapter fields must all be required")


def _provider(value: object, location: str) -> DNSProvider:
    row = _mapping(value, location)
    _shape(
        row,
        {
            "id",
            "name",
            "tier",
            "package",
            "plugin",
            "adapter",
            "delivery",
            "documentation",
            "propagation_seconds",
            "verification",
            "fields",
        },
        {"ini_section", "exactly_one_of", "propagation_minimum"},
        location,
    )
    fields_value = row["fields"]
    if not isinstance(fields_value, list) or not fields_value:
        raise ProviderCatalogError(f"{location}.fields must be a non-empty list")
    fields = tuple(
        _field(field, f"{location}.fields[{index}]") for index, field in enumerate(fields_value)
    )
    field_ids = [field.id for field in fields]
    if len(field_ids) != len(set(field_ids)):
        raise ProviderCatalogError(f"{location} has duplicate field IDs")
    keys = [field.key for field in fields if field.key is not None]
    if len(keys) != len(set(keys)):
        raise ProviderCatalogError(f"{location} has duplicate INI keys")
    tier = row["tier"]
    adapter = row["adapter"]
    verification = row["verification"]
    if tier not in {"core", "community"}:
        raise ProviderCatalogError(f"{location}.tier is not supported")
    if adapter not in ADAPTERS:
        raise ProviderCatalogError(f"{location}.adapter is not supported")
    if verification not in VERIFICATIONS:
        raise ProviderCatalogError(f"{location}.verification is not supported")
    _adapter_shape(location, adapter, fields)
    propagation_minimum = row.get("propagation_minimum", MIN_PROPAGATION)
    propagation = row["propagation_seconds"]
    if (
        type(propagation_minimum) is not int
        or not MIN_PROPAGATION <= propagation_minimum <= MAX_PROPAGATION
    ):
        raise ProviderCatalogError(f"{location}.propagation_minimum is out of range")
    if type(propagation) is not int or not propagation_minimum <= propagation <= MAX_PROPAGATION:
        raise ProviderCatalogError(
            f"{location}.propagation_seconds must be between "
            f"{propagation_minimum} and {MAX_PROPAGATION}"
        )
    ini_section = row.get("ini_section")
    if ini_section is not None:
        if adapter != "ini":
            raise ProviderCatalogError(f"{location}.ini_section belongs to the INI adapter")
        ini_section = _text(ini_section, f"{location}.ini_section", FIELD_ID)
    one_of_value = row.get("exactly_one_of", [])
    if not isinstance(one_of_value, list) or len(one_of_value) == 1:
        raise ProviderCatalogError(f"{location}.exactly_one_of must list two or more fields")
    exactly_one_of = tuple(
        _text(item, f"{location}.exactly_one_of[{index}]", FIELD_ID)
        for index, item in enumerate(one_of_value)
    )
    by_id = {field.id: field for field in fields}
    if len(set(exactly_one_of)) != len(exactly_one_of) or any(
        item not in by_id or by_id[item].required for item in exactly_one_of
    ):
        raise ProviderCatalogError(f"{location}.exactly_one_of must name distinct optional fields")
    return DNSProvider(
        id=_text(row["id"], f"{location}.id", PROVIDER_ID),
        name=_text(row["name"], f"{location}.name"),
        tier=tier,
        package=_text(row["package"], f"{location}.package", PACKAGE),
        plugin=_text(row["plugin"], f"{location}.plugin", PLUGIN),
        adapter=adapter,
        delivery=_text(row["delivery"], f"{location}.delivery", DELIVERY),
        documentation=_text(row["documentation"], f"{location}.documentation"),
        propagation_seconds=propagation,
        propagation_minimum=propagation_minimum,
        verification=verification,
        fields=fields,
        ini_section=ini_section,
        exactly_one_of=exactly_one_of,
    )


def load_full_catalog() -> Catalog:
    document = safe_yaml.load(files("haproxy_mgmt").joinpath("dns-providers.yaml").read_text())
    root = _mapping(document, "catalogue")
    _exact(root, {"schema_version", "providers", "not_offered"}, "catalogue")
    if root["schema_version"] != 1 or type(root["schema_version"]) is not int:
        raise ProviderCatalogError("catalogue.schema_version must be 1")
    if not isinstance(root["providers"], list) or not root["providers"]:
        raise ProviderCatalogError("catalogue.providers must be a non-empty list")
    if not isinstance(root["not_offered"], list):
        raise ProviderCatalogError("catalogue.not_offered must be a list")

    providers = tuple(
        _provider(value, f"catalogue.providers[{index}]")
        for index, value in enumerate(root["providers"])
    )
    ids = [provider.id for provider in providers]
    if ids != sorted(ids) or len(ids) != len(set(ids)):
        raise ProviderCatalogError("providers must have unique IDs in alphabetical order")
    plugins = [provider.plugin for provider in providers]
    if len(plugins) != len(set(plugins)):
        raise ProviderCatalogError("providers must name distinct plugins")

    not_offered: list[NotOffered] = []
    for index, value in enumerate(root["not_offered"]):
        location = f"catalogue.not_offered[{index}]"
        row = _mapping(value, location)
        _exact(row, {"package", "reason"}, location)
        not_offered.append(
            NotOffered(
                package=_text(row["package"], f"{location}.package", PACKAGE),
                reason=_text(row["reason"], f"{location}.reason"),
            )
        )
    packages = [provider.package for provider in providers] + [item.package for item in not_offered]
    if len(packages) != len(set(packages)):
        raise ProviderCatalogError("a package may appear once, offered or not")
    return Catalog(providers=providers, not_offered=tuple(not_offered))


def load_catalog() -> tuple[DNSProvider, ...]:
    return load_full_catalog().providers


def provider_by_id(identifier: str) -> DNSProvider:
    for provider in load_catalog():
        if provider.id == identifier:
            return provider
    raise ProviderCatalogError(f"unknown provider: {identifier!r}")


def _validate(field: CredentialField, value: str) -> None:
    location = f"field {field.id}"
    if field.validation == "ip_address":
        try:
            ipaddress.ip_address(value)
        except ValueError:
            raise ProviderCatalogError(f"{location} must be an IPv4 or IPv6 address") from None
    elif field.validation == "base64":
        try:
            base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError):
            raise ProviderCatalogError(f"{location} must be base64") from None
    elif field.validation == "url":
        parts = urlsplit(value)
        if parts.scheme not in {"http", "https"} or not parts.netloc:
            raise ProviderCatalogError(f"{location} must be an http or https URL")
    elif field.validation == "email":
        if EMAIL.fullmatch(value) is None:
            raise ProviderCatalogError(f"{location} must be an email address")
    elif field.validation == "uuid":
        try:
            uuid.UUID(value)
        except ValueError:
            raise ProviderCatalogError(f"{location} must be a UUID") from None


def _service_account(value: str, location: str) -> dict[str, Any]:
    try:
        document = json.loads(value)
    except ValueError:
        raise ProviderCatalogError(f"{location} must be a JSON object") from None
    if not isinstance(document, dict) or not all(isinstance(key, str) for key in document):
        raise ProviderCatalogError(f"{location} must be a JSON object")
    missing = SERVICE_ACCOUNT_KEYS - set(document)
    if missing or document.get("type") != "service_account":
        raise ProviderCatalogError(f"{location} must be a service account key")
    if not all(isinstance(document[key], str) and document[key] for key in SERVICE_ACCOUNT_KEYS):
        raise ProviderCatalogError(f"{location} must be a service account key")
    return document


def _values(
    provider: DNSProvider, supplied: Mapping[str, object]
) -> dict[str, str | tuple[str, ...] | dict[str, Any]]:
    fields = {field.id: field for field in provider.fields}
    if set(supplied) - set(fields):
        raise ProviderCatalogError("credential fields do not match the provider template")
    result: dict[str, str | tuple[str, ...] | dict[str, Any]] = {}
    for identifier, field in fields.items():
        value = supplied.get(identifier)
        location = f"field {identifier}"
        if value is None or value == "" or value == []:
            if field.required:
                raise ProviderCatalogError(f"{location} is required")
            continue
        if field.kind == "text":
            text = _text(value, location)
            _validate(field, text)
            result[identifier] = text
        elif field.kind == "choice":
            text = _text(value, location)
            if text not in field.choices:
                raise ProviderCatalogError(f"{location} must be one of the offered choices")
            result[identifier] = text
        elif field.kind == "json":
            result[identifier] = _service_account(
                _text(value, location, limit=MAX_JSON_VALUE), location
            )
        elif isinstance(value, list):
            result[identifier] = tuple(
                _text(item, f"{location}[{index}]") for index, item in enumerate(value)
            )
        else:
            raise ProviderCatalogError(f"{location} must be a non-empty list")
    if provider.exactly_one_of:
        present = [item for item in provider.exactly_one_of if item in result]
        if len(present) != 1:
            names = ", ".join(provider.exactly_one_of)
            raise ProviderCatalogError(f"exactly one of {names} must be given")
    return result


def render_credentials(provider: DNSProvider, supplied: Mapping[str, object]) -> str:
    values = _values(provider, supplied)
    if provider.adapter == "ini":
        lines: list[str] = []
        if provider.ini_section is not None:
            lines.append(f"[{provider.ini_section}]\n")
        for field in provider.fields:
            if field.id not in values:
                continue
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
    if provider.adapter == "aws-shared-credentials":
        return (
            "[default]\n"
            f"aws_access_key_id = {values['access_key_id']}\n"
            f"aws_secret_access_key = {values['secret_access_key']}\n"
        )
    if provider.adapter == "google-service-account":
        document = values["service_account_json"]
        return json.dumps(document, indent=2, sort_keys=True) + "\n"
    raise ProviderCatalogError(f"unsupported adapter: {provider.adapter}")
