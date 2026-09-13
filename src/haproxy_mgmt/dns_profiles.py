"""A DNS provider profile: credentials sealed by the web, opened only by root.

The web interface collects a provider's credentials once and stores a sealed
box (B146); the root helper opens it, checks that what is inside is what the
job asked for, renders the plugin's credentials file from the catalogue's
template and writes it where certbot will read it (B147, P5).  What both ends
agree on is here: the plaintext's shape, what binds a ciphertext to one
profile, and the request the worker sends.

The plaintext is JSON, and it carries its own binding because a sealed box
has no associated data: `profile_id`, `provider_id`, `schema_version` and
`key_id` must match what the job names, and `revision` may not be lower than
the job's.  A ciphertext moved between profiles decrypts correctly and is
refused; an older revision replayed after a replacement is refused.  A valid
ciphertext is not proof of anything - the web is allowed to make them - so
the fields inside are validated against the catalogue as untrusted input.

Field values pass through the catalogue's own renderer before they are sealed
and again after they are opened.  One rule, both ends: a profile the web
accepts is one the helper accepts, and neither can be lenient alone.
"""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from haproxy_mgmt.dns_profile_keys import (
    DnsProfilePrivateKey,
    DnsProfilePublicKey,
    KeyFileError,
    open_sealed,
    seal,
)
from haproxy_mgmt.dns_provider_catalog import (
    DNSProvider,
    ProviderCatalogError,
    provider_by_id,
    render_credentials,
)

OPERATION = "dns_profile_apply"
SCHEMA_VERSION = 1
PROFILE_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
MAX_REVISION = 1_000_000
MAX_CIPHERTEXT = 65536
HELPER = "/opt/haproxy-mgmt/current/bin/haproxy-dns-profile-apply-helper"
SUDO = "/usr/bin/sudo"


class ProfileError(ValueError):
    """The profile, its ciphertext or its binding is not what was asked for.

    Never carries a field value: the message names the field or the binding
    that failed, and the value stays inside the box.
    """


@dataclass(frozen=True, slots=True)
class OpenedProfile:
    profile_id: str
    provider_id: str
    schema_version: int
    key_id: str
    revision: int
    fields: dict[str, Any]
    credentials: str
    """The plugin's credentials file, rendered by the catalogue's adapter."""


def check_profile_id(value: object) -> str:
    if not isinstance(value, str) or PROFILE_ID.fullmatch(value) is None:
        raise ProfileError("profile id must be 1-32 lowercase letters, digits or hyphens")
    return value


def check_revision(value: object) -> int:
    if type(value) is not int or not 1 <= value <= MAX_REVISION:
        raise ProfileError(f"revision must be an integer between 1 and {MAX_REVISION}")
    return value


def validate_fields(provider: DNSProvider, fields: Mapping[str, object]) -> str:
    """The catalogue's judgement of the values, as the rendered file.

    Raised errors name fields, never values - `render_credentials` holds to
    that too - so a refusal can be shown on a form.
    """

    try:
        return render_credentials(provider, fields)
    except ProviderCatalogError as exc:
        raise ProfileError(str(exc)) from exc


def seal_profile(
    public_key: DnsProfilePublicKey,
    *,
    profile_id: str,
    provider_id: str,
    revision: int,
    fields: Mapping[str, object],
) -> bytes:
    """Validate the fields against the catalogue, then seal them for root."""

    check_profile_id(profile_id)
    check_revision(revision)
    try:
        provider = provider_by_id(provider_id)
    except ProviderCatalogError as exc:
        raise ProfileError(str(exc)) from exc
    validate_fields(provider, fields)
    plaintext = {
        "schema_version": SCHEMA_VERSION,
        "profile_id": profile_id,
        "provider_id": provider.id,
        "key_id": public_key.key_id,
        "revision": revision,
        "fields": dict(fields),
    }
    return seal(public_key, json.dumps(plaintext, separators=(",", ":")).encode("utf-8"))


def open_profile(
    key: DnsProfilePrivateKey,
    ciphertext: bytes,
    *,
    profile_id: str,
    provider_id: str,
    revision: int,
) -> OpenedProfile:
    """Open a box and hold its binding to what the job asked for.

    The checks are in the order a wrong box fails cheapest: the key first,
    then the shape, then each binding, then the fields.  A failure says which
    binding, so an operator can tell a moved ciphertext from a stale one.
    """

    check_profile_id(profile_id)
    check_revision(revision)
    if len(ciphertext) > MAX_CIPHERTEXT:
        raise ProfileError("ciphertext is larger than a profile can be")
    try:
        plaintext = open_sealed(key, ciphertext)
    except KeyFileError as exc:
        raise ProfileError(f"the profile was not sealed against key {key.key_id}") from exc
    try:
        document = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise ProfileError("the opened profile is not a JSON document") from None
    expected = {"schema_version", "profile_id", "provider_id", "key_id", "revision", "fields"}
    if not isinstance(document, dict) or set(document) != expected:
        raise ProfileError("the opened profile does not have the profile shape")
    if document["schema_version"] != SCHEMA_VERSION:
        raise ProfileError("the opened profile has a schema version this helper does not read")
    if document["profile_id"] != profile_id:
        raise ProfileError("the opened profile was sealed for another profile")
    if document["provider_id"] != provider_id:
        raise ProfileError("the opened profile was sealed for another provider")
    if document["key_id"] != key.key_id:
        raise ProfileError("the opened profile names another key than the one that opened it")
    sealed_revision = document["revision"]
    if type(sealed_revision) is not int or sealed_revision < revision:
        raise ProfileError("the opened profile is an older revision than the job asked for")
    check_revision(sealed_revision)
    fields = document["fields"]
    if not isinstance(fields, dict) or not all(isinstance(key, str) for key in fields):
        raise ProfileError("the opened profile's fields are not a mapping")
    try:
        provider = provider_by_id(provider_id)
    except ProviderCatalogError as exc:
        raise ProfileError(str(exc)) from exc
    credentials = validate_fields(provider, fields)
    return OpenedProfile(
        profile_id=profile_id,
        provider_id=provider.id,
        schema_version=SCHEMA_VERSION,
        key_id=key.key_id,
        revision=sealed_revision,
        fields=fields,
        credentials=credentials,
    )


def secret_values(provider: DNSProvider, fields: Mapping[str, object]) -> tuple[str, ...]:
    """Every value the helper must strike from certbot's output (B147)."""

    values: list[str] = []
    for field in provider.fields:
        if not field.secret:
            continue
        value = fields.get(field.id)
        if isinstance(value, str) and value:
            values.append(value)
    return tuple(values)


def build_request(
    request_id: str,
    *,
    profile_id: str,
    provider_id: str,
    key_id: str,
    revision: int,
    ciphertext: bytes,
) -> str:
    """The bounded request the worker sends. Null cluster, by contract.

    The ciphertext travels base64 inside the JSON; the helper decodes it and
    checks it against the same four bindings, so a request built from a row
    that was replaced between queueing and running is refused rather than
    applied.
    """

    return json.dumps(
        {
            "schema_version": 1,
            "operation": OPERATION,
            "cluster": None,
            "request_id": request_id,
            "parameters": {
                "profile": profile_id,
                "provider": provider_id,
                "key_id": key_id,
                "revision": revision,
                "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            },
        },
        separators=(",", ":"),
    )
