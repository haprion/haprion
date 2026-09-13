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
import contextlib
import json
import os
import re
import stat
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from haproxy_mgmt.config import DnsProfilesPolicy
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


@dataclass(frozen=True, slots=True)
class MaterializedProfile:
    """The root-only files an issue command needs without database access."""

    profile_id: str
    provider: DNSProvider
    credentials_path: str
    revision: int
    key_id: str


def credentials_path(directory: str | os.PathLike[str], profile_id: str) -> str:
    """The stable path certbot records in its renewal configuration."""

    check_profile_id(profile_id)
    return os.path.join(os.fspath(directory), profile_id)


def metadata_path(directory: str | os.PathLike[str], profile_id: str) -> str:
    """Root-only non-secret metadata that lets the CLI map ID to plugin."""

    check_profile_id(profile_id)
    return os.path.join(os.fspath(directory), f".{profile_id}.profile.json")


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


def _secure_directory(path: str, *, require_secure: bool) -> None:
    try:
        status = os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise ProfileError(f"cannot read the DNS profile directory: {exc.strerror}") from exc
    if not stat.S_ISDIR(status.st_mode):
        raise ProfileError("the DNS profile directory is not a directory")
    if require_secure and (status.st_uid != 0 or stat.S_IMODE(status.st_mode) != 0o700):
        raise ProfileError("the DNS profile directory must be owned by root, mode 0700")


def _atomic_write(path: str, content: bytes) -> None:
    """Write one root-only regular file beside its destination, then rename."""

    directory = os.path.dirname(path)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{os.path.basename(path)}.", dir=directory)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except Exception:
        with contextlib.suppress(OSError):
            os.unlink(temporary)
        raise


def materialize(
    policy: DnsProfilesPolicy,
    opened: OpenedProfile,
    *,
    require_secure: bool = True,
) -> MaterializedProfile:
    """Atomically put validated credentials where certbot will keep reading them.

    The credentials move first and the metadata last.  A terminal issue racing a
    profile's first apply therefore sees "not materialized" instead of metadata
    pointing at a file that does not exist.  A replacement keeps the same
    provider by database contract, so either complete credentials file is valid.
    """

    directory = os.fspath(policy.directory)
    _secure_directory(directory, require_secure=require_secure)
    credentials = credentials_path(directory, opened.profile_id)
    metadata = metadata_path(directory, opened.profile_id)
    document = {
        "schema_version": 1,
        "profile": opened.profile_id,
        "provider": opened.provider_id,
        "key_id": opened.key_id,
        "revision": opened.revision,
    }
    try:
        _atomic_write(credentials, opened.credentials.encode("utf-8"))
        _atomic_write(
            metadata,
            (json.dumps(document, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8"),
        )
    except OSError as exc:
        raise ProfileError(f"the DNS profile could not be materialized: {exc.strerror}") from exc
    return MaterializedProfile(
        profile_id=opened.profile_id,
        provider=provider_by_id(opened.provider_id),
        credentials_path=credentials,
        revision=opened.revision,
        key_id=opened.key_id,
    )


def remove_materialized(
    policy: DnsProfilesPolicy,
    profile_id: str,
    *,
    require_secure: bool = True,
) -> None:
    """Remove both root-only files, making the profile unusable first.

    Metadata is the commit marker used by :func:`read_materialized`, so it is
    unlinked before the credentials.  A stopped removal can consequently
    leave an inert credentials file, never a profile that appears usable
    while its credentials are gone.  Missing files make retries idempotent.
    """

    profile_id = check_profile_id(profile_id)
    directory = os.fspath(policy.directory)
    _secure_directory(directory, require_secure=require_secure)
    paths = (metadata_path(directory, profile_id), credentials_path(directory, profile_id))
    try:
        for path in paths:
            try:
                status = os.stat(path, follow_symlinks=False)
            except FileNotFoundError:
                continue
            if not stat.S_ISREG(status.st_mode) or (
                require_secure and (status.st_uid != 0 or stat.S_IMODE(status.st_mode) != 0o600)
            ):
                raise ProfileError(
                    "DNS profile files must be regular files owned by root, mode 0600"
                )
            os.unlink(path)
    except OSError as exc:
        raise ProfileError(f"the DNS profile could not be removed: {exc.strerror}") from exc


def read_materialized(
    policy: DnsProfilesPolicy,
    profile_id: str,
    *,
    require_secure: bool = True,
) -> MaterializedProfile:
    """Resolve a short profile ID to its provider and credentials as root."""

    profile_id = check_profile_id(profile_id)
    directory = os.fspath(policy.directory)
    _secure_directory(directory, require_secure=require_secure)
    credentials = credentials_path(directory, profile_id)
    metadata = metadata_path(directory, profile_id)
    try:
        metadata_status = os.stat(metadata, follow_symlinks=False)
        credentials_status = os.stat(credentials, follow_symlinks=False)
        with open(metadata, encoding="utf-8") as stream:
            raw = stream.read(4097)
    except OSError as exc:
        raise ProfileError(f"DNS profile {profile_id!r} is not materialized") from exc
    for status in (metadata_status, credentials_status):
        if not stat.S_ISREG(status.st_mode) or (
            require_secure and (status.st_uid != 0 or stat.S_IMODE(status.st_mode) != 0o600)
        ):
            raise ProfileError("DNS profile files must be regular files owned by root, mode 0600")
    if len(raw) > 4096:
        raise ProfileError("the DNS profile metadata is too large")
    try:
        document = json.loads(raw)
    except ValueError:
        raise ProfileError("the DNS profile metadata is not JSON") from None
    expected = {"schema_version", "profile", "provider", "key_id", "revision"}
    if not isinstance(document, dict) or set(document) != expected:
        raise ProfileError("the DNS profile metadata has the wrong shape")
    if document["schema_version"] != 1 or document["profile"] != profile_id:
        raise ProfileError("the DNS profile metadata does not name this profile")
    provider_id = document["provider"]
    key_id = document["key_id"]
    revision = document["revision"]
    if not isinstance(provider_id, str) or not isinstance(key_id, str):
        raise ProfileError("the DNS profile metadata has invalid bindings")
    if re.fullmatch(r"[0-9a-f]{16}", key_id) is None:
        raise ProfileError("the DNS profile metadata has an invalid key ID")
    revision = check_revision(revision)
    try:
        provider = provider_by_id(provider_id)
    except ProviderCatalogError as exc:
        raise ProfileError(str(exc)) from exc
    return MaterializedProfile(profile_id, provider, credentials, revision, key_id)


def materialized_secret_values(materialized: MaterializedProfile) -> tuple[str, ...]:
    """Read only the values marked secret, for scrubbing certbot diagnostics."""

    try:
        with open(materialized.credentials_path, encoding="utf-8") as stream:
            text = stream.read(MAX_CIPHERTEXT + 1)
    except OSError as exc:
        raise ProfileError(f"DNS profile {materialized.profile_id!r} cannot be read") from exc
    if len(text) > MAX_CIPHERTEXT:
        raise ProfileError("the materialized DNS profile is too large")
    provider = materialized.provider
    if provider.adapter == "google-service-account":
        try:
            document = json.loads(text)
        except ValueError:
            raise ProfileError("the materialized DNS profile is not valid JSON") from None
        if not isinstance(document, dict):
            raise ProfileError("the materialized DNS profile is not a JSON object")
        return tuple(value for value in document.values() if isinstance(value, str) and value)

    values: dict[str, str] = {}
    for line in text.splitlines():
        if not line or line.startswith("["):
            continue
        key, separator, value = line.partition(" = ")
        if not separator:
            raise ProfileError("the materialized DNS profile has an invalid line")
        values[key] = value
    keys: dict[str, str]
    if provider.adapter == "azure-service-principal":
        keys = {
            "client_id": "dns_azure_sp_client_id",
            "client_secret": "dns_azure_sp_client_secret",
            "tenant_id": "dns_azure_tenant_id",
        }
    elif provider.adapter == "aws-shared-credentials":
        keys = {
            "access_key_id": "aws_access_key_id",
            "secret_access_key": "aws_secret_access_key",
        }
    else:
        keys = {field.id: field.key for field in provider.fields if field.key is not None}
    result = []
    for field in provider.fields:
        credential_key = keys.get(field.id)
        if field.secret and credential_key is not None and credential_key in values:
            result.append(values[credential_key])
    return tuple(value for value in result if value)


def build_request(
    request_id: str,
    *,
    profile_id: str,
    provider_id: str,
    schema_version: int,
    key_id: str,
    revision: int,
    ciphertext: bytes,
    remove: bool = False,
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
                "profile_schema_version": schema_version,
                "key_id": key_id,
                "revision": revision,
                "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
                "remove": remove,
            },
        },
        separators=(",", ":"),
    )
