"""Materialize one sealed DNS provider profile across the root boundary."""

from __future__ import annotations

import base64
import binascii
import configparser
import sys
from pathlib import Path
from typing import BinaryIO, TextIO

from haprion import dns_profiles, exit_codes, labels
from haprion.cli import cert_job
from haprion.config import (
    DEFAULT_POLICY_PATH,
    ConfigError,
    load_policy,
    load_registry,
)
from haprion.dns_profile_keys import KeyFileError, read_private_key
from haprion.dns_provider_catalog import provider_by_id
from haprion.envelope import Message, envelope
from haprion.helper_protocol import HelperProtocolError, config_error_code, write_document

OPERATION = dns_profiles.OPERATION
PARAMETERS = frozenset(
    {
        "profile",
        "provider",
        "profile_schema_version",
        "key_id",
        "revision",
        "ciphertext",
        "remove",
    }
)
HELPER = dns_profiles.HELPER
RENEWAL_DIRECTORY = Path("/etc/letsencrypt/renewal")
_TOP_SECTION = "haprion.lineage"


def _renewal_references(directory: Path, credentials: str) -> tuple[str, ...]:
    """Lineages whose parsed renewal parameters name this exact file.

    Certbot writes ``renewal/*.conf`` with configobj: the lineage paths
    (``version``, ``archive_dir``, ``cert`` ...) stand above the first
    section header and ``[renewalparams]`` follows. ``RawConfigParser``
    rejects keys before a header, so the file is read under a synthetic
    top section; the credentials flag lives in ``[renewalparams]`` but every
    section is compared so a moved key cannot hide a reference.
    """

    references: list[str] = []
    try:
        candidates = tuple(directory.glob("*.conf")) if directory.is_dir() else ()
        for path in candidates:
            parser = configparser.RawConfigParser(interpolation=None, strict=False)
            parser.read_string(
                f"[{_TOP_SECTION}]\n" + path.read_text(encoding="utf-8"), source=str(path)
            )
            if any(
                value.strip() == credentials
                for section in parser.sections()
                for _, value in parser.items(section)
            ):
                references.append(path.stem)
    except (OSError, configparser.Error) as exc:
        raise dns_profiles.ProfileError(
            f"cannot inspect certbot renewal configuration: {exc}"
        ) from exc
    return tuple(sorted(references))


def _key_id(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 16
        or any(c not in "0123456789abcdef" for c in value)
    ):
        raise HelperProtocolError(
            "parameters.key_id must be a 16-character key ID", exit_code=exit_codes.REFUSED
        )
    return value


def main(
    argv: list[str] | None = None,
    *,
    policy_path: Path = DEFAULT_POLICY_PATH,
    input_stream: BinaryIO | None = None,
    output_stream: TextIO | None = None,
    error_stream: TextIO | None = None,
    require_secure: bool = True,
    require_root: bool = True,
    renewal_directory: Path = RENEWAL_DIRECTORY,
) -> int:
    argv = sys.argv[1:] if argv is None else argv
    writer = output_stream or sys.stdout
    errors = error_stream or sys.stderr
    try:
        request = cert_job.read_request(
            OPERATION,
            parameters=PARAMETERS,
            input_stream=input_stream,
            argv=argv,
            require_root=require_root,
            helper_name="haprion-dns-profile-apply-helper",
        )
    except HelperProtocolError as exc:
        errors.write(f"ERROR: {exc}\n")
        return exc.exit_code
    refuse = cert_job.Refuse(OPERATION, request, writer, errors)
    try:
        profile_id = dns_profiles.check_profile_id(request.parameters.get("profile"))
        provider = request.parameters.get("provider")
        if not isinstance(provider, str):
            raise dns_profiles.ProfileError("provider must be a provider ID")
        if request.parameters.get("profile_schema_version") != dns_profiles.SCHEMA_VERSION:
            raise dns_profiles.ProfileError("profile schema version is not supported")
        key_id = _key_id(request.parameters.get("key_id"))
        revision = dns_profiles.check_revision(request.parameters.get("revision"))
        encoded = request.parameters.get("ciphertext")
        if not isinstance(encoded, str) or len(encoded) > dns_profiles.MAX_CIPHERTEXT * 2:
            raise dns_profiles.ProfileError("ciphertext must be base64")
        ciphertext = base64.b64decode(encoded, validate=True)
        remove = request.parameters.get("remove", False)
        if not isinstance(remove, bool):
            raise dns_profiles.ProfileError("remove must be true or false")
    except (dns_profiles.ProfileError, HelperProtocolError, binascii.Error, ValueError) as exc:
        return refuse("bad_input", str(exc), exit_codes.REFUSED)

    try:
        policy = load_policy(policy_path, require_secure=require_secure)
    except ConfigError as exc:
        return refuse(config_error_code(exc.exit_code), str(exc), exc.exit_code)
    profile_policy = policy.acme.dns_profiles if policy.acme is not None else None
    if profile_policy is None:
        return refuse(
            "dependency_unavailable",
            "runtime policy.acme.dns_profiles is not configured",
            exit_codes.CONFIG,
        )

    selected = None
    try:
        for path in profile_policy.private_keys:
            candidate = read_private_key(path, require_secure=require_secure)
            if candidate.key_id == key_id:
                selected = candidate
                break
    except KeyFileError as exc:
        return refuse("dependency_unavailable", str(exc), exit_codes.CONFIG)
    if selected is None:
        return refuse(
            "profile_key_unavailable",
            "the profile's private key is not configured",
            exit_codes.CONFIG,
        )

    try:
        opened = dns_profiles.open_profile(
            selected,
            ciphertext,
            profile_id=profile_id,
            provider_id=provider,
            revision=revision,
        )
    except dns_profiles.ProfileError as exc:
        errors.write(f"ERROR: [profile_binding_mismatch] {exc}\n")
        return write_document(
            writer,
            envelope(
                operation=OPERATION,
                outcome="blocked",
                cluster=None,
                request_id=request.request_id,
                result=None,
                error=Message(
                    code="profile_binding_mismatch",
                    message=str(exc),
                    details={"profile": profile_id, "binding": "sealed_profile"},
                ),
            ),
            exit_codes.BLOCKED,
        )

    if remove:
        try:
            if policy.certificate_registry is None:
                raise ConfigError(
                    "no certificate registry is configured", exit_code=exit_codes.CONFIG
                )
            registry = load_registry(policy.certificate_registry, require_secure=require_secure)
            registry_references = tuple(
                entry.certificate_id
                for entry in registry.certificates.values()
                if entry.source.dns_profile == profile_id
            )
            renewal_references = _renewal_references(
                renewal_directory,
                dns_profiles.credentials_path(profile_policy.directory, profile_id),
            )
        except (ConfigError, dns_profiles.ProfileError) as exc:
            return refuse("dependency_unavailable", str(exc), exit_codes.CONFIG)
        references = tuple(sorted(set(registry_references) | set(renewal_references)))
        if references:
            return refuse(
                "profile_in_use",
                f"profile {profile_id!r} is referenced by {labels.noun(len(references), 'certificate')}: "
                f"{', '.join(references)}",
                exit_codes.REFUSED,
            )
        try:
            dns_profiles.remove_materialized(
                profile_policy, profile_id, require_secure=require_secure
            )
        except dns_profiles.ProfileError as exc:
            return refuse("dependency_unavailable", str(exc), exit_codes.CONFIG)
        result = {
            "profile": opened.profile_id,
            "provider": opened.provider_id,
            "key_id": opened.key_id,
            "revision": opened.revision,
            "plugin": provider_by_id(opened.provider_id).plugin,
            "removed": True,
        }
    else:
        try:
            materialized = dns_profiles.materialize(
                profile_policy, opened, require_secure=require_secure
            )
        except dns_profiles.ProfileError as exc:
            return refuse("dependency_unavailable", str(exc), exit_codes.CONFIG)
        result = {
            "profile": materialized.profile_id,
            "provider": materialized.provider.id,
            "key_id": materialized.key_id,
            "revision": materialized.revision,
            "plugin": materialized.provider.plugin,
        }

    return write_document(
        writer,
        envelope(
            operation=OPERATION,
            outcome="done",
            cluster=None,
            request_id=request.request_id,
            result=result,
        ),
        0,
    )


if __name__ == "__main__":
    raise SystemExit(main())
