"""Apply a sealed NDES profile through the exact root-only stdin boundary."""

from __future__ import annotations

import base64
import binascii
import fcntl
import os
import sys
from pathlib import Path
from typing import BinaryIO, TextIO

from haproxy_mgmt import ndes_profiles
from haproxy_mgmt.cli import cert_job
from haproxy_mgmt.config import DEFAULT_POLICY_PATH, ConfigError, load_policy, load_registry
from haproxy_mgmt.dns_profile_keys import KeyFileError, read_private_key
from haproxy_mgmt.dns_profiles import ProfileError, check_profile_id, check_revision
from haproxy_mgmt.envelope import envelope
from haproxy_mgmt.helper_protocol import HelperProtocolError, config_error_code, write_document

OPERATION = ndes_profiles.OPERATION
HELPER = ndes_profiles.HELPER
PARAMETERS = frozenset(
    {"profile", "provider", "profile_schema_version", "key_id", "revision", "ciphertext", "remove"}
)


def main(
    argv: list[str] | None = None,
    *,
    policy_path: Path = DEFAULT_POLICY_PATH,
    input_stream: BinaryIO | None = None,
    output_stream: TextIO | None = None,
    error_stream: TextIO | None = None,
    require_secure: bool = True,
    require_root: bool = True,
) -> int:
    writer = output_stream or sys.stdout
    errors = error_stream or sys.stderr
    try:
        request = cert_job.read_request(
            OPERATION,
            parameters=PARAMETERS,
            input_stream=input_stream,
            argv=sys.argv[1:] if argv is None else argv,
            require_root=require_root,
            helper_name="haproxy-ndes-profile-apply-helper",
        )
    except HelperProtocolError as exc:
        errors.write(f"ERROR: {exc}\n")
        return exc.exit_code
    refuse = cert_job.Refuse(OPERATION, request, writer, errors)
    try:
        profile_id = check_profile_id(request.parameters.get("profile"))
        revision = check_revision(request.parameters.get("revision"))
        key_id = request.parameters.get("key_id")
        if not isinstance(key_id, str) or ndes_profiles.KEY_ID.fullmatch(key_id) is None:
            raise ProfileError("key ID is invalid")
        if request.parameters.get("provider") != ndes_profiles.PROVIDER:
            raise ProfileError("provider must be ndes")
        version = request.parameters.get("profile_schema_version")
        if type(version) is not int or version != 1:
            raise ProfileError("profile schema is unsupported")
        encoded = request.parameters.get("ciphertext")
        if not isinstance(encoded, str) or len(encoded) > ndes_profiles.MAX_CIPHERTEXT * 2:
            raise ProfileError("ciphertext must be bounded base64")
        ciphertext = base64.b64decode(encoded, validate=True)
        remove = request.parameters.get("remove", False)
        if not isinstance(remove, bool):
            raise ProfileError("remove must be true or false")
    except (ProfileError, binascii.Error):
        return refuse("bad_input", "NDES profile request has invalid fields", 65)
    try:
        policy = load_policy(policy_path, require_secure=require_secure)
    except ConfigError as exc:
        return refuse(config_error_code(exc.exit_code), str(exc), exc.exit_code)
    if policy.ndes is None:
        return refuse("dependency_unavailable", "runtime policy.ndes is not configured", 78)
    try:
        selected = None
        for path in policy.ndes.profiles.private_keys:
            candidate = read_private_key(path, require_secure=require_secure)
            if candidate.key_id == key_id:
                selected = candidate
                break
        if selected is None:
            return refuse("profile_key_unavailable", "NDES profile key is unavailable", 78)
    except KeyFileError:
        return refuse("dependency_unavailable", "NDES profile key cannot be read", 78)
    try:
        opened = ndes_profiles.open_profile(
            selected, ciphertext, profile_id=profile_id, revision=revision
        )
    except ProfileError as exc:
        return refuse("profile_binding_mismatch", str(exc), 65)
    try:
        ndes_profiles.secure_directory(
            policy.ndes.profiles.directory, require_secure=require_secure
        )
        fd = os.open(
            policy.ndes.profiles.directory / ".apply.lock",
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
        )
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if remove:
                # The box was opened above, so a removal is bound to the same
                # profile and revision as an apply; the row is deleted by the
                # worker only after this record is gone.
                references = ndes_profiles.pending_requests(
                    policy.ndes, opened.profile_id, require_secure=require_secure
                )
                if policy.certificate_registry is not None:
                    registry = load_registry(
                        policy.certificate_registry, require_secure=require_secure
                    )
                    references += tuple(
                        entry.certificate_id
                        for entry in registry.certificates.values()
                        if entry.source.ndes_profile == opened.profile_id
                    )
                if references:
                    return refuse(
                        "profile_in_use",
                        f"profile {opened.profile_id!r} is referenced by certificate(s): "
                        + ", ".join(sorted(set(references))),
                        65,
                    )
                ndes_profiles.remove_materialized(
                    policy.ndes, opened.profile_id, require_secure=require_secure
                )
            else:
                ndes_profiles.materialize(policy.ndes, opened, require_secure=require_secure)
        finally:
            os.close(fd)
    except BlockingIOError:
        return refuse("busy", "another NDES profile apply is running", 75)
    except (ProfileError, OSError, ConfigError):
        return refuse(
            "dependency_unavailable",
            "NDES profile could not be applied; check protected policy and state",
            78,
        )
    write_document(
        writer,
        envelope(
            operation=OPERATION,
            outcome="done",
            cluster=None,
            request_id=request.request_id,
            result={
                "profile": opened.profile_id,
                "provider": "ndes",
                "key_id": opened.key_id,
                "revision": opened.revision,
                **({"removed": True} if remove else {}),
            },
        ),
    )
    return 0
