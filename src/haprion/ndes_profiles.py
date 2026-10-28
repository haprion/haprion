"""NDES credentials sealed by the web and materialized only by root.

The key files retain their DNS-profile names for compatibility. A distinct,
strict plaintext shape prevents a DNS box from becoming an NDES credential.
One atomic root-only record holds both the binding and the challenge; clients
receive a separate challenge file only inside their protected request staging.
"""

from __future__ import annotations

import base64
import json
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from haprion import atomic_file
from haprion.config import NdesPolicy
from haprion.dns_profile_keys import (
    DnsProfilePrivateKey,
    DnsProfilePublicKey,
    KeyFileError,
    open_sealed,
    seal,
)
from haprion.dns_profiles import ProfileError, check_profile_id, check_revision

OPERATION = "ndes_profile_apply"
HELPER = "/opt/haprion/current/bin/haprion-ndes-profile-apply-helper"
MAX_CIPHERTEXT = 16384
MAX_RECORD = 16384
SCHEMA_VERSION = 1
PROVIDER = "ndes"
PRINTABLE = re.compile(r"[A-Za-z0-9 '()+,./:=?\-]{1,4096}")
KEY_ID = re.compile(r"[0-9a-f]{16}")


@dataclass(frozen=True, slots=True)
class OpenedProfile:
    profile_id: str
    endpoint: str
    key_id: str
    revision: int
    challenge: str = field(repr=False)


def check_endpoint(value: object) -> str:
    if not isinstance(value, str) or len(value) > 2048:
        raise ProfileError("endpoint must be an HTTPS URL")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise ProfileError("endpoint must be an HTTPS URL") from None
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or not parsed.path.startswith("/")
        or port == 0
        or any(ord(c) <= 32 or ord(c) >= 127 or c in "\\\"'" for c in value)
    ):
        raise ProfileError("endpoint must be an HTTPS URL without credentials or query")
    return value


def check_challenge(value: object) -> str:
    if not isinstance(value, str) or PRINTABLE.fullmatch(value) is None:
        raise ProfileError("challenge must be 1-4096 ASN.1 PrintableString characters")
    return value


def seal_profile(
    key: DnsProfilePublicKey, *, profile_id: str, endpoint: str, challenge: str, revision: int
) -> bytes:
    check_profile_id(profile_id)
    check_endpoint(endpoint)
    check_challenge(challenge)
    check_revision(revision)
    record = {
        "profile_type": PROVIDER,
        "schema_version": SCHEMA_VERSION,
        "profile_id": profile_id,
        "key_id": key.key_id,
        "revision": revision,
        "endpoint": endpoint,
        "challenge": challenge,
    }
    return seal(key, json.dumps(record, separators=(",", ":")).encode("utf-8"))


def open_profile(
    key: DnsProfilePrivateKey, ciphertext: bytes, *, profile_id: str, revision: int
) -> OpenedProfile:
    check_profile_id(profile_id)
    check_revision(revision)
    if not 48 <= len(ciphertext) <= MAX_CIPHERTEXT:
        raise ProfileError("ciphertext size is invalid")
    try:
        raw = open_sealed(key, ciphertext)
        row = json.loads(raw)
    except (KeyFileError, ValueError, UnicodeError):
        raise ProfileError("NDES profile could not be opened") from None
    expected = {
        "profile_type",
        "schema_version",
        "profile_id",
        "key_id",
        "revision",
        "endpoint",
        "challenge",
    }
    if not isinstance(row, dict) or set(row) != expected:
        raise ProfileError("opened NDES profile has an invalid shape")
    if (
        row["profile_type"] != PROVIDER
        or type(row["schema_version"]) is not int
        or row["schema_version"] != SCHEMA_VERSION
    ):
        raise ProfileError("opened NDES profile type or schema does not match")
    if row["profile_id"] != profile_id or row["key_id"] != key.key_id:
        raise ProfileError("opened NDES profile identity does not match")
    sealed_revision = check_revision(row["revision"])
    if sealed_revision < revision:
        raise ProfileError("opened NDES profile revision is stale")
    return OpenedProfile(
        profile_id,
        check_endpoint(row["endpoint"]),
        key.key_id,
        sealed_revision,
        check_challenge(row["challenge"]),
    )


def secure_directory(path: Path, *, require_secure: bool) -> None:
    if not path.is_absolute():
        raise ProfileError("NDES directory must be absolute")
    # The final directory and every ancestor must resist replacement by app identities.
    for candidate in (path, *path.parents):
        try:
            info = candidate.lstat()
        except OSError:
            raise ProfileError("NDES directory is unavailable") from None
        if not stat.S_ISDIR(info.st_mode):
            raise ProfileError("NDES directories cannot traverse symlinks")
        if require_secure and (info.st_uid != 0 or info.st_mode & 0o022):
            raise ProfileError("NDES directory ancestors must be root-owned and protected")
    if require_secure and stat.S_IMODE(path.stat().st_mode) != 0o700:
        raise ProfileError("NDES directory must be root-owned mode 0700")


def secure_read(path: Path, *, require_secure: bool, secret: bool = True) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_RECORD:
                raise ProfileError("NDES file is not a bounded regular file")
            if require_secure and (info.st_uid != 0 or info.st_mode & (0o077 if secret else 0o022)):
                raise ProfileError("NDES files must be root-owned and protected")
            content = handle.read(MAX_RECORD + 1)
            if len(content) > MAX_RECORD:
                raise ProfileError("NDES file is too large")
            return content
    except OSError:
        raise ProfileError("NDES file is unavailable") from None


def record_path(policy: NdesPolicy, profile_id: str) -> Path:
    check_profile_id(profile_id)
    return policy.profiles.directory / (profile_id + ".json")


def resolve(policy: NdesPolicy, profile_id: str, *, require_secure: bool = True) -> OpenedProfile:
    secure_directory(policy.profiles.directory, require_secure=require_secure)
    try:
        row = json.loads(
            secure_read(record_path(policy, profile_id), require_secure=require_secure)
        )
    except (ValueError, UnicodeError):
        raise ProfileError("NDES profile record is unreadable") from None
    expected = {
        "profile_type",
        "schema_version",
        "profile_id",
        "key_id",
        "revision",
        "endpoint",
        "challenge",
    }
    if not isinstance(row, dict) or set(row) != expected or row["profile_type"] != PROVIDER:
        raise ProfileError("NDES profile record has an invalid shape")
    if (
        type(row["schema_version"]) is not int
        or row["schema_version"] != 1
        or row["profile_id"] != profile_id
    ):
        raise ProfileError("NDES profile record identity does not match")
    key_id = row["key_id"]
    if not isinstance(key_id, str) or KEY_ID.fullmatch(key_id) is None:
        raise ProfileError("NDES profile key ID is invalid")
    endpoint = check_endpoint(row["endpoint"])
    if policy.server(endpoint) is None:
        raise ProfileError("NDES endpoint is not a server confirmed in the runtime policy")
    return OpenedProfile(
        profile_id,
        endpoint,
        key_id,
        check_revision(row["revision"]),
        check_challenge(row["challenge"]),
    )


def materialize(policy: NdesPolicy, opened: OpenedProfile, *, require_secure: bool = True) -> None:
    secure_directory(policy.profiles.directory, require_secure=require_secure)
    check_profile_id(opened.profile_id)
    check_revision(opened.revision)
    check_challenge(opened.challenge)
    if policy.server(check_endpoint(opened.endpoint)) is None:
        raise ProfileError("NDES endpoint is not a server confirmed in the runtime policy")
    path = record_path(policy, opened.profile_id)
    # Callers serialize profile applies with the certificate operation lock.
    if path.exists() or path.is_symlink():
        previous = resolve(policy, opened.profile_id, require_secure=require_secure)
        if opened.revision < previous.revision or (
            opened.revision == previous.revision and opened != previous
        ):
            raise ProfileError("NDES profile revision cannot be replayed or changed")
    record = {
        "profile_type": PROVIDER,
        "schema_version": 1,
        "profile_id": opened.profile_id,
        "key_id": opened.key_id,
        "revision": opened.revision,
        "endpoint": opened.endpoint,
        "challenge": opened.challenge,
    }
    try:
        atomic_file.write(
            Path(path), json.dumps(record, separators=(",", ":")).encode("utf-8"), mode=0o600
        )
    except OSError:
        raise ProfileError("NDES profile could not be materialized") from None


def pending_requests(
    policy: NdesPolicy, profile_id: str, *, require_secure: bool = True
) -> tuple[str, ...]:
    """Certificate IDs of enrollment requests still bound to the profile.

    A request directory under the state root holds the key of a request the
    CA has not answered yet, and its record names the profile whose challenge
    signed it. Removing that profile would strand the request: a resume would
    have no challenge to open. A directory without a readable record is
    counted too - what cannot be read cannot be shown to be finished.
    """

    check_profile_id(profile_id)
    secure_directory(policy.state_root, require_secure=require_secure)
    bound: list[str] = []
    for entry in sorted(policy.state_root.iterdir()):
        if entry.is_symlink() or not entry.is_dir():
            continue
        try:
            record = json.loads(secure_read(entry / "request.json", require_secure=require_secure))
        except (ProfileError, ValueError, UnicodeError):
            bound.append(entry.name)
            continue
        if isinstance(record, dict) and record.get("profile") == profile_id:
            certificate = record.get("certificate")
            bound.append(certificate if isinstance(certificate, str) else entry.name)
    return tuple(bound)


def remove_materialized(
    policy: NdesPolicy, profile_id: str, *, require_secure: bool = True
) -> None:
    """Remove the root-only record. A missing record makes a retry idempotent."""

    secure_directory(policy.profiles.directory, require_secure=require_secure)
    path = record_path(policy, profile_id)
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    except OSError:
        raise ProfileError("NDES profile record is unavailable") from None
    if not stat.S_ISREG(info.st_mode):
        raise ProfileError("NDES profile record is not a regular file")
    try:
        path.unlink()
    except OSError:
        raise ProfileError("NDES profile record could not be removed") from None


def build_request(
    request_id: str,
    *,
    profile_id: str,
    schema_version: int,
    key_id: str,
    revision: int,
    ciphertext: bytes,
    remove: bool = False,
) -> str:
    return json.dumps(
        {
            "schema_version": 1,
            "operation": OPERATION,
            "cluster": None,
            "request_id": request_id,
            "parameters": {
                "profile": profile_id,
                "provider": PROVIDER,
                "profile_schema_version": schema_version,
                "key_id": key_id,
                "revision": revision,
                "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
                **({"remove": True} if remove else {}),
            },
        },
        separators=(",", ":"),
    )
