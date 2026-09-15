"""Where an NDES request's state lives, and whether it is still waiting.

Its own module because both the enrollment engine and the certificate
listing need it, and the listing must not import the engine (which imports
the import path, which imports the listing).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

MAX_RECORD_BYTES = 64 * 1024


def request_directory(state_root: Path, certificate_id: str) -> Path:
    """Where one certificate's request state lives: hashed, so an ID is never a path."""

    return state_root / hashlib.sha256(certificate_id.encode()).hexdigest()[:24]


def request_is_pending(state_root: Path, certificate_id: str) -> bool:
    """Whether a request for this ID is still waiting on the CA.

    The directory outlives a successful enrollment by nothing - it is removed
    once the material is imported - so its record, without material beside
    it, is exactly a request in flight. Read as root by the listing helper;
    anything unreadable is not pending, because "pending" is a claim.
    """

    directory = request_directory(state_root, certificate_id)
    record = directory / "request.json"
    try:
        if directory.is_symlink() or not record.is_file():
            return False
        return not (directory / "cert.pem").exists()
    except OSError:
        return False


def request_record(state_root: Path, certificate_id: str) -> dict[str, Any] | None:
    """The request's own record, for a resume that names only the certificate.

    The record binds the profile, the names, the endpoint and the trust the
    request was made with; the enrollment engine refuses a resume that
    disagrees with it. Reading it here lets a resume be asked for with
    nothing but the ID - the rest is what the request already is.
    """

    directory = request_directory(state_root, certificate_id)
    record = directory / "request.json"
    try:
        if directory.is_symlink() or record.is_symlink() or not record.is_file():
            return None
        if record.stat().st_size > MAX_RECORD_BYTES:
            return None
        loaded = json.loads(record.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError):
        return None
    return loaded if isinstance(loaded, dict) else None


#
# The renewal record: what the last scheduled renewal did to one certificate,
# written by `ndes_renew` as root and read by the listing helper as root.
#
RECORDS_DIRECTORY = "renewals"
MAX_RENEWAL_RECORD_BYTES = 16 * 1024


def records_directory(state_root: Path) -> Path:
    return state_root / RECORDS_DIRECTORY


def record_path(state_root: Path, certificate_id: str) -> Path:
    """Hashed like the request directory, so an ID is never a path."""

    return records_directory(state_root) / (
        request_directory(state_root, certificate_id).name + ".json"
    )


def renewal_record(state_root: Path, certificate_id: str) -> dict[str, Any] | None:
    """The last attempt's record, or None; anything unreadable is no record."""

    path = record_path(state_root, certificate_id)
    try:
        if (
            path.is_symlink()
            or not path.is_file()
            or path.stat().st_size > MAX_RENEWAL_RECORD_BYTES
        ):
            return None
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError):
        return None
    if not isinstance(loaded, dict):
        return None
    attempted = loaded.get("attempted_at")
    outcome = loaded.get("outcome")
    message = loaded.get("message")
    if (
        not isinstance(attempted, str)
        or outcome not in {"renewed", "pending", "failed"}
        or not isinstance(message, str)
    ):
        return None
    return {"attempted_at": attempted, "outcome": outcome, "message": message[:1000]}
