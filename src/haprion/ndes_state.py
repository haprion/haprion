"""Where an NDES request's state lives, and whether it is still waiting.

Its own module because both the enrollment engine and the certificate
listing need it, and the listing must not import the engine (which imports
the import path, which imports the listing).
"""

from __future__ import annotations

import hashlib
import json
import shutil
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from haprion import atomic_file
from haprion.config import CERTIFICATE_ID, CLUSTER_ID, RECEIVER_FORMATS, RECEIVER_ID

MAX_RECORD_BYTES = 64 * 1024
TARGETS_FILE = "targets.json"


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


def write_targets(
    state_root: Path,
    certificate_id: str,
    *,
    clusters: tuple[str, ...],
    receivers: tuple[str, ...],
    formats: Mapping[str, str] | None = None,
    interface: bool = False,
    exportable: bool = False,
) -> None:
    """Where the certificate goes once the CA answers, kept beside the request.

    Until 2026-09-17 a request the CA was holding was registered at once,
    without material and with these targets, so the listing could show it.
    But the registry's readers assume every entry has a file: the cluster's
    certificate list is built from it and the deploy preflight reads each
    file, so one waiting request refused every rollout to the clusters it
    named (review 2026-09-17, finding 1). The targets live here instead, and
    the registry names the certificate only once it exists.
    """

    directory = request_directory(state_root, certificate_id)
    targets = {
        "clusters": list(clusters),
        "receivers": list(receivers),
        "formats": dict(formats or {}),
        **({"interface": True} if interface else {}),
        **({"exportable": True} if exportable else {}),
    }
    atomic_file.write(directory / TARGETS_FILE, json.dumps(targets).encode("utf-8"), mode=0o600)


def request_targets(
    state_root: Path, certificate_id: str
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """The targets a request was made with; empty when none were kept."""

    directory = request_directory(state_root, certificate_id)
    loaded = _bounded_json(directory / TARGETS_FILE, MAX_RECORD_BYTES)
    if not isinstance(loaded, dict):
        return (), ()
    return _ids(loaded.get("clusters"), CLUSTER_ID), _ids(loaded.get("receivers"), RECEIVER_ID)


def request_is_interface(state_root: Path, certificate_id: str) -> bool:
    """Whether the waiting request is for the manager's own interface (B188)."""

    directory = request_directory(state_root, certificate_id)
    loaded = _bounded_json(directory / TARGETS_FILE, MAX_RECORD_BYTES)
    return isinstance(loaded, dict) and loaded.get("interface") is True


def request_is_exportable(state_root: Path, certificate_id: str) -> bool:
    """Whether the waiting request is for an exportable certificate (B255)."""

    directory = request_directory(state_root, certificate_id)
    loaded = _bounded_json(directory / TARGETS_FILE, MAX_RECORD_BYTES)
    return isinstance(loaded, dict) and loaded.get("exportable") is True


def request_formats(state_root: Path, certificate_id: str) -> dict[str, str]:
    """The receiver formats a request was made with (B159); a file older than
    the key, or a format not in the list, reads as `pem` by saying nothing."""

    directory = request_directory(state_root, certificate_id)
    loaded = _bounded_json(directory / TARGETS_FILE, MAX_RECORD_BYTES)
    if not isinstance(loaded, dict):
        return {}
    raw = loaded.get("formats")
    if not isinstance(raw, dict):
        return {}
    return {
        str(receiver_id): str(form)
        for receiver_id, form in raw.items()
        if isinstance(receiver_id, str)
        and RECEIVER_ID.fullmatch(receiver_id)
        and form in RECEIVER_FORMATS
    }


def _ids(value: Any, pattern: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(
        dict.fromkeys(item for item in value if isinstance(item, str) and pattern.fullmatch(item))
    )


def _bounded_json(path: Path, maximum: int) -> Any:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError):
        return None


@dataclass(frozen=True, slots=True)
class PendingRequest:
    """One request the CA is still holding, as the listing shows it."""

    certificate_id: str
    profile_id: str
    domains: tuple[str, ...]
    clusters: tuple[str, ...]
    receivers: tuple[str, ...]


def pending_requests(state_root: Path) -> tuple[PendingRequest, ...]:
    """Every request still waiting on the CA, read as root by the listing helper.

    The registry does not name these (see `write_targets`), so the listing
    has to ask here to show them at all. A directory whose record cannot be
    read, or whose certificate ID is not one, is not a request - "pending" is
    a claim, and an unreadable directory cannot make it.
    """

    found: list[PendingRequest] = []
    try:
        entries = sorted(state_root.iterdir())
    except OSError:
        return ()
    for entry in entries:
        try:
            if entry.is_symlink() or not entry.is_dir() or (entry / "cert.pem").exists():
                continue
        except OSError:
            continue
        record = _bounded_json(entry / "request.json", MAX_RECORD_BYTES)
        if not isinstance(record, dict):
            continue
        certificate_id = record.get("certificate")
        profile_id = record.get("profile")
        domains = record.get("domains")
        if (
            not isinstance(certificate_id, str)
            or not CERTIFICATE_ID.fullmatch(certificate_id)
            or request_directory(state_root, certificate_id) != entry
            or not isinstance(profile_id, str)
            or not isinstance(domains, list)
        ):
            continue
        clusters, receivers = request_targets(state_root, certificate_id)
        found.append(
            PendingRequest(
                certificate_id,
                profile_id,
                tuple(name for name in domains if isinstance(name, str)),
                clusters,
                receivers,
            )
        )
    return tuple(found)


def remove_request(state_root: Path, certificate_id: str) -> bool:
    """Remove one request's directory, key and all. True when there was one.

    A request the CA rejected, one that never reached Certmonger, or one
    whose certificate is being deleted has nothing left to resume; leaving
    the directory made the ID unusable and the profile unremovable (review
    2026-09-17, finding 2).
    """

    directory = request_directory(state_root, certificate_id)
    try:
        info = directory.lstat()
    except FileNotFoundError:
        return False
    if not stat.S_ISDIR(info.st_mode):
        raise OSError(f"NDES request path is not a directory: {directory}")
    shutil.rmtree(directory)
    return True


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
