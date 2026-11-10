"""Where a blocklist lives on the manager, and the sealed secret that gets it there (B500).

Settings keeps each list in the database; the list's password or token is
sealed by the web against the installation's DNS profile key (B146), which the
web cannot open again. The worker's job hands both to a root helper, which
opens the secret, checks that the box was sealed for this list and this
revision, and writes the definition here, root-only. The refresh timer reads it
from here and nowhere else, so the CLI fetches a list without the web.

    /etc/haprion/blocklists/<name>.json    the definition and the secret, 0600 in a 0700 directory
    /var/lib/haprion/blocklists/<name>.lst the last good list, before its exceptions
    /var/lib/haprion/blocklists/state.json when each list was fetched or failed, and why

The sealed plaintext carries its own binding, as a DNS profile's does: a box
sealed for one list or an older revision opens and is refused.
"""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from haprion import atomic_file, blocklists
from haprion.dns_profile_keys import (
    DnsProfilePrivateKey,
    DnsProfilePublicKey,
    KeyFileError,
    open_sealed,
    seal,
)

OPERATION = "blocklist_apply"
SCHEMA_VERSION = 1
DEFINITIONS = Path("/etc/haprion/blocklists")
STATE = Path("/var/lib/haprion/blocklists")
MAX_REVISION = 1_000_000
MAX_CIPHERTEXT = 16384
SUFFIX = ".json"
LIST_SUFFIX = ".lst"
STATE_FILE = "state.json"


class StoreError(ValueError):
    """A definition, a box or a state file that is not what it must be."""


@dataclass(frozen=True)
class Stored:
    """A definition as root keeps it."""

    definition: blocklists.Definition
    secret: str
    revision: int


@dataclass(frozen=True)
class ListState:
    """What the last attempt at a list did; times are ISO 8601 in UTC."""

    fetched_at: str | None = None
    attempted_at: str | None = None
    failed_at: str | None = None
    error: str = ""
    entries: int = 0
    skipped: int = 0


def check_revision(value: object) -> int:
    if type(value) is not int or not 1 <= value <= MAX_REVISION:
        raise StoreError("the revision is not a number from 1 to 1 000 000")
    return value


# - the sealed secret -------------------------------------------------------


def seal_secret(public_key: DnsProfilePublicKey, *, name: str, revision: int, secret: str) -> bytes:
    """The secret sealed for root, bound to this list and this revision."""

    blocklists.checked_name(name)
    check_revision(revision)
    if len(secret) > blocklists.SECRET_MAX or any(c in secret for c in "\r\n"):
        raise StoreError("the password or token is too long or holds a line break")
    plaintext = {
        "schema_version": SCHEMA_VERSION,
        "blocklist": name,
        "key_id": public_key.key_id,
        "revision": revision,
        "secret": secret,
    }
    return seal(public_key, json.dumps(plaintext, separators=(",", ":")).encode("utf-8"))


def open_secret(
    key: DnsProfilePrivateKey, ciphertext: bytes, *, name: str, revision: int
) -> tuple[str, int]:
    """The secret and the revision it was sealed at, or `StoreError` naming the binding that failed."""

    blocklists.checked_name(name)
    check_revision(revision)
    if len(ciphertext) > MAX_CIPHERTEXT:
        raise StoreError("the sealed secret is larger than one can be")
    try:
        plaintext = open_sealed(key, ciphertext)
    except KeyFileError as exc:
        raise StoreError(f"the secret was not sealed against key {key.key_id}") from exc
    try:
        document = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise StoreError("the opened secret is not a JSON document") from None
    expected = {"schema_version", "blocklist", "key_id", "revision", "secret"}
    if not isinstance(document, dict) or set(document) != expected:
        raise StoreError("the opened secret does not have the blocklist shape")
    if document["schema_version"] != SCHEMA_VERSION:
        raise StoreError("the opened secret has a schema version this helper does not read")
    if document["blocklist"] != name:
        raise StoreError("the secret was sealed for another blocklist")
    if document["key_id"] != key.key_id:
        raise StoreError("the opened secret names another key than the one that opened it")
    sealed_revision = document["revision"]
    if type(sealed_revision) is not int or sealed_revision < revision:
        raise StoreError("the secret is an older revision than the job asked for")
    check_revision(sealed_revision)
    secret = document["secret"]
    if not isinstance(secret, str) or len(secret) > blocklists.SECRET_MAX:
        raise StoreError("the opened secret is not text")
    return secret, sealed_revision


# - the definitions ---------------------------------------------------------


def _secure_directory(path: Path, *, require_secure: bool) -> None:
    try:
        status = os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise StoreError(f"cannot read {path}: {exc.strerror}") from exc
    if not stat.S_ISDIR(status.st_mode):
        raise StoreError(f"{path} is not a directory")
    if require_secure and (status.st_uid != 0 or stat.S_IMODE(status.st_mode) != 0o700):
        raise StoreError(f"{path} must be owned by root, mode 0700")


def _document(stored: Stored) -> dict[str, Any]:
    item = stored.definition
    return {
        "schema_version": SCHEMA_VERSION,
        "revision": stored.revision,
        "name": item.name,
        "description": item.description,
        "url": item.url,
        "authorization": item.authorization,
        "username": item.username,
        "every_hours": item.every_hours,
        "excepts": list(item.excepts),
        "secret": stored.secret,
    }


def write(stored: Stored, *, directory: Path = DEFINITIONS, require_secure: bool = True) -> Path:
    """Write one definition atomically, root-only; an older revision does not replace a newer one."""

    _secure_directory(directory, require_secure=require_secure)
    check_revision(stored.revision)
    path = directory / f"{stored.definition.name}{SUFFIX}"
    present = _read_one(path) if path.exists() else None
    if present is not None and present.revision > stored.revision:
        raise StoreError(
            f"{stored.definition.name} is at revision {present.revision} already; "
            f"revision {stored.revision} is older"
        )
    content = json.dumps(_document(stored), separators=(",", ":"), sort_keys=True) + "\n"
    try:
        atomic_file.write(path, content.encode("utf-8"), mode=0o600)
    except OSError as exc:
        raise StoreError(f"{path} could not be written: {exc.strerror}") from exc
    return path


def remove(name: str, *, directory: Path = DEFINITIONS, require_secure: bool = True) -> bool:
    """Remove a definition; whether there was one."""

    blocklists.checked_name(name)
    _secure_directory(directory, require_secure=require_secure)
    path = directory / f"{name}{SUFFIX}"
    try:
        path.unlink()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise StoreError(f"{path} could not be removed: {exc.strerror}") from exc
    atomic_file.sync_directory(directory)
    return True


def _read_one(path: Path) -> Stored:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise StoreError(f"{path} could not be read as a blocklist") from exc
    expected = {
        "schema_version",
        "revision",
        "name",
        "description",
        "url",
        "authorization",
        "username",
        "every_hours",
        "excepts",
        "secret",
    }
    if not isinstance(document, dict) or set(document) != expected:
        raise StoreError(f"{path} does not have the blocklist shape")
    if document["schema_version"] != SCHEMA_VERSION:
        raise StoreError(f"{path} has a schema version this release does not read")
    excepts = document["excepts"]
    secret = document["secret"]
    if not isinstance(excepts, list) or not all(isinstance(e, str) for e in excepts):
        raise StoreError(f"{path}: excepts is not a list of text")
    if not isinstance(secret, str):
        raise StoreError(f"{path}: the secret is not text")
    try:
        item = blocklists.definition(
            name=document["name"],
            url=document["url"],
            every_hours=document["every_hours"],
            authorization=document["authorization"],
            username=document["username"],
            description=document["description"],
            excepts=excepts,
        )
    except ValueError as exc:
        raise StoreError(f"{path}: {exc}") from exc
    if path.name != f"{item.name}{SUFFIX}":
        raise StoreError(f"{path} holds the blocklist {item.name}")
    return Stored(definition=item, secret=secret, revision=check_revision(document["revision"]))


def read_all(*, directory: Path = DEFINITIONS) -> tuple[Stored, ...]:
    """Every definition, by name; a directory not made yet holds none."""

    if not directory.exists():
        return ()
    found = sorted(
        p for p in directory.iterdir() if p.suffix == SUFFIX and not p.name.startswith(".")
    )
    return tuple(_read_one(path) for path in found)


# - the last good list and the state ---------------------------------------


def list_path(name: str, *, directory: Path = STATE) -> Path:
    return directory / f"{blocklists.checked_name(name)}{LIST_SUFFIX}"


def keep(name: str, networks: tuple[blocklists.Network, ...], *, directory: Path = STATE) -> None:
    """Keep a good list as fetched, before exceptions, so an exception changes it without a fetch."""

    atomic_file.write(list_path(name, directory=directory), blocklists.render(networks), mode=0o600)


def kept(name: str, *, directory: Path = STATE) -> tuple[blocklists.Network, ...] | None:
    """The last good list, or None when none was kept."""

    try:
        body = list_path(name, directory=directory).read_bytes()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise StoreError(f"the kept list of {name} could not be read: {exc.strerror}") from exc
    try:
        return blocklists.parse(body).networks
    except blocklists.BlocklistError as exc:
        raise StoreError(f"the kept list of {name} is not a list: {exc}") from exc


def read_state(*, directory: Path = STATE) -> dict[str, ListState]:
    try:
        document = json.loads((directory / STATE_FILE).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise StoreError("the blocklist state could not be read") from exc
    if not isinstance(document, dict) or not isinstance(document.get("lists"), dict):
        raise StoreError("the blocklist state does not have its shape")
    states: dict[str, ListState] = {}
    for name, entry in document["lists"].items():
        if not isinstance(entry, dict) or not blocklists.NAME.fullmatch(name):
            raise StoreError("the blocklist state does not have its shape")
        try:
            states[name] = ListState(**entry)
        except TypeError as exc:
            raise StoreError(f"the state of {name} does not have its shape") from exc
    return states


def write_state(states: Mapping[str, ListState], *, directory: Path = STATE) -> None:
    document = {
        "schema_version": SCHEMA_VERSION,
        "lists": {name: asdict(states[name]) for name in sorted(states)},
    }
    content = json.dumps(document, separators=(",", ":"), sort_keys=True) + "\n"
    atomic_file.write(directory / STATE_FILE, content.encode("utf-8"), mode=0o644)
