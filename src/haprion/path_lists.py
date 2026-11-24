"""Path lists: paths an object refuses under *Denied paths*, kept under Settings (B527, B532).

A path list is a set of paths that only scanners ask for (`/.env`,
`/wp-login.php` ...), written once under *Settings → Path lists* and named by
any object's *Denied paths — lists*. It is configuration the operator writes,
so it goes out with a publish and follows the published version: Settings
keeps it in the database, and the `path_list_apply` job has a root helper write
it here, root-only. The engine reads the lists from here and nowhere else.

    /etc/haprion/path-lists/<name>.json    one list, 0600 in a 0700 directory

A publish copies the lists the cluster's objects name into the version
(`managed/path-lists.yaml`) and generates from that copy, so a version, a
revert and a diff read the tree alone. A list changed since a cluster's version
makes that cluster's regeneration differ, which says it is to be published.

This module is what every reader shares: the name, the paths, the limits, the
file root keeps and the copy a version carries.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from collections.abc import Callable, Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from haprion import atomic_file, safe_yaml
from haprion.config import ConfigError
from haprion.proxy_model import (
    MAX_DENIED_PATHS,
    PATH_LIST_NAME,
    ModelError,
    Proxy,
    denied_paths,
)

OPERATION = "path_list_apply"
HELPER = "/opt/haprion/current/bin/haprion-path-list-apply-helper"
SCHEMA_VERSION = 1
DIRECTORY = Path("/etc/haprion/path-lists")
SUFFIX = ".json"
SNAPSHOT = "managed/path-lists.yaml"
DESCRIPTION_MAX = 200
MAX_REVISION = 1_000_000
DOCUMENT_KEYS = frozenset({"schema_version", "revision", "name", "description", "paths"})
#
# Every list's paths and a little YAML around each: the most a version's copy
# can need with every list full is far less, so more is a damaged file.
#
MAX_SNAPSHOT_BYTES = 1024 * 1024

type Reader = Callable[[Collection[str]], Mapping[str, tuple[str, ...]]]
"""The paths of each list named, or a `ConfigError` naming the one that is missing."""


class PathListError(ValueError):
    """A list, a file or a copy that is not what it must be."""


@dataclass(frozen=True, slots=True)
class PathList:
    name: str
    paths: tuple[str, ...]
    description: str = ""
    revision: int = 1


def checked_name(name: object) -> str:
    if not isinstance(name, str) or not PATH_LIST_NAME.fullmatch(name):
        raise PathListError(
            "a path list's name starts with a letter and holds lowercase letters, digits and -, "
            "at most 40"
        )
    return name


def check_revision(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= MAX_REVISION:
        raise PathListError(f"a revision is a whole number from 1 to {MAX_REVISION}")
    return value


def checked_paths(value: object, location: str = "paths") -> tuple[str, ...]:
    """The list's paths as an object's own are checked (`proxy_model.denied_paths`)."""

    try:
        paths = denied_paths(value, location)
    except ModelError as exc:
        raise PathListError(str(exc)) from None
    if not paths:
        raise PathListError(f"{location} must hold at least one path")
    return paths


def path_list(
    name: object, paths: object, description: object = "", revision: object = 1
) -> PathList:
    """One list from untrusted values, or why it cannot be one."""

    if not isinstance(description, str) or len(description) > DESCRIPTION_MAX:
        raise PathListError(f"a description is text of at most {DESCRIPTION_MAX} characters")
    if any(ord(c) < 32 or ord(c) == 127 for c in description):
        raise PathListError("a description is one line without control characters")
    return PathList(
        name=checked_name(name),
        paths=checked_paths(paths),
        description=description.strip(),
        revision=check_revision(revision),
    )


def lines(text: str) -> list[str]:
    """Paths as a form or a file writes them: one to a line, blank lines and spaces dropped."""

    return [line.strip() for line in text.splitlines() if line.strip()]


# - the file root keeps ------------------------------------------------------


def _secure_directory(path: Path, *, require_secure: bool) -> None:
    try:
        status = os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise PathListError(f"cannot read {path}: {exc.strerror}") from exc
    if not stat.S_ISDIR(status.st_mode):
        raise PathListError(f"{path} is not a directory")
    if require_secure and (status.st_uid != 0 or stat.S_IMODE(status.st_mode) != 0o700):
        raise PathListError(f"{path} must be owned by root, mode 0700")


def _document(item: PathList) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "revision": item.revision,
        "name": item.name,
        "description": item.description,
        "paths": list(item.paths),
    }


def _read_one(path: Path) -> PathList:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise PathListError(f"{path} could not be read as a path list") from exc
    if not isinstance(document, dict) or set(document) != DOCUMENT_KEYS:
        raise PathListError(f"{path} does not have the path list shape")
    if document["schema_version"] != SCHEMA_VERSION:
        raise PathListError(f"{path} has a schema version this release does not read")
    try:
        item = path_list(
            document["name"], document["paths"], document["description"], document["revision"]
        )
    except PathListError as exc:
        raise PathListError(f"{path}: {exc}") from None
    if path.name != f"{item.name}{SUFFIX}":
        raise PathListError(f"{path} holds the path list {item.name}")
    return item


def write(item: PathList, *, directory: Path = DIRECTORY, require_secure: bool = True) -> Path:
    """Write one list atomically, root-only; an older revision does not replace a newer one."""

    _secure_directory(directory, require_secure=require_secure)
    path = directory / f"{checked_name(item.name)}{SUFFIX}"
    present = _read_one(path) if path.exists() else None
    if present is not None and present.revision > item.revision:
        raise PathListError(
            f"{item.name} is at revision {present.revision} already; "
            f"revision {item.revision} is older"
        )
    content = json.dumps(_document(item), separators=(",", ":"), sort_keys=True) + "\n"
    try:
        atomic_file.write(path, content.encode("utf-8"), mode=0o600)
    except OSError as exc:
        raise PathListError(f"{path} could not be written: {exc.strerror}") from exc
    return path


def remove(name: str, *, directory: Path = DIRECTORY, require_secure: bool = True) -> bool:
    """Remove a list; whether there was one."""

    checked_name(name)
    _secure_directory(directory, require_secure=require_secure)
    path = directory / f"{name}{SUFFIX}"
    try:
        path.unlink()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise PathListError(f"{path} could not be removed: {exc.strerror}") from exc
    atomic_file.sync_directory(directory)
    return True


def read_all(*, directory: Path = DIRECTORY) -> dict[str, PathList]:
    """Every list by name; a directory not made yet holds none."""

    if not directory.exists():
        return {}
    found = sorted(
        p for p in directory.iterdir() if p.suffix == SUFFIX and not p.name.startswith(".")
    )
    return {item.name: item for item in (_read_one(path) for path in found)}


def digest(*, directory: Path = DIRECTORY) -> str:
    """Today's lists as one digest, for a cache that must notice a changed list."""

    try:
        stored = read_all(directory=directory)
    except PathListError:
        return "unreadable"
    document = {name: list(item.paths) for name, item in sorted(stored.items())}
    return hashlib.sha256(json.dumps(document, sort_keys=True).encode("utf-8")).hexdigest()


def _missing(name: str) -> ConfigError:
    return ConfigError(
        f"the path list {name} does not exist; add it under Settings → Path lists "
        "or take it out of Denied paths"
    )


def store_reader(directory: Path = DIRECTORY) -> Reader:
    """Today's lists, as a publish takes them."""

    def read(names: Collection[str]) -> Mapping[str, tuple[str, ...]]:
        if not names:
            return {}
        try:
            stored = read_all(directory=directory)
        except PathListError as exc:
            raise ConfigError(str(exc)) from None
        for name in sorted(names):
            if name not in stored:
                raise _missing(name)
        return {name: stored[name].paths for name in sorted(names)}

    return read


# - the copy a version carries ---------------------------------------------


def load_snapshot(content: bytes | None) -> dict[str, tuple[str, ...]]:
    """The lists a version carries; none when it has no copy."""

    if content is None:
        return {}
    if len(content) > MAX_SNAPSHOT_BYTES:
        raise ConfigError(f"{SNAPSHOT} exceeds the {MAX_SNAPSHOT_BYTES} byte size limit")
    try:
        document: Any = safe_yaml.load(content.decode("utf-8"))
    except (UnicodeError, yaml.YAMLError) as exc:
        raise ConfigError(f"{SNAPSHOT} is not valid YAML") from exc
    if (
        not isinstance(document, dict)
        or set(document) != {"schema", "lists"}
        or document["schema"] != SCHEMA_VERSION
        or not isinstance(document["lists"], dict)
    ):
        raise ConfigError(f"{SNAPSHOT} must hold schema: {SCHEMA_VERSION} and lists")
    lists: dict[str, tuple[str, ...]] = {}
    for name, paths in document["lists"].items():
        try:
            lists[checked_name(name)] = checked_paths(paths, f"{SNAPSHOT}: {name}")
        except PathListError as exc:
            raise ConfigError(f"{SNAPSHOT}: {exc}") from None
    return lists


def dump_snapshot(lists: Mapping[str, Sequence[str]]) -> bytes:
    """The copy as a version stores it: names and paths in a stable order, so a diff says what changed."""

    document = {
        "schema": SCHEMA_VERSION,
        "lists": {name: list(lists[name]) for name in sorted(lists)},
    }
    return yaml.safe_dump(document, sort_keys=False, default_flow_style=False).encode("utf-8")


def tree_reader(files: Mapping[str, bytes]) -> Reader:
    """The lists a version carries, as a revert takes them back."""

    def read(names: Collection[str]) -> Mapping[str, tuple[str, ...]]:
        carried = load_snapshot(files.get(SNAPSHOT))
        for name in sorted(names):
            if name not in carried:
                raise _missing(name)
        return {name: carried[name] for name in sorted(names)}

    return read


def named(proxies: Iterable[Proxy]) -> set[str]:
    """The lists the objects name under *Denied paths*."""

    return {
        name for proxy in proxies if proxy.deny_paths is not None for name in proxy.deny_paths.lists
    }


def changed(published: Mapping[str, bytes], candidate: Mapping[str, bytes]) -> list[str]:
    """The lists whose paths differ between two versions' copies, by name."""

    try:
        before = load_snapshot(published.get(SNAPSHOT))
    except ConfigError:
        before = {}
    after = load_snapshot(candidate.get(SNAPSHOT))
    return sorted(name for name in set(before) | set(after) if before.get(name) != after.get(name))


__all__ = [
    "DIRECTORY",
    "MAX_DENIED_PATHS",
    "SNAPSHOT",
    "PathList",
    "PathListError",
    "Reader",
    "changed",
    "checked_name",
    "dump_snapshot",
    "load_snapshot",
    "named",
    "path_list",
    "read_all",
    "remove",
    "store_reader",
    "tree_reader",
    "write",
]
