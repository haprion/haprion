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
    MAX_DENIED_PATH,
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
#
# The lists Settings keeps, and `haprion-path-lists apply` takes in one file.
#
MAX_LISTS = 64
DOCUMENT_KEYS = frozenset({"schema_version", "revision", "name", "description", "paths"})
#
# The most a version's copy can be: every list full, each path at its longest
# and written as YAML writes it (`  - ` before, a line break after; a path
# starts with `/` and has no quote or space, so it is never quoted), and the
# list's name. More is a damaged file. It was 1 MiB, which nine full lists
# passed: the version was written, and every regeneration and revert after it
# refused its copy (review 26-11-24, PWA03).
#
MAX_SNAPSHOT_BYTES = MAX_LISTS * (MAX_DENIED_PATHS * (MAX_DENIED_PATH + 8) + 64) + 64

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


def checked_description(value: object) -> str:
    """A description as it is kept: one line, stripped, and then held to its length.

    Stripped before the length is read, so the form and a file are held to one
    rule (review 26-11-24, PW03).
    """

    if not isinstance(value, str):
        raise PathListError(f"a description is text of at most {DESCRIPTION_MAX} characters")
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise PathListError("a description is one line without control characters")
    text = value.strip()
    if len(text) > DESCRIPTION_MAX:
        raise PathListError(f"a description is text of at most {DESCRIPTION_MAX} characters")
    return text


def path_list(
    name: object, paths: object, description: object = "", revision: object = 1
) -> PathList:
    """One list from untrusted values, or why it cannot be one."""

    return PathList(
        name=checked_name(name),
        paths=checked_paths(paths),
        description=checked_description(description),
        revision=check_revision(revision),
    )


def build_request(request_id: str, *, item: PathList | None, name: str, revision: int) -> str:
    """The request the worker sends the apply helper; `item` None removes the list."""

    parameters: dict[str, Any] = {"name": name, "revision": revision}
    if item is None:
        parameters["remove"] = True
    else:
        parameters.update({"description": item.description, "paths": list(item.paths)})
    return json.dumps(
        {
            "schema_version": 1,
            "operation": OPERATION,
            "cluster": None,
            "request_id": request_id,
            "parameters": parameters,
        },
        separators=(",", ":"),
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


def map_file_name(name: str) -> str:
    """The file the nodes load a list from, in the release's `maps/`, as the generator names it."""

    return f"paths-{checked_name(name)}.lst"


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


def write(
    item: PathList,
    *,
    directory: Path = DIRECTORY,
    require_secure: bool = True,
    warnings: list[str] | None = None,
) -> Path:
    """Write one list atomically, root-only, as the database has it.

    A file that cannot be read is replaced, and `warnings` says so: it holds
    nothing to compare a revision with, and refusing would leave the list
    impossible to save over (review 26-11-24, PW04). A file at a higher
    revision is replaced too, with a warning: the database is what a person
    saw and saved, and a restored dump or a hand-edited file would otherwise
    leave the list impossible to save until its revision had been counted past
    the file's (review 26-11-24, PW02). The job asks with the row's current
    revision, and the queue runs one such job at a time, so a stale job cannot
    arrive after a newer one.
    """

    _secure_directory(directory, require_secure=require_secure)
    path = directory / f"{checked_name(item.name)}{SUFFIX}"
    present = None
    if path.exists():
        try:
            present = _read_one(path)
        except PathListError as exc:
            if warnings is not None:
                warnings.append(f"{exc}; it is replaced")
    if present is not None and present.revision > item.revision and warnings is not None:
        warnings.append(
            f"revision_behind: {item.name} was at revision {present.revision}, ahead of "
            f"revision {item.revision}; it is written as the database has it"
        )
    content = json.dumps(_document(item), separators=(",", ":"), sort_keys=True) + "\n"
    try:
        atomic_file.write(path, content.encode("utf-8"), mode=0o600)
    except OSError as exc:
        raise PathListError(f"{path} could not be written: {exc.strerror}") from exc
    return path


def content_digest(description: str, paths: Sequence[str]) -> str:
    """What a list says, as one digest: the description and the paths, in order.

    The manager compares the database's row with the file root keeps by this
    and the revision; neither side sends the other the paths to compare
    (review 26-11-24, PW02).
    """

    text = json.dumps([description, list(paths)], separators=(",", ":"))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def listing(*, directory: Path = DIRECTORY, known: Collection[str] = ()) -> list[dict[str, Any]]:
    """Each file of the directory as the poller reads it: name, revision and `content_digest`.

    A file that cannot be read is revision 0 and no digest, which no row
    equals. A list whose name is not in `known` (no row in the database) also
    carries its description and paths, which is what taking it in needs.
    """

    entries: list[dict[str, Any]] = []
    for path in _files(directory):
        name = path.name[: -len(SUFFIX)]
        if not PATH_LIST_NAME.fullmatch(name):
            continue
        try:
            item = _read_one(path)
        except PathListError:
            entries.append({"name": name, "revision": 0, "digest": ""})
            continue
        entry: dict[str, Any] = {
            "name": item.name,
            "revision": item.revision,
            "digest": content_digest(item.description, item.paths),
        }
        if item.name not in known:
            entry["description"] = item.description
            entry["paths"] = list(item.paths)
        entries.append(entry)
    return entries


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

    return {item.name: item for item in _read_each(directory)[0]}


def _files(directory: Path) -> list[Path]:
    """The list files of a directory, in order; an unreadable directory is a `PathListError`."""

    try:
        if not directory.exists():
            return []
        return sorted(
            p for p in directory.iterdir() if p.suffix == SUFFIX and not p.name.startswith(".")
        )
    except OSError as exc:
        raise PathListError(f"{directory} could not be read: {exc.strerror}") from exc


def _read_each(directory: Path, *, strict: bool = True) -> tuple[list[PathList], list[str]]:
    """The readable lists and the file names that are not; the first not readable raises when strict."""

    items: list[PathList] = []
    broken: list[str] = []
    for path in _files(directory):
        try:
            items.append(_read_one(path))
        except PathListError:
            if strict:
                raise
            broken.append(path.name)
    return items, broken


def digest(*, directory: Path = DIRECTORY) -> str:
    """Today's lists as one digest, for a cache that must notice a changed list.

    A file that cannot be read adds its name and nothing else, so one that no
    object names does not make every cluster's cache stale in the same way as a
    changed list does (review 26-11-24, PW04).
    """

    try:
        items, broken = _read_each(directory, strict=False)
    except PathListError:
        return "unreadable"
    document: dict[str, Any] = {item.name: list(item.paths) for item in items}
    if broken:
        document["unreadable"] = broken
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
        #
        # Only the files of the lists named: another list's damaged file is
        # no reason to refuse this publish (review 26-11-24, PW04).
        #
        found: dict[str, tuple[str, ...]] = {}
        for name in sorted(names):
            path = directory / f"{name}{SUFFIX}"
            try:
                checked_name(name)
                if not path.exists():
                    raise _missing(name)
                found[name] = _read_one(path).paths
            except OSError as exc:
                raise ConfigError(f"{path} could not be read: {exc.strerror}") from exc
            except PathListError as exc:
                raise ConfigError(str(exc)) from None
        return found

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
    content = yaml.safe_dump(document, sort_keys=False, default_flow_style=False).encode("utf-8")
    #
    # The limit `load_snapshot` reads with: a version is never written with a
    # copy it could not take back.
    #
    if len(content) > MAX_SNAPSHOT_BYTES:
        raise ConfigError(f"{SNAPSHOT} would exceed the {MAX_SNAPSHOT_BYTES} byte size limit")
    return content


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
    "DESCRIPTION_MAX",
    "DIRECTORY",
    "HELPER",
    "MAX_DENIED_PATHS",
    "MAX_LISTS",
    "MAX_REVISION",
    "MAX_SNAPSHOT_BYTES",
    "OPERATION",
    "SNAPSHOT",
    "PathList",
    "PathListError",
    "Reader",
    "build_request",
    "changed",
    "check_revision",
    "checked_description",
    "checked_name",
    "checked_paths",
    "content_digest",
    "digest",
    "dump_snapshot",
    "lines",
    "listing",
    "load_snapshot",
    "map_file_name",
    "named",
    "path_list",
    "read_all",
    "remove",
    "store_reader",
    "tree_reader",
    "write",
]
