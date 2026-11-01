"""Would publishing again change what the nodes run? Regenerate the published version and compare.

A new release of the product can generate different configuration from the same
objects: a generator that learned a directive, a rule set that moved on. Nothing
in the repository changes, so no version says so - the nodes run what the last
publish wrote, and the next publish, whenever it comes, writes something else.
This module answers that ahead of the publish, per cluster, and publishes
nothing.

The published commit's tree is read as `inventory` reads it. Its `managed/`
layer is made again by `managed_files`, exactly as a publish makes it, with the
tree's own network description, settings and objects, and the node artifact of
the two trees is compared (`release_layout.build_node_artifact`, which leaves out
the RELEASE stamp and so the timestamp).

What is pinned and what is live follows what a publish of the same objects
would read, less what only refuses:

- the countries' networks are the published tree's, as a revert's are
  (`geo.tree_reader`): the location database is replaced every day, and a result
  that followed it would change every day;
- the rule set is the installed one, as a publish takes it: a package upgrade of
  the rule set reaches the nodes with the next publish, and this is what says so;
- the cluster registry's fields and the nodes' addresses are today's;
- certificate coverage and held ports are not asked. They only refuse, and
  never change the output.

The published tree does not record which version of the product made it, so no
result says "made by X, now Y" for the engine; it says only what can be read:
the rule set's version in the tree against the installed one.
"""

from __future__ import annotations

import dataclasses
import difflib
import hashlib
import json
from collections.abc import Callable, Mapping
from typing import Any

from haprion import __version__, crs, geo, objects, peers
from haprion.config import Cluster, ConfigError
from haprion.managed_network import location as network_location
from haprion.managed_publish import MANAGED_PREFIX, managed_files
from haprion.object_manifest import REPOSITORY_PATH as MANIFEST_PATH
from haprion.object_manifest import compare as compare_manifests
from haprion.object_manifest import parse as parse_manifest
from haprion.release_layout import LayoutError, build_node_artifact
from haprion.version_diff import MAX_DIFF_BYTES, MAX_FILES, FileChange, VersionDiff

UNCHANGED = "unchanged"
CHANGED_OUTCOME = "changed"
REFUSED = "refused"
UNPUBLISHED = "unpublished"
OUTCOMES = (UNCHANGED, CHANGED_OUTCOME, REFUSED, UNPUBLISHED)
#
# A refusal's sentence is kept in the result, which a database keeps: cut so a
# generator that names a long path cannot make it a page.
#
MAX_MESSAGE = 1024

type Addresses = tuple[tuple[str, str], ...]
type Lookup = Callable[[Cluster], Addresses]


class RegenerationError(Exception):
    """The comparison could not be made at all - not that it came out as a refusal."""


def lookup_addresses(cluster: Cluster, lookup: Lookup = peers.addresses) -> Addresses | ConfigError:
    """The nodes' addresses, or the error that says why they cannot be had.

    Part of what a result depends on, and so asked before the cache is: a node
    that changes address is a new result. An error is a value here and not an
    exception because most clusters never need the addresses - only the ones
    that share counters, export metrics or have their keepalived written - and
    a DNS failure must not blank the answer for the others.
    """

    try:
        return lookup(cluster)
    except ConfigError as exc:
        return exc


def fingerprint(
    commit: str | None,
    cluster: Cluster,
    addresses: Addresses | ConfigError,
    crs_version: str | None,
) -> str:
    """What the result depends on, as one digest: the cache key.

    The published commit, this engine's own source, the cluster's definition,
    the nodes' addresses and the installed rule set. The location database is
    not in it: the countries are the tree's own.
    """

    document = {
        "commit": commit,
        "engine": objects._engine_digest(),
        "cluster": dataclasses.asdict(cluster),
        "addresses": None if isinstance(addresses, ConfigError) else [list(a) for a in addresses],
        "crs": crs_version,
    }
    return hashlib.sha256(json.dumps(document, sort_keys=True, default=str).encode()).hexdigest()


def unchanged_result(commit: str | None, key: str) -> dict[str, Any]:
    """The answer to a caller that holds the result for this fingerprint already."""

    return {"published_commit": commit, "fingerprint": key, "unchanged": True}


def unpublished_result(key: str) -> dict[str, Any]:
    """Nothing is published, so there is nothing to compare a publish with."""

    return {
        "outcome": UNPUBLISHED,
        "fingerprint": key,
        "published_commit": None,
        "published_version": None,
        "installed_version": __version__,
        "managed": False,
        "message": None,
        "causes": [],
        "objects": [],
        "files_changed": 0,
        "diff": None,
    }


def _text(content: bytes) -> str | None:
    return None if b"\0" in content else content.decode("utf-8", "replace")


def _file_change(path: str, old: bytes | None, new: bytes | None) -> FileChange:
    status = "added" if old is None else "deleted" if new is None else "modified"
    before, after = _text(old or b""), _text(new or b"")
    if before is None or after is None:
        return FileChange(path, status, None, 0, 0, True, ())
    #
    # The patch from its first `@@` on, as git prints it and as `version_diff`
    # keeps it, so the page that draws one draws the other.
    #
    lines = list(
        difflib.unified_diff(before.splitlines(), after.splitlines(), "", "", n=3, lineterm="")
    )[2:]
    added = sum(1 for line in lines if line.startswith("+"))
    removed = sum(1 for line in lines if line.startswith("-"))
    return FileChange(path, status, None, added, removed, False, tuple(lines))


def artifact_diff(
    published: Mapping[str, bytes], candidate: Mapping[str, bytes], commit: str
) -> VersionDiff:
    """The node artifacts' difference in `version_diff`'s shape and within its bounds."""

    paths = sorted(
        path
        for path in set(published) | set(candidate)
        if published.get(path) != candidate.get(path)
    )
    truncated = len(paths) > MAX_FILES
    budget = MAX_DIFF_BYTES
    files: list[FileChange] = []
    for path in paths[:MAX_FILES]:
        change = _file_change(path, published.get(path), candidate.get(path))
        size = sum(len(line.encode()) + 1 for line in change.lines)
        if size > budget:
            #
            # Named with its counts, its lines left out - as a version's diff
            # does once the bound is reached.
            #
            change = dataclasses.replace(change, lines=())
            truncated = True
        else:
            budget -= size
        files.append(change)
    return VersionDiff(commit=commit, parent=None, files=tuple(files), truncated=truncated)


def diff_from_dict(document: Mapping[str, Any]) -> VersionDiff:
    """A diff as a result carries it, for `version_diff.render`."""

    return VersionDiff(
        commit=str(document["commit"]),
        parent=document.get("parent"),
        files=tuple(
            FileChange(
                path=item["path"],
                status=item["status"],
                old_path=item.get("old_path"),
                added=item["added"],
                removed=item["removed"],
                binary=item["binary"],
                lines=tuple(item["lines"]),
            )
            for item in document["files"]
        ),
        truncated=bool(document["truncated"]),
    )


def _object_changes(
    published: Mapping[str, bytes], candidate: Mapping[str, bytes]
) -> list[dict[str, Any]]:
    """Each object the two manifests disagree about, with the parts that differ.

    Nothing for a published version that has no manifest: it predates them, and
    saying nothing is the honest answer to a question it cannot be asked.
    """

    before = published.get(MANIFEST_PATH)
    after = candidate.get(MANIFEST_PATH)
    old = parse_manifest(before.decode("utf-8", "replace")) if before is not None else None
    new = parse_manifest(after.decode("utf-8", "replace")) if after is not None else None
    if old is None or new is None:
        return []
    return [
        {"name": name, "change": difference.state, "parts": list(difference.parts)}
        for name, difference in sorted(compare_manifests(old, new).items())
        if difference.state != "current"
    ]


def _causes(files: Mapping[str, bytes], installed_crs: str | None) -> list[dict[str, Any]]:
    """What can be said about why, from what the published tree records."""

    causes: list[dict[str, Any]] = []
    try:
        carried = crs.from_tree(files)
    except ConfigError:
        carried = None
    if carried is not None and installed_crs is not None and carried.version != installed_crs:
        causes.append(
            {"kind": "rule_set", "published": carried.version, "installed": installed_crs}
        )
    return causes


def regenerate(
    files: Mapping[str, bytes],
    cluster: Cluster,
    *,
    commit: str,
    version: int | None,
    key: str,
    addresses: Addresses | ConfigError,
    installed_crs: str | None,
    rule_set: Callable[[], crs.RuleSet | None] = crs.installed,
    location_database: geo.CountryReader | None = None,
) -> dict[str, Any]:
    """The result for one published tree: would a publish of it change the nodes' files?

    `files` is the tree at the published commit. Raises `RegenerationError` for
    what stops the comparison being made (the nodes' addresses are needed and
    cannot be had, the published tree is not a release); a generator that
    refuses the tree is a result, `refused`, as a publish would refuse it.
    """

    result: dict[str, Any] = {
        "outcome": UNCHANGED,
        "fingerprint": key,
        "published_commit": commit,
        "published_version": version,
        "installed_version": __version__,
        "managed": True,
        "message": None,
        "causes": [],
        "objects": [],
        "files_changed": 0,
        "diff": None,
    }
    document = files.get(network_location())
    if document is None:
        #
        # A cluster written by hand has no generated layer to make again.
        #
        result["managed"] = False
        return result
    try:
        published = build_node_artifact(files)
    except LayoutError as exc:
        raise RegenerationError(f"the published version is not a release: {exc}") from exc

    def node_addresses() -> Addresses:
        if isinstance(addresses, ConfigError):
            raise RegenerationError(str(addresses))
        return addresses

    try:
        managed = managed_files(
            files,
            network_document=document,
            cluster=cluster,
            country_reader=geo.tree_reader(files, location_database or geo.location_database()),
            rule_set=rule_set,
            node_addresses=node_addresses,
        )
        tree = {
            path: content for path, content in files.items() if not path.startswith(MANAGED_PREFIX)
        }
        tree.update(managed)
        candidate = build_node_artifact(tree)
    except (ConfigError, LayoutError) as exc:
        result["outcome"] = REFUSED
        result["message"] = str(exc)[:MAX_MESSAGE]
        result["causes"] = _causes(files, installed_crs)
        return result

    if candidate == published:
        return result
    diff = artifact_diff(published, candidate, commit)
    result.update(
        outcome=CHANGED_OUTCOME,
        causes=_causes(files, installed_crs),
        objects=_object_changes(files, tree),
        files_changed=sum(
            1
            for path in set(published) | set(candidate)
            if published.get(path) != candidate.get(path)
        ),
        diff=diff.as_dict(),
    )
    return result


__all__ = [
    "OUTCOMES",
    "RegenerationError",
    "artifact_diff",
    "diff_from_dict",
    "fingerprint",
    "lookup_addresses",
    "regenerate",
    "unchanged_result",
    "unpublished_result",
]
