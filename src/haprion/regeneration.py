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
- certificate coverage is the installed certificates' (the caller reads it),
  and the checks a publish makes on the bytes it would write - stick counters,
  the traffic stream, the core's TLS defaults - are made on the candidate, so a
  difference a publish would refuse is `refused` and says why;
- held ports are not asked: they need the nodes, and only refuse. Neither is
  the sandbox's `haproxy -c`, which a publish runs and this does not.

The published tree does not record which version of the product made it. It
records the generator level its manifest was written at (B493), the rule set it
carries and the files the nodes' addresses steer, and a difference is `required`
- a reason to publish and deploy - when the installed level is another, the rule
set's files are others, or one of the files that only the addresses steer
differs (the published tree does not say which addresses it was made with, so a
file they steer that differs is taken as them). Any other difference is how the
files read, the same generator at the same level; the next publish takes it.
"""

from __future__ import annotations

import dataclasses
import difflib
import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from haprion import (
    __version__,
    cluster_settings,
    crs,
    geo,
    objects,
    peers,
    release_checks,
)
from haprion.config import Cluster, ConfigError
from haprion.generate import GENERATOR_LEVEL
from haprion.managed_network import location as network_location
from haprion.managed_publish import MANAGED_PREFIX, managed_files
from haprion.object_manifest import BASELINE_LEVEL
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
#
# Stand-ins for the nodes' addresses when the files they steer are looked for:
# the benchmarking range, which no node has.
#
PLACEHOLDER_ADDRESS = "198.18.0.{}"
MAX_CAUSE_FILES = 16

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


def addresses_needed(cluster: Cluster, settings_document: bytes | None) -> bool:
    """Whether the generated layer asks for the nodes' addresses at all.

    The condition `managed_files` applies: shared counters, exported metrics, or
    a keepalived the product writes. Decided before the lookup, so a cluster
    that never needs them neither waits for DNS nor has its key change with it.
    A settings document that cannot be read counts as needing them: the
    regeneration refuses it anyway.
    """

    if cluster.vrrp_router_id is not None:
        return True
    try:
        settings = cluster_settings.load_document(settings_document)
    except ConfigError:
        return True
    return settings.peers is not None or settings.metrics is not None


def rules_digest(rules: crs.RuleSet | None) -> str | None:
    """The installed rule set's files as one digest; its VERSION alone does not say."""

    if rules is None:
        return None
    digest = hashlib.sha256()
    for name, content in sorted(rules.files.items()):
        digest.update(f"{name}\0{len(content)}\0".encode())
        digest.update(content)
    return digest.hexdigest()


def fingerprint(
    commit: str | None,
    cluster: Cluster,
    addresses: Addresses | ConfigError,
    crs_version: str | None,
    *,
    rules: str | None = None,
    certificates: str | None = None,
    blocklists: Sequence[str] = (),
) -> str:
    """What the result depends on, as one digest: the cache key.

    The published commit, this engine's own source, the cluster's definition,
    the nodes' addresses, the installed rule set (its version and a digest of
    its files: a package revision can change files and keep the version) and
    the certificates' state, which coverage follows. The location database is
    not in it: the countries are the tree's own.
    """

    document = {
        "commit": commit,
        "engine": objects._engine_digest(),
        "cluster": dataclasses.asdict(cluster),
        "addresses": None if isinstance(addresses, ConfigError) else [list(a) for a in addresses],
        "crs": crs_version,
        "rules": rules,
        "certificates": certificates,
        "blocklists": sorted(blocklists),
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
        "required": False,
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


def _causes(
    files: Mapping[str, bytes],
    installed: Callable[[], crs.RuleSet | None],
    installed_crs: str | None,
    steered: Sequence[str] = (),
) -> list[dict[str, Any]]:
    """What can be said about why, from what the published tree records.

    Each is a reason the difference must reach the nodes (B493): another
    generator level than the one the published version was written at (a
    rolled-back manager reads a newer version's too), a rule set whose files
    are others - its VERSION alone does not say - or a file that only the nodes'
    addresses steer. A difference with none of them is how the files read, and
    goes out with the next publish.
    """

    causes: list[dict[str, Any]] = []
    manifest = files.get(MANIFEST_PATH)
    parsed = parse_manifest(manifest.decode("utf-8", "replace")) if manifest is not None else None
    written = parsed.generator_level if parsed is not None else BASELINE_LEVEL
    if written != GENERATOR_LEVEL:
        causes.append(
            {"kind": "generator", "published": str(written), "installed": str(GENERATOR_LEVEL)}
        )
    try:
        carried = crs.from_tree(files)
    except ConfigError:
        carried = None
    if carried is not None and installed_crs is not None:
        if carried.version != installed_crs:
            causes.append(
                {"kind": "rule_set", "published": carried.version, "installed": installed_crs}
            )
        else:
            try:
                today = installed()
            except RegenerationError:
                today = None
            if today is not None and rules_digest(today) != rules_digest(carried):
                causes.append(
                    {"kind": "rule_set", "published": carried.version, "installed": installed_crs}
                )
    if steered:
        causes.append({"kind": "addresses", "files": list(steered[:MAX_CAUSE_FILES])})
    return causes


def _steered_by_addresses(
    candidate_tree: Callable[..., dict[str, bytes]],
    published: Mapping[str, bytes],
    candidate: Mapping[str, bytes],
    addresses: Addresses | ConfigError,
) -> list[str]:
    """The files that differ and that only the nodes' addresses steer.

    Made once more with other addresses for the same nodes: a file that reads
    differently there is one the addresses steer (keepalived's, the peers
    section, the metrics exporter's binds), and of those the ones that differ
    from the published tree are what the published addresses may have been.
    """

    if isinstance(addresses, ConfigError) or not addresses:
        return []
    placeholders = tuple(
        (name, PLACEHOLDER_ADDRESS.format(number + 1)) for number, (name, _) in enumerate(addresses)
    )
    try:
        other = build_node_artifact(candidate_tree(None, lambda: placeholders))
    except (ConfigError, LayoutError):
        return []
    return sorted(
        path
        for path in set(candidate) | set(other)
        if candidate.get(path) != other.get(path) and published.get(path) != candidate.get(path)
    )


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
    certificate_sans: Mapping[str, Sequence[str]] | None = None,
    blocklists: Sequence[str] = (),
) -> dict[str, Any]:
    """The result for one published tree: would a publish of it change the nodes' files?

    `files` is the tree at the published commit. Raises `RegenerationError` for
    what stops the comparison being made (the nodes' addresses are needed and
    cannot be had, the published tree is not a release, the installed rule set
    cannot be read - a read to be made again, not an answer); a generator that
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
        "required": False,
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

    def rules() -> crs.RuleSet | None:
        try:
            return rule_set()
        except crs.RuleSetError as exc:
            raise RegenerationError(str(exc)) from exc

    def candidate_tree(
        sans: Mapping[str, Sequence[str]] | None, nodes: Callable[[], Addresses] = node_addresses
    ) -> dict[str, bytes]:
        managed = managed_files(
            files,
            network_document=document,
            cluster=cluster,
            country_reader=geo.tree_reader(files, location_database or geo.location_database()),
            rule_set=rules,
            node_addresses=nodes,
            certificate_sans=sans,
            blocklists=blocklists,
        )
        tree = {
            path: content for path, content in files.items() if not path.startswith(MANAGED_PREFIX)
        }
        tree.update(managed)
        return tree

    #
    # Compared without the certificate coverage (26-11-01): the coverage only
    # refuses, it never changes a byte, and a cluster published with
    # `--allow-certificate-mismatch` has a hostname its certificate does not
    # cover on purpose. Asked first, it read such a cluster as `refused` for
    # ever, though a publish would change nothing. It is asked below, once
    # the candidate differs - which is when a publish would ask it.
    #
    try:
        tree = candidate_tree(None)
        candidate = build_node_artifact(tree)
        if candidate != published and certificate_sans is not None:
            tree = candidate_tree(certificate_sans)
            candidate = build_node_artifact(tree)
    except (ConfigError, LayoutError) as exc:
        result["outcome"] = REFUSED
        result["message"] = str(exc)[:MAX_MESSAGE]
        result["causes"] = _causes(files, rules, installed_crs)
        return result

    if candidate == published:
        return result
    #
    # The checks a publish makes on the bytes it would write, in its order.
    #
    problem = release_checks.first(
        tree, cluster=cluster.cluster_id, config_path=str(cluster.config_path)
    )
    if problem is not None:
        result["outcome"] = REFUSED
        result["message"] = problem.message[:MAX_MESSAGE]
        result["causes"] = _causes(files, rules, installed_crs)
        return result
    diff = artifact_diff(published, candidate, commit)
    causes = _causes(
        files,
        rules,
        installed_crs,
        _steered_by_addresses(candidate_tree, published, candidate, addresses),
    )
    result.update(
        outcome=CHANGED_OUTCOME,
        causes=causes,
        required=bool(causes),
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
    "addresses_needed",
    "lookup_addresses",
    "regenerate",
    "rules_digest",
    "unchanged_result",
    "unpublished_result",
]
