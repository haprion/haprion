"""One reading of a cluster, in the frozen status envelope.

This is the collecting half of `haproxy-status`, kept apart from both the
command that prints it and the helper that runs it as root so it can be tested
against a cluster that answers in ways the real pair cannot be made to answer.

What it adds over the shell command it replaces
-----------------------------------------------
The nodes have always reported which release they run - `release.version` and
`release.hash` are in the node status envelope and have been since the schema
was frozen. Nothing read them. The only way to find out whether the nodes were
running what was published was to start `haproxy-deploy`, which is the mutating
command: you had to reach for the thing that changes the cluster in order to
observe it.

So the comparison lives here now, and only the comparison. Whether a node is
current is decided by `ReleaseTarget.is_current` - the same call the deploy
matrix makes for the same question - because two readers deciding "in sync"
their own way is precisely how a status command and a deploy command end up
disagreeing about a cluster neither of them changed.

Why the node's own status is passed through unchanged
------------------------------------------------------
Everything under `status` is what the node said, forwarded as it arrived. A
manager that edits a node's answer before reporting it is a manager whose output
cannot be used to diagnose the node. The one exception is documented at
`_normalised`, and it converts a value rather than deciding anything with it.
"""

from __future__ import annotations

import json
import re
import subprocess
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from haproxy_mgmt import dnsdist_config
from haproxy_mgmt.cluster_status import addresses_current, ipvs_current
from haproxy_mgmt.config import DeployIdentity, Node
from haproxy_mgmt.deploy_plan import NodeObservation, ReleaseTarget, VipState
from haproxy_mgmt.envelope import Message, envelope
from haproxy_mgmt.object_manifest import (
    CURRENT,
    MANIFEST_FILE,
    Difference,
    Manifest,
    compare,
    worst,
)
from haproxy_mgmt.object_manifest import parse as parse_manifest
from haproxy_mgmt.release_layout import parse_release_file

OPERATION = "status"

#
# Carried over unchanged from the command being replaced. A wrapper reads these,
# and 69 in particular is the difference between "the cluster is degraded" and
# "the cluster could not be read at all".
#
EXIT_OK = 0
EXIT_PARTIAL = 69
EXIT_UNAVAILABLE = 68

#
# The top level of schemas/v1/haproxy-status.schema.json#/$defs/node_status. A
# response missing any of these cannot be reported on without guessing, so it is
# refused as a node status rather than partially believed.
#
REQUIRED_NODE_STATUS_KEYS = frozenset(
    {
        "schema_version",
        "node",
        "cluster",
        "haproxy",
        "keepalived",
        "vip",
        "ip_nonlocal_bind",
        "release",
        "config_validation",
        "stats_ok",
        "runtime",
        "certificates",
    }
)


SSH = "/usr/bin/ssh"
SSH_OPTIONS = (
    "-T",
    "-o",
    "BatchMode=yes",
    "-o",
    "IdentitiesOnly=yes",
    "-o",
    "StrictHostKeyChecking=yes",
    "-o",
    "ConnectTimeout=5",
    "-o",
    "ConnectionAttempts=1",
    "-o",
    "LogLevel=ERROR",
)
SSH_ENVIRONMENT = {"PATH": "/usr/bin:/bin", "HOME": "/root", "LANG": "C.UTF-8"}
#
# The whole status read, not just the connection. `ConnectTimeout` bounds the
# handshake; a node that connects and then never answers would otherwise hold
# a poll - or a deploy's reading, with the cluster lock taken - for as long as
# the TCP session lives. A read is safe to abandon: nothing on the node changes
# because the manager stopped listening. Generous, because a busy node is not a
# broken one.
#
STATUS_TIMEOUT_SECONDS = 60
#
# What a read that ran out of time reports, in the family of `timeout(1)`.
#
TIMED_OUT = 124


@dataclass(frozen=True, slots=True)
class NodeResponse:
    """What asking one node produced, before anything is believed about it."""

    exit_code: int
    stdout: str


type ReadNode = Callable[[Node], NodeResponse]


def ask_node(node: Node, identity: DeployIdentity) -> NodeResponse:
    """One node's status, as it answered. Its stderr is not the operator's.

    The status account is a forced command: connecting is the whole request, and
    what comes back on stdout is the answer. stderr is dropped because a
    connection failure is already an exit code, and ssh's own text about it
    would arrive in the middle of a status report as noise nobody can act on.
    """

    try:
        completed = subprocess.run(  # noqa: S603 - fixed path, host from validated configuration
            [
                SSH,
                *SSH_OPTIONS,
                "-i",
                str(identity.key),
                f"{identity.user}@{node.mgmt_host}",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
            env=SSH_ENVIRONMENT,
            timeout=STATUS_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return NodeResponse(exit_code=TIMED_OUT, stdout="")
    return NodeResponse(exit_code=completed.returncode, stdout=completed.stdout)


def read_target(publish_path: Path, node_path: str) -> ReleaseTarget | None:
    """The published release the nodes are supposed to be running.

    Read inside the privilege boundary rather than accepted from a caller. It
    decides which nodes a deploy skips as already current and which nodes a
    status reports as current, so a caller-supplied one would let an
    unprivileged process choose both what root does not touch and what the
    operator is told is in sync.
    """

    stamp = publish_path / "current" / node_path / "RELEASE"
    try:
        fields = parse_release_file(stamp.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return None
    version, commit = fields.get("version"), fields.get("hash")
    if not version or not version.isdigit() or not commit:
        return None
    return ReleaseTarget(version=int(version), hash=commit)


#
# A release is named by its commit, and this is the only shape that name may
# have. The name arrives in a node's own status document, so it crosses the
# privilege boundary as text a node chose: root opens a path built from it, and
# a node answering with a traversal would otherwise decide which file root
# reads. Refused rather than sanitised - a name that is not a commit is not a
# release this manager published.
#
RELEASE_NAME = re.compile(r"^[0-9a-f]{7,64}$")


def read_waf_published(publish_path: Path, node_path: str) -> bool | None:
    """Whether the published release carries WAF rules; None when it cannot be read.

    The question a node's engine state is measured against (review 2026-10-04
    F3): a stopped engine is normal on a cluster without rules and a fault on
    one with them, and only the published tree - read here, inside the
    privilege boundary - says which.
    """

    node_root = publish_path / "current" / node_path
    try:
        if not (node_root / "RELEASE").is_file():
            return None
        return (node_root / "waf" / "coraza.yaml").is_file()
    except OSError:
        return None


def read_dns_published(publish_path: Path, node_path: str) -> bool | None:
    """Whether the published release carries a dns listener; None when it cannot be read.

    `read_waf_published`'s question for dnsdist (B249): stopped is normal on a
    cluster without a dns object and a fault on one with them.
    """

    node_root = publish_path / "current" / node_path
    try:
        if not (node_root / "RELEASE").is_file():
            return None
        return (node_root / "dns" / "dnsdist.conf").is_file()
    except OSError:
        return None


@dataclass(frozen=True, slots=True)
class PublishedName:
    """A dns server published by name (B252): the name, and the address it was given."""

    pool: str
    host: str
    address: str


PUBLISHED_SERVER = re.compile(
    r'^newServer\(\{address="(?P<address>[^"]+)", name="(?P<pool>[^"/]+)/[^"]+".*\}\) -- '
    + re.escape(dnsdist_config.NAMED)
    + r"(?P<host>\S+)$"
)
MAX_DNS_CONF_BYTES = 4 * 1024 * 1024


def read_dns_names(publish_path: Path, node_path: str) -> tuple[PublishedName, ...]:
    """The dns servers the published release names, as written beside their addresses."""

    path = publish_path / "current" / node_path / "dns" / dnsdist_config.FILE
    try:
        if not path.is_file() or path.stat().st_size > MAX_DNS_CONF_BYTES:
            return ()
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return ()
    found = []
    for line in text.splitlines():
        match = PUBLISHED_SERVER.match(line)
        if match is None:
            continue
        endpoint = match["address"]
        address = (
            endpoint[1:].split("]", 1)[0]
            if endpoint.startswith("[")
            else endpoint.rsplit(":", 1)[0]
        )
        found.append(PublishedName(pool=match["pool"], host=match["host"], address=address))
    return tuple(found)


DNS_SERVER_MOVED = "dns_server_moved"


def moved_message(name: PublishedName, now: str) -> str:
    """What the warning says. `moved_pool` reads the pool back out of it."""

    return (
        f"{name.host} {now}, not {name.address} as published for pool {name.pool}; "
        f"look it up again on its object"
    )


MOVED_POOL = re.compile(r" as published for pool (?P<pool>[^;]+);")


def moved_pool(message: str) -> str | None:
    found = MOVED_POOL.search(message)
    return found["pool"] if found else None


def dns_servers_moved(
    names: tuple[PublishedName, ...], resolve: dnsdist_config.Lookup | None = None
) -> list[Message]:
    """A server published by name whose name no longer gives the published address (B252).

    The release keeps the address the name had when its object was saved, which
    is the point - dnsdist does not depend on DNS to start - and also the cost: a
    server that moved is not followed until the object is saved again (*Look up
    again*) and published.
    Asked on every status read, with the same resolver the save used (B261).
    """

    warnings = []
    for name in names:
        try:
            now = (resolve or dnsdist_config.lookup)(name.host)
        except dnsdist_config.Unresolved:
            now = "no longer resolves to one address"
        else:
            if now == name.address:
                continue
            now = f"now resolves to {now}"
        warnings.append(Message(code=DNS_SERVER_MOVED, message=moved_message(name, now)))
    return warnings


UNKNOWN = "unknown"


def read_manifest(publish_path: Path, *, release: str | None = None) -> Manifest | None:
    """What one release says its objects amount to, or nothing at all.

    `release` names a release directory; without it the answer is the published
    release, read through `current` so it is whatever the nodes are being told
    to run right now.

    Nothing for a release that has no manifest, and every release published
    before manifests existed is one. The caller reports unknown, which is the
    difference this whole comparison exists to preserve: not knowing is not the
    same as being in sync.
    """

    if release is None:
        path = publish_path / "current" / MANIFEST_FILE
    elif RELEASE_NAME.fullmatch(release):
        path = publish_path / "releases" / release / MANIFEST_FILE
    else:
        return None
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    return parse_manifest(text)


def _object_states(publish_path: Path, results: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Per object, whether every node is serving the published version of it.

    The question a row on a page asks, and one the cluster's release state
    cannot answer: a release carries every object, so "the nodes are behind"
    is true of objects nobody touched. Two manifests answer it per object
    instead, and the entrance somebody used and how long ago they used it stop
    being part of the answer.

    Unknown wherever the comparison could not be made - no published manifest,
    a node that did not say what it runs, a release with no manifest, one that
    could not be read. Unknown loses to `changed`, because a node that is
    demonstrably behind decides the answer whatever a second node could not
    tell us, and it beats `current`, because agreement among the nodes that
    could be read is not agreement.
    """

    published = read_manifest(publish_path)
    if published is None:
        return {}

    cache: dict[str, Manifest | None] = {}
    readings: dict[str, list[Difference]] = {name: [] for name in published.objects}
    unreadable = False

    for entry in results:
        if not entry["status_ok"]:
            unreadable = True
            continue
        observed = _mapping(_mapping(entry["status"]).get("release")).get("hash")
        if not isinstance(observed, str):
            unreadable = True
            continue
        if observed not in cache:
            cache[observed] = read_manifest(publish_path, release=observed)
        manifest = cache[observed]
        if manifest is None:
            unreadable = True
            continue
        for name, difference in compare(published, manifest).items():
            readings[name].append(difference)

    states: dict[str, dict[str, Any]] = {}
    for name, differences in readings.items():
        verdict = worst(differences)
        if verdict is None or (unreadable and verdict.state == CURRENT):
            states[name] = {"state": UNKNOWN, "parts": []}
        else:
            states[name] = {"state": verdict.state, "parts": list(verdict.parts)}
    return states


def _mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _normalised(status: Mapping[str, Any]) -> dict[str, Any]:
    """The node's status, with a numeric release version made a number.

    The frozen schema types `release.version` as an integer; the node writes the
    RELEASE stamp as text and reports the field as it read it, so a conforming
    node still produces `"18"`. That is the delta CONTRACT.md records, and it is
    closed here rather than on the nodes because the manager is what owes the
    frozen contract - changing six node scripts to fix the manager's output
    would be a node-side migration for a manager-side problem.

    Only an all-digit string is converted. Anything else is left exactly as the
    node sent it: a version this cannot read is a fact about the node worth
    seeing, not something to repair on its behalf.
    """

    copy = dict(status)
    release = copy.get("release")
    if isinstance(release, Mapping):
        version = release.get("version")
        if isinstance(version, str) and version.isdigit():
            copy["release"] = {**release, "version": int(version)}
    return copy


def _node_result(
    node: Node, response: NodeResponse, target: ReleaseTarget | None
) -> tuple[dict[str, Any], Message | None]:
    """One node, as the envelope describes it, plus the warning it earned."""

    entry: dict[str, Any] = {
        "name": node.name,
        "mgmt_host": node.mgmt_host,
        "reachable": False,
        "status_ok": False,
        "status": None,
        "current": None,
        "error": None,
    }

    if response.exit_code != 0:
        entry["error"] = {
            "code": "ssh_unreachable",
            "message": (
                f"SSH gave no answer within {STATUS_TIMEOUT_SECONDS} seconds"
                if response.exit_code == TIMED_OUT
                else f"SSH failed with exit {response.exit_code}"
            ),
            "node": node.name,
            "details": None,
        }
        return entry, Message(
            code="ssh_unreachable", message=f"{node.name} is unreachable", node=node.name
        )

    entry["reachable"] = True

    try:
        status = json.loads(response.stdout)
    except json.JSONDecodeError:
        entry["error"] = {
            "code": "node_status_invalid_json",
            "message": "node responded but status JSON could not be parsed",
            "node": node.name,
            "details": None,
        }
        return entry, Message(
            code="node_status_invalid_json",
            message=f"{node.name} returned a status that is not JSON",
            node=node.name,
        )

    #
    # A node status arrives from a machine this host does not control, and "the
    # JSON parsed" is not "the status is valid": null parses, and so does a
    # list. Treating those as valid used to crash the derivation below with an
    # unhandled AttributeError - no JSON on stdout, a traceback on stderr, and
    # haproxy-deploy reporting "did not return valid JSON" instead of degrading
    # to a partial run.
    #
    if not isinstance(status, dict) or not set(status) >= REQUIRED_NODE_STATUS_KEYS:
        entry["error"] = {
            "code": "node_status_invalid",
            "message": "node responded with JSON that is not a node status",
            "node": node.name,
            "details": None,
        }
        return entry, Message(
            code="node_status_invalid",
            message=f"{node.name} returned JSON that is not a node status",
            node=node.name,
        )

    entry["status_ok"] = True
    entry["status"] = _normalised(status)

    #
    # None means "not compared", and it has three causes that must not be
    # reported as being in sync: nothing is published for this cluster, the node
    # did not say which release it runs, or it said nothing about a component
    # the release owns.
    #
    # The comparison is `ReleaseTarget.is_current` itself rather than a hash
    # test written out again here. This module used to do the second, and the
    # difference stopped being cosmetic the moment "current" grew to mean more
    # than one component: a status that answered from the hash alone would call
    # a half-way node converged while the deploy it is meant to inform would
    # still have work to do on it.
    #
    if target is not None:
        observed = _mapping(entry["status"].get("release")).get("hash")
        entry["current"] = target.is_current(
            NodeObservation(
                name=str(entry["name"]),
                status_ok=True,
                release_hash=observed if isinstance(observed, str) else None,
                addresses_current=addresses_current(_mapping(entry["status"])),
                ipvs_current=ipvs_current(_mapping(entry["status"])),
            )
        )

    return entry, None


def _vip_state(results: list[dict[str, Any]]) -> tuple[VipState, list[str], list[str]]:
    owners: list[str] = []
    unknown: list[str] = []

    for entry in results:
        if not entry["status_ok"]:
            continue
        owner = _mapping(_mapping(entry["status"]).get("vip")).get("owner")
        if owner is True:
            owners.append(str(entry["name"]))
        elif owner is None:
            unknown.append(str(entry["name"]))

    #
    # Two owners seen is split brain whatever else could not be read: a node
    # that did not answer cannot make an observed conflict any safer (review
    # 2026-10-03, F1). Before INCOMPLETE, which every deploy lets through.
    #
    if len(owners) > 1:
        return VipState.SPLIT_BRAIN, owners, unknown
    if any(not entry["status_ok"] for entry in results):
        return VipState.INCOMPLETE, owners, unknown
    if unknown:
        return VipState.UNKNOWN, owners, unknown
    if not owners:
        return VipState.NO_OWNER, owners, unknown
    return VipState.SINGLE_OWNER, owners, unknown


def _release_state(results: list[dict[str, Any]], target: ReleaseTarget | None) -> str:
    """The cluster's answer to "are the nodes running what is published".

    Four states rather than a boolean, because the three ways of not being able
    to say yes are different actions for whoever is reading. `unknown` means
    nothing is published or no node said what it runs; `incomplete` means at
    least one node could not be read, so `converged` cannot be claimed for the
    pair even if the node that did answer is current.
    """

    if target is None:
        return "unknown"
    states = [entry["current"] for entry in results]
    if any(state is None for state in states):
        return "incomplete" if any(state is not None for state in states) else "unknown"
    return "converged" if all(states) else "behind"


@dataclass(frozen=True, slots=True)
class StatusReport:
    result: dict[str, Any]
    warnings: tuple[Message, ...]
    valid_nodes: int
    configured_nodes: int

    @property
    def exit_code(self) -> int:
        if self.valid_nodes == self.configured_nodes:
            return EXIT_OK
        return EXIT_PARTIAL if self.valid_nodes > 0 else EXIT_UNAVAILABLE

    def as_envelope(self, cluster: str, *, request_id: str) -> dict[str, Any]:
        if self.valid_nodes == 0:
            return envelope(
                operation=OPERATION,
                outcome="failed",
                cluster=cluster,
                result=self.result,
                request_id=request_id,
                warnings=self.warnings,
                error=Message(code="status_unavailable", message="no node returned usable status"),
            )
        if self.valid_nodes < self.configured_nodes:
            return envelope(
                operation=OPERATION,
                outcome="partial",
                cluster=cluster,
                result=self.result,
                request_id=request_id,
                warnings=self.warnings,
            )
        return envelope(
            operation=OPERATION,
            outcome="done",
            cluster=cluster,
            result=self.result,
            request_id=request_id,
            warnings=self.warnings,
        )


def collect(
    nodes: tuple[Node, ...],
    read_node: ReadNode,
    *,
    target: ReleaseTarget | None,
    publish_path: Path | None = None,
    waf_published: bool | None = None,
    dns_published: bool | None = None,
    dns_names: tuple[PublishedName, ...] = (),
    resolve: dnsdist_config.Lookup | None = None,
) -> StatusReport:
    """Ask every node, then say what the pair adds up to.

    `publish_path` is what makes the per-object answer possible: the manifests
    being compared are two releases in that tree, and reading them is a root
    reading of the published directory rather than anything a node is asked.
    Left out by a caller that only wants the cluster's own state - the deploy
    loop measures a rollout, and the objects it carries are the same objects
    either way.
    """

    results: list[dict[str, Any]] = []
    warnings: list[Message] = []

    #
    # Every node at once rather than one after the other (Fas 16 punkt 1): a
    # read is ~0.3 s per node and a node that does not answer costs its whole
    # connect timeout, so in series a cluster's read grew with every node and
    # every silent one added five seconds. `map` keeps the configured order, and each
    # node is judged afterwards exactly as before.
    #
    answers: list[NodeResponse] = []
    if nodes:
        with ThreadPoolExecutor(max_workers=len(nodes)) as pool:
            answers = list(pool.map(read_node, nodes))
    for node, answer in zip(nodes, answers, strict=True):
        entry, warning = _node_result(node, answer, target)
        results.append(entry)
        if warning is not None:
            warnings.append(warning)

    vip_state, owners, unknown = _vip_state(results)
    valid = sum(1 for entry in results if entry["status_ok"])
    if waf_published:
        #
        # The release has rules and the node's engine is not running them:
        # every WAF object there gets its `on_engine_error` - let through
        # uninspected, or refused - and nothing else says so (review
        # 2026-10-04 F3). A node that does not report the engine is one from
        # before the field, which a release with rules never reaches (B231).
        #
        for entry in results:
            engine = _mapping(_mapping(entry["status"]).get("waf_engine"))
            if entry["status_ok"] and engine and engine.get("active") is not True:
                warnings.append(
                    Message(
                        code="waf_engine_stopped",
                        message=f"the WAF engine is not running on {entry['name']}",
                        node=str(entry["name"]),
                    )
                )

    if dns_published:
        #
        # The release has a dns listener and the node's dnsdist is not
        # serving it: while that node holds the VIP, nothing answers on it.
        #
        for entry in results:
            listener = _mapping(_mapping(entry["status"]).get("dns_listener"))
            if entry["status_ok"] and listener and listener.get("active") is not True:
                warnings.append(
                    Message(
                        code="dns_listener_stopped",
                        message=f"dnsdist is not running on {entry['name']}",
                        node=str(entry["name"]),
                    )
                )

    warnings.extend(dns_servers_moved(dns_names, resolve))

    result = {
        "nodes": results,
        "summary": {
            "configured_nodes": len(results),
            "reachable_nodes": sum(1 for entry in results if entry["reachable"]),
            "valid_status_nodes": valid,
            "vip_owner_count": len(owners),
            "vip_owners": owners,
            "vip_unknown_nodes": unknown,
            "vip_state": str(vip_state),
            #
            # The published release the nodes are measured against, carried in
            # the result so a reader can see what "current" was decided from
            # rather than having to ask a second command what is published.
            #
            "target": None if target is None else {"version": target.version, "hash": target.hash},
            "release_state": _release_state(results, target),
            **({} if waf_published is None else {"waf_published": waf_published}),
            **({} if dns_published is None else {"dns_published": dns_published}),
        },
        #
        # Per object rather than per cluster, and empty when the comparison
        # could not be made at all. A row that finds no entry here reports
        # unknown, which is what every release published before manifests
        # existed produces.
        #
        "objects": {} if publish_path is None else _object_states(publish_path, results),
    }

    return StatusReport(
        result=result,
        warnings=tuple(warnings),
        valid_nodes=valid,
        configured_nodes=len(results),
    )
