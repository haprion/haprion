"""Adding a node to a cluster, and taking one away (Fas 16, B211).

A node is known to the management host in six places, all root-owned and all
written by hand until now: its line in `clusters.yaml`, its host key in root's
`known_hosts` (every status, deploy, backup and probe connection checks it),
its two fetch keys in the pull accounts' `authorized_keys`, and - where the
traffic-log collector is installed - its entry in the collector's node list
and its host key in the collector's own `known_hosts`. This module changes all
six as one: every new content is computed first, the whole change is written
down in `change_journal` before the first file is touched, every file is
replaced by a rename with its own owner and mode, and any failure - or a run
cut short, put back by the next one - puts every file back.

Nothing here is taken from the network. The node prints an enrollment block
(`04-node-prepare`): its name, its cluster, its host key and its two public
fetch keys. The block reaches this module because an administrator copied it
from the node's console - that copy is the trust, the same way accepting a
host key by hand was before, and the fingerprint the preview shows is what the
administrator compares. After writing, the node is asked for its status over
the status identity with strict host key checking: an answer proves that the
host at that name holds that key, that the node already trusts the management
host's keys, and - because the node reports its own name and cluster - that
the block described the node that answered. Anything short of that answer
undoes the change.

Pure functions compute the new contents, so the rules are tested without root;
`add` and `remove` are the only places that touch a file.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import pwd
import re
import secrets
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

import yaml

from haproxy_mgmt import change_journal, safe_yaml
from haproxy_mgmt.change_journal import FileChange as Change
from haproxy_mgmt.change_journal import Record
from haproxy_mgmt.config import (
    CLUSTER_ID,
    MAX_NODES,
    MIN_NODES,
    NAME,
    ConfigError,
    Node,
    PathPolicy,
    RuntimeConfig,
    load_runtime_config,
)
from haproxy_mgmt.status_collect import NodeResponse

BLOCK_PREFIX = "haproxy-node-v1:"
RRSYNC = "/usr/bin/rrsync"
ROOT_KNOWN_HOSTS = Path("/root/.ssh/known_hosts")
COLLECTOR_CONFIG = Path("/etc/haprion/traffic-collector.json")
COLLECTOR_KNOWN_HOSTS = Path("/etc/haprion/traffic-collector/known_hosts")

#
# The comments the fetch lines carry, one per purpose. They are how a node's
# line is found again when it is removed, so they are the node's name and
# nothing a person could have typed for another node: the lines written by hand
# before this existed (measured 2026-09-30) already read `<node> config pull`
# and `<node> certificate pull`.
#
CONFIG_PURPOSE = "config pull"
CERT_PURPOSE = "certificate pull"

HOST = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)
MAX_BLOCK_BYTES = 8192
ED25519_BLOB_BYTES = 51


class EnrollmentError(Exception):
    """A refusal with a stable code, in words the page and the terminal show."""

    def __init__(self, code: str, message: str, exit_code: int = 65):
        super().__init__(message)
        self.code = code
        self.exit_code = exit_code


def public_key(value: object, what: str) -> str:
    """An ed25519 public key as `ssh-ed25519 <base64>`, comment dropped.

    Only ed25519: it is what `04-node-prepare` generates for the fetch keys and
    what every node's host key list carries, and one type is one parser.
    """

    if not isinstance(value, str):
        raise EnrollmentError("enrollment_invalid", f"{what} is missing")
    parts = value.split()
    if len(parts) < 2 or parts[0] != "ssh-ed25519":
        raise EnrollmentError("enrollment_invalid", f"{what} is not an ssh-ed25519 key")
    try:
        blob = base64.b64decode(parts[1], validate=True)
    except (binascii.Error, ValueError):
        raise EnrollmentError("enrollment_invalid", f"{what} is not valid base64") from None
    if len(blob) != ED25519_BLOB_BYTES or blob[:15] != b"\x00\x00\x00\x0bssh-ed25519":
        raise EnrollmentError("enrollment_invalid", f"{what} is not an ssh-ed25519 key")
    return f"ssh-ed25519 {parts[1]}"


def fingerprint(key: str) -> str:
    """The key's SHA256 fingerprint, as `ssh-keygen -lf` prints it."""

    blob = base64.b64decode(key.split()[1])
    digest = base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
    return f"SHA256:{digest}"


def host_name(value: object, what: str = "the host") -> str:
    if not isinstance(value, str) or not HOST.fullmatch(value):
        raise EnrollmentError("enrollment_invalid", f"{what} is not a host name")
    return value.lower()


@dataclass(frozen=True, slots=True)
class Enrollment:
    """What a node says about itself. `host` is its suggestion, not a fact."""

    cluster: str
    name: str
    host: str
    host_key: str
    config_pull_key: str
    cert_pull_key: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "cluster": self.cluster,
            "name": self.name,
            "host": self.host,
            "host_key": self.host_key,
            "host_key_fingerprint": fingerprint(self.host_key),
            "config_pull_key": self.config_pull_key,
            "cert_pull_key": self.cert_pull_key,
        }


def render(enrollment: Enrollment) -> str:
    """The block `04-node-prepare` prints: one line, so a terminal cannot fold it."""

    document = {
        "cluster": enrollment.cluster,
        "name": enrollment.name,
        "host": enrollment.host,
        "host_key": enrollment.host_key,
        "config_pull_key": enrollment.config_pull_key,
        **({} if enrollment.cert_pull_key is None else {"cert_pull_key": enrollment.cert_pull_key}),
    }
    encoded = base64.urlsafe_b64encode(json.dumps(document, separators=(",", ":")).encode())
    return BLOCK_PREFIX + encoded.decode()


def parse(text: object) -> Enrollment:
    """Read a pasted block. Whitespace anywhere is dropped: a terminal may wrap it."""

    if not isinstance(text, str) or len(text.encode()) > MAX_BLOCK_BYTES:
        raise EnrollmentError("enrollment_invalid", "the enrollment block is missing or too long")
    compact = "".join(text.split())
    if not compact.startswith(BLOCK_PREFIX):
        raise EnrollmentError(
            "enrollment_invalid",
            f"this is not an enrollment block; it starts with {BLOCK_PREFIX}",
        )
    try:
        raw = base64.urlsafe_b64decode(compact[len(BLOCK_PREFIX) :].encode())
        document = json.loads(raw)
    except (binascii.Error, ValueError, UnicodeDecodeError):
        raise EnrollmentError(
            "enrollment_invalid", "the enrollment block is damaged; copy it again"
        ) from None
    allowed = {"cluster", "name", "host", "host_key", "config_pull_key", "cert_pull_key"}
    if not isinstance(document, dict) or not set(document) <= allowed:
        raise EnrollmentError("enrollment_invalid", "the enrollment block has unexpected fields")
    cluster, name = document.get("cluster"), document.get("name")
    if not isinstance(cluster, str) or not CLUSTER_ID.fullmatch(cluster):
        raise EnrollmentError("enrollment_invalid", "the block names no valid cluster")
    if not isinstance(name, str) or not NAME.fullmatch(name):
        raise EnrollmentError("enrollment_invalid", "the block names no valid node")
    cert = document.get("cert_pull_key")
    return Enrollment(
        cluster=cluster,
        name=name,
        host=host_name(document.get("host"), "the block's host"),
        host_key=public_key(document.get("host_key"), "the host key"),
        config_pull_key=public_key(document.get("config_pull_key"), "the config pull key"),
        cert_pull_key=None if cert is None else public_key(cert, "the certificate pull key"),
    )


# --------------------------------------------------------------- known_hosts


def hashed_host_line(host: str, key: str, *, salt: bytes | None = None) -> str:
    """A `known_hosts` line in the hashed form root's file already uses."""

    salt = salt if salt is not None else secrets.token_bytes(20)
    digest = hmac.new(salt, host.encode(), hashlib.sha1).digest()
    return f"|1|{base64.b64encode(salt).decode()}|{base64.b64encode(digest).decode()} {key}"


def _names_host(field_: str, host: str) -> bool:
    if field_.startswith("|1|"):
        try:
            _, _, salt, digest = field_.split("|")
            expected = hmac.new(base64.b64decode(salt), host.encode(), hashlib.sha1).digest()
            return hmac.compare_digest(expected, base64.b64decode(digest))
        except (ValueError, binascii.Error):
            return False
    return host in field_.split(",")


def known_hosts_without(text: bytes, host: str) -> bytes:
    """Every line that names `host` removed, hashed or plain, as `ssh-keygen -R` does."""

    kept = [
        line
        for line in text.decode().splitlines(keepends=True)
        if line.lstrip().startswith("#")
        or not line.split()
        or not _names_host(line.split()[0], host)
    ]
    return "".join(kept).encode()


def known_hosts_with(text: bytes, host: str, key: str) -> bytes:
    body = known_hosts_without(text, host).decode()
    if body and not body.endswith("\n"):
        body += "\n"
    return (body + hashed_host_line(host, key) + "\n").encode()


# ------------------------------------------------------------ authorized_keys


def pull_line(root: Path, key: str, node: str, purpose: str) -> str:
    return f'restrict,command="{RRSYNC} -ro {root}" {key} {node} {purpose}'


def _is_node_line(line: str, node: str, purpose: str) -> bool:
    return line.rstrip("\n").endswith(f" {node} {purpose}")


def keys_without(text: bytes, node: str, purpose: str) -> bytes:
    lines = text.decode().splitlines(keepends=True)
    return "".join(line for line in lines if not _is_node_line(line, node, purpose)).encode()


def keys_with(text: bytes, line: str, node: str, purpose: str) -> bytes:
    body = keys_without(text, node, purpose).decode()
    if body and not body.endswith("\n"):
        body += "\n"
    return (body + line + "\n").encode()


# ---------------------------------------------------------------- the lists


def clusters_with(text: bytes, cluster: str, node: Node) -> bytes:
    document = safe_yaml.load(text)
    document["clusters"][cluster]["nodes"].append({"name": node.name, "mgmt_host": node.mgmt_host})
    return yaml.safe_dump(document, sort_keys=False).encode()


def clusters_without(text: bytes, cluster: str, name: str) -> bytes:
    document = safe_yaml.load(text)
    nodes = document["clusters"][cluster]["nodes"]
    document["clusters"][cluster]["nodes"] = [entry for entry in nodes if entry["name"] != name]
    return yaml.safe_dump(document, sort_keys=False).encode()


def collector_with(text: bytes, cluster: str, node: Node) -> bytes:
    document = json.loads(text)
    document["nodes"] = [
        entry
        for entry in document["nodes"]
        if (entry["cluster"], entry["node"]) != (cluster, node.name)
    ] + [{"cluster": cluster, "node": node.name, "host": node.mgmt_host}]
    return (json.dumps(document, indent=2) + "\n").encode()


def collector_without(text: bytes, cluster: str, name: str) -> bytes:
    document = json.loads(text)
    document["nodes"] = [
        entry for entry in document["nodes"] if (entry["cluster"], entry["node"]) != (cluster, name)
    ]
    return (json.dumps(document, indent=2) + "\n").encode()


# ------------------------------------------------------------ the transaction


@dataclass(frozen=True, slots=True)
class Locations:
    """Where the six files live. Fixed in production; a directory in the tests."""

    root_known_hosts: Path = ROOT_KNOWN_HOSTS
    collector_config: Path = COLLECTOR_CONFIG
    collector_known_hosts: Path = COLLECTOR_KNOWN_HOSTS
    journal: Path = change_journal.JOURNAL
    home: Callable[[str], Path] = field(default=lambda account: Path(pwd.getpwnam(account).pw_dir))

    def authorized_keys(self, account: str) -> Path:
        return self.home(account) / ".ssh" / "authorized_keys"


def _read(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except FileNotFoundError:
        raise EnrollmentError(
            "dependency_unavailable", f"{path} does not exist; it is created by the installer", 78
        ) from None


# -------------------------------------------------------------- the planning


def _candidate_runtime(
    policy: PathPolicy, clusters: bytes, *, require_secure: bool
) -> RuntimeConfig:
    """Load the new `clusters.yaml` exactly as every command will, before it is installed."""

    directory = policy.cluster_file.parent
    handle, temporary = tempfile.mkstemp(dir=directory, prefix=".clusters-candidate.")
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(clusters)
        os.chmod(temporary, policy.cluster_file.stat().st_mode & 0o7777)
        return load_runtime_config(
            replace(policy, cluster_file=Path(temporary)), require_secure=require_secure
        )
    except ConfigError as exc:
        raise EnrollmentError("cluster_invalid", str(exc)) from None
    finally:
        Path(temporary).unlink(missing_ok=True)


def plan_add(
    policy: PathPolicy,
    runtime: RuntimeConfig,
    enrollment: Enrollment,
    *,
    cluster: str,
    host: str,
    locations: Locations,
    require_secure: bool = True,
) -> list[Change]:
    if cluster not in runtime.clusters:
        raise EnrollmentError("cluster_unknown", f"there is no cluster {cluster!r}")
    if enrollment.cluster != cluster:
        raise EnrollmentError(
            "enrollment_mismatch",
            f"the block was made for cluster {enrollment.cluster!r}, not {cluster!r}; "
            "run 04-node-prepare on the node with the right cluster",
        )
    for other in runtime.clusters.values():
        for existing in other.nodes:
            if existing.name == enrollment.name:
                raise EnrollmentError(
                    "node_exists", f"{enrollment.name} is already a node of {other.cluster_id}"
                )
            if existing.mgmt_host == host:
                raise EnrollmentError(
                    "node_exists", f"{host} is already {existing.name} in {other.cluster_id}"
                )
    if len(runtime.clusters[cluster].nodes) >= MAX_NODES:
        raise EnrollmentError("cluster_full", f"a cluster has at most {MAX_NODES} nodes")
    cert_account, cert_root = policy.cert_pull_account, policy.certificate_root
    cert_key = enrollment.cert_pull_key
    wants_cert = cert_root is not None
    if wants_cert and cert_key is None:
        raise EnrollmentError(
            "enrollment_invalid",
            "the block carries no certificate pull key, and this installation distributes "
            "certificates; run 04-node-prepare with NODE_CERT_PULL_KEY set",
        )

    node = Node(name=enrollment.name, mgmt_host=host)
    clusters_before = _read(policy.cluster_file)
    clusters_after = clusters_with(clusters_before, cluster, node)
    _candidate_runtime(policy, clusters_after, require_secure=require_secure)

    changes = [Change(policy.cluster_file, clusters_before, clusters_after, "clusters.yaml")]
    known = _read(locations.root_known_hosts)
    changes.append(
        Change(
            locations.root_known_hosts,
            known,
            known_hosts_with(known, host, enrollment.host_key),
            "root's known_hosts",
        )
    )
    keys_path = locations.authorized_keys(policy.pull_account)
    keys = _read(keys_path)
    changes.append(
        Change(
            keys_path,
            keys,
            keys_with(
                keys,
                pull_line(
                    policy.publish_root, enrollment.config_pull_key, node.name, CONFIG_PURPOSE
                ),
                node.name,
                CONFIG_PURPOSE,
            ),
            f"{policy.pull_account}'s authorized_keys",
        )
    )
    if cert_account is not None and cert_root is not None and cert_key is not None:
        cert_path = locations.authorized_keys(cert_account)
        cert_keys = _read(cert_path)
        changes.append(
            Change(
                cert_path,
                cert_keys,
                keys_with(
                    cert_keys,
                    pull_line(cert_root, cert_key, node.name, CERT_PURPOSE),
                    node.name,
                    CERT_PURPOSE,
                ),
                f"{cert_account}'s authorized_keys",
            )
        )
    if locations.collector_config.exists():
        collector = _read(locations.collector_config)
        changes.append(
            Change(
                locations.collector_config,
                collector,
                collector_with(collector, cluster, node),
                "the traffic collector's node list",
            )
        )
        collector_known = _read(locations.collector_known_hosts)
        changes.append(
            Change(
                locations.collector_known_hosts,
                collector_known,
                known_hosts_with(collector_known, host, enrollment.host_key),
                "the traffic collector's known_hosts",
            )
        )
    return changes


def plan_remove(
    policy: PathPolicy,
    runtime: RuntimeConfig,
    *,
    cluster: str,
    name: str,
    locations: Locations,
    require_secure: bool = True,
) -> tuple[Node, list[Change]]:
    if cluster not in runtime.clusters:
        raise EnrollmentError("cluster_unknown", f"there is no cluster {cluster!r}")
    nodes = runtime.clusters[cluster].nodes
    node = next((entry for entry in nodes if entry.name == name), None)
    if node is None:
        raise EnrollmentError("node_unknown", f"{name} is not a node of {cluster}")
    if len(nodes) <= MIN_NODES:
        raise EnrollmentError(
            "cluster_minimum",
            f"a cluster keeps at least {MIN_NODES} nodes; remove the cluster instead",
        )

    clusters_before = _read(policy.cluster_file)
    clusters_after = clusters_without(clusters_before, cluster, name)
    _candidate_runtime(policy, clusters_after, require_secure=require_secure)
    changes = [Change(policy.cluster_file, clusters_before, clusters_after, "clusters.yaml")]
    known = _read(locations.root_known_hosts)
    changes.append(
        Change(
            locations.root_known_hosts,
            known,
            known_hosts_without(known, node.mgmt_host),
            "root's known_hosts",
        )
    )
    for account, purpose in (
        (policy.pull_account, CONFIG_PURPOSE),
        (policy.cert_pull_account, CERT_PURPOSE),
    ):
        path = locations.authorized_keys(account)
        keys = _read(path)
        changes.append(
            Change(path, keys, keys_without(keys, name, purpose), f"{account}'s authorized_keys")
        )
    if locations.collector_config.exists():
        collector = _read(locations.collector_config)
        changes.append(
            Change(
                locations.collector_config,
                collector,
                collector_without(collector, cluster, name),
                "the traffic collector's node list",
            )
        )
        collector_known = _read(locations.collector_known_hosts)
        changes.append(
            Change(
                locations.collector_known_hosts,
                collector_known,
                known_hosts_without(collector_known, node.mgmt_host),
                "the traffic collector's known_hosts",
            )
        )
    return node, changes


# ---------------------------------------------------------- asking the node


type AskNode = Callable[[Node], NodeResponse]


def verify(node: Node, cluster: str, ask: AskNode) -> str | None:
    """None when the node answered as itself; otherwise why it did not."""

    response = ask(node)
    if response.exit_code != 0:
        return (
            f"{node.mgmt_host} did not answer over SSH (exit {response.exit_code}). Check that "
            "the management host's key lines are in the node's authorized_keys and that the "
            "host key in the block is the node's."
        )
    try:
        status = json.loads(response.stdout)
    except ValueError:
        return f"{node.mgmt_host} answered, but not with a node status"
    if not isinstance(status, dict):
        return f"{node.mgmt_host} answered, but not with a node status"
    if status.get("node") != node.name or status.get("cluster") != cluster:
        return (
            f"{node.mgmt_host} answered as {status.get('node')!r} in cluster "
            f"{status.get('cluster')!r}, not as {node.name!r} in {cluster!r}"
        )
    return None


def owns_vip(node: Node, ask: AskNode) -> bool | None:
    """Whether the node says it holds the VIP; None when it cannot be asked."""

    response = ask(node)
    if response.exit_code != 0:
        return None
    try:
        status = json.loads(response.stdout)
        owner = status["vip"]["owner"]
    except (ValueError, KeyError, TypeError):
        return None
    return owner if isinstance(owner, bool) else None


@dataclass(frozen=True, slots=True)
class Outcome:
    node: Node
    cluster: str
    files: tuple[str, ...]
    fingerprint: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "cluster": self.cluster,
            "node": self.node.name,
            "host": self.node.mgmt_host,
            "files": list(self.files),
            "host_key_fingerprint": self.fingerprint,
        }


def add(
    policy: PathPolicy,
    runtime: RuntimeConfig,
    enrollment: Enrollment,
    *,
    cluster: str,
    host: str,
    ask: AskNode,
    locations: Locations | None = None,
    require_secure: bool = True,
) -> Outcome:
    changes = plan_add(
        policy,
        runtime,
        enrollment,
        cluster=cluster,
        host=host,
        locations=locations or Locations(),
        require_secure=require_secure,
    )
    node = Node(name=enrollment.name, mgmt_host=host)
    with change_journal.transaction(
        Record("node add", cluster, tuple(changes)), (locations or Locations()).journal
    ):
        change_journal.apply(changes)
        problem = verify(node, cluster, ask)
        if problem is not None:
            raise EnrollmentError("node_unverified", f"{problem}. Nothing was changed.", 75)
    return Outcome(
        node=node,
        cluster=cluster,
        files=tuple(change.what for change in changes),
        fingerprint=fingerprint(enrollment.host_key),
    )


def remove(
    policy: PathPolicy,
    runtime: RuntimeConfig,
    *,
    cluster: str,
    name: str,
    ask: AskNode,
    locations: Locations | None = None,
    require_secure: bool = True,
) -> Outcome:
    node, changes = plan_remove(
        policy,
        runtime,
        cluster=cluster,
        name=name,
        locations=locations or Locations(),
        require_secure=require_secure,
    )
    #
    # Asked, not assumed. A node that answers that it holds the address is
    # serving the cluster, and removing it would leave the manager unable to
    # see the node taking every request. One that cannot be asked is usually
    # the reason somebody is removing it.
    #
    if owns_vip(node, ask) is True:
        raise EnrollmentError(
            "node_owns_vip",
            f"{name} holds the VIP right now. Move the address to another node first.",
            75,
        )
    with change_journal.transaction(
        Record("node removal", cluster, tuple(changes)), (locations or Locations()).journal
    ):
        change_journal.apply(changes)
    return Outcome(node=node, cluster=cluster, files=tuple(change.what for change in changes))
