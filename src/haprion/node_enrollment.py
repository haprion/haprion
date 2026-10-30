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

A node's host - the name the manager reaches it at - can change too (B295):
the same machine, renamed or given another address. `change_host` moves its
line in `clusters.yaml` and the host keys already pinned under the old name to
the new one, in root's `known_hosts` and the collector's, and asks the node at
the new name. The answer must come with a key already pinned and name the node
and its cluster; a machine with another key is another machine, and the change
is put back. The fetch keys are the node's and stay, written again with the new
host's addresses in `from=` (B358).

Pure functions compute the new contents, so the rules are tested without root;
`add`, `remove` and `change_host` are the only places that touch a file.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import ipaddress
import json
import os
import pwd
import re
import secrets
import tempfile
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

import yaml

from haprion import backups, change_journal, exit_codes, safe_yaml
from haprion.cert_receiver import resolve_forward
from haprion.change_journal import FileChange as Change
from haprion.change_journal import Record
from haprion.config import (
    CLUSTER_ID,
    MAX_NODES,
    MIN_NODES,
    NAME,
    Cluster,
    ConfigError,
    Node,
    PathPolicy,
    RuntimeConfig,
    load_runtime_config,
)
from haprion.status_collect import NodeResponse

BLOCK_PREFIX = "haproxy-node-v1:"
#
# The block a node's package prints (B317): no cluster - the request names it -
# and the private half of the node's one-time key, which the manager joins the
# node with once. Never written back out: not in a result, not in an audit row.
#
BLOCK_V2_PREFIX = "haprion-node-v2:"
#
# What a node's package printed before 0.99.0, under the product's old name
# (review 2026-10-22, 7-17). Read as the same block, so a node on an older
# package can still be added; never written.
#
LEGACY_V2_PREFIX = "haproxy-node-v2:"
V2_PREFIXES = (BLOCK_V2_PREFIX, LEGACY_V2_PREFIX)
JOIN_USER = "_haprion-join"
MANAGER_HOST_KEY = Path("/etc/ssh/ssh_host_ed25519_key.pub")
PRIVATE_KEY = re.compile(
    r"^-----BEGIN (OPENSSH) PRIVATE KEY-----\n[A-Za-z0-9+/=\n]{100,1800}"
    r"-----END OPENSSH PRIVATE KEY-----\n?$"
)
#
# The manager's identities by the purpose the node knows them as (node-lib.sh's
# NODE_KEY_PURPOSES, haprion-node-join's PURPOSES; a test holds the three).
#
JOIN_PURPOSES = {
    "deploy_identity": "deploy",
    "cert_deploy_identity": "cert_deploy",
    "server_state_identity": "server_state",
    "status_identity": "status",
    "probe_identity": "probe",
    "backup_identity": "backup",
}
RRSYNC = "/usr/bin/rrsync"
ROOT_KNOWN_HOSTS = Path("/root/.ssh/known_hosts")
COLLECTOR_CONFIG = Path("/etc/haprion/traffic-collector.json")
COLLECTOR_KNOWN_HOSTS = Path("/etc/haprion/traffic-collector/known_hosts")
# The collector's public key, made by platform step 13 (Fas 18, 26-10-16), and
# the purpose it is handed over as: not a runtime policy identity, so not in
# JOIN_PURPOSES.
COLLECTOR_KEY = Path("/etc/haprion/traffic-collector/id_ed25519.pub")
COLLECTOR_PURPOSE = "traffic_log"

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

    def __init__(self, code: str, message: str, exit_code: int = exit_codes.REFUSED):
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
    """What a node says about itself. `host` is its suggestion, not a fact.

    A v1 block names its cluster; a v2 block names none and carries the
    node's one-time key instead (B317).
    """

    cluster: str | None
    name: str
    host: str
    host_key: str
    config_pull_key: str
    cert_pull_key: str | None = None
    join_key: str | None = field(default=None, repr=False)

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
    """The block a node prints: one line, so a terminal cannot fold it.

    v2, from the node's package, names no cluster and carries the one-time key
    - left out where the block is stored and the key travels sealed; v1, from
    `04-node-prepare`, names its cluster.
    """

    if enrollment.cluster is None:
        joined: dict[str, Any] = {
            "name": enrollment.name,
            "host": enrollment.host,
            "host_key": enrollment.host_key,
            "config_pull_key": enrollment.config_pull_key,
            **(
                {}
                if enrollment.cert_pull_key is None
                else {"cert_pull_key": enrollment.cert_pull_key}
            ),
        }
        if enrollment.join_key is not None:
            joined["join_key"] = base64.b64encode(enrollment.join_key.encode()).decode()
        encoded = base64.urlsafe_b64encode(json.dumps(joined, separators=(",", ":")).encode())
        return BLOCK_V2_PREFIX + encoded.decode()
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
    prefix = next(
        (known for known in (*V2_PREFIXES, BLOCK_PREFIX) if compact.startswith(known)), None
    )
    if prefix is None:
        raise EnrollmentError(
            "enrollment_invalid",
            f"this is not an enrollment block; it starts with {BLOCK_V2_PREFIX}",
        )
    version2 = prefix in V2_PREFIXES
    try:
        raw = base64.urlsafe_b64decode(compact[len(prefix) :].encode())
        document = json.loads(raw)
    except (binascii.Error, ValueError, UnicodeDecodeError):
        raise EnrollmentError(
            "enrollment_invalid", "the enrollment block is damaged; copy it again"
        ) from None
    allowed = {"name", "host", "host_key", "config_pull_key", "cert_pull_key"}
    allowed |= {"join_key"} if version2 else {"cluster"}
    if not isinstance(document, dict) or not set(document) <= allowed:
        raise EnrollmentError("enrollment_invalid", "the enrollment block has unexpected fields")
    cluster, name = document.get("cluster"), document.get("name")
    if version2:
        cluster = None
    elif not isinstance(cluster, str) or not CLUSTER_ID.fullmatch(cluster):
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
        join_key=(
            private_key(document["join_key"]) if version2 and "join_key" in document else None
        ),
    )


def private_key(value: object) -> str:
    """The one-time key a v2 block carries: one OpenSSH private key, nothing else."""

    try:
        if not isinstance(value, str):
            raise ValueError
        text = base64.b64decode(value.encode(), validate=True).decode("ascii")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        raise EnrollmentError("enrollment_invalid", "the block's one-time key is damaged") from None
    if not PRIVATE_KEY.fullmatch(text):
        raise EnrollmentError("enrollment_invalid", "the block's one-time key is not one")
    return text if text.endswith("\n") else text + "\n"


def without_join_key(enrollment: Enrollment) -> Enrollment:
    """The block as it may be stored: everything but the one-time key."""

    return replace(enrollment, join_key=None)


def made_for(enrollment: Enrollment, cluster: str) -> bool:
    """A v1 block names its cluster and must name this one; a v2 block names none."""

    return enrollment.cluster is None or enrollment.cluster == cluster


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


def host_keys(text: bytes, host: str) -> list[str]:
    """The keys the file pins for `host`, in its order: `type base64` each."""

    keys: list[str] = []
    for line in text.decode().splitlines():
        fields = line.split()
        if len(fields) >= 3 and not line.lstrip().startswith("#") and _names_host(fields[0], host):
            key = f"{fields[1]} {fields[2]}"
            if key not in keys:
                keys.append(key)
    return keys


def sharing_host_key(
    runtime: RuntimeConfig, known: bytes, key: str, *, also: Iterable[tuple[str, str]] = ()
) -> list[str]:
    """The nodes already pinned with this host key, by name - a cloned machine (fynd 43).

    `also` adds (name, key) pairs not in the file yet: the other new node of a
    cluster created with two. A warning, not a refusal (B335): SSH cannot tell
    the two apart, but nothing breaks until one is rebuilt or impersonated.
    """

    pinned = key.split()[:2]
    names = [
        node.name
        for cluster in runtime.clusters.values()
        for node in cluster.nodes
        if any(other.split()[:2] == pinned for other in host_keys(known, node.mgmt_host))
    ]
    names += [name for name, other in also if other.split()[:2] == pinned]
    return sorted(set(names))


def shared_key_warning(node: str, others: Iterable[str]) -> str:
    """The one sentence, in the engine, the CLI and the job page."""

    return (
        f"{node} has the same SSH host key as {', '.join(others)}: a cloned machine. "
        "The manager cannot tell them apart; give one a new host key and add it again"
    )


def known_hosts_moved(text: bytes, old: str, new: str, keys: list[str]) -> bytes:
    """`old`'s lines gone, and `keys` pinned under `new` instead."""

    body = known_hosts_without(known_hosts_without(text, old), new).decode()
    if body and not body.endswith("\n"):
        body += "\n"
    return (body + "".join(hashed_host_line(new, key) + "\n" for key in keys)).encode()


def known_hosts_with(text: bytes, host: str, key: str) -> bytes:
    body = known_hosts_without(text, host).decode()
    if body and not body.endswith("\n"):
        body += "\n"
    return (body + hashed_host_line(host, key) + "\n").encode()


# ------------------------------------------------------------ authorized_keys


def config_root(policy: PathPolicy, cluster: str) -> Path:
    """What a node's configuration fetch key reads: its own cluster's published tree (B358)."""

    return policy.publish_root / cluster


def pull_sources(host: str, forward: Callable[[str], tuple[str, ...]]) -> tuple[str, ...]:
    """What a node's `from=` holds: its host, and the addresses that host resolves to (B358).

    As a receiver's lock (B162): sshd's `UseDNS` is off by default, and then
    `from=` matches the peer's address only, so a name alone would lock out
    the node it was written for. The name is kept for the reader and for
    `UseDNS yes`. A node whose address changes is a host change, which writes
    the lines again, or `haprion-node pull-keys` after the DNS change.
    """

    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return (host,)
    addresses = forward(host)
    if not addresses:
        raise EnrollmentError(
            "host_unresolvable",
            f"{host} does not resolve, so its fetch keys cannot be bound to its address",
        )
    return (host, *addresses)


def pull_line(
    root: Path,
    key: str,
    node: str,
    purpose: str,
    sources: Iterable[str],
    *,
    expires: str | None = None,
) -> str:
    """One node's fetch key: read-only, its cluster's tree alone, from its addresses alone.

    `sources` empty leaves `from=` out: only `pull-keys` writes such a line,
    for a node whose host does not resolve at the time, and says so.
    `expires` (`YYYYMMDDHHMM`, UTC) ends the line by itself: a test restore's
    temporary one (`TEMPORARY_NODE`) does not outlive its run.
    """

    allowed = ",".join(sources)
    lock = f'from="{allowed}",' if allowed else ""
    end = f'expiry-time="{expires}Z",' if expires else ""
    return f'{lock}restrict,{end}command="{RRSYNC} -ro {root}" {key} {node} {purpose}'


#
# The name a test restore's temporary fetch line goes under: `restore-<run>`,
# in the place of a node's name. Nothing manages such a line but the restore
# that wrote it, so `pull-keys` leaves it alone and the node commands never
# find it by a node's name (B398).
#
TEMPORARY_NODE = re.compile(r"^restore-r\d{6}-[0-9a-f]{8}$")

KEY_LINE = re.compile(
    r'^(?P<options>(?:[^\s"]|"[^"]*")+)\s+(?P<key>[a-z0-9@.-]+\s+[A-Za-z0-9+/=]+)\s+(?P<comment>.+)$'
)


def node_keys(text: bytes, purpose: str) -> dict[str, str]:
    """Each node's fetch key in an account's file, by node name: `type base64`.

    Found by the comment every line carries (`<node> <purpose>`), as a removal
    finds it. A line of another shape is not a node's and is not returned.
    """

    found: dict[str, str] = {}
    for line in text.decode().splitlines():
        match = KEY_LINE.fullmatch(line.strip())
        if match is None or not match.group("comment").endswith(f" {purpose}"):
            continue
        node = match.group("comment").removesuffix(f" {purpose}")
        if NAME.fullmatch(node):
            found[node] = match.group("key")
    return found


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


def clusters_with_host(text: bytes, cluster: str, name: str, host: str) -> bytes:
    document = safe_yaml.load(text)
    for entry in document["clusters"][cluster]["nodes"]:
        if entry["name"] == name:
            entry["mgmt_host"] = host
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


def collector_with_host(text: bytes, cluster: str, name: str, host: str) -> bytes:
    document = json.loads(text)
    for entry in document["nodes"]:
        if (entry["cluster"], entry["node"]) == (cluster, name):
            entry["host"] = host
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
    # The manager's own host key, which a joining node is given (B317).
    manager_host_key: Path = MANAGER_HOST_KEY
    # The traffic-log collector's key, which a joining node is given when there is one.
    collector_key: Path = COLLECTOR_KEY
    # The addresses a node's host resolves to, which its fetch keys are bound to (B358).
    forward: Callable[[str], tuple[str, ...]] = resolve_forward

    def authorized_keys(self, account: str) -> Path:
        return self.home(account) / ".ssh" / "authorized_keys"


def _read(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except FileNotFoundError:
        raise EnrollmentError(
            "dependency_unavailable",
            f"{path} does not exist; it is created by the installer",
            exit_codes.CONFIG,
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


def require_cert_key(policy: PathPolicy, cluster: str, enrollment: Enrollment) -> None:
    """Refuse a block without the certificate pull key where certificates are distributed.

    One rule for adding a node and for creating a cluster (review 26-10-30, E4).
    """

    if policy.certificate_directory(cluster) is not None and enrollment.cert_pull_key is None:
        raise EnrollmentError(
            "enrollment_invalid",
            f"the block for {enrollment.name} carries no certificate pull key, and this "
            "installation distributes certificates; run 04-node-prepare with "
            "NODE_CERT_PULL_KEY set",
        )


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
    if not made_for(enrollment, cluster):
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
    require_cert_key(policy, cluster, enrollment)
    cert_account, cert_root = policy.cert_pull_account, policy.certificate_directory(cluster)
    cert_key = enrollment.cert_pull_key

    node = Node(name=enrollment.name, mgmt_host=host)
    sources = pull_sources(host, locations.forward)
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
                    config_root(policy, cluster),
                    enrollment.config_pull_key,
                    node.name,
                    CONFIG_PURPOSE,
                    sources,
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
                    pull_line(cert_root, cert_key, node.name, CERT_PURPOSE, sources),
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
) -> tuple[Node, list[Change], Cluster]:
    if cluster not in runtime.clusters:
        raise EnrollmentError("cluster_unknown", f"there is no cluster {cluster!r}")
    nodes = runtime.clusters[cluster].nodes
    node = next((entry for entry in nodes if entry.name == name), None)
    if node is None:
        raise EnrollmentError("node_unknown", f"{name} is not a node of {cluster}")
    if len(nodes) <= MIN_NODES:
        raise EnrollmentError(
            "cluster_minimum",
            "a cluster keeps its last node; remove the cluster instead"
            if MIN_NODES == 1
            else f"a cluster keeps at least {MIN_NODES} nodes; remove the cluster instead",
        )

    clusters_before = _read(policy.cluster_file)
    clusters_after = clusters_without(clusters_before, cluster, name)
    candidate = _candidate_runtime(policy, clusters_after, require_secure=require_secure)
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
    return node, changes, candidate.cluster(cluster)


def plan_change_host(
    policy: PathPolicy,
    runtime: RuntimeConfig,
    *,
    cluster: str,
    name: str,
    host: str,
    locations: Locations,
    require_secure: bool = True,
) -> tuple[Node, Node, list[str], list[Change]]:
    """The node as it is, as it will be, the keys that move, and the files that change."""

    if cluster not in runtime.clusters:
        raise EnrollmentError("cluster_unknown", f"there is no cluster {cluster!r}")
    node = next((entry for entry in runtime.clusters[cluster].nodes if entry.name == name), None)
    if node is None:
        raise EnrollmentError("node_unknown", f"{name} is not a node of {cluster}")
    if node.mgmt_host == host:
        raise EnrollmentError("host_unchanged", f"{name} is already reached at {host}")
    for other in runtime.clusters.values():
        for existing in other.nodes:
            if existing.mgmt_host == host:
                raise EnrollmentError(
                    "node_exists", f"{host} is already {existing.name} in {other.cluster_id}"
                )
    known = _read(locations.root_known_hosts)
    keys = host_keys(known, node.mgmt_host)
    if not keys:
        raise EnrollmentError(
            "host_key_unknown",
            f"root's known_hosts pins no key for {node.mgmt_host}, so there is nothing to prove "
            f"the machine at {host} is {name}; remove the node and add it again instead",
        )
    moved = Node(name=name, mgmt_host=host)
    sources = pull_sources(host, locations.forward)
    clusters_before = _read(policy.cluster_file)
    clusters_after = clusters_with_host(clusters_before, cluster, name, host)
    _candidate_runtime(policy, clusters_after, require_secure=require_secure)
    changes = [
        Change(policy.cluster_file, clusters_before, clusters_after, "clusters.yaml"),
        Change(
            locations.root_known_hosts,
            known,
            known_hosts_moved(known, node.mgmt_host, host, keys),
            "root's known_hosts",
        ),
    ]
    #
    # The fetch keys are the node's and stay; their `from=` is the host's
    # (B358), so they are written again with the new host's addresses.
    #
    for account, purpose, root in (
        (policy.pull_account, CONFIG_PURPOSE, config_root(policy, cluster)),
        (policy.cert_pull_account, CERT_PURPOSE, policy.certificate_directory(cluster)),
    ):
        path = locations.authorized_keys(account)
        current = _read(path)
        key = node_keys(current, purpose).get(name)
        if root is None or key is None:
            continue
        changes.append(
            Change(
                path,
                current,
                keys_with(current, pull_line(root, key, name, purpose, sources), name, purpose),
                f"{account}'s authorized_keys",
            )
        )
    if locations.collector_config.exists():
        collector = _read(locations.collector_config)
        changes.append(
            Change(
                locations.collector_config,
                collector,
                collector_with_host(collector, cluster, name, host),
                "the traffic collector's node list",
            )
        )
        collector_known = _read(locations.collector_known_hosts)
        changes.append(
            Change(
                locations.collector_known_hosts,
                collector_known,
                known_hosts_moved(collector_known, node.mgmt_host, host, keys),
                "the traffic collector's known_hosts",
            )
        )
    return node, moved, keys, changes


# ---------------------------------------------------------- asking the node


type AskNode = Callable[[Node], NodeResponse]
#
# How the manager joins a v2 node (B317): the node, the one-time key and the
# document `haprion-node-join` reads. The helper's goes over SSH as
# _haprion-join; tests give their own.
#
type JoinNode = Callable[[Node, str, dict[str, Any]], NodeResponse]
#
# A node being removed is asked to deploy once more, over the deploy identity
# it already trusts (B319): the release it fetches no longer names it, and the
# node stops keepalived and HAProxy. The node list's publication, for the
# cluster as it will be, is what makes that release.
#
type LeaveNode = Callable[[Node], NodeResponse]
type PublishCluster = Callable[[Cluster], dict[str, Any]]


def _public(path: Path) -> str:
    try:
        return " ".join(path.read_text(encoding="ascii").split()[:2])
    except (OSError, UnicodeDecodeError) as exc:
        raise EnrollmentError(
            "dependency_unavailable", f"{path} could not be read ({exc})", exit_codes.CONFIG
        ) from None


def join_document(
    policy: PathPolicy,
    *,
    cluster: str,
    node_path: str,
    vip: str,
    host_key: Path,
    collector_key: Path | None = None,
) -> dict[str, Any]:
    """What a joining node is given: the manager's public keys and where it belongs.

    The traffic-log collector's key goes with them when the collector is
    installed: the traffic log is a base function (Fas 18, 26-10-16), and the
    node turns its route on when it is given the key.
    """

    keys = {
        purpose: _public(Path(f"{identity.key}.pub"))
        for name, purpose in JOIN_PURPOSES.items()
        if (identity := getattr(policy, name)) is not None
    }
    if collector_key is not None and os.path.isfile(collector_key):
        keys[COLLECTOR_PURPOSE] = _public(collector_key)
    if not {"deploy", "status"} <= set(keys):
        raise EnrollmentError(
            "dependency_unavailable",
            "the runtime policy names no deploy_identity or status_identity to hand a node",
            exit_codes.CONFIG,
        )
    return {
        "version": 1,
        "cluster": cluster,
        "node_path": node_path,
        "vip": vip,
        "manager_host_key": _public(host_key),
        "keys": keys,
    }


SSH_FAILED = 255

JOINED_BUT_UNVERIFIED = (
    "{node} had joined by then: its block is used up. Add it again with the same block once "
    "it answers over SSH, or make a new block on the node with  sudo haprion-node-key --again"
)


def join(
    node: Node,
    enrollment: Enrollment,
    document: dict[str, Any],
    join_node: JoinNode | None,
    ask: AskNode | None = None,
) -> bool:
    """Join a v2 node once with its one-time key; True when this call joined it.

    The join always runs first, so a live one-time key is used and the document
    is applied. Only when it cannot connect (ssh exit 255) is the node asked: one
    that already answers as itself in the document's cluster was joined by an
    earlier attempt that was rolled back on the manager (its block is used up
    by then), and is not joined again. A v1 block joins nothing.
    """

    if enrollment.join_key is None:
        return False
    if join_node is None:
        raise EnrollmentError(
            "dependency_unavailable",
            "a v2 block needs the helper's join, and there is none",
            exit_codes.CONFIG,
        )
    response = join_node(node, enrollment.join_key, document)
    if response.exit_code == SSH_FAILED and (
        ask is not None and verify(node, str(document["cluster"]), ask) is None
    ):
        return False
    if response.exit_code != 0:
        said = " ".join((response.stderr or "").strip().splitlines()[-3:])
        #
        # Step 4 stops (exit 75) before it uses the key up: the block works
        # again until it expires. Any other exit may have come after the key
        # was used, so only a new block is promised.
        #
        again = (
            "this one was not used up, so try it again within 24 hours, or make a new one"
            if response.exit_code == 75
            else "make a new one"
        )
        raise EnrollmentError(
            "node_join_failed",
            f"{node.mgmt_host} did not join (exit {response.exit_code}){': ' + said if said else ''}. "
            f"Nothing was changed here. A block is valid for 24 hours and once; {again} "
            "on the node with  sudo haprion-node-key --again",
            exit_codes.BLOCKED,
        )
    return True


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


def serving(node: Node, ask: AskNode) -> bool | None:
    """Whether keepalived or HAProxy still runs on the node; None when it cannot be asked."""

    response = ask(node)
    if response.exit_code != 0:
        return None
    try:
        status = json.loads(response.stdout)
        keepalived = status["keepalived"]["active"]
        haproxy = status["haproxy"]["active"]
    except (ValueError, KeyError, TypeError):
        return None
    if not isinstance(keepalived, bool) or not isinstance(haproxy, bool):
        return None
    return keepalived or haproxy


def step_down(
    node: Node, publication: dict[str, Any] | None, leave: LeaveNode, ask: AskNode
) -> str | None:
    """None when the node has stopped serving; otherwise what is left to do, in words.

    Read back from the node's status rather than believed from the deploy's
    exit code, as a deploy's own result is. A node that cannot be reached is
    the usual reason somebody removes one; it is removed all the same, and the
    sentence says what it will do if it is started again.
    """

    afterwards = (
        f"Stop keepalived and HAProxy on {node.name}, or shut it down: started again, "
        "it takes the cluster's addresses."
    )
    if publication is None or "error" in publication:
        return (
            f"{node.name} was not asked to stop, because the node list was not published. "
            + afterwards
        )
    asked = leave(node)
    still = serving(node, ask)
    if still is False:
        return None
    if still is None:
        return f"{node.name} did not answer (exit {asked.exit_code}). " + afterwards
    return f"{node.name} still runs keepalived or HAProxy (exit {asked.exit_code}). " + afterwards


@dataclass(frozen=True, slots=True)
class Outcome:
    node: Node
    cluster: str
    files: tuple[str, ...]
    fingerprint: str | None = None
    #
    # The nodes already pinned with the same host key (fynd 43, B335).
    #
    shares_host_key_with: tuple[str, ...] = ()

    previous_host: str | None = None
    #
    # A removal publishes before its files are written (B319), so it carries
    # its publication and whether the node stepped down; None elsewhere.
    #
    publication: dict[str, Any] | None = None
    step_down: str | None = None
    stepped_down: bool | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "cluster": self.cluster,
            "node": self.node.name,
            "host": self.node.mgmt_host,
            "files": list(self.files),
            "host_key_fingerprint": self.fingerprint,
            **(
                {"shares_host_key_with": list(self.shares_host_key_with)}
                if self.shares_host_key_with
                else {}
            ),
            **({} if self.previous_host is None else {"previous_host": self.previous_host}),
            **({} if self.publication is None else {"publication": self.publication}),
            **(
                {}
                if self.stepped_down is None
                else {
                    "step_down": {"stopped": True}
                    if self.stepped_down
                    else {"stopped": False, "message": self.step_down}
                }
            ),
        }


def add(
    policy: PathPolicy,
    runtime: RuntimeConfig,
    enrollment: Enrollment,
    *,
    cluster: str,
    host: str,
    ask: AskNode,
    join_node: JoinNode | None = None,
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
    sharing = sharing_host_key(
        runtime, _read((locations or Locations()).root_known_hosts), enrollment.host_key
    )
    backup_directories = backups.directories_to_make(policy.backup_root, (node.name,))
    with change_journal.transaction(
        Record("node add", cluster, tuple(changes), created=backup_directories),
        (locations or Locations()).journal,
    ):
        for directory in backup_directories:
            directory.mkdir(mode=0o700)
        change_journal.apply(changes)
        joined = False
        if enrollment.join_key is not None:
            target = runtime.cluster(cluster)
            joined = join(
                node,
                enrollment,
                join_document(
                    policy,
                    cluster=cluster,
                    node_path=target.node_path,
                    vip=target.vip,
                    host_key=(locations or Locations()).manager_host_key,
                    collector_key=(locations or Locations()).collector_key,
                ),
                join_node,
                ask,
            )
        problem = verify(node, cluster, ask)
        if problem is not None:
            raise EnrollmentError(
                "node_unverified",
                f"{problem}. "
                + (
                    f"The manager's files were put back, but {JOINED_BUT_UNVERIFIED.format(node=node.name)}"
                    if joined
                    else "Nothing was changed."
                ),
                exit_codes.BLOCKED,
            )
    return Outcome(
        node=node,
        cluster=cluster,
        files=tuple(change.what for change in changes),
        fingerprint=fingerprint(enrollment.host_key),
        shares_host_key_with=tuple(sharing),
    )


def remove(
    policy: PathPolicy,
    runtime: RuntimeConfig,
    *,
    cluster: str,
    name: str,
    ask: AskNode,
    publish: PublishCluster | None = None,
    leave: LeaveNode | None = None,
    locations: Locations | None = None,
    require_secure: bool = True,
) -> Outcome:
    node, changes, remaining = plan_remove(
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
            exit_codes.BLOCKED,
        )
    #
    # Before a file is written (B319, Fas 18 finding 73). Removed and left
    # running, the node kept its keepalived and its peers; once the nodes that
    # stayed had their new list they stopped hearing it and it took the
    # address beside them. So the cluster as it will be is published first, the
    # node fetches that release with the key it still has and stops, and only
    # then do its keys go. A removal run again after a stop between the two -
    # the release already without the node - publishes nothing new and asks
    # the node again.
    #
    publication = publish(remaining) if publish is not None else None
    problem = step_down(node, publication, leave, ask) if leave is not None else None
    with change_journal.transaction(
        Record("node removal", cluster, tuple(changes)), (locations or Locations()).journal
    ):
        change_journal.apply(changes)
    return Outcome(
        node=node,
        cluster=cluster,
        files=tuple(change.what for change in changes),
        publication=publication,
        step_down=problem,
        stepped_down=None if leave is None else problem is None,
    )


def change_host(
    policy: PathPolicy,
    runtime: RuntimeConfig,
    *,
    cluster: str,
    name: str,
    host: str,
    ask: AskNode,
    locations: Locations | None = None,
    require_secure: bool = True,
) -> Outcome:
    """Reach the same node at another name or address (B295), or change nothing.

    Asked after the files are written, because the question is the proof: the
    status connection checks the host key strictly against the file just
    written, so only a machine holding a key already pinned for this node gets
    as far as answering, and the answer must name the node and its cluster.
    """

    node, moved, keys, changes = plan_change_host(
        policy,
        runtime,
        cluster=cluster,
        name=name,
        host=host,
        locations=locations or Locations(),
        require_secure=require_secure,
    )
    with change_journal.transaction(
        Record("node host change", cluster, tuple(changes)), (locations or Locations()).journal
    ):
        change_journal.apply(changes)
        problem = verify(moved, cluster, ask)
        if problem is not None:
            raise EnrollmentError(
                "node_unverified",
                f"{problem}. {name} is still reached at {node.mgmt_host}; nothing was changed.",
                exit_codes.BLOCKED,
            )
    return Outcome(
        node=moved,
        cluster=cluster,
        files=tuple(change.what for change in changes),
        fingerprint=fingerprint(keys[0]),
        previous_host=node.mgmt_host,
    )
