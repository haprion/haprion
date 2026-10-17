"""Creating a cluster, and taking one away (Fas 16, B211).

A cluster is more than its entry in `clusters.yaml`. It is a configuration
repository (a bare history and the worktree an operator edits), a directory
its releases are published into, a certificate that names it in the registry,
a `sudoedit` rule per handwritten file, a `safe.directory` entry per
repository in root's git configuration - and at least two nodes, each in the
six places `node_enrollment` describes. Until now `01-manager-prepare` and
`02-manager-config` made all of it from an answers file. This module makes it
from one request, as one change:

* every file's new content is computed first, and the new `clusters.yaml` and
  registry are loaded together exactly as every command will load them;
* the repository and the release directory are created, then every file is
  replaced by a rename with its own owner and mode;
* both nodes are asked for their status over the status identity with strict
  host key checking, as a single added node is;
* anything short of that removes what was created and puts every file back.

The whole change is written down in `change_journal` before the repository is
created or anything is moved, so a run cut short is put back by the next one.

Taking a cluster away archives rather than deletes (B211): its repository, its
release directory and its nodes' backup archives are moved under `.removed/`
in their own roots, where whatever protects the root today protects them. The
name cannot be used again while its archive is there. The nodes themselves are
not touched: they keep serving their addresses until they are shut down.
"""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import subprocess
import tempfile
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

import yaml

from haprion import (
    backups,
    cert_registry,
    change_journal,
    node_enrollment,
    node_publish,
    safe_yaml,
    tls_policy,
)
from haprion.change_journal import FileChange as Change
from haprion.change_journal import Record
from haprion.config import (
    CLUSTER_ID,
    NAME,
    NODE_PATH,
    ConfigError,
    Node,
    PathPolicy,
    RuntimeConfig,
    load_runtime_config,
)
from haprion.git_command import GIT
from haprion.node_enrollment import (
    AskNode,
    Enrollment,
    EnrollmentError,
    Locations,
)

ARCHIVE = ".removed"
SUDOERS_EDIT = Path("/etc/sudoers.d/haprion-config-edit")
#
# Who a cluster's versions are recorded as: the product, in the repository's
# own configuration. Install step 1 sets the same for the clusters it creates.
#
REPOSITORY_IDENTITY = (("user.name", "haprion"), ("user.email", "haprion@localhost"))
ROOT_GITCONFIG = Path("/root/.gitconfig")
RETENTION_ROOT = Path("/etc/haprion/backup-retention")
GIT_CONFIG_NOTHING_TO_UNSET = 5
VISUDO = "/usr/sbin/visudo"
SYSTEMCTL = "/usr/bin/systemctl"
MAX_DISPLAY_NAME = 64
CONTROL = re.compile(r"[\x00-\x1f\x7f]")

#
# The layout every cluster's repository starts with: Create cluster writes it,
# and `01-manager-prepare` asks for it through `haprion-cluster-config --seed`,
# so there is one template and not two that drift apart (they did: the
# script's copy lacked the stick counters, and neither opened the status
# socket - Fas 18 finding 53).
#
SEED_DIRECTORIES = (
    "core/conf.d",
    "core/maps",
    "managed/generated",
    "managed/objects",
    "manual/conf.d",
)
GITIGNORE = "*.swp\n*~\n.#*\n"
#
# Where a cluster's HAProxy keeps the counters that carry over a reload (N3,
# 2026-10-09), named in the core template below. The HAProxy package's runtime
# directory: there on every node from boot, emptied by a restart of the node,
# which resets the counters the way a restart of HAProxy does. The validation
# sandbox gives a check the same directory (`candidate_validation`).
#
SHM_STATS_FILE = "/run/haproxy/stats.shm"
#
# The socket the node's server state helper sets drain, maintenance and ready
# on (Fas 20, B263): level admin, which `operator` is not (measured), and mode
# 600, so only root opens it. Named in the core template below.
#
MANAGER_SOCKET = "/run/haproxy/manager.sock"
#
# The socket node status reads HAProxy's counters and version from
# (`haprion-node-status`, RUNTIME_SOCKET): read-only. Without it every node
# of the cluster reads *Stats unavailable* while it serves.
#
STATUS_SOCKET = "/run/haproxy/ui-status.sock"
CORE_TEMPLATE = """#
# The handwritten `global` and `defaults` for this cluster. Generated
# configuration is assembled behind this file and never edits it.
#
global
    # Your own log, chroot, stats socket, user and group lines go here.

    # Required. A generated bind line names its certificate list by a path
    # relative to the file it is written in, and a node validates a release
    # at one path before installing it at another.
    default-path config

    # Counters that carry over a reload: HAProxy keeps them in this file and
    # finds each object again by its GUID. Opened as root before the chroot,
    # so the path is the host's (docs/user-manual.md, 'Counters across a
    # reload').
    shm-stats-file /run/haproxy/stats.shm

    # The manager's own runtime socket, root only: drain, maintenance and
    # ready per server (docs/user-manual.md, 'Node scripts').
    stats socket /run/haproxy/manager.sock mode 600 level admin

    # Status and statistics for the interface, read-only (docs/user-manual.md,
    # 'HAProxy and keepalived baseline').
    stats socket /run/haproxy/ui-status.sock mode 660 level user

    # Stick counter slots: dynamic blocking counts on the fourth and marks on
    # the fifth (docs/user-manual.md, 'Dynamic blocking').
    tune.stick-counters 5

    # The TLS defaults the publish path checks this file against, written
    # from the same source (docs/user-manual.md, 'Runtime policy').
{tls}
defaults
    log     global
    mode    http
    option  httplog
    timeout connect 5s
    timeout client  50s
    timeout server  50s
"""
RESERVATIONS = """# What the handwritten half of this cluster already uses, so the generator
# can refuse an object that would collide with it. Read, never interpreted -
# this file is a promise a person makes, not something derived.
#
# Empty is correct while nothing handwritten defines a listener.
#
# hostnames:
#   - legacy.example.com
#
# tcp_ports:
#   - 8443                 # every address on this cluster
#   - 192.0.2.10:8443      # only that address
{}
"""
NETWORK = """# Where traffic arrives, where it leaves from, and who may
# reach it. Owned by the application: edited through the same
# publish path as a proxy object, with the same lock, history
# and revert. See docs/user-manual.md, 'Cluster definitions'.
#
# Adding a VIP or a source address here does half the job. The
# other half is keepalived on the nodes, and a source address
# must sit in the same virtual_ipaddress block as its VIP.
vips:
  main:
    address: {vip}
{source}default_vip: main
"""


def seed_files(vip: str | None, source: str | None = None) -> dict[str, bytes]:
    """A new cluster's repository; without a VIP, no network description yet."""

    files = {
        ".gitignore": GITIGNORE.encode(),
        "core/haproxy.cfg": CORE_TEMPLATE.format(tls=tls_policy.core_defaults_lines()).encode(),
        "manual/reservations.yaml": RESERVATIONS.encode(),
    }
    if vip:
        line = f"    source: {source}\n" if source else ""
        files["managed/network.yaml"] = NETWORK.format(vip=vip, source=line).encode()
    for directory in SEED_DIRECTORIES:
        files[f"{directory}/.gitkeep"] = b""
    return files


# ------------------------------------------------------------------ requests


@dataclass(frozen=True, slots=True)
class Definition:
    """A cluster to be created, as the request described it."""

    cluster: str
    display_name: str
    vip: str
    node_path: str
    default_certificate: str | None
    nodes: tuple[tuple[Enrollment, str], ...]
    address_prefix: int | None = None
    address_interface: str | None = None


def check_name(
    cluster: str, *, display_name: str, vip: str
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """The ID, display name and VIP a cluster is created with, checked; the VIP as an address.

    On its own for the first cluster's guide (B315), which asks for these
    before there is a block to create the cluster with.
    """

    if not CLUSTER_ID.fullmatch(cluster):
        raise EnrollmentError("cluster_invalid", f"{cluster!r} is not a cluster ID")
    if (
        not display_name.strip()
        or len(display_name) > MAX_DISPLAY_NAME
        or CONTROL.search(display_name)
    ):
        raise EnrollmentError(
            "cluster_invalid", f"the display name must be 1-{MAX_DISPLAY_NAME} printable characters"
        )
    try:
        return ipaddress.ip_address(vip)
    except ValueError:
        raise EnrollmentError("cluster_invalid", "the VIP must be an IP address") from None


def definition(
    cluster: str,
    *,
    display_name: str,
    vip: str,
    node_path: str,
    default_certificate: str | None,
    blocks: Sequence[str],
    hosts: Sequence[str],
    address_prefix: int | None = None,
    address_interface: str | None = None,
) -> Definition:
    """Read and check a request's fields; the files are checked by `plan_add`."""

    address = check_name(cluster, display_name=display_name, vip=vip)
    if not NODE_PATH.fullmatch(node_path):
        raise EnrollmentError("cluster_invalid", f"{node_path!r} is not a node path")
    if address_prefix is not None and not 1 <= address_prefix <= address.max_prefixlen:
        raise EnrollmentError("cluster_invalid", "the address prefix does not fit the VIP")
    if address_interface is not None and not NAME.fullmatch(address_interface):
        raise EnrollmentError("cluster_invalid", f"{address_interface!r} is not an interface name")
    #
    # One node or two (B302): a cluster is created with its first node, and
    # the next is added to it; two at once is still accepted.
    #
    if not 1 <= len(blocks) <= 2 or len(hosts) != len(blocks):
        raise EnrollmentError(
            "cluster_invalid", "a cluster is created with its first node's block, or its first two"
        )
    nodes = tuple(
        (node_enrollment.parse(block), node_enrollment.host_name(host))
        for block, host in zip(blocks, hosts, strict=True)
    )
    for enrollment, _host in nodes:
        if not node_enrollment.made_for(enrollment, cluster):
            raise EnrollmentError(
                "enrollment_mismatch",
                f"the block for {enrollment.name} was made for {enrollment.cluster!r}, not "
                f"{cluster!r}; run 04-node-prepare on it with {cluster}",
            )
    if len(nodes) == 2 and (nodes[0][0].name == nodes[1][0].name or nodes[0][1] == nodes[1][1]):
        raise EnrollmentError("cluster_invalid", "the two nodes must be two nodes")
    return Definition(
        cluster=cluster,
        display_name=display_name.strip(),
        vip=str(address),
        node_path=node_path,
        default_certificate=default_certificate,
        nodes=nodes,
        address_prefix=address_prefix,
        address_interface=address_interface,
    )


# ------------------------------------------------------------------ the tools


def _run(argv: Sequence[str], *, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - every executable here is a fixed absolute path
        list(argv), input=input_text, capture_output=True, text=True, check=False
    )


@dataclass(frozen=True, slots=True)
class Tools:
    """What this module runs outside Python, replaceable in a test."""

    run: Callable[..., subprocess.CompletedProcess[str]] = _run
    owner: Callable[[Path, int, int], None] = field(
        default=lambda path, uid, gid: os.chown(path, uid, gid) if os.geteuid() == 0 else None
    )
    clock: Callable[[], float] = time.time


@dataclass(frozen=True, slots=True)
class Places:
    """Where the files outside `node_enrollment.Locations` live."""

    sudoers: Path = SUDOERS_EDIT
    gitconfig: Path = ROOT_GITCONFIG
    retention: Path = RETENTION_ROOT


# ---------------------------------------------------------------- the files


def _free_router_id(runtime: RuntimeConfig) -> int:
    """The lowest VRRP router ID no cluster of this manager has (B313).

    Unique among this manager's clusters only. With unicast adverts and
    `check_unicast_src` a router ID elsewhere on the segment never meets
    these (measured 26-10-15), so there is nothing beyond the manager to ask.
    """

    taken = {cluster.vrrp_router_id for cluster in runtime.clusters.values()}
    for candidate in range(1, 256):
        if candidate not in taken:
            return candidate
    raise EnrollmentError("cluster_invalid", "every VRRP router ID from 1 to 255 is in use")


def _cluster_entry(
    policy: PathPolicy,
    spec: Definition,
    *,
    validation_certs: str,
    logging: bool,
    vrrp_router_id: int,
) -> dict[str, Any]:
    entry: dict[str, Any] = {"display_name": spec.display_name, "vip": spec.vip}
    if spec.address_prefix is not None:
        entry["address_prefix"] = spec.address_prefix
    if spec.address_interface is not None:
        entry["address_interface"] = spec.address_interface
    entry.update(
        {
            "config_path": str(policy.config_root / spec.cluster),
            "publish_path": str(policy.publish_root / spec.cluster),
            "node_path": spec.node_path,
            "traffic_logging": logging,
            "vrrp_router_id": vrrp_router_id,
            "nodes": [
                {"name": enrollment.name, "mgmt_host": host} for enrollment, host in spec.nodes
            ],
            "validation_certs": validation_certs,
        }
    )
    if spec.default_certificate is not None:
        entry["default_certificate"] = spec.default_certificate
    return entry


def _registry_with(document: dict[str, Any], certificate: str, cluster: str) -> bytes:
    certificates = dict(document.get("certificates") or {})
    if certificate not in certificates:
        raise EnrollmentError(
            "certificate_unknown", f"there is no certificate {certificate!r} in the registry"
        )
    entry = dict(certificates[certificate])
    entry["clusters"] = sorted({*(entry.get("clusters") or ()), cluster})
    certificates[certificate] = entry
    return cert_registry.render(document, certificates).encode()


def _registry_without(document: dict[str, Any], cluster: str) -> bytes:
    certificates: dict[str, Any] = {}
    for certificate, raw in (document.get("certificates") or {}).items():
        entry = dict(raw)
        remaining = [name for name in entry.get("clusters") or () if name != cluster]
        if remaining:
            entry["clusters"] = remaining
        else:
            entry.pop("clusters", None)
        certificates[certificate] = entry
    return cert_registry.render(document, certificates).encode()


def _edit_paths(policy: PathPolicy, cluster: str) -> tuple[str, str]:
    root = policy.config_root / cluster
    return (str(root / "core/haproxy.cfg"), str(root / "manual/reservations.yaml"))


SUDOEDIT = re.compile(r"^\s*sudoedit (\S+?)(?:,\s*\\)?\s*$")


RULE = "HAPROXY_EDITORS ALL = (root) HAPROXY_EDIT"


def sudoers_with(text: str, add: Sequence[str] = (), drop: Sequence[str] = ()) -> str:
    """The operator editing policy with `add` named and `drop` gone, in step 2's shape.

    The whole alias is written again rather than one line edited: the last entry
    carries no trailing comma, so removing a line can move that position and
    leave the file unparseable (user-manual.md, 'Sudo rules'). With no file
    left to name - the last cluster removed (B302) - the alias and its rule go,
    since sudo refuses an empty alias; the next cluster writes them again.
    """

    lines = text.splitlines()
    paths = [match.group(1) for line in lines if (match := SUDOEDIT.match(line))]
    paths = [path for path in paths if path not in drop] + [
        path for path in add if path not in paths
    ]
    if not any(line.startswith("User_Alias HAPROXY_EDITORS") for line in lines):
        raise EnrollmentError(
            "dependency_unavailable", "the operator editing policy names no HAPROXY_EDITORS", 78
        )
    kept = [
        line
        for line in lines
        if not line.startswith("Cmnd_Alias HAPROXY_EDIT")
        and not SUDOEDIT.match(line)
        and line.strip() != RULE
    ]
    while kept and not kept[-1].strip():
        kept.pop()
    if not paths:
        return "\n".join(kept) + "\n"
    entries = [f"    sudoedit {path}, \\" for path in paths[:-1]] + [f"    sudoedit {paths[-1]}"]
    return "\n".join([*kept, "", "Cmnd_Alias HAPROXY_EDIT = \\", *entries, "", RULE]) + "\n"


def _checked_sudoers(text: str, tools: Tools) -> None:
    with tempfile.NamedTemporaryFile("w", suffix=".sudoers", delete=False) as handle:
        handle.write(text)
        candidate = handle.name
    try:
        checked = tools.run([VISUDO, "-cqf", candidate])
    finally:
        Path(candidate).unlink(missing_ok=True)
    if checked.returncode != 0:
        raise EnrollmentError(
            "sudoers_invalid",
            "the editing policy would not parse; nothing was changed. "
            + (checked.stderr.strip() or checked.stdout.strip()),
            70,
        )


def _gitconfig(
    text: bytes, tools: Tools, *, add: Sequence[str] = (), drop: Sequence[str] = ()
) -> bytes:
    """Root's git configuration with `safe.directory` entries added or taken away."""

    with tempfile.TemporaryDirectory() as raw:
        path = Path(raw) / "gitconfig"
        path.write_bytes(text)
        for repo in drop:
            unset = tools.run(
                [
                    GIT,
                    "config",
                    "--file",
                    str(path),
                    "--unset-all",
                    "safe.directory",
                    f"^{re.escape(repo)}$",
                ]
            )
            #
            # 5 is git's "no such entry": a repository nobody listed is already
            # gone from the list, which is what was asked for.
            #
            if unset.returncode not in (0, GIT_CONFIG_NOTHING_TO_UNSET):
                _checked(unset, "git config --unset-all safe.directory")
        for repo in add:
            _checked(
                tools.run([GIT, "config", "--file", str(path), "--add", "safe.directory", repo]),
                "git config --add safe.directory",
            )
        return path.read_bytes()


def _candidate(
    policy: PathPolicy, clusters: bytes, registry: bytes, *, require_secure: bool
) -> RuntimeConfig:
    """Load the new cluster file and registry together, as every command will."""

    registry_path = policy.certificate_registry
    if registry_path is None:
        raise EnrollmentError(
            "dependency_unavailable", "the runtime policy names no certificate_registry", 78
        )
    made: list[Path] = []
    try:
        pairs = ((policy.cluster_file, clusters), (registry_path, registry))
        paths = []
        for original, content in pairs:
            handle, temporary = tempfile.mkstemp(
                dir=original.parent, prefix=f".{original.name}-candidate."
            )
            made.append(Path(temporary))
            with os.fdopen(handle, "wb") as stream:
                stream.write(content)
            os.chmod(temporary, original.stat().st_mode & 0o7777)
            paths.append(Path(temporary))
        return load_runtime_config(
            replace(policy, cluster_file=paths[0], certificate_registry=paths[1]),
            require_secure=require_secure,
        )
    except ConfigError as exc:
        raise EnrollmentError("cluster_invalid", str(exc)) from None
    finally:
        for path in made:
            path.unlink(missing_ok=True)


def _read(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except FileNotFoundError:
        raise EnrollmentError(
            "dependency_unavailable", f"{path} does not exist; it is created by the installer", 78
        ) from None


def _archived(root: Path, cluster: str) -> bool:
    archive = root / ARCHIVE
    return archive.is_dir() and any(
        entry.name.startswith(f"{cluster}-") for entry in archive.iterdir()
    )


# ------------------------------------------------------------- the creation


@dataclass(frozen=True, slots=True)
class Outcome:
    cluster: str
    action: str
    nodes: tuple[Node, ...]
    files: tuple[str, ...]
    archive: str | None = None
    fingerprints: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "cluster": self.cluster,
            "nodes": [{"name": node.name, "host": node.mgmt_host} for node in self.nodes],
            "files": list(self.files),
            "archive": self.archive,
            "host_key_fingerprints": list(self.fingerprints),
            "warnings": list(self.warnings),
        }


def _node_changes(
    policy: PathPolicy,
    locations: Locations,
    before: dict[Path, bytes],
    *,
    add: Sequence[tuple[str, Node, Enrollment]] = (),
    drop: Sequence[tuple[str, Node]] = (),
) -> dict[Path, tuple[bytes, str]]:
    """The five node files with every node added or dropped, content by path."""

    after: dict[Path, tuple[bytes, str]] = {}

    def current(path: Path) -> bytes:
        if path not in after:
            if path not in before:
                before[path] = _read(path)
            return before[path]
        return after[path][0]

    def put(path: Path, content: bytes, what: str) -> None:
        after[path] = (content, what)

    collector = locations.collector_config.exists()
    for cluster, node, enrollment in add:
        put(
            locations.root_known_hosts,
            node_enrollment.known_hosts_with(
                current(locations.root_known_hosts), node.mgmt_host, enrollment.host_key
            ),
            "root's known_hosts",
        )
        path = locations.authorized_keys(policy.pull_account)
        line = node_enrollment.pull_line(
            policy.publish_root,
            enrollment.config_pull_key,
            node.name,
            node_enrollment.CONFIG_PURPOSE,
        )
        put(
            path,
            node_enrollment.keys_with(
                current(path), line, node.name, node_enrollment.CONFIG_PURPOSE
            ),
            f"{policy.pull_account}'s authorized_keys",
        )
        if policy.certificate_root is not None and enrollment.cert_pull_key:
            path = locations.authorized_keys(policy.cert_pull_account)
            line = node_enrollment.pull_line(
                policy.certificate_root,
                enrollment.cert_pull_key,
                node.name,
                node_enrollment.CERT_PURPOSE,
            )
            put(
                path,
                node_enrollment.keys_with(
                    current(path), line, node.name, node_enrollment.CERT_PURPOSE
                ),
                f"{policy.cert_pull_account}'s authorized_keys",
            )
        if collector:
            put(
                locations.collector_config,
                node_enrollment.collector_with(current(locations.collector_config), cluster, node),
                "the traffic collector's node list",
            )
            put(
                locations.collector_known_hosts,
                node_enrollment.known_hosts_with(
                    current(locations.collector_known_hosts), node.mgmt_host, enrollment.host_key
                ),
                "the traffic collector's known_hosts",
            )
    for cluster, node in drop:
        put(
            locations.root_known_hosts,
            node_enrollment.known_hosts_without(
                current(locations.root_known_hosts), node.mgmt_host
            ),
            "root's known_hosts",
        )
        for account, purpose in (
            (policy.pull_account, node_enrollment.CONFIG_PURPOSE),
            (policy.cert_pull_account, node_enrollment.CERT_PURPOSE),
        ):
            path = locations.authorized_keys(account)
            put(
                path,
                node_enrollment.keys_without(current(path), node.name, purpose),
                f"{account}'s authorized_keys",
            )
        if collector:
            put(
                locations.collector_config,
                node_enrollment.collector_without(
                    current(locations.collector_config), cluster, node.name
                ),
                "the traffic collector's node list",
            )
            put(
                locations.collector_known_hosts,
                node_enrollment.known_hosts_without(
                    current(locations.collector_known_hosts), node.mgmt_host
                ),
                "the traffic collector's known_hosts",
            )
    return after


def _changes(before: dict[Path, bytes], after: Mapping[Path, tuple[bytes, str]]) -> list[Change]:
    return [Change(path, before[path], content, what) for path, (content, what) in after.items()]


def _make_directory(path: Path, like: Path, tools: Tools) -> None:
    path.mkdir(mode=0o750)
    status = like.stat()
    tools.owner(path, status.st_uid, status.st_gid)
    path.chmod(0o750)


def _own_tree(root: Path, like: Path, tools: Tools) -> None:
    """Everything under `root` as the root directory of its kind is: 750 and 640, its group."""

    status = like.stat()
    for directory, directories, files in os.walk(root):
        tools.owner(Path(directory), status.st_uid, status.st_gid)
        Path(directory).chmod(0o750)
        for name in files:
            path = Path(directory) / name
            tools.owner(path, status.st_uid, status.st_gid)
            path.chmod(0o640)
        del directories


def _repository_paths(policy: PathPolicy, cluster: str) -> tuple[Path, Path, Path]:
    """The bare history, its worktree and the release directory a new cluster gets."""

    return (
        policy.config_root / f"{cluster}.git",
        policy.config_root / cluster,
        policy.publish_root / cluster,
    )


def _create_repository(
    policy: PathPolicy,
    spec: Definition,
    tools: Tools,
    files: Mapping[str, bytes] | None = None,
) -> list[Path]:
    """The bare history and its worktree, seeded, as step 1 makes them. Returns what it made.

    `files` is the first version's tree; the layout alone when not given.
    """

    bare, work, publish = _repository_paths(policy, spec.cluster)
    made: list[Path] = []
    try:
        _checked(
            tools.run([GIT, "init", "--quiet", "--bare", "--initial-branch=main", str(bare)]),
            "git init",
        )
        made.append(bare)
        #
        # The identity every version is recorded under, kept in the repository:
        # a publish refuses one without it rather than sign with whatever the
        # environment holds (`repo_snapshot._identity`). The seed's commit used
        # it only for itself, and the first publish on a new cluster stopped
        # (Fas 18, 26-10-15).
        #
        for setting, value in REPOSITORY_IDENTITY:
            _checked(tools.run([GIT, "-C", str(bare), "config", setting, value]), "git config")
        with tempfile.TemporaryDirectory() as raw:
            seed = Path(raw) / "seed"
            for relative, content in (files or seed_files(spec.vip)).items():
                path = seed / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
            identity = [
                argument
                for setting, value in REPOSITORY_IDENTITY
                for argument in ("-c", f"{setting}={value}")
            ]
            _checked(
                tools.run([GIT, "-C", str(seed), "init", "--quiet", "--initial-branch=main"]),
                "git init",
            )
            _checked(tools.run([GIT, "-C", str(seed), "add", "-A"]), "git add")
            _checked(
                tools.run(
                    [
                        GIT,
                        "-C",
                        str(seed),
                        *identity,
                        "commit",
                        "--quiet",
                        "-m",
                        f"Cluster {spec.cluster} created",
                    ]
                ),
                "git commit",
            )
            _checked(
                tools.run([GIT, "-C", str(seed), "push", "--quiet", str(bare), "main"]), "git push"
            )
        _checked(
            tools.run([GIT, "-C", str(bare), "worktree", "add", "--quiet", str(work), "main"]),
            "git worktree add",
        )
        made.append(work)
        _own_tree(bare, policy.config_root, tools)
        _own_tree(work, policy.config_root, tools)
        _make_directory(publish, policy.publish_root, tools)
        made.append(publish)
        _make_directory(publish / "releases", policy.publish_root, tools)
    except BaseException:
        _remove(made)
        raise
    return made


def _checked(completed: subprocess.CompletedProcess[str], what: str) -> None:
    if completed.returncode != 0:
        raise EnrollmentError("repository_failed", f"{what} failed: {completed.stderr.strip()}", 70)


def _remove(made: Sequence[Path]) -> None:
    for path in reversed(made):
        shutil.rmtree(path, ignore_errors=True)


def plan_add(
    policy: PathPolicy,
    runtime: RuntimeConfig,
    spec: Definition,
    *,
    locations: Locations,
    places: Places,
    tools: Tools,
    require_secure: bool = True,
) -> list[Change]:
    if policy.certificate_registry is None:
        raise EnrollmentError(
            "dependency_unavailable",
            "the runtime policy names no certificate_registry, so clusters are created by hand "
            "here",
            78,
        )
    if spec.cluster in runtime.clusters:
        raise EnrollmentError("cluster_exists", f"there is already a cluster {spec.cluster!r}")
    for root in (policy.config_root, policy.publish_root):
        if (root / spec.cluster).exists() or (root / f"{spec.cluster}.git").exists():
            raise EnrollmentError("cluster_exists", f"{root / spec.cluster} already exists")
        if _archived(root, spec.cluster):
            raise EnrollmentError(
                "cluster_archived",
                f"a removed cluster {spec.cluster!r} is archived under {root / ARCHIVE}; "
                "choose another name, or remove the archive by hand first",
            )
    for other in runtime.clusters.values():
        if other.node_path == spec.node_path:
            raise EnrollmentError(
                "cluster_invalid", f"{other.cluster_id} already uses node path {spec.node_path!r}"
            )
        for node in other.nodes:
            for enrollment, host in spec.nodes:
                if node.name == enrollment.name or node.mgmt_host == host:
                    raise EnrollmentError(
                        "node_exists",
                        f"{enrollment.name} ({host}) is already in {other.cluster_id}",
                    )
    #
    # The validation certificate's directory, as the clusters already here
    # name it, or where the installation put it when this is the first
    # (B302 - a manager is installed without clusters).
    #
    first = next(iter(runtime.clusters.values()), None)
    validation_certs = (
        str(first.validation_certs)
        if first is not None
        else str(policy.validation_certs_root / "certs")
    )

    clusters_before = _read(policy.cluster_file)
    document = safe_yaml.load(clusters_before)
    document["clusters"][spec.cluster] = _cluster_entry(
        policy,
        spec,
        validation_certs=validation_certs,
        logging=locations.collector_config.exists(),
        vrrp_router_id=_free_router_id(runtime),
    )
    clusters_after = yaml.safe_dump(document, sort_keys=False).encode()
    registry_before = _read(policy.certificate_registry)
    registry_after = (
        registry_before
        if spec.default_certificate is None
        else _registry_with(
            cert_registry.read_document(policy.certificate_registry),
            spec.default_certificate,
            spec.cluster,
        )
    )
    _candidate(policy, clusters_after, registry_after, require_secure=require_secure)

    before: dict[Path, bytes] = {}
    after = _node_changes(
        policy,
        locations,
        before,
        add=[
            (spec.cluster, Node(name=enrollment.name, mgmt_host=host), enrollment)
            for enrollment, host in spec.nodes
        ],
    )
    changes = [
        Change(policy.cluster_file, clusters_before, clusters_after, "clusters.yaml"),
        Change(
            policy.certificate_registry, registry_before, registry_after, "the certificate registry"
        ),
        *_changes(before, after),
    ]
    repositories = [
        str(policy.config_root / f"{spec.cluster}.git"),
        str(policy.config_root / spec.cluster),
    ]
    if places.gitconfig.exists():
        gitconfig = _read(places.gitconfig)
        changes.append(
            Change(
                places.gitconfig,
                gitconfig,
                _gitconfig(gitconfig, tools, add=repositories),
                "root's git safe.directory",
            )
        )
    if places.sudoers.exists():
        sudoers = _read(places.sudoers)
        edited = sudoers_with(sudoers.decode(), add=_edit_paths(policy, spec.cluster))
        _checked_sudoers(edited, tools)
        changes.append(
            Change(places.sudoers, sudoers, edited.encode(), "the operator editing policy")
        )
    return changes


def add(
    policy: PathPolicy,
    runtime: RuntimeConfig,
    spec: Definition,
    *,
    ask: AskNode,
    join_node: node_enrollment.JoinNode | None = None,
    locations: Locations | None = None,
    places: Places | None = None,
    tools: Tools | None = None,
    require_secure: bool = True,
    addresses: node_publish.Addresses | None = None,
) -> Outcome:
    """Create the cluster with its first nodes.

    With `addresses` (the node helper's), the first version carries the files
    generated for those nodes, so publishing it after is version 1 going out
    (B318); without, the layout alone.
    """

    tools = tools or Tools()
    locations = locations or Locations()
    changes = plan_add(
        policy,
        runtime,
        spec,
        locations=locations,
        places=places or Places(),
        tools=tools,
        require_secure=require_secure,
    )
    nodes = tuple(Node(name=enrollment.name, mgmt_host=host) for enrollment, host in spec.nodes)
    backup_directories = backups.directories_to_make(
        policy.backup_root, (node.name for node in nodes)
    )
    record = Record(
        "cluster add",
        spec.cluster,
        tuple(changes),
        made=_repository_paths(policy, spec.cluster),
        created=backup_directories,
    )
    files = seed_files(spec.vip)
    if addresses is not None:
        clusters_after, registry_after = (change.after for change in changes[:2])
        created = _candidate(
            policy, clusters_after, registry_after, require_secure=require_secure
        ).cluster(spec.cluster)
        files = node_publish.seed(files, created, addresses=addresses)
    with change_journal.transaction(record, locations.journal):
        _create_repository(policy, spec, tools, files)
        for directory in backup_directories:
            directory.mkdir(mode=0o700)
        change_journal.apply(changes)
        #
        # A v2 node is joined first (B317): it learns the manager's keys from
        # the manager, and only then can it answer the status question below.
        #
        if any(enrollment.join_key for enrollment, _host in spec.nodes):
            document = node_enrollment.join_document(
                policy,
                cluster=spec.cluster,
                node_path=spec.node_path,
                vip=spec.vip,
                host_key=locations.manager_host_key,
                collector_key=locations.collector_key,
            )
            for node, (enrollment, _host) in zip(nodes, spec.nodes, strict=True):
                node_enrollment.join(node, enrollment, document, join_node)
        for node in nodes:
            problem = node_enrollment.verify(node, spec.cluster, ask)
            if problem is not None:
                raise EnrollmentError("node_unverified", f"{problem}. Nothing was changed.", 75)
    return Outcome(
        cluster=spec.cluster,
        action="added",
        nodes=nodes,
        files=tuple(change.what for change in changes),
        fingerprints=tuple(
            node_enrollment.fingerprint(enrollment.host_key) for enrollment, _host in spec.nodes
        ),
    )


# -------------------------------------------------------------- the removal


def remove(
    policy: PathPolicy,
    runtime: RuntimeConfig,
    *,
    cluster: str,
    locations: Locations | None = None,
    places: Places | None = None,
    tools: Tools | None = None,
    require_secure: bool = True,
) -> Outcome:
    tools = tools or Tools()
    locations = locations or Locations()
    places = places or Places()
    if cluster not in runtime.clusters:
        raise EnrollmentError("cluster_unknown", f"there is no cluster {cluster!r}")
    if policy.certificate_registry is None:
        raise EnrollmentError(
            "dependency_unavailable", "the runtime policy names no certificate_registry", 78
        )
    target = runtime.clusters[cluster]

    clusters_before = _read(policy.cluster_file)
    document = safe_yaml.load(clusters_before)
    del document["clusters"][cluster]
    clusters_after = yaml.safe_dump(document, sort_keys=False).encode()
    registry_before = _read(policy.certificate_registry)
    registry_after = _registry_without(
        cert_registry.read_document(policy.certificate_registry), cluster
    )
    _candidate(policy, clusters_after, registry_after, require_secure=require_secure)

    before: dict[Path, bytes] = {}
    after = _node_changes(
        policy, locations, before, drop=[(cluster, node) for node in target.nodes]
    )
    changes = [
        Change(policy.cluster_file, clusters_before, clusters_after, "clusters.yaml"),
        Change(
            policy.certificate_registry, registry_before, registry_after, "the certificate registry"
        ),
        *_changes(before, after),
    ]
    repositories = [str(target.config_path) + ".git", str(target.config_path)]
    if places.gitconfig.exists():
        gitconfig = _read(places.gitconfig)
        changes.append(
            Change(
                places.gitconfig,
                gitconfig,
                _gitconfig(gitconfig, tools, drop=repositories),
                "root's git safe.directory",
            )
        )
    if places.sudoers.exists():
        sudoers = _read(places.sudoers)
        edited = sudoers_with(sudoers.decode(), drop=_edit_paths(policy, cluster))
        _checked_sudoers(edited, tools)
        changes.append(
            Change(places.sudoers, sudoers, edited.encode(), "the operator editing policy")
        )

    stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(tools.clock()))
    name = f"{cluster}-{stamp}"
    moves: list[tuple[Path, Path]] = [
        (target.config_path, target.config_path.parent / ARCHIVE / name / target.config_path.name),
        (
            Path(f"{target.config_path}.git"),
            target.config_path.parent / ARCHIVE / name / f"{target.config_path.name}.git",
        ),
        (
            target.publish_path,
            target.publish_path.parent / ARCHIVE / name / target.publish_path.name,
        ),
    ]
    if policy.backup_root is not None:
        for node in target.nodes:
            moves.append(
                (policy.backup_root / node.name, policy.backup_root / ARCHIVE / name / node.name)
            )
    retention = places.retention / f"{cluster}.json"
    if retention.exists():
        moves.append((retention, retention.parent / ARCHIVE / f"{name}.json"))

    moves = [(source, destination) for source, destination in moves if source.exists()]
    #
    # Each directory this makes is recorded, so putting the change back takes
    # it away again: an empty archive left behind would read as an archived
    # name, and refuse the next attempt for a removal that never happened.
    #
    created: list[Path] = []
    for _source, destination in moves:
        for parent in reversed(destination.parents):
            if not parent.exists() and parent not in created:
                created.append(parent)
    record = Record(
        "cluster removal", cluster, tuple(changes), moves=tuple(moves), created=tuple(created)
    )
    with change_journal.transaction(record, locations.journal):
        for directory in created:
            directory.mkdir(mode=0o700)
        for source, destination in moves:
            os.replace(source, destination)
        change_journal.apply(changes)

    warnings: list[str] = []
    timer = f"haprion-state-backup@{cluster}.timer"
    stopped = tools.run([SYSTEMCTL, "disable", "--now", timer])
    if stopped.returncode != 0:
        warnings.append(f"{timer} could not be stopped: {stopped.stderr.strip()}")
    return Outcome(
        cluster=cluster,
        action="removed",
        nodes=target.nodes,
        files=tuple(change.what for change in changes),
        archive=name,
        warnings=tuple(warnings),
    )


def parse_prefix(value: object) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool) or not isinstance(value, int | str):
        raise EnrollmentError("cluster_invalid", "the address prefix must be a number")
    try:
        return int(value)
    except ValueError:
        raise EnrollmentError("cluster_invalid", "the address prefix must be a number") from None


__all__ = [
    "Definition",
    "Outcome",
    "Places",
    "Tools",
    "add",
    "definition",
    "remove",
    "seed_files",
    "sudoers_with",
]
