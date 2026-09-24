"""Decide, before anything is written, exactly what a restore writes where.

The plan is computed on the management host from the archive, the chosen mode
and what the target reported about itself.  It is shown in full by the preview
and executed unchanged by the run, so what the operator approved and what is
written are the same object.

Three modes exist:

* ``new_vm`` - an empty VM becomes the archived node: its hostname, its
  address, its host keys, its keepalived role.
* ``test`` - the same, except that the node's identity on the network is
  rewritten to a test profile, field by field, and keepalived is masked so the
  node can never take part in the production cluster's VRRP.  Every rewritten
  field is listed; nothing else differs from ``new_vm``.
* ``overwrite`` - the archive over the node itself, running (B172, B183): the
  same files as ``new_vm``, but the node's software is its own - no repository
  file is written and only a missing product package is installed - the
  network is written only where it differs, and what the product's own
  directories hold beyond the archive goes to quarantine on the node.

Two things are split off the main file set because of *when* they may be
written, not what they are: Netplan (last, under a timer that rolls it back),
and root's ``authorized_keys`` (after everything else - it removes the
one-time key the restore itself is connected with).
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, Literal

import yaml

from haproxy_mgmt import haproxy_repository
from haproxy_mgmt.restore_source import Account, Entry, Group, RestoreSource, content

Mode = Literal["new_vm", "test", "overwrite"]
MODES: tuple[Mode, ...] = ("new_vm", "test", "overwrite")

NETPLAN_DIR = "/etc/netplan"
ROOT_KEYS = "/root/.ssh/authorized_keys"
KEEPALIVED_CONF = "/etc/keepalived/keepalived.conf"
KEEPALIVED_ADDRESSES = "/etc/keepalived/addresses.conf"
HOST_KEY_PREFIX = "/etc/ssh/ssh_host_"

#
# What a node needs from the distribution, independent of what the image it was
# built from happened to carry.  ``meta/packages.txt`` is `apt-mark showmanual`
# of the old image and is shown, not installed.  rsync is how pull-deploy
# fetches a release; python3 runs the node's status and probe scripts.
#
PRODUCT_PACKAGES = (
    "haproxy",
    "keepalived",
    "rsyslog",
    "openssh-server",
    "rsync",
    "python3",
    #
    # The network is written as Netplan and applied with `netplan apply` on
    # both supported targets; Debian's cloud image renders Netplan at boot
    # but does not carry the command (measured 2026-09-24).
    #
    "netplan.io",
)
#
# The archive's APT state names the release it was taken on; the target keeps
# its own and gets the HAProxy repository for its own release instead (B178).
#
APT_DIRECTORIES = ("/etc/apt/sources.list.d", "/etc/apt/preferences.d", "/etc/apt/keyrings")
#
# Directories the product shares with the OS image (B178). The export takes
# them whole, but only the product's own file in each comes back: the rest
# belong to the image the archive was taken on - the cloud image's sysctl and
# sshd drop-ins, cloud-init's sudoers file, rules left from before the product
# - and the target has its own. An operator's file here comes back when the
# operator names it in EXTRA_BACKUP_PATHS. The names are the ones
# install/04-node-prepare writes; a test holds the two together.
#
SHARED_DIRECTORIES = {
    "/etc/sysctl.d": frozenset({"/etc/sysctl.d/60-haproxy.conf"}),
    "/etc/sudoers.d": frozenset({"/etc/sudoers.d/haproxy-node"}),
    "/etc/ssh/sshd_config.d": frozenset(),
}
# The product sets nothing in the SSH server's own file; the target's stays.
TARGET_FILES = frozenset({"/etc/ssh/sshd_config"})
#
# What the release's node bundle writes on a restored node (B178, B180): the
# node scripts and the record of which bundle they came from, by
# 04-node-prepare, and the traffic log's rsyslog, AppArmor and retention files,
# by haproxy-traffic-log-enable when the archive shows the log was on. The
# archive's copies are of the release the node ran when it was archived.
#
SCRIPT_DIR = "/usr/local/sbin"
TRAFFIC_LOG_RULE = "/etc/rsyslog.d/48-haproxy-manager-traffic.conf"
FROM_BUNDLE = frozenset(
    {
        "/etc/haproxy-manager/node-installation.json",
        TRAFFIC_LOG_RULE,
        "/etc/apparmor.d/rsyslog.d/haproxy-manager-traffic",
        "/etc/systemd/system/haproxy-traffic-log-prune.service",
        "/etc/systemd/system/haproxy-traffic-log-prune.timer",
    }
)
#
# The directories only the product writes in (B183). Overwriting a node makes
# them hold what the archive and the node bundle put there; anything else in
# them goes to quarantine on the node, never deleted. The directories the
# product shares with the image are not among them (B178).
#
PRODUCT_DIRECTORIES = ("/etc/haproxy-manager", "/etc/systemd/system/haproxy.service.d")
# 04-node-prepare's rollback copies: history of the old node, not its state.
REPLACED = re.compile(r"\.replaced-\d{8}-\d{6}$")

MAC = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


class PlanError(ValueError):
    """The archive and the target cannot be combined into a safe restore."""


@dataclass(frozen=True, slots=True)
class TestProfile:
    hostname: str
    address: ipaddress.IPv4Interface
    vip: ipaddress.IPv4Interface


@dataclass(frozen=True, slots=True)
class Target:
    """What the target reported in the preview session."""

    os_release: dict[str, str]
    interface: str
    mac: str
    #
    # For an overwrite (B183), what the node holds now: the SHA-256 of each
    # archived path that is a file there (None where it is not), what the
    # product's directories and /etc/netplan contain, and which product
    # packages are installed.
    #
    hashes: dict[str, str | None] = field(default_factory=dict)
    listing: dict[str, tuple[str, ...]] = field(default_factory=dict)
    installed: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PlannedFile:
    path: str
    kind: str
    mode: int
    uid: int
    gid: int
    entry: Entry | None = None
    data: bytes | None = None
    link: str | None = None


@dataclass(frozen=True, slots=True)
class Rewrite:
    path: str
    field: str
    old: str
    new: str


@dataclass(frozen=True, slots=True)
class RestorePlan:
    mode: Mode
    source_hostname: str
    hostname: str
    address: ipaddress.IPv4Interface
    files: tuple[PlannedFile, ...]
    equal_directories: tuple[str, ...]
    #
    # Files in the archive this restore does not write, because the target
    # has its own (B178). Shown, so an operator's own file among them is seen
    # before the restore rather than missed after it.
    #
    left_out: tuple[str, ...]
    # Archived files the node bundle writes in its own version instead.
    from_bundle: tuple[str, ...]
    # The archive shows the traffic log was on; haproxy-traffic-log-enable runs.
    traffic_log: bool
    parents: tuple[str, ...]
    network: tuple[PlannedFile, ...]
    root_keys: PlannedFile | None
    groups: tuple[Group, ...]
    accounts: tuple[Account, ...]
    packages: tuple[str, ...]
    keepalived: Literal["start", "mask"]
    rewrites: tuple[Rewrite, ...] = field(default=())
    #
    # Overwrite only (B183): the planned files whose contents differ from the
    # node's or that it does not have, the number already equal, what moves to
    # quarantine, and whether the network is written at all.
    #
    changed: tuple[str, ...] = ()
    unchanged: int = 0
    quarantined: tuple[str, ...] = ()
    network_unchanged: bool = False

    def summary(self) -> dict[str, Any]:
        """The plan as the preview shows it: paths and fields, never contents or hashes."""

        return {
            "mode": self.mode,
            "source_hostname": self.source_hostname,
            "hostname": self.hostname,
            "address": str(self.address),
            "files": [file.path for file in self.files],
            "network": [file.path for file in self.network],
            "equal_directories": list(self.equal_directories),
            "left_out": list(self.left_out),
            "from_bundle": list(self.from_bundle),
            "traffic_log": self.traffic_log,
            "groups": [{"name": group.name, "gid": group.gid} for group in self.groups],
            "accounts": [
                {
                    "name": account.name,
                    "uid": account.uid,
                    "gid": account.gid,
                    "home": account.home,
                    "groups": list(account.groups),
                    "service": account.service,
                    "has_password": bool(account.password_hash)
                    and account.password_hash not in {"!", "*", "!*"},
                }
                for account in self.accounts
            ],
            "packages": list(self.packages),
            "keepalived": self.keepalived,
            "rewrites": [
                {"path": item.path, "field": item.field, "old": item.old, "new": item.new}
                for item in self.rewrites
            ],
        } | (
            {
                "changed": list(self.changed),
                "unchanged": self.unchanged,
                "quarantined": list(self.quarantined),
                "network_unchanged": self.network_unchanged,
            }
            if self.mode == "overwrite"
            else {}
        )


def _under(path: str, roots: Iterable[str]) -> bool:
    return any(path == root or path.startswith(f"{root}/") for root in roots)


def _targets_own(path: str, extra: tuple[str, ...]) -> bool:
    """True for an archived path the target keeps its own version of (B178)."""

    if _under(path, extra):
        return False
    if path in TARGET_FILES or _under(path, APT_DIRECTORIES) or REPLACED.search(path):
        return True
    for directory, own in SHARED_DIRECTORIES.items():
        if _under(path, (directory,)):
            return path not in own
    return False


def _planned(entry: Entry, data: bytes | None = None) -> PlannedFile:
    return PlannedFile(
        path=entry.path,
        kind=entry.kind,
        mode=entry.mode,
        uid=entry.uid,
        gid=entry.gid,
        entry=entry if data is None else None,
        data=data,
        link=entry.target,
    )


def _text(source: RestoreSource, entry: Entry) -> str:
    try:
        return content(source, entry).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PlanError(f"{entry.path} is not UTF-8 text") from exc


def _netplan_files(source: RestoreSource) -> list[Entry]:
    return [
        entry
        for entry in source.owned()
        if entry.path.startswith(f"{NETPLAN_DIR}/")
        and entry.kind == "file"
        and entry.path.endswith((".yaml", ".yml"))
    ]


def _ethernet(document: Any, path: str) -> tuple[str, dict[str, Any]] | None:
    if not isinstance(document, dict) or not isinstance(document.get("network"), dict):
        raise PlanError(f"{path} is not a Netplan document")
    ethernets = document["network"].get("ethernets") or {}
    if not isinstance(ethernets, dict):
        raise PlanError(f"{path} has an unreadable ethernets section")
    carrying = [(name, value) for name, value in ethernets.items() if isinstance(value, dict)]
    carrying = [(name, value) for name, value in carrying if value.get("addresses")]
    if len(carrying) > 1:
        raise PlanError(f"{path} gives addresses to more than one interface")
    return carrying[0] if carrying else None


def _address(interface: dict[str, Any], path: str) -> ipaddress.IPv4Interface:
    addresses = interface.get("addresses")
    if not isinstance(addresses, list) or len(addresses) != 1:
        raise PlanError(f"{path} does not give its interface exactly one address")
    try:
        return ipaddress.IPv4Interface(str(addresses[0]))
    except ValueError as exc:
        raise PlanError(f"{path} has an address a restore does not handle") from exc


def _network(
    source: RestoreSource, target: Target, profile: TestProfile | None
) -> tuple[tuple[PlannedFile, ...], ipaddress.IPv4Interface, list[Rewrite]]:
    files: list[PlannedFile] = []
    rewrites: list[Rewrite] = []
    node_address: ipaddress.IPv4Interface | None = None
    for entry in _netplan_files(source):
        try:
            document = yaml.safe_load(_text(source, entry))
        except yaml.YAMLError as exc:
            raise PlanError(f"{entry.path} is not valid YAML") from exc
        found = _ethernet(document, entry.path)
        if found is None:
            files.append(_planned(entry))
            continue
        if node_address is not None:
            raise PlanError("more than one Netplan file gives the node an address")
        name, interface = found
        node_address = _address(interface, entry.path)
        live_name = interface.get("set-name") or name
        if live_name != target.interface:
            raise PlanError(
                f"the archive's interface is {live_name} and the target's is "
                f"{target.interface}; renaming a live interface is not part of a restore"
            )
        rewritten = len(rewrites)
        match = interface.get("match")
        if isinstance(match, dict) and "macaddress" in match:
            old_mac = str(match["macaddress"]).lower()
            if old_mac != target.mac:
                match["macaddress"] = target.mac
                rewrites.append(Rewrite(entry.path, "match.macaddress", old_mac, target.mac))
        if profile is not None:
            if profile.address.network != node_address.network:
                raise PlanError(
                    f"the test address {profile.address} is not in the node's network "
                    f"{node_address.network}; its routes would not reach the gateway"
                )
            interface["addresses"] = [str(profile.address)]
            rewrites.append(
                Rewrite(entry.path, "addresses", str(node_address), str(profile.address))
            )
        if len(rewrites) == rewritten:
            # Nothing to change: the archive's own bytes, so a node that already
            # has them is seen to have them (B183).
            files.append(_planned(entry))
            continue
        data = yaml.safe_dump(document, default_flow_style=False, sort_keys=False).encode()
        files.append(_planned(entry, data))
    if node_address is None:
        raise PlanError("no Netplan file in the archive gives the node its address")
    address = profile.address if profile is not None else node_address
    return tuple(files), address, rewrites


def _hosts(text: str, old: str, new: str) -> str:
    lines = []
    for line in text.splitlines(keepends=True):
        body, hash_, comment = line.partition("#")
        words = re.split(r"(\s+)", body)
        renamed = []
        for word in words:
            if word == old:
                renamed.append(new)
            elif word.startswith(f"{old}."):
                renamed.append(new + word[len(old) :])
            else:
                renamed.append(word)
        lines.append("".join(renamed) + hash_ + comment)
    return "".join(lines)


def _keepalived_test(text: str, address: str, vip: str) -> tuple[str, list[tuple[str, str]]]:
    changes: list[tuple[str, str]] = []

    def source_ip(matched: re.Match[str]) -> str:
        changes.append(("unicast_src_ip", matched.group(2)))
        return f"{matched.group(1)}{address}"

    text = re.sub(r"^([ \t]*unicast_src_ip[ \t]+)(\S+)", source_ip, text, flags=re.MULTILINE)

    included = re.compile(
        rf"^[ \t]*include[ \t]+{re.escape(KEEPALIVED_ADDRESSES)}[ \t]*$", re.MULTILINE
    )

    def addresses(matched: re.Match[str]) -> str:
        #
        # The include may sit inside the block itself. Said as its own change,
        # as it is when it stands outside, rather than as the block's old text.
        #
        body = matched.group(2)
        if included.search(body):
            changes.append(("include", KEEPALIVED_ADDRESSES))
            body = included.sub("", body)
        changes.append(("virtual_ipaddress", " ".join(body.split()) or "(none)"))
        indent = matched.group(1)
        return f"{indent}virtual_ipaddress {{\n{indent}    {vip}\n{indent}}}"

    text = re.sub(
        r"^([ \t]*)virtual_ipaddress[ \t]*\{([^}]*)\}", addresses, text, flags=re.MULTILINE
    )
    if included.search(text):
        changes.append(("include", KEEPALIVED_ADDRESSES))
        text = re.sub(
            rf"^[ \t]*include[ \t]+{re.escape(KEEPALIVED_ADDRESSES)}[ \t]*\n",
            "",
            text,
            flags=re.MULTILINE,
        )
    return text, changes


def build(
    source: RestoreSource, mode: Mode, target: Target, profile: TestProfile | None = None
) -> RestorePlan:
    if mode not in MODES:
        raise PlanError(f"{mode!r} is not a restore mode")
    if (mode == "test") != (profile is not None):
        raise PlanError("a test profile is required in test mode and refused otherwise")
    if not MAC.fullmatch(target.mac):
        raise PlanError(f"the target reported an unusable MAC address: {target.mac!r}")

    network, address, rewrites = _network(source, target, profile)
    hostname = source.hostname if profile is None else profile.hostname

    files: list[PlannedFile] = []
    left_out: list[str] = []
    from_bundle: list[str] = []
    root_keys: PlannedFile | None = None
    for entry in source.owned():
        if entry.path == NETPLAN_DIR or entry.path.startswith(f"{NETPLAN_DIR}/"):
            continue
        if _targets_own(entry.path, source.extra_paths):
            if entry.kind != "directory":
                left_out.append(entry.path)
            continue
        if not _under(entry.path, source.extra_paths) and (
            entry.path in FROM_BUNDLE or _under(entry.path, (SCRIPT_DIR,))
        ):
            from_bundle.append(entry.path)
            continue
        if entry.path == ROOT_KEYS:
            root_keys = _planned(entry)
            continue
        if profile is not None and entry.path.startswith(HOST_KEY_PREFIX):
            # The test node keeps the host keys it was installed with - the ones
            # the operator compared in the preview - so it is never mistaken
            # for the archived node by anything that trusts that node's key.
            continue
        data: bytes | None = None
        if profile is not None and entry.kind == "file":
            if entry.path == "/etc/hostname":
                data = f"{hostname}\n".encode()
                rewrites.append(Rewrite(entry.path, "hostname", source.hostname, hostname))
            elif entry.path == "/etc/hosts":
                data = _hosts(_text(source, entry), source.hostname, hostname).encode()
                rewrites.append(Rewrite(entry.path, "hostname", source.hostname, hostname))
            elif entry.path == KEEPALIVED_CONF:
                text, changes = _keepalived_test(
                    _text(source, entry), str(profile.address.ip), str(profile.vip)
                )
                data = text.encode()
                for name, old in changes:
                    new = {
                        "unicast_src_ip": str(profile.address.ip),
                        "virtual_ipaddress": str(profile.vip),
                        "include": "(removed)",
                    }[name]
                    rewrites.append(Rewrite(entry.path, name, old, new))
            elif entry.path == KEEPALIVED_ADDRESSES:
                old = ", ".join(
                    line.split("#", 1)[0].strip()
                    for line in _text(source, entry).splitlines()
                    if line.split("#", 1)[0].strip()
                )
                data = f"{profile.vip}\n".encode()
                rewrites.append(Rewrite(entry.path, "addresses", old, str(profile.vip)))
        files.append(_planned(entry, data))

    if root_keys is None:
        raise PlanError(f"the archive has no {ROOT_KEYS}; the one-time key would stay behind")

    #
    # Only for a target this can serve: an unsupported one is a problem the
    # preview names, with the rest of the plan shown, rather than no plan.
    #
    if mode == "overwrite":
        return _overwrite(
            source,
            target,
            RestorePlan(
                mode=mode,
                source_hostname=source.hostname,
                hostname=hostname,
                address=address,
                files=tuple(files),
                equal_directories=PRODUCT_DIRECTORIES,
                left_out=tuple(left_out),
                from_bundle=tuple(from_bundle),
                traffic_log=source.entry(TRAFFIC_LOG_RULE) is not None,
                parents=source.parents(),
                network=network,
                root_keys=root_keys,
                groups=source.groups,
                accounts=source.accounts,
                packages=tuple(p for p in PRODUCT_PACKAGES if p not in target.installed),
                keepalived="start",
                rewrites=tuple(rewrites),
            ),
        )

    if haproxy_repository.supported(target.os_release):
        try:
            branch = haproxy_repository.branch_of(source.haproxy_version)
            written = haproxy_repository.repository_files(target.os_release, branch)
        except haproxy_repository.RepositoryError as exc:
            raise PlanError(str(exc)) from exc
        files.extend(
            PlannedFile(path=item.path, kind="file", mode=0o644, uid=0, gid=0, data=item.data)
            for item in written
        )

    return RestorePlan(
        mode=mode,
        source_hostname=source.hostname,
        hostname=hostname,
        address=address,
        files=tuple(files),
        #
        # A new VM has nothing of its own in the product's directories to set
        # aside, and the directories it shares with the image keep the image's
        # files (B178). Overwrite node (B172) is what will fill this.
        #
        equal_directories=(),
        left_out=tuple(left_out),
        from_bundle=tuple(from_bundle),
        traffic_log=source.entry(TRAFFIC_LOG_RULE) is not None,
        parents=source.parents(),
        network=network,
        root_keys=root_keys,
        groups=source.groups,
        accounts=source.accounts,
        packages=PRODUCT_PACKAGES,
        keepalived="mask" if profile is not None else "start",
        rewrites=tuple(rewrites),
    )


def _digest(source: RestoreSource, file: PlannedFile) -> str | None:
    if file.kind != "file":
        return None
    data = (
        file.data if file.data is not None else content(source, file.entry) if file.entry else b""
    )
    return hashlib.sha256(data).hexdigest()


def _overwrite(source: RestoreSource, target: Target, plan: RestorePlan) -> RestorePlan:
    """What an overwrite changes on the node, from what the node said it holds (B183).

    The node's software stays its own: no repository file is planned, and only
    the product packages it lacks are. A file counts as changed when its
    contents differ or the node does not have it; a directory or link is
    written as planned and not counted. Netplan is written only when the
    node's differs from the archive's, bound to the node's MAC.
    """

    changed: list[str] = []
    unchanged = 0
    for file in (*plan.files, *((plan.root_keys,) if plan.root_keys else ())):
        digest = _digest(source, file)
        if digest is None:
            continue
        if target.hashes.get(file.path) == digest:
            unchanged += 1
        else:
            changed.append(file.path)

    planned_netplan = {file.path: _digest(source, file) for file in plan.network}
    live_netplan = {
        path: target.hashes.get(path)
        for path in target.listing.get(NETPLAN_DIR, ())
        if path.endswith((".yaml", ".yml"))
    }
    network_unchanged = planned_netplan == live_netplan
    if not network_unchanged:
        changed.extend(sorted(set(planned_netplan) | set(live_netplan)))

    # What moves is the topmost path not kept; what is under it moves with it.
    keep = {file.path for file in plan.files} | set(plan.from_bundle)
    # 04-node-prepare's `.replaced-` copies are the node's history and stay (B178).
    moving = sorted(
        path
        for directory in plan.equal_directories
        for path in target.listing.get(directory, ())
        if path not in keep
        and not REPLACED.search(path)
        and not any(k.startswith(f"{path}/") for k in keep)
    )
    quarantined = [
        path for path in moving if not any(path.startswith(f"{other}/") for other in moving)
    ]
    return RestorePlan(
        **{
            name: getattr(plan, name)
            for name in plan.__dataclass_fields__
            if name not in {"network", "changed", "unchanged", "quarantined", "network_unchanged"}
        },
        network=() if network_unchanged else plan.network,
        changed=tuple(changed),
        unchanged=unchanged,
        quarantined=tuple(quarantined),
        network_unchanged=network_unchanged,
    )
