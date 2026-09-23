"""Decide, before anything is written, exactly what a restore writes where.

The plan is computed on the management host from the archive, the chosen mode
and what the target reported about itself.  It is shown in full by the preview
and executed unchanged by the run, so what the operator approved and what is
written are the same object.

Two modes exist in this first delivery:

* ``new_vm`` - an empty VM becomes the archived node: its hostname, its
  address, its host keys, its keepalived role.
* ``test`` - the same, except that the node's identity on the network is
  rewritten to a test profile, field by field, and keepalived is masked so the
  node can never take part in the production cluster's VRRP.  Every rewritten
  field is listed; nothing else differs from ``new_vm``.

Two things are split off the main file set because of *when* they may be
written, not what they are: Netplan (last, under a timer that rolls it back),
and root's ``authorized_keys`` (after everything else - it removes the
one-time key the restore itself is connected with).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, Literal

import yaml

from haproxy_mgmt.restore_source import Account, Entry, Group, RestoreSource, content

Mode = Literal["new_vm", "test"]

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
PRODUCT_PACKAGES = ("haproxy", "keepalived", "rsyslog", "openssh-server", "rsync", "python3")

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
    parents: tuple[str, ...]
    network: tuple[PlannedFile, ...]
    root_keys: PlannedFile | None
    groups: tuple[Group, ...]
    accounts: tuple[Account, ...]
    packages: tuple[str, ...]
    keepalived: Literal["start", "mask"]
    rewrites: tuple[Rewrite, ...] = field(default=())

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
        }


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

    def addresses(matched: re.Match[str]) -> str:
        changes.append(("virtual_ipaddress", " ".join(matched.group(2).split())))
        indent = matched.group(1)
        return f"{indent}virtual_ipaddress {{\n{indent}    {vip}\n{indent}}}"

    text = re.sub(
        r"^([ \t]*)virtual_ipaddress[ \t]*\{([^}]*)\}", addresses, text, flags=re.MULTILINE
    )
    if re.search(
        rf"^[ \t]*include[ \t]+{re.escape(KEEPALIVED_ADDRESSES)}[ \t]*$", text, re.MULTILINE
    ):
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
    if (mode == "test") != (profile is not None):
        raise PlanError("a test profile is required in test mode and refused otherwise")
    if not MAC.fullmatch(target.mac):
        raise PlanError(f"the target reported an unusable MAC address: {target.mac!r}")

    network, address, rewrites = _network(source, target, profile)
    hostname = source.hostname if profile is None else profile.hostname

    files: list[PlannedFile] = []
    root_keys: PlannedFile | None = None
    for entry in source.owned():
        if entry.path == NETPLAN_DIR or entry.path.startswith(f"{NETPLAN_DIR}/"):
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

    equal = tuple(
        entry.path
        for entry in source.owned()
        if entry.kind == "directory" and entry.path in source.roots and entry.path != NETPLAN_DIR
    )
    return RestorePlan(
        mode=mode,
        source_hostname=source.hostname,
        hostname=hostname,
        address=address,
        files=tuple(files),
        equal_directories=equal,
        parents=source.parents(),
        network=network,
        root_keys=root_keys,
        groups=source.groups,
        accounts=source.accounts,
        packages=PRODUCT_PACKAGES,
        keepalived="mask" if profile is not None else "start",
        rewrites=tuple(rewrites),
    )
