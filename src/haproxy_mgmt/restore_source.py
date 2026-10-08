"""Read one validated node state archive as the input to a restore.

``backup_archive.validate`` says an archive is complete and matches its
manifest.  This module says what a restore would do with it: which files carry
the node's own ownership and mode, which accounts and groups must exist with
which IDs, and which of the paths are the operator's rather than the product's.

Ownership and mode come from the manifest only at an *export root* - a path the
exporter copied with ``cp -a`` - and below it.  The exporter runs under
``umask 077`` and creates every parent of a copied path with ``mkdir -p``, so
``rootfs/etc`` and ``rootfs/home`` are recorded as ``0700 root`` while the node
has ``0755``.  Applying those entries would lock ``/etc``.  A parent is
therefore only something that must exist, never something whose metadata is
restored.

Nothing is extracted to disk here.  The archive holds password hashes and
private keys; file contents are read into memory when a restore streams them to
its target, and never land anywhere on the management host.
"""

from __future__ import annotations

import json
import re
import tarfile
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from haproxy_mgmt.backup_archive import MANIFEST, ArchiveError, ArchiveFacts, validate

#
# Every literal `copy_path` argument in install/node/haproxy-state-export, in
# the exporter's order.  A contract test reads the exporter and fails when the
# two lists differ, so a path added there cannot be restored with the wrong
# metadata here without the gate noticing.
#
EXPORT_ROOTS = (
    "/etc/hostname",
    "/etc/hosts",
    "/etc/keepalived/keepalived.conf",
    "/etc/keepalived/addresses.conf",
    "/etc/keepalived/ipvs.conf",
    "/etc/default/keepalived",
    "/etc/netplan",
    "/etc/sysctl.d",
    "/etc/systemd/system/haproxy.service.d",
    "/etc/default/haproxy",
    "/etc/apt/sources.list.d",
    "/etc/apt/preferences.d",
    "/etc/apt/keyrings",
    "/etc/sudoers.d",
    "/etc/haproxy-manager",
    "/etc/ssh/sshd_config",
    "/etc/ssh/sshd_config.d",
    "/root/.ssh",
    "/etc/rsyslog.d/48-haproxy-manager-traffic.conf",
    "/etc/apparmor.d/rsyslog.d/haproxy-manager-traffic",
    "/etc/systemd/system/haproxy-traffic-log-prune.service",
    "/etc/systemd/system/haproxy-traffic-log-prune.timer",
    "/etc/systemd/system/ipvsadm.service",
    "/etc/cloud/cloud-init.disabled",
)

# The exporter's DR_SCRIPTS, each copied on its own from /usr/local/sbin.
EXPORT_SCRIPT_DIR = "/usr/local/sbin"

# `for f in /etc/ssh/ssh_host_*` - each host key file is its own root.
HOST_KEY_PREFIX = "/etc/ssh/ssh_host_"

NAME = re.compile(r"^[a-z_][a-z0-9_-]{0,31}\$?$")
MAX_META_BYTES = 256 * 1024
SERVICE_ACCOUNTS_LINE = re.compile(r'^BACKUP_SERVICE_ACCOUNTS="(?P<names>[^"$`\\]*)"$')
ID_GROUP = re.compile(r"^(?P<gid>\d+)\((?P<name>[^()]+)\)$")


@dataclass(frozen=True, slots=True)
class Entry:
    """One manifest entry, with its path on the target."""

    path: str
    kind: str
    mode: int
    uid: int
    gid: int
    member: str
    size: int = 0
    target: str | None = None


@dataclass(frozen=True, slots=True)
class Group:
    name: str
    gid: int


@dataclass(frozen=True, slots=True)
class Account:
    name: str
    uid: int
    gid: int
    gecos: str
    home: str
    shell: str
    groups: tuple[str, ...]
    password_hash: str | None
    service: bool


@dataclass(frozen=True, slots=True)
class RestoreSource:
    archive: Path
    facts: ArchiveFacts
    os_release: dict[str, str]
    groups: tuple[Group, ...]
    accounts: tuple[Account, ...]
    extra_paths: tuple[str, ...]
    roots: tuple[str, ...]
    #
    # The node's installed HAProxy, from `meta/package-versions.txt`: the
    # restored node gets the same branch (B178), from its own distribution's
    # build of it. Empty when the archive does not say.
    #
    haproxy_version: str
    entries: tuple[Entry, ...] = field(repr=False)

    @property
    def hostname(self) -> str:
        return self.facts.hostname

    def owned(self) -> Iterator[Entry]:
        """Entries whose ownership and mode the restore applies."""

        return (entry for entry in self.entries if _under(entry.path, self.roots))

    def parents(self) -> tuple[str, ...]:
        """Directories that must exist and are otherwise left as the target has them."""

        return tuple(
            entry.path
            for entry in self.entries
            if entry.kind == "directory" and not _under(entry.path, self.roots)
        )

    def entry(self, path: str) -> Entry | None:
        return next((entry for entry in self.entries if entry.path == path), None)


def _under(path: str, roots: tuple[str, ...]) -> bool:
    return any(path == root or path.startswith(f"{root}/") for root in roots)


def _text(archive: tarfile.TarFile, name: str, *, required: bool = True) -> str:
    try:
        member = archive.getmember(name)
    except KeyError:
        if required:
            raise ArchiveError(f"the archive has no {name}") from None
        return ""
    stream = archive.extractfile(member)
    if stream is None:
        raise ArchiveError(f"the archive cannot read {name}")
    raw = stream.read(MAX_META_BYTES + 1)
    if len(raw) > MAX_META_BYTES:
        raise ArchiveError(f"{name} is larger than a restore reads")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ArchiveError(f"{name} is not UTF-8") from exc


def _lines(text: str) -> list[str]:
    return [line for line in text.splitlines() if line.strip()]


def _name(value: str, what: str) -> str:
    if not NAME.fullmatch(value):
        raise ArchiveError(f"the archive names an unusable {what}: {value!r}")
    return value


def _number(value: str, what: str) -> int:
    if not value.isdigit() or len(value) > 10:
        raise ArchiveError(f"the archive has an unusable {what}: {value!r}")
    return int(value)


def _absolute(value: str, what: str) -> str:
    path = PurePosixPath(value)
    if not path.is_absolute() or ".." in path.parts or "\n" in value or ":" in value:
        raise ArchiveError(f"the archive has an unusable {what}: {value!r}")
    return path.as_posix()


def os_release(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in _lines(text):
        key, separator, value = line.partition("=")
        if not separator or not key.isidentifier():
            continue
        values[key] = value.strip().strip('"').strip("'")
    return values


def _groups(text: str) -> tuple[Group, ...]:
    groups: list[Group] = []
    for line in _lines(text):
        fields = line.split(":")
        if len(fields) != 4:
            raise ArchiveError("meta/group-definitions.txt has a malformed line")
        groups.append(Group(_name(fields[0], "group"), _number(fields[2], "GID")))
    names = [group.name for group in groups]
    if len(set(names)) != len(names):
        raise ArchiveError("meta/group-definitions.txt defines a group twice")
    return tuple(groups)


def _memberships(text: str) -> dict[str, tuple[str, ...]]:
    """`id <user>` lines: uid=1000(ops) gid=1000(ops) groups=1000(ops),27(sudo)."""

    memberships: dict[str, tuple[str, ...]] = {}
    for line in _lines(text):
        fields = dict(part.split("=", 1) for part in line.split() if "=" in part)
        user = ID_GROUP.fullmatch(fields.get("uid", ""))
        if user is None:
            raise ArchiveError("meta/groups.txt has a malformed line")
        names: list[str] = []
        for item in filter(None, fields.get("groups", "").split(",")):
            group = ID_GROUP.fullmatch(item)
            if group is None:
                raise ArchiveError("meta/groups.txt has a malformed group")
            names.append(_name(group.group("name"), "group"))
        memberships[_name(user.group("name"), "account")] = tuple(names)
    return memberships


def _hashes(text: str) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for line in _lines(text):
        fields = line.split(":")
        if len(fields) != 9:
            raise ArchiveError("meta/shadow.txt has a malformed line")
        hashes[_name(fields[0], "account")] = fields[1]
    return hashes


def _service_accounts(node_conf: str) -> frozenset[str]:
    for line in node_conf.splitlines():
        matched = SERVICE_ACCOUNTS_LINE.fullmatch(line.strip())
        if matched is not None:
            return frozenset(_name(name, "account") for name in matched.group("names").split())
    raise ArchiveError("node.conf in the archive does not name BACKUP_SERVICE_ACCOUNTS")


def _accounts(
    users: str,
    memberships: dict[str, tuple[str, ...]],
    hashes: dict[str, str],
    services: frozenset[str],
) -> tuple[Account, ...]:
    accounts: list[Account] = []
    for line in _lines(users):
        fields = line.split(":")
        if len(fields) != 7:
            raise ArchiveError("meta/users.txt has a malformed line")
        name = _name(fields[0], "account")
        accounts.append(
            Account(
                name=name,
                uid=_number(fields[2], "UID"),
                gid=_number(fields[3], "GID"),
                gecos=fields[4],
                home=_absolute(fields[5], "home directory"),
                shell=_absolute(fields[6], "shell"),
                groups=memberships.get(name, ()),
                password_hash=hashes.get(name),
                service=name in services,
            )
        )
    names = [account.name for account in accounts]
    if len(set(names)) != len(names):
        raise ArchiveError("meta/users.txt lists an account twice")
    missing = sorted(services - set(names))
    if missing:
        raise ArchiveError(f"the archive has no account line for service account {missing[0]}")
    return tuple(accounts)


def _entries(document: Any) -> tuple[Entry, ...]:
    entries: list[Entry] = []
    for raw in document["entries"]:
        name = raw["path"]
        if not name.startswith("rootfs/"):
            continue
        entries.append(
            Entry(
                path="/" + name.removeprefix("rootfs/"),
                kind=raw["type"],
                mode=raw["mode"],
                uid=raw["uid"],
                gid=raw["gid"],
                member=name,
                size=raw.get("size", 0),
                target=raw.get("target"),
            )
        )
    return tuple(entries)


def _roots(
    entries: tuple[Entry, ...], accounts: tuple[Account, ...], extra: tuple[str, ...]
) -> tuple[str, ...]:
    present = {entry.path for entry in entries}
    candidates = [*EXPORT_ROOTS, *extra, *(f"{account.home}/.ssh" for account in accounts)]
    candidates += [
        path
        for path in sorted(present)
        if (path.startswith(HOST_KEY_PREFIX) and "/" not in path.removeprefix("/etc/ssh/"))
        or (path.startswith(f"{EXPORT_SCRIPT_DIR}/") and path.count("/") == 4)
    ]
    return tuple(dict.fromkeys(path for path in candidates if path in present))


def _version(text: str, package: str) -> str:
    for line in _lines(text):
        name, _tab, version = line.partition("\t")
        if name.split(":", 1)[0] == package:
            return version.strip()
    return ""


def read(path: Path) -> RestoreSource:
    """Validate the archive and read it as a restore's input."""

    facts = validate(path)
    try:
        archive = tarfile.open(path, mode="r:gz")  # noqa: SIM115
    except (OSError, tarfile.TarError) as exc:
        raise ArchiveError("the state export is not a readable tar.gz archive") from exc
    with archive:
        document = json.loads(_text(archive, MANIFEST, required=True))
        entries = _entries(document)
        extra = tuple(
            _absolute(line.strip(), "extra path")
            for line in _lines(_text(archive, "meta/extra-paths.txt", required=False))
        )
        hashes = _hashes(_text(archive, "meta/shadow.txt"))
        accounts = _accounts(
            _text(archive, "meta/users.txt"),
            _memberships(_text(archive, "meta/groups.txt")),
            hashes,
            _service_accounts(_text(archive, "rootfs/etc/haproxy-manager/node.conf")),
        )
        return RestoreSource(
            archive=path,
            facts=facts,
            os_release=os_release(_text(archive, "meta/os-release")),
            groups=_groups(_text(archive, "meta/group-definitions.txt")),
            accounts=accounts,
            extra_paths=extra,
            roots=_roots(entries, accounts, extra),
            haproxy_version=_version(_text(archive, "meta/package-versions.txt"), "haproxy"),
            entries=entries,
        )


def content(source: RestoreSource, entry: Entry) -> bytes:
    """One regular file's bytes, read on demand from the archive."""

    if entry.kind != "file":
        raise ValueError(f"{entry.path} is not a regular file")
    with tarfile.open(source.archive, mode="r:gz") as archive:
        stream = archive.extractfile(entry.member)
        if stream is None:
            raise ArchiveError(f"the archive cannot read {entry.member}")
        return stream.read()
