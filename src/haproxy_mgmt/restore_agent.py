"""The half of a node restore that runs on the target, as root, over SSH.

The management host sends this file's source with every session and runs it
with the target's own ``python3``; nothing is installed on the target first.  It
therefore uses the standard library only and imports nothing from this package.

Each session is one operation.  Stdin carries one JSON header line and, for the
operations that write, a tar stream of the files to place.  Stdout carries one
JSON result document; stderr carries progress lines for the operator's log.

``inspect``  reads: OS, interface, host key, accounts.  Writes nothing.
``apply``    groups and accounts with the archive's IDs, password hashes where
             an account has none (B173), APT sources and the product's
             packages, the files, the
             HAProxy release layout, the service states, the hostname - then
             the release's node bundle: its 04-node-prepare with answers
             derived from the archive, and the traffic log if it was on.
``network``  Netplan, under a timer that puts the previous Netplan back unless
             the next session cancels it from the node's new address.
``finish``   cancels that timer, pulls configuration and certificates the way
             a deploy does, starts the services, and writes root's
             ``authorized_keys`` last - which removes the one-time key this
             restore is connected with.

Every check an operation makes happens before its first write.  A directory the
plan names in ``equal_directories`` is made equal to the archive; what was there
and is not in the archive is moved to a quarantine directory, never deleted.  A
new VM's plan names none (B178): the product's files are written beside the
target's own.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import IO, Any

STATE = "/var/lib/haproxy-restore"
#
# The packages whose presence means the VM is not empty. A restore installs
# them itself with their services held off; one already there has run with the
# package's defaults and owns accounts made with whatever IDs were free.
# rsyslog and openssh-server are not here: every image has them.
#
NOT_EMPTY_IF_INSTALLED = ("haproxy", "keepalived")
NETPLAN = "/etc/netplan"
ROOT_KEYS = "/root/.ssh/authorized_keys"
POLICY_RC = "/usr/sbin/policy-rc.d"
NODE_CONF = "/etc/haproxy-manager/node.conf"
#
# The release's node bundle (B180), sent in the apply payload at this name in
# the run's own directory, and extracted beside it. Its 04-node-prepare writes
# what the product owns on a node, in the running release's version.
#
BUNDLE_FILE = "node-bundle.tar.gz"
BUNDLE_ROOT = re.compile(r"^haproxy-manager-node-[0-9a-f]{12}$")
CLUSTER_ID = re.compile(r"^[a-z0-9][a-z0-9_]{0,31}$")
#
# Turns the traffic log on in the release's version: the rsyslog rule, the
# AppArmor snippet and the retention timer, enabled. Run when the archive
# shows the log was on; the archive's own copies are not written.
#
TRAFFIC_LOG_ENABLE = "/usr/local/sbin/haproxy-traffic-log-enable"
HAPROXY = "/etc/haproxy"
EMPTY_RELEASE = "00000000-000000"
BOOTSTRAP_SOCKET = "/run/haproxy-restore-bootstrap.sock"
#
# The release `current` points at until the first deploy. 04-node-prepare
# leaves an empty haproxy.cfg there, and on a fresh node that is a dead end:
# `haproxy -c` answers 2 on a configuration without a listener, so cert-pull
# refuses to validate against it, and HAProxy will not start on it, so neither
# script can reload. The published configuration names its certificates by
# absolute path, so it cannot be validated before they are there either.
# One listener on a root-only unix socket breaks the circle: HAProxy runs,
# cert-pull validates and reloads, pull-deploy replaces the release. Nothing
# can reach it, and it is gone with the first deploy.
#
BOOTSTRAP_CONFIG = f"""# Written by a node restore. Replaced by the first deploy.
defaults
    mode tcp
    timeout connect 5s
    timeout client 30s
    timeout server 30s

frontend restore-bootstrap
    bind unix@{BOOTSTRAP_SOCKET} mode 600
"""
HOSTNAME = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
APT_DIRECTORIES = ("/etc/apt/sources.list.d", "/etc/apt/preferences.d", "/etc/apt/keyrings")
#
# `apt-get update` against the distribution's own mirrors: three tries, and
# APT's own retries inside each. A mirror caught mid-sync answers with a hash
# mismatch for a while and then does not (seen on security.ubuntu.com
# 2026-09-24, for an AppStream index no package install reads).
#
APT_UPDATE_TRIES = 3
APT_UPDATE_PAUSE = 20.0
FETCH_FAILED = re.compile(r"^(?:Err:\d+|E: Failed to fetch)\s+(\S+)", re.MULTILINE)
RUN_ID = re.compile(r"^[a-z0-9][a-z0-9-]{7,39}$")
NAME = re.compile(r"^[a-z_][a-z0-9_-]{0,31}\$?$")
CERTIFICATE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,254}$")
MAX_HEADER = 1024 * 1024
MAX_PAYLOAD = 64 * 1024 * 1024
ENVIRONMENT = {
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG": "C.UTF-8",
    "DEBIAN_FRONTEND": "noninteractive",
}


class Refused(RuntimeError):
    """The target is not in a state this operation may write to."""


class Failed(RuntimeError):
    """A step that had begun writing did not complete."""


def log(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


class Host:
    """The target machine.  Tests replace it with a directory and a recorder."""

    def __init__(self, root: str = "/") -> None:
        self.root = Path(root)

    def path(self, path: str) -> Path:
        return self.root / path.lstrip("/")

    def run(
        self, argv: list[str], *, stdin: str | None = None, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        completed = subprocess.run(  # noqa: S603 - fixed argv built by this agent
            argv,
            input=stdin,
            capture_output=True,
            text=True,
            check=False,
            env=ENVIRONMENT,
            timeout=900,
        )
        if check and completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).strip().splitlines()[-5:]
            raise Failed(
                f"{' '.join(argv[:3])} exited {completed.returncode}: {' / '.join(detail)}"
            )
        return completed

    def chown(self, path: Path, uid: int, gid: int) -> None:
        os.lchown(path, uid, gid)


# --------------------------------------------------------------------------
# Reading the target
# --------------------------------------------------------------------------


def _colon_file(host: Host, path: str) -> list[list[str]]:
    target = host.path(path)
    if not target.exists():
        return []
    return [line.split(":") for line in target.read_text(encoding="utf-8").splitlines() if line]


def local_accounts(host: Host) -> dict[str, tuple[int, int, str]]:
    """Each account in /etc/passwd: UID, GID and home. No password is in that file."""

    return {
        fields[0]: (int(fields[2]), int(fields[3]), fields[5])
        for fields in _colon_file(host, "/etc/passwd")
        if len(fields) >= 7
    }


def groups(host: Host) -> dict[str, int]:
    return {
        fields[0]: int(fields[2]) for fields in _colon_file(host, "/etc/group") if len(fields) >= 3
    }


def usable_password(host: Host) -> dict[str, bool]:
    return {
        fields[0]: bool(fields[1]) and fields[1][0] not in "!*"
        for fields in _colon_file(host, "/etc/shadow")
        if len(fields) >= 2
    }


def os_release(host: Host) -> dict[str, str]:
    values: dict[str, str] = {}
    target = host.path("/etc/os-release")
    if target.exists():
        for line in target.read_text(encoding="utf-8").splitlines():
            key, separator, value = line.partition("=")
            if separator and key.isidentifier():
                values[key] = value.strip().strip('"').strip("'")
    return values


def _interface(host: Host) -> dict[str, Any]:
    route = json.loads(host.run(["ip", "-j", "route", "show", "default"]).stdout or "[]")
    if len(route) != 1 or "dev" not in route[0]:
        raise Refused("the target does not have exactly one default route")
    device = route[0]["dev"]
    link = json.loads(host.run(["ip", "-j", "link", "show", "dev", device]).stdout)[0]
    addresses = json.loads(host.run(["ip", "-j", "-4", "addr", "show", "dev", device]).stdout)
    return {
        "name": device,
        "mac": str(link.get("address", "")).lower(),
        "addresses": [
            f"{item['local']}/{item['prefixlen']}"
            for entry in addresses
            for item in entry.get("addr_info", [])
        ],
    }


def _fingerprints(host: Host) -> dict[str, str]:
    prints: dict[str, str] = {}
    for kind in ("ed25519", "ecdsa", "rsa"):
        public = f"/etc/ssh/ssh_host_{kind}_key.pub"
        if host.path(public).exists():
            output = host.run(["ssh-keygen", "-lf", public]).stdout.split()
            if len(output) >= 2:
                prints[kind] = output[1]
    return prints


def installed(host: Host, packages: tuple[str, ...]) -> list[str]:
    """Which of these packages dpkg says are installed; unknown ones are not."""

    listed = host.run(
        ["dpkg-query", "-W", "-f", "${Package}\t${db:Status-Status}\n", *packages], check=False
    ).stdout
    rows = (line.split("\t", 1) for line in listed.splitlines() if "\t" in line)
    return sorted(name for name, status in rows if status == "installed")


def network_managers(host: Host) -> dict[str, list[str]]:
    """What configures the network here: Netplan's files, and interfaces ifupdown brings up.

    A restore writes the network as Netplan. A VM whose interfaces ifupdown
    configures - a Debian installed from its installer rather than a cloud
    image - would have both after the restore, each configuring the interface.
    """

    netplan = host.path(NETPLAN)
    files = sorted(p.name for p in netplan.glob("*.yaml")) if netplan.is_dir() else []
    sources = [host.path("/etc/network/interfaces")]
    directory = host.path("/etc/network/interfaces.d")
    if directory.is_dir():
        sources.extend(sorted(p for p in directory.iterdir() if p.is_file()))
    interfaces: set[str] = set()
    for source in sources:
        if not source.is_file():
            continue
        for line in source.read_text(encoding="utf-8", errors="replace").splitlines():
            words = line.split("#", 1)[0].split()
            if len(words) >= 2 and words[0] == "iface" and words[1] != "lo":
                interfaces.add(words[1])
    return {"netplan": files, "ifupdown": sorted(interfaces)}


def inspect(host: Host, header: dict[str, Any], _payload: IO[bytes]) -> dict[str, Any]:
    names = set(header.get("names", []))
    ids = set(header.get("ids", []))
    users = local_accounts(host)
    return {
        "os_release": os_release(host),
        "hostname": host.path("/etc/hostname").read_text(encoding="utf-8").strip()
        if host.path("/etc/hostname").exists()
        else "",
        "interface": _interface(host),
        "host_keys": _fingerprints(host),
        "accounts": {
            name: list(value[:2])
            for name, value in users.items()
            if name in names or value[0] in ids
        },
        "groups": {name: gid for name, gid in groups(host).items() if name in names or gid in ids},
        "previous_restore": host.path(STATE).exists(),
        "installed": installed(host, NOT_EMPTY_IF_INSTALLED),
        "network": network_managers(host),
    }


# --------------------------------------------------------------------------
# The payload
# --------------------------------------------------------------------------


@dataclass(slots=True)
class Item:
    path: str
    kind: str
    mode: int
    uid: int
    gid: int
    data: bytes = b""
    link: str = ""


def _clean(name: str) -> str:
    path = PurePosixPath("/" + name.lstrip("/"))
    if ".." in path.parts or name.startswith("//"):
        raise Refused(f"the payload names an unsafe path: {name!r}")
    return path.as_posix()


def read_payload(stream: IO[bytes]) -> list[Item]:
    raw = stream.read(MAX_PAYLOAD + 1)
    if len(raw) > MAX_PAYLOAD:
        raise Refused("the payload is larger than a restore carries")
    if not raw:
        return []
    items: list[Item] = []
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        for member in archive.getmembers():
            path = _clean(member.name)
            if member.isdir():
                kind, data, link = "directory", b"", ""
            elif member.issym():
                kind, data, link = "symlink", b"", member.linkname
            elif member.isfile():
                source = archive.extractfile(member)
                if source is None:
                    raise Refused(f"the payload cannot read {path}")
                kind, data, link = "file", source.read(), ""
            else:
                raise Refused(f"the payload has an unsupported entry at {path}")
            items.append(Item(path, kind, member.mode & 0o7777, member.uid, member.gid, data, link))
    return items


# --------------------------------------------------------------------------
# Writing
# --------------------------------------------------------------------------


@dataclass(slots=True)
class Report:
    steps: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def step(self, name: str, **detail: Any) -> None:
        self.steps.append({"step": name, **detail})
        log(f"[{name}] " + ", ".join(f"{key}={value}" for key, value in detail.items()))


def _ensure_parents(host: Host, path: str) -> None:
    """Create a missing parent as root 0755; an existing one is left exactly as it is."""

    missing: list[Path] = []
    parent = host.path(path).parent
    while not parent.exists() and parent != host.root:
        missing.append(parent)
        parent = parent.parent
    for directory in reversed(missing):
        directory.mkdir(mode=0o755)
        directory.chmod(0o755)
        host.chown(directory, 0, 0)


def place(host: Host, item: Item) -> None:
    target = host.path(item.path)
    _ensure_parents(host, item.path)
    if item.kind == "directory":
        if target.is_symlink() or (target.exists() and not target.is_dir()):
            raise Failed(f"{item.path} exists and is not a directory")
        target.mkdir(mode=0o700, exist_ok=True)
        host.chown(target, item.uid, item.gid)
        target.chmod(item.mode)
        return
    if target.is_dir() and not target.is_symlink():
        raise Failed(f"{item.path} is a directory on the target and a file in the archive")
    descriptor, temporary = tempfile.mkstemp(dir=target.parent, prefix=".restore-")
    os.close(descriptor)
    staged = Path(temporary)
    try:
        if item.kind == "symlink":
            staged.unlink()
            staged.symlink_to(item.link)
        else:
            staged.write_bytes(item.data)
            staged.chmod(item.mode)
        host.chown(staged, item.uid, item.gid)
        if item.kind == "file":
            staged.chmod(item.mode)
        staged.replace(target)
    except BaseException:
        if staged.exists() or staged.is_symlink():
            staged.unlink()
        raise


def quarantine(
    host: Host, directory: str, keep: Iterable[str], run: str, report: Report
) -> list[str]:
    """Move what is in `directory` and not in `keep` aside; return what moved."""

    base = host.path(directory)
    if not base.is_dir() or base.is_symlink():
        return []
    kept = set(keep)
    ancestors = {str(PurePosixPath(path).parent) for path in kept}
    while True:
        more = {str(PurePosixPath(path).parent) for path in ancestors} - ancestors
        if not more:
            break
        ancestors |= more
    moved: list[str] = []
    for current, subdirectories, files in os.walk(base, topdown=True):
        relative = "/" + str(Path(current).relative_to(host.root))
        for name in sorted([*files, *subdirectories]):
            path = f"{relative.rstrip('/')}/{name}"
            if path in kept or path in ancestors:
                continue
            destination = host.path(f"{STATE}/{run}/quarantine{path}")
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            shutil.move(str(host.path(path)), destination)
            moved.append(path)
        subdirectories[:] = [
            name for name in subdirectories if f"{relative.rstrip('/')}/{name}" in kept | ancestors
        ]
    if moved:
        report.step("quarantine", directory=directory, moved=len(moved))
    return moved


# --------------------------------------------------------------------------
# apply
# --------------------------------------------------------------------------


def _conflicts(header: dict[str, Any]) -> list[str]:
    """What stops apply before it writes: an account whose group the archive does not name.

    Numbers taken on the target stop nothing (B181): an account or group is
    its name, and the number follows the target - see ``_accounts``.
    """

    problems: list[str] = []
    named = {group["gid"] for group in header["groups"]} | {0}
    for account in header["accounts"]:
        if account["gid"] not in named:
            problems.append(
                f"account {account['name']} has primary GID {account['gid']}, "
                "which no group in the archive has"
            )
    return problems


def _bundle_path(run: str) -> str:
    return f"{STATE}/{run}/{BUNDLE_FILE}"


def _validate_apply(header: dict[str, Any], items: list[Item]) -> Item:
    """Everything apply checks before its first write; answers the node bundle."""

    for record in (*header["groups"], *header["accounts"]):
        if not NAME.fullmatch(str(record.get("name", ""))):
            raise Refused("the header names an unusable account or group")
    wanted = _bundle_path(header["run"])
    bundle: Item | None = None
    for item in items:
        if item.path == ROOT_KEYS or item.path == NETPLAN or item.path.startswith(f"{NETPLAN}/"):
            raise Refused(f"{item.path} is written by a later session, not by apply")
        if item.path == wanted and item.kind == "file":
            bundle = item
        elif item.path == STATE or item.path.startswith(f"{STATE}/"):
            raise Refused(f"{item.path} is this restore's own directory, not a file to place")
    described = header.get("node_bundle")
    if bundle is None or not isinstance(described, dict):
        raise Refused("the payload carries no node bundle")
    if not BUNDLE_ROOT.fullmatch(str(described.get("root", ""))):
        raise Refused("the node bundle's root is not usable")
    if hashlib.sha256(bundle.data).hexdigest() != described.get("sha256"):
        raise Refused("the node bundle does not match the digest the manager sent")
    if not CLUSTER_ID.fullmatch(str(header.get("cluster", ""))):
        raise Refused("the cluster ID is not usable")
    if not isinstance(header.get("answers"), str) or "\0" in header["answers"]:
        raise Refused("the answers for the node bundle are not usable")
    if header["keepalived"] not in {"start", "mask"}:
        raise Refused("keepalived must be started or masked")
    if not HOSTNAME.fullmatch(header["hostname"]):
        raise Refused("the hostname is not usable")
    return bundle


def _node_bundle(
    host: Host, header: dict[str, Any], bundle: Item, items: list[Item], report: Report
) -> None:
    """Run the release's 04-node-prepare on the node, with answers from its archive."""

    work = host.path(f"{STATE}/{header['run']}/node-bundle")
    work.mkdir(parents=True, exist_ok=True, mode=0o700)
    work.chmod(0o700)
    with tarfile.open(fileobj=io.BytesIO(bundle.data), mode="r:gz") as archive:
        archive.extractall(work, filter="data")
    install = work / header["node_bundle"]["root"] / "install"
    if not (install / "04-node-prepare").is_file():
        raise Failed("the node bundle has no install/04-node-prepare")
    answers = work / "answers.env"
    answers.write_text(header["answers"], encoding="utf-8")
    answers.chmod(0o600)
    prepared = host.run(["bash", str(install / "04-node-prepare"), str(answers), header["cluster"]])
    #
    # 04-node-prepare writes one warning over several `warn` calls, each line
    # after the first indented: "WARNING:   does not always ...". Those are
    # joined onto the line before, so a warning reads as the sentence it is.
    #
    warnings: list[str] = []
    for line in prepared.stderr.splitlines():
        if not line.startswith("WARNING:"):
            continue
        text = line.removeprefix("WARNING:")
        if warnings and text.startswith("  "):
            warnings[-1] += " " + text.strip()
        else:
            warnings.append(text.strip())
    report.warnings += [f"node preparation: {line}" for line in warnings]
    report.step("node-bundle", root=header["node_bundle"]["root"], warnings=len(warnings))

    #
    # 04-node-prepare renders node.conf from the answers derived from the
    # archived one, and a test holds the two to the same bytes. An archive
    # from an older template can still differ; its copy is kept beside it.
    #
    archived = next((item for item in items if item.path == NODE_CONF), None)
    written = host.path(NODE_CONF)
    if (
        archived is not None
        and written.is_file()
        and written.read_bytes().rstrip(b"\n") != archived.data.rstrip(b"\n")
    ):
        report.warnings.append(
            f"{NODE_CONF} was rendered differently from the archive's; "
            "the archive's is kept as node.conf.replaced-<time>"
        )

    if header.get("traffic_log"):
        host.run([TRAFFIC_LOG_ENABLE])
        report.step("traffic-log", enabled=True)


def _packages(host: Host, header: dict[str, Any], items: list[Item], report: Report) -> None:
    apt = [item for item in items if item.path.startswith(APT_DIRECTORIES)]
    for directory in APT_DIRECTORIES:
        if directory in header["equal_directories"]:
            quarantine(host, directory, [i.path for i in items], header["run"], report)
    for item in sorted(apt, key=lambda i: (i.path.count("/"), i.path)):
        place(host, item)
    report.step("apt-sources", files=len([i for i in apt if i.kind == "file"]))

    # Packages start their services on install unless told otherwise. Nothing
    # may run before its configuration is in place: keepalived with the image's
    # defaults is not a harmless keepalived.
    policy = host.path(POLICY_RC)
    policy.write_text("#!/bin/sh\nexit 101\n", encoding="utf-8")
    policy.chmod(0o755)
    try:
        _update(host, _required_uris(apt), report)
        host.run(
            [
                "apt-get",
                "install",
                "-y",
                "-o",
                "Dpkg::Options::=--force-confdef",
                "-o",
                "Dpkg::Options::=--force-confold",
                *header["packages"],
            ]
        )
    finally:
        policy.unlink(missing_ok=True)
    versions = host.run(
        ["dpkg-query", "-W", "-f", "${Package}\t${Version}\n", *header["packages"]], check=False
    ).stdout
    report.step(
        "packages",
        installed=dict(line.split("\t", 1) for line in versions.splitlines() if "\t" in line),
    )


def _required_uris(apt: list[Item]) -> tuple[str, ...]:
    """The URIs of the deb822 sources this restore placed: the HAProxy repository."""

    uris: list[str] = []
    for item in apt:
        if item.kind != "file" or not item.path.endswith(".sources"):
            continue
        for line in item.data.decode("utf-8", "replace").splitlines():
            if line.startswith("URIs:"):
                uris.extend(uri.rstrip("/") for uri in line.split()[1:])
    return tuple(uris)


def _update(
    host: Host,
    required: tuple[str, ...],
    report: Report,
    *,
    tries: int = APT_UPDATE_TRIES,
    pause: float = APT_UPDATE_PAUSE,
    sleep: Callable[[float], None] = time.sleep,
) -> None:
    """`apt-get update`, tried again, and let through when only other indexes failed.

    The HAProxy repository's index must arrive: without it APT installs the
    distribution's own, older HAProxy and says nothing. An index of the
    distribution's that still fails after the tries is a warning - the install
    that follows fails by itself if a package it needs really cannot be had.
    """

    argv = ["apt-get", "-o", "Acquire::Retries=3", "update"]
    for attempt in range(1, tries + 1):
        completed = host.run(argv, check=False)
        if completed.returncode == 0:
            return
        if attempt < tries:
            sleep(pause)
    output = f"{completed.stdout}\n{completed.stderr}"
    failed = sorted(set(FETCH_FAILED.findall(output)))
    detail = (completed.stderr or completed.stdout).strip().splitlines()[-5:]
    if not failed or any(url.startswith(required) for url in failed) or not required:
        raise Failed(f"apt-get update exited {completed.returncode}: {' / '.join(detail)}")
    report.warnings.append(
        f"apt-get update could not fetch {len(failed)} index file(s) outside the HAProxy "
        f"repository after {tries} tries; installing from what it has: {', '.join(failed[:3])}"
    )


@dataclass(slots=True)
class Owners:
    """The archive's UIDs and GIDs to the target's, by name (B181)."""

    uids: dict[int, int] = field(default_factory=dict)
    gids: dict[int, int] = field(default_factory=dict)

    def translate(self, items: list[Item], report: Report) -> None:
        unknown: set[str] = set()
        for item in items:
            if item.uid in self.uids:
                item.uid = self.uids[item.uid]
            elif item.uid != 0:
                unknown.add(f"UID {item.uid}")
            if item.gid in self.gids:
                item.gid = self.gids[item.gid]
            elif item.gid != 0:
                unknown.add(f"GID {item.gid}")
        if unknown:
            report.warnings.append(
                "files owned by numbers no archived account or group has, kept as numbers: "
                + ", ".join(sorted(unknown))
            )


def _free_id_argument(flag: str, wanted: int, taken: set[int]) -> list[str]:
    """The archive's number where it is free; otherwise a free one of the same kind.

    A system account or group (below 1000) gets another system number, an
    operator's another ordinary one - the target's own ranges decide which.
    """

    if wanted not in taken:
        return [flag, str(wanted)]
    return ["-r"] if wanted < 1000 else []


def _accounts(host: Host, header: dict[str, Any], report: Report) -> Owners:
    """Groups and accounts by name, numbered as the target allows; answers the translation.

    B181: an account or group is its name. One the target already has keeps
    the target's number; a new one gets the archive's number where it is free
    and another where the target's image already uses it - Debian's
    systemd-timesync holds 997, which an Ubuntu node's service account had.
    Files are then owned by name, through the translation this answers.
    """

    owners = Owners()
    renumbered: list[str] = []
    created_groups = []
    for group in header["groups"]:
        name, gid = group["name"], group["gid"]
        existing = groups(host)
        if name not in existing:
            host.run(["groupadd", *_free_id_argument("-g", gid, set(existing.values())), name])
            created_groups.append(name)
            existing = groups(host)
        owners.gids[gid] = existing[name]
        if existing[name] != gid:
            renumbered.append(f"group {name} {gid} -> {existing[name]}")
    created: list[str] = []
    for account in header["accounts"]:
        name, uid = account["name"], account["uid"]
        users = local_accounts(host)
        if name not in users:
            argv = [
                "useradd",
                *_free_id_argument("-u", uid, {value[0] for value in users.values()}),
                "-g", str(owners.gids.get(account["gid"], account["gid"])),
                "-d", account["home"],
                "-s", account["shell"],
                "-c", account["gecos"],
            ]  # fmt: skip
            argv += ["-M"] if account["service"] else ["-m"]
            host.run([*argv, name])
            created.append(name)
            users = local_accounts(host)
        owners.uids[uid] = users[name][0]
        if users[name][0] != uid:
            renumbered.append(f"account {name} {uid} -> {users[name][0]}")
        if account["service"]:
            # As 04-node-prepare: the account owns nothing in its home (B131).
            home = host.path(account["home"])
            home.mkdir(parents=True, exist_ok=True)
            host.chown(home, 0, 0)
            home.chmod(0o755)
            host.run(["passwd", "--lock", name], check=False)
    present = groups(host)
    missing: list[str] = []
    for account in header["accounts"]:
        extra = [g for g in account["groups"] if g != account["name"]]
        for group in extra:
            if group in present:
                host.run(["usermod", "-a", "-G", group, account["name"]])
            else:
                missing.append(f"{account['name']}:{group}")
    if missing:
        report.warnings.append(
            "groups not on the target, membership skipped: " + ", ".join(missing)
        )
    report.step("accounts", created=created, groups_created=created_groups, renumbered=renumbered)

    usable = usable_password(host)
    restored = []
    for account in header["accounts"]:
        hashed = account.get("password_hash") or ""
        if hashed and hashed[0] not in "!*" and not usable.get(account["name"], False):
            host.run(["chpasswd", "-e"], stdin=f"{account['name']}:{hashed}\n")
            restored.append(account["name"])
    report.step("passwords", restored=restored)
    return owners


def _layout(host: Host, run: str, report: Report) -> None:
    for directory in (f"{HAPROXY}/releases", f"{HAPROXY}/certs"):
        target = host.path(directory)
        target.mkdir(parents=True, exist_ok=True)
        host.chown(target, 0, 0)
        target.chmod(0o750)
    current = host.path(f"{HAPROXY}/current")
    if not current.is_symlink():
        empty = host.path(f"{HAPROXY}/releases/{EMPTY_RELEASE}")
        for child in ("", "conf.d", "maps"):
            (empty / child).mkdir(parents=True, exist_ok=True)
            (empty / child).chmod(0o755)
        (empty / "haproxy.cfg").write_text(BOOTSTRAP_CONFIG, encoding="utf-8")
        (empty / "haproxy.cfg").chmod(0o644)
        current.symlink_to(f"{HAPROXY}/releases/{EMPTY_RELEASE}")
    for name in ("haproxy.cfg", "conf.d", "maps"):
        path = host.path(f"{HAPROXY}/{name}")
        if path.is_symlink():
            continue
        if path.exists():
            destination = host.path(f"{STATE}/{run}/quarantine{HAPROXY}/{name}")
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            shutil.move(str(path), destination)
        path.symlink_to(f"current/{name}")
    report.step("haproxy-layout")


def _services(host: Host, header: dict[str, Any], report: Report) -> None:
    host.run(["sysctl", "--system"])
    host.run(["systemctl", "daemon-reload"])
    if header["keepalived"] == "mask":
        host.run(["systemctl", "disable", "--now", "keepalived"], check=False)
        host.run(["systemctl", "mask", "keepalived"])
    else:
        host.run(["systemctl", "enable", "keepalived"])
    host.run(["systemctl", "enable", "haproxy"])
    report.step("services", keepalived=header["keepalived"], haproxy="enabled")

    host.run(["hostnamectl", "set-hostname", header["hostname"]])
    report.step("hostname", hostname=header["hostname"])

    host.run(["sshd", "-t"])
    host.run(["systemctl", "reload-or-restart", "ssh.service"])
    report.step("sshd", reloaded=True)


def apply(host: Host, header: dict[str, Any], payload: IO[bytes]) -> dict[str, Any]:
    items = read_payload(payload)
    bundle = _validate_apply(header, items)
    items = [item for item in items if item is not bundle]
    problems = _conflicts(header)
    if problems:
        raise Refused("; ".join(problems))
    report = Report()

    # Accounts before packages. A package that creates a system account or
    # group takes the next free ID, and on a fresh target that can be the one
    # the archive's own account holds - the node got its IDs in another order.
    # Created first, the archive's IDs are taken, and the packages go around them.
    owners = _accounts(host, header, report)
    owners.translate(items, report)
    _packages(host, header, items, report)

    keep = [item.path for item in items]
    for directory in header["equal_directories"]:
        if directory in APT_DIRECTORIES:
            continue
        spared = [ROOT_KEYS] if directory == "/root/.ssh" else []
        quarantine(host, directory, [*keep, *spared], header["run"], report)
    written = 0
    for item in sorted(items, key=lambda i: (i.kind != "directory", i.path.count("/"), i.path)):
        if item.path.startswith(APT_DIRECTORIES):
            continue
        place(host, item)
        written += 1
    report.step("files", written=written)

    _layout(host, header["run"], report)
    _services(host, header, report)
    _node_bundle(host, header, bundle, items, report)
    return {"steps": report.steps, "warnings": report.warnings}


# --------------------------------------------------------------------------
# network
# --------------------------------------------------------------------------


def _unit(run: str, what: str) -> str:
    return f"haproxy-restore-{what}-{run}"


def network(host: Host, header: dict[str, Any], payload: IO[bytes]) -> dict[str, Any]:
    items = read_payload(payload)
    if not items or any(not item.path.startswith(f"{NETPLAN}/") for item in items):
        raise Refused("the network session carries Netplan files and nothing else")
    seconds = int(header["rollback_seconds"])
    if not 60 <= seconds <= 900:
        raise Refused("the rollback delay must be between 60 and 900 seconds")
    run = header["run"]
    report = Report()

    before = host.path(f"{STATE}/{run}/netplan-before")
    if before.exists():
        raise Refused("this run has already changed the network once")
    shutil.copytree(host.path(NETPLAN), before, symlinks=True)
    quarantine(host, NETPLAN, [item.path for item in items], run, report)
    for item in items:
        place(host, item)
    generated = host.run(["netplan", "generate"], check=False)
    if generated.returncode != 0:
        _restore_netplan(host, before)
        raise Failed("netplan generate rejected the archive's network: " + generated.stderr.strip())
    report.step("netplan", files=len(items))

    script = host.path(f"{STATE}/{run}/rollback.sh")
    script.write_text(
        "#!/bin/sh\n"
        "# Written by a node restore: put the network back as it was.\n"
        f"find {NETPLAN} -mindepth 1 -maxdepth 1 -exec rm -rf {{}} +\n"
        f"cp -a {STATE}/{run}/netplan-before/. {NETPLAN}/\n"
        "netplan apply\n",
        encoding="utf-8",
    )
    script.chmod(0o700)
    rollback = _unit(run, "rollback")
    host.run(
        ["systemd-run", f"--unit={rollback}", f"--on-active={seconds}", "/bin/sh", str(script)]
    )
    apply_unit = _unit(run, "apply")
    host.run(["systemd-run", f"--unit={apply_unit}", "--on-active=3", "netplan", "apply"])
    report.step("scheduled", apply_in=3, rollback_in=seconds, rollback_unit=rollback)
    return {"steps": report.steps, "warnings": report.warnings, "rollback_unit": rollback}


def _restore_netplan(host: Host, before: Path) -> None:
    target = host.path(NETPLAN)
    for child in target.iterdir():
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child)
        else:
            child.unlink()
    for child in before.iterdir():
        destination = target / child.name
        if child.is_dir() and not child.is_symlink():
            shutil.copytree(child, destination, symlinks=True)
        else:
            shutil.copy2(child, destination, follow_symlinks=False)


# --------------------------------------------------------------------------
# finish
# --------------------------------------------------------------------------


def finish(host: Host, header: dict[str, Any], payload: IO[bytes]) -> dict[str, Any]:
    items = read_payload(payload)
    if [item.path for item in items] != [ROOT_KEYS]:
        raise Refused("the finish session carries root's authorized_keys and nothing else")
    certificates = header.get("certificates", [])
    if any(not CERTIFICATE_ID.fullmatch(str(value)) for value in certificates):
        raise Refused("a certificate ID is not usable")
    if header["keepalived"] not in {"start", "mask"}:
        raise Refused("keepalived must be started or masked")
    run = header["run"]
    report = Report()

    timer = f"{_unit(run, 'rollback')}.timer"
    active = host.run(["systemctl", "is-active", timer], check=False).stdout.strip()
    if active != "active":
        raise Refused(f"the network rollback timer is {active or 'gone'}; it may already have run")
    host.run(["systemctl", "stop", timer])
    report.step("rollback-cancelled", timer=timer)

    # Certificates before configuration: the published configuration names
    # them by path and does not validate without them. Both scripts reload,
    # so HAProxy runs on the bootstrap release first (see BOOTSTRAP_CONFIG).
    host.run(["systemctl", "start", "haproxy"])
    if certificates:
        host.run(["/usr/local/sbin/haproxy-cert-pull", *certificates])
    report.step("certificates", pulled=list(certificates))
    host.run(["/usr/local/sbin/haproxy-pull-deploy"])
    report.step("config", pulled=True)

    if header["keepalived"] == "start":
        host.run(["systemctl", "start", "keepalived"])
    states = {
        unit: host.run(["systemctl", "is-active", unit], check=False).stdout.strip()
        for unit in ("haproxy", "keepalived", "ssh")
    }
    report.step("services", **states)
    expected_keepalived = "active" if header["keepalived"] == "start" else "inactive"
    if states["haproxy"] != "active" or states["keepalived"] != expected_keepalived:
        raise Failed(f"services are not as expected: {states}")

    # Last. The one-time key this session is using is in the file being replaced.
    place(host, items[0])
    report.step("root-keys", replaced=True)
    return {"steps": report.steps, "warnings": report.warnings}


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

OPERATIONS: dict[str, Callable[[Host, dict[str, Any], IO[bytes]], dict[str, Any]]] = {
    "inspect": inspect,
    "apply": apply,
    "network": network,
    "finish": finish,
}


def serve(host: Host, stdin: IO[bytes]) -> dict[str, Any]:
    line = stdin.readline(MAX_HEADER + 1)
    if len(line) > MAX_HEADER or not line.endswith(b"\n"):
        return {"ok": False, "error": "the request header is missing or too large"}
    try:
        header = json.loads(line)
    except json.JSONDecodeError:
        return {"ok": False, "error": "the request header is not JSON"}
    operation = header.get("op") if isinstance(header, dict) else None
    if operation not in OPERATIONS:
        return {"ok": False, "error": "the operation is not one this agent performs"}
    if operation != "inspect" and not RUN_ID.fullmatch(str(header.get("run", ""))):
        return {"ok": False, "op": operation, "error": "the run ID is not usable"}
    try:
        result = OPERATIONS[operation](host, header, stdin)
    except Refused as exc:
        return {"ok": False, "op": operation, "refused": True, "error": str(exc)}
    except (Failed, OSError, subprocess.SubprocessError, ValueError, KeyError) as exc:
        return {"ok": False, "op": operation, "refused": False, "error": str(exc)}
    return {"ok": True, "op": operation, **result}


def main() -> int:
    if os.geteuid() != 0:
        print(json.dumps({"ok": False, "error": "the restore agent must run as root"}))
        return 1
    os.umask(0o022)
    result = serve(Host(), sys.stdin.buffer)
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
