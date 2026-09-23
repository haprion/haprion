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
             HAProxy release layout, the service states, the hostname.
``network``  Netplan, under a timer that puts the previous Netplan back unless
             the next session cancels it from the node's new address.
``finish``   cancels that timer, pulls configuration and certificates the way
             a deploy does, starts the services, and writes root's
             ``authorized_keys`` last - which removes the one-time key this
             restore is connected with.

Every check an operation makes happens before its first write.  A directory the
export carries whole is made equal to the archive; what was there and is not in
the archive is moved to a quarantine directory, never deleted.
"""

from __future__ import annotations

import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import IO, Any

STATE = "/var/lib/haproxy-restore"
NETPLAN = "/etc/netplan"
ROOT_KEYS = "/root/.ssh/authorized_keys"
POLICY_RC = "/usr/sbin/policy-rc.d"
TRAFFIC_LOG_ROOT = "/var/log/haproxy-manager"
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


def passwd(host: Host) -> dict[str, tuple[int, int, str]]:
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


def inspect(host: Host, header: dict[str, Any], _payload: IO[bytes]) -> dict[str, Any]:
    names = set(header.get("names", []))
    ids = set(header.get("ids", []))
    users = passwd(host)
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


def _conflicts(host: Host, header: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    existing_users = passwd(host)
    existing_groups = groups(host)
    for group in header["groups"]:
        name, gid = group["name"], group["gid"]
        if name in existing_groups and existing_groups[name] != gid:
            problems.append(
                f"group {name} has GID {existing_groups[name]} here, {gid} in the archive"
            )
        holder = next((n for n, g in existing_groups.items() if g == gid and n != name), None)
        if holder is not None:
            problems.append(f"GID {gid} of group {name} belongs to {holder} here")
    for account in header["accounts"]:
        name, uid, gid = account["name"], account["uid"], account["gid"]
        if name in existing_users and existing_users[name][:2] != (uid, gid):
            here = existing_users[name][:2]
            problems.append(
                f"account {name} is {here[0]}:{here[1]} here, {uid}:{gid} in the archive"
            )
        holder = next((n for n, v in existing_users.items() if v[0] == uid and n != name), None)
        if holder is not None:
            problems.append(f"UID {uid} of account {name} belongs to {holder} here")
        known = {group["gid"] for group in header["groups"]} | set(existing_groups.values())
        if gid not in known:
            problems.append(
                f"account {name} has primary GID {gid}, which no group here or in the archive has"
            )
    return problems


def _validate_apply(header: dict[str, Any], items: list[Item]) -> None:
    for record in (*header["groups"], *header["accounts"]):
        if not NAME.fullmatch(str(record.get("name", ""))):
            raise Refused("the header names an unusable account or group")
    for item in items:
        if item.path == ROOT_KEYS or item.path == NETPLAN or item.path.startswith(f"{NETPLAN}/"):
            raise Refused(f"{item.path} is written by a later session, not by apply")
    if header["keepalived"] not in {"start", "mask"}:
        raise Refused("keepalived must be started or masked")
    if not HOSTNAME.fullmatch(header["hostname"]):
        raise Refused("the hostname is not usable")


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
        host.run(["apt-get", "update"])
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


def _accounts(host: Host, header: dict[str, Any], report: Report) -> None:
    created_groups = []
    existing = groups(host)
    for group in header["groups"]:
        if group["name"] not in existing:
            host.run(["groupadd", "-g", str(group["gid"]), group["name"]])
            created_groups.append(group["name"])
    users = passwd(host)
    created: list[str] = []
    for account in header["accounts"]:
        name = account["name"]
        if name not in users:
            argv = [
                "useradd",
                "-u", str(account["uid"]),
                "-g", str(account["gid"]),
                "-d", account["home"],
                "-s", account["shell"],
                "-c", account["gecos"],
            ]  # fmt: skip
            argv += ["-M"] if account["service"] else ["-m"]
            host.run([*argv, name])
            created.append(name)
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
    report.step("accounts", created=created, groups_created=created_groups)

    usable = usable_password(host)
    restored = []
    for account in header["accounts"]:
        hashed = account.get("password_hash") or ""
        if hashed and hashed[0] not in "!*" and not usable.get(account["name"], False):
            host.run(["chpasswd", "-e"], stdin=f"{account['name']}:{hashed}\n")
            restored.append(account["name"])
    report.step("passwords", restored=restored)


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


def _traffic_log(host: Host, header: dict[str, Any], report: Report) -> None:
    group = header.get("logread_group")
    if not group:
        return
    target = host.path(TRAFFIC_LOG_ROOT)
    target.mkdir(parents=True, exist_ok=True)
    users = passwd(host)
    present = groups(host)
    if "syslog" not in users or group not in present:
        report.warnings.append(f"{TRAFFIC_LOG_ROOT} left root-owned: syslog or {group} is missing")
        return
    host.chown(target, users["syslog"][0], present[group])
    target.chmod(0o2750)
    report.step("traffic-log-root", owner=f"syslog:{group}", mode="2750")


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
    _validate_apply(header, items)
    problems = _conflicts(host, header)
    if problems:
        raise Refused("; ".join(problems))
    report = Report()

    # Accounts before packages. A package that creates a system account or
    # group takes the next free ID, and on a fresh target that can be the one
    # the archive's own account holds - the node got its IDs in another order.
    # Created first, the archive's IDs are taken, and the packages go around them.
    _accounts(host, header, report)
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
    _traffic_log(host, header, report)
    _services(host, header, report)
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
