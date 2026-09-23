"""Restore one node's state archive onto an empty VM - the management half.

Three steps, each its own command and later its own job (B175):

``prepare``  creates a run: a directory under ``RUN_ROOT`` holding a one-time
             key pair, and the line the operator pastes into the target's
             console.  Nothing is sent anywhere.
``preview``  checks the target's host key against the fingerprint the operator
             read on its console, asks the target about itself, builds the plan
             and records a digest of everything the plan was built from.
``run``      asks again, refuses unless the digest is unchanged, then runs the
             agent's ``apply``, ``network`` and ``finish`` sessions.

The archive is chosen by name from this host's own listing, never by path.  The
target is reached only with the one-time key, with ``StrictHostKeyChecking``
against a ``known_hosts`` that holds exactly the keys this run has verified.
"""

from __future__ import annotations

import base64
import hashlib
import io
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tarfile
import time
import zlib
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TextIO

from haproxy_mgmt import restore_agent, restore_plan
from haproxy_mgmt.backups import node_backups
from haproxy_mgmt.config import Cluster, Node
from haproxy_mgmt.restore_plan import PlannedFile, RestorePlan, Target, TestProfile
from haproxy_mgmt.restore_source import RestoreSource, content, read

RUN_ROOT = Path("/var/lib/haproxy-mgmt/restore")
SSH = "/usr/bin/ssh"
SSH_KEYGEN = "/usr/bin/ssh-keygen"
SSH_KEYSCAN = "/usr/bin/ssh-keyscan"
IP = "/usr/sbin/ip"
ENVIRONMENT = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": "/root", "LANG": "C.UTF-8"}
FINGERPRINT = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")
VERSION = re.compile(r"^\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}$")
ROLLBACK_SECONDS = 180
SESSION_TIMEOUT = 900.0
LOGREAD_GROUP_LINE = re.compile(r'^BACKUP_GROUPS="(?P<first>[a-z_][a-z0-9_-]*)')


class RestoreError(RuntimeError):
    """The restore cannot start or continue; nothing further was sent."""


@dataclass(frozen=True, slots=True)
class Request:
    run: str
    cluster: str
    node: str
    archive: str
    target: str
    mode: restore_plan.Mode
    profile: TestProfile | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "run": self.run,
            "cluster": self.cluster,
            "node": self.node,
            "archive": self.archive,
            "target": self.target,
            "mode": self.mode,
            "profile": None
            if self.profile is None
            else {
                "hostname": self.profile.hostname,
                "address": str(self.profile.address),
                "vip": str(self.profile.vip),
            },
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Request:
        profile = raw.get("profile")
        return cls(
            run=raw["run"],
            cluster=raw["cluster"],
            node=raw["node"],
            archive=raw["archive"],
            target=raw["target"],
            mode=raw["mode"],
            profile=None
            if profile is None
            else TestProfile(
                hostname=profile["hostname"],
                address=ipaddress.IPv4Interface(profile["address"]),
                vip=ipaddress.IPv4Interface(profile["vip"]),
            ),
        )


# --------------------------------------------------------------------------
# The run directory
# --------------------------------------------------------------------------


def _private_directory(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.stat()
    if info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise RestoreError(f"{path} must be owned by this user and closed to everyone else")


def run_directory(root: Path, run: str) -> Path:
    if not restore_agent.RUN_ID.fullmatch(run):
        raise RestoreError("the run ID is not usable")
    directory = root / run
    if not directory.is_dir():
        raise RestoreError(f"there is no restore run {run}")
    _private_directory(directory)
    return directory


def _write_json(path: Path, document: dict[str, Any]) -> None:
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.chmod(0o600)
    temporary.replace(path)


def read_json(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RestoreError(f"{path.name} in the run directory cannot be read") from exc
    if not isinstance(document, dict):
        raise RestoreError(f"{path.name} in the run directory is not an object")
    return document


# --------------------------------------------------------------------------
# Choosing the archive and the node
# --------------------------------------------------------------------------


def node_of(cluster: Cluster, name: str) -> Node:
    matches = [node for node in cluster.nodes if node.name == name]
    if len(matches) != 1:
        raise RestoreError(f"{name} is not a node of this cluster")
    return matches[0]


def archive_path(backup_root: Path, node: Node, version: str) -> Path:
    """The archive, named by version and found in this host's own listing."""

    if not VERSION.fullmatch(version):
        raise RestoreError("the archive is named by its version, YYYY-MM-DD_HH-MM-SS")
    listed = node_backups(backup_root, node, limit=None)
    if not listed.available:
        raise RestoreError(f"the backups of {node.name} cannot be read: {listed.error}")
    if version not in {backup["version"] for backup in listed.backups}:
        raise RestoreError(f"{node.name} has no retained archive {version}")
    return backup_root / node.name / f"{version}.tar.gz"


def _digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


# --------------------------------------------------------------------------
# Talking to the target
# --------------------------------------------------------------------------


def source_address(target: str) -> str:
    """The address this host would reach `target` from - what `from=` must name."""

    completed = subprocess.run(  # noqa: S603 - fixed binary, validated address
        [IP, "-j", "route", "get", str(ipaddress.IPv4Address(target))],
        capture_output=True,
        text=True,
        check=False,
        env=ENVIRONMENT,
    )
    try:
        return str(ipaddress.IPv4Address(json.loads(completed.stdout)[0]["prefsrc"]))
    except (ValueError, KeyError, IndexError, json.JSONDecodeError) as exc:
        raise RestoreError(f"this host has no route to {target}") from exc


def answers(address: str, *, port: int = 22, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((address, port), timeout=timeout):
            return True
    except OSError:
        return False


def scan_host_key(address: str) -> str:
    """The target's ed25519 host key line, as `ssh-keyscan` sees it."""

    completed = subprocess.run(  # noqa: S603 - fixed binary, validated address
        [SSH_KEYSCAN, "-T", "5", "-t", "ed25519", str(ipaddress.IPv4Address(address))],
        capture_output=True,
        text=True,
        check=False,
        env=ENVIRONMENT,
    )
    lines = [line for line in completed.stdout.splitlines() if line and not line.startswith("#")]
    if len(lines) != 1:
        raise RestoreError(f"{address} did not offer exactly one ed25519 host key")
    return lines[0].split(None, 1)[1]


def fingerprint(key: str) -> str:
    completed = subprocess.run(  # noqa: S603 - fixed binary, key on stdin
        [SSH_KEYGEN, "-lf", "-"],
        input=f"host {key}\n",
        capture_output=True,
        text=True,
        check=False,
        env=ENVIRONMENT,
    )
    fields = completed.stdout.split()
    if completed.returncode != 0 or len(fields) < 2:
        raise RestoreError("the host key could not be fingerprinted")
    return fields[1]


def agent_command() -> str:
    """The remote command: the agent's source, compressed, run by the target's python3."""

    source = Path(restore_agent.__file__).read_bytes()
    packed = base64.b64encode(zlib.compress(source, 9)).decode()
    return (
        "python3 -c 'import base64,zlib;"
        f'exec(compile(zlib.decompress(base64.b64decode("{packed}")),"restore-agent","exec"))\''
    )


@dataclass(frozen=True, slots=True)
class Session:
    key: Path
    known_hosts: Path

    def call(
        self,
        address: str,
        header: dict[str, Any],
        payload: bytes = b"",
        *,
        progress: TextIO | None = None,
        timeout: float = SESSION_TIMEOUT,
    ) -> dict[str, Any]:
        argv = [
            SSH,
            "-T",
            "-i", str(self.key),
            "-o", "IdentitiesOnly=yes",
            "-o", "BatchMode=yes",
            "-o", f"UserKnownHostsFile={self.known_hosts}",
            "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", "StrictHostKeyChecking=yes",
            "-o", "ConnectTimeout=10",
            "-o", "ServerAliveInterval=15",
            "-o", "LogLevel=ERROR",
            f"root@{ipaddress.IPv4Address(address)}",
            agent_command(),
        ]  # fmt: skip
        stream = progress or sys.stderr
        request = json.dumps(header, separators=(",", ":")).encode() + b"\n" + payload
        process = subprocess.Popen(  # noqa: S603 - fixed binary, argv built here
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=ENVIRONMENT,
        )
        try:
            output, errors = process.communicate(request, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            process.kill()
            process.communicate()
            raise RestoreError(f"the {header['op']} session did not finish in time") from exc
        for line in errors.decode("utf-8", "replace").splitlines():
            stream.write(f"  {line}\n")
        try:
            result = json.loads(output.decode("utf-8").strip().splitlines()[-1])
        except (IndexError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RestoreError(
                f"the {header['op']} session gave no answer (ssh exited {process.returncode})"
            ) from exc
        if not isinstance(result, dict):
            raise RestoreError(f"the {header['op']} session answered something else")
        return result


# --------------------------------------------------------------------------
# The payload
# --------------------------------------------------------------------------


def payload(source: RestoreSource, files: tuple[PlannedFile, ...]) -> bytes:
    buffer = io.BytesIO()
    with (
        tarfile.open(source.archive, mode="r:gz") as archive,
        tarfile.open(fileobj=buffer, mode="w:", format=tarfile.PAX_FORMAT) as output,
    ):
        for file in files:
            info = tarfile.TarInfo(file.path.lstrip("/"))
            info.mode, info.uid, info.gid = file.mode, file.uid, file.gid
            if file.kind == "directory":
                info.type = tarfile.DIRTYPE
                output.addfile(info)
            elif file.kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = file.link or ""
                output.addfile(info)
            else:
                if file.data is not None:
                    data = file.data
                else:
                    stream = None if file.entry is None else archive.extractfile(file.entry.member)
                    if stream is None:
                        raise RestoreError(f"the archive cannot read {file.path}")
                    data = stream.read()
                info.size = len(data)
                output.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


# --------------------------------------------------------------------------
# prepare
# --------------------------------------------------------------------------


def new_run_id() -> str:
    return f"r{time.strftime('%y%m%d')}-{secrets.token_hex(4)}"


def prepare(
    root: Path,
    request: Request,
    *,
    source_of: Callable[[str], str] = source_address,
    keygen: str = SSH_KEYGEN,
) -> dict[str, Any]:
    _private_directory(root)
    directory = root / request.run
    directory.mkdir(mode=0o700)
    key = directory / "key"
    subprocess.run(  # noqa: S603 - fixed binary, paths built here
        [
            keygen,
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            f"haproxy-restore-{request.run}",
            "-f",
            str(key),
        ],
        check=True,
        env=ENVIRONMENT,
    )
    public = (directory / "key.pub").read_text(encoding="utf-8").strip()
    manager = source_of(request.target)
    line = f'from="{manager}",restrict {public}'
    _write_json(directory / "request.json", request.as_dict())
    paste = (
        f"echo '{line}' | sudo sh -c 'install -d -m 700 /root/.ssh && "
        "cat >> /root/.ssh/authorized_keys' && ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub"
    )
    return {"run": request.run, "paste": paste, "from": manager}


# --------------------------------------------------------------------------
# preview
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Checked:
    source: RestoreSource
    plan: RestorePlan
    inspected: dict[str, Any]
    digest: str
    problems: tuple[str, ...]


def _logread_group(source: RestoreSource) -> str | None:
    entry = source.entry("/etc/haproxy-manager/node.conf")
    if entry is None:
        return None
    for line in content(source, entry).decode("utf-8").splitlines():
        matched = LOGREAD_GROUP_LINE.match(line.strip())
        if matched:
            return matched.group("first")
    return None


def _inspect_header(source: RestoreSource) -> dict[str, Any]:
    return {
        "op": "inspect",
        "names": sorted({a.name for a in source.accounts} | {g.name for g in source.groups}),
        "ids": sorted({a.uid for a in source.accounts} | {g.gid for g in source.groups}),
    }


def _problems(
    request: Request,
    node: Node,
    source: RestoreSource,
    plan: RestorePlan,
    inspected: dict[str, Any],
    answering: Callable[[str], bool],
) -> list[str]:
    problems: list[str] = []
    # B168: an archive carries one node's identity and is offered for that node only.
    if source.hostname != node.name:
        problems.append(f"the archive is of {source.hostname}, not of {node.name}")
    # B174: the same distribution and version; another version needs a
    # confirmation this first delivery does not offer, another distribution never.
    theirs = inspected["os_release"]
    ours = source.os_release
    if theirs.get("ID") != ours.get("ID"):
        problems.append(
            f"the target runs {theirs.get('ID')} and the archive is of {ours.get('ID')}; "
            "a restore does not cross distributions"
        )
    elif theirs.get("VERSION_ID") != ours.get("VERSION_ID"):
        problems.append(
            f"the target runs {ours.get('ID')} {theirs.get('VERSION_ID')} and the archive is of "
            f"{ours.get('VERSION_ID')}; another version is not restored in this delivery"
        )
    final = str(plan.address.ip)
    if final != request.target and answering(final):
        problems.append(f"{final} already answers; two machines would hold one address")
    if request.mode == "new_vm" and node.mgmt_host != final and answering(node.mgmt_host):
        problems.append(f"{node.name} still answers at {node.mgmt_host}")
    existing_accounts = inspected.get("accounts", {})
    existing_groups = inspected.get("groups", {})
    for group in source.groups:
        gid = existing_groups.get(group.name)
        if gid is not None and gid != group.gid:
            problems.append(f"group {group.name} has GID {gid} on the target, {group.gid} here")
        for name, other in existing_groups.items():
            if other == group.gid and name != group.name:
                problems.append(f"GID {group.gid} of {group.name} belongs to {name} on the target")
    for account in source.accounts:
        ids = existing_accounts.get(account.name)
        if ids is not None and tuple(ids) != (account.uid, account.gid):
            problems.append(
                f"account {account.name} is {ids[0]}:{ids[1]} on the target, "
                f"{account.uid}:{account.gid} here"
            )
        for name, other in existing_accounts.items():
            if other[0] == account.uid and name != account.name:
                problems.append(
                    f"UID {account.uid} of {account.name} belongs to {name} on the target"
                )
    return problems


def check(
    request: Request,
    cluster: Cluster,
    backup_root: Path,
    *,
    session: Session,
    answering: Callable[[str], bool] = answers,
    progress: TextIO | None = None,
) -> Checked:
    node = node_of(cluster, request.node)
    archive = archive_path(backup_root, node, request.archive)
    source = read(archive)
    inspected = session.call(request.target, _inspect_header(source), progress=progress)
    if not inspected.get("ok"):
        raise RestoreError(f"the target could not be inspected: {inspected.get('error')}")
    interface = inspected["interface"]
    target = Target(
        os_release=inspected["os_release"], interface=interface["name"], mac=interface["mac"]
    )
    try:
        plan = restore_plan.build(source, request.mode, target, request.profile)
    except restore_plan.PlanError as exc:
        raise RestoreError(str(exc)) from exc
    problems = _problems(request, node, source, plan, inspected, answering)
    bound = {
        "request": request.as_dict(),
        "archive_sha256": _digest_file(archive),
        "target": {
            "os_release": inspected["os_release"],
            "interface": interface,
            "host_keys": inspected["host_keys"],
        },
        "plan": plan.summary(),
    }
    digest = hashlib.sha256(json.dumps(bound, sort_keys=True).encode()).hexdigest()
    return Checked(source, plan, inspected, digest, tuple(problems))


def preview(
    root: Path,
    run: str,
    fingerprint_seen: str,
    cluster: Cluster,
    backup_root: Path,
    *,
    scan: Callable[[str], str] = scan_host_key,
    fingerprint_of: Callable[[str], str] = fingerprint,
    answering: Callable[[str], bool] = answers,
    progress: TextIO | None = None,
    session_for: Callable[[Path, Path], Session] = Session,
) -> dict[str, Any]:
    directory = run_directory(root, run)
    request = Request.from_dict(read_json(directory / "request.json"))
    if not FINGERPRINT.fullmatch(fingerprint_seen):
        raise RestoreError("the fingerprint is written as SHA256:<43 characters>")
    key = scan(request.target)
    if fingerprint_of(key) != fingerprint_seen:
        raise RestoreError(
            f"{request.target} offers a host key whose fingerprint is not the one read on its "
            "console; nothing was sent to it"
        )
    known_hosts = directory / "known_hosts"
    known_hosts.write_text(f"{request.target} {key}\n", encoding="utf-8")
    known_hosts.chmod(0o600)
    _write_json(directory / "target-key.json", {"key": key, "fingerprint": fingerprint_seen})
    session = session_for(directory / "key", known_hosts)
    checked = check(
        request, cluster, backup_root, session=session, answering=answering, progress=progress
    )
    summary = {
        "run": run,
        "digest": checked.digest,
        "problems": list(checked.problems),
        "plan": checked.plan.summary(),
        "target": {
            "hostname": checked.inspected["hostname"],
            "os_release": {
                key: checked.inspected["os_release"].get(key) for key in ("ID", "VERSION_ID")
            },
            "interface": checked.inspected["interface"],
            "fingerprint": fingerprint_seen,
        },
        "archive": {
            "node": request.node,
            "version": request.archive,
            "os_release": {key: checked.source.os_release.get(key) for key in ("ID", "VERSION_ID")},
            "extra_paths": list(checked.source.extra_paths),
        },
    }
    _write_json(directory / "preview.json", summary)
    return summary


# --------------------------------------------------------------------------
# run
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Clock:
    now: Callable[[], float] = time.monotonic
    sleep: Callable[[float], None] = time.sleep


def _wait_for(
    address: str, deadline: float, answering: Callable[[str], bool], pause: float, clock: Clock
) -> bool:
    while clock.now() < deadline:
        if answering(address):
            return True
        clock.sleep(pause)
    return False


def run(
    root: Path,
    run_id: str,
    confirm: str,
    cluster: Cluster,
    backup_root: Path,
    *,
    answering: Callable[[str], bool] = answers,
    progress: TextIO | None = None,
    pause: float = 3.0,
    rollback_seconds: int = ROLLBACK_SECONDS,
    clock: Clock = Clock(),  # noqa: B008 - immutable
    session_for: Callable[[Path, Path], Session] = Session,
) -> dict[str, Any]:
    stream = progress or sys.stderr
    directory = run_directory(root, run_id)
    request = Request.from_dict(read_json(directory / "request.json"))
    previewed = read_json(directory / "preview.json")
    if (directory / "result.json").exists():
        raise RestoreError("this run has already been carried out; prepare a new one")
    session = session_for(directory / "key", directory / "known_hosts")
    checked = check(
        request, cluster, backup_root, session=session, answering=answering, progress=stream
    )
    if checked.digest != previewed.get("digest"):
        raise RestoreError(
            "the archive, the target or the plan changed after the preview; preview again"
        )
    if checked.problems:
        raise RestoreError("; ".join(checked.problems))
    plan = checked.plan
    if confirm != plan.hostname:
        raise RestoreError(f"confirm with the restored node's name, {plan.hostname}")

    result: dict[str, Any] = {
        "run": run_id,
        "outcome": "failed",
        "rolled_back": False,
        "sessions": {},
    }

    def finish_with(outcome: str, **extra: Any) -> dict[str, Any]:
        result.update(outcome=outcome, **extra)
        _write_json(directory / "result.json", result)
        return result

    apply_header = {
        "op": "apply",
        "run": run_id,
        "hostname": plan.hostname,
        "keepalived": plan.keepalived,
        "packages": list(plan.packages),
        "equal_directories": list(plan.equal_directories),
        "logread_group": _logread_group(checked.source),
        "groups": [{"name": g.name, "gid": g.gid} for g in plan.groups],
        "accounts": [
            {
                "name": a.name,
                "uid": a.uid,
                "gid": a.gid,
                "gecos": a.gecos,
                "home": a.home,
                "shell": a.shell,
                "groups": list(a.groups),
                "service": a.service,
                "password_hash": a.password_hash,
            }
            for a in plan.accounts
        ],
    }
    stream.write(f"apply on {request.target}\n")
    applied = session.call(
        request.target, apply_header, payload(checked.source, plan.files), progress=stream
    )
    result["sessions"]["apply"] = {k: v for k, v in applied.items() if k != "ok"}
    if not applied.get("ok"):
        return finish_with("failed", error=applied.get("error"), stage="apply")

    stream.write(
        f"network on {request.target}: {plan.address} after 3 s, rollback in {rollback_seconds} s\n"
    )
    changed = session.call(
        request.target,
        {"op": "network", "run": run_id, "rollback_seconds": rollback_seconds},
        payload(checked.source, plan.network),
        progress=stream,
    )
    result["sessions"]["network"] = {k: v for k, v in changed.items() if k != "ok"}
    if not changed.get("ok"):
        return finish_with("failed", error=changed.get("error"), stage="network")

    final = str(plan.address.ip)
    if plan.mode == "test":
        key = read_json(directory / "target-key.json")["key"]
    else:
        public = checked.source.entry("/etc/ssh/ssh_host_ed25519_key.pub")
        if public is None:
            return finish_with(
                "failed", error="the archive has no ed25519 host key", stage="network"
            )
        key = " ".join(content(checked.source, public).decode().split()[:2])
    with (directory / "known_hosts").open("a", encoding="utf-8") as stream_hosts:
        stream_hosts.write(f"{final} {key}\n")

    started = clock.now()
    clock.sleep(min(pause * 2, 6.0))
    reached = _wait_for(final, started + rollback_seconds - 30, answering, pause, clock)
    if not reached:
        stream.write(f"{final} did not answer; waiting for the rollback timer\n")
        clock.sleep(max(0.0, started + rollback_seconds + 20 - clock.now()))
        back = _wait_for(request.target, clock.now() + 60, answering, pause, clock)
        return finish_with(
            "failed",
            rolled_back=back,
            stage="network",
            error=f"{final} never answered; the network was "
            + ("rolled back" if back else "NOT confirmed rolled back - go to the console"),
        )

    stream.write(f"finish on {final}\n")
    finished = session.call(
        final,
        {
            "op": "finish",
            "run": run_id,
            "certificates": list(cluster.certificate_ids),
            "keepalived": plan.keepalived,
        },
        payload(checked.source, (plan.root_keys,)) if plan.root_keys else b"",
        progress=stream,
    )
    result["sessions"]["finish"] = {k: v for k, v in finished.items() if k != "ok"}
    if not finished.get("ok"):
        return finish_with("failed", error=finished.get("error"), stage="finish")
    return finish_with("done", address=final, hostname=plan.hostname)


def forget(root: Path, run_id: str) -> None:
    """Remove a run's directory - its one-time private key with it."""

    shutil.rmtree(run_directory(root, run_id))
