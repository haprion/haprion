"""Restore one node's state archive as the node - onto an empty VM or over the node itself.

The management half. Which of the two a run is, is decided at the preview from
the host key the target offers (B184): the archived one means the node itself.

Three steps, each its own command and later its own job (B175):

``prepare``  creates a run: a directory under ``RUN_ROOT`` holding a one-time
             key pair, and the line the operator pastes into the target's
             console.  Nothing is sent anywhere.
``preview``  checks the target's host key against the fingerprint the operator
             read on its console, asks the target about itself, builds the plan
             and records a digest of everything the plan was built from.
``run``      asks again, refuses unless the digest is unchanged, then runs the
             agent's ``apply``, ``network`` and ``finish`` sessions.

A run has an hour from ``prepare`` to ``run`` (B182). After that it has expired:
``preview`` and ``run`` refuse it and remove its directory, and every call
through the helper sweeps away the directories of runs past the hour that
nothing holds. The line pasted on the target carries an ``expiry-time`` of its
own, so the target stops accepting the one-time key whatever happens here.

The archive is chosen by name from this host's own listing, never by path.  The
target is reached only with the one-time key, with ``StrictHostKeyChecking``
against a ``known_hosts`` that holds exactly the keys this run has verified.
"""

from __future__ import annotations

import base64
import dataclasses
import fcntl
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

from haproxy_mgmt import (
    backup_retention,
    cluster_lock,
    haproxy_repository,
    node_package,
    restore_agent,
    restore_answers,
    restore_plan,
    state_backup,
)
from haproxy_mgmt.backups import node_backups
from haproxy_mgmt.cluster_status import StatusError, parse_status
from haproxy_mgmt.config import Cluster, Node, PathPolicy
from haproxy_mgmt.envelope import new_request_id
from haproxy_mgmt.restore_plan import PlannedFile, RestorePlan, Target, TestProfile
from haproxy_mgmt.restore_source import RestoreSource, content, read
from haproxy_mgmt.status_collect import ask_node, collect

RUN_ROOT = state_backup.RESTORE_RUN_ROOT
SSH = "/usr/bin/ssh"
SSH_KEYGEN = "/usr/bin/ssh-keygen"
SSH_KEYSCAN = "/usr/bin/ssh-keyscan"
IP = "/usr/sbin/ip"
ENVIRONMENT = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": "/root", "LANG": "C.UTF-8"}
FINGERPRINT = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")
VERSION = re.compile(r"^\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}$")
ROLLBACK_SECONDS = 180
#
# One SSH session, bounded below the worker's client (`node_restore_ask`, 840 s)
# so a session that hangs ends in the helper's own words rather than the
# client giving up first. A step is expected to take about a minute.
#
SESSION_TIMEOUT = 600.0
#
# From `prepare` to the start of `run`. Past it the run is gone and the operator
# starts again (B182): a key nobody is about to use is a key
# nobody should be holding. The web page reads the same constant.
#
START_WINDOW = 3600
#
# How long the target itself accepts the one-time key: the hour to start, and
# room after it for a run started at the last minute. `finish` removes the line
# from a node it restored; this is what removes it from one it did not.
#
KEY_LIFETIME = 2 * START_WINDOW
#
# A run that began writing keeps its outcome after its hour, as long as the
# web keeps its jobs (a week), so a job that lost its answer can still ask
# for it (review 2026-09-25, track 8). Only these files stay: the key,
# known_hosts and the preview's plan go at the hour, as before.
#
RESULT_KEPT = 7 * 24 * 3600
KEPT_FILES = frozenset({"request.json", "prepared.json", "started.json", "result.json"})


class RestoreError(RuntimeError):
    """The restore cannot start or continue; nothing further was sent."""


@dataclass(frozen=True, slots=True)
class Standing:
    """The node's place in its pair, read before an overwrite (B172)."""

    vip_owner: bool | None
    neighbour: str
    neighbour_healthy: bool
    detail: str = ""


@dataclass(frozen=True, slots=True)
class OverwriteChecks:
    """What an overwrite asks about the cluster, beyond the node itself.

    ``backup`` takes the cluster's state backup and answers None, or why it
    could not. ``standing`` reads the pair for the named node. Built from the
    runtime policy by the helper; tests pass their own.
    """

    backup: Callable[[], str | None]
    standing: Callable[[str], Standing]


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
        #
        # Written by `prepare` alone, root-only - but a file that lost a key is
        # still an answer the helper has to give in words, not a traceback
        # (review 2026-09-25, finding 4).
        #
        try:
            return cls._from_dict(raw)
        except (KeyError, TypeError, ValueError) as exc:
            raise RestoreError(f"request.json in the run directory is incomplete: {exc}") from exc

    @classmethod
    def _from_dict(cls, raw: dict[str, Any]) -> Request:
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


def prepared_at(directory: Path) -> float:
    """When the run was prepared, as epoch seconds.

    Runs prepared before B182 have no `prepared.json`; the request file was
    written in the same breath and never again, so its time stands in.
    """

    try:
        document = json.loads((directory / "prepared.json").read_text(encoding="utf-8"))
        at = document["at"] if isinstance(document, dict) else None
        if isinstance(at, int | float) and not isinstance(at, bool):
            return float(at)
    except (OSError, ValueError, KeyError):
        pass
    try:
        return (directory / "request.json").stat().st_mtime
    except OSError:
        return directory.stat().st_mtime


def expired(directory: Path, now: float) -> bool:
    return now - prepared_at(directory) > START_WINDOW


def _retire(directory: Path, now: float) -> bool:
    """Put a run past its hour away; True when its directory is gone.

    A run that began writing keeps its outcome files until RESULT_KEPT, and
    everything else goes - the one-time key first among them. Any other run
    past its hour goes whole.
    """

    began = (directory / "started.json").exists() or (directory / "result.json").exists()
    if not began or now - prepared_at(directory) > RESULT_KEPT:
        shutil.rmtree(directory)
        return True
    for entry in directory.iterdir():
        if entry.name in KEPT_FILES:
            continue
        if entry.is_dir() and not entry.is_symlink():
            shutil.rmtree(entry)
        else:
            entry.unlink()
    return False


class _Held:
    """An exclusive lock on a run directory for as long as a step works in it.

    `sweep` and `discard` take the same lock without waiting, so a run that is
    being carried out is never removed from under itself.
    """

    def __init__(self, directory: Path, *, wait: bool) -> None:
        self._fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            fcntl.flock(self._fd, fcntl.LOCK_EX if wait else fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(self._fd)
            raise

    def __enter__(self) -> _Held:
        return self

    def __exit__(self, *_exc: object) -> None:
        os.close(self._fd)


def _unexpired(root: Path, run: str, now: float) -> Path:
    """The run's directory, or a refusal that removes it when its hour is past."""

    directory = run_directory(root, run)
    if expired(directory, now):
        _retire(directory, now)
        raise RestoreError(
            f"run {run} was prepared more than an hour ago and has expired; prepare a new one"
        )
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
    now: Callable[[], float] = time.time,
) -> dict[str, Any]:
    _private_directory(root)
    at = int(now())
    directory = root / request.run
    directory.mkdir(mode=0o700)
    key = directory / "key"
    completed = subprocess.run(  # noqa: S603 - fixed binary, paths built here
        [
            keygen,
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            f"haprion-restore-{request.run}",
            "-f",
            str(key),
        ],
        check=False,
        capture_output=True,
        text=True,
        env=ENVIRONMENT,
    )
    if completed.returncode != 0:
        #
        # The directory goes with it: a run without its key can never be used,
        # and leaving it would make the same run ID "already exist".
        #
        shutil.rmtree(directory, ignore_errors=True)
        detail = completed.stderr.strip().splitlines()[-1:] or [f"exit {completed.returncode}"]
        raise RestoreError(f"the one-time key could not be made: {detail[0]}")
    public = (directory / "key.pub").read_text(encoding="utf-8").strip()
    manager = source_of(request.target)
    until = time.strftime("%Y%m%d%H%M", time.gmtime(at + KEY_LIFETIME))
    line = f'from="{manager}",restrict,expiry-time="{until}Z" {public}'
    _write_json(directory / "request.json", request.as_dict())
    _write_json(directory / "prepared.json", {"at": at})
    paste = (
        f"echo '{line}' | sudo sh -c 'install -d -m 700 /root/.ssh && "
        "cat >> /root/.ssh/authorized_keys' && sudo tail -n 1 /root/.ssh/authorized_keys && "
        "ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub"
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
    #
    # The running release's node package and the answers derived for it (B180).
    # None and "" when either cannot be had; `problems` then says why.
    #
    package: node_package.ReleasePackage | None = None
    answers: str = ""


def _inspect_header(source: RestoreSource, mode: str, run: str) -> dict[str, Any]:
    header: dict[str, Any] = {
        "op": "inspect",
        "names": sorted({a.name for a in source.accounts} | {g.name for g in source.groups}),
        "ids": sorted({a.uid for a in source.accounts} | {g.gid for g in source.groups}),
    }
    if mode == "overwrite":
        # B183: what the node holds, so the preview can say what changes.
        header["hash"] = sorted(entry.path for entry in source.owned() if entry.kind == "file")
        header["list"] = [restore_plan.NETPLAN_DIR, *restore_plan.PRODUCT_DIRECTORIES]
        header["packages"] = list(restore_plan.PRODUCT_PACKAGES)
        # Root's keys hold this run's one-time key by now; the agent leaves that
        # line out of the file's digest, so a node nobody touched compares equal.
        header["run"] = run
    return header


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
    # B178: the target may run another release or distribution than the archive
    # was taken on, as long as it is one a restore supports.
    theirs = inspected["os_release"]
    if not haproxy_repository.supported(theirs):
        problems.append(
            f"the target runs {theirs.get('ID')} {theirs.get('VERSION_ID')}; "
            "restore onto Ubuntu 26.04 or Debian 13"
        )
    #
    # The network is written as Netplan. A target whose network something else
    # configures would end up with two configurations of one interface.
    #
    network = inspected.get("network")
    if not isinstance(network, dict):
        problems.append("the target did not say how its network is configured")
    elif network.get("ifupdown"):
        problems.append(
            f"ifupdown configures {', '.join(network['ifupdown'])} on the target; a restore writes "
            "the network as Netplan - restore onto a cloud image of Ubuntu 26.04 or Debian 13"
        )
    elif not network.get("netplan"):
        problems.append(
            "the target has no Netplan configuration; a restore writes the network as Netplan - "
            "restore onto a cloud image of Ubuntu 26.04 or Debian 13"
        )
    final = str(plan.address.ip)
    if request.mode == "overwrite":
        # B172: the node itself, at its own address - the reverse of a new VM.
        if request.target != final:
            problems.append(
                f"an overwrite connects to {node.name} at its own address {final}, "
                f"not {request.target}"
            )
        return problems
    if final != request.target and answering(final):
        problems.append(f"{final} already answers; two machines would hold one address")
    if request.mode == "new_vm" and node.mgmt_host != final and answering(node.mgmt_host):
        problems.append(f"{node.name} still answers at {node.mgmt_host}")
    #
    # "Nothing is installed on the VM beforehand" is a requirement, not a
    # description. A VM this product has already restored onto is the one
    # exception: a run that rolled its network back left its packages behind,
    # and the next attempt must not be refused for them.
    #
    preinstalled = inspected.get("installed", [])
    if preinstalled and not inspected.get("previous_restore"):
        problems.append(
            f"{' and '.join(preinstalled)} already installed on the target, and its host key "
            f"is not {node.name}'s archived one; restore onto an empty VM, or onto the node "
            "itself to repair it"
        )
    return problems


def renumbered(source: RestoreSource, inspected: dict[str, Any]) -> list[str]:
    """Accounts and groups whose number on the VM will differ from the archive's (B181).

    Not a problem: an account or group is its name. One the VM already has
    keeps the VM's number; a new one whose number the VM already uses for
    something else gets a free one. Listed so the preview says so.
    """

    existing_accounts = inspected.get("accounts", {})
    existing_groups = inspected.get("groups", {})
    notes: list[str] = []
    for group in source.groups:
        here = existing_groups.get(group.name)
        if here is not None and here != group.gid:
            notes.append(f"group {group.name} keeps the VM's GID {here} (archive {group.gid})")
        elif here is None and group.gid in existing_groups.values():
            notes.append(f"group {group.name} gets a free GID")
    for account in source.accounts:
        ids = existing_accounts.get(account.name)
        if ids is not None and ids[0] != account.uid:
            notes.append(
                f"account {account.name} keeps the VM's UID {ids[0]} (archive {account.uid})"
            )
        elif ids is None and any(taken[0] == account.uid for taken in existing_accounts.values()):
            notes.append(f"account {account.name} gets a free UID")
    return notes


def check(
    request: Request,
    cluster: Cluster,
    backup_root: Path,
    *,
    session: Session,
    publish_root: Path,
    answering: Callable[[str], bool] = answers,
    progress: TextIO | None = None,
    package_of: Callable[[], node_package.ReleasePackage | None] = node_package.release_package,
) -> Checked:
    node = node_of(cluster, request.node)
    archive = archive_path(backup_root, node, request.archive)
    source = read(archive)
    inspected = session.call(
        request.target, _inspect_header(source, request.mode, request.run), progress=progress
    )
    if not inspected.get("ok"):
        raise RestoreError(f"the target could not be inspected: {inspected.get('error')}")
    interface = inspected["interface"]
    target = Target(
        os_release=inspected["os_release"],
        interface=interface["name"],
        mac=interface["mac"],
        hashes=inspected.get("hashes", {}),
        listing={k: tuple(v) for k, v in inspected.get("listing", {}).items()},
        installed=tuple(inspected.get("product_installed", ())),
    )
    try:
        plan = restore_plan.build(source, request.mode, target, request.profile)
    except restore_plan.PlanError as exc:
        raise RestoreError(str(exc)) from exc
    problems = _problems(request, node, source, plan, inspected, answering)
    #
    # B178/B180: the node scripts and what else the product writes come from
    # this manager's own release, prepared with answers read out of the
    # archive's node.conf. Either missing stops the restore at the preview.
    #
    package: node_package.ReleasePackage | None = None
    try:
        package = package_of()
    except node_package.PackageError as exc:
        problems.append(f"this manager's node package cannot be used: {exc}")
    else:
        if package is None:
            problems.append(
                "this manager's CLI release carries no node package; install it with --node-package"
            )
    derived = ""
    try:
        derived = restore_answers.derive(source, request.cluster, publish_root)
    except restore_answers.AnswersError as exc:
        problems.append(str(exc))
    bound = {
        "request": request.as_dict(),
        "archive_sha256": _digest_file(archive),
        "target": {
            "os_release": inspected["os_release"],
            "interface": interface,
            "host_keys": inspected["host_keys"],
        },
        "plan": plan.summary(),
        "node_package": None if package is None else package.sha256,
        "answers": derived,
    }
    digest = hashlib.sha256(json.dumps(bound, sort_keys=True).encode()).hexdigest()
    return Checked(source, plan, inspected, digest, tuple(problems), package, derived)


def preview(
    root: Path,
    run: str,
    fingerprint_seen: str,
    cluster: Cluster,
    backup_root: Path,
    *,
    scan: Callable[[str], str] = scan_host_key,
    fingerprint_of: Callable[[str], str] = fingerprint,
    publish_root: Path,
    answering: Callable[[str], bool] = answers,
    progress: TextIO | None = None,
    session_for: Callable[[Path, Path], Session] = Session,
    package_of: Callable[[], node_package.ReleasePackage | None] = node_package.release_package,
    now: Callable[[], float] = time.time,
    checks: OverwriteChecks | None = None,
) -> dict[str, Any]:
    with _Held(run_directory(root, run), wait=True):
        return _preview(
            _unexpired(root, run, now()),
            fingerprint_seen,
            cluster,
            backup_root,
            scan=scan,
            fingerprint_of=fingerprint_of,
            publish_root=publish_root,
            answering=answering,
            progress=progress,
            session_for=session_for,
            package_of=package_of,
            checks=checks,
        )


def _preview(
    directory: Path,
    fingerprint_seen: str,
    cluster: Cluster,
    backup_root: Path,
    *,
    scan: Callable[[str], str],
    fingerprint_of: Callable[[str], str],
    publish_root: Path,
    answering: Callable[[str], bool],
    progress: TextIO | None,
    session_for: Callable[[Path, Path], Session],
    package_of: Callable[[], node_package.ReleasePackage | None],
    checks: OverwriteChecks | None,
) -> dict[str, Any]:
    request = Request.from_dict(read_json(directory / "request.json"))
    if fingerprint_seen and not FINGERPRINT.fullmatch(fingerprint_seen):
        raise RestoreError("the fingerprint is written as SHA256:<43 characters>")
    key = scan(request.target)
    if fingerprint_seen and fingerprint_of(key) != fingerprint_seen:
        raise RestoreError(
            f"{request.target} offers a host key whose fingerprint is not the one read on its "
            "console; nothing was sent to it"
        )
    if request.mode != "test":
        #
        # B184: a restore as the node is one operation whatever it lands on. A
        # target offering the archived host key is the node itself, and the
        # archive goes back over it (B172, B183); any other is a VM in its
        # place. Decided here, from the key just verified, and kept in the
        # run's request so the run is held to the same case.
        #
        source = read(archive_path(backup_root, node_of(cluster, request.node), request.archive))
        archived = source.entry(ARCHIVED_HOST_KEY)
        itself = archived is not None and _key(content(source, archived)) == _key(key.encode())
        if not fingerprint_seen and not itself:
            #
            # Without a fingerprint only the node itself is trusted: its archived
            # host key is the proof. A VM in its place is known only by the key
            # read on its console.
            #
            raise RestoreError(
                f"{request.target} does not offer {request.node}'s archived host key; for a new "
                "VM, give the fingerprint read on its console - nothing was sent to it"
            )
        mode: restore_plan.Mode = "overwrite" if itself else "new_vm"
        if mode != request.mode:
            request = dataclasses.replace(request, mode=mode)
            _write_json(directory / "request.json", request.as_dict())
    elif not fingerprint_seen:
        raise RestoreError("a test restore is a new VM; give the fingerprint read on its console")
    if request.mode == "overwrite" and checks is None:
        raise RestoreError("an overwrite needs the cluster's backup and status; none were given")
    known_hosts = directory / "known_hosts"
    known_hosts.write_text(f"{request.target} {key}\n", encoding="utf-8")
    known_hosts.chmod(0o600)
    # What the preview shows: the key's own fingerprint when none was given (the node itself).
    fingerprint_seen = fingerprint_seen or fingerprint_of(key)
    _write_json(directory / "target-key.json", {"key": key, "fingerprint": fingerprint_seen})
    session = session_for(directory / "key", known_hosts)
    checked = check(
        request,
        cluster,
        backup_root,
        session=session,
        publish_root=publish_root,
        answering=answering,
        progress=progress,
        package_of=package_of,
    )
    summary = {
        "run": request.run,
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
    summary["renumbered"] = renumbered(checked.source, checked.inspected)
    if request.mode == "overwrite" and checks is not None:
        summary["overwrite"] = _overwrite_standing(request, checks, progress)
    if checked.package is not None:
        summary["node_package"] = {
            "version": checked.package.version,
            "commit": checked.package.commit,
        }
    _write_json(directory / "preview.json", summary)
    return summary


ARCHIVED_HOST_KEY = "/etc/ssh/ssh_host_ed25519_key.pub"


def overwrite_checks(cluster_id: str, cluster: Cluster, policy: PathPolicy) -> OverwriteChecks:
    """The backup and the pair's reading an overwrite makes, as the backup job and deploy make them."""

    def backup() -> str | None:
        try:
            report = state_backup.run(
                cluster_id,
                cluster,
                policy.backup_identity,
                policy.backup_root,
                retention=backup_retention.read(cluster_id),
            )
        except (state_backup.BackupRunError, backup_retention.RetentionError) as exc:
            return str(exc)
        failed = [
            f"{node.name}: {node.error or node.outcome}"
            for node in report.nodes
            if node.outcome != "done"
        ]
        return None if not failed else "; ".join(failed)

    def standing(name: str) -> Standing:
        others = [node.name for node in cluster.nodes if node.name != name]
        neighbour = others[0] if len(others) == 1 else ", ".join(others)
        identity = policy.status_identity
        if identity is None:
            return Standing(None, neighbour, False, "no status_identity in the runtime policy")
        report = collect(cluster.nodes, lambda node: ask_node(node, identity), target=None)
        try:
            parsed = parse_status(report.as_envelope(cluster_id, request_id=new_request_id()))
            own = parsed.node(name).owns_vip
        except StatusError as exc:
            return Standing(None, neighbour, False, str(exc))
        raw = {entry["name"]: entry for entry in report.result.get("nodes", [])}
        entry = raw.get(neighbour) or {}
        status = entry.get("status") or {}
        haproxy = bool((status.get("haproxy") or {}).get("active"))
        keepalived = bool((status.get("keepalived") or {}).get("active"))
        healthy = bool(entry.get("status_ok")) and haproxy and keepalived
        detail = (
            ""
            if healthy
            else f"reachable {bool(entry.get('reachable'))}, HAProxy active {haproxy}, "
            f"keepalived active {keepalived}"
        )
        return Standing(own, neighbour, healthy, detail)

    return OverwriteChecks(backup=backup, standing=standing)


def _key(line: bytes) -> str:
    """A public key's type and body, without the comment."""

    return " ".join(line.decode("utf-8", "replace").split()[:2])


def _overwrite_standing(
    request: Request, checks: OverwriteChecks, progress: TextIO | None
) -> dict[str, Any]:
    """The backup and the pair, as the preview shows them. Not bound by the digest:
    both change on their own, and the run reads the pair again."""

    stream = progress or sys.stderr
    stream.write(f"state backup of {request.cluster}\n")
    backup_error = checks.backup()
    standing = checks.standing(request.node)
    return {
        "backup": "done" if backup_error is None else "failed",
        "backup_error": backup_error,
        "vip_owner": standing.vip_owner,
        "neighbour": standing.neighbour,
        "neighbour_healthy": standing.neighbour_healthy,
        "detail": standing.detail,
    }


def _overwrite_refusals(
    request: Request,
    previewed: dict[str, Any],
    checks: OverwriteChecks,
    *,
    backup_failed_ok: bool,
    break_traffic: bool,
) -> list[str]:
    """What stops an overwrite at the run unless the operator ticked it (B172)."""

    refusals: list[str] = []
    backup = previewed.get("overwrite", {})
    if backup.get("backup") != "done" and not backup_failed_ok:
        refusals.append(
            "no state backup could be taken before the overwrite; "
            "tick that you continue without one"
        )
    standing = checks.standing(request.node)
    if standing.vip_owner is not False and not standing.neighbour_healthy and not break_traffic:
        refusals.append(
            f"{request.node} may hold the VIP and {standing.neighbour} is not healthy "
            f"({standing.detail or 'no detail'}); this WILL break live traffic unless ticked"
        )
    return refusals


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


def _archived_host_key(source: RestoreSource) -> str | None:
    """The archived node's ed25519 host key as a known_hosts value, or None."""

    public = source.entry("/etc/ssh/ssh_host_ed25519_key.pub")
    if public is None:
        return None
    return " ".join(content(source, public).decode().split()[:2])


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
    publish_root: Path,
    package_of: Callable[[], node_package.ReleasePackage | None] = node_package.release_package,
    now: Callable[[], float] = time.time,
    checks: OverwriteChecks | None = None,
    backup_failed_ok: bool = False,
    break_traffic: bool = False,
    lock_root: Path = cluster_lock.DEFAULT_LOCK_ROOT,
) -> dict[str, Any]:
    """Carry out the previewed plan, holding the run's directory throughout.

    The hour is checked once, here at the start: a run that has begun is
    carried to its end however long its sessions take.

    The cluster's lock too, the one a deploy takes. The run's own directory
    lock only stops the same run twice; a deploy, or a second restore under
    another run ID, would otherwise read and change the same pair while this
    one rebuilds a node in it. Taken after the run's own lock and never
    waited for, like a deploy's: a busy cluster is a refusal before anything
    is written, not a queue.
    """

    with _Held(run_directory(root, run_id), wait=True):
        try:
            with cluster_lock.hold(cluster.cluster_id, operation="node_restore", root=lock_root):
                return _run(
                    _unexpired(root, run_id, now()),
                    run_id,
                    confirm,
                    cluster,
                    backup_root,
                    answering=answering,
                    progress=progress,
                    pause=pause,
                    rollback_seconds=rollback_seconds,
                    clock=clock,
                    session_for=session_for,
                    publish_root=publish_root,
                    package_of=package_of,
                    checks=checks,
                    backup_failed_ok=backup_failed_ok,
                    break_traffic=break_traffic,
                )
        except cluster_lock.LockBusy as exc:
            raise RestoreError(str(exc)) from exc


def _run(
    directory: Path,
    run_id: str,
    confirm: str,
    cluster: Cluster,
    backup_root: Path,
    *,
    answering: Callable[[str], bool],
    progress: TextIO | None,
    pause: float,
    rollback_seconds: int,
    clock: Clock,
    session_for: Callable[[Path, Path], Session],
    publish_root: Path,
    package_of: Callable[[], node_package.ReleasePackage | None],
    checks: OverwriteChecks | None,
    backup_failed_ok: bool,
    break_traffic: bool,
) -> dict[str, Any]:
    stream = progress or sys.stderr
    request = Request.from_dict(read_json(directory / "request.json"))
    previewed = read_json(directory / "preview.json")
    if (directory / "result.json").exists():
        raise RestoreError("this run has already been carried out; prepare a new one")
    session = session_for(directory / "key", directory / "known_hosts")
    checked = check(
        request,
        cluster,
        backup_root,
        session=session,
        publish_root=publish_root,
        answering=answering,
        progress=stream,
        package_of=package_of,
    )
    if checked.digest != previewed.get("digest"):
        raise RestoreError(
            "the archive, the target or the plan changed after the preview; preview again"
        )
    if checked.problems:
        raise RestoreError("; ".join(checked.problems))
    plan = checked.plan
    package = checked.package
    if package is None:
        raise RestoreError("this manager's CLI release carries no node package")
    if confirm != plan.hostname:
        raise RestoreError(f"confirm with the restored node's name, {plan.hostname}")
    overwrite = plan.mode == "overwrite"
    if overwrite:
        if checks is None:
            raise RestoreError(
                "an overwrite needs the cluster's backup and status; none were given"
            )
        refusals = _overwrite_refusals(
            request,
            previewed,
            checks,
            backup_failed_ok=backup_failed_ok,
            break_traffic=break_traffic,
        )
        if refusals:
            raise RestoreError("; ".join(refusals))

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
        "overwrite": overwrite,
        "keep": list(plan.from_package),
        "cluster": request.cluster,
        "node_package": {"version": package.version, "sha256": package.sha256},
        "answers": checked.answers,
        "traffic_log": plan.traffic_log,
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
    #
    # From here the target is written to. Whatever stops the run now is a
    # failure in the session it reached, recorded in result.json - never the
    # refusal the steps above give, which says nothing was written.
    #
    _write_json(directory / "started.json", {"at": time.time()})
    stage = "apply"
    try:
        stream.write(f"apply on {request.target}\n")
        carried = PlannedFile(
            path=f"{restore_agent.STATE}/{run_id}/{restore_agent.PACKAGE_FILE}",
            kind="file",
            mode=0o600,
            uid=0,
            gid=0,
            data=package.path.read_bytes(),
        )
        applied = session.call(
            request.target,
            apply_header,
            payload(checked.source, (*plan.files, carried)),
            progress=stream,
        )
        result["sessions"]["apply"] = {k: v for k, v in applied.items() if k != "ok"}
        if not applied.get("ok"):
            return finish_with(
                "failed",
                error=applied.get("error"),
                stage="apply",
                rolled_back=bool(applied.get("rolled_back")),
            )

        final = str(plan.address.ip)
        archived = None if plan.mode == "test" else _archived_host_key(checked.source)
        if plan.mode != "test" and archived is None:
            return finish_with("failed", error="the archive has no ed25519 host key", stage="apply")
        if plan.mode == "new_vm":
            # `apply` wrote the archive's host keys and reloaded sshd, so the VM on
            # its temporary address now answers with the node's key, not the one
            # verified at the preview. The network session is the first to meet it.
            with (directory / "known_hosts").open("a", encoding="utf-8") as stream_hosts:
                stream_hosts.write(f"{request.target} {archived}\n")
        if overwrite and not plan.network:
            # B183: the node's network is already the archive's; it is not applied again.
            stream.write("network unchanged; not applied\n")
            stage = "finish"
            return _finish(
                session,
                directory,
                checked,
                cluster,
                final,
                result,
                finish_with,
                stream,
                network=False,
            )

        stage = "network"
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

        key = read_json(directory / "target-key.json")["key"] if archived is None else archived
        with (directory / "known_hosts").open("a", encoding="utf-8") as stream_hosts:
            stream_hosts.write(f"{final} {key}\n")

        started = clock.now()
        clock.sleep(min(pause * 2, 6.0))
        reached = _wait_for(final, started + rollback_seconds - 30, answering, pause, clock)
        if not reached:
            stream.write(f"{final} did not answer; waiting for the rollback timer\n")
            clock.sleep(max(0.0, started + rollback_seconds + 20 - clock.now()))
            back = _wait_for(request.target, clock.now() + 60, answering, pause, clock)
            if back and overwrite:
                # The network is the node's again; its files are put back from its copy.
                undone = session.call(
                    request.target, {"op": "rollback", "run": run_id}, progress=stream
                )
                result["sessions"]["rollback"] = {k: v for k, v in undone.items() if k != "ok"}
                back = bool(undone.get("ok"))
            return finish_with(
                "failed",
                rolled_back=back,
                stage="network",
                error=f"{final} never answered; the "
                + ("node" if overwrite else "network")
                + " was "
                + ("rolled back" if back else "NOT confirmed rolled back - go to the console"),
            )

        stage = "finish"
        return _finish(
            session, directory, checked, cluster, final, result, finish_with, stream, network=True
        )
    except (RestoreError, OSError) as exc:
        result["sessions"].setdefault(stage, {})
        return finish_with("failed", error=str(exc), stage=stage)


def _finish(
    session: Session,
    directory: Path,
    checked: Checked,
    cluster: Cluster,
    final: str,
    result: dict[str, Any],
    finish_with: Callable[..., dict[str, Any]],
    stream: TextIO,
    *,
    network: bool,
) -> dict[str, Any]:
    plan = checked.plan
    stream.write(f"finish on {final}\n")
    finished = session.call(
        final,
        {
            "op": "finish",
            "run": directory.name,
            "certificates": list(cluster.certificate_ids),
            "keepalived": plan.keepalived,
            "overwrite": plan.mode == "overwrite",
            "network": network,
        },
        payload(checked.source, (plan.root_keys,)) if plan.root_keys else b"",
        progress=stream,
    )
    result["sessions"]["finish"] = {k: v for k, v in finished.items() if k != "ok"}
    if not finished.get("ok"):
        return finish_with(
            "failed",
            error=finished.get("error"),
            stage="finish",
            rolled_back=bool(finished.get("rolled_back")),
        )
    return finish_with("done", address=final, hostname=plan.hostname)


def discard(root: Path, run_id: str) -> bool:
    """Remove a run's directory unless a step is working in it; False when there was none.

    Nothing is sent to the target. The line pasted there stays until its
    `expiry-time`, and without the private half removed here nothing can use it.
    """

    if not restore_agent.RUN_ID.fullmatch(run_id):
        raise RestoreError("the run ID is not usable")
    directory = root / run_id
    if not directory.is_dir():
        return False
    _private_directory(directory)
    try:
        with _Held(directory, wait=False):
            shutil.rmtree(directory)
    except BlockingIOError as exc:
        raise RestoreError(f"run {run_id} is being worked on; wait for it to finish") from exc
    return True


def sweep(root: Path, now: float) -> list[str]:
    """Put away every run past its hour that no step holds; the runs removed whole.

    A run that began writing loses its key and plan at the hour and keeps its
    outcome for `status` until RESULT_KEPT; see `_retire`.
    """

    if not root.is_dir():
        return []
    removed = []
    for directory in sorted(root.iterdir()):
        if not directory.is_dir() or not restore_agent.RUN_ID.fullmatch(directory.name):
            continue
        try:
            if not expired(directory, now):
                continue
            with _Held(directory, wait=False):
                gone = _retire(directory, now)
        except (BlockingIOError, FileNotFoundError):
            continue
        if gone:
            removed.append(directory.name)
    return removed


def status(root: Path, run_id: str) -> dict[str, Any]:
    """How a run stands, read from its directory; nothing is changed.

    ``running``      a step holds the run's lock: it is working now
    ``finished``     the run wrote its outcome; `outcome`, `error` and `result`
                     are what `run` answered, or would have
    ``stopped``      it began writing to the target and left no outcome - the
                     helper was stopped mid-run; the target must be looked at
    ``not_started``  it never began writing: waiting, refused, or past its hour
    """

    if not restore_agent.RUN_ID.fullmatch(run_id):
        raise RestoreError("the run ID is not usable")
    directory = root / run_id
    if not directory.is_dir():
        raise RestoreError(
            f"there is no restore run {run_id}; a run's outcome is kept for "
            f"{RESULT_KEPT // 86400} days, and a discarded run is gone at once"
        )
    _private_directory(directory)
    try:
        held = _Held(directory, wait=False)
    except BlockingIOError:
        return {"run": run_id, "state": "running"}
    with held:
        if (directory / "result.json").exists():
            carried = read_json(directory / "result.json")
            error = carried.get("error")
            return {
                "run": run_id,
                "state": "finished",
                "outcome": "done" if carried.get("outcome") == "done" else "failed",
                "error": None if error is None else str(error),
                "result": {k: v for k, v in carried.items() if k not in {"outcome", "error"}},
            }
        if (directory / "started.json").exists():
            return {"run": run_id, "state": "stopped"}
        return {"run": run_id, "state": "not_started"}
