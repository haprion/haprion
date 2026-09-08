"""Manager-initiated, bounded mirroring of node traffic logs."""

from __future__ import annotations

import fcntl
import json
import os
import re
import selectors
import stat
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

MAX_CONFIG_BYTES = 1024 * 1024
MAX_HEADER_BYTES = 4096
MAX_SEND = 8 * 1024 * 1024
MAX_STDERR = 64 * 1024
MAX_MIRROR_BYTES = 256 * 1024 * 1024
RETENTION_DAYS = 14
SSH_TIMEOUT_SECONDS = 30
ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
NODE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
USER = re.compile(r"^[a-z_][a-z0-9_-]{0,30}$")
HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.:-]{0,252}$")


class CollectorError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class NodeTarget:
    cluster: str
    node: str
    host: str


@dataclass(frozen=True, slots=True)
class CollectorConfig:
    user: str
    key: Path
    known_hosts: Path
    mirror: Path
    staging: Path
    nodes: tuple[NodeTarget, ...]


@dataclass(frozen=True, slots=True)
class Response:
    size: int
    offset: int
    sent: int
    eof: bool
    reset: bool
    skipped_bytes: int
    payload: bytes


Fetch = Callable[[NodeTarget, date, int], Response]


def _regular(path: Path, *, maximum: int | None = None) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise CollectorError(f"cannot stat {path.name}: {exc}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise CollectorError(f"{path.name} is not a regular non-symlink")
    if maximum is not None and metadata.st_size > maximum:
        raise CollectorError(f"{path.name} exceeds its size limit")
    return metadata


def _directory(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise CollectorError(f"cannot stat {path.name}: {exc}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise CollectorError(f"{path.name} is not a directory or is a symlink")


def _absolute(value: Any, field: str) -> Path:
    if not isinstance(value, str) or not value:
        raise CollectorError(f"{field} must be a non-empty path")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise CollectorError(f"{field} must be absolute and contain no '..'")
    return path


def load_config(path: Path, *, require_secure: bool = True) -> CollectorConfig:
    metadata = _regular(path, maximum=MAX_CONFIG_BYTES)
    if require_secure and (metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o027):
        raise CollectorError("collector configuration must be root-owned and mode 640 or stricter")
    try:
        value = json.loads(path.read_bytes())
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CollectorError(f"cannot read collector configuration: {exc}") from exc
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "user",
        "key",
        "known_hosts",
        "mirror",
        "staging",
        "nodes",
    }:
        raise CollectorError("collector configuration has unexpected or missing fields")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise CollectorError("collector configuration schema_version must be 1")
    user = value["user"]
    if not isinstance(user, str) or USER.fullmatch(user) is None:
        raise CollectorError("collector user is invalid")
    raw_nodes = value["nodes"]
    if not isinstance(raw_nodes, list) or not raw_nodes:
        raise CollectorError("collector nodes must be a non-empty list")
    nodes: list[NodeTarget] = []
    for raw in raw_nodes:
        if not isinstance(raw, dict) or set(raw) != {"cluster", "node", "host"}:
            raise CollectorError("collector node has unexpected or missing fields")
        cluster, node, host = raw["cluster"], raw["node"], raw["host"]
        if not isinstance(cluster, str) or ID.fullmatch(cluster) is None:
            raise CollectorError("collector node cluster is invalid")
        if not isinstance(node, str) or NODE.fullmatch(node) is None:
            raise CollectorError("collector node name is invalid")
        if not isinstance(host, str) or HOST.fullmatch(host) is None:
            raise CollectorError("collector node host is invalid")
        nodes.append(NodeTarget(cluster, node, host))
    identities = [(item.cluster, item.node) for item in nodes]
    if len(set(identities)) != len(identities):
        raise CollectorError("collector nodes contain a duplicate cluster/node")
    if len({item.host for item in nodes}) != len(nodes):
        raise CollectorError("collector nodes contain a duplicate host")
    return CollectorConfig(
        user=user,
        key=_absolute(value["key"], "key"),
        known_hosts=_absolute(value["known_hosts"], "known_hosts"),
        mirror=_absolute(value["mirror"], "mirror"),
        staging=_absolute(value["staging"], "staging"),
        nodes=tuple(nodes),
    )


def _bounded_ssh(argv: list[str]) -> tuple[int, bytes, bytes]:
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)  # noqa: S603
    if process.stdout is None or process.stderr is None:  # pragma: no cover - PIPE guarantees it
        process.kill()
        raise CollectorError("cannot open SSH output pipes")
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    held = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + SSH_TIMEOUT_SECONDS
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise CollectorError("SSH request timed out")
            ready = selector.select(remaining)
            if not ready:
                raise CollectorError("SSH request timed out")
            for key, _ in ready:
                chunk = os.read(key.fd, 64 * 1024)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                bucket = held[key.data]
                bucket.extend(chunk)
                limit = MAX_HEADER_BYTES + MAX_SEND if key.data == "stdout" else MAX_STDERR
                if len(bucket) > limit:
                    raise CollectorError(f"SSH {key.data} exceeds its size limit")
        return process.wait(), bytes(held["stdout"]), bytes(held["stderr"])
    except BaseException:
        process.kill()
        process.wait()
        raise
    finally:
        selector.close()


def _parse_response(raw: bytes, wanted: date, offset: int) -> Response:
    try:
        header_line, payload = raw.split(b"\n", 1)
    except ValueError as exc:
        raise CollectorError("node response has no header") from exc
    if len(header_line) > MAX_HEADER_BYTES:
        raise CollectorError("node response header is too large")
    try:
        header = json.loads(header_line)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise CollectorError("node response header is not JSON") from exc
    expected = {"file", "size", "offset", "sent", "eof", "reset", "skipped_bytes"}
    if not isinstance(header, dict) or set(header) != expected:
        raise CollectorError("node response header has unexpected or missing fields")
    if header["file"] != wanted.isoformat() or header["offset"] != offset:
        raise CollectorError("node response does not match the request")
    for field in ("size", "offset", "sent", "skipped_bytes"):
        value = header[field]
        if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 2**63 - 1:
            raise CollectorError(f"node response {field} is invalid")
    if not isinstance(header["eof"], bool) or not isinstance(header["reset"], bool):
        raise CollectorError("node response flags are invalid")
    if header["sent"] != len(payload) or len(payload) > MAX_SEND:
        raise CollectorError("node response payload length is invalid")
    if payload and not payload.endswith(b"\n"):
        raise CollectorError("node response ends in a partial record")
    advanced = offset + header["skipped_bytes"] + len(payload)
    if header["reset"]:
        if (
            payload
            or header["sent"]
            or header["skipped_bytes"]
            or not header["eof"]
            or header["size"] >= offset
        ):
            raise CollectorError("node reset response is inconsistent")
    elif advanced > header["size"]:
        raise CollectorError("node response advances beyond its file size")
    elif header["eof"] != (advanced == header["size"]):
        raise CollectorError("node response eof flag is inconsistent")
    return Response(
        size=header["size"],
        offset=header["offset"],
        sent=header["sent"],
        eof=header["eof"],
        reset=header["reset"],
        skipped_bytes=header["skipped_bytes"],
        payload=payload,
    )


def ssh_fetch(config: CollectorConfig, target: NodeTarget, wanted: date, offset: int) -> Response:
    argv = [
        "/usr/bin/ssh",
        "-T",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=10",
        "-o",
        "ConnectionAttempts=1",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={config.known_hosts}",
        "-i",
        str(config.key),
        "-l",
        config.user,
        "--",
        target.host,
        f"{wanted.isoformat()} {offset}",
    ]
    code, stdout, _stderr = _bounded_ssh(argv)
    if code != 0:
        raise CollectorError(f"SSH request failed with exit {code}")
    return _parse_response(stdout, wanted, offset)


def _part(config: CollectorConfig, target: NodeTarget, wanted: date) -> Path:
    return config.staging / f"{target.cluster}--{target.node}--{wanted.isoformat()}.jsonl"


def _safe_size(path: Path) -> int:
    try:
        return _regular(path, maximum=MAX_MIRROR_BYTES).st_size
    except CollectorError:
        if path.exists() or path.is_symlink():
            raise
        return 0


def _replace(path: Path, content: bytes, mode: int = 0o640) -> None:
    temporary = path.parent / f".{path.name}.new-{os.getpid()}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(temporary, flags, mode)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _append(path: Path, payload: bytes) -> None:
    if not payload:
        return
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise CollectorError("staging part is not a regular file")
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise CollectorError("short write to staging part")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _update_day(config: CollectorConfig, target: NodeTarget, wanted: date, fetch: Fetch) -> bool:
    path = _part(config, target, wanted)
    offset = _safe_size(path)
    response = fetch(target, wanted, offset)
    if response.reset:
        _replace(path, b"", 0o600)
        return False
    if response.skipped_bytes:
        # A local cursor in the middle of a remote record can only come from a
        # damaged/replaced file. Rebuild the day rather than preserving a hole.
        _replace(path, b"", 0o600)
        return False
    if offset + len(response.payload) > MAX_MIRROR_BYTES:
        raise CollectorError("one node day exceeds the mirror size limit")
    _append(path, response.payload)
    return response.eof


def _assemble(config: CollectorConfig, target: NodeTarget, days: tuple[date, ...]) -> None:
    destination = config.mirror / f"{target.cluster}--{target.node}.jsonl"
    temporary = config.staging / f".{target.cluster}--{target.node}.mirror-{os.getpid()}"
    total = 0
    try:
        with temporary.open("xb") as output:
            os.chmod(temporary, 0o600)
            for wanted in days:
                path = _part(config, target, wanted)
                if not path.exists() and not path.is_symlink():
                    continue
                metadata = _regular(path, maximum=MAX_MIRROR_BYTES)
                total += metadata.st_size
                if total > MAX_MIRROR_BYTES:
                    raise CollectorError("node mirror exceeds its size limit")
                with path.open("rb") as source:
                    while chunk := source.read(1024 * 1024):
                        output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, 0o640)
        os.replace(temporary, destination)
        directory = os.open(config.mirror, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary.exists() or temporary.is_symlink():
            temporary.unlink()


def _meta_path(config: CollectorConfig, target: NodeTarget) -> Path:
    return config.mirror / f"{target.cluster}--{target.node}.meta.json"


def _previous_success(path: Path) -> str | None:
    try:
        value = json.loads(path.read_bytes())
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    success = value.get("last_success") if isinstance(value, dict) else None
    return success if isinstance(success, str) else None


def _write_meta(
    config: CollectorConfig,
    target: NodeTarget,
    *,
    attempted: datetime,
    outcome: str,
    success: bool,
) -> None:
    path = _meta_path(config, target)
    previous = _previous_success(path)
    stamp = attempted.isoformat()
    content = json.dumps(
        {
            "schema_version": 1,
            "cluster": target.cluster,
            "node": target.node,
            "last_attempt": stamp,
            "last_success": stamp if success else previous,
            "outcome": outcome,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    _replace(path, content + b"\n")


def collect_node(
    config: CollectorConfig,
    target: NodeTarget,
    *,
    now: datetime,
    fetch: Fetch,
) -> None:
    today = now.date()
    days = tuple(today - timedelta(days=offset) for offset in reversed(range(RETENTION_DAYS)))
    keep = {item.isoformat() for item in days}
    prefix = f"{target.cluster}--{target.node}--"
    for path in config.staging.glob(f"{prefix}*.jsonl"):
        day = path.name[len(prefix) : -len(".jsonl")]
        if day not in keep:
            _regular(path, maximum=MAX_MIRROR_BYTES)
            path.unlink()

    try:
        current_complete = _update_day(config, target, today, fetch)
        # Bootstrap/catch-up progresses one closed day per run, while current
        # traffic is always fetched first. A large backlog therefore cannot
        # starve the last minute before an incident.
        if current_complete:
            for wanted in days[:-1]:
                marker = config.staging / f"{prefix}{wanted.isoformat()}.done"
                if marker.exists() or marker.is_symlink():
                    _regular(marker, maximum=1)
                    continue
                if _update_day(config, target, wanted, fetch):
                    _replace(marker, b"", 0o600)
                break
        _assemble(config, target, days)
        _write_meta(config, target, attempted=now, outcome="ok", success=True)
    except (CollectorError, OSError) as exc:
        _write_meta(
            config,
            target,
            attempted=now,
            outcome=type(exc).__name__.lower(),
            success=False,
        )
        raise


def collect(
    config: CollectorConfig, *, now: datetime | None = None, fetch: Fetch | None = None
) -> int:
    _directory(config.mirror)
    _directory(config.staging)
    lock_path = config.staging / ".collector.lock"
    lock_flags = os.O_RDWR | os.O_APPEND | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
    lock_flags |= getattr(os, "O_NOFOLLOW", 0)
    lock_descriptor = os.open(lock_path, lock_flags, 0o600)
    with os.fdopen(lock_descriptor, "a+b") as lock:
        if not stat.S_ISREG(os.fstat(lock.fileno()).st_mode):
            raise CollectorError("collector lock is not a regular file")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return 0
        attempted = now or datetime.now(UTC)
        failures = 0
        for target in config.nodes:
            selected = fetch or (lambda node, day, offset: ssh_fetch(config, node, day, offset))
            try:
                collect_node(config, target, now=attempted, fetch=selected)
            except (CollectorError, OSError) as exc:
                print(f"{target.cluster}/{target.node}: {exc}", file=sys.stderr)
                failures += 1
        return 1 if failures else 0


def _entry() -> None:
    if len(sys.argv) != 3 or sys.argv[1] != "--config":
        print("usage: haproxy-ui-traffic-collector --config <path>", file=sys.stderr)
        raise SystemExit(64)
    try:
        config = load_config(Path(sys.argv[2]))
        code = collect(config)
    except (CollectorError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(65) from exc
    raise SystemExit(code)
