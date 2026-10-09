"""UI-independent, manager-initiated mirroring of node traffic logs."""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import re
import selectors
import stat
import subprocess
import sys
import time
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

import psycopg

from haproxy_mgmt.proxy_model import NAME as OBJECT_NAME
from haproxy_mgmt.proxy_model import WAF_DECIDING_RULES, waf_field

MAX_CONFIG_BYTES = 1024 * 1024
MAX_HEADER_BYTES = 4096
MAX_SEND = 8 * 1024 * 1024
MAX_STDERR = 64 * 1024
MAX_RECORD_BYTES = 16 * 1024
DATABASE_BATCH_ROWS = 1000
MAX_TIMESTAMP = 253402300799  # 9999-12-31T23:59:59Z, the last second datetime holds
#
# What the manager keeps when it has no database to ask. The number is B125's:
# it was the product's history window back when the mirror was the store and the
# page read these files directly. With the records in PostgreSQL the database
# decides how far back anything can be read, so this is the fallback for a
# mirror-only installation and for a run that cannot reach the database - never
# a second window kept in step by hand.
#
RETENTION_DAYS = 14
#
# How many nodes one run fetches from at a time: a bound on the SSH sessions
# open at once, not on how many nodes there may be.
#
MAX_PARALLEL_NODES = 8
MIRROR_MARGIN_DAYS = 1
SSH_TIMEOUT_SECONDS = 30
# A node names its day file from its own UTC clock.  During the first minutes
# after the manager has crossed midnight, the node may therefore still append
# to what the manager calls yesterday.  The one-minute timer gets several
# independent reads before this expires; only after the grace may EOF make the
# closed day immutable locally.
CLOSED_DAY_GRACE = timedelta(minutes=5)
ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
DATABASE = re.compile(r"^[a-z][a-z0-9_]{0,62}$")
NODE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
USER = re.compile(r"^[a-z_][a-z0-9_-]{0,30}$")
HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.:-]{0,252}$")


class CollectorError(ValueError):
    pass


class SSHError(CollectorError):
    pass


class ProtocolError(CollectorError):
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
    database: str | None = None
    database_socket: str | None = None


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
    base_fields = {
        "schema_version",
        "user",
        "key",
        "known_hosts",
        "mirror",
        "staging",
        "nodes",
    }
    if not isinstance(value, dict):
        raise CollectorError("collector configuration has unexpected or missing fields")
    schema_version = value.get("schema_version")
    expected = base_fields if schema_version == 1 else base_fields | {"database", "database_socket"}
    if set(value) != expected:
        raise CollectorError("collector configuration has unexpected or missing fields")
    if type(schema_version) is not int or schema_version not in {1, 2}:
        raise CollectorError("collector configuration schema_version must be 1 or 2")
    database: str | None = None
    database_socket: str | None = None
    if schema_version == 2:
        database = value["database"]
        database_socket = value["database_socket"]
        if not isinstance(database, str) or DATABASE.fullmatch(database) is None:
            raise CollectorError("collector database is invalid")
        if (
            not isinstance(database_socket, str)
            or not Path(database_socket).is_absolute()
            or ".." in Path(database_socket).parts
        ):
            raise CollectorError("collector database_socket is invalid")
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
        database=database,
        database_socket=database_socket,
    )


def _bounded_ssh(argv: list[str]) -> tuple[int, bytes, bytes]:
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)  # noqa: S603
    if process.stdout is None or process.stderr is None:  # pragma: no cover - PIPE guarantees it
        process.kill()
        raise SSHError("cannot open SSH output pipes")
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    held = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + SSH_TIMEOUT_SECONDS
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SSHError("SSH request timed out")
            ready = selector.select(remaining)
            if not ready:
                raise SSHError("SSH request timed out")
            for key, _ in ready:
                chunk = os.read(key.fd, 64 * 1024)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                bucket = held[key.data]
                bucket.extend(chunk)
                limit = MAX_HEADER_BYTES + MAX_SEND if key.data == "stdout" else MAX_STDERR
                if len(bucket) > limit:
                    raise SSHError(f"SSH {key.data} exceeds its size limit")
        return process.wait(), bytes(held["stdout"]), bytes(held["stderr"])
    except BaseException:
        process.kill()
        process.wait()
        raise
    finally:
        selector.close()
        #
        # `Popen` hands out two pipe objects and closes neither. The child is
        # reaped by `wait`, but the descriptors live until the garbage collector
        # gets to them, so a run that fetches many node-days holds far more open
        # files than it needs. Found by R3, where the leak surfaced as a
        # ResourceWarning on every fetch.
        #
        for pipe in (process.stdout, process.stderr):
            if pipe is not None:
                pipe.close()


def _parse_response(raw: bytes, wanted: date, offset: int) -> Response:
    try:
        header_line, payload = raw.split(b"\n", 1)
    except ValueError as exc:
        raise ProtocolError("node response has no header") from exc
    if len(header_line) > MAX_HEADER_BYTES:
        raise ProtocolError("node response header is too large")
    try:
        header = json.loads(header_line)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("node response header is not JSON") from exc
    expected = {"file", "size", "offset", "sent", "eof", "reset", "skipped_bytes"}
    if not isinstance(header, dict) or set(header) != expected:
        raise ProtocolError("node response header has unexpected or missing fields")
    if header["file"] != wanted.isoformat() or header["offset"] != offset:
        raise ProtocolError("node response does not match the request")
    for field in ("size", "offset", "sent", "skipped_bytes"):
        value = header[field]
        if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 2**63 - 1:
            raise ProtocolError(f"node response {field} is invalid")
    if not isinstance(header["eof"], bool) or not isinstance(header["reset"], bool):
        raise ProtocolError("node response flags are invalid")
    if header["sent"] != len(payload) or len(payload) > MAX_SEND:
        raise ProtocolError("node response payload length is invalid")
    if payload and not payload.endswith(b"\n"):
        raise ProtocolError("node response ends in a partial record")
    advanced = offset + header["skipped_bytes"] + len(payload)
    if header["reset"]:
        if (
            payload
            or header["sent"]
            or header["skipped_bytes"]
            or not header["eof"]
            or header["size"] >= offset
        ):
            raise ProtocolError("node reset response is inconsistent")
    elif advanced > header["size"]:
        raise ProtocolError("node response advances beyond its file size")
    elif header["eof"] != (advanced == header["size"]):
        raise ProtocolError("node response eof flag is inconsistent")
    return Response(
        size=header["size"],
        offset=header["offset"],
        sent=header["sent"],
        eof=header["eof"],
        reset=header["reset"],
        skipped_bytes=header["skipped_bytes"],
        payload=payload,
    )


def _ssh_argv(config: CollectorConfig, target: NodeTarget, request: str) -> list[str]:
    return [
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
        request,
    ]


def ssh_fetch(config: CollectorConfig, target: NodeTarget, wanted: date, offset: int) -> Response:
    argv = _ssh_argv(config, target, f"{wanted.isoformat()} {offset}")
    try:
        code, stdout, _stderr = _bounded_ssh(argv)
    except OSError as exc:
        raise SSHError(f"cannot run SSH request: {exc}") from exc
    if code != 0:
        raise SSHError(f"SSH request failed with exit {code}")
    return _parse_response(stdout, wanted, offset)


def _part(config: CollectorConfig, target: NodeTarget, wanted: date) -> Path:
    return config.staging / f"{target.cluster}--{target.node}--{wanted.isoformat()}.jsonl"


def _safe_size(path: Path) -> int:
    try:
        return _regular(path).st_size
    except CollectorError:
        if path.exists() or path.is_symlink():
            raise
        return 0


def _replace(path: Path, content: bytes, mode: int = 0o640) -> None:
    temporary = path.parent / f".{path.name}.new-{os.getpid()}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(temporary, flags, mode)
    temporary_exists = True
    try:
        try:
            os.fchmod(descriptor, mode)
            with os.fdopen(descriptor, "wb", closefd=False) as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            os.close(descriptor)
        os.replace(temporary, path)
        temporary_exists = False
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary_exists:
            temporary.unlink(missing_ok=True)


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


def _update_day(
    config: CollectorConfig, target: NodeTarget, wanted: date, fetch: Fetch
) -> tuple[bool, int]:
    path = _part(config, target, wanted)
    offset = _safe_size(path)
    response = fetch(target, wanted, offset)
    if response.reset:
        _replace(path, b"", 0o600)
        return False, response.size
    if response.skipped_bytes:
        # A local cursor in the middle of a remote record can only come from a
        # damaged/replaced file. Rebuild the day rather than preserving a hole.
        _replace(path, b"", 0o600)
        return False, response.size
    _append(path, response.payload)
    return response.eof, response.size - _safe_size(path)


def _assemble(config: CollectorConfig, target: NodeTarget, days: tuple[date, ...]) -> None:
    destination = config.mirror / f"{target.cluster}--{target.node}.jsonl"
    #
    # Beside the destination, never in staging. `rename` is atomic within one
    # filesystem, and the two directories deliberately share a parent - but the
    # unit hands each of them to systemd as its own `ReadWritePaths` entry, and
    # systemd bind-mounts each entry separately. A rename between two bind
    # mounts is EXDEV even when one filesystem backs both, which is exactly how
    # this failed on the first real run: four nodes fetched, four mirrors
    # refused with "Invalid cross-device link". Staging a temporary file in the
    # directory it will be renamed into is the ordinary idiom anyway, and it is
    # what `_replace` beside this already does.
    #
    temporary = config.mirror / f".{target.cluster}--{target.node}.mirror-{os.getpid()}"
    try:
        with temporary.open("xb") as output:
            os.chmod(temporary, 0o600)
            for wanted in days:
                path = _part(config, target, wanted)
                if not path.exists() and not path.is_symlink():
                    continue
                _regular(path)
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


def _drop_mirror(config: CollectorConfig, target: NodeTarget) -> None:
    destination = config.mirror / f"{target.cluster}--{target.node}.jsonl"
    if destination.exists() or destination.is_symlink():
        _regular(destination)
        destination.unlink()


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
    current_complete: bool | None = None,
    remaining_bytes: int | None = None,
    pending_days: int | None = None,
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
            "current_day": attempted.astimezone(UTC).date().isoformat(),
            "current_complete": current_complete,
            "remaining_bytes": remaining_bytes,
            "pending_days": pending_days,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    _replace(path, content + b"\n")


def _failure_outcome(exc: CollectorError | OSError) -> str:
    if isinstance(exc, SSHError):
        return "ssh"
    if isinstance(exc, ProtocolError):
        return "protocol"
    return "disk"


def collect_node(
    config: CollectorConfig,
    target: NodeTarget,
    *,
    now: datetime,
    fetch: Fetch,
    window: int = RETENTION_DAYS,
) -> None:
    utc_now = now.astimezone(UTC)
    today = utc_now.date()
    days = tuple(today - timedelta(days=offset) for offset in reversed(range(window)))
    keep = {item.isoformat() for item in days}
    prefix = f"{target.cluster}--{target.node}--"
    #
    # Both kinds of leftover, or staging grows for ever: the parts are the day
    # data, and the markers are the empty files that say a closed day is
    # complete. Pruning only the parts left one marker per node-day behind, and
    # nothing ever removed them.
    #
    for suffix, maximum in ((".jsonl", None), (".done", 1)):
        for path in config.staging.glob(f"{prefix}*{suffix}"):
            day = path.name[len(prefix) : -len(suffix)]
            if day not in keep:
                _regular(path, maximum=maximum)
                path.unlink()
                if suffix == ".jsonl":
                    checkpoint = _database_checkpoint(config, path)
                    if checkpoint.exists() or checkpoint.is_symlink():
                        _regular(checkpoint, maximum=32)
                        checkpoint.unlink()

    try:
        current_complete, remaining_bytes = _update_day(config, target, today, fetch)
        # Bootstrap/catch-up progresses one closed day per run, while current
        # traffic is always fetched first. A large backlog therefore cannot
        # starve the last minute before an incident.
        # One block for today and one for older data, even while today grows:
        # at most two MAX_SEND responses and two bounded SSH calls per node.
        # Neither backlog can starve the other.
        for wanted in days[:-1]:
            marker = config.staging / f"{prefix}{wanted.isoformat()}.done"
            if marker.exists() or marker.is_symlink():
                _regular(marker, maximum=1)
                continue
            complete, _ = _update_day(config, target, wanted, fetch)
            yesterday_still_open = (
                wanted == today - timedelta(days=1)
                and utc_now - datetime.combine(today, datetime.min.time(), UTC) < CLOSED_DAY_GRACE
            )
            if complete and not yesterday_still_open:
                _replace(marker, b"", 0o600)
            break
        #
        # The joined file is for a reader of files. With the database as the
        # reader (schema 2) nothing reads it: the interface asks PostgreSQL and
        # looks at the metadata beside it for freshness, and the import reads
        # the day parts in staging. Joining every retained day into it on every
        # run rewrote the whole history once a minute for no one (review
        # 2026-09-30, R2), so it is not written, and one left from before is
        # removed.
        #
        if config.database is None:
            _assemble(config, target, days)
        else:
            _drop_mirror(config, target)
        pending_days = sum(
            not (config.staging / f"{prefix}{wanted.isoformat()}.done").exists()
            for wanted in days[:-1]
        )
        _write_meta(
            config,
            target,
            attempted=now,
            outcome="ok",
            success=True,
            current_complete=current_complete,
            remaining_bytes=remaining_bytes,
            pending_days=pending_days,
        )
    except (CollectorError, OSError) as exc:
        _write_meta(
            config,
            target,
            attempted=now,
            outcome=_failure_outcome(exc),
            success=False,
        )
        raise


def _retire(config: CollectorConfig, *, now: datetime, window: int = RETENTION_DAYS) -> None:
    """Let what a node left behind when it left inventory die of old age.

    Nothing is deleted while it could still be worth reading. A mirror is
    rewritten on every successful run, so its modification time is when the
    manager last heard from that node; once that is a whole retention window
    old, every record in the file is older than the node's own retention too -
    the data no longer exists at the source and the copy is a museum piece.

    Staging is left to `collect_node`, which prunes by the day in the name and
    therefore drains a retired node's parts on the same window without needing
    to know that the node is gone.
    """

    keep = set()
    for target in config.nodes:
        keep.add(f"{target.cluster}--{target.node}.jsonl")
        keep.add(f"{target.cluster}--{target.node}.meta.json")
    cutoff = (now - timedelta(days=window)).timestamp()
    for path in config.mirror.iterdir():
        if path.name in keep or path.name.startswith("."):
            continue
        if not path.name.endswith((".jsonl", ".meta.json")):
            continue
        try:
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_mtime >= cutoff:
                continue
            path.unlink()
        except OSError as exc:
            print(f"retired mirror {path.name}: {exc}", file=sys.stderr)


def _retire_staging(
    config: CollectorConfig, *, now: datetime, window: int = RETENTION_DAYS
) -> None:
    """The same window, applied to parts and markers no active node claims."""

    keep = {f"{target.cluster}--{target.node}--" for target in config.nodes}
    cursors = {_waf_cursor_path(config, target).name for target in config.nodes}
    oldest = (now.date() - timedelta(days=window - 1)).isoformat()
    for path in config.staging.iterdir():
        name = path.name
        if name.endswith(".waf-cursor") and name not in cursors:
            #
            # A node no longer in inventory. Should it come back, its journal is
            # read again from the start and nothing is stored twice.
            #
            try:
                if stat.S_ISREG(path.lstat().st_mode):
                    path.unlink()
            except OSError as exc:
                print(f"retired cursor {name}: {exc}", file=sys.stderr)
            continue
        if name.startswith(".") or not name.endswith((".jsonl", ".done")):
            continue
        if any(name.startswith(prefix) for prefix in keep):
            continue
        day = name.rsplit("--", 1)[-1].rsplit(".", 1)[0]
        if len(day) != 10 or day >= oldest:
            continue
        try:
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode):
                continue
            path.unlink()
        except OSError as exc:
            print(f"retired part {name}: {exc}", file=sys.stderr)


def _database_checkpoint(config: CollectorConfig, part: Path) -> Path:
    return config.staging / f".{part.name}.database-offset"


def _checkpoint_offset(path: Path, *, size: int) -> int:
    try:
        raw = _read_small_file(path, 32)
        offset = int(raw)
    except (OSError, ValueError):
        return 0
    return offset if 0 <= offset <= size else 0


def _read_small_file(path: Path, maximum: int) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
            raise CollectorError("database checkpoint is invalid")
        return os.read(descriptor, maximum)
    finally:
        os.close(descriptor)


def _database_row(cluster: str, node: str, line: bytes) -> tuple[Any, ...]:
    if not line or len(line) > MAX_RECORD_BYTES:
        raise CollectorError("traffic record exceeds its size limit")
    try:
        value = json.loads(line)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise CollectorError("traffic record is not JSON") from exc
    if not isinstance(value, dict) or value.get("schema") != 1:
        raise CollectorError("traffic record has an unsupported schema")

    def number(name: str, *, low: int = -1, high: int = 2**63 - 1) -> int:
        item = value.get(name)
        if not isinstance(item, int) or isinstance(item, bool) or not low <= item <= high:
            raise CollectorError(f"traffic record {name} is invalid")
        return item

    def text(name: str, maximum: int) -> str:
        item = value.get(name)
        #
        # A NUL is legal JSON and illegal in a PostgreSQL text column; letting
        # it through makes COPY refuse the whole batch, which is the permanent
        # stop this function exists to prevent. The record is unusable here.
        #
        if not isinstance(item, str) or len(item) > maximum or "\0" in item:
            raise CollectorError(f"traffic record {name} is invalid")
        return item

    #
    # Bounded to what `datetime` can hold, so an absurd stamp is this
    # function's refusal and not an OSError or ValueError two lines later,
    # which nothing above catches per record.
    #
    stamp = number("at", low=0, high=MAX_TIMESTAMP)
    request = value.get("request", 0)
    if not isinstance(request, int) or isinstance(request, bool) or request < 0:
        raise CollectorError("traffic record request is invalid")
    #
    # Tolerated rather than required, as `request` is: a record written before
    # access rules existed has no field, and that means what an empty one does
    # - no rule met the request (migration 0050, B227).
    #
    if "rule" not in value:
        value["rule"] = ""
    identity = hashlib.sha256(cluster.encode() + b"\0" + node.encode() + b"\0" + line).digest()
    return (
        identity,
        cluster,
        node,
        datetime.fromtimestamp(stamp, UTC),
        request,
        text("client", 64),
        text("method", 16),
        text("host", 253),
        text("path", 8192),
        text("frontend", 128),
        text("backend", 128),
        text("server", 128),
        number("status", low=0, high=999),
        number("request_time"),
        number("queue_time"),
        number("connect_time"),
        number("response_time"),
        number("total_time"),
        number("bytes", low=0),
        text("rule", MAX_RULE_LENGTH),
        _waf_rules(value.get("waf_rules")),
        _waf_score(value.get("waf_score")),
        _waf_id(value.get("waf_id")),
    )


#
# What the WAF engine found (migration 0051, B233). Read leniently, unlike the
# fields above: a record is the traffic a site received, and an odd value in
# what the engine said about it is no reason to lose the record. A field that
# is absent - a record from before the engine, or from an object it does not
# see - means nothing was found.
#
WAF_RULE_ID = re.compile(r"[0-9]{6}")
MAX_WAF_RULES = 1024
MAX_WAF_SCORE = 100000


def _waf_rules(item: Any) -> str:
    """Whole six-digit rule IDs only, within the column's bound.

    HAProxy cuts the list at the bound, which can leave half an ID at its end;
    that half, and anything else that is not an ID, is dropped rather than
    stored as one.
    """

    if not isinstance(item, str):
        return ""
    kept: list[str] = []
    length = 0
    for rule in item.split(","):
        if not WAF_RULE_ID.fullmatch(rule):
            continue
        length += len(rule) + (1 if kept else 0)
        if length > MAX_WAF_RULES:
            break
        kept.append(rule)
    return ",".join(kept)


def _waf_score(item: Any) -> int:
    """The anomaly score: a number when the engine answered, empty when it did not."""

    if not isinstance(item, int) or isinstance(item, bool) or item < 0:
        return 0
    return min(item, MAX_WAF_SCORE)


#
# `<object>.<uuid>`, as the generator sets it; read only for its form here.
#
WAF_ID = re.compile(r"[A-Za-z0-9_.-]{1,96}")


def _waf_id(item: Any) -> str:
    """The engine's transaction ID (migration 0052), or empty where there is none."""

    if not isinstance(item, str) or WAF_ID.fullmatch(item) is None:
        return ""
    return item


#
# The column's own bound (migration 0050). A longer value is no rule this
# installation wrote.
#
MAX_RULE_LENGTH = 160

_TRAFFIC_COPY = """
copy traffic_log
    (event_id, cluster, node, occurred_at, request_number, client, method, host,
     path, frontend, backend, server, status, request_time, queue_time,
     connect_time, response_time, total_time, bytes, rule, waf_rules, waf_score, waf_id)
from stdin
"""


def _passed_line_end(stream: Any) -> bool:
    """Read past the end of the current line; False, with nothing passed, at end of file first."""

    start = stream.tell()
    while block := stream.readline(64 * 1024):
        if block.endswith(b"\n"):
            return True
    stream.seek(start)
    return False


def _ingest_part(
    config: CollectorConfig,
    connection: psycopg.Connection[Any],
    target: NodeTarget,
    part: Path,
) -> int:
    """Import one staging part, and answer how many records it had to skip."""

    metadata = _regular(part)
    checkpoint = _database_checkpoint(config, part)
    offset = _checkpoint_offset(checkpoint, size=metadata.st_size)
    rows: list[tuple[Any, ...]] = []
    end = offset
    skipped = 0
    with part.open("rb") as stream:
        stream.seek(offset)
        while line := stream.readline(MAX_RECORD_BYTES + 1):
            if not line.endswith(b"\n") and len(line) > MAX_RECORD_BYTES:
                #
                # Longer than any record, so not a record the writer is half
                # way through but one no schema here describes (review
                # 2026-10-03, F3). Read on to its end a block at a time, so
                # memory stays bounded however long it is, and count it as
                # skipped like any other unreadable line. Without its newline
                # yet it is still being written: wait for it from its start.
                #
                if not _passed_line_end(stream):
                    break
                skipped += 1
                end = stream.tell()
                continue
            if not line.endswith(b"\n"):
                #
                # The open day is still being written to. A final line without
                # its newline is the writer half way through a record, not
                # damage: stop before it and take it on the next run, when it is
                # whole. Treating it as an error stopped the import of the day
                # that is actually accumulating.
                #
                break
            try:
                rows.append(_database_row(target.cluster, target.node, line[:-1]))
            except CollectorError:
                #
                # One unreadable record must not stop a hundred thousand good
                # ones, and stopping would be permanent rather than momentary:
                # the checkpoint never advances past the record that raised, so
                # every later run reaches the same line and fails again. The
                # mirror legitimately holds lines this schema does not describe -
                # the route's own probe record carries no timestamp, and an
                # rsyslog restart can cut a line in half. Count them, step over
                # them, and say how many in the run's output.
                #
                skipped += 1
            end = stream.tell()
            if len(rows) == DATABASE_BATCH_ROWS:
                with connection.cursor() as cursor, cursor.copy(_TRAFFIC_COPY) as copy:
                    for row in rows:
                        copy.write_row(row)
                connection.commit()
                _replace(checkpoint, f"{end}\n".encode(), 0o600)
                rows.clear()
        if rows:
            with connection.cursor() as cursor, cursor.copy(_TRAFFIC_COPY) as copy:
                for row in rows:
                    copy.write_row(row)
            connection.commit()
            _replace(checkpoint, f"{end}\n".encode(), 0o600)
        elif end > offset:
            #
            # Nothing to commit, but the reader did move: a tail of records this
            # schema cannot use. The checkpoint still has to pass them, or the
            # next run reads and rejects exactly the same bytes forever.
            #
            _replace(checkpoint, f"{end}\n".encode(), 0o600)
    return skipped


def _database_days(
    connection: psycopg.Connection[Any], table: str = "traffic_log"
) -> frozenset[str]:
    """The days the database can still store, asked of the database itself.

    The mirror deliberately keeps files for longer than the database keeps rows:
    after a restore it is the only thing left to replay from. The two windows
    are therefore different on purpose, and the collector must not offer a row
    the database has no partition for - PostgreSQL refuses the whole batch with
    `no partition of relation "traffic_log" found for row`, which fails the
    import for every node, not just the day that is out of range.

    Asked rather than configured: this is a fact about what exists, not a policy
    to keep in step. `[traffic_logs].retention_days` can change on the platform
    without anything here being told, and the next run simply reads the new
    horizon.

    `waf_match` (0052) is partitioned the same way and asked the same thing.
    """

    with connection.cursor() as cursor:
        cursor.execute(
            "select right(child.relname, 8) from pg_inherits "
            "join pg_class child on child.oid = pg_inherits.inhrelid "
            "join pg_class parent on parent.oid = pg_inherits.inhparent "
            "where parent.relname = %s "
            "and child.relname ~ ('^' || %s || '_[0-9]{8}$')",
            (table, table),
        )
        days = frozenset(str(row[0]) for row in cursor.fetchall())
    if not days:
        #
        # Loud rather than quiet. No partitions at all means the schema is not
        # what this collector was built against, and skipping every part would
        # look exactly like a quiet week of traffic.
        #
        raise CollectorError(f"the database holds no {table} partitions")
    return days


def _within_margin(day: str, days: frozenset[str]) -> bool:
    """Whether a staging day is the margin the mirror keeps below the oldest partition."""

    try:
        oldest = datetime.strptime(min(days), "%Y%m%d").date()
        part_day = datetime.strptime(day, "%Y-%m-%d").date()
    except ValueError:
        return False
    return oldest - timedelta(days=MIRROR_MARGIN_DAYS) <= part_day < oldest


def _mirror_window(config: CollectorConfig, *, now: datetime) -> int:
    """How many days the manager keeps, taken from what the database keeps.

    Three windows is two too many. B125 gave the node and the manager fourteen
    days each, because the mirror was then the store and that was the product's
    history. The database took that role with its own, configurable, retention,
    and the manager's copy was never revisited: it went on holding a week of
    records nothing could read and nothing could import, growing with traffic on
    the volume that has to be sized for it.

    So the window is derived rather than configured, from the same fact the
    import already asks for - which day partitions exist. One margin day is kept
    deliberately: the mirror is the only thing left to replay from if the
    database is restored, and a boundary that lines up exactly would lose the
    oldest day to the clock.

    The node keeps its own fourteen. Those cost the node's disk rather than this
    one, and they are the headroom that makes raising the database's retention a
    setting rather than a hole in the history.
    """

    if config.database is None or config.database_socket is None:
        return RETENTION_DAYS
    try:
        with psycopg.connect(
            f"dbname={config.database} host={config.database_socket}"
        ) as connection:
            days = _database_days(connection)
    except (psycopg.Error, CollectorError):
        #
        # Mirroring must not stop because the database is unreachable: fetching
        # is the part that cannot be caught up later, since the node drops its
        # own day files on its own schedule. Fall back to the wider window - the
        # safe direction - and let the import phase report the failure.
        #
        return RETENTION_DAYS
    today = now.astimezone(UTC).date()
    past = sum(1 for day in days if day <= f"{today:%Y%m%d}")
    return min(RETENTION_DAYS, max(1, past) + MIRROR_MARGIN_DAYS)


def _database_reason(exc: psycopg.Error) -> str:
    """Why PostgreSQL refused, for the collector's log (review 2026-10-04 F6).

    The primary message and the SQLSTATE: 26-10-03 a refused batch said only
    "database import failed", and the constraint that refused it was in
    PostgreSQL's own log. Never the DETAIL, which quotes the refused row - a
    requester's text. A connection that failed before any server message has
    only its own first line, which names the socket and nothing secret.
    """

    message = exc.diag.message_primary or (str(exc).splitlines() or [""])[0]
    state = f" ({exc.sqlstate})" if exc.sqlstate else ""
    return f"{message[:300]}{state}"


def _ingest_database(config: CollectorConfig) -> tuple[int, int]:
    """Import every staging part, and answer what it skipped: records, parts."""

    if config.database is None or config.database_socket is None:
        return 0, 0
    skipped = 0
    expired = 0
    try:
        with psycopg.connect(
            f"dbname={config.database} host={config.database_socket}", autocommit=False
        ) as connection:
            days = _database_days(connection)
            for target in config.nodes:
                prefix = f"{target.cluster}--{target.node}--"
                for part in sorted(config.staging.glob(f"{prefix}*.jsonl")):
                    day = part.name[len(prefix) : -len(".jsonl")]
                    if day.replace("-", "") not in days:
                        #
                        # The margin day the mirror keeps on purpose (see
                        # `_mirror_window`) is not an anomaly and is not
                        # counted; saying so every minute would drown the day
                        # it is one - a part older than that, or newer than any
                        # partition, which the retention timer should have made.
                        #
                        if not _within_margin(day, days):
                            expired += 1
                        continue
                    skipped += _ingest_part(config, connection, target, part)
    except psycopg.Error as exc:
        raise CollectorError(f"database import failed: {_database_reason(exc)}") from exc
    return skipped, expired


#
# The WAF engine's own log, rule by rule (Fas 21, B234-B236). Each node keeps it
# in a journal namespace that the traffic log's forced command reads after a
# journald cursor (`waf <cursor>`, or `waf -` from the oldest entry). Unlike the
# traffic log there is no staging copy: the node's journal is the buffer, and
# the cursor is a database position - written only after the rows it covers
# are committed, so a failed import fetches the same lines again and the
# duplicate trigger passes over what was already stored.
#
# Only with a database. The rows exist for the WAF page, which reads nothing
# else, and a mirror-only installation has no page to read them.
#
WAF_CURSOR = re.compile(r"[A-Za-z0-9=;_-]{1,512}")
WAF_MATCHED_PREFIX = "Matched Data: "
WAF_MATCHED_WITHIN = " found within "
MAX_WAF_FIELD = 256
MAX_WAF_MATCHED = 1024
MAX_WAF_PATH = 2048
WAF_CLIENT = re.compile(r"[0-9A-Fa-f.:]{2,64}")
MAX_WAF_MICROSECONDS = MAX_TIMESTAMP * 1_000_000


@dataclass(frozen=True, slots=True)
class WafPage:
    cursor: str
    reset: bool
    rows: tuple[tuple[Any, ...], ...]
    skipped: int


WafFetch = Callable[[NodeTarget, str], bytes]


def ssh_fetch_waf(config: CollectorConfig, target: NodeTarget, cursor: str) -> bytes:
    try:
        code, stdout, _stderr = _bounded_ssh(_ssh_argv(config, target, f"waf {cursor}"))
    except OSError as exc:
        raise SSHError(f"cannot run SSH request: {exc}") from exc
    if code == 64:
        #
        # 64 is the reader's answer to a request it does not know: a node
        # bundle from before the WAF journal - installed by mistake, or rolled
        # back to - or a request this collector got wrong. A failure either
        # way, and not one to tolerate: the node's matches would be missing
        # from the WAF page while every run looked fine, and an empty page is
        # what is read before an object leaves `log`. Nodes get the bundle
        # before the manager gets this collector, so no rollout passes here.
        #
        raise SSHError(
            "the node refused the WAF request (exit 64): its node bundle is older than "
            "this collector"
        )
    if code != 0:
        raise SSHError(f"SSH request failed with exit {code}")
    return stdout


def _waf_cursor_path(config: CollectorConfig, target: NodeTarget) -> Path:
    return config.staging / f".{target.cluster}--{target.node}.waf-cursor"


def _waf_cursor(config: CollectorConfig, target: NodeTarget) -> str:
    """Where the node's journal was last imported to; `-` for its start."""

    path = _waf_cursor_path(config, target)
    if not path.exists() and not path.is_symlink():
        return "-"
    raw = _read_small_file(path, 1024)
    try:
        cursor = raw.decode("ascii").strip()
    except UnicodeError:
        return "-"
    #
    # A cursor this collector did not write is no position at all. Starting
    # over costs one read of the node's journal and stores nothing twice.
    #
    return cursor if WAF_CURSOR.fullmatch(cursor) else "-"


def _storable(text: str, maximum: int) -> str:
    """Text a PostgreSQL text column takes: no NUL, and nothing UTF-8 cannot encode.

    JSON can spell a lone surrogate (`\\ud800`), which `json.loads` hands on
    and COPY then cannot encode - an error outside everything the import
    catches. Neither the engine nor the reader writes one; this does not rely
    on it.
    """

    return text.replace("\0", "").encode("utf-8", "replace").decode("utf-8")[:maximum]


def _waf_data(item: Any) -> tuple[str, str]:
    """The field and the value out of a rule's log data, as far as they can be told.

    The rule set writes `Matched Data: <match> found within <field>: <value>`
    for most attack rules, and every part after the prefix is the requester's
    own text. The first ` found within ` after the prefix is taken, and the
    field ends at the first `: ` after it; a request built to say otherwise can
    move where the split falls, which changes what the page shows and nothing
    else. The field is kept only where an exception could name it
    (`waf_field`), so it is never more than a suggestion the model checks
    again. Data in any other form is the value, with no field.
    """

    if not isinstance(item, str):
        return "", ""
    if item.startswith(WAF_MATCHED_PREFIX):
        within = item.find(WAF_MATCHED_WITHIN, len(WAF_MATCHED_PREFIX))
        if within >= 0:
            name, separator, value = item[within + len(WAF_MATCHED_WITHIN) :].partition(": ")
            if separator:
                field = name if len(name) <= MAX_WAF_FIELD and waf_field(name) else ""
                return field, _storable(value, MAX_WAF_MATCHED)
    return "", _storable(item, MAX_WAF_MATCHED)


def _waf_row(cluster: str, node: str, at: int, cursor: str, message: str) -> tuple[Any, ...] | None:
    """One `waf_match` row, None for a line that is no match, or CollectorError.

    The engine logs more than matches - starting, reloading, its own errors -
    and those are not rows. A match is: what the rule set reports, the object
    taken from the transaction ID HAProxy gave the engine (`<object>.<uuid>`),
    and the time journald received the line, which no requester writes.
    """

    try:
        value = json.loads(message)
    except ValueError:
        return None
    match = value.get("match") if isinstance(value, dict) else None
    if not isinstance(match, dict):
        return None
    rule = match.get("rule_id")
    if not isinstance(rule, int) or isinstance(rule, bool) or not 1 <= rule <= 999999:
        raise CollectorError("WAF match rule_id is invalid")
    #
    # The score crossing its threshold, and the report of every score: the
    # traffic record already carries both, and neither is a finding to allow.
    #
    if rule // 1000 in WAF_DECIDING_RULES:
        return None
    request_id = match.get("unique_id")
    if not isinstance(request_id, str) or WAF_ID.fullmatch(request_id) is None:
        raise CollectorError("WAF match unique_id is invalid")
    name, dot, _ = request_id.partition(".")
    if not dot or OBJECT_NAME.fullmatch(name) is None:
        raise CollectorError("WAF match names no object")
    if not 0 <= at <= MAX_WAF_MICROSECONDS:
        raise CollectorError("WAF match time is invalid")
    field, matched = _waf_data(match.get("data"))
    uri = match.get("uri")
    path = _storable(uri.partition("?")[0], MAX_WAF_PATH) if isinstance(uri, str) else ""
    #
    # The address HAProxy handed the engine (`src-ip=src`), not text from the
    # request; anything that is not the form of one is not kept.
    #
    client = match.get("client")
    if not isinstance(client, str) or WAF_CLIENT.fullmatch(client) is None:
        client = ""
    seconds, microseconds = divmod(at, 1_000_000)
    return (
        hashlib.sha256(f"{cluster}\0{node}\0{cursor}".encode()).digest(),
        cluster,
        node,
        datetime.fromtimestamp(seconds, UTC).replace(microsecond=microseconds),
        request_id,
        name,
        rule,
        field,
        matched,
        path,
        client,
    )


def _parse_waf_response(raw: bytes, target: NodeTarget) -> WafPage:
    try:
        header_line, payload = raw.split(b"\n", 1)
    except ValueError as exc:
        raise ProtocolError("node WAF response has no header") from exc
    if len(header_line) > MAX_HEADER_BYTES:
        raise ProtocolError("node WAF response header is too large")
    try:
        header = json.loads(header_line)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("node WAF response header is not JSON") from exc
    if not isinstance(header, dict) or set(header) != {"cursor", "eof", "reset", "sent"}:
        raise ProtocolError("node WAF response header has unexpected or missing fields")
    cursor, sent = header["cursor"], header["sent"]
    if not isinstance(cursor, str) or (cursor and WAF_CURSOR.fullmatch(cursor) is None):
        raise ProtocolError("node WAF response cursor is invalid")
    if not isinstance(header["eof"], bool) or not isinstance(header["reset"], bool):
        raise ProtocolError("node WAF response flags are invalid")
    if not isinstance(sent, int) or isinstance(sent, bool) or sent < 0:
        raise ProtocolError("node WAF response sent is invalid")
    if payload and not payload.endswith(b"\n"):
        raise ProtocolError("node WAF response ends in a partial record")
    lines = payload.splitlines()
    if sent != len(lines):
        raise ProtocolError("node WAF response record count is invalid")
    if header["reset"] and (sent or cursor):
        raise ProtocolError("node WAF reset response is inconsistent")
    rows: list[tuple[Any, ...]] = []
    skipped = 0
    for line in lines:
        try:
            record = json.loads(line)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ProtocolError("node WAF record is not JSON") from exc
        if not isinstance(record, dict) or set(record) != {"at", "cursor", "message"}:
            raise ProtocolError("node WAF record has unexpected or missing fields")
        at, position, message = record["at"], record["cursor"], record["message"]
        if (
            not isinstance(at, int)
            or isinstance(at, bool)
            or not isinstance(position, str)
            or WAF_CURSOR.fullmatch(position) is None
            or not isinstance(message, str)
        ):
            raise ProtocolError("node WAF record is invalid")
        #
        # The record's frame is the reader's, so a fault in it is the
        # protocol's; the message inside is the engine's, about a requester's
        # text, and one that cannot be stored is stepped over and counted -
        # as an unusable traffic record is - rather than stopping the node.
        #
        try:
            row = _waf_row(target.cluster, target.node, at, position, message)
        except CollectorError:
            skipped += 1
            continue
        if row is not None:
            rows.append(row)
    return WafPage(cursor=cursor, reset=header["reset"], rows=tuple(rows), skipped=skipped)


def fetch_waf(config: CollectorConfig, target: NodeTarget, fetch: WafFetch) -> WafPage:
    """One page of the node's WAF journal after the imported position.

    One page per run, as the traffic log takes one closed day per run: a
    backlog is caught up a minute at a time without holding more than one
    response per node in memory.
    """

    return _parse_waf_response(fetch(target, _waf_cursor(config, target)), target)


_WAF_COPY = """
copy waf_match
    (event_id, cluster, node, occurred_at, request_id, object, rule_id, field,
     matched, path, client)
from stdin
"""


def _ingest_waf(
    config: CollectorConfig, pages: list[tuple[NodeTarget, WafPage]]
) -> tuple[int, int]:
    """Store each node's page, then move its cursor; answer what was skipped: matches, expired."""

    #
    # Most minutes bring nothing: no WAF on the cluster, or no request matched.
    # That is no reason to open a database connection per run.
    #
    pages = [
        (target, page)
        for target, page in pages
        if page.reset
        or page.rows
        or page.skipped
        or page.cursor not in ("", _waf_cursor(config, target))
    ]
    if config.database is None or config.database_socket is None or not pages:
        return 0, 0
    try:
        with psycopg.connect(
            f"dbname={config.database} host={config.database_socket}", autocommit=False
        ) as connection:
            return _ingest_waf_pages(config, connection, pages)
    except psycopg.Error as exc:
        raise CollectorError(f"WAF import failed: {_database_reason(exc)}") from exc


def _ingest_waf_pages(
    config: CollectorConfig,
    connection: psycopg.Connection[Any],
    pages: list[tuple[NodeTarget, WafPage]],
) -> tuple[int, int]:
    skipped = 0
    expired = 0
    days = _database_days(connection, "waf_match")
    for target, page in pages:
        path = _waf_cursor_path(config, target)
        skipped += page.skipped
        if page.reset:
            #
            # The node no longer knows the position: its journal was rotated
            # past it or replaced. Read it again from the start.
            #
            if path.exists() or path.is_symlink():
                _regular(path, maximum=1024)
                path.unlink()
            continue
        #
        # Never offered to a day without a partition: PostgreSQL refuses the
        # whole batch for one such row (see `_database_days`). A match that
        # falls outside is passed by the cursor all the same - unlike a staged
        # traffic day, nothing here could hold it until its day exists.
        #
        rows = [row for row in page.rows if f"{row[3]:%Y%m%d}" in days]
        expired += len(page.rows) - len(rows)
        if rows:
            with connection.cursor() as cursor, cursor.copy(_WAF_COPY) as copy:
                for row in rows:
                    copy.write_row(row)
            connection.commit()
        if page.cursor and page.cursor != _waf_cursor(config, target):
            _replace(path, f"{page.cursor}\n".encode(), 0o600)
    return skipped, expired


@contextlib.contextmanager
def _run_lock(config: CollectorConfig, *, wait: bool) -> Iterator[bool]:
    """The collector's one lock; yields False when not waiting and another run holds it."""

    lock_path = config.staging / ".collector.lock"
    lock_flags = os.O_RDWR | os.O_APPEND | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
    lock_flags |= getattr(os, "O_NOFOLLOW", 0)
    lock_descriptor = os.open(lock_path, lock_flags, 0o600)
    with os.fdopen(lock_descriptor, "a+b") as lock:
        if not stat.S_ISREG(os.fstat(lock.fileno()).st_mode):
            raise CollectorError("collector lock is not a regular file")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX if wait else fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            yield False
            return
        yield True


def forget_database_positions(config: CollectorConfig) -> int:
    """Make the next run import every staged day again; answer how many positions were dropped.

    For a database restored on its own (review 2026-09-30, R3). Each day part's
    import position is a file in staging, written after the batch committed,
    and a dump from yesterday knows nothing of it: the next run would go on from
    today's position and leave the records between the dump and the restore
    missing, although every one of them is still here. Dropping the positions
    replays the staged days whole; what the database already holds is passed
    over by its own duplicate trigger, so nothing is counted twice. The fetch
    cursors - how far each node's day has been copied - are not touched.

    The WAF journal's cursors are dropped with them: they are database
    positions too (see `_ingest_waf`), and without them the next runs read each
    node's journal again from its oldest entry.

    Waits for a run in progress rather than racing it: that run's import would
    otherwise write a position back after it was dropped.
    """

    _directory(config.staging)
    with _run_lock(config, wait=True):
        dropped = 0
        for pattern, maximum in ((".*.database-offset", 32), (".*.waf-cursor", 1024)):
            for checkpoint in config.staging.glob(pattern):
                _regular(checkpoint, maximum=maximum)
                checkpoint.unlink()
                dropped += 1
        return dropped


@dataclass(frozen=True, slots=True)
class _NodeRun:
    problem: str | None
    waf: WafPage | None = None
    waf_problem: str | None = None


def collect(
    config: CollectorConfig,
    *,
    now: datetime | None = None,
    fetch: Fetch | None = None,
    fetch_waf_page: WafFetch | None = None,
) -> int:
    _directory(config.mirror)
    _directory(config.staging)
    with _run_lock(config, wait=False) as held:
        if not held:
            return 0
        attempted = now or datetime.now(UTC)
        window = _mirror_window(config, now=attempted)
        selected = fetch or (lambda node, day, offset: ssh_fetch(config, node, day, offset))
        selected_waf = fetch_waf_page or (lambda node, cursor: ssh_fetch_waf(config, node, cursor))

        def one(target: NodeTarget) -> _NodeRun:
            problem = None
            try:
                collect_node(config, target, now=attempted, fetch=selected, window=window)
            except (CollectorError, OSError) as exc:
                problem = str(exc)
            if config.database is None:
                return _NodeRun(problem)
            #
            # Its own outcome, apart from the traffic log's: the page's
            # freshness is the traffic log's metadata, and a node whose WAF
            # journal cannot be read is still a node whose traffic is current.
            #
            try:
                return _NodeRun(problem, waf=fetch_waf(config, target, selected_waf))
            except (CollectorError, OSError) as exc:
                return _NodeRun(problem, waf_problem=str(exc))

        #
        # The nodes at once (Fas 16 punkt 1). Each node's staging parts, mirror
        # and metadata carry its own name, so two nodes never touch one file;
        # the import below reads them afterwards, one after the other, as before.
        #
        runs: list[_NodeRun] = []
        if config.nodes:
            with ThreadPoolExecutor(
                max_workers=min(len(config.nodes), MAX_PARALLEL_NODES)
            ) as threads:
                runs = list(threads.map(one, config.nodes))
        failures = 0
        mirrored: list[NodeTarget] = []
        pages: list[tuple[NodeTarget, WafPage]] = []
        for target, run in zip(config.nodes, runs, strict=True):
            if run.waf is not None:
                pages.append((target, run.waf))
            if run.waf_problem is not None:
                print(f"{target.cluster}/{target.node}: waf: {run.waf_problem}", file=sys.stderr)
                failures += 1
            if run.problem is None:
                mirrored.append(target)
                continue
            print(f"{target.cluster}/{target.node}: {run.problem}", file=sys.stderr)
            failures += 1
        try:
            skipped, expired = _ingest_database(config)
            if skipped:
                print(f"database: skipped {skipped} unusable record(s)", file=sys.stderr)
            if expired:
                print(
                    f"database: {expired} mirrored day(s) are older than the database keeps",
                    file=sys.stderr,
                )
        except (CollectorError, OSError) as exc:
            print(f"database: {exc}", file=sys.stderr)
            for target in mirrored:
                _write_meta(
                    config,
                    target,
                    attempted=attempted,
                    outcome="database",
                    success=False,
                )
            failures += 1
        try:
            skipped, expired = _ingest_waf(config, pages)
            if skipped:
                print(f"waf: skipped {skipped} unusable match(es)", file=sys.stderr)
            if expired:
                print(
                    f"waf: {expired} match(es) fall outside the days the database holds",
                    file=sys.stderr,
                )
        except (CollectorError, OSError) as exc:
            print(f"waf: {exc}", file=sys.stderr)
            failures += 1
        _retire(config, now=attempted, window=window)
        _retire_staging(config, now=attempted, window=window)
        return 1 if failures else 0


def _entry() -> None:
    modes = {"--check-config", "--config", "--replay-database"}
    if len(sys.argv) != 3 or sys.argv[1] not in modes:
        print(
            "usage: haprion-traffic-collector (--check-config|--config|--replay-database) <path>",
            file=sys.stderr,
        )
        raise SystemExit(64)
    try:
        config = load_config(Path(sys.argv[2]))
        if sys.argv[1] == "--check-config":
            print(f"parsed {len(config.nodes)} node(s) as {config.user}")
            code = 0
        elif sys.argv[1] == "--replay-database":
            if config.database is None:
                raise CollectorError("this collector imports into no database; nothing to replay")
            dropped = forget_database_positions(config)
            print(
                f"dropped {dropped} import position(s); the next run imports every staged day again"
            )
            code = 0
        else:
            code = collect(config)
    except (CollectorError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(65) from exc
    raise SystemExit(code)
