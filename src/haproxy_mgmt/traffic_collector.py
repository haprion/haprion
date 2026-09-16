"""UI-independent, manager-initiated mirroring of node traffic logs."""

from __future__ import annotations

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
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

import psycopg

MAX_CONFIG_BYTES = 1024 * 1024
MAX_HEADER_BYTES = 4096
MAX_SEND = 8 * 1024 * 1024
MAX_STDERR = 64 * 1024
MAX_RECORD_BYTES = 16 * 1024
DATABASE_BATCH_ROWS = 1000
#
# What the manager keeps when it has no database to ask. The number is B125's:
# it was the product's history window back when the mirror was the store and the
# page read these files directly. With the records in PostgreSQL the database
# decides how far back anything can be read, so this is the fallback for a
# mirror-only installation and for a run that cannot reach the database - never
# a second window kept in step by hand.
#
RETENTION_DAYS = 14
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
    _append(path, response.payload)
    return response.eof


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
                complete = _update_day(config, target, wanted, fetch)
                yesterday_still_open = (
                    wanted == today - timedelta(days=1)
                    and utc_now - datetime.combine(today, datetime.min.time(), UTC)
                    < CLOSED_DAY_GRACE
                )
                if complete and not yesterday_still_open:
                    _replace(marker, b"", 0o600)
                break
        _assemble(config, target, days)
        _write_meta(config, target, attempted=now, outcome="ok", success=True)
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
    oldest = (now.date() - timedelta(days=window - 1)).isoformat()
    for path in config.staging.iterdir():
        name = path.name
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
        if not isinstance(item, str) or len(item) > maximum:
            raise CollectorError(f"traffic record {name} is invalid")
        return item

    stamp = number("at", low=0)
    request = value.get("request", 0)
    if not isinstance(request, int) or isinstance(request, bool) or request < 0:
        raise CollectorError("traffic record request is invalid")
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
    )


_TRAFFIC_COPY = """
copy traffic_log
    (event_id, cluster, node, occurred_at, request_number, client, method, host,
     path, frontend, backend, server, status, request_time, queue_time,
     connect_time, response_time, total_time, bytes)
from stdin
"""


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


def _database_days(connection: psycopg.Connection[Any]) -> frozenset[str]:
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
    """

    with connection.cursor() as cursor:
        cursor.execute(
            "select right(child.relname, 8) from pg_inherits "
            "join pg_class child on child.oid = pg_inherits.inhrelid "
            "join pg_class parent on parent.oid = pg_inherits.inhparent "
            "where parent.relname = 'traffic_log' "
            "and child.relname ~ '^traffic_log_[0-9]{8}$'"
        )
        days = frozenset(str(row[0]) for row in cursor.fetchall())
    if not days:
        #
        # Loud rather than quiet. No partitions at all means the schema is not
        # what this collector was built against, and skipping every part would
        # look exactly like a quiet week of traffic.
        #
        raise CollectorError("the database holds no traffic log partitions")
    return days


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
                        expired += 1
                        continue
                    skipped += _ingest_part(config, connection, target, part)
    except psycopg.Error as exc:
        raise CollectorError("database import failed") from exc
    return skipped, expired


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
        window = _mirror_window(config, now=attempted)
        failures = 0
        mirrored: list[NodeTarget] = []
        for target in config.nodes:
            selected = fetch or (lambda node, day, offset: ssh_fetch(config, node, day, offset))
            try:
                collect_node(config, target, now=attempted, fetch=selected, window=window)
                mirrored.append(target)
            except (CollectorError, OSError) as exc:
                print(f"{target.cluster}/{target.node}: {exc}", file=sys.stderr)
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
        _retire(config, now=attempted, window=window)
        _retire_staging(config, now=attempted, window=window)
        return 1 if failures else 0


def _entry() -> None:
    if len(sys.argv) != 3 or sys.argv[1] not in {"--check-config", "--config"}:
        print(
            "usage: haproxy-ui-traffic-collector (--check-config|--config) <path>",
            file=sys.stderr,
        )
        raise SystemExit(64)
    try:
        config = load_config(Path(sys.argv[2]))
        if sys.argv[1] == "--check-config":
            print(f"parsed {len(config.nodes)} node(s) as {config.user}")
            code = 0
        else:
            code = collect(config)
    except (CollectorError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(65) from exc
    raise SystemExit(code)
