from __future__ import annotations

import hashlib
import os
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from haproxy_mgmt.helper_protocol import HelperProtocolError, JsonValue

MAX_CANDIDATE_BYTES = 4 * 1024 * 1024
MAX_CANDIDATE_FILES = 512
MAX_FILE_BYTES = 1024 * 1024


@dataclass(frozen=True, slots=True)
class Candidate:
    files: Mapping[str, bytes]
    sha256: str


@dataclass(frozen=True, slots=True)
class ValidationResult:
    valid: bool
    diagnostics: str


def _allowed_path(raw: str) -> str:
    path = PurePosixPath(raw)
    if (
        not raw
        or path.is_absolute()
        or str(path) != raw
        or any(part in (".", "..") for part in path.parts)
    ):
        raise HelperProtocolError("candidate contains an invalid relative path", exit_code=65)
    if raw == "haproxy.cfg":
        return raw
    if len(path.parts) == 2 and path.parts[0] == "conf.d" and path.suffix == ".cfg":
        return raw
    if path.parts[0] == "maps" and len(path.parts) >= 2:
        return raw
    raise HelperProtocolError("candidate contains a path outside its allowlist", exit_code=65)


def parse_candidate(parameters: Mapping[str, JsonValue]) -> Candidate:
    raw_files = parameters.get("files")
    if not isinstance(raw_files, dict) or not raw_files:
        raise HelperProtocolError("parameters.files must be a non-empty object", exit_code=65)
    if len(raw_files) > MAX_CANDIDATE_FILES:
        raise HelperProtocolError("candidate contains too many files", exit_code=65)

    files: dict[str, bytes] = {}
    total = 0
    digest = hashlib.sha256()
    for raw_path in sorted(raw_files):
        content = raw_files[raw_path]
        if not isinstance(raw_path, str) or not isinstance(content, str):
            raise HelperProtocolError("candidate paths and contents must be strings", exit_code=65)
        path = _allowed_path(raw_path)
        encoded = content.encode("utf-8")
        if b"\x00" in encoded:
            raise HelperProtocolError("candidate files may not contain NUL", exit_code=65)
        if len(encoded) > MAX_FILE_BYTES:
            raise HelperProtocolError("candidate contains an oversized file", exit_code=65)
        total += len(encoded)
        if total > MAX_CANDIDATE_BYTES:
            raise HelperProtocolError("candidate exceeds the total size limit", exit_code=65)
        files[path] = encoded
        path_bytes = path.encode()
        digest.update(len(path_bytes).to_bytes(4, "big"))
        digest.update(path_bytes)
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)

    if "haproxy.cfg" not in files:
        raise HelperProtocolError("candidate must contain haproxy.cfg", exit_code=65)
    return Candidate(files=files, sha256=digest.hexdigest())


def materialize_candidate(
    candidate: Candidate,
    root: Path,
    *,
    certificate_ids: Sequence[str],
    validation_certificate: bytes,
) -> None:
    root.mkdir(mode=0o700)
    for directory in (root / "conf.d", root / "maps", root / "certs"):
        directory.mkdir(mode=0o700)

    for relative, original in candidate.files.items():
        target = root / relative
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        content = original
        if relative == "haproxy.cfg" or relative.startswith("conf.d/"):
            content = content.replace(b"/etc/haproxy/maps/", b"/candidate/maps/")
            content = content.replace(b"/etc/haproxy/certs/", b"/candidate/certs/")
        descriptor = os.open(
            target,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
        with os.fdopen(descriptor, "wb") as output:
            output.write(content)

    for certificate_id in certificate_ids:
        target = root / "certs" / f"{certificate_id}.pem"
        descriptor = os.open(
            target,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
        with os.fdopen(descriptor, "wb") as output:
            output.write(validation_certificate)


def sandbox_command(candidate_root: Path, request_id: str) -> list[str]:
    unit = f"haproxy-manager-validation-{request_id.replace('-', '')}"
    properties = (
        "NoNewPrivileges=yes",
        "PrivateDevices=yes",
        "PrivateNetwork=yes",
        "ProtectSystem=strict",
        "ProtectHome=yes",
        "ProtectKernelTunables=yes",
        "ProtectKernelModules=yes",
        "ProtectKernelLogs=yes",
        "ProtectControlGroups=yes",
        "ProtectClock=yes",
        "ProtectProc=invisible",
        "ProcSubset=pid",
        "RestrictSUIDSGID=yes",
        "LockPersonality=yes",
        "CapabilityBoundingSet=",
        "AmbientCapabilities=",
        "RestrictAddressFamilies=AF_UNIX",
        "IPAddressDeny=any",
        "UMask=0077",
        "InaccessiblePaths=/boot /etc /home /media /mnt /opt /root /srv /var /apps /configs",
        "TemporaryFileSystem=/run",
        f"BindReadOnlyPaths={candidate_root}:/candidate",
    )
    command = [
        "/usr/bin/systemd-run",
        "--quiet",
        "--wait",
        "--pipe",
        "--collect",
        "--service-type=exec",
        f"--unit={unit}",
    ]
    for value in properties:
        command.extend(("--property", value))
    command.extend(
        (
            "/usr/sbin/haproxy",
            "-c",
            "-f",
            "/candidate/haproxy.cfg",
            "-f",
            "/candidate/conf.d",
        )
    )
    return command


def validate_in_sandbox(candidate_root: Path, request_id: str) -> ValidationResult:
    completed = subprocess.run(  # noqa: S603 - argv is entirely constructed above
        sandbox_command(candidate_root, request_id),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        env={"PATH": "/usr/sbin:/usr/bin"},
    )
    diagnostics = (completed.stdout + completed.stderr)[:16384]
    return ValidationResult(valid=completed.returncode == 0, diagnostics=diagnostics)
