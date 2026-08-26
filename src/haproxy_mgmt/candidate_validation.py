from __future__ import annotations

import hashlib
import os
import stat
import subprocess
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from haproxy_mgmt.config import ConfigError
from haproxy_mgmt.helper_protocol import HelperProtocolError, JsonValue

MAX_CANDIDATE_BYTES = 4 * 1024 * 1024
MAX_CANDIDATE_FILES = 512
MAX_FILE_BYTES = 1024 * 1024

#
# Both privileged helpers validate, and both must validate the same way: the
# same certificate, the same run root, the same sandbox. The environment is
# therefore prepared here rather than in either command.
#
DEFAULT_RUN_ROOT = Path("/run/haproxy-manager-validation")
VALIDATION_CERTIFICATE = "validation.pem"


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


def candidate_from_files(files: Mapping[str, bytes]) -> Candidate:
    """The same candidate, built from bytes that never were JSON.

    The publishing helper derives the node artifact itself, on root's side of
    the boundary, and then has to validate it. Routing that through the JSON
    parser would mean encoding bytes back into strings only to decode them
    again - so the checks and the digest live here, and `parse_candidate` is the
    JSON front door onto the same code. One implementation, one digest.
    """

    if not files:
        raise HelperProtocolError("candidate must contain at least one file", exit_code=65)
    if len(files) > MAX_CANDIDATE_FILES:
        raise HelperProtocolError("candidate contains too many files", exit_code=65)

    checked: dict[str, bytes] = {}
    total = 0
    digest = hashlib.sha256()
    for raw_path in sorted(files):
        content = files[raw_path]
        path = _allowed_path(raw_path)
        if b"\x00" in content:
            raise HelperProtocolError("candidate files may not contain NUL", exit_code=65)
        if len(content) > MAX_FILE_BYTES:
            raise HelperProtocolError("candidate contains an oversized file", exit_code=65)
        total += len(content)
        if total > MAX_CANDIDATE_BYTES:
            raise HelperProtocolError("candidate exceeds the total size limit", exit_code=65)
        checked[path] = content
        path_bytes = path.encode()
        digest.update(len(path_bytes).to_bytes(4, "big"))
        digest.update(path_bytes)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)

    if "haproxy.cfg" not in checked:
        raise HelperProtocolError("candidate must contain haproxy.cfg", exit_code=65)
    return Candidate(files=checked, sha256=digest.hexdigest())


def parse_candidate(parameters: Mapping[str, JsonValue]) -> Candidate:
    """The JSON front door: decode, then hand over to `candidate_from_files`."""

    raw_files = parameters.get("files")
    if not isinstance(raw_files, dict) or not raw_files:
        raise HelperProtocolError("parameters.files must be a non-empty object", exit_code=65)
    if len(raw_files) > MAX_CANDIDATE_FILES:
        raise HelperProtocolError("candidate contains too many files", exit_code=65)

    decoded: dict[str, bytes] = {}
    for raw_path in sorted(raw_files):
        content = raw_files[raw_path]
        if not isinstance(raw_path, str) or not isinstance(content, str):
            raise HelperProtocolError("candidate paths and contents must be strings", exit_code=65)
        decoded[raw_path] = content.encode("utf-8")
    return candidate_from_files(decoded)


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
        "InaccessiblePaths=/boot /home /media /mnt /opt /root /srv /var /apps /configs",
        "TemporaryFileSystem=/run",
        #
        # /etc is replaced rather than hidden. It used to be listed above as
        # inaccessible, and that measured wrong against a real cluster
        # configuration on 2026-08-26: every production config names
        # "user haproxy", "group haproxy" and seven errorfile paths under
        # /etc/haproxy/errors, so haproxy -c failed on all nine before it ever
        # looked at what was being validated.
        #
        # An inaccessible /etc cannot be poked a hole in - the overmount has no
        # paths inside it to bind onto - so the fix is an empty /etc containing
        # exactly what parsing a configuration needs. That is strictly tighter
        # than hiding /etc would have been if it had worked: nothing else in
        # /etc exists at all, including /etc/haproxy/certs, which is what the
        # substituted certificates under /candidate/certs are there to replace.
        #
        # The errorfiles are the manager host's copies, which is what the shell
        # path validated against too. They are read-only and world readable.
        #
        "TemporaryFileSystem=/etc",
        "BindReadOnlyPaths=-/etc/ld.so.cache",
        "BindReadOnlyPaths=/etc/passwd",
        "BindReadOnlyPaths=/etc/group",
        "BindReadOnlyPaths=-/etc/nsswitch.conf",
        "BindReadOnlyPaths=/etc/haproxy/errors",
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
            #
            # Ignore server address resolution failures. The sandbox has no
            # network at all, so every `server` line naming a hostname would
            # otherwise fail here - measured against a production cluster on
            # 2026-08-26, where a single backend server named by hostname was
            # enough to fail the whole validation.
            #
            # Nothing is lost by this that was ever worth much. The shell path
            # resolved those names on the MANAGER, which says nothing about
            # whether the nodes can resolve them - and the nodes check for
            # themselves: haproxy-pull-deploy runs `haproxy -c` before the
            # symlink swap and again after it, and rolls back if either fails.
            # That check runs with the node's own resolver, which is the only
            # one whose answer matters.
            #
            # The alternative was to give this sandbox a network, and a parser
            # reading an unreviewed candidate is exactly what should not have
            # one.
            #
            "-dr",
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


type SandboxValidator = Callable[[Path, str], ValidationResult]


def read_validation_certificate(path: Path, *, require_secure: bool) -> bytes:
    """The certificate the sandbox substitutes for the real ones.

    Root-only by construction: it is the one secret this path touches, and a
    candidate that could name a readable copy of it could name anything.
    """

    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ConfigError(f"cannot stat validation certificate: {exc}", exit_code=68) from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ConfigError("validation certificate must be a regular non-symlink", exit_code=68)
    if require_secure and (metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o077):
        raise ConfigError("validation certificate must be mode 600 root:root", exit_code=68)
    try:
        return path.read_bytes()
    except OSError as exc:
        raise ConfigError(f"cannot read validation certificate: {exc}", exit_code=68) from exc


def prepare_run_root(path: Path, *, require_secure: bool) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = path.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise ConfigError("validation run root must be a non-symlink directory", exit_code=68)
    if require_secure and (metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o077):
        raise ConfigError("validation run root must be mode 700 root:root", exit_code=68)


def validate_candidate(
    candidate: Candidate,
    *,
    run_root: Path,
    certificate_ids: Sequence[str],
    validation_certificate: bytes,
    request_id: str,
    validator: SandboxValidator = validate_in_sandbox,
) -> ValidationResult:
    """Materialize the candidate somewhere private and run the sandbox on it.

    The directory is removed whether validation passed, failed or raised: a
    candidate left on disk is a copy of the substituted certificate left on
    disk with it.
    """

    with tempfile.TemporaryDirectory(prefix="request-", dir=run_root) as temporary:
        candidate_root = Path(temporary) / "candidate"
        materialize_candidate(
            candidate,
            candidate_root,
            certificate_ids=certificate_ids,
            validation_certificate=validation_certificate,
        )
        return validator(candidate_root, request_id)
