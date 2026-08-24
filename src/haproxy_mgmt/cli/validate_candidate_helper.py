from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import BinaryIO, TextIO

from haproxy_mgmt.candidate_validation import (
    MAX_CANDIDATE_BYTES,
    ValidationResult,
    materialize_candidate,
    parse_candidate,
    validate_in_sandbox,
)
from haproxy_mgmt.config import DEFAULT_POLICY_PATH, ConfigError, load_policy, load_runtime_config
from haproxy_mgmt.helper_protocol import (
    HelperProtocolError,
    read_helper_request,
    require_no_arguments,
)

DEFAULT_RUN_ROOT = Path("/run/haproxy-manager-validation")
VALIDATION_CERTIFICATE = "validation.pem"
SandboxValidator = Callable[[Path, str], ValidationResult]


def _secure_bytes(path: Path, *, require_secure: bool) -> bytes:
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


def _prepare_run_root(path: Path, *, require_secure: bool) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = path.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise ConfigError("validation run root must be a non-symlink directory", exit_code=68)
    if require_secure and (metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o077):
        raise ConfigError("validation run root must be mode 700 root:root", exit_code=68)


def main(
    argv: list[str] | None = None,
    *,
    policy_path: Path = DEFAULT_POLICY_PATH,
    run_root: Path = DEFAULT_RUN_ROOT,
    input_stream: BinaryIO | None = None,
    output_stream: TextIO | None = None,
    error_stream: TextIO | None = None,
    require_secure: bool = True,
    require_root: bool = True,
    validator: SandboxValidator = validate_in_sandbox,
) -> int:
    output_stream = output_stream or sys.stdout
    error_stream = error_stream or sys.stderr
    input_stream = input_stream or sys.stdin.buffer

    try:
        require_no_arguments(argv or [])
        if require_root and os.geteuid() != 0:
            raise HelperProtocolError("candidate validation helper must run as root", exit_code=77)
        request = read_helper_request(
            input_stream,
            expected_operation="validate_candidate",
            allowed_parameter_keys=frozenset({"files"}),
            max_bytes=MAX_CANDIDATE_BYTES + 1024 * 1024,
        )
        candidate = parse_candidate(request.parameters)
        policy = load_policy(policy_path, require_secure=require_secure)
        cluster = load_runtime_config(policy, require_secure=require_secure).cluster(
            request.cluster
        )
        certificate = _secure_bytes(
            cluster.validation_certs / VALIDATION_CERTIFICATE,
            require_secure=require_secure,
        )
        _prepare_run_root(run_root, require_secure=require_secure)
        with tempfile.TemporaryDirectory(prefix="request-", dir=run_root) as temporary:
            candidate_root = Path(temporary) / "candidate"
            materialize_candidate(
                candidate,
                candidate_root,
                certificate_ids=cluster.certificate_ids,
                validation_certificate=certificate,
            )
            result = validator(candidate_root, request.request_id)
    except (ConfigError, HelperProtocolError) as exc:
        print(f"ERROR: {exc}", file=error_stream)
        return exc.exit_code

    json.dump(
        {
            "schema_version": 1,
            "operation": request.operation,
            "cluster": request.cluster,
            "request_id": request.request_id,
            "candidate_sha256": candidate.sha256,
            "valid": result.valid,
            "diagnostics": result.diagnostics,
        },
        output_stream,
        sort_keys=True,
    )
    output_stream.write("\n")
    return 0 if result.valid else 65


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
