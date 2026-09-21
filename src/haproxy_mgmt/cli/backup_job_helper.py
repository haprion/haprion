"""Root socket helper for one cluster backup run or daily schedule change."""

from __future__ import annotations

import io
import json
import os
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import BinaryIO, TextIO

from haproxy_mgmt import backup_schedule_write, state_backup
from haproxy_mgmt.config import DEFAULT_POLICY_PATH, ConfigError, load_policy, load_runtime_config
from haproxy_mgmt.envelope import Message, envelope, failure
from haproxy_mgmt.helper_protocol import (
    MAX_REQUEST_BYTES,
    HelperProtocolError,
    JsonValue,
    config_error_code,
    read_helper_request,
    write_document,
)

RUN = "backup_run"
SCHEDULE = "backup_schedule"
OPERATIONS = frozenset({RUN, SCHEDULE})
HELPER = "/opt/haproxy-mgmt/current/bin/haproxy-backup-job-helper"
EXIT_NOT_ROOT = 77

__all__ = ["HELPER", "RUN", "SCHEDULE", "build_run_request", "build_schedule_request", "main"]


def _document(
    operation: str, cluster: str, request_id: str, parameters: Mapping[str, JsonValue]
) -> str:
    return json.dumps(
        {
            "schema_version": 1,
            "operation": operation,
            "cluster": cluster,
            "request_id": request_id,
            "parameters": dict(parameters),
        },
        separators=(",", ":"),
    )


def build_run_request(cluster: str, request_id: str) -> str:
    return _document(RUN, cluster, request_id, {})


def build_schedule_request(cluster: str, request_id: str, *, time: str, enabled: bool) -> str:
    return _document(SCHEDULE, cluster, request_id, {"time": time, "enabled": enabled})


def _raw(stream: BinaryIO) -> tuple[bytes, str]:
    raw = stream.read(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES:
        raise HelperProtocolError("helper request is larger than allowed", exit_code=65)
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HelperProtocolError("helper request is not valid JSON", exit_code=65) from exc
    operation = document.get("operation") if isinstance(document, dict) else None
    if operation not in OPERATIONS:
        raise HelperProtocolError("operation is not allowed by this helper", exit_code=65)
    return raw, str(operation)


def _schedule(parameters: Mapping[str, JsonValue]) -> tuple[str, bool]:
    value = parameters.get("time")
    enabled = parameters.get("enabled")
    if not isinstance(value, str):
        raise HelperProtocolError(
            "parameters.time must be HH:MM on the manager's clock", exit_code=65
        )
    try:
        backup_schedule_write.calendar(value)
    except backup_schedule_write.ScheduleWriteError as exc:
        raise HelperProtocolError(str(exc), exit_code=65) from exc
    if type(enabled) is not bool:
        raise HelperProtocolError("parameters.enabled must be true or false", exit_code=65)
    return value, enabled


def _validate_schedule(parameters: Mapping[str, JsonValue]) -> None:
    _schedule(parameters)


def _refuse(
    writer: TextIO,
    errors: TextIO,
    *,
    operation: str,
    cluster: str,
    request_id: str,
    code: str,
    message: str,
    exit_code: int,
) -> int:
    errors.write(f"ERROR: [{code}] {message}\n")
    write_document(
        writer,
        failure(
            operation=operation,
            cluster=cluster,
            request_id=request_id,
            code=code,
            message=message,
            exit_code=exit_code,
        ),
    )
    return exit_code


def main(
    argv: list[str] | None = None,
    *,
    policy_path: Path = DEFAULT_POLICY_PATH,
    input_stream: BinaryIO | None = None,
    output_stream: TextIO | None = None,
    error_stream: TextIO | None = None,
    require_secure: bool = True,
    require_root: bool = True,
) -> int:
    argv = sys.argv[1:] if argv is None else argv
    writer = output_stream or sys.stdout
    errors = error_stream or sys.stderr
    if argv:
        errors.write("ERROR: haproxy-backup-job-helper accepts no arguments\n")
        return 64
    if require_root and os.geteuid() != 0:
        errors.write("ERROR: haproxy-backup-job-helper must run as root\n")
        return EXIT_NOT_ROOT
    try:
        raw, operation = _raw(input_stream or sys.stdin.buffer)
        request = read_helper_request(
            io.BytesIO(raw),
            expected_operation=operation,
            allowed_parameter_keys=(
                frozenset() if operation == RUN else frozenset({"time", "enabled"})
            ),
            validate_parameters=None if operation == RUN else _validate_schedule,
        )
    except HelperProtocolError as exc:
        errors.write(f"ERROR: {exc}\n")
        return exc.exit_code

    try:
        policy = load_policy(policy_path, require_secure=require_secure)
        runtime = load_runtime_config(policy, require_secure=require_secure)
        cluster = runtime.cluster(request.cluster)
    except ConfigError as exc:
        return _refuse(
            writer,
            errors,
            operation=operation,
            cluster=request.cluster,
            request_id=request.request_id,
            code=config_error_code(exc.exit_code),
            message=str(exc),
            exit_code=exc.exit_code,
        )

    if operation == SCHEDULE:
        value, enabled = _schedule(request.parameters)
        try:
            result = backup_schedule_write.apply(request.cluster, value, enabled)
        except backup_schedule_write.ScheduleWriteError as exc:
            return _refuse(
                writer,
                errors,
                operation=operation,
                cluster=request.cluster,
                request_id=request.request_id,
                code="schedule_failed",
                message=str(exc),
                exit_code=1,
            )
        write_document(
            writer,
            envelope(
                operation=operation,
                outcome="done",
                cluster=request.cluster,
                request_id=request.request_id,
                result=result.as_dict(),
            ),
        )
        return 0

    try:
        report = state_backup.run(
            request.cluster, cluster, policy.backup_identity, policy.backup_root
        )
    except state_backup.BackupRunError as exc:
        return _refuse(
            writer,
            errors,
            operation=operation,
            cluster=request.cluster,
            request_id=request.request_id,
            code="backup_failed",
            message=str(exc),
            exit_code=1,
        )
    failed = tuple(node for node in report.nodes if node.outcome != "done")
    if report.outcome == "failed":
        error = Message(code="backup_failed", message="No node produced a valid state archive")
    else:
        error = None
    warnings = tuple(
        Message(
            code=node.error or "backup_failed",
            message="The node did not produce a valid state archive",
            node=node.name,
        )
        for node in failed
    )
    write_document(
        writer,
        envelope(
            operation=operation,
            outcome=report.outcome,
            cluster=request.cluster,
            request_id=request.request_id,
            result=report.as_dict(),
            warnings=warnings if report.outcome == "partial" else (),
            error=error,
        ),
    )
    return 0 if report.outcome in {"done", "partial"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
