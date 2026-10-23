"""Root socket helper for one cluster backup run or schedule change."""

from __future__ import annotations

import io
import json
import os
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import BinaryIO, TextIO

from haprion import backup_retention, backup_schedule_write, exit_codes, state_backup
from haprion.backup_schedule import Schedule
from haprion.config import DEFAULT_POLICY_PATH, ConfigError, load_policy, load_runtime_config
from haprion.envelope import Message, envelope, failure
from haprion.helper_protocol import (
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
HELPER = "/opt/haprion/current/bin/haprion-backup-job-helper"

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


SCHEDULE_KEYS = frozenset({"time", "enabled", "frequency", "weekdays", "day_of_month", "retention"})


def build_schedule_request(
    cluster: str, request_id: str, *, schedule: Schedule, enabled: bool
) -> str:
    return _document(SCHEDULE, cluster, request_id, {**schedule.as_dict(), "enabled": enabled})


def run_document(
    report: state_backup.BackupResult, *, cluster: str, request_id: str
) -> tuple[dict[str, object], int]:
    """One backup run as its envelope and exit code: the helper's, and `haprion-state-backup --json`'s."""

    failed = tuple(node for node in report.nodes if node.outcome != "done")
    error = (
        Message(code="backup_failed", message="No node produced a valid state archive")
        if report.outcome == "failed"
        else None
    )
    warnings = tuple(
        Message(
            code=node.error or "backup_failed",
            message="The node did not produce a valid state archive",
            node=node.name,
        )
        for node in failed
    )
    return (
        envelope(
            operation=RUN,
            outcome=report.outcome,
            cluster=cluster,
            request_id=request_id,
            result=report.as_dict(),
            warnings=warnings if report.outcome == "partial" else (),
            error=error,
        ),
        0 if report.outcome in {"done", "partial"} else 1,
    )


def _raw(stream: BinaryIO) -> tuple[bytes, str]:
    raw = stream.read(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES:
        raise HelperProtocolError(
            "helper request is larger than allowed", exit_code=exit_codes.REFUSED
        )
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HelperProtocolError(
            "helper request is not valid JSON", exit_code=exit_codes.REFUSED
        ) from exc
    operation = document.get("operation") if isinstance(document, dict) else None
    if operation not in OPERATIONS:
        raise HelperProtocolError(
            "operation is not allowed by this helper", exit_code=exit_codes.REFUSED
        )
    return raw, str(operation)


def _schedule(parameters: Mapping[str, JsonValue]) -> tuple[Schedule, bool]:
    enabled = parameters.get("enabled")
    try:
        requested = backup_schedule_write.schedule(parameters)
    except backup_schedule_write.ScheduleWriteError as exc:
        raise HelperProtocolError(f"parameters: {exc}", exit_code=exit_codes.REFUSED) from exc
    if type(enabled) is not bool:
        raise HelperProtocolError(
            "parameters.enabled must be true or false", exit_code=exit_codes.REFUSED
        )
    return requested, enabled


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
    return write_document(
        writer,
        failure(
            operation=operation,
            cluster=cluster,
            request_id=request_id,
            code=code,
            message=message,
            exit_code=exit_code,
        ),
        exit_code,
    )


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
        errors.write("ERROR: haprion-backup-job-helper accepts no arguments\n")
        return exit_codes.USAGE
    if require_root and os.geteuid() != 0:
        errors.write("ERROR: haprion-backup-job-helper must run as root\n")
        return exit_codes.NOT_ROOT
    try:
        raw, operation = _raw(input_stream or sys.stdin.buffer)
        request = read_helper_request(
            io.BytesIO(raw),
            expected_operation=operation,
            allowed_parameter_keys=(frozenset() if operation == RUN else SCHEDULE_KEYS),
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
        requested, enabled = _schedule(request.parameters)
        try:
            result = backup_schedule_write.apply(request.cluster, requested, enabled)
        except backup_schedule_write.ScheduleWriteError as exc:
            return _refuse(
                writer,
                errors,
                operation=operation,
                cluster=request.cluster,
                request_id=request.request_id,
                code="schedule_failed",
                message=str(exc),
                exit_code=exit_codes.FAILED,
            )
        return write_document(
            writer,
            envelope(
                operation=operation,
                outcome="done",
                cluster=request.cluster,
                request_id=request.request_id,
                result=result.as_dict(),
            ),
            0,
        )

    try:
        retention = backup_retention.read(request.cluster)
        report = state_backup.run(
            request.cluster,
            cluster,
            policy.backup_identity,
            policy.backup_root,
            retention=retention,
        )
    except (state_backup.BackupRunError, backup_retention.RetentionError) as exc:
        return _refuse(
            writer,
            errors,
            operation=operation,
            cluster=request.cluster,
            request_id=request.request_id,
            code="backup_busy" if isinstance(exc, state_backup.BackupBusy) else "backup_failed",
            message=str(exc),
            exit_code=exit_codes.FAILED,
        )
    document, exit_code = run_document(
        report, cluster=request.cluster, request_id=request.request_id
    )
    return write_document(writer, document, exit_code)


if __name__ == "__main__":
    raise SystemExit(main())
