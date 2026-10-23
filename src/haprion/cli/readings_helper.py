"""`haprion-readings-helper` - the poller's manager-local readings in one call (review 26-10-08, N2).

Six of the poller's readings touch nothing but the manager: the version
listing, the backup archives, the certificate list, the network description,
the cluster settings and the stored objects. Each was its own helper behind
its own sudo rule, run once per cluster every pass - sixteen sudo calls a pass
for two clusters, and with every call sudo-rs's warning and two PAM lines, some
70 % of the manager's journal (measured 26-10-08). The readings stay as fresh
as they were; only the number of privileged calls changes.

This helper asks for them in one call. It runs each reading's own helper - its
`main`, in this process, with the request that helper always received - so
nothing is read a second way: every reading is validated, refused and answered
exactly as before, and the answer carries each helper's own envelope and exit
code. A reading that fails is that reading's answer; the others still come.

The caller names a cluster and, per reading, the parameters that reading's
helper takes - the diffs the version listing is asked for, the fingerprint the
object listing may be unchanged since. Which readings exist is fixed here. A
null cluster asks for the manager's own readings, of which `cert_list` is the
one (B304): every pass makes it, whether or not a cluster exists yet.
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, BinaryIO, TextIO

from haprion import exit_codes
from haprion.cli import (
    cert_list_helper,
    cluster_settings_helper,
    list_backups_helper,
    list_helper,
    network_helper,
    objects_helper,
)
from haprion.config import DEFAULT_POLICY_PATH
from haprion.envelope import envelope
from haprion.helper_protocol import (
    HelperProtocolError,
    HelperRequest,
    JsonValue,
    read_scoped_request,
    require_no_arguments,
    write_document,
)

OPERATION = "readings"
PARAMETERS = frozenset({"reads"})
HELPER = "/opt/haprion/current/bin/haprion-readings-helper"
SUDO = "/usr/bin/sudo"
#
# What each reading's `stderr` is cut to in the answer: enough for the error a
# helper writes there, never a page of it.
#
MAX_STDERR = 2048

type Helper = Callable[..., int]

READINGS: Mapping[str, Helper] = {
    list_helper.OPERATION: list_helper.main,
    list_backups_helper.OPERATION: list_backups_helper.main,
    cert_list_helper.OPERATION: cert_list_helper.main,
    network_helper.OPERATION: network_helper.main,
    cluster_settings_helper.OPERATION: cluster_settings_helper.main,
    objects_helper.OPERATION: objects_helper.main,
}
#
# The readings that answer for the manager when the cluster is null. Each of
# their helpers takes either form; the others would refuse a null cluster, and
# are refused here first so the answer names the reading.
#
MANAGER_READINGS: frozenset[str] = frozenset({cert_list_helper.OPERATION})


def build_request(
    cluster: str | None, request_id: str, reads: Mapping[str, Mapping[str, Any]]
) -> str:
    """The poller's one request: each reading named with its own parameters."""

    return json.dumps(
        {
            "schema_version": 1,
            "operation": OPERATION,
            "cluster": cluster,
            "request_id": request_id,
            "parameters": {"reads": {name: dict(value) for name, value in reads.items()}},
        },
        separators=(",", ":"),
    )


def run_readings_helper(
    cluster: str | None, request_id: str, reads: Mapping[str, Mapping[str, Any]]
) -> subprocess.CompletedProcess[str]:
    """Ask the root helper for these readings of one cluster, or of the manager."""

    return subprocess.run(  # noqa: S603 - fixed helper path, no caller argv
        [SUDO, "-n", HELPER],
        input=build_request(cluster, request_id, reads),
        capture_output=True,
        text=True,
        check=False,
    )


def _reads(parameters: Mapping[str, JsonValue]) -> dict[str, dict[str, JsonValue]]:
    raw = parameters.get("reads")
    if not isinstance(raw, dict) or not raw:
        raise HelperProtocolError(
            "parameters.reads must name at least one reading", exit_code=exit_codes.REFUSED
        )
    unknown = sorted(set(raw) - set(READINGS))
    if unknown:
        raise HelperProtocolError(
            f"unknown reading(s): {', '.join(unknown)}", exit_code=exit_codes.REFUSED
        )
    reads: dict[str, dict[str, JsonValue]] = {}
    for name, value in raw.items():
        if not isinstance(value, dict):
            raise HelperProtocolError(
                f"parameters.reads.{name} must be an object", exit_code=exit_codes.REFUSED
            )
        reads[name] = value
    return reads


def read_one(
    helper: Helper,
    request: Mapping[str, Any],
    *,
    policy_path: Path,
    require_secure: bool,
    require_root: bool,
) -> dict[str, Any]:
    """One reading: its helper's own answer, exit code and error text."""

    output, errors = io.StringIO(), io.StringIO()
    try:
        code = helper(
            [],
            policy_path=policy_path,
            input_stream=io.BytesIO(json.dumps(request).encode("utf-8")),
            output_stream=output,
            error_stream=errors,
            require_secure=require_secure,
            require_root=require_root,
        )
    except Exception as exc:  # noqa: BLE001 - one reading that breaks is that reading's answer
        code, errors = exit_codes.INTERNAL, io.StringIO(f"ERROR: {type(exc).__name__}: {exc}\n")
    try:
        answer: Any = json.loads(output.getvalue()) if output.getvalue().strip() else None
    except json.JSONDecodeError:
        answer = None
    return {"exit_code": code, "envelope": answer, "stderr": errors.getvalue()[:MAX_STDERR]}


def main(
    argv: list[str] | None = None,
    *,
    policy_path: Path = DEFAULT_POLICY_PATH,
    input_stream: BinaryIO | None = None,
    output_stream: TextIO | None = None,
    error_stream: TextIO | None = None,
    require_secure: bool = True,
    require_root: bool = True,
    readings: Mapping[str, Helper] = READINGS,
) -> int:
    argv = sys.argv[1:] if argv is None else argv
    writer: TextIO = output_stream or sys.stdout
    errors: TextIO = error_stream or sys.stderr

    try:
        require_no_arguments(argv)
        if require_root and os.geteuid() != 0:
            raise HelperProtocolError(
                "haprion-readings-helper must run as root", exit_code=exit_codes.NOT_ROOT
            )
        request = read_scoped_request(
            input_stream or sys.stdin.buffer,
            expected_operation=OPERATION,
            allowed_parameter_keys=PARAMETERS,
        )
        reads = _reads(request.parameters)
        cluster = request.cluster if isinstance(request, HelperRequest) else None
        if cluster is None and not set(reads) <= MANAGER_READINGS:
            refused = ", ".join(sorted(set(reads) - MANAGER_READINGS))
            raise HelperProtocolError(
                f"reading(s) that need a cluster: {refused}", exit_code=exit_codes.REFUSED
            )
    except HelperProtocolError as exc:
        errors.write(f"ERROR: {exc}\n")
        return exc.exit_code

    answers = {
        name: read_one(
            readings[name],
            {
                "schema_version": 1,
                "operation": name,
                "cluster": cluster,
                "request_id": request.request_id,
                "parameters": parameters,
            },
            policy_path=policy_path,
            require_secure=require_secure,
            require_root=require_root,
        )
        for name, parameters in reads.items()
    }
    return write_document(
        writer,
        envelope(
            operation=OPERATION,
            outcome="done",
            cluster=cluster,
            request_id=request.request_id,
            result={"reads": answers},
        ),
        0,
    )


if __name__ == "__main__":
    raise SystemExit(main())
