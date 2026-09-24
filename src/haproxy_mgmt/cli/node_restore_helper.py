"""Root socket helper for the three node restore jobs (B175).

The worker cannot do this through sudo: a restore writes under /var/lib and
reaches the target over SSH as root, and a sudoed child would inherit the
worker's read-only mount namespace. So the helper answers on a root-owned
socket, like the backup and receiver helpers, and runs the same engine the
terminal's ``haproxy-node-restore`` runs - one implementation, two callers.

``node_restore_prepare``  creates the run and its one-time key; answers with
                          the line the operator pastes on the target
``node_restore_preview``  checks the fingerprint the operator read on the
                          target's console and answers with the plan
``node_restore``          carries out the previewed plan
``node_restore_discard``  removes a run and its one-time key (B182)

Every call also sweeps away the runs past their hour (B182), after answering.

The run ID is chosen by the caller, so the page that follows a restore can be
drawn before its first job has run. It is held to the same pattern the run
directory is, and a run that already exists is refused rather than reused.
"""

from __future__ import annotations

import io
import ipaddress
import json
import os
import re
import sys
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any, BinaryIO, TextIO

from haproxy_mgmt import node_restore, restore_agent
from haproxy_mgmt.backup_archive import ArchiveError
from haproxy_mgmt.config import DEFAULT_POLICY_PATH, ConfigError, load_policy, load_runtime_config
from haproxy_mgmt.envelope import BLOCKED_EXIT, Message, envelope, failure
from haproxy_mgmt.helper_protocol import (
    MAX_REQUEST_BYTES,
    HelperProtocolError,
    JsonValue,
    ParameterValidator,
    config_error_code,
    read_helper_request,
    write_document,
)
from haproxy_mgmt.node_restore import Request, RestoreError
from haproxy_mgmt.restore_plan import TestProfile

PREPARE = "node_restore_prepare"
PREVIEW = "node_restore_preview"
RUN = "node_restore"
DISCARD = "node_restore_discard"
OPERATIONS = frozenset({PREPARE, PREVIEW, RUN, DISCARD})
HELPER = "/opt/haproxy-mgmt/current/bin/haproxy-node-restore-helper"
EXIT_NOT_ROOT = 77

KEYS = {
    PREPARE: frozenset({"run", "node", "archive", "target", "test"}),
    PREVIEW: frozenset({"run", "fingerprint"}),
    RUN: frozenset({"run", "confirm"}),
    DISCARD: frozenset({"run"}),
}
NODE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$")
TEST_KEYS = frozenset({"hostname", "address", "vip"})
#
# The fingerprint as it stands inside the line `ssh-keygen -lf` prints
# ("256 SHA256:... root@host (ED25519)"), unanchored so the whole line can be
# pasted; `validate` still holds the result to the anchored pattern.
#
FINGERPRINT_IN_LINE = re.compile(r"SHA256:[A-Za-z0-9+/]{43}(?![A-Za-z0-9+/=])")

__all__ = [
    "DISCARD",
    "HELPER",
    "KEYS",
    "OPERATIONS",
    "PREPARE",
    "PREVIEW",
    "RUN",
    "ParameterProblem",
    "build_request",
    "fingerprint_in",
    "main",
    "validate",
]


class ParameterProblem(ValueError):
    """The parameters are not what this operation takes."""


def _string(parameters: Mapping[str, Any], name: str) -> str:
    value = parameters.get(name)
    if not isinstance(value, str) or not value:
        raise ParameterProblem(f"{name} is required")
    return value


def test_profile(raw: Any) -> TestProfile | None:
    if raw is None:
        return None
    if not isinstance(raw, dict) or set(raw) != TEST_KEYS:
        raise ParameterProblem("test takes hostname, address and vip, or is null")
    hostname = _string(raw, "hostname")
    if not restore_agent.HOSTNAME.fullmatch(hostname):
        raise ParameterProblem("the test hostname is not a usable host name")
    try:
        address = ipaddress.IPv4Interface(_string(raw, "address"))
        vip = ipaddress.IPv4Interface(_string(raw, "vip"))
    except ValueError as exc:
        raise ParameterProblem("the test address and VIP are written address/prefix") from exc
    if "/" not in raw["address"] or "/" not in raw["vip"]:
        raise ParameterProblem("the test address and VIP are written address/prefix")
    return TestProfile(hostname=hostname, address=address, vip=vip)


def fingerprint_in(text: str) -> str:
    """The SHA256 fingerprint in what the operator pasted, or the text as given.

    The console shows a whole line, and which part of it to copy is a question
    nobody should have to ask. The command line and the web form both read the
    fingerprint through this, so the two accept exactly the same input.
    """

    found = FINGERPRINT_IN_LINE.search(text)
    return found.group(0) if found else text.strip()


def validate(operation: str, parameters: Mapping[str, Any]) -> None:
    """Every check a request's parameters get, shared by this helper and the web form."""

    if operation not in OPERATIONS:
        raise ParameterProblem("not a restore operation")
    unexpected = sorted(set(parameters) - KEYS[operation])
    missing = sorted(KEYS[operation] - set(parameters))
    if unexpected or missing:
        raise ParameterProblem(f"{operation} takes exactly: {', '.join(sorted(KEYS[operation]))}")
    if not restore_agent.RUN_ID.fullmatch(_string(parameters, "run")):
        raise ParameterProblem("the run ID is not usable")
    if operation == PREPARE:
        if not NODE.fullmatch(_string(parameters, "node")):
            raise ParameterProblem("the node is not a node name")
        if not node_restore.VERSION.fullmatch(_string(parameters, "archive")):
            raise ParameterProblem("the archive is named by its version, YYYY-MM-DD_HH-MM-SS")
        try:
            ipaddress.IPv4Address(_string(parameters, "target"))
        except ValueError as exc:
            raise ParameterProblem("the target is an IPv4 address") from exc
        test_profile(parameters["test"])
    elif operation == PREVIEW:
        if not node_restore.FINGERPRINT.fullmatch(_string(parameters, "fingerprint")):
            raise ParameterProblem("the fingerprint is written SHA256: and 43 characters")
    elif operation == RUN and not restore_agent.HOSTNAME.fullmatch(_string(parameters, "confirm")):
        raise ParameterProblem("confirm with the name the node will have")


def build_request(
    operation: str, cluster: str, request_id: str, parameters: Mapping[str, JsonValue]
) -> str:
    """The exact request, built in one place for the worker and the tests alike."""

    validate(operation, parameters)
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


def _checked(operation: str) -> ParameterValidator:
    def check(parameters: Mapping[str, JsonValue]) -> None:
        try:
            validate(operation, parameters)
        except ParameterProblem as exc:
            raise HelperProtocolError(f"parameters: {exc}", exit_code=65) from exc

    return check


def main(
    argv: list[str] | None = None,
    *,
    policy_path: Path = DEFAULT_POLICY_PATH,
    run_root: Path = node_restore.RUN_ROOT,
    input_stream: BinaryIO | None = None,
    output_stream: TextIO | None = None,
    error_stream: TextIO | None = None,
    require_secure: bool = True,
    require_root: bool = True,
    engine: Any = node_restore,
    now: Any = time.time,
) -> int:
    try:
        return _answer(
            argv,
            policy_path=policy_path,
            run_root=run_root,
            input_stream=input_stream,
            output_stream=output_stream,
            error_stream=error_stream,
            require_secure=require_secure,
            require_root=require_root,
            engine=engine,
            now=now,
        )
    finally:
        #
        # After the answer, so a run that has just expired is refused by its
        # own step in words; and not as anyone but root, who owns the runs.
        #
        if not require_root or os.geteuid() == 0:
            try:
                engine.sweep(run_root, now())
            except OSError as exc:
                (error_stream or sys.stderr).write(f"WARNING: sweeping expired runs: {exc}\n")


def _answer(
    argv: list[str] | None,
    *,
    policy_path: Path,
    run_root: Path,
    input_stream: BinaryIO | None,
    output_stream: TextIO | None,
    error_stream: TextIO | None,
    require_secure: bool,
    require_root: bool,
    engine: Any,
    now: Any,
) -> int:
    argv = sys.argv[1:] if argv is None else argv
    writer = output_stream or sys.stdout
    errors = error_stream or sys.stderr
    if argv:
        errors.write("ERROR: haproxy-node-restore-helper accepts no arguments\n")
        return 64
    if require_root and os.geteuid() != 0:
        errors.write("ERROR: haproxy-node-restore-helper must run as root\n")
        return EXIT_NOT_ROOT
    try:
        raw, operation = _raw(input_stream or sys.stdin.buffer)
        request = read_helper_request(
            io.BytesIO(raw),
            expected_operation=operation,
            allowed_parameter_keys=KEYS[operation],
            validate_parameters=_checked(operation),
        )
    except HelperProtocolError as exc:
        errors.write(f"ERROR: {exc}\n")
        return exc.exit_code
    parameters = request.parameters

    def refuse(code: str, message: str, exit_code: int) -> int:
        errors.write(f"ERROR: [{code}] {message}\n")
        write_document(
            writer,
            failure(
                operation=operation,
                cluster=request.cluster,
                request_id=request.request_id,
                code=code,
                message=message,
                exit_code=exit_code,
            ),
        )
        return exit_code

    try:
        policy = load_policy(policy_path, require_secure=require_secure)
        runtime = load_runtime_config(policy, require_secure=require_secure)
        cluster = runtime.cluster(request.cluster)
        if policy.backup_root is None:
            raise RestoreError("the runtime policy declares no backup_root")
    except ConfigError as exc:
        return refuse(config_error_code(exc.exit_code), str(exc), exc.exit_code)
    except RestoreError as exc:
        return refuse("restore_refused", str(exc), BLOCKED_EXIT)

    run = str(parameters["run"])
    try:
        if operation == DISCARD:
            #
            # Not the stored request's cluster check the other steps make: a run
            # already swept has nothing left to compare, and removing nothing is
            # the answer to discarding it. The job's cluster is still the web's.
            #
            directory = run_root / run
            if (directory / "request.json").is_file():
                owner = Request.from_dict(engine.read_json(directory / "request.json")).cluster
                if owner != request.cluster:
                    raise RestoreError(f"run {run} belongs to cluster {owner}")
            removed = engine.discard(run_root, run)
            write_document(
                writer,
                envelope(
                    operation=operation,
                    outcome="done",
                    cluster=request.cluster,
                    request_id=request.request_id,
                    result={"run": run, "removed": removed},
                ),
            )
            return 0

        if operation == PREPARE:
            profile = test_profile(parameters["test"])
            restore = Request(
                run=run,
                cluster=request.cluster,
                node=str(parameters["node"]),
                archive=str(parameters["archive"]),
                target=str(parameters["target"]),
                mode="test" if profile is not None else "new_vm",
                profile=profile,
            )
            node = engine.node_of(cluster, restore.node)
            engine.archive_path(policy.backup_root, node, restore.archive)
            if (run_root / run).exists():
                raise RestoreError(f"a restore run {run} already exists")
            prepared = engine.prepare(run_root, restore, now=now)
            result: dict[str, Any] = {**restore.as_dict(), "paste": prepared["paste"]}
            document = envelope(
                operation=operation,
                outcome="done",
                cluster=request.cluster,
                request_id=request.request_id,
                result=result,
            )
            write_document(writer, document)
            return 0

        stored = Request.from_dict(
            engine.read_json(engine.run_directory(run_root, run) / "request.json")
        )
        if stored.cluster != request.cluster:
            raise RestoreError(f"run {run} belongs to cluster {stored.cluster}")

        if operation == PREVIEW:
            summary = engine.preview(
                run_root,
                run,
                str(parameters["fingerprint"]),
                cluster,
                policy.backup_root,
                publish_root=policy.publish_root,
                progress=errors,
                now=now,
            )
            problems = summary["problems"]
            write_document(
                writer,
                envelope(
                    operation=operation,
                    outcome="blocked" if problems else "done",
                    cluster=request.cluster,
                    request_id=request.request_id,
                    result=summary,
                    error=Message(
                        code="restore_blocked",
                        message="; ".join(problems)[:2048],
                    )
                    if problems
                    else None,
                ),
            )
            return BLOCKED_EXIT if problems else 0

        carried = engine.run(
            run_root,
            run,
            str(parameters["confirm"]),
            cluster,
            policy.backup_root,
            publish_root=policy.publish_root,
            progress=errors,
            now=now,
        )
    except (RestoreError, ArchiveError) as exc:
        return refuse("restore_refused", str(exc), BLOCKED_EXIT)
    except OSError as exc:
        return refuse("restore_failed", f"the restore could not continue: {exc}", 1)

    done = carried["outcome"] == "done"
    result = {key: value for key, value in carried.items() if key not in {"outcome", "error"}}
    write_document(
        writer,
        envelope(
            operation=operation,
            outcome="done" if done else "failed",
            cluster=request.cluster,
            request_id=request.request_id,
            result=result,
            error=None
            if done
            else Message(code="restore_failed", message=str(carried.get("error"))[:2048]),
        ),
    )
    return 0 if done else 1


if __name__ == "__main__":
    raise SystemExit(main())
