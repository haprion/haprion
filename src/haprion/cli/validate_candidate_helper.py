from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import BinaryIO, TextIO

from haprion import exit_codes
from haprion.candidate_validation import (
    DEFAULT_RUN_ROOT,
    MAX_CANDIDATE_BYTES,
    VALIDATION_CERTIFICATE,
    SandboxValidator,
    parse_candidate,
    prepare_run_root,
    read_validation_certificate,
    validate_candidate,
    validate_in_sandbox,
)
from haprion.config import DEFAULT_POLICY_PATH, ConfigError, load_policy, load_runtime_config
from haprion.helper_protocol import (
    HelperProtocolError,
    read_helper_request,
    require_no_arguments,
)


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
    arguments = sys.argv[1:] if argv is None else argv

    try:
        require_no_arguments(arguments)
        if require_root and os.geteuid() != 0:
            raise HelperProtocolError(
                "candidate validation helper must run as root", exit_code=exit_codes.NOT_ROOT
            )
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
        certificate = read_validation_certificate(
            cluster.validation_certs / VALIDATION_CERTIFICATE,
            require_secure=require_secure,
        )
        prepare_run_root(run_root, require_secure=require_secure)
        result = validate_candidate(
            candidate,
            run_root=run_root,
            certificate_ids=cluster.certificate_ids,
            authority_ids=cluster.authority_ids,
            validation_certificate=certificate,
            request_id=request.request_id,
            validator=validator,
        )
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
    return exit_codes.OK if result.valid else exit_codes.REFUSED


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
