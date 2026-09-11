"""The privileged half of `haproxy-cert-publish` - registered certificates to their targets.

The same `publish` the certbot deploy hook runs, reached from a job instead of
from a hook. The caller may narrow the run to certificates the registry already
lists and may ask for the rollout afterwards; it cannot name a path, an account
or a target, because every one of those is read from the registry and the
runtime policy.

`partial` is a real outcome here and not a rounding of failure: a registry can
hold an entry whose source is an import whose material has not arrived yet, and
a run that published everything else is not a failed run. The skipped entries
arrive as warnings naming each one.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import BinaryIO, TextIO

from haproxy_mgmt.cert_publish import (
    DEFAULT_LOCK_PATH,
    IMPORT_STORE,
    LETSENCRYPT_LIVE,
    Deployer,
    PublishError,
    Report,
    publish,
)
from haproxy_mgmt.cli import cert_job
from haproxy_mgmt.cli.cert_publish import default_deployer
from haproxy_mgmt.config import DEFAULT_POLICY_PATH, ConfigError, load_policy, load_runtime_config
from haproxy_mgmt.envelope import BLOCKED_EXIT, Message, envelope
from haproxy_mgmt.helper_protocol import (
    HelperProtocolError,
    config_error_code,
    write_document,
)

OPERATION = "cert_publish"
PARAMETERS = frozenset({"certificates", "deploy"})
HELPER = "/opt/haproxy-mgmt/current/bin/haproxy-cert-publish-helper"
SUDO = "/usr/bin/sudo"


def build_request(
    request_id: str,
    *,
    certificates: tuple[str, ...] = (),
    deploy: bool = False,
) -> str:
    """The exact bounded request the worker sends. An empty list means all of them."""

    return json.dumps(
        {
            "schema_version": 1,
            "operation": OPERATION,
            "cluster": None,
            "request_id": request_id,
            "parameters": {"certificates": list(certificates), "deploy": deploy},
        },
        separators=(",", ":"),
    )


def result_envelope(report: Report, *, request_id: str) -> tuple[dict[str, object], int]:
    """One report, turned into the one envelope and exit code it means.

    Shared with the target helper, which publishes the certificate it just
    retargeted and has to answer in exactly these terms.
    """

    warnings = tuple(
        Message(code=entry.error[0], message=entry.error[1], node=entry.certificate_id)
        for entry in report.skipped
        if entry.error
    )
    failed = [entry.certificate_id for entry in report.failed]
    not_deployed = [item.cluster for item in report.deployments if item.exit_code != 0]
    if not failed and not not_deployed:
        return (
            envelope(
                operation=OPERATION,
                outcome="partial" if warnings else "done",
                cluster=None,
                request_id=request_id,
                result=report.as_dict(),
                warnings=warnings,
            ),
            0,
        )
    parts = []
    if failed:
        parts.append("not published: " + ", ".join(failed))
    if not_deployed:
        parts.append("not deployed: " + ", ".join(not_deployed))
    return (
        envelope(
            operation=OPERATION,
            outcome="failed",
            cluster=None,
            request_id=request_id,
            result=report.as_dict(),
            warnings=warnings,
            error=Message(code="publish_failed", message="; ".join(parts)),
        ),
        1,
    )


def publish_exit_code(exc: PublishError) -> int:
    """The publisher's refusal, in the contract's exit codes.

    Three cases and no default that guesses: a lock is the one refusal the
    contract calls `blocked` rather than `failed`, a bad request is the caller's,
    and everything else is the installation's. Written out so a new refusal code
    in the publisher lands as a decision somebody makes here.
    """

    if exc.code == "operation_locked":
        return BLOCKED_EXIT
    return 64 if exc.code == "bad_input" else 78


def main(
    argv: list[str] | None = None,
    *,
    policy_path: Path = DEFAULT_POLICY_PATH,
    input_stream: BinaryIO | None = None,
    output_stream: TextIO | None = None,
    error_stream: TextIO | None = None,
    require_secure: bool = True,
    require_root: bool = True,
    deployer: Deployer | None = None,
    live: Path = LETSENCRYPT_LIVE,
    store: Path = IMPORT_STORE,
    lock_path: Path = DEFAULT_LOCK_PATH,
    now: datetime | None = None,
) -> int:
    argv = sys.argv[1:] if argv is None else argv
    writer: TextIO = output_stream or sys.stdout
    errors: TextIO = error_stream or sys.stderr

    try:
        request = cert_job.read_request(
            OPERATION,
            parameters=PARAMETERS,
            input_stream=input_stream,
            argv=argv,
            require_root=require_root,
            helper_name="haproxy-cert-publish-helper",
        )
    except HelperProtocolError as exc:
        errors.write(f"ERROR: {exc}\n")
        return exc.exit_code

    refuse = cert_job.Refuse(OPERATION, request, writer, errors)
    try:
        only = cert_job.certificates(request.parameters)
        deploy = cert_job.flag(request.parameters, "deploy")
    except HelperProtocolError as exc:
        return refuse("bad_input", str(exc), exc.exit_code)

    try:
        policy = load_policy(policy_path, require_secure=require_secure)
        runtime = load_runtime_config(policy, require_secure=require_secure)
    except ConfigError as exc:
        return refuse(config_error_code(exc.exit_code), str(exc), exc.exit_code)

    try:
        report = publish(
            runtime,
            policy,
            #
            # An empty list is every certificate, which is what the hook does.
            # `publish` says that with None, and the difference is kept at this
            # boundary rather than given to the caller as two ways to say it.
            #
            only=list(only) or None,
            live=live,
            store=store,
            lock_path=lock_path,
            deployer=(deployer if deployer is not None else default_deployer(errors))
            if deploy
            else None,
            now=now,
        )
    except PublishError as exc:
        return refuse(exc.code, str(exc), publish_exit_code(exc))

    document, exit_code = result_envelope(report, request_id=request.request_id)
    write_document(writer, document)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
