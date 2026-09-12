"""The privileged half of `haproxy-cert-issue` - one ACME certificate, from a job.

Calls the same `issue` the terminal command calls, so the five-minute gate C3
measured is the same code path the interface will use. What this half adds is
the boundary: a bounded request in, one envelope out, and no way to name a
file, a directory, an account or a certbot flag.

What the caller may decide: a domain, a challenge method, and targets that the
registry already knows. Everything certbot is told beyond that is fixed in the
engine or read from the runtime policy.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import BinaryIO, TextIO

from haproxy_mgmt.cert_inventory import IMPORT_STORE, LETSENCRYPT_LIVE
from haproxy_mgmt.cert_issue import Certbot, IssueError, issue, run_certbot
from haproxy_mgmt.cert_publish import DEFAULT_LOCK_PATH, Deployer
from haproxy_mgmt.cli import cert_job
from haproxy_mgmt.cli.cert_issue import result_envelope
from haproxy_mgmt.cli.cert_publish import default_deployer
from haproxy_mgmt.config import DEFAULT_POLICY_PATH, ConfigError, load_policy, load_runtime_config
from haproxy_mgmt.helper_protocol import (
    HelperProtocolError,
    config_error_code,
    write_document,
)

OPERATION = "cert_issue"
PARAMETERS = frozenset({"domain", "method", "clusters", "receivers"})
MAX_DOMAIN_BYTES = 255
HELPER = "/opt/haproxy-mgmt/current/bin/haproxy-cert-issue-helper"
SUDO = "/usr/bin/sudo"


def build_request(
    request_id: str,
    *,
    domain: str,
    method: str,
    clusters: tuple[str, ...] = (),
    receivers: tuple[str, ...] = (),
) -> str:
    """The exact bounded request the worker sends. Null cluster, by contract."""

    return json.dumps(
        {
            "schema_version": 1,
            "operation": OPERATION,
            "cluster": None,
            "request_id": request_id,
            "parameters": {
                "domain": domain,
                "method": method,
                "clusters": list(clusters),
                "receivers": list(receivers),
            },
        },
        separators=(",", ":"),
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
    certbot: Certbot = run_certbot,
    deployer: Deployer | None = None,
    live: Path = LETSENCRYPT_LIVE,
    store: Path = IMPORT_STORE,
    lock_path: Path = DEFAULT_LOCK_PATH,
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
            helper_name="haproxy-cert-issue-helper",
        )
    except HelperProtocolError as exc:
        errors.write(f"ERROR: {exc}\n")
        return exc.exit_code

    refuse = cert_job.Refuse(OPERATION, request, writer, errors)
    try:
        domain = request.parameters.get("domain")
        if (
            not isinstance(domain, str)
            or not domain
            or len(domain.encode("utf-8")) > MAX_DOMAIN_BYTES
        ):
            raise HelperProtocolError("parameters.domain must be a domain name", exit_code=65)
        method = request.parameters.get("method")
        if not isinstance(method, str) or not method:
            raise HelperProtocolError("parameters.method must be a string", exit_code=65)
        clusters = cert_job.clusters(request.parameters)
        receivers = cert_job.receivers(request.parameters)
    except HelperProtocolError as exc:
        return refuse("bad_input", str(exc), exc.exit_code)

    try:
        policy = load_policy(policy_path, require_secure=require_secure)
        runtime = load_runtime_config(policy, require_secure=require_secure)
    except ConfigError as exc:
        return refuse(config_error_code(exc.exit_code), str(exc), exc.exit_code)

    #
    # Rolled out at the end, with the same `haproxy-cert-deploy` the hook uses.
    # A certificate that is published but not deployed is one the nodes do not
    # have, and the gate this phase lives or dies on is measured from the click
    # to a certificate that actually answers.
    #
    try:
        result = issue(
            domain=domain,
            method=method,
            clusters=clusters,
            receivers=receivers,
            policy=policy,
            runtime=runtime,
            certbot=certbot,
            deployer=deployer if deployer is not None else default_deployer(errors),
            live=live,
            store=store,
            lock_path=lock_path,
            require_secure=require_secure,
        )
    except IssueError as exc:
        return refuse(exc.code, str(exc), exc.exit_code, exc.details)

    document, exit_code = result_envelope(result, request_id=request.request_id)
    write_document(writer, document)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
