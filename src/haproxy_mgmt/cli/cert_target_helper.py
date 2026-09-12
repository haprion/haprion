"""Change one certificate's targets in the registry, then publish it there.

The operation the interface's target checkboxes become. One request states the
whole intended target set - not an add and not a remove - because the page it
came from was drawn from a registry some seconds old, and two people editing two
certificates would otherwise each write their own view of the other's.

What it will not do
-------------------
Invent a target. A cluster has to be one `clusters.yaml` defines and a receiver
one the registry already lists; `cert_registry.set_targets` checks both, and a
receiver is registered during installation rather than by a request. That is the
property the phase gate names: the interface can choose targets but cannot
create them, so a certificate cannot be published into a directory nobody
registered.

Delete nothing
--------------
A target dropped here keeps the copy it was last published. Nothing in this
project removes certificate material, and a helper that did would be able to
erase a certificate a cluster is currently serving - a reload away from a site
that no longer answers. The abandoned targets are reported instead, by name, as
a warning the operator can act on by hand.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import BinaryIO, TextIO

from haproxy_mgmt import cert_registry
from haproxy_mgmt.cert_inventory import IMPORT_STORE, LETSENCRYPT_LIVE
from haproxy_mgmt.cert_publish import (
    DEFAULT_LOCK_PATH,
    Deployer,
    PublishError,
    publish,
)
from haproxy_mgmt.cli import cert_job
from haproxy_mgmt.cli.cert_publish import default_deployer
from haproxy_mgmt.cli.cert_publish_helper import publish_exit_code
from haproxy_mgmt.config import DEFAULT_POLICY_PATH, ConfigError, load_policy, load_runtime_config
from haproxy_mgmt.envelope import Message, envelope
from haproxy_mgmt.helper_protocol import (
    HelperProtocolError,
    config_error_code,
    write_document,
)

OPERATION = "cert_target"
PARAMETERS = frozenset({"certificate", "clusters", "receivers", "deploy"})
HELPER = "/opt/haproxy-mgmt/current/bin/haproxy-cert-target-helper"
SUDO = "/usr/bin/sudo"

# EX_CONFIG: the installation has no registry, which is not the request's fault.
EXIT_NO_REGISTRY = 78


def build_request(
    request_id: str,
    *,
    certificate: str,
    clusters: tuple[str, ...] = (),
    receivers: tuple[str, ...] = (),
    deploy: bool = False,
) -> str:
    """The exact bounded request the worker sends. Null cluster, by contract."""

    return json.dumps(
        {
            "schema_version": 1,
            "operation": OPERATION,
            "cluster": None,
            "request_id": request_id,
            "parameters": {
                "certificate": certificate,
                "clusters": list(clusters),
                "receivers": list(receivers),
                "deploy": deploy,
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
            helper_name="haproxy-cert-target-helper",
        )
    except HelperProtocolError as exc:
        errors.write(f"ERROR: {exc}\n")
        return exc.exit_code

    refuse = cert_job.Refuse(OPERATION, request, writer, errors)
    try:
        certificate = cert_job.certificate(request.parameters)
        clusters = cert_job.clusters(request.parameters)
        receivers = cert_job.receivers(request.parameters)
        deploy = cert_job.flag(request.parameters, "deploy")
    except HelperProtocolError as exc:
        return refuse("bad_input", str(exc), exc.exit_code)

    try:
        policy = load_policy(policy_path, require_secure=require_secure)
        runtime = load_runtime_config(policy, require_secure=require_secure)
    except ConfigError as exc:
        return refuse(config_error_code(exc.exit_code), str(exc), exc.exit_code)

    if policy.certificate_registry is None:
        return refuse(
            "dependency_unavailable",
            "no certificate registry is configured. Add certificate_registry to the "
            "runtime policy.",
            EXIT_NO_REGISTRY,
        )

    try:
        change = cert_registry.set_targets(
            policy.certificate_registry,
            certificate_id=certificate,
            clusters=clusters,
            receivers=receivers,
            runtime=runtime,
            require_secure=require_secure,
        )
    except cert_registry.RegistryError as exc:
        return refuse(exc.code, str(exc), exc.exit_code)

    #
    # Re-read rather than patched in memory, for the reason `issue` gives: the
    # publisher must see exactly what the next renewal's hook will see.
    #
    try:
        refreshed = load_runtime_config(policy, require_secure=require_secure)
    except ConfigError as exc:
        return refuse(config_error_code(exc.exit_code), str(exc), exc.exit_code)

    try:
        report = publish(
            refreshed,
            policy,
            only=[certificate],
            live=live,
            store=store,
            lock_path=lock_path,
            deployer=(deployer if deployer is not None else default_deployer(errors))
            if deploy
            else None,
            now=now,
        )
    except PublishError as exc:
        #
        # The registry was already changed and stays changed. Reporting the
        # publish failure as the result of the whole operation is the honest
        # answer - the targets are what the operator asked for, and the material
        # has not reached the new ones yet - and a rollback of the registry here
        # would undo a decision because a later step failed.
        #
        return refuse(exc.code, str(exc), publish_exit_code(exc))

    warnings = [
        Message(code=entry.error[0], message=entry.error[1], node=entry.certificate_id)
        for entry in report.skipped
        if entry.error
    ]
    if change.abandoned:
        warnings.append(
            Message(
                code="target_abandoned",
                message=(
                    "no longer published to: "
                    + ", ".join(change.abandoned)
                    + ". The copy already there was left in place; remove it by hand when "
                    "the target no longer needs it."
                ),
                details={"targets": list(change.abandoned)},
            )
        )

    result = {"registry": change.as_dict(), "publish": report.as_dict()}
    failed = [entry.certificate_id for entry in report.failed]
    not_deployed = [item.cluster for item in report.deployments if item.exit_code != 0]
    if failed or not_deployed:
        parts = []
        if failed:
            parts.append("not published: " + ", ".join(failed))
        if not_deployed:
            parts.append("not deployed: " + ", ".join(not_deployed))
        write_document(
            writer,
            envelope(
                operation=OPERATION,
                outcome="failed",
                cluster=None,
                request_id=request.request_id,
                result=result,
                warnings=tuple(warnings),
                error=Message(code="publish_failed", message="; ".join(parts)),
            ),
        )
        return 1

    write_document(
        writer,
        envelope(
            operation=OPERATION,
            outcome="partial" if warnings else "done",
            cluster=None,
            request_id=request.request_id,
            result=result,
            warnings=tuple(warnings),
        ),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
