"""Publish certificates to more targets, or withdraw them from some.

The operation the interface's *Publish to…* and *Remove from…* become. One
request names a list of certificates and one delta - targets to add, or
targets to remove - and `cert_retarget` decides per certificate what that
means from the registry, the cluster files and each cluster's committed
objects; never from the request. Until 2026-09-15 this helper took one
certificate and its whole new target set, and left a dropped cluster's copy
on its nodes; the batch and the removal are the maintainer's two asks.

One refused certificate does not stop the batch. The envelope is `done` when
every certificate followed the request, `partial` when any was refused or
left a copy behind or a rollout failed, `blocked` when every one was refused,
and `failed` only when nothing changed and something went wrong.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import BinaryIO, TextIO

from haprion import cert_retarget, exit_codes, labels
from haprion.cert_delete import NodeRemover, ask_node, read_guards
from haprion.cert_inventory import IMPORT_STORE, LETSENCRYPT_LIVE
from haprion.cert_publish import DEFAULT_LOCK_PATH, Deployer
from haprion.cert_retarget import HELPER, OPERATION, SUDO, Change, Report, RetargetError
from haprion.cli import cert_job
from haprion.cli.cert_publish import default_deployer
from haprion.config import DEFAULT_POLICY_PATH, ConfigError, load_policy
from haprion.envelope import Message, Outcome, envelope
from haprion.helper_protocol import (
    HelperProtocolError,
    JsonValue,
    config_error_code,
    write_document,
)

PARAMETERS = frozenset({"certificates", "add", "remove", "deploy"})

__all__ = ["HELPER", "SUDO", "build_request", "main", "outcome_of"]


def build_request(
    request_id: str,
    *,
    certificates: tuple[str, ...],
    action: str,
    clusters: tuple[str, ...] = (),
    receivers: tuple[str, ...] = (),
    deploy: bool = True,
    formats: Mapping[str, str] | None = None,
) -> str:
    """The exact bounded request the worker sends. Null cluster, by contract."""

    block: dict[str, JsonValue] = {"clusters": list(clusters), "receivers": list(receivers)}
    if formats:
        block["formats"] = dict(formats)
    return json.dumps(
        {
            "schema_version": 1,
            "operation": OPERATION,
            "cluster": None,
            "request_id": request_id,
            "parameters": {
                "certificates": list(certificates),
                action: block,
                "deploy": deploy,
            },
        },
        separators=(",", ":"),
    )


def read_change(parameters: Mapping[str, JsonValue]) -> Change:
    """Exactly one of `add` and `remove`, each an object of cluster and receiver IDs."""

    present = [key for key in ("add", "remove") if key in parameters]
    if len(present) != 1:
        raise HelperProtocolError(
            "parameters must carry exactly one of add and remove", exit_code=exit_codes.REFUSED
        )
    action = present[0]
    block = parameters.get(action)
    if not isinstance(block, dict):
        raise HelperProtocolError(
            f"parameters.{action} must be an object", exit_code=exit_codes.REFUSED
        )
    unknown = sorted(set(block) - {"clusters", "receivers", "formats"})
    if unknown:
        raise HelperProtocolError(
            f"parameters.{action} has unknown {labels.noun(len(unknown), 'key')}: {', '.join(unknown)}",
            exit_code=exit_codes.REFUSED,
        )
    if action == "remove" and "formats" in block:
        raise HelperProtocolError(
            "parameters.remove does not take formats", exit_code=exit_codes.REFUSED
        )
    receivers = cert_job.receivers(block)
    change = Change(
        action,
        clusters=cert_job.clusters(block),
        receivers=receivers,
        formats=cert_job.formats(block, receivers),
    )
    if not change.targets:
        raise HelperProtocolError(
            f"parameters.{action} names no target", exit_code=exit_codes.REFUSED
        )
    return change


def outcome_of(report: Report) -> tuple[Outcome, int]:
    """`done` every certificate as asked; `blocked` every one refused; `partial`
    when anything followed and something did not; `failed` when nothing did."""

    if not report.outcomes:
        return "failed", exit_codes.FAILED
    followed = len(report.changed) + len(report.unchanged)
    if followed == len(report.outcomes) and not report.deploy_failed:
        return "done", exit_codes.OK
    if len(report.refused) == len(report.outcomes):
        return "blocked", exit_codes.BLOCKED
    if followed or report.incomplete:
        return "partial", exit_codes.PARTIAL
    return "failed", exit_codes.FAILED


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
    node_remover: NodeRemover = ask_node,
    guards_reader: cert_retarget.GuardsReader = read_guards,
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
            helper_name="haprion-cert-target-helper",
        )
    except HelperProtocolError as exc:
        errors.write(f"ERROR: {exc}\n")
        return exc.exit_code

    refuse = cert_job.Refuse(OPERATION, request, writer, errors)
    try:
        certificates = cert_job.certificates(request.parameters)
        change = read_change(request.parameters)
        deploy = (
            cert_job.flag(request.parameters, "deploy") if "deploy" in request.parameters else True
        )
    except HelperProtocolError as exc:
        return refuse("bad_input", str(exc), exc.exit_code)
    if not certificates:
        return refuse(
            "bad_input", "parameters.certificates names no certificate", exit_codes.REFUSED
        )

    try:
        policy = load_policy(policy_path, require_secure=require_secure)
    except ConfigError as exc:
        return refuse(config_error_code(exc.exit_code), str(exc), exc.exit_code)

    if policy.certificate_registry is None:
        return refuse(
            "dependency_unavailable",
            "no certificate registry is configured. Add certificate_registry to the "
            "runtime policy.",
            exit_codes.CONFIG,
        )

    try:
        report = cert_retarget.retarget(
            certificates,
            change,
            policy,
            deploy=deploy,
            require_secure=require_secure,
            live=live,
            store=store,
            lock_path=lock_path,
            deployer=deployer if deployer is not None else default_deployer(errors),
            node_remover=node_remover,
            guards_reader=guards_reader,
            now=now,
        )
    except RetargetError as exc:
        return refuse(exc.code, str(exc), exc.exit_code)

    outcome, exit_code = outcome_of(report)
    warnings = [
        Message(
            code=item.code or "incomplete",
            message=item.reason,
            details={"certificate": item.certificate_id},
        )
        for item in report.outcomes
        if item.state in {"refused", "incomplete"}
    ]
    for cluster_id in report.deploy_failed:
        warnings.append(
            Message(
                code="deploy_failed",
                message=f"cluster {cluster_id} was not rolled out; deploy it again",
                details={"cluster": cluster_id},
            )
        )
    error = None
    if outcome == "blocked":
        error = Message(
            code="all_refused",
            message="every certificate was refused: " + ", ".join(report.refused),
        )
    elif outcome == "failed":
        error = Message(code="retarget_failed", message="no certificate's targets changed")
    return write_document(
        writer,
        envelope(
            operation=OPERATION,
            outcome=outcome,
            cluster=None,
            request_id=request.request_id,
            result=report.as_dict(),
            warnings=tuple(warnings),
            error=error,
        ),
        exit_code,
    )


if __name__ == "__main__":
    raise SystemExit(main())
