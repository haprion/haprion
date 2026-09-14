"""Delete certificates from the registry, the targets, certbot and the nodes.

The privileged half of B139's cleanup operation. The request names a list of
certificate IDs and nothing else; which of them may go, and what deleting one
means, is decided in `cert_delete` from the registry, the cluster files and
each cluster's committed objects - never from the request.

One refused certificate does not stop the batch. The envelope is `done` when
every certificate went through all four layers, `partial` when any was
refused or left a layer behind, and `failed` only when nothing was removed and
something went wrong. A `partial` is the normal answer to a cleanup that
included one certificate somebody still needs, and the row says which; the
same selection deleted again finishes what a `partial` left.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import BinaryIO, TextIO

from haproxy_mgmt import cert_delete
from haproxy_mgmt.cert_delete import HELPER, OPERATION, SUDO, DeleteError, Report
from haproxy_mgmt.cert_inventory import IMPORT_STORE
from haproxy_mgmt.cert_issue import certbot_binary
from haproxy_mgmt.cert_publish import DEFAULT_LOCK_PATH
from haproxy_mgmt.cli import cert_job
from haproxy_mgmt.config import DEFAULT_POLICY_PATH, ConfigError, load_policy
from haproxy_mgmt.envelope import Message, Outcome, envelope
from haproxy_mgmt.helper_protocol import (
    HelperProtocolError,
    config_error_code,
    write_document,
)

PARAMETERS = frozenset({"certificates"})
__all__ = ["HELPER", "SUDO", "build_request", "main", "outcome_of"]
RENEWAL_DIRECTORY = Path("/etc/letsencrypt/renewal")


def build_request(request_id: str, *, certificates: tuple[str, ...]) -> str:
    """The exact bounded request the worker sends. Null cluster, by contract."""

    return json.dumps(
        {
            "schema_version": 1,
            "operation": OPERATION,
            "cluster": None,
            "request_id": request_id,
            "parameters": {"certificates": list(certificates)},
        },
        separators=(",", ":"),
    )


def outcome_of(report: Report) -> tuple[Outcome, int]:
    """`done` all gone; `blocked` every one refused and nothing touched;
    `partial` when any layer of any certificate went; `failed` only when
    nothing at all was removed and something was tried.

    A certificate whose registry entry, files and lineage are gone but whose
    node copies were kept is the normal shape of a deletion run before the
    nodes carry the verb (INSTALLATION.md 1.4.6). Calling that `failed` was
    the first live run's mistake: three layers of four had gone, and the
    envelope said nothing had. `failed` is what is left when the first layer
    already would not go - a PEM that cannot be unlinked, a node that cannot
    be reached for a certificate nothing else holds.
    """

    if report.outcomes and len(report.removed) == len(report.outcomes):
        return "done", 0
    if len(report.refused) == len(report.outcomes):
        return "blocked", 65
    if report.touched or report.refused:
        return "partial", 0
    return "failed", 1


def main(
    argv: list[str] | None = None,
    *,
    policy_path: Path = DEFAULT_POLICY_PATH,
    input_stream: BinaryIO | None = None,
    output_stream: TextIO | None = None,
    error_stream: TextIO | None = None,
    require_secure: bool = True,
    require_root: bool = True,
    renewal_directory: Path = RENEWAL_DIRECTORY,
    store: Path = IMPORT_STORE,
    lock_path: Path = DEFAULT_LOCK_PATH,
    lineage_remover: cert_delete.LineageRemover = cert_delete.run_certbot,
    node_remover: cert_delete.NodeRemover = cert_delete.ask_node,
    guards_reader: cert_delete.GuardsReader = cert_delete.read_guards,
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
            helper_name="haproxy-cert-delete-helper",
        )
    except HelperProtocolError as exc:
        errors.write(f"ERROR: {exc}\n")
        return exc.exit_code

    refuse = cert_job.Refuse(OPERATION, request, writer, errors)
    try:
        certificates = cert_job.certificates(request.parameters)
    except HelperProtocolError as exc:
        return refuse("bad_input", str(exc), exc.exit_code)
    if not certificates:
        return refuse("bad_input", "parameters.certificates names no certificate", 65)

    try:
        policy = load_policy(policy_path, require_secure=require_secure)
    except ConfigError as exc:
        return refuse(config_error_code(exc.exit_code), str(exc), exc.exit_code)

    try:
        report = cert_delete.delete(
            certificates,
            policy,
            require_secure=require_secure,
            renewal_directory=renewal_directory,
            store=store,
            lock_path=lock_path,
            certbot=certbot_binary(policy),
            lineage_remover=lineage_remover,
            node_remover=node_remover,
            guards_reader=guards_reader,
        )
    except DeleteError as exc:
        return refuse(exc.code, str(exc), exc.exit_code)

    outcome, exit_code = outcome_of(report)
    warnings = tuple(
        Message(
            code=item.code or "incomplete",
            message=item.reason,
            details={"certificate": item.certificate_id},
        )
        for item in report.outcomes
        if item.state != "removed"
    )
    error = None
    if outcome == "blocked":
        error = Message(
            code="all_refused",
            message="every certificate was refused: " + ", ".join(report.refused),
        )
    elif outcome == "failed":
        error = Message(
            code="delete_failed",
            message="nothing was removed: " + ", ".join(report.incomplete),
        )
    write_document(
        writer,
        envelope(
            operation=OPERATION,
            outcome=outcome,
            cluster=None,
            request_id=request.request_id,
            result=report.as_dict(),
            warnings=warnings,
            error=error,
        ),
    )
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
