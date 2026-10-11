"""The privileged half of `haprion-cert-deploy` - the reconcile loop, for certificates.

Shares the loop, the matrix and the node result with `haprion-deploy-helper`,
because §6.4 says certificate rollout follows exactly the same ordering,
blocking and partial rules as configuration rollout, and the frozen contracts
agree. What differs is one object: the target. Everything the operator sees
about ordering, blocking and catch-up is therefore the same by construction
rather than by two implementations happening to agree.

What this half decides, and the caller cannot
---------------------------------------------
Which certificates go out. The referenced list is read here, from the cluster
configuration, and the bytes are identified here, from the distribution
directory. The unprivileged caller sends a cluster name and two booleans.

Every referenced certificate is resolved before the first node is touched. A
missing one stops the run with nothing done, rather than being discovered after
half the pair has been reloaded.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import BinaryIO, TextIO, cast

from haprion.certificates import CertificateError, target_for
from haprion.cli.deploy_helper import (
    EXIT_NO_IDENTITY,
    EXIT_NOT_ROOT,
    SSH,
    SSH_OPTIONS,
    read_status,
    run_trigger,
)
from haprion.cluster_lock import DEFAULT_LOCK_ROOT, LockBusy, hold
from haprion.cluster_status import NodeStatus
from haprion.config import (
    DEFAULT_POLICY_PATH,
    ConfigError,
    DeployIdentity,
    load_policy,
    load_runtime_config,
)
from haprion.deploy_plan import CertificateTarget
from haprion.deploy_run import CERT_OPERATION, ReadStatus, TriggerNode, run
from haprion.envelope import failure
from haprion.helper_protocol import (
    HelperProtocolError,
    JsonValue,
    Lifeline,
    read_helper_request,
    require_no_arguments,
    write_document,
)

OPERATION = "cert_deploy_cluster"
PARAMETERS = frozenset({"allow_vip_unknown", "json"})

#
# The verb the node's trigger wrapper expects, followed by the certificate IDs.
# It lands in SSH_ORIGINAL_COMMAND on the node, where the wrapper validates it
# unprivileged before escalating - so this string is a request, never a command
# that runs as written.
#
REQUEST_VERB = "cert-pull"
#
# The same for the cluster's authorities (B276), the CA files its pools verify
# against. A verb of its own because the node fetches them from their own
# directory and installs them in one; a node without the verb refuses it, and
# the run then reports that node as failed rather than as current.
#
AUTHORITY_VERB = "ca-pull"

# EX_CONFIG: the installation is incomplete rather than the caller being wrong.
EXIT_NO_CERTIFICATE_ROOT = 78


def _validate(parameters: Mapping[str, JsonValue]) -> None:
    for key in PARAMETERS:
        value = parameters.get(key, False)
        if not isinstance(value, bool):
            raise HelperProtocolError(f"{key} must be a boolean", exit_code=65)


def trigger_node(
    node: NodeStatus,
    identity: DeployIdentity,
    target: CertificateTarget,
    writer: TextIO,
) -> int:
    """Ask one node to pull the referenced certificates. Its output is the operator's.

    The IDs are sent as the requested command. They came from the cluster
    configuration, which validates their form, and the node validates them again
    twice - in the unprivileged wrapper and in the root helper - because a node
    must not depend on the caller having been honest.
    """

    requests = []
    #
    # The authorities first: they are what a pool's `ca-file` reads, and a
    # certificate pull reloads HAProxy, which would read a missing one.
    #
    if target.authorities:
        requests.append(" ".join([AUTHORITY_VERB, *(ref.id for ref in target.authorities)]))
    requests.append(" ".join([REQUEST_VERB, *(ref.id for ref in target.certificates)]))
    for request in requests:
        code = run_trigger(
            [
                SSH,
                *SSH_OPTIONS,
                "-i",
                str(identity.key),
                f"{identity.user}@{node.mgmt_host}",
                request,
            ],
            node.name,
            writer,
        )
        if code != 0:
            return code
    return 0


def main(
    argv: list[str] | None = None,
    *,
    policy_path: Path = DEFAULT_POLICY_PATH,
    input_stream: BinaryIO | None = None,
    output_stream: TextIO | None = None,
    error_stream: TextIO | None = None,
    require_secure: bool = True,
    require_root: bool = True,
    lock_root: Path = DEFAULT_LOCK_ROOT,
    status_reader: ReadStatus | None = None,
    node_trigger: TriggerNode | None = None,
) -> int:
    argv = sys.argv[1:] if argv is None else argv
    writer: TextIO = output_stream or sys.stdout
    errors: TextIO = error_stream or sys.stderr

    try:
        require_no_arguments(argv)
        if require_root and os.geteuid() != 0:
            raise HelperProtocolError(
                "haprion-cert-deploy-helper must run as root", exit_code=EXIT_NOT_ROOT
            )
        request = read_helper_request(
            input_stream or sys.stdin.buffer,
            expected_operation=OPERATION,
            allowed_parameter_keys=PARAMETERS,
            validate_parameters=_validate,
            lifeline=True,
        )
    except HelperProtocolError as exc:
        #
        # Deliberately stderr only. JSON mode, the cluster and the request ID an
        # envelope must be bound to are all fields of the request that just
        # failed to parse; an envelope invented here could not be bound to the
        # caller's job, and would rightly be rejected as somebody else's answer.
        #
        errors.write(f"ERROR: {exc}\n")
        return exc.exit_code

    allow_vip_unknown = bool(request.parameters.get("allow_vip_unknown", False))
    json_mode = bool(request.parameters.get("json", False))

    def refuse(code: str, message: str, exit_code: int) -> int:
        """End the run with a result, not just an exit code.

        Everything below this point knows which job it belongs to, so every exit
        can carry the envelope the contract promises on every path. Without it a
        worker sees an unparseable answer and stores `unknown` - "this may have
        taken effect" - for a refusal that provably reached no node.
        """

        #
        # The code beside the message, not instead of it. The terminal, the jobs
        # page and the audit trail then name the same string for the same
        # failure, so "what my window said" and "what the page says" can be put
        # side by side without guessing. Added 2026-08-31 as F1b.
        #
        errors.write(f"ERROR: [{code}] {message}\n")
        if json_mode:
            write_document(
                writer,
                failure(
                    operation=CERT_OPERATION,
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
        cluster = load_runtime_config(policy, require_secure=require_secure).cluster(
            request.cluster
        )
    except ConfigError as exc:
        return refuse(
            "bad_input" if exc.exit_code == 64 else "dependency_unavailable",
            str(exc),
            exc.exit_code,
        )

    if policy.certificate_root is None:
        return refuse(
            "dependency_unavailable",
            "no certificate root is configured. Add certificate_root to the runtime policy.",
            EXIT_NO_CERTIFICATE_ROOT,
        )

    identity = policy.cert_deploy_identity
    if identity is None and node_trigger is None:
        return refuse(
            "dependency_unavailable",
            "no certificate deploy identity is configured. Add cert_deploy_identity "
            "with 'user' and 'key' to the runtime policy.",
            EXIT_NO_IDENTITY,
        )

    #
    # Resolved before the lock is taken and before anything is sent: a run that
    # cannot name what it is deploying has nothing to do, and holding the
    # cluster's lock while finding that out would block an operator who could
    # have run something useful.
    #
    try:
        target = target_for(cluster, policy.certificate_root)
    except CertificateError as exc:
        return refuse("certificate_missing", str(exc), 68)

    #
    # In JSON mode the rollout text goes to stderr, the job's diagnostics, so a
    # node that refuses says why on the jobs page too; stdout stays the
    # document alone. As in deploy_helper (26-10-03).
    #
    stream: TextIO = errors if json_mode else writer

    status_identity = policy.status_identity
    if status_identity is None and status_reader is None:
        #
        # Not defaulted to the deploy identity, however convenient that would
        # be here. Reading a node and changing one are separate identities on
        # purpose, and quietly reading with the identity that can act would
        # dissolve that separation at exactly the moment nobody is looking.
        #
        return refuse(
            "dependency_unavailable",
            "no status identity is configured. Add status_identity with "
            "'user' and 'key' to the runtime policy.",
            EXIT_NO_IDENTITY,
        )

    read: ReadStatus = status_reader or (
        lambda: read_status(cluster, cast(DeployIdentity, status_identity))
    )

    def default_trigger(node: NodeStatus) -> int:
        assert identity is not None  # noqa: S101 - guarded above, stated for the reader
        return trigger_node(node, identity, target, stream)

    trigger: TriggerNode = node_trigger or default_trigger

    #
    # Watched only if the caller said it is holding the stream; see the same
    # note in the deploy helper.
    #
    lifeline = Lifeline.take(input_stream or sys.stdin.buffer) if request.lifeline else None
    if lifeline is not None:
        lifeline.watch()

    try:
        #
        # The same per-cluster lock configuration deployment takes. The two must
        # exclude each other: a certificate landing halfway through a
        # configuration rollout would be validated against a tree that is about
        # to be replaced.
        #
        with hold(request.cluster, operation="cert_deploy", root=lock_root):
            outcome = run(
                read,
                trigger,
                stream,
                target=target,
                allow_vip_unknown=allow_vip_unknown,
                operation=CERT_OPERATION,
                lifeline=lifeline,
            )
    except LockBusy as exc:
        return refuse("operation_locked", str(exc), exc.exit_code)

    if json_mode:
        write_document(
            writer, outcome.report.as_envelope(request.cluster, request_id=request.request_id)
        )
    return outcome.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
