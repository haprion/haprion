"""The privileged half of `haproxy-deploy` - the whole reconcile loop.

Takes no arguments; the cluster and the two options arrive as a structured
request on stdin. Same form and same reason as the other helpers: PRIVILEGE.md
forbids wildcards in argument matching, so a rule naming a cluster is not
available, and one no-argument rule covers every cluster.

Why the WHOLE loop is inside the boundary
-----------------------------------------
Publishing splits cleanly: the caller previews, root writes once. Deploy does
not. It is privileged read, decide, privileged mutate, privileged read, decide
again - and the decisions depend on readings only root can take. Split per step,
the caller would cross the boundary four or five times in one rollout, and an
operator would be asked for a password in the middle of it. The tempting fix for
that is a blanket NOPASSWD rule, which would be a real loss: this is the command
that reaches the nodes.

So the loop runs here, once, and streams its progress to stdout as it goes. The
caller inherits that stream and adds nothing to it.

What it still does not trust
----------------------------
The cluster name is validated here, the target is resolved here from the
published tree rather than accepted from the caller, and the status is collected
by the existing status helper rather than passed in. Nothing the unprivileged
half looked up is used as the basis for what happens to a node.
"""

from __future__ import annotations

import io
import os
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import BinaryIO, TextIO, cast

from haproxy_mgmt.cluster_lock import DEFAULT_LOCK_ROOT, LockBusy, hold
from haproxy_mgmt.cluster_status import ClusterStatus, NodeStatus, parse_status
from haproxy_mgmt.config import (
    DEFAULT_POLICY_PATH,
    Cluster,
    ConfigError,
    DeployIdentity,
    load_policy,
    load_runtime_config,
)
from haproxy_mgmt.deploy_run import OPERATION as DEPLOY_OPERATION
from haproxy_mgmt.deploy_run import ReadStatus, TriggerNode, run
from haproxy_mgmt.envelope import failure, new_request_id
from haproxy_mgmt.helper_protocol import (
    HelperProtocolError,
    JsonValue,
    read_helper_request,
    require_no_arguments,
    write_document,
)
from haproxy_mgmt.status_collect import ask_node, collect, read_target

OPERATION = "deploy_cluster"
PARAMETERS = frozenset({"allow_vip_unknown", "json"})

SSH = "/usr/bin/ssh"

#
# The node is reached with the same options the shell-era command used. They are
# not defaults worth rediscovering: BatchMode never prompts, IdentitiesOnly stops
# an agent from offering a different key, and StrictHostKeyChecking is what makes
# the connection mean anything at all.
#
SSH_OPTIONS = (
    "-T",
    "-o",
    "BatchMode=yes",
    "-o",
    "IdentitiesOnly=yes",
    "-o",
    "StrictHostKeyChecking=yes",
    "-o",
    "ConnectTimeout=10",
    "-o",
    "ConnectionAttempts=1",
    "-o",
    "LogLevel=ERROR",
)

SSH_ENVIRONMENT = {"PATH": "/usr/bin:/bin", "HOME": "/root", "LANG": "C.UTF-8"}

EXIT_NOT_ROOT = 68

#
# EX_CONFIG: the installation is incomplete, which is neither the caller's
# mistake nor a cluster problem.
#
EXIT_NO_IDENTITY = 78


def _validate(parameters: Mapping[str, JsonValue]) -> None:
    for key in PARAMETERS:
        value = parameters.get(key, False)
        if not isinstance(value, bool):
            raise HelperProtocolError(f"{key} must be a boolean", exit_code=65)


def read_status(cluster: Cluster, identity: DeployIdentity) -> ClusterStatus:
    """Collected by the same code the status command uses, in this process.

    This used to shell out to the standalone `haproxy-status-root` script, back
    when that script was the only implementation. Now that collecting a cluster
    lives in the package, calling it directly is what keeps the guarantee the
    subprocess was there to provide: the status command and the deploy command
    read one pair through one collector, so they cannot come to different
    conclusions about it.

    The target is left out here. What this needs is the reading; which release
    the nodes ought to be on is decided once by the caller below and passed to
    the loop, so a rollout cannot be measured against a target that changed
    underneath it mid-run.
    """

    report = collect(cluster.nodes, lambda node: ask_node(node, identity), target=None)
    return parse_status(report.as_envelope(cluster.cluster_id, request_id=new_request_id()))


def trigger_node(node: NodeStatus, identity: DeployIdentity, writer: TextIO) -> int:
    """Ask one node to pull and reload. Its output is the operator's.

    The account and the key come from the runtime policy. Neither is compiled
    in: both identify a real installation, and this repository is meant to be
    public.
    """

    completed = subprocess.run(  # noqa: S603 - fixed path, host from validated configuration
        [
            SSH,
            *SSH_OPTIONS,
            "-i",
            str(identity.key),
            f"{identity.user}@{node.mgmt_host}",
        ],
        capture_output=True,
        text=True,
        check=False,
        env=SSH_ENVIRONMENT,
    )
    if completed.stdout:
        writer.write(completed.stdout.rstrip() + "\n")
    if completed.stderr:
        writer.write(completed.stderr.rstrip() + "\n")
    return completed.returncode


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
                "haproxy-deploy-helper must run as root", exit_code=EXIT_NOT_ROOT
            )
        request = read_helper_request(
            input_stream or sys.stdin.buffer,
            expected_operation=OPERATION,
            allowed_parameter_keys=PARAMETERS,
            validate_parameters=_validate,
        )
    except HelperProtocolError as exc:
        #
        # Deliberately stderr only. JSON mode is a parameter of the request, and
        # so are the operation, cluster and request ID an envelope would have to
        # be bound to; a request that failed to parse supplies none of them. An
        # envelope invented here could not be bound to the caller's job and would
        # be rejected as somebody else's answer - correctly - so there is nothing
        # honest to write on stdout.
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
        taken effect" - for a refusal that provably changed nothing.
        """

        errors.write(f"ERROR: {message}\n")
        if json_mode:
            write_document(
                writer,
                failure(
                    operation=DEPLOY_OPERATION,
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

    identity = policy.deploy_identity
    if identity is None and node_trigger is None:
        #
        # Named rather than guessed. There is no default account here: a wrong
        # guess would reach a node as the wrong identity, and a compiled-in right
        # one would put a real account name in a repository meant to be public.
        #
        return refuse(
            "dependency_unavailable",
            "no deploy identity is configured. Add deploy_identity with "
            "'user' and 'key' to the runtime policy.",
            EXIT_NO_IDENTITY,
        )

    #
    # In JSON mode the human-readable stream is collected and thrown away rather
    # than interleaved with the result: a reader parsing stdout must not have to
    # skip past progress lines to find the document.
    #
    stream: TextIO = io.StringIO() if json_mode else writer

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
        return trigger_node(node, identity, stream)

    trigger: TriggerNode = node_trigger or default_trigger

    try:
        with hold(request.cluster, operation="deploy", root=lock_root):
            outcome = run(
                read,
                trigger,
                stream,
                target=read_target(Path(cluster.publish_path), cluster.node_path),
                allow_vip_unknown=allow_vip_unknown,
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
