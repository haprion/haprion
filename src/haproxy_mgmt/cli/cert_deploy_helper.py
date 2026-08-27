"""The privileged half of `haproxy-cert-deploy` - the reconcile loop, for certificates.

Shares the loop, the matrix and the node result with `haproxy-deploy-helper`,
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

import io
import json
import os
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import BinaryIO, TextIO

from haproxy_mgmt.certificates import CertificateError, target_for
from haproxy_mgmt.cli.deploy_helper import (
    EXIT_NO_IDENTITY,
    EXIT_NOT_ROOT,
    SSH,
    SSH_ENVIRONMENT,
    SSH_OPTIONS,
    read_status,
)
from haproxy_mgmt.cluster_lock import DEFAULT_LOCK_ROOT, LockBusy, hold
from haproxy_mgmt.cluster_status import NodeStatus
from haproxy_mgmt.config import (
    DEFAULT_POLICY_PATH,
    ConfigError,
    DeployIdentity,
    load_policy,
    load_runtime_config,
)
from haproxy_mgmt.deploy_plan import CertificateTarget
from haproxy_mgmt.deploy_run import CERT_OPERATION, ReadStatus, TriggerNode, run
from haproxy_mgmt.helper_protocol import (
    HelperProtocolError,
    JsonValue,
    read_helper_request,
    require_no_arguments,
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

    request = " ".join([REQUEST_VERB, *(ref.id for ref in target.certificates)])

    completed = subprocess.run(  # noqa: S603 - fixed path, host and IDs from validated configuration
        [
            SSH,
            *SSH_OPTIONS,
            "-i",
            str(identity.key),
            f"{identity.user}@{node.mgmt_host}",
            request,
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
                "haproxy-cert-deploy-helper must run as root", exit_code=EXIT_NOT_ROOT
            )
        request = read_helper_request(
            input_stream or sys.stdin.buffer,
            expected_operation=OPERATION,
            allowed_parameter_keys=PARAMETERS,
            validate_parameters=_validate,
        )
    except HelperProtocolError as exc:
        errors.write(f"ERROR: {exc}\n")
        return exc.exit_code

    allow_vip_unknown = bool(request.parameters.get("allow_vip_unknown", False))
    json_mode = bool(request.parameters.get("json", False))

    try:
        policy = load_policy(policy_path, require_secure=require_secure)
        cluster = load_runtime_config(policy, require_secure=require_secure).cluster(
            request.cluster
        )
    except ConfigError as exc:
        errors.write(f"ERROR: {exc}\n")
        return exc.exit_code

    if policy.certificate_root is None:
        errors.write(
            "ERROR: no certificate root is configured. Add certificate_root to "
            "the runtime policy.\n"
        )
        return EXIT_NO_CERTIFICATE_ROOT

    identity = policy.cert_deploy_identity
    if identity is None and node_trigger is None:
        errors.write(
            "ERROR: no certificate deploy identity is configured. Add "
            "cert_deploy_identity with 'user' and 'key' to the runtime policy.\n"
        )
        return EXIT_NO_IDENTITY

    #
    # Resolved before the lock is taken and before anything is sent: a run that
    # cannot name what it is deploying has nothing to do, and holding the
    # cluster's lock while finding that out would block an operator who could
    # have run something useful.
    #
    try:
        target = target_for(cluster, policy.certificate_root)
    except CertificateError as exc:
        errors.write(f"ERROR: {exc}\n")
        return 68

    stream: TextIO = io.StringIO() if json_mode else writer

    read: ReadStatus = status_reader or (lambda: read_status(request.cluster))

    def default_trigger(node: NodeStatus) -> int:
        assert identity is not None  # noqa: S101 - guarded above, stated for the reader
        return trigger_node(node, identity, target, stream)

    trigger: TriggerNode = node_trigger or default_trigger

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
            )
    except LockBusy as exc:
        errors.write(f"ERROR: {exc}\n")
        return exc.exit_code

    if json_mode:
        writer.write(
            json.dumps(
                outcome.report.as_envelope(request.cluster, request_id=request.request_id),
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        )
    return outcome.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
