"""The privileged half of `haproxy-probe` - ask the nodes to try a check.

Takes no arguments; the request arrives on stdin, the same form and for the same
reason as every other helper: PRIVILEGE.md forbids wildcards in sudoers argument
matching, so one no-argument rule covers every cluster.

Why this needs root for something that changes nothing
------------------------------------------------------
One thing only: the probe identity's private key is root-owned, because no
application identity may hold a key that reaches a node. Nothing here writes,
and nothing here takes the cluster lock - a probe must stay answerable while a
deploy is running, and one that queued behind a rollout would answer about a
pool that has since moved.

What it does not trust
----------------------
The targets. They arrive from a caller that may be a web request somebody typed
into, so each one is validated here before it is sent, and the node validates
them again before it opens anything. Neither check is redundant with the other:
this one protects the node from a manager, and the node's protects it from
whoever holds the key.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import BinaryIO, TextIO

from haproxy_mgmt.config import (
    DEFAULT_POLICY_PATH,
    ConfigError,
    DeployIdentity,
    load_policy,
    load_runtime_config,
)
from haproxy_mgmt.envelope import new_request_id
from haproxy_mgmt.health_probe import MAX_TARGETS, Target, probe
from haproxy_mgmt.helper_protocol import (
    HelperProtocolError,
    config_error_code,
    read_helper_request,
    require_no_arguments,
    write_document,
    write_failure,
)
from haproxy_mgmt.proxy_model import HOSTNAME

OPERATION = "probe"
PARAMETERS = frozenset({"targets", "source", "timeout_ms"})

EXIT_NOT_ROOT = 77
EXIT_NO_IDENTITY = 78
EXIT_BAD_INPUT = 65

TYPES = ("tcp", "http")


def _targets(parameters: object) -> tuple[list[Target], str, int]:
    """The request's targets, or a refusal naming the field that was wrong."""

    if not isinstance(parameters, dict):
        raise HelperProtocolError("parameters must be an object", exit_code=EXIT_BAD_INPUT)

    entries = parameters.get("targets")
    if not isinstance(entries, list) or not entries:
        raise HelperProtocolError("targets must be a non-empty list", exit_code=EXIT_BAD_INPUT)
    if len(entries) > MAX_TARGETS:
        raise HelperProtocolError(
            f"at most {MAX_TARGETS} targets may be probed at once", exit_code=EXIT_BAD_INPUT
        )

    targets = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise HelperProtocolError("a target is not an object", exit_code=EXIT_BAD_INPUT)
        host = entry.get("host")
        port = entry.get("port")
        kind = entry.get("type", "tcp")
        if not isinstance(host, str) or not HOSTNAME.match(host):
            raise HelperProtocolError("a target's host is not usable", exit_code=EXIT_BAD_INPUT)
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            raise HelperProtocolError("a target's port is not a port", exit_code=EXIT_BAD_INPUT)
        if kind not in TYPES:
            raise HelperProtocolError(
                "a target's type must be tcp or http", exit_code=EXIT_BAD_INPUT
            )
        path = entry.get("path", "/") or "/"
        header = entry.get("host_header", "") or ""
        if not isinstance(path, str) or not path.startswith("/") or len(path) > 1024:
            raise HelperProtocolError("a target's path is not a path", exit_code=EXIT_BAD_INPUT)
        if not isinstance(header, str) or (header and not HOSTNAME.match(header)):
            raise HelperProtocolError(
                "a target's host header is not a name", exit_code=EXIT_BAD_INPUT
            )
        targets.append(
            Target(
                host=host,
                port=port,
                type=kind,
                tls=entry.get("tls") is True,
                verify=entry.get("verify") is True,
                path=path,
                host_header=header,
            )
        )

    source = parameters.get("source", "") or ""
    if not isinstance(source, str) or len(source) > 45:
        raise HelperProtocolError("source must be an address", exit_code=EXIT_BAD_INPUT)

    timeout = parameters.get("timeout_ms", 2000)
    if not isinstance(timeout, int) or isinstance(timeout, bool):
        raise HelperProtocolError("timeout_ms must be a number", exit_code=EXIT_BAD_INPUT)
    return targets, source, timeout


def main(
    argv: list[str] | None = None,
    *,
    policy_path: Path = DEFAULT_POLICY_PATH,
    input_stream: BinaryIO | None = None,
    output_stream: TextIO | None = None,
    error_stream: TextIO | None = None,
    require_secure: bool = True,
    require_root: bool = True,
    ask: object = None,
) -> int:
    argv = sys.argv[1:] if argv is None else argv
    writer: TextIO = output_stream or sys.stdout
    errors: TextIO = error_stream or sys.stderr

    try:
        require_no_arguments(argv)
        if require_root and os.geteuid() != 0:
            raise HelperProtocolError(
                "haproxy-probe-helper must run as root", exit_code=EXIT_NOT_ROOT
            )
        request = read_helper_request(
            input_stream or sys.stdin.buffer,
            expected_operation=OPERATION,
            allowed_parameter_keys=PARAMETERS,
        )
        targets, source, timeout_ms = _targets(request.parameters)
    except HelperProtocolError as exc:
        errors.write(f"ERROR: {exc}\n")
        return exc.exit_code

    try:
        policy = load_policy(policy_path, require_secure=require_secure)
        cluster = load_runtime_config(policy, require_secure=require_secure).cluster(
            request.cluster
        )
    except ConfigError as exc:
        errors.write(f"ERROR: {exc}\n")
        return write_failure(
            writer,
            operation=OPERATION,
            cluster=request.cluster,
            request_id=request.request_id,
            code=config_error_code(exc.exit_code),
            message=str(exc),
            exit_code=exc.exit_code,
        )

    identity = policy.probe_identity
    if identity is None and ask is None:
        message = (
            "no probe identity is configured. Add probe_identity with "
            "'user' and 'key' to the runtime policy."
        )
        errors.write(f"ERROR: [probe_unavailable] {message}\n")
        return write_failure(
            writer,
            operation=OPERATION,
            cluster=request.cluster,
            request_id=request.request_id,
            code="probe_unavailable",
            message=message,
            exit_code=EXIT_NO_IDENTITY,
        )

    #
    # Only reachable with an identity, or with a caller that replaces the SSH
    # entirely - which is what the tests do. Stated rather than ignored, so the
    # reader is not left checking whether the guard above really covers it.
    #
    assert identity is not None or ask is not None  # noqa: S101
    answers = probe(
        cluster.nodes,
        identity if identity is not None else DeployIdentity(user="", key=Path("/dev/null")),
        targets,
        source=source,
        timeout_ms=timeout_ms,
        ask=ask,
    )
    #
    # `done` whenever the nodes answered, whatever they said about the pool. A
    # server that is down is a finding, not a failure of the command: reporting
    # it as a failed operation would put a red job in the queue every time
    # somebody checked a pool they already knew was broken.
    #
    reachable = [answer for answer in answers if answer.reachable]
    #
    # An object with a source address can only be answered for from the node
    # that holds it, and in an active/passive pair that is one node. Asking the
    # other would bind a foreign address and fail the route lookup, which
    # describes the binding and not the pool - so those nodes probe nothing and
    # say so.
    #
    # All of them saying so is a different matter: the address is nowhere, and
    # nothing was tried anywhere. That is the probe being unable to run rather
    # than a pool that failed, and it is reported as such.
    #
    answered = [answer for answer in reachable if answer.source_held is not False]
    nowhere = bool(source) and bool(reachable) and not answered
    ran = bool(answered)
    outcome = "done" if ran else "failed"
    document = {
        "schema_version": 1,
        "ok": ran,
        "outcome": outcome,
        "operation": OPERATION,
        "cluster": request.cluster,
        "request_id": request.request_id or new_request_id(),
        "result": {
            "source": source,
            "nodes": [
                {
                    "node": answer.node,
                    "reachable": answer.reachable,
                    "error": answer.error,
                    "source_held": answer.source_held,
                    "results": [
                        {
                            "host": entry.host,
                            "port": entry.port,
                            "ok": entry.ok,
                            "status": entry.status,
                            "error": entry.error,
                            "ms": entry.ms,
                        }
                        for entry in answer.results
                    ],
                }
                for answer in answers
            ],
        },
        "warnings": [
            f"{answer.node}: {answer.error}"
            for answer in answers
            if answer.error and answer.reachable
        ],
        "error": None
        if ran
        else {
            "code": "probe_unavailable",
            "message": (
                f"no node carries the source address {source}, so nothing was tried"
                if nowhere
                else "no node answered the probe"
            ),
        },
    }
    write_document(writer, document)
    return 0 if ran else 68


if __name__ == "__main__":
    raise SystemExit(main())
