"""``haprion-node`` - add a node to a cluster, or take one away (B211).

    haprion-node add -c <cluster> --host <name> [--deploy | --json] < block
    haprion-node remove -c <cluster> <node> [--deploy | --json]
    haprion-node host -c <cluster> <node> --host <new name> [--json]

`--json` prints the helper's envelope (`schemas/v1/haprion-cluster-node`) and
leaves with its exit code. The block is what `04-node-prepare` printed on the node. `--host` is the name
this management host reaches the node at; the block carries the node's own
suggestion, which is shown and may be wrong. Both go through the same root
helper the interface's Nodes card uses, so the terminal and the browser change
the same six files the same way - and a node that does not then answer as
itself is taken back out.

`host` reaches the same node at another name or address (B295): the host keys
pinned for it move to the new name, and the node must answer there with one
of them, as itself, or nothing is changed. Changing the machine is not this:
that is a restore, or a removal and an addition.

A new node has no certificates and no release until `haprion-cert-deploy -c <cluster>`
and then `haprion-deploy -c <cluster>`. `--deploy` runs both after an addition, and the
deploy after a removal, when every node ran the published version before the change - then
the change is the only thing the deploy rolls out (B321), as in the interface. Otherwise it
says why it did not, and the commands are left to the operator.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Callable, Mapping
from typing import Any, TextIO

from haprion import node_enrollment, node_publish
from haprion.cli import cert_deploy, deploy, node_helper
from haprion.cli.caller import usage, without_answer
from haprion.envelope import new_request_id
from haprion.helper_protocol import write_document
from haprion.node_enrollment import MAX_BLOCK_BYTES

SUDO = "/usr/bin/sudo"
USAGE = (
    "Usage:\n"
    "  haprion-node add -c <cluster> --host <name> [--deploy | --json] < block\n"
    "  haprion-node remove -c <cluster> <node> [--deploy | --json]\n"
    "  haprion-node host -c <cluster> <node> --host <new name> [--json]\n"
)

type RunHelper = Callable[[str], subprocess.CompletedProcess[str]]
type DeployAfter = Callable[[str, int, str], int]


def run_helper(request: str) -> subprocess.CompletedProcess[str]:
    """Through sudo, or directly when this already runs as root (F2, 2026-09-29)."""

    argv = [node_helper.HELPER] if os.geteuid() == 0 else [SUDO, "--", node_helper.HELPER]
    return subprocess.run(  # noqa: S603 - fixed helper path, no caller argv
        argv, input=request, capture_output=True, text=True, check=False
    )


def deploy_after(cluster: str, version: int, action: str) -> int:
    """The certificates (after an addition) and then the version, streamed as the commands print them.

    The deploy is bound to the version the change published, as the
    interface's is: one published after it is refused rather than rolled out.
    """

    if action == "add":
        code = cert_deploy.main(["-c", cluster])
        if code != 0:
            return code
    request = deploy.build_request(
        cluster,
        new_request_id(),
        allow_vip_unknown=False,
        json_mode=False,
        expected_version=version,
    )
    return subprocess.run(  # noqa: S603 - fixed helper path, no caller argv
        [deploy.SUDO, "--", deploy.HELPER], input=request.encode(), check=False
    ).returncode


def _deployable(result: Mapping[str, Any]) -> tuple[int | None, str]:
    """The version to deploy after a change, or None and why not (B321)."""

    publication = result.get("publication")
    if not isinstance(publication, Mapping):
        publication = {}
    version = publication.get("version")
    if not isinstance(version, int) or isinstance(version, bool) or "error" in publication:
        return None, "Not deployed: the node list was not published.\n"
    if result.get("converged_before") is not True:
        return None, (
            "Not deployed: not every node ran the published version before the change, "
            "so a deploy would roll out more than it.\n"
        )
    return version, ""


def _parse(argv: list[str]) -> tuple[str, str, str, str | None]:
    """(action, cluster, host or node, the new host for `host`)."""

    if (
        len(argv) == 5
        and argv[0] == "add"
        and argv[1] in ("-c", "--cluster")
        and argv[3] == "--host"
    ):
        return "add", argv[2], argv[4], None
    if len(argv) == 4 and argv[0] == "remove" and argv[1] in ("-c", "--cluster"):
        return "remove", argv[2], argv[3], None
    if (
        len(argv) == 6
        and argv[0] == "host"
        and argv[1] in ("-c", "--cluster")
        and argv[4] == "--host"
    ):
        return "host", argv[2], argv[3], argv[5]
    usage(USAGE)


def document_of(
    completed: subprocess.CompletedProcess[str], operation: str = node_helper.OPERATION
) -> dict[str, Any]:
    """The helper's envelope, or why there is none."""

    try:
        document = json.loads(completed.stdout)
    except ValueError:
        raise ValueError(completed.stderr.strip() or "the helper gave no answer") from None
    if not isinstance(document, dict) or document.get("operation") != operation:
        raise ValueError("the helper returned an invalid result")
    return document


def json_answer(
    completed: subprocess.CompletedProcess[str],
    operation: str,
    cluster: str,
    writer: TextIO,
    errors: TextIO,
) -> int:
    """`--json`: the helper's envelope as it came and its exit code, or the one document anyway."""

    try:
        document = document_of(completed, operation)
    except ValueError as exc:
        return without_answer(
            completed,
            operation=operation,
            cluster=cluster,
            json_mode=True,
            writer=writer,
            errors=errors,
            fallback=str(exc),
        )
    return write_document(writer, document, completed.returncode)


def _answer(
    completed: subprocess.CompletedProcess[str], operation: str = node_helper.OPERATION
) -> Mapping[str, Any]:
    document = document_of(completed, operation)
    error = document.get("error")
    if isinstance(error, Mapping):
        raise ValueError(str(error.get("message")))
    result = document.get("result")
    if not isinstance(result, Mapping):
        raise ValueError("the helper returned an invalid result")
    return result


def main(
    argv: list[str] | None = None,
    *,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
    run: RunHelper = run_helper,
    then_deploy: DeployAfter = deploy_after,
) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    writer = stdout or sys.stdout
    errors = stderr or sys.stderr
    json_mode = "--json" in arguments
    deploying = "--deploy" in arguments
    action, cluster, value, new_host = _parse(
        [item for item in arguments if item not in ("--json", "--deploy")]
    )
    if deploying and (json_mode or action == "host" or arguments.count("--deploy") > 1):
        usage(USAGE)
    if action == "add":
        block = (stdin or sys.stdin).read(MAX_BLOCK_BYTES + 1)
        request = node_helper.build_request(
            cluster, new_request_id(), action="add", block=block, host=value
        )
    elif action == "host":
        request = node_helper.build_request(
            cluster, new_request_id(), action="host", node=value, host=new_host
        )
    else:
        request = node_helper.build_request(cluster, new_request_id(), action="remove", node=value)

    completed = run(request)
    if json_mode:
        return json_answer(completed, node_helper.OPERATION, cluster, writer, errors)
    try:
        result = _answer(completed)
    except ValueError as exc:
        errors.write(f"ERROR: {exc}\n")
        return 1

    if result.get("action") == "host_changed":
        writer.write(
            f"{result.get('node')} of {cluster} is now reached at {result.get('host')} "
            f"(was {result.get('previous_host')}).\n"
            f"Host key: {result.get('host_key_fingerprint')}\n"
            f"Changed: {', '.join(str(item) for item in result.get('files', []))}\n"
            + node_publish.said(result.get("publication"), cluster)
        )
        return 0
    version, refusal = _deployable(result) if deploying else (None, "")
    #
    # What is left to run, unless --deploy is about to run it (B321).
    #
    published = node_publish.said(result.get("publication"), cluster)
    if version is not None and "error" not in (result.get("publication") or {}):
        published = f"Published as version {version}; deploying it now.\n"
    if result.get("action") == "added":
        writer.write(
            f"Added {result.get('node')} ({result.get('host')}) to {cluster}.\n"
            f"Host key: {result.get('host_key_fingerprint')}\n"
            + (
                "WARNING: "
                + node_enrollment.shared_key_warning(
                    str(result.get("node")), result["shares_host_key_with"]
                )
                + "\n"
                if result.get("shares_host_key_with")
                else ""
            )
            + f"Changed: {', '.join(str(item) for item in result.get('files', []))}\n"
            + (
                ""
                if version is not None
                else f"The node has no certificates yet: haprion-cert-deploy -c {cluster}\n"
            )
            + published
        )
    else:
        writer.write(
            f"Removed {result.get('node')} from {cluster}.\n"
            f"Changed: {', '.join(str(item) for item in result.get('files', []))}\n"
            + _stepped_down(result.get("step_down"), str(result.get("node")))
            + published
        )
    if version is None:
        writer.write(refusal)
        return 0
    writer.flush()
    return then_deploy(cluster, version, action)


def _stepped_down(step_down: object, node: str) -> str:
    """Whether the removed node stopped serving (B319), in a line."""

    if not isinstance(step_down, dict):
        return ""
    if step_down.get("stopped") is True:
        return f"{node} stopped keepalived and HAProxy and will not start them at boot.\n"
    return f"WARNING: {step_down.get('message')}\n"


if __name__ == "__main__":
    raise SystemExit(main())
