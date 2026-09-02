"""The privileged, read-only half of ``haproxy-objects``.

The caller names a cluster; the helper chooses the repository inside the
privilege boundary and reads the committed tree. It never opens the working
copy - a file somebody is halfway through saving must not be able to look like
a stored object.

**Read at HEAD, not at the published release**, and that is the one thing that
differs from ``haproxy-inventory``. The two answer different questions.
Inventory says what a node is serving, so it reads the commit the RELEASE stamp
names. This is the base an edit is made against, and a publish checks its
snapshot against HEAD - so a draft that recorded anything else would be
comparing itself to a commit nobody is going to publish onto.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import BinaryIO, TextIO

from haproxy_mgmt.config import DEFAULT_POLICY_PATH, ConfigError, load_policy, load_runtime_config
from haproxy_mgmt.envelope import Message, envelope
from haproxy_mgmt.git_command import GitError
from haproxy_mgmt.helper_protocol import (
    HelperProtocolError,
    config_error_code,
    read_helper_request,
    require_no_arguments,
    write_document,
    write_failure,
)
from haproxy_mgmt.objects import ObjectsError, objects_result
from haproxy_mgmt.repo_snapshot import PublishError, read_tree_files, resolve_head

OPERATION = "objects"
PARAMETERS: frozenset[str] = frozenset()
EXIT_NOT_ROOT = 77

type ReadTree = Callable[[Path, str], Mapping[str, bytes]]
type ResolveHead = Callable[[Path], tuple[str, str]]


def main(
    argv: list[str] | None = None,
    *,
    policy_path: Path = DEFAULT_POLICY_PATH,
    input_stream: BinaryIO | None = None,
    output_stream: TextIO | None = None,
    error_stream: TextIO | None = None,
    require_secure: bool = True,
    require_root: bool = True,
    tree_reader: ReadTree = read_tree_files,
    head_resolver: ResolveHead = resolve_head,
) -> int:
    argv = sys.argv[1:] if argv is None else argv
    writer: TextIO = output_stream or sys.stdout
    errors: TextIO = error_stream or sys.stderr

    try:
        require_no_arguments(argv)
        if require_root and os.geteuid() != 0:
            raise HelperProtocolError(
                "haproxy-objects-helper must run as root", exit_code=EXIT_NOT_ROOT
            )
        request = read_helper_request(
            input_stream or sys.stdin.buffer,
            expected_operation=OPERATION,
            allowed_parameter_keys=PARAMETERS,
        )
    except HelperProtocolError as exc:
        #
        # Deliberately stderr only, for the reason the inventory helper gives:
        # an envelope invented here could not be bound to the caller's request.
        #
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

    def fail(code: str, message: str, exit_code: int) -> int:
        write_document(
            writer,
            envelope(
                operation=OPERATION,
                outcome="failed",
                cluster=request.cluster,
                request_id=request.request_id,
                result=None,
                error=Message(code=code, message=message),
            ),
        )
        return exit_code

    repo = Path(cluster.config_path)
    try:
        _, head = head_resolver(repo)
        result = objects_result(tree_reader(repo, head), head)
    except PublishError as exc:
        return fail("objects_unavailable", str(exc), exc.exit_code)
    except GitError as exc:
        return fail("objects_unavailable", str(exc), exc.exit_code)
    except ObjectsError as exc:
        return fail("objects_invalid", str(exc), 65)

    write_document(
        writer,
        envelope(
            operation=OPERATION,
            outcome="done",
            cluster=request.cluster,
            request_id=request.request_id,
            result=result,
        ),
    )
    return 0
