"""The privileged, read-only half of "is anything written by hand not published" (B529).

The caller names a cluster; the helper reads the draft area's `core/` and
`manual/` with the reader `haprion-publish` and the interface's publish use
(`haprion.handwritten`), and compares them with the version the branch is on.
It publishes and writes nothing.

Asked only inside `haprion-readings-helper`, as the poller's other
manager-local readings are: it has no command and no sudo rule of its own.

The answer is one of three states. `clean`: nothing differs. `pending`: the
files that differ, the difference itself within the Versions page's bounds and
the fingerprint a publish must name to take exactly these files. `refused`: the
draft holds something no publish can take - a link, a file that is not text -
said in the words a publish would refuse it in.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, BinaryIO, TextIO

from haprion import exit_codes, handwritten
from haprion.config import DEFAULT_POLICY_PATH, ConfigError, load_policy, load_runtime_config
from haprion.envelope import Message, envelope
from haprion.git_command import GitError
from haprion.helper_protocol import (
    HelperProtocolError,
    config_error_code,
    read_helper_request,
    require_no_arguments,
    write_document,
    write_failure,
)
from haprion.repo_snapshot import PublishError, resolve_head

OPERATION = "handwritten"
PARAMETERS: frozenset[str] = frozenset()
CLEAN, PENDING, REFUSED = "clean", "pending", "refused"


def reading(repo: Path) -> dict[str, Any]:
    """The draft area of `repo` against the version its branch is on, as the result says it."""

    _, head = resolve_head(repo)
    try:
        draft, published = handwritten.read_draft(repo, head)
    except handwritten.HandwrittenError as exc:
        return {"state": REFUSED, "head": head, "message": str(exc)}
    if not draft.pending:
        return {"state": CLEAN, "head": head}
    return {
        "state": PENDING,
        "head": head,
        "fingerprint": draft.fingerprint,
        "pending": [{"path": item.path, "kind": item.kind} for item in draft.pending],
        "diff": draft.diff(published).as_dict(),
    }


def main(
    argv: list[str] | None = None,
    *,
    policy_path: Path = DEFAULT_POLICY_PATH,
    input_stream: BinaryIO | None = None,
    output_stream: TextIO | None = None,
    error_stream: TextIO | None = None,
    require_secure: bool = True,
    require_root: bool = True,
) -> int:
    argv = sys.argv[1:] if argv is None else argv
    writer: TextIO = output_stream or sys.stdout
    errors: TextIO = error_stream or sys.stderr

    try:
        require_no_arguments(argv)
        if require_root and os.geteuid() != 0:
            raise HelperProtocolError(
                "the handwritten reading must run as root", exit_code=exit_codes.NOT_ROOT
            )
        request = read_helper_request(
            input_stream or sys.stdin.buffer,
            expected_operation=OPERATION,
            allowed_parameter_keys=PARAMETERS,
        )
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

    try:
        result = reading(Path(cluster.config_path))
    except (PublishError, GitError) as exc:
        errors.write(f"ERROR: {exc}\n")
        return write_document(
            writer,
            envelope(
                operation=OPERATION,
                outcome="failed",
                cluster=request.cluster,
                request_id=request.request_id,
                result=None,
                error=Message(code="handwritten_unavailable", message=str(exc)),
            ),
            exc.exit_code,
        )

    return write_document(
        writer,
        envelope(
            operation=OPERATION,
            outcome="done",
            cluster=request.cluster,
            request_id=request.request_id,
            result=result,
        ),
        0,
    )


if __name__ == "__main__":
    raise SystemExit(main())
