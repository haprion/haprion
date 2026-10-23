"""The privileged, read-only half of ``haprion-objects``.

The caller names a cluster; the helper chooses the repository inside the
privilege boundary and reads the committed tree. It never opens the working
copy - a file somebody is halfway through saving must not be able to look like
a stored object.

**Read at HEAD, not at the published release**, and that is the one thing that
differs from ``haprion-inventory``. The two answer different questions.
Inventory says what a node is serving, so it reads the commit the RELEASE stamp
names. This is the base an edit is made against, and a publish checks its
snapshot against HEAD - so a draft that recorded anything else would be
comparing itself to a commit nobody is going to publish onto.
"""

from __future__ import annotations

import os
import re
import sys
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import BinaryIO, TextIO

from haprion import crs, exit_codes, geo
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
from haprion.objects import ObjectsError, fingerprint, objects_result, unchanged_result
from haprion.repo_snapshot import PublishError, read_tree_files, resolve_head

OPERATION = "objects"
#
# `unchanged_since` (B222, 2026-10-01): the fingerprint of the listing the
# caller already holds. When it still matches, the answer says so instead of
# reading the tree and parsing every document again.
#
PARAMETERS: frozenset[str] = frozenset({"unchanged_since"})
FINGERPRINT = re.compile(r"^[0-9a-f]{64}$")

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
    waf_versions: Callable[[], Mapping[str, str | None]] = crs.manager_versions,
) -> int:
    argv = sys.argv[1:] if argv is None else argv
    writer: TextIO = output_stream or sys.stdout
    errors: TextIO = error_stream or sys.stderr

    try:
        require_no_arguments(argv)
        if require_root and os.geteuid() != 0:
            raise HelperProtocolError(
                "haprion-objects-helper must run as root", exit_code=exit_codes.NOT_ROOT
            )
        request = read_helper_request(
            input_stream or sys.stdin.buffer,
            expected_operation=OPERATION,
            allowed_parameter_keys=PARAMETERS,
        )
        known = request.parameters.get("unchanged_since")
        if known is not None and (not isinstance(known, str) or not FINGERPRINT.fullmatch(known)):
            raise HelperProtocolError(
                "parameters.unchanged_since must be a listing fingerprint",
                exit_code=exit_codes.REFUSED,
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
        return write_document(
            writer,
            envelope(
                operation=OPERATION,
                outcome="failed",
                cluster=request.cluster,
                request_id=request.request_id,
                result=None,
                error=Message(code=code, message=message),
            ),
            exit_code,
        )

    #
    # The network description the generator reads, for each object's VIP and
    # source (B222). One that cannot be read leaves those fields empty and says
    # why; it is no reason to withhold the objects themselves.
    #
    warnings: tuple[Message, ...] = ()
    try:
        network = cluster.network()
    except ConfigError as exc:
        network = None
        warnings = (Message(code="network_unreadable", message=str(exc)[:1024]),)

    repo = Path(cluster.config_path)
    stamp = geo.database_stamp()
    waf = waf_versions()
    try:
        _, head = head_resolver(repo)
        if known is not None and known == fingerprint(head, network, stamp, waf):
            result = unchanged_result(head, network, geo_stamp=stamp, waf=waf)
        else:
            result = objects_result(
                tree_reader(repo, head), head, network=network, geo_stamp=stamp, waf=waf
            )
    except PublishError as exc:
        return fail("objects_unavailable", str(exc), exc.exit_code)
    except GitError as exc:
        return fail("objects_unavailable", str(exc), exc.exit_code)
    except ObjectsError as exc:
        return fail("objects_invalid", str(exc), exit_codes.REFUSED)

    return write_document(
        writer,
        envelope(
            operation=OPERATION,
            outcome="done",
            cluster=request.cluster,
            request_id=request.request_id,
            result=result,
            warnings=warnings,
        ),
        0,
    )
