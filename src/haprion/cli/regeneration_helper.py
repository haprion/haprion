"""The privileged, read-only half of "would a publish change what runs".

The caller names a cluster; the helper reads the commit the RELEASE stamp
names - what the nodes are told to run - makes its generated layer again with
the installed product and compares the node files (`haprion.regeneration`).
It publishes and writes nothing.

`unchanged_since` is the fingerprint of the result the caller holds, as for
`objects`: while it still stands the answer says so, without reading the tree
or generating anything.
"""

from __future__ import annotations

import os
import re
import sys
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import BinaryIO, TextIO

from haprion import crs, exit_codes, regeneration
from haprion.config import DEFAULT_POLICY_PATH, ConfigError, load_policy, load_runtime_config
from haprion.deploy_plan import ReleaseTarget
from haprion.envelope import Message, envelope
from haprion.git_command import GitError
from haprion.helper_protocol import (
    HelperProtocolError,
    config_error_code,
    read_helper_request,
    require_no_arguments,
    write_bad_input,
    write_document,
    write_failure,
)
from haprion.repo_snapshot import PublishError, read_tree_files
from haprion.status_collect import read_target

OPERATION = "regeneration"
PARAMETERS: frozenset[str] = frozenset({"unchanged_since"})
FINGERPRINT = re.compile(r"^[0-9a-f]{64}$")

type ReadTree = Callable[[Path, str], Mapping[str, bytes]]
type ReadTarget = Callable[[Path, str], ReleaseTarget | None]


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
    target_reader: ReadTarget = read_target,
    waf_versions: Callable[[], Mapping[str, str | None]] = crs.manager_versions,
    addresses: regeneration.Lookup | None = None,
    rule_set: Callable[[], crs.RuleSet | None] = crs.installed,
) -> int:
    argv = sys.argv[1:] if argv is None else argv
    writer: TextIO = output_stream or sys.stdout
    errors: TextIO = error_stream or sys.stderr

    try:
        require_no_arguments(argv)
        if require_root and os.geteuid() != 0:
            raise HelperProtocolError(
                "haprion-regeneration-helper must run as root", exit_code=exit_codes.NOT_ROOT
            )
        request = read_helper_request(
            input_stream or sys.stdin.buffer,
            expected_operation=OPERATION,
            allowed_parameter_keys=PARAMETERS,
        )
    except HelperProtocolError as exc:
        # Stderr only, for the reason the inventory helper gives.
        errors.write(f"ERROR: {exc}\n")
        return exc.exit_code

    known = request.parameters.get("unchanged_since")
    if known is not None and (not isinstance(known, str) or not FINGERPRINT.fullmatch(known)):
        message = "parameters.unchanged_since must be a result fingerprint"
        errors.write(f"ERROR: {message}\n")
        return write_bad_input(writer, OPERATION, request, message)

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

    try:
        target = target_reader(Path(cluster.publish_path), cluster.node_path)
        commit = target.hash if target is not None else None
        found = (
            regeneration.lookup_addresses(cluster)
            if addresses is None
            else regeneration.lookup_addresses(cluster, addresses)
        )
        installed_crs = waf_versions().get("crs")
        key = regeneration.fingerprint(commit, cluster, found, installed_crs)
        if known is not None and known == key:
            result = regeneration.unchanged_result(commit, key)
        elif target is None:
            result = regeneration.unpublished_result(key)
        else:
            result = regeneration.regenerate(
                tree_reader(Path(cluster.config_path), target.hash),
                cluster,
                commit=target.hash,
                version=target.version,
                key=key,
                addresses=found,
                installed_crs=installed_crs,
                rule_set=rule_set,
            )
    except (PublishError, GitError) as exc:
        return fail("regeneration_unavailable", str(exc), exc.exit_code)
    except regeneration.RegenerationError as exc:
        return fail("regeneration_unavailable", str(exc), exit_codes.UNAVAILABLE)

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
