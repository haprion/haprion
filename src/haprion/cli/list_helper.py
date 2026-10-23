"""The privileged, read-only half of ``haprion-list``.

A human running `haprion-list` can already read the cluster repository, so the
command itself needs no privilege. The interface's poller cannot and must not:
the configuration repositories are readable by the management group only, and
giving the web platform's poller a group membership to read them would hand it
every cluster's published configuration for the sake of a listing.

So it asks root for exactly this, through one sudoers rule, with no arguments.
The caller names a cluster; the helper chooses the repository inside the
privilege boundary and returns a version listing and nothing else. It opens no
file in the work tree and writes nothing anywhere.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import BinaryIO, TextIO

from haprion import exit_codes
from haprion.config import DEFAULT_POLICY_PATH, ConfigError, load_policy, load_runtime_config
from haprion.envelope import Message, envelope
from haprion.git_command import GitError
from haprion.git_command import git as _git
from haprion.helper_protocol import (
    HelperProtocolError,
    config_error_code,
    read_helper_request,
    require_no_arguments,
    write_document,
    write_failure,
)
from haprion.history import history_result
from haprion.repo_health import describe_problem, is_repo_root
from haprion.status_collect import read_target
from haprion.version_diff import COMMIT, version_diff
from haprion.version_history import LIST_LIMIT, MAX_LIST_LIMIT, recent_versions

OPERATION = "list"
#
# How many versions to list, newest first: `LIST_LIMIT` when not given, at
# most `MAX_LIST_LIMIT`. The interface asks for more and pages in the browser.
#
#
# And, since 2026-10-01, what some of them changed (`diffs`, full commit hashes):
# the poller asks for the versions it has no diff for yet and keeps the answer,
# because a version's diff never changes. Ten at a time, so a first run over a
# long history spreads its git work over several polls instead of one long one.
#
PARAMETERS: frozenset[str] = frozenset({"limit", "diffs"})
MAX_DIFFS = 10


def parse_limit(raw: object) -> int:
    if raw is None:
        return LIST_LIMIT
    if isinstance(raw, bool) or not isinstance(raw, int) or not 1 <= raw <= MAX_LIST_LIMIT:
        raise HelperProtocolError(
            f"parameters.limit must be a whole number from 1 to {MAX_LIST_LIMIT}",
            exit_code=exit_codes.REFUSED,
        )
    return raw


def parse_diffs(raw: object) -> tuple[str, ...]:
    if raw is None:
        return ()
    if (
        not isinstance(raw, list)
        or len(raw) > MAX_DIFFS
        or not all(isinstance(item, str) and COMMIT.fullmatch(item) for item in raw)
    ):
        raise HelperProtocolError(
            f"parameters.diffs must be a list of at most {MAX_DIFFS} full commit hashes",
            exit_code=exit_codes.REFUSED,
        )
    return tuple(dict.fromkeys(raw))


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
                "haprion-list-helper must run as root", exit_code=exit_codes.NOT_ROOT
            )
        request = read_helper_request(
            input_stream or sys.stdin.buffer,
            expected_operation=OPERATION,
            allowed_parameter_keys=PARAMETERS,
        )
        limit = parse_limit(request.parameters.get("limit"))
        wanted = parse_diffs(request.parameters.get("diffs"))
    except HelperProtocolError as exc:
        #
        # Deliberately stderr only. The cluster and the request ID an envelope
        # must be bound to are fields of the request that just failed to parse;
        # an envelope invented here could not be bound to the caller's request
        # and would rightly be rejected as somebody else's answer.
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

    repo = Path(cluster.config_path)
    #
    # A missing or broken repository is the cluster's answer, not this process
    # failing to run. It is reported in the envelope so the interface can show
    # the cluster as unreadable while the others keep rendering.
    #
    if not is_repo_root(repo):
        return write_document(
            writer,
            envelope(
                operation=OPERATION,
                outcome="failed",
                cluster=request.cluster,
                request_id=request.request_id,
                result=None,
                error=Message(
                    code="history_unavailable",
                    message=describe_problem(request.cluster, repo),
                ),
            ),
            exit_codes.UNAVAILABLE,
        )

    target = read_target(Path(cluster.publish_path), cluster.node_path)
    try:
        result = history_result(recent_versions(repo, limit), target, limit=limit)
        if wanted:
            #
            # Only a version of this cluster: a hash on its first-parent
            # history. One that is not - asked for before a history reset, say
            # - is left out of the answer rather than failing the listing.
            #
            versions = set(_git(repo, "rev-list", "--first-parent", "HEAD").decode().split())
            result["diffs"] = {
                commit: version_diff(repo, commit).as_dict()
                for commit in wanted
                if commit in versions
            }
    except GitError as exc:
        return write_document(
            writer,
            envelope(
                operation=OPERATION,
                outcome="failed",
                cluster=request.cluster,
                request_id=request.request_id,
                result=None,
                error=Message(code="history_unavailable", message=str(exc)),
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
