"""`haprion-revert` - make an earlier version the current one again.

The thin half. It runs entirely as the calling user: it resolves the cluster,
checks that the draft area holds nothing unsaved, translates the version number
into a commit, shows the operator what they are about to restore, and hands a
structured request to the root helper.

Everything it looked up, the helper looks up again. That is not caution for its
own sake: between the preview and the write, somebody with sudoedit could change
the repository, and then the version the human approved is no longer the version
that would be written.

What a revert is, since B10 step 5: a NEW version holding the chosen version's
content. The history keeps every intermediate version, and nothing is rewritten.

`--json` prints one envelope (`schemas/v1/haprion-revert`) instead of the
preview and the summary: the helper's, or this half's own when it stops before
asking - a refusal. The current version is sent to the helper like any other:
it finds the content in place, installs the release if that is missing and
answers `done` with `changed: false`, as it does for the interface.
"""

from __future__ import annotations

import json
import subprocess
import sys
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import TextIO

from haprion import exit_codes
from haprion.cli.caller import CallerError, usage
from haprion.cli.caller import config_path as _config_path
from haprion.digits import is_digits
from haprion.envelope import failure
from haprion.git_command import GitError
from haprion.helper_protocol import config_error_code, write_document
from haprion.repo_health import describe_problem, is_repo_root, unsaved_changes
from haprion.repo_snapshot import resolve_head
from haprion.version_history import count_versions, version_commit, version_summary

OPERATION = "revert_version"
#
# What the result envelope is called (`schemas/v1/haprion-revert`); the request
# says `revert_version` to reach the helper.
#
REVERT_OPERATION = "revert"

HELPER = "/opt/haprion/current/bin/haprion-revert-helper"
SUDO = "/usr/bin/sudo"

USAGE = (
    "Usage:\n"
    "  haprion-revert -c <cluster> [--json]\n"
    "  haprion-revert -c <cluster> VERSION [--json]\n"
    "\n"
    "Examples:\n"
    "  haprion-revert -c alpha\n"
    "  haprion-revert -c alpha 7\n"
    "  haprion-revert -c beta\n"
)

type RunHelper = Callable[[bytes], tuple[int, str, str]]
type ConfigPath = Callable[[str], Path]


def _run_helper(request: bytes) -> tuple[int, str, str]:
    completed = subprocess.run(  # noqa: S603 - fixed path, no caller-supplied arguments
        [SUDO, "--", HELPER],
        input=request,
        capture_output=True,
        check=False,
    )
    return (
        completed.returncode,
        completed.stdout.decode("utf-8", "replace"),
        completed.stderr.decode("utf-8", "replace"),
    )


def _parse(argv: list[str]) -> tuple[str, str | None]:
    if len(argv) not in (2, 3) or argv[0] not in ("-c", "--cluster"):
        usage(USAGE)
    return argv[1], argv[2] if len(argv) == 3 else None


def _target_version(cluster_id: str, requested: str | None, total: int) -> int:
    """The version to restore: the one asked for, or the previous one."""

    if requested is None:
        if total < 2:
            raise CallerError(f"there is no previous version for cluster '{cluster_id}'.")
        return total - 1

    if not is_digits(requested) or requested.startswith("0"):
        raise CallerError(
            "the version must be a plain version number.\n\n"
            "Examples:\n"
            f"  haprion-revert -c {cluster_id} 7\n\n"
            f"Run haprion-list -c {cluster_id} to list the versions.",
            exit_code=exit_codes.USAGE,
        )

    version = int(requested)
    if version > total:
        raise CallerError(
            f"version {version} does not exist in cluster '{cluster_id}'.\n\n"
            f"The current version is {total}."
        )
    return version


def build_request(
    cluster_id: str,
    request_id: str,
    *,
    version: int,
    expected_commit: str,
    expected_head: str | None = None,
    requested_by: str | None = None,
) -> str:
    """The exact request a revert sends, built in one place.

    Public for the same reason as the other write operations: the interface's
    worker sends this operation too, and a second construction of the envelope is
    a second thing to keep in step with the helper's strict validation.

    `expected_commit` is the fencing that makes a revert safe to retry. The
    helper refuses if the cluster no longer stands where the caller thought it
    did, so a request that was built from a stale reading fails instead of
    reverting something else.

    `expected_head` is the newest version the caller saw. With it, the helper
    refuses a revert once anything else has been recorded since, rather than
    reverting that away too (review 2026-10-04, CR-09).

    `requested_by` names the person the interface's worker acts for (B207). It
    is left out rather than sent empty when nobody is named, and the helper
    then records the account sudo ran it as.
    """

    return json.dumps(
        {
            "schema_version": 1,
            "operation": OPERATION,
            "cluster": cluster_id,
            "request_id": request_id,
            "parameters": {
                "version": version,
                "expected_commit": expected_commit,
                **({} if expected_head is None else {"expected_head": expected_head}),
                **({} if requested_by is None else {"requested_by": requested_by}),
            },
        }
    )


def main(
    argv: list[str] | None = None,
    *,
    stream_out: TextIO | None = None,
    run_helper: RunHelper = _run_helper,
    config_path: ConfigPath = _config_path,
) -> int:
    argv = sys.argv[1:] if argv is None else argv
    writer: TextIO = stream_out or sys.stdout
    json_mode = "--json" in argv
    cluster_id, requested = _parse([item for item in argv if item != "--json"])
    request_id = str(uuid.uuid4())

    def emit(document: dict[str, object], exit_code: int) -> int:
        return write_document(writer, document, exit_code)

    def refuse(code: str, message: str, exit_code: int) -> int:
        if json_mode:
            emit(
                failure(
                    operation=REVERT_OPERATION,
                    cluster=cluster_id,
                    request_id=request_id,
                    code=code,
                    message=message,
                    exit_code=exit_code,
                ),
                exit_code,
            )
        else:
            writer.write(f"{'' if code == 'not_a_repository' else 'ERROR: '}{message}\n")
        return exit_code

    try:
        try:
            repo = config_path(cluster_id)
        except SystemExit as stopped:
            #
            # cluster-config has said why on stderr - an unknown cluster, with
            # the ones there are. In --json the answer is still a document
            # (review 26-10-24, 06-06).
            #
            code = stopped.code if isinstance(stopped.code, int) else exit_codes.USAGE
            return refuse(
                config_error_code(code),
                f"cluster {cluster_id} could not be looked up",
                exit_codes.of_process(code, exit_codes.USAGE) or exit_codes.USAGE,
            )
        if not is_repo_root(repo):
            return refuse(
                "not_a_repository", describe_problem(cluster_id, repo), exit_codes.UNAVAILABLE
            )

        dirty = unsaved_changes(repo)
        if dirty:
            return refuse(
                "dirty_worktree",
                f"there are unsaved changes in {repo}.\n\n{dirty}\n\n"
                "Publish or discard them before reverting.",
                exit_codes.BLOCKED,
            )

        total = count_versions(repo)
        version = _target_version(cluster_id, requested, total)
        commit = version_commit(repo, version)
        if commit is None:
            raise CallerError(f"could not find version {version}.")
        _, head = resolve_head(repo)
        summary = version_summary(repo, version, commit)
    except (CallerError, GitError) as exc:
        return refuse(
            "bad_input" if exc.exit_code == exit_codes.USAGE else "refused", str(exc), exc.exit_code
        )

    if not json_mode:
        writer.write(
            "\nReverting the HAProxy configuration:\n\n"
            f"  Cluster:   {cluster_id}\n"
            f"  Version:   {summary.version}\n"
            f"  Date:      {summary.date}\n"
            f"  Comment:   {summary.comment}\n\n"
        )

    request = build_request(
        cluster_id, request_id, version=version, expected_commit=commit, expected_head=head
    ).encode()

    code, out, err = run_helper(request)

    try:
        document = json.loads(out) if out else None
    except json.JSONDecodeError:
        document = None

    if not isinstance(document, dict) or "outcome" not in document:
        #
        # No envelope means the helper died before it could describe what it did.
        # Its stderr is the only account of the run there is, so it is shown as
        # it stands rather than replaced by a friendlier sentence that would say
        # less.
        #
        # Signalled or never run (negative, 126, 127): no exit this table
        # explains, and a document with it is one no check writes (06-05).
        failed, interrupted = exit_codes.foreign(code, "revert helper")
        failed = failed or exit_codes.INTERNAL
        said = (
            "; ".join(part for part in (interrupted, err.strip()) if part)
            or f"the revert failed with exit code {code}."
        )
        if json_mode:
            return refuse("helper_failed", said[:2048], failed)
        writer.write(f"ERROR: {said}\n" if interrupted else err or f"ERROR: {said}\n")
        return failed

    if json_mode:
        return emit(document, code)

    if document.get("outcome") != "done":
        error = document.get("error") or {}
        diagnostics = (error.get("details") or {}).get("diagnostics")
        if diagnostics:
            writer.write(f"{diagnostics}\n")
        writer.write(f"ERROR: {error.get('message', 'the revert did not run.')}\n")
        return exit_codes.of_process(code, exit_codes.INTERNAL) or exit_codes.INTERNAL

    result = document.get("result") or {}
    if not result.get("changed"):
        #
        # The helper found the chosen version's content already in place. It is
        # a success, and saying so is more useful than reporting a version
        # number that was not created.
        #
        writer.write(
            f"Cluster '{cluster_id}' already holds the content of version {version}. "
            "No new version was created.\n"
        )
        if result.get("deployment_required") and result.get("next_command"):
            #
            # The helper cannot tell a repeat from a run cut short before
            # anybody was told to deploy, and says so (review 26-10-24, 01-04).
            #
            writer.write(
                "\nNo node deployment has run. If the nodes are behind, bring them "
                f"into step with:\n\n  {result['next_command']}\n"
            )
        return 0

    writer.write(
        "HAProxy configuration OK.\n\n"
        f"Cluster '{cluster_id}' is back on the content of version {version}, "
        f"recorded as version {result['new_version']}.\n\n"
        f"  Hash:     {result['hash']}\n"
        f"  Release:  {result['release']}\n\n"
        "No node deployment has run. Bring the nodes into step with:\n\n"
        f"  {result['next_command']}\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
