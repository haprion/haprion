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
asking - a refusal, or a version that is already current, which is `done`
with `changed: false`.
"""

from __future__ import annotations

import json
import subprocess
import sys
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import TextIO

from haprion.cli.caller import CallerError, usage
from haprion.cli.caller import config_path as _config_path
from haprion.digits import is_digits
from haprion.envelope import envelope, failure
from haprion.git_command import GitError
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
    "  haprion-revert -c internal\n"
    "  haprion-revert -c internal 7\n"
    "  haprion-revert -c external\n"
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
            exit_code=64,
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

    def emit(document: dict[str, object]) -> None:
        writer.write(json.dumps(document, separators=(",", ":"), sort_keys=True) + "\n")

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
                )
            )
        else:
            writer.write(f"{'' if code == 'not_a_repository' else 'ERROR: '}{message}\n")
        return exit_code

    try:
        repo = config_path(cluster_id)
        if not is_repo_root(repo):
            return refuse("not_a_repository", describe_problem(cluster_id, repo), 68)

        dirty = unsaved_changes(repo)
        if dirty:
            return refuse(
                "unsaved_changes",
                f"there are unsaved changes in {repo}.\n\n{dirty}\n\n"
                "Publish or discard them before reverting.",
                65,
            )

        total = count_versions(repo)
        version = _target_version(cluster_id, requested, total)
        if version == total:
            if json_mode:
                emit(
                    envelope(
                        operation=REVERT_OPERATION,
                        outcome="done",
                        cluster=cluster_id,
                        request_id=request_id,
                        result={
                            "changed": False,
                            "from_version": total,
                            "restored_version": version,
                            "new_version": None,
                            "hash": None,
                            "published_at": None,
                            "deployment_required": False,
                            "next_command": None,
                        },
                    )
                )
            else:
                writer.write(f"Version {version} is already current for cluster '{cluster_id}'.\n")
            return 0

        commit = version_commit(repo, version)
        if commit is None:
            raise CallerError(f"could not find version {version}.")
        _, head = resolve_head(repo)
        summary = version_summary(repo, version, commit)
    except (CallerError, GitError) as exc:
        return refuse("bad_input" if exc.exit_code == 64 else "refused", str(exc), exc.exit_code)

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
        if json_mode:
            return refuse(
                "helper_failed",
                (err.strip() or f"the revert failed with exit code {code}.")[:2048],
                code or 70,
            )
        writer.write(err or f"ERROR: the revert failed with exit code {code}.\n")
        return code or 70

    if json_mode:
        emit(document)
        return 0 if document.get("outcome") == "done" else code or 70

    if document.get("outcome") != "done":
        error = document.get("error") or {}
        diagnostics = (error.get("details") or {}).get("diagnostics")
        if diagnostics:
            writer.write(f"{diagnostics}\n")
        writer.write(f"ERROR: {error.get('message', 'the revert did not run.')}\n")
        return code or 70

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
