"""`haproxy-revert` - make an earlier version the current one again.

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
"""

from __future__ import annotations

import json
import subprocess
import sys
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import TextIO

from haproxy_mgmt.cli.caller import CallerError, usage
from haproxy_mgmt.cli.caller import config_path as _config_path
from haproxy_mgmt.git_command import GitError
from haproxy_mgmt.repo_health import describe_problem, is_repo_root, unsaved_changes
from haproxy_mgmt.version_history import count_versions, version_commit, version_summary

OPERATION = "revert_version"

HELPER = "/opt/haproxy-mgmt/current/bin/haproxy-revert-helper"
SUDO = "/usr/bin/sudo"

USAGE = (
    "Usage:\n"
    "  haproxy-revert -c <cluster>\n"
    "  haproxy-revert -c <cluster> VERSION\n"
    "\n"
    "Examples:\n"
    "  haproxy-revert -c internal\n"
    "  haproxy-revert -c internal 7\n"
    "  haproxy-revert -c external\n"
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

    if not requested.isdigit() or requested.startswith("0"):
        raise CallerError(
            "the version must be a plain version number.\n\n"
            "Examples:\n"
            f"  haproxy-revert -c {cluster_id} 7\n\n"
            f"Run haproxy-list -c {cluster_id} to list the versions.",
            exit_code=64,
        )

    version = int(requested)
    if version > total:
        raise CallerError(
            f"version {version} does not exist in cluster '{cluster_id}'.\n\n"
            f"The current version is {total}."
        )
    return version


def build_request(cluster_id: str, request_id: str, *, version: int, expected_commit: str) -> str:
    """The exact request a revert sends, built in one place.

    Public for the same reason as the other write operations: the interface's
    worker sends this operation too, and a second construction of the envelope is
    a second thing to keep in step with the helper's strict validation.

    `expected_commit` is the fencing that makes a revert safe to retry. The
    helper refuses if the cluster no longer stands where the caller thought it
    did, so a request that was built from a stale reading fails instead of
    reverting something else.
    """

    return json.dumps(
        {
            "schema_version": 1,
            "operation": OPERATION,
            "cluster": cluster_id,
            "request_id": request_id,
            "parameters": {"version": version, "expected_commit": expected_commit},
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
    cluster_id, requested = _parse(argv)

    try:
        repo = config_path(cluster_id)
        if not is_repo_root(repo):
            writer.write(f"{describe_problem(cluster_id, repo)}\n")
            return 68

        dirty = unsaved_changes(repo)
        if dirty:
            writer.write(
                f"ERROR: there are unsaved changes in {repo}.\n\n"
                f"{dirty}\n\n"
                "Publish or discard them before reverting.\n"
            )
            return 65

        total = count_versions(repo)
        version = _target_version(cluster_id, requested, total)
        if version == total:
            writer.write(f"Version {version} is already current for cluster '{cluster_id}'.\n")
            return 0

        commit = version_commit(repo, version)
        if commit is None:
            raise CallerError(f"could not find version {version}.")
        summary = version_summary(repo, version, commit)
    except (CallerError, GitError) as exc:
        writer.write(f"ERROR: {exc}\n")
        return exc.exit_code

    writer.write(
        "\nReverting the HAProxy configuration:\n\n"
        f"  Cluster:   {cluster_id}\n"
        f"  Version:   {summary.version}\n"
        f"  Date:      {summary.date}\n"
        f"  Comment:   {summary.comment}\n\n"
    )

    request = build_request(
        cluster_id, str(uuid.uuid4()), version=version, expected_commit=commit
    ).encode()

    code, out, err = run_helper(request)

    try:
        result = json.loads(out) if out else None
    except json.JSONDecodeError:
        result = None

    if result is None:
        writer.write(err or f"ERROR: the revert failed with exit code {code}.\n")
        return code or 70

    if not result["valid"]:
        writer.write(
            f"{result['diagnostics']}\n"
            "ERROR: the restored configuration is not valid for this cluster today.\n"
            "No version was created and nothing was published.\n"
        )
        return code or 65

    if code != 0:
        writer.write(err or f"ERROR: the revert failed with exit code {code}.\n")
        return code

    writer.write(
        "HAProxy configuration OK.\n\n"
        f"Cluster '{cluster_id}' is back on the content of version {version}, "
        f"recorded as version {result['version']}.\n\n"
        f"  Hash:     {result['commit']}\n"
        f"  Release:  {result['release']}\n\n"
        "No node deployment has run. Bring the nodes into step with:\n\n"
        f"  haproxy-deploy -c {cluster_id}\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
