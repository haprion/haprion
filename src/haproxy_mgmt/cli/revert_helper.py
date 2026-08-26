"""The privileged half of `haproxy-revert`.

Takes no arguments; the cluster, the version number and the commit the operator
actually saw arrive as a structured request on stdin. Same form and same reason
as the other helpers: PRIVILEGE.md forbids wildcards in argument matching, so a
rule naming a cluster is not available, and one no-argument rule covers every
cluster.

Nothing the caller looked up is believed. The split between reading and writing
opens a window that did not exist when the whole command ran as root: between
the caller showing which version will be restored and this half writing it,
somebody could have changed the repository with sudoedit. So the draft is
checked for unsaved work again here, the version number is resolved to a commit
again here, and the answer must match the one the human approved exactly. A
lookup made outside the boundary must never be the basis for a write inside it.

What a revert is, since B10 step 5: a NEW version holding the chosen version's
tree. It does not rewrite history and it does not restore over a draft first -
that used to write destructively into a human's work tree, and it also could not
restore `managed/`, because publishing takes that layer from the latest version.
Building the version straight from the chosen tree gets all three layers right
and keeps every intermediate version in the history.

It validates. The content was published once before, but a revert must not slip
past validation for that reason: what a node can accept depends on the
certificates and the maps present now, not on what was true then.
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO, TextIO

from haproxy_mgmt.candidate_validation import (
    DEFAULT_RUN_ROOT,
    VALIDATION_CERTIFICATE,
    SandboxValidator,
    candidate_from_files,
    prepare_run_root,
    read_validation_certificate,
    validate_candidate,
    validate_in_sandbox,
)
from haproxy_mgmt.config import DEFAULT_POLICY_PATH, ConfigError, load_policy, load_runtime_config
from haproxy_mgmt.git_command import GitError
from haproxy_mgmt.git_command import git as _git
from haproxy_mgmt.helper_protocol import (
    HelperProtocolError,
    HelperRequest,
    JsonValue,
    read_helper_request,
    require_no_arguments,
)
from haproxy_mgmt.release_install import (
    PUBLISH_GROUP,
    ChangeOwner,
    InstallError,
    default_change_owner,
    install_release,
)
from haproxy_mgmt.release_layout import LayoutError, ReleaseMetadata, build_node_artifact
from haproxy_mgmt.repo_health import unsaved_changes
from haproxy_mgmt.repo_snapshot import (
    PublishError,
    commit_and_swap,
    read_tree_files,
    resolve_head,
)
from haproxy_mgmt.version_history import (
    count_versions,
    restore_worktree,
    version_commit,
)

OPERATION = "revert_version"
PARAMETERS = frozenset({"version", "expected_commit"})
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

#
# The message a reverted version is recorded under. Frozen: an operator reading
# a version list recognises it, and haproxy-list shows it verbatim.
#
MESSAGE = "Revert configuration to version {version}"


def parse_version(raw: JsonValue) -> int:
    if type(raw) is not int or raw < 1:
        raise HelperProtocolError(
            "parameters.version must be a positive version number", exit_code=65
        )
    return raw


def parse_expected_commit(raw: JsonValue) -> str:
    if not isinstance(raw, str) or len(raw) != 40 or not all(c in "0123456789abcdef" for c in raw):
        raise HelperProtocolError(
            "parameters.expected_commit must be a full commit ID", exit_code=65
        )
    return raw


def _response(request: HelperRequest, **fields: Any) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "operation": request.operation,
        "cluster": request.cluster,
        "request_id": request.request_id,
        "valid": True,
        "diagnostics": "",
        "restored_version": None,
        "version": None,
        "commit": None,
        "timestamp": None,
        "release": None,
        "already_current": False,
        **fields,
    }


def _tree_of(repo: Path, commit: str) -> str:
    return _git(repo, "rev-parse", f"{commit}^{{tree}}").decode().strip()


def main(
    argv: list[str] | None = None,
    *,
    policy_path: Path = DEFAULT_POLICY_PATH,
    run_root: Path = DEFAULT_RUN_ROOT,
    input_stream: BinaryIO | None = None,
    output_stream: TextIO | None = None,
    error_stream: TextIO | None = None,
    require_secure: bool = True,
    require_root: bool = True,
    validator: SandboxValidator = validate_in_sandbox,
    group: str = PUBLISH_GROUP,
    change_owner: ChangeOwner = default_change_owner,
    now: Callable[[], datetime] | None = None,
) -> int:
    output = output_stream or sys.stdout
    errors = error_stream or sys.stderr
    stream = input_stream or sys.stdin.buffer
    arguments = sys.argv[1:] if argv is None else argv
    clock = now or (lambda: datetime.now(UTC))

    try:
        require_no_arguments(arguments)
        if require_root and os.geteuid() != 0:
            raise HelperProtocolError("revert helper must run as root", exit_code=77)

        request = read_helper_request(
            stream,
            expected_operation=OPERATION,
            allowed_parameter_keys=PARAMETERS,
        )
        version = parse_version(request.parameters.get("version"))
        expected_commit = parse_expected_commit(request.parameters.get("expected_commit"))

        policy = load_policy(policy_path, require_secure=require_secure)
        cluster = load_runtime_config(policy, require_secure=require_secure).cluster(
            request.cluster
        )
        repo = cluster.config_path

        #
        # Checked again on this side. The draft may have become dirty after the
        # operator approved the preview, and the reset below would overwrite it.
        #
        dirty = unsaved_changes(repo)
        if dirty:
            raise PublishError(
                f"there are unsaved changes in {repo}. Publish or discard them before reverting."
            )

        branch, head = resolve_head(repo)

        #
        # The same lookup the caller made. A different answer means the
        # repository moved in between, and the preview the human approved is no
        # longer true.
        #
        actual = version_commit(repo, version)
        if actual != expected_commit:
            raise PublishError(
                f"the repository changed during the revert; version {version} no longer "
                f"points at the same commit. Expected {expected_commit}, "
                f"now {actual or 'missing'}. Check the version list and try again."
            )

        target_tree = _tree_of(repo, expected_commit)
        artifact = build_node_artifact(read_tree_files(repo, target_tree))

        certificate = read_validation_certificate(
            cluster.validation_certs / VALIDATION_CERTIFICATE,
            require_secure=require_secure,
        )
        prepare_run_root(run_root, require_secure=require_secure)
        result = validate_candidate(
            candidate_from_files(artifact),
            run_root=run_root,
            certificate_ids=cluster.certificate_ids,
            validation_certificate=certificate,
            request_id=request.request_id,
            validator=validator,
        )
        if not result.valid:
            json.dump(
                _response(
                    request,
                    valid=False,
                    diagnostics=result.diagnostics,
                    restored_version=version,
                ),
                output,
                sort_keys=True,
            )
            output.write("\n")
            return 65

        commit = commit_and_swap(
            repo,
            branch=branch,
            tree=target_tree,
            parent=head,
            message=MESSAGE.format(version=version),
        )
        #
        # A hard reset, unlike publishing's index refresh: a revert changes what
        # the configuration IS, so the files a person opens next must be the
        # reverted ones.
        #
        restore_worktree(repo, commit)

        metadata = ReleaseMetadata(
            cluster=request.cluster,
            version=count_versions(repo, commit),
            commit=commit,
            timestamp=clock().strftime(TIMESTAMP_FORMAT),
        )
        installed = install_release(
            cluster.publish_path,
            node_path=cluster.node_path,
            artifact=artifact,
            metadata=metadata,
            group=group,
            change_owner=change_owner,
        )
    except (
        ConfigError,
        GitError,
        HelperProtocolError,
        InstallError,
        LayoutError,
        PublishError,
    ) as exc:
        print(f"ERROR: {exc}", file=errors)
        return exc.exit_code

    json.dump(
        _response(
            request,
            diagnostics=result.diagnostics,
            restored_version=version,
            version=metadata.version,
            commit=metadata.commit,
            timestamp=metadata.timestamp,
            release=str(installed.release),
            already_current=installed.already_current,
        ),
        output,
        sort_keys=True,
    )
    output.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
