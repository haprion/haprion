"""The privileged half of `haproxy-publish`.

Takes no arguments. What is published arrives as a structured request on stdin,
for the reason PRIVILEGE.md gives and `haproxy-history-reset-helper` already
follows: a sudoers rule that matched a cluster name would need a wildcard in
argument matching, and wildcards there are forbidden. One no-argument rule
covers every cluster, and adding a cluster does not touch sudoers.

What crosses the boundary is the configuration BYTES, never a path and never a
finished artifact. Root cannot be handed something to install:

* it receives `core/` and `manual/` as files and builds the version itself
* it derives the node artifact from the COMMITTED candidate with the same code
  the caller uses, so "what was validated is what gets installed" is a property
  of the construction rather than a promise
* it validates in the same sandbox as `haproxy-validate-candidate-helper` - no
  network, no capabilities, the candidate bound read-only - which is strictly
  stronger than the shell path, where `haproxy -c` ran as root

The order is the one the shell path established and is not free to change: the
version is recorded only AFTER validation passes, and the reference moves by
compare-and-swap against the head the caller measured. A candidate that changes
nothing is reported rather than recorded.

Nothing the caller says about the repository is believed. The paths, the current
head, the version number and the author identity are all read again here.
"""

from __future__ import annotations

import os
import re
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Protocol, TextIO

from haproxy_mgmt.candidate_validation import (
    DEFAULT_RUN_ROOT,
    MAX_CANDIDATE_BYTES,
    MAX_CANDIDATE_FILES,
    MAX_FILE_BYTES,
    VALIDATION_CERTIFICATE,
    SandboxValidator,
    candidate_from_files,
    prepare_run_root,
    read_validation_certificate,
    validate_candidate,
    validate_in_sandbox,
)
from haproxy_mgmt.cluster_lock import DEFAULT_LOCK_ROOT, LockBusy, hold
from haproxy_mgmt.config import (
    DEFAULT_POLICY_PATH,
    Cluster,
    ConfigError,
    load_policy,
    load_runtime_config,
)
from haproxy_mgmt.envelope import BLOCKED_EXIT, envelope, failure
from haproxy_mgmt.git_command import GitError
from haproxy_mgmt.helper_protocol import (
    HelperProtocolError,
    HelperRequest,
    JsonValue,
    read_helper_request,
    require_no_arguments,
    write_document,
)
from haproxy_mgmt.release_install import (
    PUBLISH_GROUP,
    ChangeOwner,
    InstallError,
    default_change_owner,
    install_release,
)
from haproxy_mgmt.release_layout import LayoutError, ReleaseMetadata, build_node_artifact
from haproxy_mgmt.repo_snapshot import (
    SNAPSHOT_PREFIXES,
    ConcurrentUpdate,
    PublishError,
    build_candidate_tree,
    commit_and_swap,
    read_tree_files,
    refresh_worktree_index,
    resolve_head,
)
from haproxy_mgmt.version_history import count_versions, with_request_trailer

#
# Two names, deliberately. `OPERATION` is what the request must say to reach this
# helper - a privileged entry point, named for what it does rather than for the
# command. `PUBLISH_OPERATION` is what the frozen contract calls the result, and
# it is what a caller matches its own job against.
#
OPERATION = "publish_version"
PUBLISH_OPERATION = "publish"
PARAMETERS = frozenset({"files", "expected_head", "comment"})
COMMIT_ID = re.compile(r"^[0-9a-f]{40}$")
CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")

#
# The published contract caps a comment at 4096 characters. The same cap is
# applied on the way in, so a comment that would be rejected when the version is
# read back cannot be recorded in the first place.
#
MAX_COMMENT_BYTES = 4096

TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def _repository_path(raw: str) -> str:
    """A repository-relative path inside the layers a human publish owns.

    Rejected rather than normalized. A path that has to be cleaned up before it
    is safe is a path whose sender and receiver disagree about what it means.
    """

    path = PurePosixPath(raw)
    if (
        not raw
        or path.is_absolute()
        or str(path) != raw
        or any(part in (".", "..") for part in path.parts)
    ):
        raise HelperProtocolError("the request contains an invalid relative path", exit_code=65)
    if not raw.startswith(SNAPSHOT_PREFIXES):
        raise HelperProtocolError(
            f"'{raw}' is outside the layers this path publishes "
            f"({', '.join(prefix.rstrip('/') for prefix in SNAPSHOT_PREFIXES)}).",
            exit_code=65,
        )
    return raw


def parse_files(raw_files: JsonValue) -> dict[str, bytes]:
    """The `core/` and `manual/` bytes being published, decoded and bounded.

    The limits are the candidate limits, deliberately: this is the same payload
    seen one step earlier, before it has been collapsed into an artifact, and a
    request that could not survive validation should not reach git either.
    """

    if not isinstance(raw_files, dict) or not raw_files:
        raise HelperProtocolError("parameters.files must be a non-empty object", exit_code=65)
    if len(raw_files) > MAX_CANDIDATE_FILES:
        raise HelperProtocolError("the request contains too many files", exit_code=65)

    files: dict[str, bytes] = {}
    total = 0
    for raw_path in sorted(raw_files):
        content = raw_files[raw_path]
        if not isinstance(raw_path, str) or not isinstance(content, str):
            raise HelperProtocolError("paths and contents must be strings", exit_code=65)
        path = _repository_path(raw_path)
        encoded = content.encode("utf-8")
        if b"\x00" in encoded:
            raise HelperProtocolError("published files may not contain NUL", exit_code=65)
        if len(encoded) > MAX_FILE_BYTES:
            raise HelperProtocolError("the request contains an oversized file", exit_code=65)
        total += len(encoded)
        if total > MAX_CANDIDATE_BYTES:
            raise HelperProtocolError("the request exceeds the total size limit", exit_code=65)
        files[path] = encoded
    return files


def parse_comment(raw_comment: JsonValue) -> str:
    """The message the version is recorded under.

    Control characters are refused because the comment is shown back in version
    listings and in the deployment output, and a comment able to redraw those is
    a comment able to hide what was published.
    """

    if not isinstance(raw_comment, str) or not raw_comment.strip():
        raise HelperProtocolError("parameters.comment must be a non-empty string", exit_code=65)
    if len(raw_comment.encode("utf-8")) > MAX_COMMENT_BYTES:
        raise HelperProtocolError("parameters.comment is too long", exit_code=65)
    if CONTROL.search(raw_comment):
        raise HelperProtocolError(
            "parameters.comment may not contain control characters", exit_code=65
        )
    return raw_comment


def parse_expected_head(raw_head: JsonValue) -> str:
    if not isinstance(raw_head, str) or not COMMIT_ID.fullmatch(raw_head):
        raise HelperProtocolError("parameters.expected_head must be a full commit ID", exit_code=65)
    return raw_head


class Refuse(Protocol):
    """How this helper ends a run that will not record a version."""

    def __call__(
        self, code: str, message: str, exit_code: int, details: dict[str, Any] | None = None
    ) -> int: ...


def _result(
    *,
    changed: bool,
    deployment_required: bool,
    version: int | None,
    commit: str | None,
    published_at: str | None,
    comment: str,
    valid: bool,
    cluster: str,
    candidate_sha256: str | None = None,
    release: str | None = None,
    already_current: bool = False,
) -> dict[str, Any]:
    """The frozen `publish` result.

    `changed` and `deployment_required` are two questions, not one. A publish
    that recorded no new version can still have moved the published release -
    that is what finishing an interrupted run looks like - and telling the
    operator no deploy is needed would leave the nodes behind a release nobody
    mentioned.

    `issues` is present and empty rather than absent. The contract has a place
    for structured validation findings; what this path has is HAProxy's own
    diagnostics text, which is not that. Returning an empty list says truthfully
    that no structured issue was produced, and leaves the field free to be filled
    once the generator owns validation. The text itself travels with the error,
    where a reader looks for the reason something was refused.
    """

    return {
        "changed": changed,
        "version": version,
        "hash": commit,
        "published_at": published_at,
        "comment": comment,
        "validation": {"valid": valid, "issues": []},
        "deployment_required": deployment_required,
        "next_command": f"haproxy-deploy -c {cluster}" if deployment_required else None,
        #
        # Outside the frozen fields, and allowed to be: v1 ignores unknown keys.
        # The candidate digest is what ties a stored result to the exact bytes
        # that were validated, and the release path is what an operator looks at
        # when asking whether the published area really moved.
        #
        "candidate_sha256": candidate_sha256,
        "release": release,
        "already_current": already_current,
    }


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
    lock_root: Path = DEFAULT_LOCK_ROOT,
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
            raise HelperProtocolError("publish helper must run as root", exit_code=77)

        request = read_helper_request(
            stream,
            expected_operation=OPERATION,
            allowed_parameter_keys=PARAMETERS,
            max_bytes=MAX_CANDIDATE_BYTES + 1024 * 1024,
        )
    except HelperProtocolError as exc:
        #
        # Deliberately stderr only. The cluster and the request ID an envelope
        # must be bound to are fields of the request that just failed to parse;
        # an envelope invented here could not be bound to the caller's job and
        # would rightly be rejected as somebody else's answer.
        #
        errors.write(f"ERROR: {exc}\n")
        return exc.exit_code

    def refuse(
        code: str, message: str, exit_code: int, details: dict[str, Any] | None = None
    ) -> int:
        """End the run with a result, not just an exit code."""

        #
        # The code beside the message, not instead of it. The terminal, the jobs
        # page and the audit trail then name the same string for the same
        # failure, so "what my window said" and "what the page says" can be put
        # side by side without guessing. Added 2026-08-31 as F1b.
        #
        errors.write(f"ERROR: [{code}] {message}\n")
        write_document(
            output,
            failure(
                operation=PUBLISH_OPERATION,
                cluster=request.cluster,
                request_id=request.request_id,
                code=code,
                message=message,
                exit_code=exit_code,
                details=details,
            ),
        )
        return exit_code

    try:
        files = parse_files(request.parameters.get("files"))
        expected_head = parse_expected_head(request.parameters.get("expected_head"))
        comment = parse_comment(request.parameters.get("comment"))

        policy = load_policy(policy_path, require_secure=require_secure)
        cluster = load_runtime_config(policy, require_secure=require_secure).cluster(
            request.cluster
        )
    except HelperProtocolError as exc:
        return refuse("bad_input", str(exc), exc.exit_code)
    except ConfigError as exc:
        return refuse(
            "bad_input" if exc.exit_code == 64 else "dependency_unavailable",
            str(exc),
            exc.exit_code,
        )

    try:
        #
        # Everything that decides what gets written happens inside the cluster's
        # lock, the head included. Publishing used to take no lock at all: the
        # compare-and-swap on the branch reference caught a second publish, but
        # nothing stopped a deploy from reading the release area while this run
        # was rewriting it, and nothing serialised publish against revert.
        #
        with hold(request.cluster, operation="publish", root=lock_root):
            return _publish(
                request=request,
                cluster=cluster,
                files=files,
                expected_head=expected_head,
                comment=comment,
                output=output,
                run_root=run_root,
                require_secure=require_secure,
                validator=validator,
                group=group,
                change_owner=change_owner,
                clock=clock,
                refuse=refuse,
            )
    except LockBusy as exc:
        return refuse("operation_locked", str(exc), exc.exit_code)
    except ConcurrentUpdate as exc:
        return refuse("base_version_changed", str(exc), exc.exit_code)
    except (InstallError, LayoutError) as exc:
        return refuse("publish_incomplete", str(exc), exc.exit_code)
    except PublishError as exc:
        return refuse("publish_incomplete", str(exc), exc.exit_code)
    except GitError as exc:
        return refuse("internal_error", str(exc), exc.exit_code)


def _publish(
    *,
    request: HelperRequest,
    cluster: Cluster,
    files: dict[str, bytes],
    expected_head: str,
    comment: str,
    output: TextIO,
    run_root: Path,
    require_secure: bool,
    validator: SandboxValidator,
    group: str,
    change_owner: ChangeOwner,
    clock: Callable[[], datetime],
    refuse: Refuse,
) -> int:
    """The publish itself, with the cluster's lock already held."""

    repo = cluster.config_path

    #
    # 1. Where the repository actually is now. The caller measured the same
    #    value before building its request; if the two disagree, something was
    #    published or reverted in between and this candidate was built on a
    #    starting point that no longer exists.
    #
    branch, head = resolve_head(repo)
    if head != expected_head:
        return refuse(
            "base_version_changed",
            "the configuration changed after this candidate was prepared. "
            "Nothing was published; run the command again so the candidate "
            "is built on the current version.",
            BLOCKED_EXIT,
        )

    #
    # 2. The candidate tree. managed/ is carried over from HEAD untouched.
    #
    snapshot = build_candidate_tree(repo, head, files)
    if snapshot.unchanged:
        #
        # The contract's verified no-op - and the shape a retry takes.
        #
        # The release is still installed. That is not belt and braces: it is the
        # repair the recovery path needs. A run interrupted between the commit
        # and the install leaves a version whose release was never published, and
        # the retry arrives here - the candidate already matches the head it
        # produced - so this is the only place that repair can happen.
        # `install_release` is idempotent, so when nothing was missing it
        # verifies the stamp and returns.
        #
        installed = install_release(
            cluster.publish_path,
            node_path=cluster.node_path,
            artifact=build_node_artifact(read_tree_files(repo, snapshot.tree)),
            metadata=ReleaseMetadata(
                cluster=request.cluster,
                version=count_versions(repo, head),
                commit=head,
                timestamp=clock().strftime(TIMESTAMP_FORMAT),
            ),
            group=group,
            change_owner=change_owner,
        )
        write_document(
            output,
            envelope(
                operation=PUBLISH_OPERATION,
                outcome="done",
                cluster=request.cluster,
                request_id=request.request_id,
                result=_result(
                    changed=False,
                    deployment_required=not installed.already_current,
                    version=count_versions(repo, head),
                    commit=head,
                    published_at=None,
                    comment=comment,
                    valid=True,
                    cluster=request.cluster,
                    release=str(installed.release),
                    already_current=installed.already_current,
                ),
            ),
        )
        return 0

    #
    # 3. The artifact, derived here from the candidate tree - not received.
    #
    artifact = build_node_artifact(read_tree_files(repo, snapshot.tree))
    candidate = candidate_from_files(artifact)

    #
    # 4. Validation, in the sandbox, on exactly those bytes.
    #
    certificate = read_validation_certificate(
        cluster.validation_certs / VALIDATION_CERTIFICATE,
        require_secure=require_secure,
    )
    prepare_run_root(run_root, require_secure=require_secure)
    result = validate_candidate(
        candidate,
        run_root=run_root,
        certificate_ids=cluster.certificate_ids,
        validation_certificate=certificate,
        request_id=request.request_id,
        validator=validator,
    )
    if not result.valid:
        return refuse(
            "candidate_invalid",
            "the HAProxy configuration is invalid. "
            "No version was created and nothing was published.",
            65,
            {"diagnostics": result.diagnostics, "candidate_sha256": candidate.sha256},
        )

    #
    # 5. Only now is a version recorded, and only if nobody moved the branch
    #    while the sandbox was running.
    #
    commit = commit_and_swap(
        repo,
        branch=branch,
        tree=snapshot.tree,
        parent=head,
        message=with_request_trailer(comment, request.request_id),
    )
    refresh_worktree_index(repo, commit)

    #
    # 6. Install the release the nodes fetch, named by the commit.
    #
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

    write_document(
        output,
        envelope(
            operation=PUBLISH_OPERATION,
            outcome="done",
            cluster=request.cluster,
            request_id=request.request_id,
            result=_result(
                changed=True,
                deployment_required=True,
                version=metadata.version,
                commit=metadata.commit,
                published_at=metadata.timestamp,
                comment=comment,
                valid=True,
                cluster=request.cluster,
                candidate_sha256=candidate.sha256,
                release=str(installed.release),
                already_current=installed.already_current,
            ),
        ),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
