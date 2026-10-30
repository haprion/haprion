"""The privileged half of `haprion-publish`.

Takes no arguments. What is published arrives as a structured request on stdin,
for the reason PRIVILEGE.md gives and `haprion-history-reset-helper` already
follows: a sudoers rule that matched a cluster name would need a wildcard in
argument matching, and wildcards there are forbidden. One no-argument rule
covers every cluster, and adding a cluster does not touch sudoers.

What crosses the boundary is the configuration BYTES, never a path and never a
finished artifact. Root cannot be handed something to install:

* it receives `core/` and `manual/` as files and builds the version itself
* it derives the node artifact from the COMMITTED candidate with the same code
  the caller uses, so "what was validated is what gets installed" is a property
  of the construction rather than a promise
* it validates in the same sandbox as `haprion-validate-candidate-helper` - no
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
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Protocol, TextIO

from haprion import exit_codes, tls_policy
from haprion.candidate_validation import (
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
from haprion.cluster_lock import DEFAULT_LOCK_ROOT, LockBusy, hold
from haprion.config import (
    DEFAULT_POLICY_PATH,
    Cluster,
    ConfigError,
    load_policy,
    load_runtime_config,
)
from haprion.envelope import envelope, failure
from haprion.git_command import GitError
from haprion.helper_protocol import (
    HelperProtocolError,
    HelperRequest,
    JsonValue,
    config_error_code,
    read_helper_request,
    require_no_arguments,
    write_document,
)
from haprion.release_install import (
    DEPLOYMENT_REQUIRED_AFTER_INSTALL,
    PUBLISH_GROUP,
    ChangeOwner,
    InstallError,
    default_change_owner,
    install_release,
)
from haprion.release_layout import (
    LayoutError,
    ReleaseMetadata,
    build_node_artifact,
    build_release_index,
)
from haprion.repo_snapshot import (
    SNAPSHOT_PREFIXES,
    ConcurrentUpdate,
    PublishError,
    build_candidate_tree,
    commit_and_swap,
    read_tree_files,
    refresh_worktree_index,
    resolve_head,
)
from haprion.reservations import (
    NOTHING_TO_REVIEW,
    RESERVATIONS_PATH,
    FragmentReview,
    load_reservations,
    review_fragments,
)
from haprion.status_collect import read_target
from haprion.version_history import (
    comment_problem,
    count_versions,
    index_left_behind,
    request_names,
    version_message,
)

#
# Two names, deliberately. `OPERATION` is what the request must say to reach this
# helper - a privileged entry point, named for what it does rather than for the
# command. `PUBLISH_OPERATION` is what the frozen contract calls the result, and
# it is what a caller matches its own job against.
#
OPERATION = "publish_version"
PUBLISH_OPERATION = "publish"
PARAMETERS = frozenset({"files", "expected_head", "comment", "requested_by"})
COMMIT_ID = re.compile(r"^[0-9a-f]{40}$")

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
        raise HelperProtocolError(
            "the request contains an invalid relative path", exit_code=exit_codes.REFUSED
        )
    if not raw.startswith(SNAPSHOT_PREFIXES):
        raise HelperProtocolError(
            f"'{raw}' is outside the layers this path publishes "
            f"({', '.join(prefix.rstrip('/') for prefix in SNAPSHOT_PREFIXES)}).",
            exit_code=exit_codes.REFUSED,
        )
    return raw


def parse_files(raw_files: JsonValue) -> dict[str, bytes]:
    """The `core/` and `manual/` bytes being published, decoded and bounded.

    The limits are the candidate limits, deliberately: this is the same payload
    seen one step earlier, before it has been collapsed into an artifact, and a
    request that could not survive validation should not reach git either.
    """

    if not isinstance(raw_files, dict) or not raw_files:
        raise HelperProtocolError(
            "parameters.files must be a non-empty object", exit_code=exit_codes.REFUSED
        )
    if len(raw_files) > MAX_CANDIDATE_FILES:
        raise HelperProtocolError(
            "the request contains too many files", exit_code=exit_codes.REFUSED
        )

    files: dict[str, bytes] = {}
    total = 0
    for raw_path in sorted(raw_files):
        content = raw_files[raw_path]
        if not isinstance(raw_path, str) or not isinstance(content, str):
            raise HelperProtocolError(
                "paths and contents must be strings", exit_code=exit_codes.REFUSED
            )
        path = _repository_path(raw_path)
        encoded = content.encode("utf-8")
        if b"\x00" in encoded:
            raise HelperProtocolError(
                "published files may not contain NUL", exit_code=exit_codes.REFUSED
            )
        if len(encoded) > MAX_FILE_BYTES:
            raise HelperProtocolError(
                "the request contains an oversized file", exit_code=exit_codes.REFUSED
            )
        total += len(encoded)
        if total > MAX_CANDIDATE_BYTES:
            raise HelperProtocolError(
                "the request exceeds the total size limit", exit_code=exit_codes.REFUSED
            )
        files[path] = encoded
    return files


def parse_comment(raw_comment: JsonValue) -> str:
    """The message the version is recorded under.

    Control characters are refused because the comment is shown back in version
    listings and in the deployment output, and a comment able to redraw those is
    a comment able to hide what was published.
    """

    if not isinstance(raw_comment, str) or not raw_comment.strip():
        raise HelperProtocolError(
            "parameters.comment must be a non-empty string", exit_code=exit_codes.REFUSED
        )
    if len(raw_comment.encode("utf-8")) > MAX_COMMENT_BYTES:
        raise HelperProtocolError("parameters.comment is too long", exit_code=exit_codes.REFUSED)
    problem = comment_problem(raw_comment)
    if problem:
        raise HelperProtocolError(f"parameters.comment {problem}", exit_code=exit_codes.REFUSED)
    return raw_comment


def parse_expected_head(raw_head: JsonValue) -> str:
    if not isinstance(raw_head, str) or not COMMIT_ID.fullmatch(raw_head):
        raise HelperProtocolError(
            "parameters.expected_head must be a full commit ID", exit_code=exit_codes.REFUSED
        )
    return raw_head


class Refuse(Protocol):
    """How this helper ends a run that will not record a version."""

    def __call__(
        self, code: str, message: str, exit_code: int, details: dict[str, Any] | None = None
    ) -> int: ...


def _fragment_review(files: Mapping[str, bytes]) -> FragmentReview:
    """Whether the promise is current with the handwritten fragments.

    Reads both the promise and the fragments from the same tree the publish is
    built from, so the digests compared describe the version being published
    rather than whatever happens to be in the work tree.
    """

    try:
        reservations = load_reservations(files.get(RESERVATIONS_PATH, b"{}"))
    except ConfigError:
        #
        # A file that cannot be read is reported by the path that generates
        # from it, with the reason. Saying nothing here leaves that refusal to
        # be the one the operator sees, instead of a second, vaguer line about
        # the same file.
        #
        return NOTHING_TO_REVIEW
    return review_fragments(files, reservations)


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
    review: FragmentReview = NOTHING_TO_REVIEW,
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
        "next_command": f"haprion-deploy -c {cluster}" if deployment_required else None,
        #
        # Outside the frozen fields, and allowed to be: v1 ignores unknown keys.
        # The candidate digest is what ties a stored result to the exact bytes
        # that were validated, and the release path is what an operator looks at
        # when asking whether the published area really moved.
        #
        "candidate_sha256": candidate_sha256,
        "release": release,
        "already_current": already_current,
        #
        # An observation, not a refusal. The handwritten layer is read and
        # never interpreted, so nothing here knows whether these fragments
        # actually collide - only whether the promise about them is current.
        # Refusing on that would block a cluster whose fragments are perfectly
        # fine; saying it is what a person needs to hear.
        #
        # Three lists rather than the single one B86 returned, because the
        # operator does something different about each. Both halves of this
        # command ship in one release and reach each other through
        # `current/bin`, so the shape moves in step with its only reader.
        #
        "fragment_review": {
            "unreviewed": list(review.unreviewed),
            "changed": list(review.changed),
            "vanished": list(review.vanished),
        },
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
            raise HelperProtocolError(
                "publish helper must run as root", exit_code=exit_codes.NOT_ROOT
            )

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
        return write_document(
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
            exit_code,
        )

    try:
        files = parse_files(request.parameters.get("files"))
        expected_head = parse_expected_head(request.parameters.get("expected_head"))
        comment = parse_comment(request.parameters.get("comment"))

        policy = load_policy(policy_path, require_secure=require_secure)
        names = request_names(request.parameters, interface_account=policy.interface_account)
        cluster = load_runtime_config(policy, require_secure=require_secure).cluster(
            request.cluster
        )
    except HelperProtocolError as exc:
        return refuse("bad_input", str(exc), exc.exit_code)
    except ConfigError as exc:
        return refuse(
            config_error_code(exc.exit_code),
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
                names=names,
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
    names: tuple[str, str],
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
            exit_codes.BLOCKED,
        )

    #
    # 2. The candidate tree. managed/ is carried over from HEAD untouched.
    #
    def sandboxed(tree_files: Mapping[str, bytes]) -> int | None:
        """HAProxy's own check of these files in the sandbox; the refusal, or None."""

        candidate = candidate_from_files(build_node_artifact(tree_files))
        certificate = read_validation_certificate(
            cluster.validation_certs / VALIDATION_CERTIFICATE,
            require_secure=require_secure,
        )
        prepare_run_root(run_root, require_secure=require_secure)
        result = validate_candidate(
            candidate,
            run_root=run_root,
            certificate_ids=cluster.certificate_ids,
            authority_ids=cluster.authority_ids,
            validation_certificate=certificate,
            request_id=request.request_id,
            validator=validator,
        )
        if result.valid:
            return None
        return refuse(
            "candidate_invalid",
            "the HAProxy configuration is invalid. "
            "No version was created and nothing was published.",
            exit_codes.REFUSED,
            {"diagnostics": result.diagnostics, "candidate_sha256": candidate.sha256},
        )

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
        #
        # The index too: a run stopped between moving the branch and
        # `reset --mixed` leaves the files as this version and the index as the
        # one before, and every later check reads that as unsaved work
        # (review 26-10-30, D3).
        #
        if index_left_behind(repo, head):
            refresh_worktree_index(repo, head)
        current_files = read_tree_files(repo, snapshot.tree)
        short = tls_policy.stick_counters_problem(
            current_files, cluster=request.cluster, config_path=str(cluster.config_path)
        )
        if short is not None:
            return refuse("stick_counters_short", short, exit_codes.BLOCKED)
        #
        # A head whose release was never installed was never checked either: a
        # commit made by hand, a cluster's first version whose publish failed
        # (B318), version 1 after a history reset. It goes through the sandbox
        # before it goes out, as the managed path's does; a retry of a version
        # already installed is not checked again (review 2026-10-22, 1A-6).
        #
        published = read_target(cluster.publish_path, cluster.node_path)
        if published is None or published.hash != head:
            refused = sandboxed(current_files)
            if refused is not None:
                return refused
        #
        # The same policy as a change: an unchanged tree is how a retry
        # arrives, and it must not install what the first attempt refused.
        #
        stale = tls_policy.core_defaults_problem(
            current_files["core/haproxy.cfg"],
            cluster=request.cluster,
            config_path=str(cluster.config_path),
        )
        if stale is not None:
            return refuse("tls_defaults_stale", stale, exit_codes.BLOCKED)
        installed = install_release(
            cluster.publish_path,
            node_path=cluster.node_path,
            artifact=build_node_artifact(current_files),
            index=build_release_index(current_files),
            metadata=ReleaseMetadata(
                cluster=request.cluster,
                version=count_versions(repo, head),
                commit=head,
                timestamp=clock().strftime(TIMESTAMP_FORMAT),
            ),
            group=group,
            change_owner=change_owner,
        )
        return write_document(
            output,
            envelope(
                operation=PUBLISH_OPERATION,
                outcome="done",
                cluster=request.cluster,
                request_id=request.request_id,
                result=_result(
                    changed=False,
                    deployment_required=DEPLOYMENT_REQUIRED_AFTER_INSTALL,
                    version=count_versions(repo, head),
                    commit=head,
                    published_at=None,
                    comment=comment,
                    valid=True,
                    cluster=request.cluster,
                    release=str(installed.release),
                    already_current=installed.already_current,
                    review=_fragment_review(current_files),
                ),
            ),
            0,
        )

    #
    # 3. The artifact, derived here from the candidate tree - not received.
    #
    published_files = read_tree_files(repo, snapshot.tree)
    artifact = build_node_artifact(published_files)
    index = build_release_index(published_files)
    candidate = candidate_from_files(artifact)

    #
    # Before the sandbox, where HAProxy would refuse the same release in words
    # that name neither the file nor the line (`stick_counters_problem`).
    #
    short = tls_policy.stick_counters_problem(
        published_files, cluster=request.cluster, config_path=str(cluster.config_path)
    )
    if short is not None:
        return refuse("stick_counters_short", short, exit_codes.BLOCKED)

    #
    # 4. Validation, in the sandbox, on exactly those bytes.
    #
    refused = sandboxed(published_files)
    if refused is not None:
        return refused

    #
    # After the sandbox, deliberately. A `core/haproxy.cfg` can be both stale and
    # syntactically broken, and the broken half is the one that stops HAProxy
    # from starting - reporting the cipher list first would hide it behind the
    # smaller problem. Checked on the bytes about to be published, so a refusal
    # describes what would have gone out - and before the commit, so a refusal
    # leaves no version behind that a retry would then find unchanged and
    # publish without asking again.
    #
    stale = tls_policy.core_defaults_problem(
        published_files["core/haproxy.cfg"],
        cluster=request.cluster,
        config_path=str(cluster.config_path),
    )
    if stale is not None:
        return refuse("tls_defaults_stale", stale, exit_codes.BLOCKED)

    #
    # 5. Only now is a version recorded, and only if nobody moved the branch
    #    while the sandbox was running.
    #
    commit = commit_and_swap(
        repo,
        branch=branch,
        tree=snapshot.tree,
        parent=head,
        message=version_message(comment, request.request_id, names),
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
        index=index,
        metadata=metadata,
        group=group,
        change_owner=change_owner,
    )

    return write_document(
        output,
        envelope(
            operation=PUBLISH_OPERATION,
            outcome="done",
            cluster=request.cluster,
            request_id=request.request_id,
            result=_result(
                changed=True,
                deployment_required=DEPLOYMENT_REQUIRED_AFTER_INSTALL,
                version=metadata.version,
                commit=metadata.commit,
                published_at=metadata.timestamp,
                comment=comment,
                valid=True,
                cluster=request.cluster,
                candidate_sha256=candidate.sha256,
                release=str(installed.release),
                already_current=installed.already_current,
                review=_fragment_review(published_files),
            ),
        ),
        0,
    )


if __name__ == "__main__":
    raise SystemExit(main())
