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

import os
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO, Protocol, TextIO

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
from haproxy_mgmt.git_command import git as _git
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
from haproxy_mgmt.release_layout import (
    LayoutError,
    ReleaseMetadata,
    build_node_artifact,
    build_release_index,
)
from haproxy_mgmt.repo_health import unsaved_changes
from haproxy_mgmt.repo_snapshot import (
    ConcurrentUpdate,
    PublishError,
    commit_and_swap,
    read_tree_files,
    resolve_head,
)
from haproxy_mgmt.version_history import (
    count_versions,
    recent_versions,
    request_names,
    restore_worktree,
    version_commit,
    version_message,
)

#
# Two names, deliberately. `OPERATION` is what the request must say to reach this
# helper - a privileged entry point, named for what it does rather than for the
# command. `REVERT_OPERATION` is what the frozen contract calls the result, and
# it is what a caller matches its own job against.
#
OPERATION = "revert_version"
REVERT_OPERATION = "revert"
PARAMETERS = frozenset({"version", "expected_commit", "expected_head", "requested_by"})
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


def parse_expected_head(raw: JsonValue) -> str | None:
    """The newest version the caller saw, when it says (CR-09); absent from older callers."""

    if raw is None:
        return None
    if not isinstance(raw, str) or len(raw) != 40 or not all(c in "0123456789abcdef" for c in raw):
        raise HelperProtocolError("parameters.expected_head must be a full commit ID", exit_code=65)
    return raw


class Refuse(Protocol):
    """How this helper ends a run that will not write anything."""

    def __call__(
        self, code: str, message: str, exit_code: int, details: dict[str, Any] | None = None
    ) -> int: ...


def _tree_of(repo: Path, commit: str) -> str:
    return _git(repo, "rev-parse", f"{commit}^{{tree}}").decode().strip()


def _result(
    *,
    changed: bool,
    deployment_required: bool,
    from_version: int,
    restored_version: int,
    new_version: int,
    commit: str,
    published_at: str | None,
    cluster: str,
    release: str | None,
    already_current: bool,
) -> dict[str, Any]:
    """The frozen `revert` result.

    `changed` and `deployment_required` are two questions, not one. A revert that
    recorded no new version can still have moved the published release - that is
    what finishing an interrupted run looks like - and telling the operator no
    deploy is needed would leave the nodes behind a release nobody mentioned.
    """

    return {
        "changed": changed,
        "from_version": from_version,
        "restored_version": restored_version,
        "new_version": new_version,
        "hash": commit,
        "published_at": published_at,
        "deployment_required": deployment_required,
        "next_command": f"haproxy-deploy -c {cluster}" if deployment_required else None,
        #
        # Outside the frozen fields, and allowed to be: v1 ignores unknown keys.
        # The release path is what an operator looks for when asking whether the
        # published area really moved, and `already_current` records that the
        # release was installed before this run - which is how a repeated revert
        # of the same content is recognised as a repeat rather than as a change.
        #
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
            raise HelperProtocolError("revert helper must run as root", exit_code=77)
        request = read_helper_request(
            stream,
            expected_operation=OPERATION,
            allowed_parameter_keys=PARAMETERS,
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
        """End the run with a result, not just an exit code.

        Everything below this point knows which job it belongs to, so every exit
        carries the envelope the contract promises on every path. Without it a
        worker sees an unparseable answer and stores `unknown` - "this may have
        taken effect" - for a refusal that provably wrote nothing.
        """

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
                operation=REVERT_OPERATION,
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
        version = parse_version(request.parameters.get("version"))
        expected_commit = parse_expected_commit(request.parameters.get("expected_commit"))
        expected_head = parse_expected_head(request.parameters.get("expected_head"))
        policy = load_policy(policy_path, require_secure=require_secure)
        names = request_names(request.parameters, interface_account=policy.interface_account)
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
        # lock, and the checks are made again in here rather than carried in from
        # outside it. A revert taken without the lock could be prepared against a
        # repository that a deploy or another revert moved a moment later, and
        # the reference swap alone would not notice a release area changing
        # underneath it.
        #
        with hold(request.cluster, operation="revert", root=lock_root):
            return _revert(
                request=request,
                names=names,
                cluster=cluster,
                version=version,
                expected_commit=expected_commit,
                expected_head=expected_head,
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
        return refuse("expected_target_changed", str(exc), exc.exit_code)
    except (InstallError, LayoutError) as exc:
        return refuse("publish_incomplete", str(exc), exc.exit_code)
    except PublishError as exc:
        return refuse("publish_incomplete", str(exc), exc.exit_code)
    except GitError as exc:
        return refuse("internal_error", str(exc), exc.exit_code)


def _revert(
    *,
    request: HelperRequest,
    names: tuple[str, str],
    cluster: Cluster,
    version: int,
    expected_commit: str,
    expected_head: str | None,
    output: TextIO,
    run_root: Path,
    require_secure: bool,
    validator: SandboxValidator,
    group: str,
    change_owner: ChangeOwner,
    clock: Callable[[], datetime],
    refuse: Refuse,
) -> int:
    """The revert itself, with the cluster's lock already held."""

    repo = cluster.config_path

    #
    # Checked again on this side. The draft may have become dirty after the
    # operator approved the preview, and the reset below would overwrite it.
    #
    dirty = unsaved_changes(repo)
    if dirty:
        return refuse(
            "dirty_worktree",
            f"there are unsaved changes in {repo}. Publish or discard them before reverting.",
            BLOCKED_EXIT,
        )

    branch, head = resolve_head(repo)
    from_version = count_versions(repo, head)

    #
    # A revert is a decision about the history its caller read, and it is
    # retried after a worker dies (review 2026-10-04, CR-09). Retried blindly,
    # it reverted again on top of a version somebody recorded in between and
    # took that change away. So:
    #
    # - this request's own version as the newest is the retry of a run that
    #   committed and stopped: the tree matches below, and the unchanged path
    #   repairs the release;
    # - this request's own version with anything after it has been superseded,
    #   and is left alone;
    # - otherwise the head has to be the one the caller saw, when it says.
    #
    own = next(
        (summary for summary in recent_versions(repo) if summary.request_id == request.request_id),
        None,
    )
    if own is not None and own.commit != head:
        return refuse(
            "expected_target_changed",
            f"this revert was recorded as version {own.version}, and version {from_version} "
            "has been recorded since. It is not run again, so the later version stays.",
            BLOCKED_EXIT,
        )

    #
    # The same lookup the caller made. A different answer means the repository
    # moved in between, and the preview the human approved is no longer true.
    #
    actual = version_commit(repo, version)
    if actual != expected_commit:
        return refuse(
            "expected_target_changed",
            f"the repository changed during the revert; version {version} no longer "
            f"points at the same commit. Expected {expected_commit}, "
            f"now {actual or 'missing'}. Check the version list and try again.",
            BLOCKED_EXIT,
        )

    if own is None and expected_head is not None and head != expected_head:
        return refuse(
            "expected_target_changed",
            f"the configuration moved since the revert was asked for: version {from_version} "
            "was recorded after the version list was read. Nothing was changed; check the "
            "version list and try again.",
            BLOCKED_EXIT,
        )

    target_tree = _tree_of(repo, expected_commit)
    target_files = read_tree_files(repo, target_tree)

    if target_tree == _tree_of(repo, head):
        #
        # The contract's successful no-op, and the shape a retry takes.
        # Recording a second version holding byte-identical content would grow
        # the history without changing the configuration.
        #
        # The release is still installed. That is not belt and braces: it is the
        # repair the recovery path needs. A run interrupted between the commit
        # and the install leaves a version whose release was never published, and
        # the retry arrives here - the tree already matches - so this is the only
        # place that repair can happen. `install_release` is idempotent, so when
        # nothing was missing it verifies the stamp and returns.
        #
        installed = install_release(
            cluster.publish_path,
            node_path=cluster.node_path,
            artifact=build_node_artifact(target_files),
            index=build_release_index(target_files),
            metadata=ReleaseMetadata(
                cluster=request.cluster,
                version=from_version,
                commit=head,
                timestamp=clock().strftime(TIMESTAMP_FORMAT),
            ),
            group=group,
            change_owner=change_owner,
        )
        write_document(
            output,
            envelope(
                operation=REVERT_OPERATION,
                outcome="done",
                cluster=request.cluster,
                request_id=request.request_id,
                result=_result(
                    changed=False,
                    #
                    # True whether or not the install did anything, and
                    # `already_current` is the record of which it was.
                    #
                    # This branch cannot tell a repeat from a repair. Both arrive
                    # with the tree already matching and the release already in
                    # place, and the difference between them is not in the
                    # repository at all - it is whether anybody was ever told to
                    # deploy. A repeat follows a run that said so; a repair
                    # follows a run that was killed before it could say
                    # anything.
                    #
                    # Measured on 2026-08-31: a worker killed after its helper
                    # committed and installed left both nodes a version behind,
                    # and the retry answered that no deploy was needed. Answering
                    # from node state would mean reading nodes, which this
                    # command deliberately does not do - so it answers with the
                    # side whose cost is a no-op deploy reporting `skip`, rather
                    # than the side whose cost is a cluster left behind a release
                    # nobody named.
                    #
                    deployment_required=True,
                    from_version=from_version,
                    restored_version=version,
                    new_version=from_version,
                    commit=head,
                    published_at=None,
                    cluster=request.cluster,
                    release=str(installed.release),
                    already_current=installed.already_current,
                ),
            ),
        )
        return 0

    artifact = build_node_artifact(target_files)
    index = build_release_index(target_files)

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
        #
        # The content was valid when it was published, which is exactly why this
        # is checked again: what a node can accept depends on the certificates
        # and maps present now. The diagnostics travel in the error's details
        # because they are the whole answer to "why not", and a reader that only
        # understands the stable code can still show the refusal.
        #
        return refuse(
            "candidate_invalid",
            f"the content of version {version} is not valid for this cluster today. "
            "No version was created and nothing was published.",
            65,
            {"diagnostics": result.diagnostics, "restored_version": version},
        )

    commit = commit_and_swap(
        repo,
        branch=branch,
        tree=target_tree,
        parent=head,
        message=version_message(MESSAGE.format(version=version), request.request_id, names),
    )
    #
    # A hard reset, unlike publishing's index refresh: a revert changes what the
    # configuration IS, so the files a person opens next must be the reverted
    # ones.
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
        index=index,
        metadata=metadata,
        group=group,
        change_owner=change_owner,
    )

    write_document(
        output,
        envelope(
            operation=REVERT_OPERATION,
            outcome="done",
            cluster=request.cluster,
            request_id=request.request_id,
            result=_result(
                changed=True,
                deployment_required=True,
                from_version=from_version,
                restored_version=version,
                new_version=metadata.version,
                commit=metadata.commit,
                published_at=metadata.timestamp,
                cluster=request.cluster,
                release=str(installed.release),
                already_current=installed.already_current,
            ),
        ),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
