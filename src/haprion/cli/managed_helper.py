"""The publishing loop behind the helper that replaces part of ``managed/``.

The application-owned layer - the network description, the cluster's settings
and the proxy objects - is written by one helper since B257, the one that
publishes saved changes. Until then three helpers wrote it, one document each,
and what they did with a document once it was read lived here once, so a fix
was a fix to all three (Fas 15's review, F3). The loop stays apart from the
helper for the same reason it was written: the dirty worktree, the head the
request was built on, the retry that finds its own version, the sandbox, the
TLS defaults, the commit and the release are decided here, and a helper says
only which words its refusals use, how its parameters are read, and what it
puts into ``managed/``.
"""

from __future__ import annotations

import os
import re
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO, TextIO

from haprion import advanced, exit_codes, tls_policy
from haprion.candidate_validation import (
    VALIDATION_CERTIFICATE,
    SandboxValidator,
    candidate_from_files,
    prepare_run_root,
    read_validation_certificate,
    validate_candidate,
)
from haprion.cluster_lock import LockBusy, hold
from haprion.config import Cluster, ConfigError, PathPolicy, load_policy, load_runtime_config
from haprion.envelope import envelope, failure
from haprion.git_command import GitError
from haprion.helper_protocol import (
    MAX_REQUEST_BYTES,
    HelperProtocolError,
    HelperRequest,
    JsonValue,
    read_helper_request,
    require_no_arguments,
    write_document,
)
from haprion.managed_network import location as network_location
from haprion.managed_publish import GENERATED_PREFIX, MANAGED_PREFIX
from haprion.release_install import ChangeOwner, InstallError, install_release
from haprion.release_layout import (
    LayoutError,
    ReleaseMetadata,
    build_node_artifact,
    build_release_index,
)
from haprion.repo_health import unsaved_changes
from haprion.repo_snapshot import (
    ConcurrentUpdate,
    PublishError,
    build_candidate_tree,
    commit_and_swap,
    committed_snapshot,
    read_tree_files,
    resolve_head,
)
from haprion.status_collect import read_target
from haprion.version_history import (
    comment_problem,
    count_versions,
    recorded_on,
    request_names,
    restore_worktree,
    version_message,
)

COMMIT_ID = re.compile(r"^[0-9a-f]{40}$")
MAX_COMMENT_BYTES = 4096
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
SUDO = "/usr/bin/sudo"


@dataclass(frozen=True, slots=True)
class Words:
    """What one helper is called, and how its refusals read.

    Kept per helper because the sentence is what the person reads on the page
    they published from: "these objects were loaded" on the objects page, "this
    network page was read" on the network page.
    """

    operation: str
    #
    # The version's subject, before the comment.
    #
    message: str
    #
    # "helper must run as root" is prefixed with this.
    #
    helper: str
    #
    # Completes "Publish or discard them before ...".
    #
    doing: str
    moved: str
    invalid: str


class Refusal(Exception):
    """An answer about the document itself, raised while it is applied."""

    def __init__(self, code: str, message: str, exit_code: int):
        super().__init__(message)
        self.code = code
        self.exit_code = exit_code


@dataclass(frozen=True, slots=True)
class Change:
    """One request, read: what it is fenced on, and what it does to ``managed/``.

    `apply` takes the committed base's files and returns the complete managed
    snapshot, or raises `Refusal`. It is not called on a retry: the request's
    own version already holds what it asked for, and asking again is not always
    a no-op - a removal asked twice is a removal of something that is gone.

    `named` is added to the result, for a helper whose version is worth naming
    in more words than a hash.
    """

    expected_head: str
    comment: str
    apply: Callable[[Mapping[str, bytes]], Mapping[str, bytes]]
    named: Mapping[str, Any] = field(default_factory=dict)


class Refuse:
    """Write the one valid failure envelope once the request is known."""

    def __init__(self, operation: str, request: HelperRequest, output: TextIO, errors: TextIO):
        self.operation = operation
        self.request = request
        self.output = output
        self.errors = errors

    def __call__(
        self, code: str, message: str, exit_code: int, details: dict[str, Any] | None = None
    ) -> int:
        self.errors.write(f"ERROR: [{code}] {message}\n")
        return write_document(
            self.output,
            failure(
                operation=self.operation,
                cluster=self.request.cluster,
                request_id=self.request.request_id,
                code=code,
                message=message,
                exit_code=exit_code,
                details=details,
            ),
            exit_code,
        )


def text(parameters: Mapping[str, JsonValue], key: str, *, limit: int) -> str:
    value = parameters.get(key)
    if not isinstance(value, str) or not value:
        raise HelperProtocolError(
            f"parameters.{key} must be a non-empty string", exit_code=exit_codes.REFUSED
        )
    if len(value.encode("utf-8")) > limit:
        raise HelperProtocolError(f"parameters.{key} is too long", exit_code=exit_codes.REFUSED)
    return value


def flag(parameters: Mapping[str, JsonValue], key: str) -> bool:
    """An override somebody had to ask for, absent by default.

    Only a real boolean. A string "false" arriving as true is exactly how an
    override turns itself on without anybody deciding to.
    """

    value = parameters.get(key, False)
    if not isinstance(value, bool):
        raise HelperProtocolError(
            f"parameters.{key} must be true or false", exit_code=exit_codes.REFUSED
        )
    return value


def fence(parameters: Mapping[str, JsonValue]) -> tuple[str, str]:
    """The head the request was built on, and the comment its version carries."""

    expected_head = text(parameters, "expected_head", limit=40)
    if not COMMIT_ID.fullmatch(expected_head):
        raise HelperProtocolError(
            "parameters.expected_head must be a full commit ID", exit_code=exit_codes.REFUSED
        )
    comment = text(parameters, "comment", limit=MAX_COMMENT_BYTES)
    problem = comment_problem(comment)
    if problem:
        raise HelperProtocolError(f"parameters.comment {problem}", exit_code=exit_codes.REFUSED)
    return expected_head, comment


def _only_managed(porcelain: str) -> bool:
    """Whether every path `git status --porcelain` names is the application's own layer."""

    paths = [line[3:].split(" -> ")[-1] for line in porcelain.splitlines() if line.strip()]
    return bool(paths) and all(path.startswith(MANAGED_PREFIX) for path in paths)


def network_of(base_files: Mapping[str, bytes], *, doing: str) -> bytes:
    """The committed network description, carried through untouched.

    Its absence is not something another helper may paper over with a default:
    the generated layer would be rebuilt against invented addresses.
    """

    document = base_files.get(network_location())
    if document is None:
        raise Refusal(
            "network_missing",
            f"this cluster has no network description yet. Publish one before {doing}.",
            exit_codes.BLOCKED,
        )
    return document


def _result(
    *,
    cluster: str,
    changed: bool,
    version: int,
    commit: str,
    published_at: str | None,
    comment: str,
    release: str,
    already_current: bool,
    named: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "changed": changed,
        "version": version,
        "hash": commit,
        "published_at": published_at,
        "comment": comment,
        #
        # Always: a managed publish records a version and a release, and only a
        # deploy takes either to the nodes.
        #
        "deployment_required": True,
        "next_command": f"haprion-deploy -c {cluster}",
        "release": release,
        "already_current": already_current,
        **named,
    }


def _publish(
    *,
    words: Words,
    request: HelperRequest,
    names: tuple[str, str],
    cluster: Cluster,
    change: Change,
    output: TextIO,
    run_root: Path,
    require_secure: bool,
    validator: SandboxValidator,
    group: str,
    change_owner: ChangeOwner,
    clock: Callable[[], datetime],
    refuse: Refuse,
) -> int:
    repo = cluster.config_path
    branch, head = resolve_head(repo)
    #
    # Moved by this request's own version is not moved: that is a run which
    # committed and stopped before its release was installed, retried. It takes
    # the unchanged path with nothing applied again.
    #
    retry = head != change.expected_head and recorded_on(
        repo, head, base=change.expected_head, request_id=request.request_id
    )
    dirty = unsaved_changes(repo)
    if dirty and retry and _only_managed(dirty):
        #
        # The run stopped between its commit and writing the worktree out, so
        # the application's own layer still shows the version before. Written
        # out now, as that run would have; anything a person changed is
        # outside managed/ and still refuses (review 26-10-24, 01-03).
        #
        restore_worktree(repo, head)
        dirty = unsaved_changes(repo)
    if dirty:
        return refuse(
            "dirty_worktree",
            "there are unsaved changes in the cluster worktree. Publish or discard them before "
            f"{words.doing}.",
            exit_codes.BLOCKED,
        )
    if head != change.expected_head and not retry:
        return refuse("expected_target_changed", words.moved, exit_codes.BLOCKED)

    if retry:
        snapshot = committed_snapshot(repo, head)
    else:
        try:
            managed = change.apply(read_tree_files(repo, head))
        except Refusal as exc:
            return refuse(exc.code, str(exc), exc.exit_code)
        snapshot = build_candidate_tree(repo, head, managed, prefixes=(MANAGED_PREFIX,))
    published_files = read_tree_files(repo, snapshot.tree)
    artifact = build_node_artifact(published_files)
    index = build_release_index(published_files)

    #
    # Checked on the bytes about to be published, so a refusal describes what
    # would have gone out. On the unchanged path because an unchanged tree is how
    # a retry arrives, and it must not install what the first attempt refused;
    # on a change after the sandbox, deliberately - a `core/haproxy.cfg` can be
    # both stale and syntactically broken, and the broken half is the one that
    # stops HAProxy from starting, so reporting the cipher list first would hide
    # it behind the smaller problem. And before the commit, so a refusal leaves
    # no version behind that a retry would then find unchanged and publish
    # without asking again.
    #
    def stale() -> str | None:
        return tls_policy.core_defaults_problem(
            published_files["core/haproxy.cfg"],
            cluster=request.cluster,
            config_path=str(cluster.config_path),
        )

    #
    # Before the sandbox, where HAProxy would refuse the same release in words
    # that name neither the file nor the line (`stick_counters_problem`).
    #
    short = tls_policy.stick_counters_problem(
        published_files, cluster=request.cluster, config_path=str(cluster.config_path)
    )
    if short is not None:
        return refuse("stick_counters_short", short, exit_codes.BLOCKED)

    def invalid() -> int | None:
        """The sandbox's verdict on the artifact, as a refusal; None when it passes."""

        certificate = read_validation_certificate(
            cluster.validation_certs / VALIDATION_CERTIFICATE, require_secure=require_secure
        )
        prepare_run_root(run_root, require_secure=require_secure)
        validation = validate_candidate(
            candidate_from_files(artifact),
            run_root=run_root,
            certificate_ids=cluster.certificate_ids,
            authority_ids=cluster.authority_ids,
            validation_certificate=certificate,
            request_id=request.request_id,
            validator=validator,
        )
        #
        # `haproxy -c` names a generated file and a line; a line that came from
        # an object's advanced config is said again as that object's line, so
        # the person who pasted it can find it. The generated files carry the
        # mapping themselves (`advanced.block`).
        #
        generated = {
            path.removeprefix(GENERATED_PREFIX): content.decode("utf-8", "replace")
            for path, content in published_files.items()
            if path.startswith(GENERATED_PREFIX)
        }
        diagnostics, ignored = advanced.annotate(validation.diagnostics, generated)
        if not validation.valid:
            return refuse(
                "candidate_invalid", words.invalid, exit_codes.REFUSED, {"diagnostics": diagnostics}
            )
        if ignored:
            #
            # Valid, and still refused: a warning on a pasted line is HAProxy
            # saying it will ignore that line, and `-c` passes it. Publishing
            # would promise something the configuration does not do (B218).
            # Only here, where the text is published - a revert or a publish of
            # the core files is not the place to refuse an earlier text.
            #
            return refuse(
                "advanced_ignored",
                "HAProxy would ignore a line of an object's advanced config: "
                + ignored[0].split("parsing ", 1)[-1][:1500],
                exit_codes.REFUSED,
                {"diagnostics": diagnostics},
            )
        return None

    if snapshot.unchanged:
        #
        # A version whose release was never installed has never been checked
        # either: a new cluster's first version is committed when the cluster
        # is made and published after (B318, 26-10-16). Checked here before it
        # goes out; a retry of a version that was already checked and
        # installed is not checked again.
        #
        published = read_target(cluster.publish_path, cluster.node_path)
        if published is None or published.hash != head:
            refused = invalid()
            if refused is not None:
                return refused
        problem = stale()
        if problem is not None:
            return refuse("tls_defaults_stale", problem, exit_codes.BLOCKED)
        metadata = ReleaseMetadata(
            cluster=request.cluster,
            version=count_versions(repo, head),
            commit=head,
            timestamp=clock().strftime(TIMESTAMP_FORMAT),
        )
        published_at = None
    else:
        refused = invalid()
        if refused is not None:
            return refused
        problem = stale()
        if problem is not None:
            return refuse("tls_defaults_stale", problem, exit_codes.BLOCKED)

        commit = commit_and_swap(
            repo,
            branch=branch,
            tree=snapshot.tree,
            parent=head,
            message=version_message(
                f"{words.message}: {change.comment}", request.request_id, names
            ),
        )
        # The worktree was verified clean immediately above, and everything this
        # commit touched is application-owned, so writing the committed result out
        # cannot erase a human draft. Leaving it behind would instead make the
        # next publish read this version's own files as an unrelated dirty change.
        restore_worktree(repo, commit)
        metadata = ReleaseMetadata(
            cluster=request.cluster,
            version=count_versions(repo, commit),
            commit=commit,
            timestamp=clock().strftime(TIMESTAMP_FORMAT),
        )
        published_at = metadata.timestamp

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
            operation=words.operation,
            outcome="done",
            cluster=request.cluster,
            request_id=request.request_id,
            result=_result(
                cluster=request.cluster,
                changed=not snapshot.unchanged,
                version=metadata.version,
                commit=metadata.commit,
                published_at=published_at,
                comment=change.comment,
                release=str(installed.release),
                already_current=installed.already_current,
                named=change.named,
            ),
        ),
        0,
    )


type Reader = Callable[[Mapping[str, JsonValue]], Callable[[PathPolicy, Cluster], Change]]


def run(
    words: Words,
    read: Reader,
    *,
    parameters: frozenset[str],
    max_request_bytes: int = MAX_REQUEST_BYTES,
    argv: list[str] | None,
    policy_path: Path,
    run_root: Path,
    input_stream: BinaryIO | None,
    output_stream: TextIO | None,
    error_stream: TextIO | None,
    require_secure: bool,
    require_root: bool,
    lock_root: Path,
    validator: SandboxValidator,
    group: str,
    change_owner: ChangeOwner,
    now: Callable[[], datetime] | None,
) -> int:
    """A helper's `main`, from its words and its reader.

    `read` is called on the request's parameters before anything else is
    opened, so a malformed request is refused as that and not as whatever the
    policy or the cluster said first. It returns what builds the `Change` once
    the policy and the cluster are known - the helpers that ask whether a
    certificate answers for a name need both - and that is called under the
    cluster's lock.
    """

    output = output_stream or sys.stdout
    errors = error_stream or sys.stderr
    arguments = sys.argv[1:] if argv is None else argv
    try:
        require_no_arguments(arguments)
        if require_root and os.geteuid() != 0:
            raise HelperProtocolError(
                f"{words.helper} helper must run as root", exit_code=exit_codes.NOT_ROOT
            )
        request = read_helper_request(
            input_stream or sys.stdin.buffer,
            expected_operation=words.operation,
            allowed_parameter_keys=parameters,
            max_bytes=max_request_bytes,
        )
    except HelperProtocolError as exc:
        errors.write(f"ERROR: {exc}\n")
        return exc.exit_code

    refuse = Refuse(words.operation, request, output, errors)
    try:
        build = read(request.parameters)
        policy = load_policy(policy_path, require_secure=require_secure)
        names = request_names(request.parameters, interface_account=policy.interface_account)
        cluster = load_runtime_config(policy, require_secure=require_secure).cluster(
            request.cluster
        )
    except HelperProtocolError as exc:
        return refuse("bad_input", str(exc), exc.exit_code)
    except ConfigError as exc:
        return refuse(
            "bad_input" if exc.exit_code == exit_codes.USAGE else "dependency_unavailable",
            str(exc),
            exc.exit_code,
        )

    try:
        with hold(request.cluster, operation=words.operation, root=lock_root):
            #
            # Built under the lock, where the certificate inventory it may read
            # describes the same moment the publish does.
            #
            change = build(policy, cluster)
            return _publish(
                words=words,
                request=request,
                names=names,
                cluster=cluster,
                change=change,
                output=output,
                run_root=run_root,
                require_secure=require_secure,
                validator=validator,
                group=group,
                change_owner=change_owner,
                clock=now or (lambda: datetime.now(UTC)),
                refuse=refuse,
            )
    except LockBusy as exc:
        return refuse("operation_locked", str(exc), exc.exit_code)
    except ConcurrentUpdate as exc:
        return refuse("expected_target_changed", str(exc), exc.exit_code)
    except (InstallError, LayoutError, PublishError) as exc:
        return refuse("publish_incomplete", str(exc), exc.exit_code)
    except ConfigError as exc:
        return refuse("bad_input", str(exc), exc.exit_code)
    except GitError as exc:
        return refuse("internal_error", str(exc), exc.exit_code)
