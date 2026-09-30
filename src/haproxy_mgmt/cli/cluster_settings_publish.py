"""Privileged publication of the cluster's own settings (Fas 15, B209).

`managed/cluster.yaml`: where the traffic log is sent and whether the metrics
exporter listens. The same shape as the network helper - one fixed document,
the managed layer rebuilt around it in an isolated index, validated in the
sandbox, recorded as a version - and a separate operation, so a change of log
target is a version of its own that says so.
"""

from __future__ import annotations

import json
import os
import re
import sys
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO, TextIO

from haproxy_mgmt import cluster_settings, tls_policy
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
from haproxy_mgmt.config import DEFAULT_POLICY_PATH, ConfigError, load_policy, load_runtime_config
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
from haproxy_mgmt.managed_network import location as network_location
from haproxy_mgmt.managed_publish import MANAGED_PREFIX, managed_files
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
    build_candidate_tree,
    commit_and_swap,
    committed_snapshot,
    read_tree_files,
    resolve_head,
)
from haproxy_mgmt.version_history import (
    count_versions,
    recorded_on,
    request_names,
    restore_worktree,
    version_message,
)

OPERATION = "cluster_settings_publish"
PARAMETERS = frozenset({"settings", "expected_head", "comment", "requested_by"})
COMMIT_ID = re.compile(r"^[0-9a-f]{40}$")
CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
MAX_COMMENT_BYTES = 4096
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
MESSAGE = "Update cluster settings"
HELPER = "/opt/haproxy-mgmt/current/bin/haproxy-cluster-settings-publish-helper"
SUDO = "/usr/bin/sudo"


def build_request(
    cluster: str,
    request_id: str,
    *,
    settings: str,
    expected_head: str,
    comment: str,
    requested_by: str | None = None,
) -> str:
    """Build the exact bounded request the UI worker and the CLI send to this helper.

    `requested_by` names the person the interface's worker acts for (B207). It
    is left out rather than sent empty when nobody is named, and the helper
    then records the account sudo ran it as.
    """

    return json.dumps(
        {
            "schema_version": 1,
            "operation": OPERATION,
            "cluster": cluster,
            "request_id": request_id,
            "parameters": {
                "settings": settings,
                "expected_head": expected_head,
                "comment": comment,
                **({} if requested_by is None else {"requested_by": requested_by}),
            },
        },
        separators=(",", ":"),
    )


class Refuse:
    """Write the one valid failure envelope once the request is known."""

    def __init__(self, request: HelperRequest, output: TextIO, errors: TextIO):
        self.request = request
        self.output = output
        self.errors = errors

    def __call__(
        self, code: str, message: str, exit_code: int, details: dict[str, Any] | None = None
    ) -> int:
        self.errors.write(f"ERROR: [{code}] {message}\n")
        write_document(
            self.output,
            failure(
                operation=OPERATION,
                cluster=self.request.cluster,
                request_id=self.request.request_id,
                code=code,
                message=message,
                exit_code=exit_code,
                details=details,
            ),
        )
        return exit_code


def _text(parameters: Mapping[str, JsonValue], key: str, *, limit: int) -> str:
    value = parameters.get(key)
    if not isinstance(value, str) or not value:
        raise HelperProtocolError(f"parameters.{key} must be a non-empty string", exit_code=65)
    if len(value.encode("utf-8")) > limit:
        raise HelperProtocolError(f"parameters.{key} is too long", exit_code=65)
    return value


def _parameters(parameters: Mapping[str, JsonValue]) -> tuple[bytes, str, str]:
    settings = _text(parameters, "settings", limit=cluster_settings.MAX_BYTES).encode("utf-8")
    expected_head = _text(parameters, "expected_head", limit=40)
    if not COMMIT_ID.fullmatch(expected_head):
        raise HelperProtocolError("parameters.expected_head must be a full commit ID", exit_code=65)
    comment = _text(parameters, "comment", limit=MAX_COMMENT_BYTES)
    if CONTROL.search(comment):
        raise HelperProtocolError(
            "parameters.comment may not contain control characters", exit_code=65
        )
    return settings, expected_head, comment


def _result(
    *,
    cluster: str,
    changed: bool,
    deployment_required: bool,
    version: int,
    commit: str,
    published_at: str | None,
    comment: str,
    release: str,
    already_current: bool,
) -> dict[str, Any]:
    return {
        "changed": changed,
        "version": version,
        "hash": commit,
        "published_at": published_at,
        "comment": comment,
        "deployment_required": deployment_required,
        "next_command": f"haproxy-deploy -c {cluster}" if deployment_required else None,
        "release": release,
        "already_current": already_current,
    }


def _publish(
    *,
    request: HelperRequest,
    names: tuple[str, str],
    cluster: Any,
    settings: bytes,
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
    repo = cluster.config_path
    dirty = unsaved_changes(repo)
    if dirty:
        return refuse(
            "dirty_worktree",
            "there are unsaved changes in the cluster worktree. Publish or discard them before "
            "changing the cluster settings.",
            BLOCKED_EXIT,
        )

    branch, head = resolve_head(repo)
    #
    # Moved by this request's own version is not moved: that is a run which
    # committed and stopped before its release was installed, retried. It takes
    # the unchanged path with nothing applied again.
    #
    retry = head != expected_head and recorded_on(
        repo, head, base=expected_head, request_id=request.request_id
    )
    if head != expected_head and not retry:
        return refuse(
            "expected_target_changed",
            "the configuration changed since these settings were read. Refresh them before "
            "trying again.",
            BLOCKED_EXIT,
        )

    base_files = read_tree_files(repo, head)
    #
    # The network helper's document, carried through untouched; without one
    # the generated layer would be rebuilt against invented addresses.
    #
    network_document = base_files.get(network_location())
    if network_document is None:
        return refuse(
            "network_missing",
            "this cluster has no network description yet. Publish one before changing its "
            "settings.",
            BLOCKED_EXIT,
        )

    if retry:
        snapshot = committed_snapshot(repo, head)
    else:
        try:
            #
            # Stored in its canonical form, so two ways of writing the same
            # settings are one version and a diff shows only what changed.
            #
            canonical = cluster_settings.dump_document(cluster_settings.load_document(settings))
            managed = managed_files(
                base_files,
                network_document=network_document,
                cluster=cluster,
                #
                # Certificate coverage is not asked again. Nothing here changes an
                # object or a certificate, and an object published with the
                # mismatch override would otherwise block every settings change.
                #
                certificate_sans=None,
                settings_document=canonical,
            )
        except ConfigError as exc:
            return refuse("settings_invalid", str(exc), 65)
        snapshot = build_candidate_tree(repo, head, managed, prefixes=(MANAGED_PREFIX,))
    published_files = read_tree_files(repo, snapshot.tree)
    artifact = build_node_artifact(published_files)
    index = build_release_index(published_files)
    version = count_versions(repo, head)

    if snapshot.unchanged:
        #
        # The same policy as a change: an unchanged tree is how a retry
        # arrives, and it must not install what the first attempt refused.
        #
        stale = tls_policy.core_defaults_problem(
            published_files["core/haproxy.cfg"],
            cluster=request.cluster,
            config_path=str(cluster.config_path),
        )
        if stale is not None:
            return refuse("tls_defaults_stale", stale, BLOCKED_EXIT)
        installed = install_release(
            cluster.publish_path,
            node_path=cluster.node_path,
            artifact=artifact,
            index=index,
            metadata=ReleaseMetadata(
                cluster=request.cluster,
                version=version,
                commit=head,
                timestamp=clock().strftime(TIMESTAMP_FORMAT),
            ),
            group=group,
            change_owner=change_owner,
        )
        write_document(
            output,
            envelope(
                operation=OPERATION,
                outcome="done",
                cluster=request.cluster,
                request_id=request.request_id,
                result=_result(
                    cluster=request.cluster,
                    changed=False,
                    deployment_required=True,
                    version=version,
                    commit=head,
                    published_at=None,
                    comment=comment,
                    release=str(installed.release),
                    already_current=installed.already_current,
                ),
            ),
        )
        return 0

    certificate = read_validation_certificate(
        cluster.validation_certs / VALIDATION_CERTIFICATE, require_secure=require_secure
    )
    prepare_run_root(run_root, require_secure=require_secure)
    validation = validate_candidate(
        candidate_from_files(artifact),
        run_root=run_root,
        certificate_ids=cluster.certificate_ids,
        validation_certificate=certificate,
        request_id=request.request_id,
        validator=validator,
    )
    if not validation.valid:
        return refuse(
            "candidate_invalid",
            "the settings did not produce a valid HAProxy candidate. Nothing was published.",
            65,
            {"diagnostics": validation.diagnostics},
        )

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
        return refuse("tls_defaults_stale", stale, BLOCKED_EXIT)

    commit = commit_and_swap(
        repo,
        branch=branch,
        tree=snapshot.tree,
        parent=head,
        message=version_message(f"{MESSAGE}: {comment}", request.request_id, names),
    )
    # The worktree was verified clean immediately above.  Its managed document
    # is application-owned, so making it show the committed result cannot erase
    # a human draft and prevents the next managed publish seeing its own prior
    # version as an unrelated dirty change.
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
            operation=OPERATION,
            outcome="done",
            cluster=request.cluster,
            request_id=request.request_id,
            result=_result(
                cluster=request.cluster,
                changed=True,
                deployment_required=True,
                version=metadata.version,
                commit=metadata.commit,
                published_at=metadata.timestamp,
                comment=comment,
                release=str(installed.release),
                already_current=installed.already_current,
            ),
        ),
    )
    return 0


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
    arguments = sys.argv[1:] if argv is None else argv
    try:
        require_no_arguments(arguments)
        if require_root and os.geteuid() != 0:
            raise HelperProtocolError(
                "cluster settings publish helper must run as root", exit_code=77
            )
        request = read_helper_request(
            input_stream or sys.stdin.buffer,
            expected_operation=OPERATION,
            allowed_parameter_keys=PARAMETERS,
        )
    except HelperProtocolError as exc:
        errors.write(f"ERROR: {exc}\n")
        return exc.exit_code

    refuse = Refuse(request, output, errors)
    try:
        settings, expected_head, comment = _parameters(request.parameters)
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
        with hold(request.cluster, operation=OPERATION, root=lock_root):
            return _publish(
                request=request,
                names=names,
                cluster=cluster,
                settings=settings,
                expected_head=expected_head,
                comment=comment,
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


if __name__ == "__main__":
    raise SystemExit(main())
