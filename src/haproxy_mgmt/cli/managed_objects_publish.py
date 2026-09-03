"""Privileged publication of the proxy objects a person edited in the browser.

Deliberately not a mode on ``haproxy-network-publish`` and not a flag on
``haproxy-publish``.  Three writers touch this repository and each owns one
layer: the terminal command publishes the human-owned ``core/`` and ``manual/``
draft, the network helper replaces the application's one network document, and
this helper replaces proxy objects.  Sharing the tree, release and validation
machinery keeps a single history; keeping the entry points apart is what stops
any one of them from publishing another's layer with a mistyped parameter.

The network description is read from the committed base rather than accepted
from the caller.  It is the other helper's document, and a stale browser tab
that carried its own copy could undo an address change through this path.
"""

from __future__ import annotations

import json
import os
import re
import sys
from collections.abc import Callable, Mapping, Sequence
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
from haproxy_mgmt.cert_inventory import coverage
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
from haproxy_mgmt.proxy_model import MAX_MODEL_BYTES, NAME, NAME_RULE, name_refusal
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
    ConcurrentUpdate,
    PublishError,
    build_candidate_tree,
    commit_and_swap,
    read_tree_files,
    resolve_head,
)
from haproxy_mgmt.version_history import count_versions, restore_worktree, with_request_trailer

OPERATION = "objects_publish"
PARAMETERS = frozenset({"objects", "expected_head", "comment", "allow_certificate_mismatch"})
COMMIT_ID = re.compile(r"^[0-9a-f]{40}$")
CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
MAX_COMMENT_BYTES = 4096
#
# One publish carries what one person selected, not a bulk import.  The count
# and the whole-request ceiling exist so the refusal is a sentence about the
# request rather than a helper that spends a cluster lock parsing megabytes.
# `MAX_MODEL_BYTES` is the model's own limit, checked here so an oversized
# document is refused before it is written into a candidate tree.
#
MAX_OBJECTS = 16
MAX_REQUEST_BYTES = 256 * 1024
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
MESSAGE = "Update proxy objects"
HELPER = "/opt/haproxy-mgmt/current/bin/haproxy-objects-publish-helper"
SUDO = "/usr/bin/sudo"


def build_request(
    cluster: str,
    request_id: str,
    *,
    objects: Mapping[str, str | None],
    expected_head: str,
    comment: str,
    allow_certificate_mismatch: bool = False,
) -> str:
    """Build the exact bounded request the UI worker sends to this helper.

    `None` for an object asks for its removal.  The override defaults to off
    here as well as in the helper, for the reason B66 gives: a default every
    caller has to spell out is one a caller eventually gets wrong, and this one
    publishes a site under a certificate that does not answer for it.
    """

    return json.dumps(
        {
            "schema_version": 1,
            "operation": OPERATION,
            "cluster": cluster,
            "request_id": request_id,
            "parameters": {
                "objects": dict(objects),
                "expected_head": expected_head,
                "comment": comment,
                "allow_certificate_mismatch": allow_certificate_mismatch,
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


def _flag(parameters: Mapping[str, JsonValue], key: str) -> bool:
    """An override somebody had to ask for, absent by default."""

    value = parameters.get(key, False)
    if not isinstance(value, bool):
        raise HelperProtocolError(f"parameters.{key} must be true or false", exit_code=65)
    return value


def _objects(parameters: Mapping[str, JsonValue]) -> dict[str, bytes | None]:
    """Read the published snapshot: object name to document, or to removal.

    The names arrive from a job payload and are held to the model's own pattern
    here, before `managed_files` turns one into a path.  It is checked in both
    places on purpose: this one keeps a bad name out of the candidate builder,
    and the one there keeps the builder safe for any future caller.
    """

    raw = parameters.get("objects")
    if not isinstance(raw, dict) or not raw:
        raise HelperProtocolError("parameters.objects must be a non-empty object", exit_code=65)
    if len(raw) > MAX_OBJECTS:
        raise HelperProtocolError(
            f"parameters.objects carries more than {MAX_OBJECTS} objects", exit_code=65
        )

    objects: dict[str, bytes | None] = {}
    for name, document in raw.items():
        if not NAME.fullmatch(name):
            raise HelperProtocolError(
                f"{name} is not a usable object name - {name_refusal(name)}; use {NAME_RULE}",
                exit_code=65,
            )
        if document is None:
            objects[name] = None
            continue
        if not isinstance(document, str) or not document:
            raise HelperProtocolError(
                f"parameters.objects.{name} must be a document or null", exit_code=65
            )
        encoded = document.encode("utf-8")
        if len(encoded) > MAX_MODEL_BYTES:
            raise HelperProtocolError(f"parameters.objects.{name} is too long", exit_code=65)
        objects[name] = encoded
    return objects


def _parameters(
    parameters: Mapping[str, JsonValue],
) -> tuple[dict[str, bytes | None], str, str, bool]:
    objects = _objects(parameters)
    expected_head = _text(parameters, "expected_head", limit=40)
    if not COMMIT_ID.fullmatch(expected_head):
        raise HelperProtocolError("parameters.expected_head must be a full commit ID", exit_code=65)
    comment = _text(parameters, "comment", limit=MAX_COMMENT_BYTES)
    if CONTROL.search(comment):
        raise HelperProtocolError(
            "parameters.comment may not contain control characters", exit_code=65
        )
    return objects, expected_head, comment, _flag(parameters, "allow_certificate_mismatch")


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
    objects: Sequence[str],
    removed: Sequence[str],
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
        #
        # What this version did, named.  The caller knows what it sent, but the
        # audit record and the operator reading a job do not, and "version 26
        # changed shop and removed staging" is the sentence they need.
        #
        "objects": list(objects),
        "removed": list(removed),
    }


def _publish(
    *,
    request: HelperRequest,
    cluster: Any,
    objects: Mapping[str, bytes | None],
    expected_head: str,
    comment: str,
    allow_certificate_mismatch: bool,
    certificate_sans: Mapping[str, Sequence[str]] | None,
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
    if unsaved_changes(repo):
        return refuse(
            "dirty_worktree",
            "there are unsaved changes in the cluster worktree. Publish or discard them before "
            "publishing proxy objects.",
            BLOCKED_EXIT,
        )

    branch, head = resolve_head(repo)
    if head != expected_head:
        return refuse(
            "expected_target_changed",
            "the configuration changed since these objects were loaded. Refresh and try again.",
            BLOCKED_EXIT,
        )

    base_files = read_tree_files(repo, head)
    #
    # The other helper's document, carried through untouched.  Its absence is
    # not something this path may paper over with a default: the generated
    # layer would be rebuilt against invented addresses.
    #
    network_document = base_files.get(network_location())
    if network_document is None:
        return refuse(
            "network_missing",
            "this cluster has no network description yet. Publish one before publishing "
            "proxy objects.",
            BLOCKED_EXIT,
        )

    changed = sorted(name for name, document in objects.items() if document is not None)
    removed = sorted(name for name, document in objects.items() if document is None)

    #
    # Everything the managed layer can refuse arrives here as one exception:
    # a document the model rejects, a removal of an object this version does
    # not have, a hostname another object already owns, a certificate that does
    # not answer for a name.  They are answers about the objects somebody
    # edited, so they are reported as that rather than as a bad payload - the
    # editor has a field to attach the sentence to.
    #
    try:
        managed = managed_files(
            base_files,
            network_document=network_document,
            cluster=cluster,
            objects=objects,
            certificate_sans=certificate_sans,
            allow_certificate_mismatch=allow_certificate_mismatch,
        )
    except ConfigError as exc:
        return refuse("objects_invalid", str(exc), 65)
    snapshot = build_candidate_tree(repo, head, managed, prefixes=(MANAGED_PREFIX,))
    artifact = build_node_artifact(read_tree_files(repo, snapshot.tree))
    version = count_versions(repo, head)

    if snapshot.unchanged:
        installed = install_release(
            cluster.publish_path,
            node_path=cluster.node_path,
            artifact=artifact,
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
                    objects=changed,
                    removed=removed,
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
            "these objects did not produce a valid HAProxy candidate. Nothing was published.",
            65,
            {"diagnostics": validation.diagnostics},
        )

    commit = commit_and_swap(
        repo,
        branch=branch,
        tree=snapshot.tree,
        parent=head,
        message=with_request_trailer(f"{MESSAGE}: {comment}", request.request_id),
    )
    # The worktree was verified clean immediately above, and everything this
    # commit touched is application-owned, so writing the committed result out
    # cannot erase a human draft.  Leaving it behind would instead make the
    # next publish read this version's own files as an unrelated dirty change.
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
                objects=changed,
                removed=removed,
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
            raise HelperProtocolError("objects publish helper must run as root", exit_code=77)
        request = read_helper_request(
            input_stream or sys.stdin.buffer,
            expected_operation=OPERATION,
            allowed_parameter_keys=PARAMETERS,
            max_bytes=MAX_REQUEST_BYTES,
        )
    except HelperProtocolError as exc:
        errors.write(f"ERROR: {exc}\n")
        return exc.exit_code

    refuse = Refuse(request, output, errors)
    try:
        objects, expected_head, comment, allow_certificate_mismatch = _parameters(
            request.parameters
        )
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
        with hold(request.cluster, operation=OPERATION, root=lock_root):
            return _publish(
                request=request,
                cluster=cluster,
                objects=objects,
                expected_head=expected_head,
                comment=comment,
                allow_certificate_mismatch=allow_certificate_mismatch,
                #
                # Read here rather than inside the publishing module, which
                # takes a Git tree and a cluster and opens nothing itself
                # (B66). No certificate root configured means the question
                # cannot be answered, and None says exactly that.
                #
                certificate_sans=(
                    coverage(policy.certificate_root, cluster)
                    if policy.certificate_root is not None
                    else None
                ),
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
