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
from collections.abc import Callable, Mapping
from datetime import datetime
from pathlib import Path
from typing import BinaryIO, TextIO

from haproxy_mgmt.candidate_validation import (
    DEFAULT_RUN_ROOT,
    SandboxValidator,
    validate_in_sandbox,
)
from haproxy_mgmt.cert_inventory import coverage
from haproxy_mgmt.cli import managed_helper
from haproxy_mgmt.cli.managed_helper import (
    SUDO,
    Change,
    Refusal,
    Words,
    fence,
    flag,
    network_of,
)
from haproxy_mgmt.cluster_lock import DEFAULT_LOCK_ROOT
from haproxy_mgmt.config import DEFAULT_POLICY_PATH, Cluster, ConfigError, PathPolicy
from haproxy_mgmt.helper_protocol import HelperProtocolError, JsonValue
from haproxy_mgmt.managed_publish import managed_files
from haproxy_mgmt.proxy_model import MAX_MODEL_BYTES, NAME, NAME_RULE, name_refusal
from haproxy_mgmt.release_install import PUBLISH_GROUP, ChangeOwner, default_change_owner

OPERATION = "objects_publish"
PARAMETERS = frozenset(
    {"objects", "expected_head", "comment", "allow_certificate_mismatch", "requested_by"}
)
#
# One publish carries what one person selected, not a bulk import.  The count
# and the whole-request ceiling exist so the refusal is a sentence about the
# request rather than a helper that spends a cluster lock parsing megabytes.
# `MAX_MODEL_BYTES` is the model's own limit, checked here so an oversized
# document is refused before it is written into a candidate tree.
#
MAX_OBJECTS = 16
MAX_REQUEST_BYTES = 256 * 1024
MESSAGE = "Update proxy objects"
HELPER = "/opt/haproxy-mgmt/current/bin/haproxy-objects-publish-helper"
WORDS = Words(
    operation=OPERATION,
    message=MESSAGE,
    helper="objects publish",
    doing="publishing proxy objects",
    moved="the configuration changed since these objects were loaded. Refresh and try again.",
    invalid="these objects did not produce a valid HAProxy candidate. Nothing was published.",
)
__all__ = ["HELPER", "MAX_OBJECTS", "OPERATION", "SUDO", "build_request", "main"]


def build_request(
    cluster: str,
    request_id: str,
    *,
    objects: Mapping[str, str | None],
    expected_head: str,
    comment: str,
    allow_certificate_mismatch: bool = False,
    requested_by: str | None = None,
) -> str:
    """Build the exact bounded request the UI worker sends to this helper.

    `None` for an object asks for its removal.  The override defaults to off
    here as well as in the helper, for the reason B66 gives: a default every
    caller has to spell out is one a caller eventually gets wrong, and this one
    publishes a site under a certificate that does not answer for it.

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
                "objects": dict(objects),
                "expected_head": expected_head,
                "comment": comment,
                "allow_certificate_mismatch": allow_certificate_mismatch,
                **({} if requested_by is None else {"requested_by": requested_by}),
            },
        },
        separators=(",", ":"),
    )


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


def _read(parameters: Mapping[str, JsonValue]) -> Callable[[PathPolicy, Cluster], Change]:
    objects = _objects(parameters)
    expected_head, comment = fence(parameters)
    allow_certificate_mismatch = flag(parameters, "allow_certificate_mismatch")

    def change(policy: PathPolicy, cluster: Cluster) -> Change:
        #
        # Read here rather than inside the publishing module, which takes a Git
        # tree and a cluster and opens nothing itself (B66). No certificate root
        # configured means the question cannot be answered, and None says
        # exactly that.
        #
        certificate_sans = (
            coverage(policy.certificate_root, cluster)
            if policy.certificate_root is not None
            else None
        )

        def apply(base_files: Mapping[str, bytes]) -> Mapping[str, bytes]:
            network_document = network_of(base_files, doing="publishing proxy objects")
            #
            # Everything the managed layer can refuse arrives here as one
            # exception: a document the model rejects, a removal of an object
            # this version does not have, a hostname another object already
            # owns, a certificate that does not answer for a name.  They are
            # answers about the objects somebody edited, so they are reported
            # as that rather than as a bad payload - the editor has a field to
            # attach the sentence to.
            #
            try:
                return managed_files(
                    base_files,
                    network_document=network_document,
                    cluster=cluster,
                    objects=objects,
                    certificate_sans=certificate_sans,
                    allow_certificate_mismatch=allow_certificate_mismatch,
                )
            except ConfigError as exc:
                raise Refusal("objects_invalid", str(exc), 65) from exc

        return Change(
            expected_head=expected_head,
            comment=comment,
            apply=apply,
            #
            # What this version did, named.  The caller knows what it sent, but
            # the audit record and the operator reading a job do not, and
            # "version 26 changed shop and removed staging" is the sentence they
            # need.
            #
            named={
                "objects": sorted(
                    name for name, document in objects.items() if document is not None
                ),
                "removed": sorted(name for name, document in objects.items() if document is None),
            },
        )

    return change


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
    return managed_helper.run(
        WORDS,
        _read,
        parameters=PARAMETERS,
        max_request_bytes=MAX_REQUEST_BYTES,
        argv=argv,
        policy_path=policy_path,
        run_root=run_root,
        input_stream=input_stream,
        output_stream=output_stream,
        error_stream=error_stream,
        require_secure=require_secure,
        require_root=require_root,
        lock_root=lock_root,
        validator=validator,
        group=group,
        change_owner=change_owner,
        now=now,
    )


if __name__ == "__main__":
    raise SystemExit(main())
