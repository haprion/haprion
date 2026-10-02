"""Privileged publication of the application's network description.

This is intentionally not an extension of ``haproxy-publish``.  The terminal
command publishes the human-owned ``core/`` and ``manual/`` draft; this helper
accepts one fixed application-owned document and replaces only ``managed/`` in
an isolated Git index.  Sharing the release and validation machinery keeps one
history, while keeping the two writers unable to publish one another's layer.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from datetime import datetime
from pathlib import Path
from typing import BinaryIO, TextIO

from haproxy_mgmt import crs, geo
from haproxy_mgmt.candidate_validation import (
    DEFAULT_RUN_ROOT,
    SandboxValidator,
    validate_in_sandbox,
)
from haproxy_mgmt.cert_inventory import coverage
from haproxy_mgmt.cli import managed_helper
from haproxy_mgmt.cli.managed_helper import SUDO, Change, Words, fence, flag, text
from haproxy_mgmt.cluster_lock import DEFAULT_LOCK_ROOT
from haproxy_mgmt.config import DEFAULT_POLICY_PATH, Cluster, PathPolicy
from haproxy_mgmt.helper_protocol import JsonValue
from haproxy_mgmt.managed_network import MAX_NETWORK_BYTES
from haproxy_mgmt.managed_publish import managed_files
from haproxy_mgmt.release_install import PUBLISH_GROUP, ChangeOwner, default_change_owner

OPERATION = "network_publish"
PARAMETERS = frozenset(
    {"network", "expected_head", "comment", "allow_certificate_mismatch", "requested_by"}
)
MESSAGE = "Update network description"
HELPER = "/opt/haproxy-mgmt/current/bin/haproxy-network-publish-helper"
WORDS = Words(
    operation=OPERATION,
    message=MESSAGE,
    helper="network publish",
    doing="changing the network description",
    moved="the configuration changed since this network page was read. Refresh it before "
    "trying again.",
    invalid="the network change did not produce a valid HAProxy candidate. Nothing was published.",
)
__all__ = ["HELPER", "OPERATION", "SUDO", "build_request", "main"]


def build_request(
    cluster: str,
    request_id: str,
    *,
    network: str,
    expected_head: str,
    comment: str,
    allow_certificate_mismatch: bool = False,
    requested_by: str | None = None,
) -> str:
    """Build the exact bounded request the UI worker sends to this helper.

    The override defaults to off here as well as in the helper. A default that
    had to be spelled out by every caller is a default one caller eventually
    gets wrong, and this one silently publishes a site under a certificate that
    does not answer for it.

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
                "network": network,
                "expected_head": expected_head,
                "comment": comment,
                "allow_certificate_mismatch": allow_certificate_mismatch,
                **({} if requested_by is None else {"requested_by": requested_by}),
            },
        },
        separators=(",", ":"),
    )


def _read(parameters: Mapping[str, JsonValue]) -> Callable[[PathPolicy, Cluster], Change]:
    network = text(parameters, "network", limit=MAX_NETWORK_BYTES).encode("utf-8")
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
        return Change(
            expected_head=expected_head,
            comment=comment,
            apply=lambda base_files: managed_files(
                base_files,
                network_document=network,
                cluster=cluster,
                certificate_sans=certificate_sans,
                country_reader=geo.location_database(),
                rule_set=crs.installed,
                allow_certificate_mismatch=allow_certificate_mismatch,
            ),
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
