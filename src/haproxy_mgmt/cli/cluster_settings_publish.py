"""Privileged publication of the cluster's own settings (Fas 15, B209).

`managed/cluster.yaml`: where the traffic log is sent and whether the metrics
exporter listens. The same shape as the network helper - one fixed document,
the managed layer rebuilt around it in an isolated index, validated in the
sandbox, recorded as a version - and a separate operation, so a change of log
target is a version of its own that says so.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from datetime import datetime
from pathlib import Path
from typing import BinaryIO, TextIO

from haproxy_mgmt import cluster_settings
from haproxy_mgmt.candidate_validation import (
    DEFAULT_RUN_ROOT,
    SandboxValidator,
    validate_in_sandbox,
)
from haproxy_mgmt.cli import managed_helper
from haproxy_mgmt.cli.managed_helper import SUDO, Change, Refusal, Words, fence, network_of, text
from haproxy_mgmt.cluster_lock import DEFAULT_LOCK_ROOT
from haproxy_mgmt.config import DEFAULT_POLICY_PATH, Cluster, ConfigError, PathPolicy
from haproxy_mgmt.helper_protocol import JsonValue
from haproxy_mgmt.managed_publish import managed_files
from haproxy_mgmt.release_install import PUBLISH_GROUP, ChangeOwner, default_change_owner

OPERATION = "cluster_settings_publish"
PARAMETERS = frozenset({"settings", "expected_head", "comment", "requested_by"})
MESSAGE = "Update cluster settings"
HELPER = "/opt/haproxy-mgmt/current/bin/haproxy-cluster-settings-publish-helper"
WORDS = Words(
    operation=OPERATION,
    message=MESSAGE,
    helper="cluster settings publish",
    doing="changing the cluster settings",
    moved="the configuration changed since these settings were read. Refresh them before "
    "trying again.",
    invalid="the settings did not produce a valid HAProxy candidate. Nothing was published.",
)
__all__ = ["HELPER", "OPERATION", "SUDO", "build_request", "main"]


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


def _read(parameters: Mapping[str, JsonValue]) -> Callable[[PathPolicy, Cluster], Change]:
    settings = text(parameters, "settings", limit=cluster_settings.MAX_BYTES).encode("utf-8")
    expected_head, comment = fence(parameters)

    def change(_policy: PathPolicy, cluster: Cluster) -> Change:
        def apply(base_files: Mapping[str, bytes]) -> Mapping[str, bytes]:
            network_document = network_of(base_files, doing="changing its settings")
            try:
                #
                # Stored in its canonical form, so two ways of writing the same
                # settings are one version and a diff shows only what changed.
                #
                canonical = cluster_settings.dump_document(cluster_settings.load_document(settings))
                return managed_files(
                    base_files,
                    network_document=network_document,
                    cluster=cluster,
                    #
                    # Certificate coverage is not asked again. Nothing here
                    # changes an object or a certificate, and an object
                    # published with the mismatch override would otherwise
                    # block every settings change.
                    #
                    certificate_sans=None,
                    settings_document=canonical,
                )
            except ConfigError as exc:
                raise Refusal("settings_invalid", str(exc), 65) from exc

        return Change(expected_head=expected_head, comment=comment, apply=apply)

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
