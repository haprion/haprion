"""Privileged publication of the changes a person saved, as one version (B257).

Proxy objects, the network description and the cluster's settings, in any
combination, published together: one version, one release and one revert. The
three single-document helpers this replaced each published their own layer as
a version of its own, so a VIP added for a new object was two versions and two reverts, and
the version between them was one nobody had asked for.

The documents that are not sent are read from the committed base, as the other
helpers read the network: a stale tab that carried its own copy of a document
it did not change could otherwise undo somebody else's change through this path.
`expected_head` fences the whole package on the version it was saved against.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from datetime import datetime
from pathlib import Path
from typing import Any, BinaryIO, TextIO

from haprion import cluster_settings, crs, exit_codes, geo, held_ports, peers, server_names
from haprion.candidate_validation import (
    DEFAULT_RUN_ROOT,
    SandboxValidator,
    validate_in_sandbox,
)
from haprion.cert_inventory import coverage
from haprion.cli import managed_helper
from haprion.cli.managed_helper import (
    SUDO,
    Change,
    Refusal,
    Words,
    fence,
    flag,
    network_of,
    text,
)
from haprion.cluster_lock import DEFAULT_LOCK_ROOT
from haprion.config import DEFAULT_POLICY_PATH, Cluster, ConfigError, PathPolicy
from haprion.held_ports import HeldPorts
from haprion.helper_protocol import HelperProtocolError, JsonValue
from haprion.managed_network import MAX_NETWORK_BYTES, load_document
from haprion.managed_network import location as network_location
from haprion.managed_publish import managed_files
from haprion.proxy_model import MAX_MODEL_BYTES, NAME, NAME_RULE, load_proxy, name_refusal
from haprion.release_install import PUBLISH_GROUP, ChangeOwner, default_change_owner

OPERATION = "changes_publish"
PARAMETERS = frozenset(
    {
        "objects",
        "network",
        "settings",
        "expected_head",
        "comment",
        "allow_certificate_mismatch",
        "requested_by",
    }
)
#
# Everything somebody saved before publishing, which is more than one person's
# selection: 64 objects (B257). Generating and validating the candidate costs
# the same for one changed object as for 64 - the whole configuration is built
# either way - so the count is a sentence about the package and not a cost.
# The ceiling on the request is what keeps a helper from parsing megabytes
# under the cluster's lock: the objects in service measured 300-600 bytes
# (2026-10-08), so 1 MiB holds 64 objects at 15 KB each beside a network and
# settings document at their own limits.
#
MAX_OBJECTS = 64
MAX_REQUEST_BYTES = 1024 * 1024
MESSAGE = "Publish changes"
HELPER = "/opt/haprion/current/bin/haprion-changes-publish-helper"
WORDS = Words(
    operation=OPERATION,
    message=MESSAGE,
    helper="changes publish",
    doing="publishing saved changes",
    moved="the configuration changed since these changes were saved. Review them and try again.",
    invalid="these changes did not produce a valid HAProxy candidate. Nothing was published.",
)
__all__ = ["HELPER", "MAX_OBJECTS", "OPERATION", "SUDO", "build_request", "main"]


def build_request(
    cluster: str,
    request_id: str,
    *,
    expected_head: str,
    comment: str,
    objects: Mapping[str, str | None] | None = None,
    network: str | None = None,
    settings: str | None = None,
    allow_certificate_mismatch: bool = False,
    requested_by: str | None = None,
) -> str:
    """Build the exact bounded request the UI worker sends to this helper.

    `None` for an object asks for its removal. A part that is not changed is
    left out of the request rather than sent empty, and the helper then reads
    it from the base. The override defaults to off here as well as in the
    helper, for the reason B66 gives.
    """

    parameters: dict[str, object] = {
        "expected_head": expected_head,
        "comment": comment,
        "allow_certificate_mismatch": allow_certificate_mismatch,
    }
    if objects:
        parameters["objects"] = dict(objects)
    if network is not None:
        parameters["network"] = network
    if settings is not None:
        parameters["settings"] = settings
    if requested_by is not None:
        parameters["requested_by"] = requested_by
    return json.dumps(
        {
            "schema_version": 1,
            "operation": OPERATION,
            "cluster": cluster,
            "request_id": request_id,
            "parameters": parameters,
        },
        separators=(",", ":"),
    )


def _objects(parameters: Mapping[str, JsonValue]) -> dict[str, bytes | None]:
    """The objects part: name to document, or to removal; empty when not sent.

    The names arrive from a job payload and are held to the model's own pattern
    here, before `managed_files` turns one into a path. It is checked in both
    places on purpose: this one keeps a bad name out of the candidate builder,
    and the one there keeps the builder safe for any future caller.
    """

    if "objects" not in parameters:
        return {}
    raw = parameters["objects"]
    if not isinstance(raw, dict) or not raw:
        raise HelperProtocolError(
            "parameters.objects must be a non-empty object", exit_code=exit_codes.REFUSED
        )
    if len(raw) > MAX_OBJECTS:
        raise HelperProtocolError(
            f"parameters.objects carries more than {MAX_OBJECTS} objects",
            exit_code=exit_codes.REFUSED,
        )

    objects: dict[str, bytes | None] = {}
    for name, document in raw.items():
        if not NAME.fullmatch(name):
            raise HelperProtocolError(
                f"{name} is not a usable object name - {name_refusal(name)}; use {NAME_RULE}",
                exit_code=exit_codes.REFUSED,
            )
        if document is None:
            objects[name] = None
            continue
        if not isinstance(document, str) or not document:
            raise HelperProtocolError(
                f"parameters.objects.{name} must be a document or null",
                exit_code=exit_codes.REFUSED,
            )
        encoded = document.encode("utf-8")
        if len(encoded) > MAX_MODEL_BYTES:
            raise HelperProtocolError(
                f"parameters.objects.{name} is too long", exit_code=exit_codes.REFUSED
            )
        objects[name] = encoded
    return objects


def _document(parameters: Mapping[str, JsonValue], key: str, *, limit: int) -> bytes | None:
    if key not in parameters:
        return None
    return text(parameters, key, limit=limit).encode("utf-8")


def _read(parameters: Mapping[str, JsonValue]) -> Callable[[PathPolicy, Cluster], Change]:
    objects = _objects(parameters)
    network = _document(parameters, "network", limit=MAX_NETWORK_BYTES)
    settings = _document(parameters, "settings", limit=cluster_settings.MAX_BYTES)
    if not objects and network is None and settings is None:
        raise HelperProtocolError(
            "a publish carries at least one of parameters.objects, network or settings",
            exit_code=exit_codes.REFUSED,
        )
    expected_head, comment = fence(parameters)
    allow_certificate_mismatch = flag(parameters, "allow_certificate_mismatch")

    def change(policy: PathPolicy, cluster: Cluster) -> Change:
        #
        # Coverage is asked when the package changes what a certificate has to
        # answer for - an object, or a network that moves one - and not for a
        # settings change alone, where an object published with the mismatch
        # override would otherwise block every change of log target. The same
        # rule the three single-document helpers this replaced applied.
        #
        certificate_sans = (
            coverage(directory, cluster)
            if (directory := policy.certificate_directory(cluster.cluster_id)) is not None
            and (objects or network is not None)
            else None
        )

        named: dict[str, Any] = {
            "objects": sorted(name for name, document in objects.items() if document is not None),
            "removed": sorted(name for name, document in objects.items() if document is None),
            "network": network is not None,
            "settings": settings is not None,
        }

        def apply(base_files: Mapping[str, bytes]) -> Mapping[str, bytes]:
            #
            # Each document the package carries is read on its own first, so a
            # refusal names the part that was wrong; what is left after that is
            # the combination, which only the managed layer as a whole can judge.
            #
            if network is None:
                network_document = network_of(base_files, doing="publishing saved changes")
            else:
                try:
                    load_document(network, ownership_vip=cluster.vip, location=network_location())
                except ConfigError as exc:
                    raise Refusal("network_invalid", str(exc), exit_codes.REFUSED) from exc
                network_document = network
            canonical: bytes | None = None
            if settings is not None:
                try:
                    #
                    # Stored in its canonical form, so two ways of writing the
                    # same settings are one version and a diff shows only what
                    # changed.
                    #
                    canonical = cluster_settings.dump_document(
                        cluster_settings.load_document(settings)
                    )
                except ConfigError as exc:
                    raise Refusal("settings_invalid", str(exc), exit_codes.REFUSED) from exc
            #
            # Asked when objects or the network change, as coverage is: what
            # binds on a VIP is decided there. A node that did not answer is
            # named in the result, not a refusal (26-10-15).
            #
            held = HeldPorts()
            if objects or network is not None:
                held = held_ports.read(policy, cluster)
                named["ports_unchecked"] = list(held.unread)
            try:
                files = managed_files(
                    base_files,
                    network_document=network_document,
                    cluster=cluster,
                    objects=objects,
                    certificate_sans=certificate_sans,
                    country_reader=geo.location_database(),
                    rule_set=crs.installed,
                    allow_certificate_mismatch=allow_certificate_mismatch,
                    settings_document=canonical,
                    node_addresses=lambda: peers.addresses(cluster),
                    held_ports=held.held,
                )
            except ConfigError as exc:
                raise Refusal("changes_invalid", str(exc), exit_codes.REFUSED) from exc
            #
            # The changed objects' server names the manager cannot resolve
            # (finding 72): said, never refused - the node's check decides.
            # Read once the objects have been accepted above.
            #
            if objects:
                named["unresolved_servers"] = server_names.unresolved(
                    load_proxy(name, document)
                    for name, document in objects.items()
                    if document is not None
                )
            return files

        return Change(
            expected_head=expected_head,
            comment=comment,
            apply=apply,
            #
            # What this version did, named, for the audit record and the job
            # page: "version 26 changed shop, removed staging and the network" -
            # and, filled in by `apply`, the nodes whose ports were not checked.
            #
            named=named,
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
