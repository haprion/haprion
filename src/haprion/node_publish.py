"""Each change to a cluster's node list is a version (B318, 26-10-16).

keepalived's configuration is generated when a version is published, from the
node list as it is then. A node added to a cluster that was already serving
was therefore in no release - it got no keepalived.conf and the other nodes
kept their old peers - until somebody happened to publish an object change, and
a new cluster had a first version that was never published at all.

So the node helper publishes after every change to the node list, under the
cluster's lock it already holds, through the same path an object change takes:
the managed layer generated again from the committed base, `haproxy -c` in the
sandbox, a commit, a release. A new cluster's first version already carries
the generated files (`seed`), so publishing it adds no second version: version
1 is the cluster being made.

The node change itself has been made when this runs. A publish that is refused
- a worktree somebody is editing, a configuration that does not validate - is
said in the node change's result, not undone by it.
"""

from __future__ import annotations

import io
import json
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from haprion import crs, exit_codes, geo, peers
from haprion.candidate_validation import DEFAULT_RUN_ROOT, SandboxValidator, validate_in_sandbox
from haprion.cli.managed_helper import Change, Refusal, Refuse, Words, _publish, network_of
from haprion.config import Cluster, ConfigError
from haprion.helper_protocol import HelperRequest
from haprion.managed_publish import MANAGED_PREFIX, managed_files
from haprion.release_install import PUBLISH_GROUP, ChangeOwner, default_change_owner
from haprion.repo_snapshot import resolve_head

OPERATION = "cluster_node"
WORDS = Words(
    operation=OPERATION,
    message="Nodes",
    helper="node",
    doing="the node list changes",
    moved="the cluster's version moved while its node list changed. Publish again.",
    invalid="the configuration with the new node list did not validate. Nothing was published.",
)

type Addresses = Callable[[Cluster], Sequence[tuple[str, str]]]


def generated(
    base_files: Mapping[str, bytes], cluster: Cluster, *, addresses: Addresses = peers.addresses
) -> dict[str, bytes]:
    """The managed layer for `base_files` and the cluster's node list as it is now."""

    return managed_files(
        base_files,
        network_document=network_of(base_files, doing=WORDS.doing),
        cluster=cluster,
        country_reader=geo.location_database(),
        rule_set=crs.installed,
        node_addresses=lambda: addresses(cluster),
    )


def seed(
    files: Mapping[str, bytes], cluster: Cluster, *, addresses: Addresses = peers.addresses
) -> dict[str, bytes]:
    """A new cluster's first version with its generated files, or as it is when they cannot be made.

    Made before the version is committed, so the first publish finds nothing to
    change and version 1 is what goes out. A node list that cannot be resolved
    yet leaves the layout as it was; the publish after then says why.
    """

    try:
        managed = generated(files, cluster, addresses=addresses)
    except (ConfigError, Refusal):
        return dict(files)
    kept = {path: content for path, content in files.items() if not path.startswith(MANAGED_PREFIX)}
    return {**kept, **managed}


class _Kept(Refuse):
    """A refusal kept for the node change's result instead of written as its envelope."""

    def __init__(self, request: HelperRequest) -> None:
        super().__init__(OPERATION, request, io.StringIO(), io.StringIO())
        self.error: dict[str, Any] | None = None

    def __call__(
        self, code: str, message: str, exit_code: int, details: dict[str, Any] | None = None
    ) -> int:
        self.error = {"code": code, "message": message}
        return exit_code


def publish(
    request: HelperRequest,
    cluster: Cluster,
    *,
    comment: str,
    require_secure: bool = True,
    run_root: Path = DEFAULT_RUN_ROOT,
    validator: SandboxValidator = validate_in_sandbox,
    group: str = PUBLISH_GROUP,
    change_owner: ChangeOwner = default_change_owner,
    clock: Callable[[], datetime] | None = None,
    addresses: Addresses = peers.addresses,
    names: tuple[str, str] = ("root", "root"),
) -> dict[str, Any]:
    """Publish the cluster's node list as a version; what it became, or why it did not.

    `names` is (requested by, run by) for the version, from `request_names`.

    Called with the cluster's lock held. `{"version", "hash", "changed"}` when
    a release was installed, `{"error": {"code", "message"}}` when not.
    """

    try:
        _branch, head = resolve_head(cluster.config_path)
    except Exception as exc:  # noqa: BLE001 - said in the result, whatever it was
        return {"error": {"code": "publish_incomplete", "message": str(exc)}}

    def apply(base_files: Mapping[str, bytes]) -> Mapping[str, bytes]:
        try:
            return generated(base_files, cluster, addresses=addresses)
        except ConfigError as exc:
            raise Refusal("changes_invalid", str(exc), exit_codes.REFUSED) from exc

    kept = _Kept(request)
    output = io.StringIO()
    try:
        _publish(
            words=WORDS,
            request=request,
            names=names,
            cluster=cluster,
            change=Change(expected_head=head, comment=comment, apply=apply),
            output=output,
            run_root=run_root,
            require_secure=require_secure,
            validator=validator,
            group=group,
            change_owner=change_owner,
            clock=clock or (lambda: datetime.now(UTC)),
            refuse=kept,
        )
    except Exception as exc:  # noqa: BLE001 - the node change stands; its result says why
        return {"error": {"code": "publish_incomplete", "message": str(exc)}}
    if kept.error is not None:
        return {"error": kept.error}
    result = json.loads(output.getvalue())["result"]
    return {"version": result["version"], "hash": result["hash"], "changed": result["changed"]}


def said(publication: object, cluster: str) -> str:
    """The line the terminal prints for a node change's publication; empty when it has none."""

    if not isinstance(publication, dict):
        return ""
    error = publication.get("error")
    if isinstance(error, dict):
        return (
            f"WARNING: the node list was not published: {error.get('message')}\n"
            f"Publish a change to {cluster} once that is put right; until then its release "
            "has the nodes it had.\n"
        )
    return (
        f"Published as version {publication.get('version')}; "
        f"haprion-deploy -c {cluster} takes it to the nodes.\n"
    )
