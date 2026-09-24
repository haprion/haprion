#!/usr/bin/env python3

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from copy import deepcopy
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from haproxy_mgmt import backup_schedule

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "schemas" / "v1"
FIXTURE_ROOT = ROOT / "fixtures"
STATUS_SCHEMA_ID = "https://example.com/haproxy-manager/schemas/v1/haproxy-status.schema.json"


def load_json(path: Path) -> object:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def build_registry() -> tuple[Registry, dict[str, object]]:
    registry = Registry()
    schemas: dict[str, object] = {}

    for path in sorted(SCHEMA_DIR.glob("*.schema.json")):
        schema = load_json(path)
        if not isinstance(schema, dict) or "$id" not in schema:
            raise AssertionError(f"{path}: schema must be an object with $id")
        Draft202012Validator.check_schema(schema)
        schema_id = str(schema["$id"])
        registry = registry.with_resource(schema_id, Resource.from_contents(schema))
        schemas[schema_id] = schema

    return registry, schemas


def derive_vip_state(nodes: list[dict[str, object]]) -> tuple[list[str], list[str], str]:
    valid_nodes = [node for node in nodes if node["status_ok"] is True]
    owners: list[str] = []
    unknown: list[str] = []

    for node in valid_nodes:
        status = node["status"]
        assert isinstance(status, dict)
        vip = status["vip"]
        assert isinstance(vip, dict)
        owner = vip["owner"]
        if owner is True:
            owners.append(str(node["name"]))
        elif owner is None:
            unknown.append(str(node["name"]))

    if len(valid_nodes) < len(nodes):
        state = "incomplete"
    elif unknown:
        state = "unknown"
    elif not owners:
        state = "no_owner"
    elif len(owners) == 1:
        state = "single_owner"
    else:
        state = "split_brain"

    return owners, unknown, state


def check_release_comparison(nodes: list[object], summary: dict[str, object], path: Path) -> None:
    """Whether a node runs the published release, re-derived rather than believed.

    This is the one part of a status result the manager decides rather than
    forwards, so the contract test derives it independently: a status command
    that got this wrong would send an operator away from a cluster that needed a
    deploy, and it would look correct while doing it.
    """

    target = summary["target"]

    for node in nodes:
        assert isinstance(node, dict)
        current = node["current"]
        status = node["status"] if node["status_ok"] is True else None
        observed = None
        if isinstance(status, dict) and isinstance(status.get("release"), dict):
            observed = status["release"].get("hash")

        if target is None or observed is None:
            expected: object = None
        else:
            assert isinstance(target, dict)
            expected = target["hash"] == observed
        if current != expected:
            raise AssertionError(
                f"{path}: {node['name']} current={current!r}, expected {expected!r}"
            )

    states = [node["current"] for node in nodes if isinstance(node, dict)]
    if target is None:
        expected_state = "unknown"
    elif any(state is None for state in states):
        expected_state = "incomplete" if any(state is not None for state in states) else "unknown"
    elif all(states):
        expected_state = "converged"
    else:
        expected_state = "behind"
    if summary["release_state"] != expected_state:
        raise AssertionError(
            f"{path}: release_state={summary['release_state']!r}, expected {expected_state!r}"
        )


def check_status_semantics(document: dict[str, object], path: Path) -> None:
    result = document["result"]
    outcome = document["outcome"]

    if result is None:
        if outcome != "failed":
            raise AssertionError(f"{path}: null result is only valid for failed status")
        return

    assert isinstance(result, dict)
    nodes = result["nodes"]
    summary = result["summary"]
    assert isinstance(nodes, list)
    assert isinstance(summary, dict)

    reachable = sum(node["reachable"] is True for node in nodes)
    valid = sum(node["status_ok"] is True for node in nodes)
    owners, unknown, vip_state = derive_vip_state(nodes)

    expected = {
        "configured_nodes": len(nodes),
        "reachable_nodes": reachable,
        "valid_status_nodes": valid,
        "vip_owner_count": len(owners),
        "vip_owners": owners,
        "vip_unknown_nodes": unknown,
        "vip_state": vip_state,
    }

    for key, value in expected.items():
        if summary[key] != value:
            raise AssertionError(f"{path}: summary.{key}={summary[key]!r}, expected {value!r}")

    cluster = document["cluster"]
    for node in nodes:
        if node["status_ok"] is not True:
            continue
        status = node["status"]
        assert isinstance(status, dict)
        if status["node"] != node["name"]:
            raise AssertionError(f"{path}: node result and node status names differ")
        if status["cluster"] != cluster:
            raise AssertionError(f"{path}: node status cluster differs from envelope")

    check_release_comparison(nodes, summary, path)

    if outcome == "done" and valid != len(nodes):
        raise AssertionError(f"{path}: done requires usable status from every node")
    if outcome == "partial" and not (0 < valid < len(nodes)):
        raise AssertionError(f"{path}: partial requires both usable and unusable node status")
    if outcome == "failed" and valid != 0:
        raise AssertionError(f"{path}: failed status with a result cannot contain usable nodes")


def check_list_semantics(document: dict[str, object], path: Path) -> None:
    result = document["result"]
    if result is None:
        return
    versions = result["versions"]
    numbers = [entry["version"] for entry in versions]
    if numbers != sorted(numbers, reverse=True) or len(numbers) != len(set(numbers)):
        raise AssertionError(f"{path}: versions must be unique and newest first")
    if result["total_versions"] < len(versions):
        raise AssertionError(f"{path}: total_versions is smaller than returned history")
    current = [entry["version"] for entry in versions if entry["current"]]
    expected = [] if result["current_version"] is None else [result["current_version"]]
    if current != expected:
        raise AssertionError(f"{path}: current marker does not match current_version")


def check_cert_list_semantics(document: dict[str, object], path: Path) -> None:
    result = document["result"]
    if result is None:
        return
    certificates = result["certificates"]
    identifiers = [certificate["id"] for certificate in certificates]
    if len(identifiers) != len(set(identifiers)):
        raise AssertionError(f"{path}: certificate IDs must be unique")
    for certificate in certificates:
        if certificate["deployable"] and not certificate["valid"]:
            raise AssertionError(f"{path}: an invalid certificate cannot be deployable")
        if certificate["deployable"] and certificate["validation_error"] is not None:
            raise AssertionError(f"{path}: a deployable certificate cannot have a validation error")

    registry = result.get("registry")
    if registry is None:
        return
    entries = registry["certificates"]
    registered = [entry["id"] for entry in entries]
    if len(registered) != len(set(registered)):
        raise AssertionError(f"{path}: a registered certificate is reported twice")

    for entry in entries:
        # Readable means measured. The inert fields exist so an unreadable
        # certificate is still listed, and nothing may read them without
        # checking this flag first.
        if entry["readable"] != (entry["fingerprint_sha256"] is not None):
            raise AssertionError(f"{path}: {entry['id']} is readable without a fingerprint")
        if entry["readable"] and entry["validation_error"] is not None:
            raise AssertionError(f"{path}: {entry['id']} was read and carries a reason it was not")
        if not entry["readable"] and entry["validation_error"] is None:
            raise AssertionError(f"{path}: {entry['id']} could not be read for no stated reason")
        # The shared cluster copy is reported where a cluster reads it, and the
        # question does not apply where none does.
        if bool(entry["targets"]["clusters"]) != (entry["distribution"] is not None):
            raise AssertionError(f"{path}: {entry['id']} reports a copy no cluster reads")
        for receiver in entry["targets"]["receivers"]:
            if receiver["id"] not in registry["receivers"]:
                raise AssertionError(f"{path}: {entry['id']} names unregistered {receiver['id']}")
            # Nothing published cannot be the current version of anything.
            if receiver["published_at"] is None and receiver["current"]:
                raise AssertionError(
                    f"{path}: {entry['id']} is current on an empty {receiver['id']}"
                )


def check_network_semantics(document: dict[str, object], path: Path) -> None:
    result = document["result"]
    if result is None:
        return
    vips = result["vips"]
    names = [vip["name"] for vip in vips]
    if len(names) != len(set(names)):
        raise AssertionError(f"{path}: VIP names must be unique")
    addresses = [vip["address"] for vip in vips]
    if len(addresses) != len(set(addresses)):
        raise AssertionError(f"{path}: one address may not have two VIP names")
    #
    # The default is what every object that names nothing gets. A default
    # naming a VIP that is not in the table would place those objects nowhere,
    # and the generator would refuse the whole layer rather than one object.
    #
    if result["default_vip"] not in names:
        raise AssertionError(f"{path}: default_vip must name one of this cluster's VIPs")
    source_names = [source["name"] for source in result["sources"]]
    if len(source_names) != len(set(source_names)):
        raise AssertionError(f"{path}: source address names must be unique")
    group_names = [group["name"] for group in result["groups"]]
    if len(group_names) != len(set(group_names)):
        raise AssertionError(f"{path}: group names must be unique")


def check_backup_semantics(document: dict[str, object], path: Path) -> None:
    result = document["result"]
    if result is None:
        return
    nodes = result["nodes"]
    names = [node["name"] for node in nodes]
    if len(names) != len(set(names)):
        raise AssertionError(f"{path}: backup node names must be unique")
    available_count = 0
    for node in nodes:
        backups = node["backups"]
        versions = [backup["version"] for backup in backups]
        if len(versions) != len(set(versions)):
            raise AssertionError(f"{path}: backup versions must be unique per node")
        if result["limit"] is not None and len(backups) > result["limit"]:
            raise AssertionError(f"{path}: node contains more backups than the requested limit")
        latest = [backup["version"] for backup in backups if backup["latest"]]
        expected_latest = [] if node["latest_version"] is None else [node["latest_version"]]
        if latest != expected_latest:
            raise AssertionError(f"{path}: latest marker does not match latest_version")
        if node["available"]:
            available_count += 1
            if node["error"] is not None:
                raise AssertionError(f"{path}: available backup metadata cannot have an error")
        elif node["error"] is None or backups or node["latest_version"] is not None:
            raise AssertionError(f"{path}: unavailable backup metadata must be empty with an error")
    if document["outcome"] == "done" and available_count != len(nodes):
        raise AssertionError(f"{path}: done requires backup metadata for every node")
    if document["outcome"] == "partial" and not (0 < available_count < len(nodes)):
        raise AssertionError(f"{path}: partial requires available and unavailable node metadata")


def check_inventory_semantics(document: dict[str, object], path: Path) -> None:
    result = document["result"]
    if result is None:
        return
    proxies = result["proxies"]
    identifiers = [proxy["id"] for proxy in proxies]
    if len(identifiers) != len(set(identifiers)):
        raise AssertionError(f"{path}: proxy IDs must be unique")
    for proxy in proxies:
        if proxy["managed"] != (proxy["source"] == "managed"):
            raise AssertionError(f"{path}: managed flag and source disagree")


def check_objects_semantics(document: dict[str, object], path: Path) -> None:
    result = document["result"]
    if result is None:
        return
    objects = result["objects"]
    names = [entry["name"] for entry in objects]
    if len(names) != len(set(names)):
        raise AssertionError(f"{path}: object names must be unique")
    for entry in objects:
        #
        # An object that could not be read has no shape to report, and one that
        # could must not carry a problem. The two fields are one answer written
        # twice, and a listing where they disagree is a listing nobody can act
        # on.
        #
        if entry["readable"] != (entry["problem"] is None):
            raise AssertionError(f"{path}: readable and problem disagree")
        if not entry["readable"] and (entry["protocol"] is not None or entry["hostnames"]):
            raise AssertionError(f"{path}: an unreadable object cannot report a shape")
    if result["commit"] is None and objects:
        raise AssertionError(f"{path}: objects cannot be listed without a commit to read them at")


def check_publish_semantics(document: dict[str, object], path: Path) -> None:
    result = document["result"]
    if result is None:
        return
    if document["outcome"] == "done" and not result["validation"]["valid"]:
        raise AssertionError(f"{path}: done publish requires successful validation")
    if result["changed"]:
        required = (result["version"], result["hash"], result["published_at"])
        if any(value is None for value in required):
            raise AssertionError(f"{path}: changed publish requires release metadata")
        if not result["deployment_required"] or result["next_command"] is None:
            raise AssertionError(f"{path}: changed publish must require explicit deploy")
    elif result["deployment_required"] or result["next_command"] is not None:
        raise AssertionError(f"{path}: no-op publish must not claim a new deploy is required")


def check_revert_semantics(document: dict[str, object], path: Path) -> None:
    result = document["result"]
    if result is None:
        return
    if result["changed"]:
        required = (result["new_version"], result["hash"], result["published_at"])
        if any(value is None for value in required):
            raise AssertionError(f"{path}: changed revert requires new release metadata")
        if not result["deployment_required"] or result["next_command"] is None:
            raise AssertionError(f"{path}: changed revert must require explicit deploy")
    else:
        if result["deployment_required"] or result["next_command"] is not None:
            raise AssertionError(f"{path}: no-op revert must not require deploy")


def check_network_publish_semantics(document: dict[str, object], path: Path) -> None:
    result = document["result"]
    if result is None:
        return
    # Even a no-op network publish reinstalls the release from the committed
    # tree.  The helper therefore always tells the operator to reconcile nodes;
    # a previous failed deploy must not become invisible merely because the
    # network document was byte-identical on the retry.
    if not result["deployment_required"] or result["next_command"] is None:
        raise AssertionError(f"{path}: network publish must require explicit deploy")
    if result["changed"] and result["published_at"] is None:
        raise AssertionError(f"{path}: changed network publish requires a timestamp")


def check_objects_publish_semantics(document: dict[str, object], path: Path) -> None:
    result = document["result"]
    if result is None:
        return
    # Same reason as the network publish above: even a byte-identical retry
    # reinstalls the release, so the operator is always told to reconcile.
    if not result["deployment_required"] or result["next_command"] is None:
        raise AssertionError(f"{path}: objects publish must require explicit deploy")
    if result["changed"] and result["published_at"] is None:
        raise AssertionError(f"{path}: changed objects publish requires a timestamp")
    # An object cannot be both written and removed by one version.  The two
    # lists are what the audit record and the job page read, and a name in both
    # would describe a publish that did not happen.
    overlap = sorted(set(result["objects"]) & set(result["removed"]))
    if overlap:
        raise AssertionError(f"{path}: {', '.join(overlap)} is both published and removed")
    if result["changed"] and not (result["objects"] or result["removed"]):
        raise AssertionError(f"{path}: a changed objects publish names what it changed")


def check_reconcile_semantics(document: dict[str, object], path: Path) -> None:
    result = document["result"]
    if result is None:
        return
    outcome = document["outcome"]
    if outcome == "done" and not result["converged"]:
        raise AssertionError(f"{path}: done reconcile must be converged")
    if outcome == "partial" and result["converged"]:
        raise AssertionError(f"{path}: partial reconcile cannot be converged")
    for node in result["nodes"]:
        node_outcome = node["outcome"]
        if node_outcome in ("current", "updated") and not node["verified"]:
            raise AssertionError(f"{path}: current/updated node must be verified")
        if node["current_before"] is True and (
            node["action"] != "skip" or node_outcome != "current"
        ):
            raise AssertionError(f"{path}: already-current node must be skipped")
        if node["action"] == "deploy" and node_outcome not in ("updated", "failed"):
            raise AssertionError(f"{path}: deploy action has an impossible node outcome")
        if node["action"] == "none" and node_outcome not in ("unavailable", "not_attempted"):
            raise AssertionError(f"{path}: no-action node has an impossible outcome")
    if result["converged"] and any(
        not node["verified"] or node["outcome"] not in ("current", "updated")
        for node in result["nodes"]
    ):
        raise AssertionError(f"{path}: converged requires every node verified current")


def check_cert_publish_semantics(document: dict[str, object], path: Path) -> None:
    """Publishing is what every certificate operation ends with, so this is shared.

    The invariant the phase gate names in its own words - "exactly the targets
    chosen, and no others" - cannot be measured from an envelope, because the
    envelope does not carry the registry. What can be measured is that the
    report does not contradict itself, and that a failure is never dressed up as
    a run that worked.
    """

    result = document["result"]
    if result is None:
        return
    certificates = result["certificates"]
    named = [entry["id"] for entry in certificates]
    if len(named) != len(set(named)):
        raise AssertionError(f"{path}: a certificate is reported twice")

    for entry in certificates:
        if entry["status"] in ("skipped", "failed") and entry["error"] is None:
            raise AssertionError(f"{path}: {entry['id']} is {entry['status']} without a reason")
        if entry["status"] in ("published", "unchanged") and entry["error"] is not None:
            raise AssertionError(f"{path}: {entry['id']} both succeeded and carries an error")
        # Nothing published means nothing to have changed on a target.
        if entry["status"] == "unchanged" and any(t["changed"] for t in entry["targets"]):
            raise AssertionError(f"{path}: {entry['id']} is unchanged but a target changed")

    # A cluster is only listed as changed if some certificate changed on it.
    changed_targets = {
        target["name"]
        for entry in certificates
        for target in entry["targets"]
        if target["changed"] and target["kind"] == "cluster"
    }
    for cluster in result["changed_clusters"]:
        if cluster not in changed_targets:
            raise AssertionError(f"{path}: {cluster} is listed as changed by nothing")

    # A rollout that failed cannot be reported by a done envelope.
    if document["outcome"] == "done":
        if any(entry["status"] == "failed" for entry in certificates):
            raise AssertionError(f"{path}: done envelope carries a failed certificate")
        if any(item["exit_code"] != 0 for item in result["deployments"]):
            raise AssertionError(f"{path}: done envelope carries a failed deployment")


def check_dns_profile_apply_semantics(document: dict[str, object], path: Path) -> None:
    result = document["result"]
    if result is None:
        if document["outcome"] == "done":
            raise AssertionError(f"{path}: a done dns_profile_apply carries a result")
        return
    #
    # The result names what was applied and never what it contained: no
    # field values, no file path, no credentials. A key that is anything but
    # a key id, or a text that looks like a rendered INI line, did not come
    # from this helper.
    #
    for value in result.values():
        if isinstance(value, str) and (" = " in value or "\n" in value):
            raise AssertionError(f"{path}: dns_profile_apply result carries file content")


def check_cert_delete_semantics(document: dict[str, object], path: Path) -> None:
    result = document["result"]
    if result is None:
        if document["outcome"] != "failed":
            raise AssertionError(f"{path}: only a failed cert_delete may carry no result")
        return
    assert isinstance(result, dict)
    certificates = result["certificates"]
    assert isinstance(certificates, list)
    by_state: dict[str, list[str]] = {"removed": [], "refused": [], "incomplete": []}
    for entry in certificates:
        assert isinstance(entry, dict)
        by_state[str(entry["state"])].append(str(entry["certificate"]))
        #
        # A refused certificate was not touched, so it has no layers to
        # report; a removed one has every layer gone and every node copy gone.
        #
        if entry["state"] == "refused" and (entry.get("layers") or entry.get("nodes")):
            raise AssertionError(f"{path}: a refused certificate carries layers")
        if entry["state"] == "removed":
            layers = entry.get("layers") or []
            nodes = entry.get("nodes") or []
            if any(layer["state"] not in ("removed", "absent") for layer in layers) or any(
                node["state"] not in ("removed", "absent") for node in nodes
            ):
                raise AssertionError(f"{path}: a removed certificate carries a kept layer")
    for state, ids in by_state.items():
        if result[state] != ids:
            raise AssertionError(f"{path}: result.{state} disagrees with the rows")
    #
    # The envelope follows the rows: done only when every row is removed,
    # blocked only when every row is refused.
    #
    if document["outcome"] == "done" and (by_state["refused"] or by_state["incomplete"]):
        raise AssertionError(f"{path}: done envelope carries a refused or incomplete row")
    if document["outcome"] == "blocked" and (by_state["removed"] or by_state["incomplete"]):
        raise AssertionError(f"{path}: blocked envelope carries a touched row")


def check_cert_issue_semantics(document: dict[str, object], path: Path) -> None:
    result = document["result"]
    if result is None:
        # A run that did not issue anything has nothing to report, and one
        # that says "done" with nothing to show for it did not come from this
        # engine. certbot's failure keeps its evidence under `diagnostics`,
        # never as a message cut off at the envelope's cap.
        if document["outcome"] == "done":
            raise AssertionError(f"{path}: a done cert_issue carries a result")
        error = document["error"]
        assert isinstance(error, dict)
        if error["code"] == "certbot_failed":
            details = error["details"]
            if not isinstance(details, dict) or not details.get("diagnostics"):
                raise AssertionError(f"{path}: certbot_failed carries certbot's output")
        return
    if not result["targets"]["clusters"] and not result["targets"]["receivers"]:
        raise AssertionError(f"{path}: an issued certificate goes somewhere")
    # A wildcard cannot be proved over HTTP-01; certbot refuses it and so does
    # the form, so an envelope claiming otherwise did not come from this engine.
    if any(name.startswith("*.") for name in result["domains"]) and result["method"] != "dns-01":
        raise AssertionError(f"{path}: a wildcard needs DNS-01")
    if result["certbot_seconds"] > result["total_seconds"]:
        raise AssertionError(f"{path}: certbot cannot take longer than the whole run")
    # The publish half is the same report, held to the same rules.
    check_cert_publish_semantics(
        {"outcome": document["outcome"], "result": result["publish"]}, path
    )


def check_cert_import_semantics(document: dict[str, object], path: Path) -> None:
    """An import is a leaf's facts and the publish that followed; held to the same rules."""

    result = document["result"]
    if result is None:
        if document["outcome"] == "done":
            raise AssertionError(f"{path}: a done cert_import carries a result")
        return
    if not result["publish"]["certificates"]:
        raise AssertionError(f"{path}: an import publishes the certificate it wrote")
    for entry in result["publish"]["certificates"]:
        if entry["id"] != result["certificate"]:
            raise AssertionError(f"{path}: an import publishes exactly the certificate it wrote")
    if result["not_after"] <= result["not_before"]:
        raise AssertionError(f"{path}: a certificate expires after it starts")
    check_cert_publish_semantics(
        {"outcome": document["outcome"], "result": result["publish"]}, path
    )


def check_cert_request_semantics(document: dict[str, object], path: Path) -> None:
    """A request is a CSR for the names it asked for; the CN is never a wildcard."""

    result = document["result"]
    if result is None:
        if document["outcome"] == "done":
            raise AssertionError(f"{path}: a done cert_request carries a result")
        return
    assert isinstance(result, dict)
    if str(result["domains"][0]).startswith("*."):
        raise AssertionError(f"{path}: the primary name cannot be a wildcard")
    if "PRIVATE KEY" in str(result["csr_pem"]):
        raise AssertionError(f"{path}: a request never carries the key")


def check_cert_target_semantics(document: dict[str, object], path: Path) -> None:
    result = document["result"]
    if result is None:
        if document["outcome"] == "done":
            raise AssertionError(f"{path}: a done cert_target carries a result")
        return
    assert isinstance(result, dict)
    certificates = result["certificates"]
    assert isinstance(certificates, list)
    by_state: dict[str, list[str]] = {
        "changed": [],
        "unchanged": [],
        "refused": [],
        "incomplete": [],
    }
    for entry in certificates:
        assert isinstance(entry, dict)
        by_state[str(entry["state"])].append(str(entry["certificate"]))
        added, abandoned = set(entry["added"]), set(entry["abandoned"])
        # One delta per request: a row gained targets or lost them, never both,
        # and a row that changed names what moved.
        if added and abandoned:
            raise AssertionError(f"{path}: a row both added and abandoned targets")
        if result["action"] == "add" and abandoned:
            raise AssertionError(f"{path}: an add abandoned a target")
        if result["action"] == "remove" and added:
            raise AssertionError(f"{path}: a remove added a target")
        if entry["state"] == "changed" and not (added or abandoned):
            raise AssertionError(f"{path}: a changed row names no target")
        # A refused or unchanged certificate was not touched.
        if entry["state"] in ("refused", "unchanged") and (
            added or abandoned or entry.get("layers") or entry.get("nodes")
        ):
            raise AssertionError(f"{path}: an untouched row carries a change")
        if entry["state"] == "changed" and (
            any(layer["state"] == "failed" for layer in entry.get("layers") or [])
            or any(node["state"] not in ("removed", "absent") for node in entry.get("nodes") or [])
        ):
            raise AssertionError(f"{path}: a changed row carries a kept copy")
    for state, ids in by_state.items():
        if result[state] != ids:
            raise AssertionError(f"{path}: result.{state} disagrees with the rows")
    deployments = result["deployments"]
    assert isinstance(deployments, list)
    if result["action"] == "remove" and deployments:
        raise AssertionError(f"{path}: a remove rolls nothing out")
    failed_deploys = [d for d in deployments if d["exit_code"] != 0]
    if document["outcome"] == "done" and (
        by_state["refused"] or by_state["incomplete"] or failed_deploys
    ):
        raise AssertionError(f"{path}: done envelope carries a refused or incomplete row")
    if document["outcome"] == "blocked" and (by_state["changed"] or by_state["incomplete"]):
        raise AssertionError(f"{path}: blocked envelope carries a touched row")


def check_cert_scep_semantics(document: dict[str, object], path: Path) -> None:
    result = document["result"]
    if result is None:
        if document["outcome"] in {"done", "partial"}:
            raise AssertionError(f"{path}: a done or pending cert_scep carries a result")
        return
    assert isinstance(result, dict)
    # The wildcard is a SAN beside its base name; the CN is never a wildcard
    # (the engine refuses the request before Certmonger starts).
    if str(result["domains"][0]).startswith("*."):
        raise AssertionError(f"{path}: the primary name cannot be a wildcard")
    if result["state"] == "pending":
        if document["outcome"] != "partial" or "publication" in result:
            raise AssertionError(f"{path}: a pending request is partial and unpublished")
        return
    if document["outcome"] == "partial":
        raise AssertionError(f"{path}: an issued certificate is not partial")
    publication = result["publication"]
    assert isinstance(publication, dict)
    if publication["certificate"] != result["id"]:
        raise AssertionError(f"{path}: the publication names the enrolled certificate")
    if set(publication["sans"]) != set(result["domains"]):
        raise AssertionError(f"{path}: the issued SANs are exactly the requested names")
    check_cert_publish_semantics(
        {**document, "operation": "cert_publish", "result": publication["publish"]}, path
    )


def check_cert_receiver_semantics(document: dict[str, object], path: Path) -> None:
    result = document["result"]
    if result is None:
        if document["outcome"] != "failed":
            raise AssertionError(f"{path}: a {document['outcome']} cert_receiver carries a result")
        return
    assert isinstance(result, dict)
    layers = result["layers"]
    assert isinstance(layers, list)
    failed = [layer for layer in layers if isinstance(layer, dict) and layer["state"] == "failed"]
    # A layer that failed is what `partial` means; `done` has none.
    if document["outcome"] == "done" and failed:
        raise AssertionError(f"{path}: a done cert_receiver has a failed layer")
    if document["outcome"] == "partial" and not failed:
        raise AssertionError(f"{path}: a partial cert_receiver names no failed layer")
    # A removal leaves nothing to instruct; a registration always does.
    if result["action"] == "removed" and result["instructions"]:
        raise AssertionError(f"{path}: a removal carries instructions")
    if result["action"] == "added" and not result["instructions"]:
        raise AssertionError(f"{path}: a registration carries no instructions")


def check_backup_run_semantics(document: dict[str, object], path: Path) -> None:
    result = document["result"]
    if result is None:
        if document["outcome"] != "failed":
            raise AssertionError(f"{path}: a {document['outcome']} backup_run carries a result")
        return
    assert isinstance(result, dict)
    nodes = result["nodes"]
    assert isinstance(nodes, list)
    names = [node["name"] for node in nodes]
    if len(set(names)) != len(names):
        raise AssertionError(f"{path}: backup_run node names must be unique")
    failed = [node for node in nodes if node["outcome"] == "failed"]
    done = [node for node in nodes if node["outcome"] == "done"]
    # The outcome is derived from the nodes: all done, none done, or some.
    expected = "done" if not failed else ("partial" if done else "failed")
    if document["outcome"] != expected:
        raise AssertionError(f"{path}: backup_run outcome does not follow its nodes")
    for node in nodes:
        if node["outcome"] == "done":
            if node["version"] != result["version"] or node["size_bytes"] is None or node["error"]:
                raise AssertionError(f"{path}: a done node carries the run version and a size")
        elif node["version"] is not None or node["size_bytes"] is not None or not node["error"]:
            raise AssertionError(f"{path}: a failed node carries only a reason")
    # A partial run names every failed node in its warnings, so the job row can say which.
    warned = {warning.get("node") for warning in document["warnings"]}
    if {node["name"] for node in failed} != warned:
        raise AssertionError(f"{path}: backup_run warnings do not match the failed nodes")


def check_backup_schedule_semantics(document: dict[str, object], path: Path) -> None:
    result = document["result"]
    if result is None:
        if document["outcome"] != "failed":
            raise AssertionError(f"{path}: only a failed backup_schedule may carry no result")
        return
    assert isinstance(result, dict)
    schedule = result["schedule"]
    assert isinstance(schedule, dict)
    if result["cluster"] != document["cluster"]:
        raise AssertionError(f"{path}: backup_schedule result names another cluster")
    if schedule["unit"] != f"haproxy-state-backup@{result['cluster']}.timer":
        raise AssertionError(f"{path}: backup_schedule unit is not the cluster's timer instance")
    # `done` is the read-back: systemd knows the timer, reports the requested
    # calendar and sits in the requested enabled/active state.
    if schedule["known"] is not True:
        raise AssertionError(f"{path}: a done backup_schedule names a timer systemd loaded")
    expected = backup_schedule.parse_schedule(result).calendar()
    if schedule["calendar"] != expected:
        raise AssertionError(f"{path}: backup_schedule calendar does not match the request")
    if schedule.get("retention") != result["retention"]:
        raise AssertionError(f"{path}: backup_schedule read-back keeps another retention")
    if schedule["enabled"] is not result["enabled"] or schedule["active"] is not result["enabled"]:
        raise AssertionError(f"{path}: backup_schedule timer state does not match the request")


def check_node_restore_prepare_semantics(document: dict[str, object], path: Path) -> None:
    result = document["result"]
    if result is None:
        if document["outcome"] == "done":
            raise AssertionError(f"{path}: a done node_restore_prepare carries its run")
        return
    assert isinstance(result, dict)
    if result["cluster"] != document["cluster"]:
        raise AssertionError(f"{path}: node_restore_prepare result names another cluster")
    # Test mode is exactly the mode with a profile: the rewrite has values or does not happen.
    if (result["mode"] == "test") != (result["profile"] is not None):
        raise AssertionError(f"{path}: node_restore_prepare mode and profile disagree")
    # The pasted line authorizes this run's key, restricted and for a while only (B182).
    paste = str(result["paste"])
    if f"haproxy-restore-{result['run']}" not in paste or ",restrict," not in paste:
        raise AssertionError(f"{path}: the pasted line is not this run's restricted key")
    if 'expiry-time="' not in paste:
        raise AssertionError(f"{path}: the pasted line lets the target accept the key forever")


def check_node_restore_preview_semantics(document: dict[str, object], path: Path) -> None:
    result = document["result"]
    if result is None:
        if document["outcome"] == "done":
            raise AssertionError(f"{path}: a done node_restore_preview carries its plan")
        return
    assert isinstance(result, dict)
    problems = result["problems"]
    assert isinstance(problems, list)
    # done means run may proceed; a plan that stops carries why.
    if document["outcome"] == "done" and problems:
        raise AssertionError(f"{path}: a done preview lists problems")
    if document["outcome"] == "blocked" and not problems:
        raise AssertionError(f"{path}: a blocked preview with a plan names no problem")
    plan = result["plan"]
    assert isinstance(plan, dict)
    if (plan["mode"] == "test") != (plan["keepalived"] == "mask"):
        raise AssertionError(f"{path}: keepalived is masked in test mode and only there")
    # B183: what an overwrite changes, and the backup and pair it read, belong
    # to an overwrite and to nothing else.
    overwrite = plan["mode"] == "overwrite"
    compared = {"changed", "unchanged", "quarantined", "network_unchanged"}
    if overwrite != ("overwrite" in result) or any(overwrite != (key in plan) for key in compared):
        raise AssertionError(f"{path}: only an overwrite's preview says what it changes")


def check_node_restore_discard_semantics(document: dict[str, object], path: Path) -> None:
    result = document["result"]
    if result is None:
        if document["outcome"] == "done":
            raise AssertionError(f"{path}: a done node_restore_discard names its run")
        return
    assert isinstance(result, dict)
    if document["outcome"] != "done":
        raise AssertionError(f"{path}: only a done node_restore_discard carries a result")


def check_node_restore_semantics(document: dict[str, object], path: Path) -> None:
    result = document["result"]
    if result is None:
        if document["outcome"] == "done":
            raise AssertionError(f"{path}: a done node_restore carries its result")
        return
    assert isinstance(result, dict)
    sessions = result["sessions"]
    assert isinstance(sessions, dict)
    if document["outcome"] == "done":
        # B176: rolled back is a kind of failure, never a success.
        if result["rolled_back"] or "stage" in result or "finish" not in sessions:
            raise AssertionError(f"{path}: a done restore reached finish without rolling back")
        if not result.get("address") or not result.get("hostname"):
            raise AssertionError(f"{path}: a done restore names the node it made")
    elif "stage" not in result or result["stage"] not in sessions:
        raise AssertionError(f"{path}: a failed restore names the session it stopped in")


SEMANTIC_CHECKS = {
    "status": check_status_semantics,
    "list": check_list_semantics,
    "cert_list": check_cert_list_semantics,
    "network": check_network_semantics,
    "list_backups": check_backup_semantics,
    "backup_run": check_backup_run_semantics,
    "backup_schedule": check_backup_schedule_semantics,
    "inventory": check_inventory_semantics,
    "objects": check_objects_semantics,
    "publish": check_publish_semantics,
    "revert": check_revert_semantics,
    "network_publish": check_network_publish_semantics,
    "objects_publish": check_objects_publish_semantics,
    "deploy": check_reconcile_semantics,
    "cert_deploy": check_reconcile_semantics,
    "cert_issue": check_cert_issue_semantics,
    "cert_import": check_cert_import_semantics,
    "cert_request": check_cert_request_semantics,
    "dns_profile_apply": check_dns_profile_apply_semantics,
    "ndes_profile_apply": check_dns_profile_apply_semantics,
    "cert_publish": check_cert_publish_semantics,
    "cert_target": check_cert_target_semantics,
    "cert_delete": check_cert_delete_semantics,
    "cert_scep": check_cert_scep_semantics,
    "cert_receiver": check_cert_receiver_semantics,
    "node_restore_prepare": check_node_restore_prepare_semantics,
    "node_restore_preview": check_node_restore_preview_semantics,
    "node_restore": check_node_restore_semantics,
    "node_restore_discard": check_node_restore_discard_semantics,
}


def make_semantically_invalid(document: dict[str, object]) -> dict[str, object]:
    invalid = deepcopy(document)
    operation = invalid["operation"]
    result = invalid["result"]

    if result is None:
        invalid["outcome"] = "done"
        return invalid

    assert isinstance(result, dict)

    if operation == "status":
        result["summary"]["configured_nodes"] += 1
    elif operation == "list":
        result["total_versions"] = 0
    elif operation == "cert_list":
        result["certificates"].append(deepcopy(result["certificates"][0]))
    elif operation == "network":
        result["default_vip"] = "not-a-vip-in-this-table"
    elif operation == "list_backups":
        result["nodes"][0]["latest_version"] = "2026-01-01_00-00-00"
    elif operation == "inventory":
        result["proxies"].append(deepcopy(result["proxies"][0]))
    elif operation == "objects":
        result["objects"][1]["readable"] = True
    elif operation in ("publish", "revert", "network_publish", "objects_publish"):
        result["deployment_required"] = False
    elif operation == "deploy":
        result["converged"] = True
    elif operation == "cert_deploy":
        result["converged"] = False
    elif operation == "cert_publish":
        result["changed_clusters"] = ["a-cluster-nothing-changed-on"]
    elif operation == "cert_issue":
        result["method"] = "http-01"
        result["domains"] = ["*." + str(result["id"])]
    elif operation == "cert_import":
        result["publish"]["certificates"][0]["id"] = "a-certificate-the-import-did-not-write"
    elif operation == "cert_request":
        result["domains"] = ["*." + str(result["domains"][0])]
    elif operation in {"dns_profile_apply", "ndes_profile_apply"}:
        result["plugin"] = "dns_example_login = leaked-example"
    elif operation == "cert_target":
        result["changed"] = ["a-certificate-no-row-names"]
    elif operation == "cert_delete":
        result["removed"] = ["a-certificate-no-row-names"]
    elif operation == "cert_scep":
        result["domains"] = ["*." + str(result["domains"][0])]
    elif operation == "backup_run":
        result["nodes"][0]["outcome"] = "failed"
    elif operation == "backup_schedule":
        result["schedule"]["calendar"] = "*-*-* 00:00:00"
    elif operation == "cert_receiver":
        result["layers"] = [{"layer": "account", "state": "failed", "detail": "userdel: busy"}]
    elif operation == "node_restore_prepare":
        result["mode"] = "new_vm"
    elif operation == "node_restore_preview":
        result["problems"] = [] if result["problems"] else ["a problem the outcome ignores"]
    elif operation == "node_restore_discard":
        invalid["outcome"] = "blocked"
    elif operation == "node_restore":
        if invalid["outcome"] == "done":
            result["rolled_back"] = True
        else:
            result.pop("stage", None)
    else:
        raise AssertionError(f"no semantic mutation defined for {operation}")

    return invalid


class NotApplicable(Exception):
    """This mutation has nothing to change in this particular fixture.

    Raised rather than returning quietly, because a mutation that silently did
    nothing would be indistinguishable from one that is broken. The run tracks
    which mutations fired at least once and fails if any never did, so an
    optional block can have its own fixture without weakening the guarantee
    that every rule here is actually exercised.
    """


def claim_current_on_an_empty_receiver(document: dict[str, object]) -> None:
    """The lie the C5 listing must not be able to tell.

    `published_at` is the manager's own write and `current` compares it with the
    source. A target nothing was ever written to cannot be carrying the current
    certificate, and a document saying so did not come from this engine.
    """

    result = document["result"]
    assert isinstance(result, dict)
    for entry in result.get("registry", {}).get("certificates", ()):
        for receiver in entry["targets"]["receivers"]:
            receiver["published_at"] = None
            receiver["current"] = True
            return
    raise NotApplicable


def drop_the_shared_distribution_copy(document: dict[str, object]) -> None:
    """A certificate a cluster reads always has a shared copy to report on."""

    result = document["result"]
    assert isinstance(result, dict)
    for entry in result.get("registry", {}).get("certificates", ()):
        if entry["targets"]["clusters"]:
            entry["distribution"] = None
            return
    raise NotApplicable


def flip_release_state(document: dict[str, object]) -> None:
    result = document["result"]
    assert isinstance(result, dict)
    summary = result["summary"]
    summary["release_state"] = "converged" if summary["release_state"] != "converged" else "behind"


def flip_node_current(document: dict[str, object]) -> None:
    result = document["result"]
    assert isinstance(result, dict)
    node = result["nodes"][0]
    node["current"] = not node["current"] if isinstance(node["current"], bool) else True


#
# One mutation per document is enough to prove a check exists, but not to prove
# which check. These are the extra ones for rules added after the framework was
# written: without them a document whose release comparison is nonsense would be
# caught by whichever earlier assertion happened to fire first, and the rule the
# fixture is here to defend would never be exercised.
#
EXTRA_MUTATIONS: dict[str, tuple[Callable[[dict[str, object]], None], ...]] = {
    "status": (flip_release_state, flip_node_current),
    "cert_list": (claim_current_on_an_empty_receiver, drop_the_shared_distribution_copy),
}


def format_errors(errors: list[object]) -> str:
    lines = []
    for error in errors:
        location = "/".join(str(part) for part in error.absolute_path) or "<root>"
        lines.append(f"  {location}: {error.message}")
    return "\n".join(lines)


def main() -> int:
    registry, schemas = build_registry()
    valid_count = 0
    invalid_count = 0
    generated_count = 0
    contract_count = 0
    exercised: set[str] = set()

    for schema_id, schema in sorted(schemas.items()):
        if schema_id.endswith("/common.schema.json"):
            continue

        command = Path(schema_id).name.removesuffix(".schema.json")
        fixture_dir = FIXTURE_ROOT / command
        valid_paths = sorted((fixture_dir / "valid").glob("*.json"))
        if not valid_paths:
            raise AssertionError(f"{command}: at least one valid fixture is required")

        validator = Draft202012Validator(
            schema,
            registry=registry,
            format_checker=FormatChecker(),
        )

        for path in valid_paths:
            document = load_json(path)
            errors = sorted(validator.iter_errors(document), key=lambda error: list(error.path))
            if errors:
                raise AssertionError(f"{path}: expected valid fixture\n{format_errors(errors)}")
            assert isinstance(document, dict)
            operation = document["operation"]
            SEMANTIC_CHECKS[operation](document, path)
            valid_count += 1

            unsupported = deepcopy(document)
            unsupported["schema_version"] = 2
            if not list(validator.iter_errors(unsupported)):
                raise AssertionError(f"{path}: schema_version 2 must be rejected by v1")
            invalid_count += 1

            semantic_invalid = make_semantically_invalid(document)
            try:
                SEMANTIC_CHECKS[operation](semantic_invalid, path)
            except AssertionError:
                invalid_count += 1
            else:
                raise AssertionError(f"{path}: semantic mutation was not rejected")

            for mutate in EXTRA_MUTATIONS.get(str(operation), ()) if document["result"] else ():
                mutated = deepcopy(document)
                try:
                    mutate(mutated)
                except NotApplicable:
                    continue
                exercised.add(mutate.__name__)
                if mutated == document:
                    raise AssertionError(f"{path}: {mutate.__name__} changed nothing")
                try:
                    SEMANTIC_CHECKS[operation](mutated, path)
                except AssertionError:
                    invalid_count += 1
                else:
                    raise AssertionError(f"{path}: {mutate.__name__} was not rejected")

            failed = deepcopy(document)
            failed.update(
                {
                    "ok": False,
                    "outcome": "failed",
                    "cluster": None,
                    "result": None,
                    "warnings": [],
                    "error": {
                        "code": "bad_input",
                        "message": "Generated invalid-input contract test",
                    },
                }
            )
            errors = list(validator.iter_errors(failed))
            if errors:
                raise AssertionError(
                    f"{path}: generated failed envelope is invalid\n{format_errors(errors)}"
                )
            SEMANTIC_CHECKS[operation](failed, path)
            generated_count += 1

            if operation in ("publish", "revert", "deploy", "cert_deploy"):
                blocked = deepcopy(failed)
                blocked.update(
                    {
                        "cluster": document["cluster"],
                        "outcome": "blocked",
                        "error": {
                            "code": "operation_locked",
                            "message": "Another operation holds the cluster lock",
                        },
                    }
                )
                errors = list(validator.iter_errors(blocked))
                if errors:
                    raise AssertionError(
                        f"{path}: generated blocked envelope is invalid\n{format_errors(errors)}"
                    )
                generated_count += 1

        for path in sorted((fixture_dir / "invalid").glob("*.json")):
            document = load_json(path)
            errors = list(validator.iter_errors(document))
            if not errors:
                raise AssertionError(f"{path}: expected schema validation to fail")
            invalid_count += 1

        contract_count += 1

    if contract_count == 0 or valid_count == 0 or invalid_count == 0:
        raise AssertionError("schemas plus valid and invalid coverage are required")

    #
    # A mutation that never applied to any fixture proves nothing, and looks
    # exactly like one that is quietly broken. Either the rule needs a fixture
    # shaped for it or the mutation does not belong here.
    #
    never = sorted(
        mutate.__name__
        for mutations in EXTRA_MUTATIONS.values()
        for mutate in mutations
        if mutate.__name__ not in exercised
    )
    if never:
        raise AssertionError(f"extra mutations never applied to any fixture: {', '.join(never)}")

    print(
        "contracts: OK "
        f"(contracts={contract_count}, schemas={len(schemas)}, "
        f"valid={valid_count}, generated={generated_count}, invalid={invalid_count})"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"contracts: FAILED: {exc}", file=sys.stderr)
        raise
