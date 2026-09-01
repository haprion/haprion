#!/usr/bin/env python3

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from copy import deepcopy
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

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


SEMANTIC_CHECKS = {
    "status": check_status_semantics,
    "list": check_list_semantics,
    "cert_list": check_cert_list_semantics,
    "network": check_network_semantics,
    "list_backups": check_backup_semantics,
    "inventory": check_inventory_semantics,
    "publish": check_publish_semantics,
    "revert": check_revert_semantics,
    "network_publish": check_network_publish_semantics,
    "deploy": check_reconcile_semantics,
    "cert_deploy": check_reconcile_semantics,
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
    elif operation in ("publish", "revert", "network_publish"):
        result["deployment_required"] = False
    elif operation == "deploy":
        result["converged"] = True
    elif operation == "cert_deploy":
        result["converged"] = False
    else:
        raise AssertionError(f"no semantic mutation defined for {operation}")

    return invalid


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
                mutate(mutated)
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
