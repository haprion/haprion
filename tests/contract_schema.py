"""Validate what a helper actually printed against the frozen v1 schemas.

The contract suite validates the fixtures, which proves the schemas describe the
documents somebody wrote by hand. It cannot prove that a helper emits one. That
gap is not theoretical: the revert helper printed a document of its own design
for months, valid JSON and completely outside its contract, and every test
passed because they all read the human output the caller printed afterwards.
"""

from __future__ import annotations

import json
from functools import cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

SCHEMA_DIR = Path(__file__).resolve().parents[1] / "schemas" / "v1"


@cache
def _registry() -> Registry:
    registry = Registry()
    for path in sorted(SCHEMA_DIR.glob("*.schema.json")):
        schema = json.loads(path.read_text(encoding="utf-8"))
        registry = registry.with_resource(str(schema["$id"]), Resource.from_contents(schema))
    return registry


@cache
def _validator(command: str) -> Draft202012Validator:
    schema = json.loads((SCHEMA_DIR / f"{command}.schema.json").read_text(encoding="utf-8"))
    return Draft202012Validator(schema, registry=_registry(), format_checker=FormatChecker())


def assert_contract(command: str, stdout: str) -> dict[str, Any]:
    """Parse one helper's stdout and hold it to `schemas/v1/<command>`.

    Returns the parsed document so a test can go on to assert what it says, not
    only that it is well formed.
    """

    document = json.loads(stdout)
    errors = sorted(_validator(command).iter_errors(document), key=lambda error: error.path)
    if errors:
        detail = "\n".join(f"  {list(error.path)}: {error.message}" for error in errors)
        raise AssertionError(f"{command} document does not match its frozen schema:\n{detail}")
    if not isinstance(document, dict):
        raise AssertionError(f"{command} document is not an object")
    return document


def published(_request: object, _cluster: object, **_options: object) -> dict[str, object]:
    """A node helper's publication in a test that is about the node change (B318)."""

    return {"version": 2, "hash": "c" * 40, "changed": True}
