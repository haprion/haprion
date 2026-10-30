"""Validate what a tool actually printed against the frozen v1 schemas.

The same check as `tests/contract_schema.py` of the engine, for the interface's
root tools (`haprion-user`, `-settings`, `-profiles`, `-export`): their tests
compared the keys of a document with a fixture, which holds neither types nor
enumerations nor `required` (review 26-10-30, E11). Needs `jsonschema`, which
the dev group of this distribution carries.
"""

from __future__ import annotations

import json
from functools import cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

SCHEMA_DIR = Path(__file__).resolve().parents[2] / "schemas" / "v1"


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
