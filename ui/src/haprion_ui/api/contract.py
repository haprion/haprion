"""The API's contract: one JSON Schema per operation, the same files the tests hold the routes to.

`schemas/<operation>.schema.json` describes the envelope's `result` of a done
answer; `refusal.schema.json` the envelope of every other. `/api/v1` adds
fields and never removes or renames one, so these files are the promise, and
`tests/test_api_contract.py` is what makes a route keep it.

The files live in the package, not beside the CLI's under the repository's
`schemas/`: the wheel carries what the service reads at import, and one copy
is the only way two readers cannot drift. OpenAPI cannot follow a `$ref` to a
file, so the schemas are laid out in full here.
"""

from __future__ import annotations

import json
from functools import cache
from importlib import resources
from typing import Any

DEFINITIONS = "definitions.schema.json"
REFUSAL = "refusal.schema.json"
SUFFIX = ".schema.json"


def _directory() -> Any:
    return resources.files("haprion_ui").joinpath("api", "schemas")


@cache
def document(name: str) -> dict[str, Any]:
    """One schema file, as written; `name` is the file's name."""

    loaded = json.loads(_directory().joinpath(name).read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError(f"{name} is not a JSON Schema object")
    return loaded


def operations() -> tuple[str, ...]:
    """Every operation that has a schema: the route names."""

    return tuple(
        sorted(
            entry.name.removesuffix(SUFFIX)
            for entry in _directory().iterdir()
            if entry.name.endswith(SUFFIX) and entry.name not in {DEFINITIONS, REFUSAL}
        )
    )


def _pointed(source: dict[str, Any], pointer: str) -> Any:
    found: Any = source
    for part in pointer.split("/")[1:]:
        found = found[part]
    return found


def _laid_out(node: Any, within: str) -> Any:
    """The schema with every `$ref` replaced by what it names; a sibling keyword wins."""

    if isinstance(node, list):
        return [_laid_out(item, within) for item in node]
    if not isinstance(node, dict):
        return node
    if "$ref" not in node:
        return {key: _laid_out(item, within) for key, item in node.items()}
    name, _, pointer = str(node["$ref"]).partition("#")
    target = name or within
    found = _pointed(document(target), pointer) if pointer else _top(document(target))
    siblings = {key: _laid_out(item, within) for key, item in node.items() if key != "$ref"}
    return {**_laid_out(found, target), **siblings}


def _top(schema: dict[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in schema.items() if key not in {"$schema", "$id", "$defs"}}


def _described(name: str) -> dict[str, Any]:
    return _top(_laid_out(_top(document(name)), name))


def _answer(operation: str) -> dict[str, Any]:
    """The whole envelope of a done answer, with the operation's result in it."""

    return {
        "type": "object",
        "description": "The contract's envelope; the operation's answer is in result.",
        "required": [
            "schema_version",
            "ok",
            "outcome",
            "operation",
            "cluster",
            "request_id",
            "result",
            "warnings",
            "error",
        ],
        "properties": {
            "schema_version": {"const": 1},
            "ok": {"const": True},
            "outcome": {"const": "done"},
            "operation": {"const": operation},
            "cluster": {
                "type": ["string", "null"],
                "description": "Value. The cluster the call was about; null where it was about none.",
            },
            "request_id": {"type": "string", "format": "uuid"},
            "result": _described(f"{operation}{SUFFIX}"),
            "warnings": {"type": "array", "items": {"type": "object"}},
            "error": {"type": "null"},
        },
    }


def responses(operation: str) -> dict[int | str, dict[str, Any]]:
    """The route's responses for OpenAPI: its answer, and the refusal every route may give."""

    return {
        200: {
            "description": "The operation's result, in the contract's envelope.",
            "content": {"application/json": {"schema": _answer(operation)}},
        },
        "default": {
            "description": "A refusal: the envelope with ok false and error.code saying which.",
            "content": {"application/json": {"schema": _described(REFUSAL)}},
        },
    }
