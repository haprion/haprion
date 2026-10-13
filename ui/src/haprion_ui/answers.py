"""Whether a helper's answer is the v1 envelope of the request that was asked.

One definition for the worker and the poller. They checked the same envelope
two ways: the worker bound it to its request and its cross-fields, the poller
to the operation and an outcome only, so a helper answering for another
cluster became a cached `done` (review 26-10-13, K3). What each operation's
`result` holds stays with the module that reads it.
"""

from __future__ import annotations

import json
from collections.abc import Collection
from typing import Any, cast

REQUIRED_FIELDS = frozenset(
    {
        "schema_version",
        "ok",
        "outcome",
        "operation",
        "cluster",
        "request_id",
        "result",
        "warnings",
        "error",
    }
)


class _Invalid(ValueError):
    """The document is not one result a caller may accept."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise _Invalid("duplicate field")
        value[key] = item
    return value


def _finite_number(_value: str) -> None:
    raise _Invalid("non-finite number")


def is_message(value: Any) -> bool:
    """A structured warning or error: a non-empty code and message."""

    return (
        isinstance(value, dict)
        and isinstance(value.get("code"), str)
        and bool(value["code"])
        and isinstance(value.get("message"), str)
        and bool(value["message"])
    )


def accepted(
    stdout: str,
    *,
    operation: str,
    cluster: str | None,
    request_id: str,
    outcomes: Collection[str],
) -> dict[str, Any] | None:
    """The envelope when it answers exactly this request, otherwise None."""

    try:
        parsed = json.loads(
            stdout,
            object_pairs_hook=_unique_object,
            parse_constant=_finite_number,
        )
    except (json.JSONDecodeError, TypeError, _Invalid):
        return None
    if not isinstance(parsed, dict):
        return None
    envelope = cast(dict[str, Any], parsed)
    if not REQUIRED_FIELDS.issubset(envelope):
        return None
    if type(envelope["schema_version"]) is not int or envelope["schema_version"] != 1:
        return None
    if envelope["operation"] != operation:
        return None
    if envelope["cluster"] != cluster:
        return None
    if envelope["request_id"] != request_id:
        return None

    outcome = envelope["outcome"]
    if not isinstance(outcome, str) or outcome not in outcomes:
        return None
    if not isinstance(envelope["ok"], bool):
        return None
    warnings = envelope["warnings"]
    if not isinstance(warnings, list) or not all(is_message(item) for item in warnings):
        return None

    error = envelope["error"]
    if outcome == "done":
        valid_cross_fields = envelope["ok"] and error is None
    elif outcome == "partial":
        valid_cross_fields = not envelope["ok"] and bool(warnings) and error is None
    else:
        valid_cross_fields = not envelope["ok"] and is_message(error)
    if not valid_cross_fields:
        return None
    if outcome in {"done", "partial"} and not isinstance(envelope["result"], dict):
        return None
    return envelope
