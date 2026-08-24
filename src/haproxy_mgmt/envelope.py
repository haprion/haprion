from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any, Literal

Outcome = Literal["done", "partial", "failed", "blocked"]


@dataclass(frozen=True, slots=True)
class Message:
    code: str
    message: str
    node: str | None = None
    details: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "node": self.node,
            "details": self.details,
        }


def new_request_id() -> str:
    return str(uuid.uuid4())


def envelope(
    *,
    operation: str,
    outcome: Outcome,
    cluster: str | None,
    result: dict[str, Any] | None,
    request_id: str | None = None,
    warnings: tuple[Message, ...] = (),
    error: Message | None = None,
) -> dict[str, Any]:
    if outcome == "done" and error is not None:
        raise ValueError("done cannot contain a top-level error")
    if outcome == "partial" and (not warnings or error is not None):
        raise ValueError("partial requires warnings and a null top-level error")
    if outcome in ("failed", "blocked") and error is None:
        raise ValueError("failed and blocked require a top-level error")

    return {
        "schema_version": 1,
        "ok": outcome == "done",
        "outcome": outcome,
        "operation": operation,
        "cluster": cluster,
        "request_id": request_id or new_request_id(),
        "result": result,
        "warnings": [warning.as_dict() for warning in warnings],
        "error": error.as_dict() if error is not None else None,
    }
