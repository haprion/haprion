from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any, Literal, cast

from haprion import exit_codes

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


def outcome_for_exit(exit_code: int) -> Outcome:
    """The outcome a failure's exit code stands for: `blocked` or `failed`.

    Helpers used to decide this at each error site, which is how several early
    failures ended up writing nothing at all: the decision was small enough to
    forget. The table is `exit_codes`; a failure with `OK` or `PARTIAL` is a
    contradiction, and `envelope` refuses it.
    """

    return cast(Outcome, exit_codes.outcome(exit_code))


def failure(
    *,
    operation: str,
    cluster: str | None,
    request_id: str,
    code: str,
    message: str,
    exit_code: int,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """The envelope a helper owes its caller when it refuses or fails.

    JSON mode promises exactly one document on stdout on every path. A helper
    that returned an exit code and a line of stderr instead left the worker with
    nothing to record but `unknown`, which reads as "the operation may have taken
    effect" - the opposite of what a refusal before any write actually means.
    """

    return envelope(
        operation=operation,
        outcome=outcome_for_exit(exit_code),
        cluster=cluster,
        result=None,
        request_id=request_id,
        error=Message(code=code, message=message[:2048], details=details),
    )
