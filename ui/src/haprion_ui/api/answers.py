"""What the API answers: the contract's envelope, as the engine's commands write it.

`ok`, `outcome`, `operation`, `request_id`, `result`, `warnings` and `error`
(§1.3), so a script that reads `haprion` JSON reads this the same way. The
HTTP status says the kind of answer; `error.code` says which, in the words
the commands use.
"""

from __future__ import annotations

from typing import Any

from fastapi import Request
from fastapi.responses import JSONResponse
from haprion.envelope import Message, envelope


class Refusal(Exception):
    """An answer that is not a result: raised anywhere a route runs, answered as JSON."""

    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        *,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.headers = headers or {}


def operation_of(request: Request) -> str:
    """The route's name, which is the operation the envelope reports."""

    route = request.scope.get("route")
    return getattr(route, "name", None) or "api"


def answer(
    request: Request,
    result: dict[str, Any],
    *,
    cluster: str | None = None,
    status: int = 200,
) -> JSONResponse:
    return JSONResponse(
        envelope(
            operation=operation_of(request),
            outcome="done",
            cluster=cluster,
            result=result,
        ),
        status_code=status,
    )


def refusal(request: Request, refused: Refusal) -> JSONResponse:
    #
    # A refusal before anything was done is `blocked`; a failure of this side
    # (a 5xx) is `failed`, as the commands' exit codes say.
    #
    return JSONResponse(
        envelope(
            operation=operation_of(request),
            outcome="failed" if refused.status >= 500 else "blocked",
            cluster=request.path_params.get("cluster"),
            result=None,
            error=Message(code=refused.code, message=refused.message),
        ),
        status_code=refused.status,
        headers=refused.headers,
    )
