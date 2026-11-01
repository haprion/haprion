"""A call is refused for a query parameter it does not take (review 26-11-01, c-P3-3).

FastAPI leaves an undeclared parameter alone, so `?since=` for `?from=` was
answered with the last hour and looked filtered. A script that is told what it
asked for was not understood can mend the call; one that is silently given
something else cannot know. The body models already refuse an unknown field.
"""

from __future__ import annotations

from fastapi import Depends, Request
from fastapi.dependencies.models import Dependant
from fastapi.routing import APIRoute

from haprion_ui.api.answers import Refusal
from haprion_ui.api.caller import Caller, current_caller


def _declared(dependant: Dependant) -> set[str]:
    """The query parameters a route takes, its own and those of what it depends on."""

    names = {field.alias for field in dependant.query_params}
    for each in dependant.dependencies:
        names |= _declared(each)
    return names


def only_declared_parameters(
    request: Request,
    caller: Caller = Depends(current_caller),  # noqa: B008
) -> None:
    """Refuse a query parameter the route does not declare, after the token is judged.

    Behind `current_caller` so that a call without a valid token is the same
    401 whatever it carries; FastAPI runs that dependency once for both.
    """

    del caller
    #
    # A NUL byte cannot be a PostgreSQL text value: left alone it is a 500 where
    # a parameter reaches a query (26-11-01).
    #
    for value in (*request.query_params.values(), *request.path_params.values()):
        if isinstance(value, str) and "\x00" in value:
            raise Refusal(400, "bad_input", "A parameter holds a character no value can.")
    route = request.scope.get("route")
    if not isinstance(route, APIRoute):
        return
    declared = _declared(route.dependant)
    unknown = sorted(set(request.query_params) - declared)
    if unknown:
        raise Refusal(400, "bad_input", f"Not a parameter of this call: {', '.join(unknown)}.")
