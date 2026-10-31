"""The API (B416): `/api/v1/`, a bearer token, JSON in and out.

A FastAPI application of its own, mounted beside the pages rather than among
them, for three reasons that are each a boundary:

* **Its refusals are JSON.** The pages answer a refusal with a page; a script
  reading the API is given the envelope, never HTML.
* **It reads no cookie.** Nothing under `/api/` depends on the session, so
  there is no CSRF to defend; nothing outside it reads a bearer token.
* **It has a schema.** `/api/v1/openapi.json`, generated from these routes
  and given only to a valid token, where the pages publish none.

The pool is the pages' own: `app.create_app` hands it over when it opens, and
the API may use `CONCURRENT_CALLS` of its connections at once.
"""

from __future__ import annotations

import logging
import threading

import psycopg
from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from starlette.exceptions import HTTPException as StarletteHTTPException

from haprion_ui.api import (
    blocks,
    certificates,
    changes,
    clusters,
    jobs,
    objects,
    servers,
    token,
    traffic,
    waf,
)
from haprion_ui.api.answers import Refusal, refusal
from haprion_ui.api.caller import CONCURRENT_CALLS, Caller, current_caller
from haprion_ui.config import Config

PREFIX = "/api/v1"

logger = logging.getLogger("haprion_ui.api")


def build_api(config: Config) -> FastAPI:
    api = FastAPI(
        title="Haprion API",
        version="1",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    api.state.config = config
    api.state.slots = threading.BoundedSemaphore(CONCURRENT_CALLS)

    @api.exception_handler(Refusal)
    async def refused(request: Request, exc: Refusal) -> Response:
        return refusal(request, exc)

    @api.exception_handler(StarletteHTTPException)
    async def http_errors(request: Request, exc: StarletteHTTPException) -> Response:
        codes = {404: "not_found", 405: "method_not_allowed"}
        return refusal(
            request,
            Refusal(exc.status_code, codes.get(exc.status_code, "refused"), str(exc.detail)),
        )

    #
    # Which field, never the value: a body is the caller's, and echoing it
    # back is how a log or a proxy ends up holding what it should not.
    #
    @api.exception_handler(RequestValidationError)
    async def bad_input(request: Request, exc: RequestValidationError) -> Response:
        fields = sorted({".".join(str(part) for part in error["loc"]) for error in exc.errors()})
        return refusal(request, Refusal(400, "bad_input", f"Not valid: {', '.join(fields)}."))

    @api.exception_handler(psycopg.OperationalError)
    async def database_errors(request: Request, exc: psycopg.OperationalError) -> Response:
        logger.warning(
            "api: %s %s: the database did not answer: %s", request.method, request.url.path, exc
        )
        return refusal(
            request,
            Refusal(503, "database_unavailable", "The database did not answer; try again shortly."),
        )

    #
    # Anything else is this side's fault: logged with its traceback, answered
    # in the envelope without one, so a script is never handed a text page.
    #
    @api.exception_handler(Exception)
    async def unexpected(request: Request, exc: Exception) -> Response:
        logger.error("api: %s %s failed", request.method, request.url.path, exc_info=exc)
        return refusal(
            request, Refusal(500, "internal_error", "The request failed on the manager.")
        )

    for module in (
        token,
        clusters,
        objects,
        changes,
        certificates,
        blocks,
        servers,
        traffic,
        waf,
        jobs,
    ):
        api.include_router(module.router)

    @api.get("/openapi.json", include_in_schema=False)
    def openapi(caller: Caller = Depends(current_caller)) -> JSONResponse:  # noqa: B008
        del caller
        return JSONResponse(api.openapi())

    return api
