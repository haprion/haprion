"""The web service. Read-only until a deployment says otherwise.

Phase 4 installs the platform without management writes, so this starts with the
write path switched off and reports that it is off. The flag lives in
configuration rather than in a release, because the documented rollback for the
write path is to turn it off and be back in a read-only interface - and that is
not a rollback that should require a build.

The health endpoint answers with the identity the database reports rather than
the one this process believes it has, and judges it (B332): the configured
database, a role holding the web's grants, and a schema this release runs on.
Running as the wrong role otherwise looks exactly like running correctly, right
up until something is denied or, worse, allowed.
"""

from __future__ import annotations

import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import psycopg
from fastapi import FastAPI, Request
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool

from haprion_ui import compatibility, db, page_headers, pages, timing, views
from haprion_ui.config import DEFAULT_CONFIG_PATH, Config
from haprion_ui.config import load as load_config

CONFIG_PATH_VARIABLE = "HAPRION_UI_CONFIG"
STATIC_DIRECTORY = Path(__file__).parent / "static"

logger = logging.getLogger("haprion_ui")


def _config_path() -> Path:
    return Path(os.environ.get(CONFIG_PATH_VARIABLE, str(DEFAULT_CONFIG_PATH)))


#
# The schema revisions this release runs on, from the file the installer and
# `check-compatibility` read - one definition of compatible, not two.
#
REQUIREMENTS = Path(__file__).with_name("compatibility.json")


def health_problem(
    found: db.Health, *, database: str, requirements: compatibility.Requirements
) -> tuple[str, str] | None:
    """Why this process cannot do its job, as (code, message); None when it can.

    A revision newer than this release's head is accepted: that is a rollback
    onto a schema whose migrations were declared safe for it, a decision the
    rollback command made. Older than every revision the release runs on, or
    none at all, is a database the release was never migrated against.
    """

    if found.database != database:
        return "wrong_database", f"connected to {found.database}, configured for {database}"
    if not found.web:
        return "wrong_role", f"{found.identity} does not hold the web's grants (app_web)"
    if found.revision is None:
        return "schema_missing", "the database has no schema revision; it was never migrated"
    accepted = requirements.database_revisions
    if found.revision not in accepted and not found.revision > requirements.database_head:
        return (
            "schema_not_accepted",
            f"schema revision {found.revision} is not one this release runs on "
            f"({accepted[0]}..{requirements.database_head})",
        )
    return None


def create_app(config: Config | None = None) -> FastAPI:
    """Build the application. Reads configuration; connects to nothing.

    The pool is opened in the lifespan rather than here, so importing this
    module - which tests, tooling and `--help` all do - never reaches for a
    database. A failure to connect then happens at startup, where it is reported
    and where systemd can see it.
    """

    config_path = _config_path()
    settings = config if config is not None else load_config(config_path)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        #
        # Six rather than the default four: a traffic page reads its cards on
        # `TRAFFIC_READERS` connections at once, and the rest of the interface
        # must still find one while it does.
        #
        connections = db.pool(settings.database, max_size=6)
        connections.open(wait=True, timeout=10)
        app.state.pool = connections
        try:
            yield
        finally:
            connections.close()

    app = FastAPI(title="Haprion", lifespan=lifespan, docs_url=None, redoc_url=None)
    app.state.config = settings
    app.mount("/static", StaticFiles(directory=str(STATIC_DIRECTORY)), name="static")

    #
    # Said out loud, every start, because a session cookie without Secure is a
    # session that can be taken off the wire - and the setting exists only so a
    # developer instance on loopback is usable at all. A quiet installation
    # running this way in production is exactly what this line is for.
    #
    if not settings.session.cookie_secure:
        logger.warning(
            "session.cookie_secure is off: the session cookie will be sent over plain HTTP"
        )

    app.include_router(pages.build_router(settings))

    #
    # A form the framework refuses is answered as a page (CR-06); anything
    # else keeps FastAPI's JSON answer.
    #
    @app.exception_handler(RequestValidationError)
    async def form_errors(request: Request, exc: RequestValidationError) -> Response:
        kind = request.headers.get("content-type", "")
        if not kind.startswith(("application/x-www-form-urlencoded", "multipart/form-data")):
            return await request_validation_exception_handler(request, exc)
        return await run_in_threadpool(views.form_refusal, request, settings, exc.errors())

    #
    # A database that does not answer - gone, out of connections, or a query
    # past its time limit - is a page that says so, not a bare 500 (review
    # 2026-10-20, U2). PoolTimeout and QueryCanceled are both OperationalError.
    #
    @app.exception_handler(psycopg.OperationalError)
    async def database_errors(request: Request, exc: psycopg.OperationalError) -> Response:
        return views.database_unavailable(request, exc)

    #
    # Each response says where its time went (`timing`): in a header for the
    # browser's network panel and in a line in the service log. The line is
    # wired only for the service itself, which builds from the installed file;
    # a test passes its own configuration and keeps its output to itself.
    #
    if config is None:
        timing.log_handler()
    app.add_middleware(timing.TimingMiddleware)
    app.add_middleware(page_headers.PageHeadersMiddleware)

    requirements = compatibility.load_requirements(REQUIREMENTS)

    @app.get("/healthz")
    def healthz() -> JSONResponse:
        """Whether this process can do its job, and as whom.

        Deliberately more than "ok". An interface that answers 200 while
        connected as the wrong role, or while pointed at an empty database, is
        an interface that will fail later and elsewhere - so both are checked,
        with the schema's revision, and either is a 503 that says which.
        """

        body: dict[str, Any] = {
            "schema_version": 1,
            "ok": False,
            "database": None,
            "identity": None,
            "schema_revision": None,
            "management_writes": settings.management_writes,
        }
        try:
            with app.state.pool.connection() as connection:
                found = db.health(connection)
        except Exception as exc:  # noqa: BLE001 - any failure to reach the database is one answer
            #
            # The exception goes to the log, not to the caller. /healthz is
            # unauthenticated and reachable through nginx, and a psycopg error
            # names the socket, the role and whatever PostgreSQL wanted to say -
            # which is a description of the inside of the machine handed to
            # anyone who asks.
            #
            # The operator loses nothing: the detail is in the service log,
            # where they are already looking when a health check goes red.
            #
            logger.warning("healthz: the database did not answer: %s", exc)
            body["error"] = {
                "code": "database_unavailable",
                "message": "the database did not answer; the detail is in the service log",
            }
            return JSONResponse(body, status_code=503)

        body.update(
            {
                "identity": found.identity,
                "database": found.database,
                "schema_revision": found.revision,
            }
        )
        problem = health_problem(found, database=settings.database.name, requirements=requirements)
        if problem is not None:
            code, message = problem
            logger.warning("healthz: %s", message)
            body["error"] = {"code": code, "message": message}
            return JSONResponse(body, status_code=503)
        body["ok"] = True
        return JSONResponse(body)

    return app
