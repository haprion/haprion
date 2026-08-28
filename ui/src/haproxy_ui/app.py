"""The web service. Read-only until a deployment says otherwise.

Phase 4 installs the platform without management writes, so this starts with the
write path switched off and reports that it is off. The flag lives in
configuration rather than in a release, because the documented rollback for the
write path is to turn it off and be back in a read-only interface - and that is
not a rollback that should require a build.

The health endpoint answers with the identity the database reports rather than
the one this process believes it has. Running as the wrong role otherwise looks
exactly like running correctly, right up until something is denied or, worse,
allowed.
"""

from __future__ import annotations

import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from haproxy_ui import db, views
from haproxy_ui.config import DEFAULT_CONFIG_PATH, Config
from haproxy_ui.config import load as load_config

CONFIG_PATH_VARIABLE = "HAPROXY_UI_CONFIG"

logger = logging.getLogger("haproxy_ui")


def _config_path() -> Path:
    return Path(os.environ.get(CONFIG_PATH_VARIABLE, str(DEFAULT_CONFIG_PATH)))


def create_app(config: Config | None = None) -> FastAPI:
    """Build the application. Reads configuration; connects to nothing.

    The pool is opened in the lifespan rather than here, so importing this
    module - which tests, tooling and `--help` all do - never reaches for a
    database. A failure to connect then happens at startup, where it is reported
    and where systemd can see it.
    """

    settings = config if config is not None else load_config(_config_path())

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        connections = db.pool(settings.database)
        connections.open(wait=True, timeout=10)
        app.state.pool = connections
        try:
            yield
        finally:
            connections.close()

    app = FastAPI(title="HAProxy Manager", lifespan=lifespan, docs_url=None, redoc_url=None)
    app.state.config = settings

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

    app.include_router(views.build_router(settings))

    @app.get("/healthz")
    def healthz() -> JSONResponse:
        """Whether this process can do its job, and as whom.

        Deliberately more than "ok". An interface that answers 200 while
        connected as the wrong role, or while pointed at an empty database, is
        an interface that will fail later and elsewhere.
        """

        body: dict[str, Any] = {
            "schema_version": 1,
            "ok": False,
            "database": None,
            "identity": None,
            "management_writes": settings.management_writes,
        }
        try:
            with app.state.pool.connection() as connection:
                identity, database = db.connected_identity(connection)
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

        body.update({"ok": True, "identity": identity, "database": database})
        return JSONResponse(body)

    return app
