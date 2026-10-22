"""How a migration connects, and as whom.

There is no model metadata here and no autogenerate. The schema is described
once, as SQL, in the migrations themselves - because the parts that matter most
in this database are the parts autogenerate cannot see. Column-level grants,
CHECK constraints used as allowlists and `server_default` are the privilege
boundary, and a model beside them that does not describe them is a second
description that can quietly disagree with the first.

The `server_default` case is the sharp one: the database sets a job's state,
request ID and timestamps precisely so the web role cannot choose them. Written
as a client-side default instead, the value is chosen by the application - the
same schema on paper, and a guarantee silently turned into a convention.
"""

from __future__ import annotations

import os

from alembic import context
from sqlalchemy import engine_from_config, pool

config = context.config

VARIABLE = "HAPRION_UI_DATABASE_URL"


def _url() -> str:
    """The connection, supplied rather than guessed.

    There is no default, and the missing default is the point. libpq asks for a
    role named after the operating-system user unless the URL says otherwise, so
    a URL with the role left out connects root as a role called "root" - which
    does not exist, and on a host where it did would be the wrong one. A default
    here would be a guess at deployment data that this repository must not hold
    anyway: the role name is configuration.

    `install/platform/migrate` builds it from the installation's fixed names. Connecting is
    over the local socket with peer authentication and the ident map, so there
    is no password in the URL, the environment, or a process listing.
    """

    url = os.environ.get(VARIABLE, "")
    if not url:
        raise SystemExit(
            f"{VARIABLE} is not set. Run migrations through "
            "install/platform/migrate, which builds it from the installation's fixed names."
        )
    return url


def run_migrations_offline() -> None:
    context.configure(url=_url(), literal_binds=True, dialect_opts={"paramstyle": "named"})
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    section = config.get_section(config.config_ini_section, {})
    section["sqlalchemy.url"] = _url()
    #
    # A lock waited for at most half a minute. A migration queued behind
    # something holding its table - the nightly retention dropping a partition,
    # a long read - holds every query that arrives after it, the web's
    # included, for as long as it waits; with a limit the release stops and
    # says so, and can be run again (review 2026-10-22, D).
    #
    connectable = engine_from_config(
        section,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
        connect_args={"options": "-c lock_timeout=30s"},
    )

    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=None)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
