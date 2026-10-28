"""What every page shares: sessions, cookies, the poller's readings, templates and gates.

The pages themselves are in `haprion_ui.pages`, one module per area; they read
from here and this module reads nothing of theirs.

The rules that shape every handler:

* **The client address comes from a header nginx overwrites**, never from one a
  client can contribute to. The site config sets `X-Forwarded-For` to the peer
  address rather than appending to it, so what arrives here is one address that
  a request cannot lie about. If it is missing or unparseable, the peer address
  is used and the request is still served - the throttle must not be the reason
  the interface stops working.
* **Failures say one thing.** Unknown account, wrong password, disabled account
  and a throttled address all render the same sentence. Anything else turns the
  form into a way to learn which usernames exist and which are locked.
* **Every state-changing request carries a CSRF token**, including logout. A
  forced logout is a small attack, but an exception in the rule is how the rule
  stops being checkable.
"""

from __future__ import annotations

import io
import logging
import zipfile
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlencode
from uuid import UUID, uuid4

import anyio
from fastapi import File, Form, Request, Response
from fastapi.responses import (
    PlainTextResponse,
    RedirectResponse,
)
from haprion import (
    crs,
    proxy_model,
)
from haprion.certificates import CERTIFICATE_OPENING
from haprion.config import CERTIFICATE_ID
from haprion.digits import is_digits
from haprion.dns_profile_keys import DnsProfilePublicKey, KeyFileError, read_public_key
from haprion.proxy_model import (
    ModelError,
    load_written,
)
from starlette.datastructures import FormData

from haprion_ui import (
    attention,
    auth,
    backups,
    certificates,
    dashboard,
    db,
    features,
    first_cluster,
    health,
    jobs,
    metrics,
    moments,
    network,
    objects,
    oidc_web,
    operations,
    sorting,
    traffic_logs,
    users,
    waf,
)
from haprion_ui import editor as editor_module
from haprion_ui.access import current_session, forbidden_page
from haprion_ui.config import Config
from haprion_ui.db import AuthenticatedSession
from haprion_ui.editor_flow import carried_base, editor_state, state_reading
from haprion_ui.reading import (
    BACKUP_SOURCE,
    CERTIFICATE_SOURCE,
    NETWORK_SOURCE,
    OBJECTS_SOURCE,
    STATUS_SOURCE,
    cluster_creations,
    listed_clusters,
    read_certificate_takeouts,
    read_manager_certificates,
    read_source,
)
from haprion_ui.saved_work import (
    objects_reading_of,
    saved_network_rows,
    settled_drafts,
    settled_work,
    top_layers,
)
from haprion_ui.templates import TEMPLATES

logger = logging.getLogger("haprion_ui")

#
# A multi-select arrives as repeated fields, so its default has to be a list -
# and a list built in an argument default would be one list shared by every
# request. Named here so there is exactly one, and it is never mutated.
#
NETWORK_SELECTION = Form(default=[])
#
# The one file input the interface has (B165): optional at the parameter so a
# submission without a file is the form's refusal, not a 422 from the
# framework. Named here for the reason the multi-select is.
#
UPLOADED_FILE = File(default=None)


def _freshness_warnings(reading: traffic_logs.Reading, now: datetime) -> tuple[Any, ...]:
    """(node, seconds since success, seconds since attempt) for each node the log warning names."""

    freshness = tuple(
        (node, node.stale_seconds(now=now), node.attempt_seconds(now=now)) for node in reading.nodes
    )
    return tuple(
        item
        for item in freshness
        if item[0].latest_attempt_failed()
        or item[0].catching_up()
        or item[1] is None
        or item[1] > 300
    )


def _log_time_filter(
    value: str,
    *,
    earliest: datetime,
    latest: datetime,
    end_of_minute: bool = False,
    outside: str = "Choose a date and time within the available 14 days.",
) -> datetime | None:
    """Turn a date and time in the reader's clock into the UTC used by log records."""

    if not value:
        return None
    if len(value) != 14:
        raise ValueError(outside)
    try:
        local = datetime.strptime(value, moments.PICKED)
    except ValueError as exc:
        raise ValueError("Choose a valid date and time.") from exc
    if local.tzinfo is not None:
        raise ValueError("Choose a local date and time.")
    result = metrics.wall(local).astimezone(UTC)
    if result < earliest or result > latest:
        raise ValueError(outside)
    if end_of_minute:
        result = min(result + timedelta(minutes=1, microseconds=-1), latest)
    return result


def _traffic_marks(request: Request, marked: metrics.Selection) -> dict[str, object]:
    """What a card needs to draw and extend the reader's marked range.

    The link is handed over as a callable rather than one link per bucket:
    every page draws between sixty and a hundred and eighty buckets per card
    and several cards, and building all of them for the one the reader will
    click is a page assembled for the click that did not happen yet.

    The rest of the query string is carried through it, so a range marked on
    the 7-day view stays on the 7-day view - and so does anything else the
    address is carrying that this function has never heard of.
    """

    base = {name: value for name, value in request.query_params.items()}
    return {
        "traffic_marked": marked,
        "traffic_range": metrics.range_label(marked),
        "traffic_link": lambda stamp: metrics.link_to(base, marked, stamp),
        #
        # Where "clear the marks" leads, for the reader who wants out without
        # hunting for the third click.
        #
        "traffic_clear": metrics.link_clear(base) if marked.since is not None else "",
    }


# How long saving a DNS profile waits for its apply job before the list is
# drawn. The job is one root helper call; when the queue is idle it is done
# within a second, and the page should say so rather than send the operator
# to the Jobs page for a one-second job. In seconds.
#
DNS_PROFILE_APPLY_WAIT = 6.0

#
# The figures an object's traffic card draws, by what serves it: dnsdist counts
# a dns pool's queries (Fas 19a B4), IPVS a syslog pool's messages (19b B3),
# HAProxy everything else.
#
OBJECT_FIGURES = {"dns": metrics.DNS_FIGURES, "syslog": metrics.SYSLOG_FIGURES}

SIGN_IN_FAILED = "Sign-in failed. Check the username and password and try again."
SIGN_IN_BUSY = "Too many sign-ins at once. Try again in a moment."
UNAVAILABLE_PROVIDER = "Sign-in through the provider is not available"
EXPIRED = (
    "This run has expired: it was prepared more than an hour ago. Start a new restore from the "
    "backup page."
)


#
# A page number past this is not one anybody reached by clicking Next.
#
MAX_SEARCH_PAGE = 10000


#
# Why the Servers card's buttons did nothing, by `?servers=` (B263). A queued
# job needs no sentence: the buttons give way to its spinner.
#
SERVER_NOTICES = {
    "none": "Tick the servers first.",
    "busy": "A job is already running for this cluster. Try again when it has finished.",
}
BLOCKED_NOTICES = {
    "none": "Tick the addresses first.",
    "busy": SERVER_NOTICES["busy"],
}


#
# What Settings says after a switch has been flipped, by `?switched=`.
#
SWITCHED = {
    "cert_receivers-off": "Certificates for other hosts turned off. Registered receivers still get new certificates.",
    "cert_receivers-on": "Certificates for other hosts turned on.",
    "node_backups-off": "Node backups turned off. The clusters' schedules are being stopped; see Jobs.",
    "node_backups-on": "Node backups turned on. The schedules that were stopped are being started again.",
    "cluster_colours-off": "Cluster colours turned off.",
    "cluster_colours-on": "Cluster colours turned on.",
    "advanced_config-off": "Advanced config turned off. Proxies keep their text and it is still published.",
    "advanced_config-on": "Advanced config turned on.",
    "update_check-off": "Update check turned off. GitHub is not asked again.",
    "update_check-on": "Update check turned on. The poller asks GitHub within a minute.",
}


#
# Every handler is a plain `def`, which FastAPI runs in its thread pool. They
# all read the database - the session check alone does - with the synchronous
# pool, and an `async def` doing that waited on the event loop: while it waited
# for a connection, no other request of anybody's was answered (review
# 26-10-13, K1). What is asynchronous in a request - its form, an upload - is
# read from the thread through the loop instead.
#
async def _read_form(request: Request) -> FormData:
    return await request.form()


def _posted(request: Request) -> FormData:
    """The request's form, read from a handler running in the thread pool."""

    return anyio.from_thread.run(_read_form, request)


def _registry_overview(config: Config, request: Request) -> certificates.RegistryView | None:
    clusters, certificate_rows = read_source(request, config, CERTIFICATE_SOURCE)
    overview = certificates.build_certificate_overview(
        clusters,
        certificate_rows,
        manager=read_manager_certificates(request, config),
        stale_after=config.poller.stale_after,
    )
    return overview.registry


def _page_context(
    config: Config, request: Request, session: AuthenticatedSession
) -> tuple[str, certificates.RegistryView | None, dict[str, Any]]:
    token = request.cookies.get(auth.SESSION_COOKIE, "")
    registry = _registry_overview(config, request)
    with request.app.state.pool.connection() as connection:
        recent = db.recent_jobs(connection)
    return (
        token,
        registry,
        {
            "username": session.username,
            "role": session.role,
            "csrf_token": auth.csrf_token(token),
            "registry_present": registry is not None,
            "certificate_job": jobs.certificate_in_flight(recent),
            "section": "certificates",
            "management_writes": config.management_writes,
            "demo_fixture": config.demo_fixture,
        },
    )


def _backup_overview(config: Config, request: Request) -> Any:
    clusters, backup_rows = read_source(request, config, BACKUP_SOURCE)
    return backups.build_backup_overview(
        clusters,
        backup_rows,
        stale_after=config.poller.stale_after,
    )


def _account_rows(config: Config, request: Request) -> list[db.AccountRow]:
    with request.app.state.pool.connection() as connection:
        return db.account_rows(
            connection,
            window_minutes=config.throttle.window_minutes,
            max_failures=config.throttle.max_failures,
        )


def _status_row(config: Config, request: Request, cluster: str) -> Any | None:
    clusters, rows = read_source(request, config, STATUS_SOURCE)
    if cluster not in clusters:
        return None
    return next((row for row in rows if row.cluster == cluster), None)


def _queue_node_job(
    config: Config,
    request: Request,
    gate: AuthenticatedSession,
    cluster: str,
    payload: Mapping[str, Any],
    key: UUID,
    node: str | None,
    again: Callable[[str], Response],
    *,
    operation: str = "cluster_node",
    back: str | None = None,
) -> Response:
    #
    # Who asked, for the version a node change publishes (B335): the helper
    # records it only because the worker is the one who sends it.
    #
    payload = {**payload, "requested_by": gate.username}
    try:
        operations.prepare(
            operation=operation, cluster=cluster, request_id=uuid4(), payload=payload
        )
    except operations.BadPayload as refused:
        return again(str(refused))
    with request.app.state.pool.connection() as connection:
        try:
            job = db.queue_job(
                connection,
                operation=operation,
                cluster=cluster,
                payload=payload,
                idempotency_key=key,
            )
        except (db.ClusterBusy, db.RequestConflict) as refused:
            connection.rollback()
            #
            # A join key is sealed again on every submission, so a second click
            # is other bytes under the same key (review 26-10-24, 02-06).
            #
            if db.job_for_key(connection, key, operation=operation, cluster=cluster) is None:
                if isinstance(refused, db.RequestConflict):
                    raise refused
                return again(
                    "A job is already running for this cluster. Try again when it has finished."
                )
        else:
            #
            # The audit row names the node and the action, never the block: the
            # block holds public keys, and the audit log is not where a reader
            # looks for one.
            #
            detail: dict[str, Any] = {
                "operation": operation,
                "job": job.id,
                "action": payload["action"],
            }
            if node is not None:
                detail["node"] = node
            db.record_audit_event(
                connection,
                actor=gate.username,
                action="queue_job",
                cluster=cluster,
                request_id=job.request_id,
                detail=detail,
            )
            connection.commit()
    if back is not None:
        return RedirectResponse(back, status_code=303)
    #
    # Back to the cluster's page, named from the configured list rather
    # than from the request: the callers already refused a cluster not on
    # it, and the address is then never built from what the browser sent.
    #
    listed = next(name for name in listed_clusters(request, config) if name == cluster)
    return RedirectResponse("/settings/nodes/" + listed, status_code=303)


def _first_cluster(
    config: Config,
    request: Request,
    session: AuthenticatedSession,
    *,
    recent: list[Any],
    busy: Mapping[str, str],
    status_rows: Iterable[Any],
    network_readings: Iterable[Any],
) -> first_cluster.Guide | None:
    """The guide's step for an admin who may write, or None (B315)."""

    if session.role != "admin" or not config.management_writes:
        return None
    listed = listed_clusters(request, config)
    cluster = listed[0] if len(listed) == 1 else ""
    reading = next((row for row in status_rows if row.cluster == cluster), None)
    #
    # The address from the network description, not the dashboard card's
    # `vip`, which says who holds it: the guide showed a node's name as the
    # address (R2 26-10-22, F1).
    #
    vip = network.default_vip_address(
        next((row for row in network_readings if row.cluster == cluster), None)
    )
    return first_cluster.guide(
        clusters=listed,
        reading=reading,
        creations=cluster_creations(request, recent),
        busy=busy,
        vip=vip,
        phase=request.query_params.get("first-cluster", ""),
        deployed_recently=first_cluster.deployed_recently(recent, cluster),
        failure=first_cluster.failure(recent, cluster) if cluster else None,
    )


def _oidc_page(
    config: Config,
    request: Request,
    session: AuthenticatedSession,
    provider: db.OidcProvider,
    *,
    form: Mapping[str, Any] | None = None,
    problem: str = "",
    done: str = "",
    checks: list[dict[str, Any]] | None = None,
    status_code: int = 200,
) -> Response:
    token = request.cookies.get(auth.SESSION_COOKIE, "")
    values: dict[str, Any] = {
        name: getattr(provider, name) for name in db.OIDC_SETTINGS if name != "client_secret_sealed"
    }
    values.update(form or {})
    return TEMPLATES.TemplateResponse(
        request,
        "settings-oidc.html",
        {
            "username": session.username,
            "role": session.role,
            "csrf_token": auth.csrf_token(token),
            "section": "settings",
            "management_writes": config.management_writes,
            "provider": provider,
            "values": values,
            "secret_set": provider.client_secret_sealed is not None,
            "installed": config.oidc_public_key is not None,
            "redirect_uri": oidc_web.redirect_uri(str(request.base_url)),
            "auth_methods": oidc_web.AUTH_METHODS,
            "logout_modes": oidc_web.LOGOUT_MODES,
            "local_logins": oidc_web.LOCAL_LOGINS,
            "checks": checks,
            "problem": problem,
            "done": done,
        },
        status_code=status_code,
    )


def _oidc_provider(request: Request) -> db.OidcProvider | None:
    with request.app.state.pool.connection() as connection:
        return db.oidc_provider(connection)


def _dns_public_key(config: Config) -> DnsProfilePublicKey | None:
    """The key the web seals against, read fresh: a rotation is a file swap."""

    if config.dns_profiles_public_key is None:
        return None
    try:
        return read_public_key(config.dns_profiles_public_key)
    except KeyFileError as exc:
        logger.error("dns_profiles.public_key cannot be read: %s", exc)
        return None


def _oidc_redirect(request: Request) -> str:
    return oidc_web.redirect_uri(str(request.base_url))


def _start_oidc(
    request: Request,
    provider: db.OidcProvider,
    *,
    mode: str,
    bound_to: str,
) -> Response:
    """Record a sign-in in progress and answer where the browser goes (O5).

    `bound_to` is the cookie the answer must come back with: the
    pre-sign-in cookie for a sign-in, the session for Test sign-in. Its
    hash is kept, never the token. A provider that cannot be reached is
    the caller's to say, as `oidc_web.OidcProblem`.
    """

    tokens = oidc_web.new_login_tokens()
    redirect = _oidc_redirect(request)
    found = oidc_web.ask("discover", provider, redirect=redirect)
    with request.app.state.pool.connection() as connection:
        db.start_oidc_login(
            connection,
            state=tokens.state,
            nonce=tokens.nonce,
            verifier=tokens.verifier,
            mode=mode,
            pre_session_hash=auth.token_hash(bound_to),
        )
        connection.commit()
    return RedirectResponse(
        oidc_web.authorization_url(provider, found, tokens, redirect=redirect), status_code=303
    )


#
# How many rows *Audit* shows to a page unless the reader chooses 25 or 100,
# as the traffic log does (B275, 26-10-11).
#
AUDIT_PAGE = 50

#
# How far back the record reaches: haprion-retention's AUDIT_KEEP_DAYS, which
# removes what is older. The From and To fields are bounded by it.
#
AUDIT_KEEP_DAYS = 730

#
# Audit's headings, sorted as every sortable table is (THEME.md) but in the
# database: the page holds one page of the record, and ordering only that
# would be a lie about the rest. The keys are unused for the same reason.
#
#
# How far back *Events → Nodes* reaches: haprion-retention's NODE_EVENT_KEEP_DAYS.
#
NODE_EVENT_KEEP_DAYS = 90

NODE_EVENT_TABLE = sorting.Table(
    columns=(
        sorting.Column("time", lambda _row, _: None, descending_first=True),
        sorting.Column("node", lambda _row, _: None),
        sorting.Column("what", lambda _row, _: None),
        sorting.Column("where", lambda _row, _: None),
    ),
    cookie="haprion_ui_node_event_sort",
    path="/jobs",
)

AUDIT_TABLE = sorting.Table(
    columns=(
        sorting.Column("time", lambda _row, _: None, descending_first=True),
        sorting.Column("who", lambda _row, _: None),
        sorting.Column("what", lambda _row, _: None),
        sorting.Column("where", lambda _row, _: None),
    ),
    cookie="haprion_ui_audit_sort",
    path="/jobs",
)


#
# Where an operation may send somebody afterwards. A closed set and not the
# submitted string: this value arrives in a form, and a redirect that trusts one
# is how a page is turned into a way of sending somebody somewhere else.
#
RETURN_PATHS = {
    "dashboard": "/",
    "first-cluster": "/first-cluster?first-cluster=deploying",
    "proxies": "/proxies",
    "certificates": "/certificates?view=registry",
    "history": "/history",
    "backups": "/backups",
    "network": "/network",
    "jobs": "/jobs",
}


def _return_path(name: str, *, open: str = "") -> str:
    """The page an operation returns to, or the jobs page.

    The jobs page is the fallback rather than the default, so a form that has
    not been told where it lives still lands somewhere that shows what happened.
    `open` names the registry row the button was on, so the person lands on
    it still unfolded; only a certificate ID is accepted, and only for the
    registry, since that is the one page with rows to unfold.
    """

    path = RETURN_PATHS.get(name, "/jobs")
    if name == "certificates" and open and CERTIFICATE_ID.fullmatch(open):
        return path + "&open=" + open
    return path


def _new_password_problem(new_password: str, repeat_password: str) -> str:
    """The sentence a new password is refused with, or ''. The CLI's same rules."""

    if len(new_password) < auth.MINIMUM_PASSWORD_LENGTH:
        return f"The new password must be at least {auth.MINIMUM_PASSWORD_LENGTH} characters."
    if len(new_password.encode("utf-8")) > auth.MAX_PASSWORD_BYTES:
        return f"The new password must be under {auth.MAX_PASSWORD_BYTES} bytes."
    if new_password != repeat_password:
        return "The two new passwords do not match."
    return ""


HASHING_BUSY = "Too many passwords are being checked at once. Try again in a moment."


def _hashed(password: str) -> str | None:
    """`password` hashed for storing, holding no connection; None while the hashing is full.

    At most auth.HASHING_AT_ONCE at a time, as the sign-in hashes: six
    connections serve every page, and Argon2 held one for each password set
    here (review 26-10-24, 09-02).
    """

    if not auth.HASHING.acquire(timeout=auth.HASHING_WAIT_SECONDS):
        return None
    try:
        return auth.hash_password(password)
    finally:
        auth.HASHING.release()


def _sign_in_throttled(connection: Any, config: Config, *, username: str, address: str) -> bool:
    """Whether `username` may not be tried from `address` now.

    Two budgets: the name and address together, and the name from anywhere
    (B305). The sign-in and the check of one's own password read the same two.
    """

    window = config.throttle.window_minutes
    return db.failures_since_last_success(
        connection, username=username, client_ip=address, window_minutes=window
    ) >= config.throttle.max_failures or (
        db.account_failures_since_last_success(connection, username=username, window_minutes=window)
        >= config.throttle.max_failures * auth.ACCOUNT_FAILURE_FACTOR
    )


def _count_attempt(pool: Any, config: Config, *, username: str, address: str) -> bool:
    """Write this password attempt down as a failure, before its hash; True if throttled.

    Counted before the hash, not after it, and one attempt at a time per name.
    A count read before the hash and a row written after it were seconds apart,
    and every attempt sent at once read the same count - so a burst passed the
    budget by as many as could hash in it (review 2026-10-22, 3-3). Under a
    lock on the name the count is read again and this attempt is written down;
    a success written after the hash is what clears it, as any success does.

    A throttled attempt is not written at all - the caller's audit row says it
    happened. Written, it counted towards the account's own budget, and one
    address kept the right password out from every other (review 26-10-24,
    09-01; the own-password check, review 26-10-25, 2-03).
    """

    with pool.connection() as connection:
        db.lock_sign_in(connection, username=username)
        throttled = _sign_in_throttled(connection, config, username=username, address=address)
        if not throttled:
            db.record_login_attempt(
                connection, username=username or "?", client_ip=address, succeeded=False
            )
        connection.commit()
    return throttled


def _prove_password(
    pool: Any,
    config: Config,
    session: AuthenticatedSession,
    password: str,
    *,
    address: str,
    failed_action: str,
    wrong: str,
    detail: Mapping[str, object] | None = None,
) -> str:
    """'' when `password` is the signed-in account's own; else why not, recorded.

    Tried as a sign-in is, for this name and address: the same budgets, the
    same failure written before the hash, and the right password written as a
    success - so a session somebody else is holding cannot be used to guess
    the password behind it, nor to lock the account for everyone else.

    The hash runs holding no connection and under the sign-in's limit, and a
    throttled attempt is not hashed at all (review 26-10-24, 09-02). A full
    limit is said as such and counts against nobody.
    """

    with pool.connection() as connection:
        throttled = _sign_in_throttled(
            connection, config, username=session.username, address=address
        )
        account = None if throttled else db.account_by_username(connection, session.username)
    if not throttled:
        if not auth.HASHING.acquire(timeout=auth.HASHING_WAIT_SECONDS):
            return HASHING_BUSY
        try:
            throttled = _count_attempt(pool, config, username=session.username, address=address)
            if throttled:
                accepted = False
            elif account is None or account.disabled or account.password_hash is None:
                auth.burn_absent_user_time(password)
                accepted = False
            else:
                accepted = auth.verify_password(account.password_hash, password)
        finally:
            auth.HASHING.release()
        if accepted:
            with pool.connection() as connection:
                db.record_login_attempt(
                    connection, username=session.username, client_ip=address, succeeded=True
                )
                connection.commit()
            return ""
    with pool.connection() as connection:
        db.record_audit_event(
            connection,
            actor=session.username,
            action=failed_action,
            detail={
                **(detail or {}),
                "client_ip": address,
                "reason": "throttled" if throttled else "rejected",
                "via": "web",
            },
        )
        connection.commit()
    return "Too many failed attempts. Try again later." if throttled else wrong


def _password_page(
    request: Request,
    config: Config,
    session: AuthenticatedSession,
    *,
    problem: str = "",
    changed: bool = False,
    status_code: int = 200,
) -> Response:
    """The own-password form. Never echoes a password, not even a wrong one."""

    token = request.cookies.get(auth.SESSION_COOKIE, "")
    return TEMPLATES.TemplateResponse(
        request,
        "account-password.html",
        {
            "username": session.username,
            "role": session.role,
            "management_writes": config.management_writes,
            "csrf_token": auth.csrf_token(token),
            "problem": problem,
            "changed": changed,
            "minimum_length": auth.MINIMUM_PASSWORD_LENGTH,
        },
        status_code=status_code,
    )


def _public_files(certificate_id: str, fullchain_pem: str) -> list[tuple[str, bytes, bool]]:
    """An external certificate's public files: the chain whole, the leaf, the issuers.

    The three a device asks for (B255), named after the certificate, and
    marked not secret for the zip's permission bits.
    """

    blocks = [CERTIFICATE_OPENING + block for block in fullchain_pem.split(CERTIFICATE_OPENING)[1:]]
    files = [
        (f"{certificate_id}.fullchain.pem", "".join(blocks)),
        (f"{certificate_id}.crt.pem", "".join(blocks[:1])),
        (f"{certificate_id}.chain.pem", "".join(blocks[1:])),
    ]
    return [(name, text.encode("ascii"), False) for name, text in files if text]


def _zip_response(files: Sequence[tuple[str, bytes, bool]], filename: str) -> Response:
    """Files as one zip, built in memory and served without a copy kept (2026-10-07).

    A secret member is marked owner-only, so an unzip that honours the bits
    leaves the key as a key file would be left; the rest are world-readable.
    """

    stamp = datetime.now(UTC).timetuple()[:6]
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content, secret in files:
            member = zipfile.ZipInfo(name, date_time=stamp)
            member.compress_type = zipfile.ZIP_DEFLATED
            member.external_attr = (0o100600 if secret else 0o100644) << 16
            archive.writestr(member, content)
    return Response(
        buffer.getvalue(),
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
        },
    )


def _network_page(request: Request, config: Config) -> Response:
    """Each cluster's addresses, as the poller last read them.

    The page reads the cache like every other page rather than reaching a
    helper while somebody is looking at a screen. What it adds to the reading
    is one judgement: whether the description came from the cluster repository,
    because only then can it be changed from here.
    """

    session = current_session(request)
    if session is None:
        return RedirectResponse("/login", status_code=303)
    token = request.cookies.get(auth.SESSION_COOKIE, "")
    clusters, network_rows = read_source(request, config, NETWORK_SOURCE)
    #
    # A saved description is what the form shows and what the next publish
    # carries (B257), so it is drawn in place of the published one and said so.
    #
    with request.app.state.pool.connection() as connection:
        network_rows, saved_network = saved_network_rows(connection, list(network_rows))
    overview = network.build_network_overview(
        clusters,
        network_rows,
        stale_after=config.poller.stale_after,
    )
    #
    # Published is not deployed, and this page had no way to say so: publishing
    # here moved somebody to the jobs page, which was the only place that knew.
    # The two facts it needs to keep them are the same two the dashboard uses -
    # what is still owed, and what is running - so the state is stated where the
    # change was made rather than on a page they were sent to.
    #
    with request.app.state.pool.connection() as connection:
        recent = db.recent_jobs(connection)
    #
    # Where the configuration has got to, as one badge per cluster. Three of
    # the four states come from the machine - which is what lets the page
    # correct itself when somebody deploys from the command line, and why it
    # needs no memory of what was pressed here.
    #
    _, status_rows = read_source(request, config, STATUS_SOURCE)
    board = dashboard.build_dashboard(
        clusters,
        status_rows,
        stale_after=config.poller.stale_after,
    )
    serving = {view.cluster: view for view in board.clusters}
    #
    # Which objects use each VIP, source and group (26-10-10), from the stored
    # objects as the helper read them. A cluster whose objects could not be
    # read says nothing rather than "not used".
    #
    _, object_rows = read_source(request, config, OBJECTS_SOURCE)
    used = {
        reading.cluster: network.usage(objects.cluster_object_views(reading))
        for reading in object_rows
        if reading.outcome == "done" and not reading.poll_error
    }
    awaiting = network.awaiting_deploy(recent)
    busy = jobs.in_flight(recent)
    failures = jobs.last_failure(recent)
    state = {
        view.cluster: network.deployment(
            running=busy.get(view.cluster),
            failure=failures.get(view.cluster),
            awaiting=view.cluster in awaiting,
            release_state=serving[view.cluster].release_state if view.cluster in serving else "",
            version=serving[view.cluster].version if view.cluster in serving else "",
        )
        for view in overview
    }
    return TEMPLATES.TemplateResponse(
        request,
        "network.html",
        {
            "username": session.username,
            "role": session.role,
            "csrf_token": auth.csrf_token(token),
            "section": "network",
            "clusters": overview,
            "usage": used,
            "saved_network": saved_network,
            "awaiting_deploy": awaiting,
            "deployment": state,
            "targets": {name: view.target_version for name, view in serving.items()},
            "management_writes": config.management_writes,
            "demo_fixture": config.demo_fixture,
        },
    )


def _sso_button(request: Request) -> str | None:
    """The provider button's text while sign-in goes through one, else None."""

    with request.app.state.pool.connection() as connection:
        provider = db.oidc_provider(connection)
    return provider.button_text if provider is not None and provider.enabled else None


def _oidc_account_refusal(
    connection: Any,
    *,
    issuer: str,
    subject: str,
    username: str,
) -> tuple[str, str] | None:
    """Why a sign-in as this identity stops at the account step, or None. Reads only.

    One answer for the sign-in and for Test sign-in, which must not promise what
    the sign-in refuses: a Test sign-in as a name a local account holds said
    "would sign in as admin" (2026-09-28). An account is made at the first
    sign-in, with the role the groups give (B297); an account of the same name
    is never taken over (B196).
    """

    account = db.account_by_oidc(connection, issuer=issuer, subject=subject)
    if account is None:
        named = db.account_by_username(connection, username)
        if named is not None:
            #
            # Bound to another issuer: the provider was changed, or its
            # application renamed, since this account first signed in. Said
            # as that, since "already exists" sends everyone looking for a
            # local account (review 2026-09-28 F5).
            #
            if named.source == "oidc" and named.oidc_issuer not in (None, issuer):
                return (
                    f"The account {username} here belongs to another provider's sign-in. "
                    "An admin can remove it so that it is made again.",
                    "other_issuer",
                )
            return f"An account named {username} already exists here.", "name_taken"
        if users.name_problem(username) is not None:
            #
            # A version records the name as who published it (B207); one that
            # cannot stand there never becomes an account (review 2026-09-29 F1).
            #
            return "The name the provider sent cannot be an account name here.", "unfit_name"
    if account is not None and account.disabled:
        return "That account is disabled here.", "disabled"
    return None


def _login_again(request: Request, config: Config, *, error: str | None = None) -> Response:
    """Render a fresh login form, with a fresh token to post it with."""

    pre_token = auth.new_session_token()
    response: Response = TEMPLATES.TemplateResponse(
        request,
        "login.html",
        {"error": error, "csrf_token": auth.csrf_token(pre_token), "sso": _sso_button(request)},
        status_code=401 if error else 200,
    )
    response.set_cookie(
        auth.PRE_SESSION_COOKIE,
        pre_token,
        max_age=600,
        httponly=True,
        secure=config.session.cookie_secure,
        samesite="lax",
        path="/",
    )
    return response


# - WAF page (Fas 21 del B, B234) ------------------------------------------
#
# What the engine found per object and rule, and the exceptions objects carry.
# A finding is let through with an exception that is saved into the object's
# draft, as the editor saves one: the same row, the same revision check, the
# same refusal of a document the engine will not take. Publishing it is the
# object's own publish.
#
WAF_DAYS = 7


def _waf_documents(
    request: Request, config: Config, connection: Any, clusters: Sequence[str]
) -> tuple[dict[tuple[str, str], str], dict[tuple[str, str], str]]:
    """Each object's stored document, and its draft's where it has one (not a removal)."""

    _, object_rows = read_source(request, config, OBJECTS_SOURCE)
    stored: dict[tuple[str, str], str] = {}
    readings: dict[str, Any] = {}
    for row in object_rows:
        if row.cluster not in clusters:
            continue
        readings[row.cluster] = row
        for view in objects.cluster_object_views(row):
            if view.readable:
                stored[(row.cluster, view.name)] = view.document
    drafted: dict[tuple[str, str], str] = {}
    for cluster in clusters:
        names = {name for owner, name in stored if owner == cluster}
        for draft in top_layers(
            settled_drafts(connection, cluster, objects_reading_of(readings.get(cluster), names))
        ):
            if not draft.deleted:
                drafted[(cluster, draft.object_id)] = draft.yaml
    return stored, drafted


@dataclass(frozen=True, slots=True)
class WafOverview:
    """What the WAF page's three tabs show, and the figure on each (mock round 7)."""

    days: int
    findings: list[Any]
    exceptions: list[Any]
    request_count: int

    def tab_counts(self) -> dict[str, int]:
        return {
            "findings": sum(len(card.findings) for card in self.findings),
            "exceptions": len(self.exceptions),
            "requests": self.request_count,
        }


def _waf_not_working(
    request: Request, config: Config, connection: Any, chosen: Sequence[str]
) -> set[tuple[str, str, Any]]:
    """The published exceptions the WAF page marks *Not working*, for the attention list."""

    days = min(WAF_DAYS, config.traffic_logs.retention_days)
    since = datetime.now(UTC) - timedelta(days=days)
    stored, _drafted = _waf_documents(request, config, connection, chosen)
    rows = db.waf_findings(connection, clusters=chosen, since=since)
    reached = {
        (cluster, moment): done
        for cluster, moments in waf.exception_moments(rows, stored).items()
        for moment, done in db.deploys_carrying(
            connection, cluster=cluster, moments=sorted(moments)
        ).items()
    }
    return waf.ineffective_exceptions(rows, stored, reached)


def _service_lamps(
    request: Request, config: Config, clusters: Iterable[Any], status_rows: Sequence[Any]
) -> dict[str, dict[str, health.ObjectHealth]]:
    """Each object's *Proxies* lamp, for the clusters whose reading is current.

    The same call the listing makes, on the same objects cache and status
    reading. A cluster read too long ago is its own row already, and a lamp
    from that reading would be a guess about now.
    """

    current = [
        cluster.cluster
        for cluster in clusters
        if getattr(cluster, "configured", True) and not cluster.stale
    ]
    if not current:
        return {}
    _, object_rows = read_source(request, config, OBJECTS_SOURCE)
    rows = {reading.cluster: reading for reading in object_rows}
    lamps: dict[str, dict[str, health.ObjectHealth]] = {}
    for cluster in current:
        stored = objects.cluster_object_views(rows.get(cluster))
        lamps[cluster] = health.object_healths(
            status_rows,
            cluster=cluster,
            owners=health.backend_owners(stored),
            objects={obj.name: (obj.health_checked, obj.sourced) for obj in stored},
        )
    return lamps


def _attention(request: Request, config: Config) -> attention.Attention:
    """What needs doing, worked out from the pages' own builders (B274)."""

    stale_after = config.poller.stale_after
    now = datetime.now(UTC)
    clusters, status_rows = read_source(request, config, STATUS_SOURCE)
    status_rows = tuple(status_rows)
    _, network_rows = read_source(request, config, NETWORK_SOURCE)
    board = dashboard.build_dashboard(
        clusters, status_rows, stale_after=stale_after, network_readings=network_rows
    )
    certificate_clusters, certificate_rows = read_source(request, config, CERTIFICATE_SOURCE)
    certificate_view = certificates.build_certificate_overview(
        certificate_clusters,
        certificate_rows,
        manager=read_manager_certificates(request, config),
        stale_after=stale_after,
        status_readings=status_rows,
        taken_out=read_certificate_takeouts(request, config),
    )
    items: list[attention.Item] = []
    with request.app.state.pool.connection() as connection:
        features.read_in(db.feature_switches(connection))
        recent = db.recent_jobs(connection, limit=200)
        known = {job.id for job in recent}
        #
        # A removed cluster's failures are no longer anybody's to settle: no
        # step runs on a cluster that is gone, and a new cluster given the
        # name would inherit them (review 26-10-25, 4-02). An unread list
        # hides nothing.
        #
        items += attention.from_jobs(
            [
                job
                for job in recent
                + [job for job in db.attention_evidence(connection) if job.id not in known]
                if job.cluster is None or not clusters or job.cluster in clusters
            ]
        )
        cluster_list_at = db.cluster_list_observed(connection)
        items += attention.from_manager(
            cluster_list_at=cluster_list_at,
            poller_silent_after=max(stale_after, timedelta(minutes=5)),
            rows=recent,
            writes=config.management_writes,
            horizons=db.partition_horizons(connection, attention.MAINTENANCE_AHEAD),
            now=now,
            maintained_at=db.retention_completed(connection),
        )
        items += attention.from_packages(db.package_waiting(connection))
        if config.traffic_logs.enabled:
            items += attention.from_waf(
                _waf_not_working(request, config, connection, clusters),
                describe=waf.where,
            )
    if config.traffic_logs.enabled:
        items += attention.from_traffic_logs(
            traffic_logs.read_freshness(config.traffic_logs.directory, tuple(clusters)).nodes,
            now=now,
        )
    items += attention.from_log_forwarding(status_rows, now=now)
    items += attention.from_dashboard(
        board.clusters,
        drift_label=dashboard.VERSION_DRIFT,
        cluster_faults=dashboard.CLUSTER_FAULTS,
    )
    items += attention.from_services(
        _service_lamps(request, config, board.clusters, status_rows),
        held_label=health.HELD_LABEL,
    )
    items += attention.from_certificates(certificate_view.registry, certificate_view.clusters)
    if features.is_on(features.NODE_BACKUPS):
        backup_clusters, backup_rows = read_source(request, config, BACKUP_SOURCE)
        items += attention.from_backups(
            backups.build_backup_overview(
                backup_clusters, backup_rows, stale_after=stale_after
            ).clusters
        )
    status_age: dict[str, int | None] = {
        row.cluster: int((now - row.observed_at).total_seconds()) for row in status_rows
    }
    for cluster in clusters:
        status_age.setdefault(cluster, None)
    with request.app.state.pool.connection() as connection:
        items, gone = attention.unacknowledged(items, db.attention_acks(connection))
        if gone:
            db.forget_attention_acks(connection, gone)
            connection.commit()
    return attention.build_attention(
        items,
        status_age=status_age,
        stale_after_seconds=int(stale_after.total_seconds()),
        list_age=None if cluster_list_at is None else int((now - cluster_list_at).total_seconds()),
        now=now,
    )


def _waf_overview(request: Request, config: Config, chosen: Sequence[str]) -> WafOverview:
    days = min(WAF_DAYS, config.traffic_logs.retention_days)
    since = datetime.now(UTC) - timedelta(days=days)
    rules = crs.installed_catalog()
    with request.app.state.pool.connection() as connection:
        stored, drafted = _waf_documents(request, config, connection, chosen)
        rows = db.waf_findings(connection, clusters=chosen, since=since)
        verdicts = db.waf_verdicts(connection, clusters=chosen, since=since)
        request_count = db.waf_request_count(connection, clusters=chosen, since=since)
        #
        # What each exception let through, as its counter counted it within
        # what the exception covers (B273, review 26-10-11).
        #
        counted = db.waf_counted(connection, scopes=waf.counter_scopes(stored, rules), since=since)
        #
        # When each published exception that covers a finding reached the
        # nodes: the first deploy after it was made (26-10-11). Matches after
        # that mean the exception is not working, which the page says rather
        # than hides.
        #
        reached = {
            (cluster, moment): done
            for cluster, moments in waf.exception_moments(rows, stored).items()
            for moment, done in db.deploys_carrying(
                connection, cluster=cluster, moments=sorted(moments)
            ).items()
        }
    return WafOverview(
        days=days,
        findings=waf.build_findings(rows, verdicts, stored, drafted, rules, reached),
        exceptions=waf.build_exceptions(
            stored, drafted, rules, waf.ineffective_exceptions(rows, stored, reached), counted
        ),
        request_count=request_count,
    )


def _waf_work_page(request: Request, config: Config, view: str, problem: str = "") -> Response:
    session = current_session(request)
    if session is None:
        return RedirectResponse("/login", status_code=303)
    token = request.cookies.get(auth.SESSION_COOKIE, "")
    clusters = listed_clusters(request, config)
    selected = request.query_params.get("cluster", "")[:32]
    chosen = (selected,) if selected in clusters else tuple(clusters)
    overview = _waf_overview(request, config, chosen)
    days, findings, exceptions = overview.days, overview.findings, overview.exceptions
    return TEMPLATES.TemplateResponse(
        request,
        "waf.html",
        {
            "username": session.username,
            "role": session.role,
            "csrf_token": auth.csrf_token(token),
            "section": "waf",
            "management_writes": config.management_writes,
            "view": view,
            "days": days,
            "clusters": clusters,
            "selected_cluster": selected if selected in clusters else "",
            "findings": findings,
            "tab_counts": overview.tab_counts(),
            "exceptions": exceptions,
            "where": waf.where,
            "saved": request.query_params.get("saved", "")[:40],
            "saved_in": request.query_params.get("in", "")[:32],
            "can_write": config.management_writes and session.role == "admin",
            "problem": problem,
        },
        status_code=409 if problem else 200,
    )


def _waf_write_gate(
    request: Request, config: Config, csrf: str | None
) -> AuthenticatedSession | Response:
    session = current_session(request)
    if session is None:
        return RedirectResponse("/login", status_code=303)
    if not config.management_writes:
        return PlainTextResponse("Not found", status_code=404)
    token = request.cookies.get(auth.SESSION_COOKIE, "")
    if csrf is not None and not auth.csrf_token_is_valid(token, csrf):
        return forbidden_page(request, config)
    if session.role != "admin":
        return forbidden_page(request, config)
    return session


def _waf_save(
    request: Request,
    config: Config,
    session: AuthenticatedSession,
    *,
    cluster: str,
    name: str,
    change: Callable[[str], str],
    detail: dict[str, Any],
) -> str | None:
    """Apply one change to the object's draft (or its stored document); the problem, or None."""

    state = editor_state(request, config, cluster)
    stored = next((view for view in state.stored if view.name == name), None)
    with request.app.state.pool.connection() as connection:
        work = settled_work(connection, cluster, name, state_reading(state))
    #
    # An exception is finished work, so it is a saved change (B257), made on
    # the saved change or the stored object and never on a draft somebody has
    # not finished.
    #
    if work.draft is not None:
        return f"{name} has a draft. Save or discard it in the editor first."
    draft = work.saved
    if draft is not None and draft.deleted:
        return f"The saved changes remove {name}."
    base = draft.yaml if draft is not None else (stored.document if stored is not None else "")
    if not base or state.commit is None:
        return "The stored proxies have not been read yet."
    try:
        document = change(base)
        load_written(name, document.encode())
    except (ValueError, ModelError) as exc:
        return str(exc)
    if editor_module.unchanged(document, base):
        return None
    with request.app.state.pool.connection() as connection:
        try:
            saved = db.save_change(
                connection,
                cluster=cluster,
                object_id=name,
                yaml=document,
                base_version=state.base_version,
                base_hash=state.commit,
                updated_by=session.username,
                base_document=carried_base(state, name, draft),
                replaces=draft.replaces if draft is not None else None,
                saved_revision=draft.revision if draft is not None else None,
                draft_revision=None,
            )
        except db.DraftConflict as conflict:
            connection.rollback()
            return f"{conflict}. Reload the page and try again."
        db.record_audit_event(
            connection,
            actor=session.username,
            action="save_change",
            cluster=cluster,
            request_id=uuid4(),
            detail={"object": name, "revision": saved.revision, **detail},
        )
        connection.commit()
    return None


def _waf_target(request: Request, config: Config, cluster: str, name: str) -> bool:
    return cluster in listed_clusters(request, config) and bool(proxy_model.NAME.fullmatch(name))


def _waf_allow(request: Request, config: Config, form: Any) -> Response:
    """The Allow dialog (B234, B235): where to let a finding through, as narrow as it allows."""

    values = form if form is not None else request.query_params
    gate = _waf_write_gate(
        request, config, str(values.get("csrf_token", "")) if form is not None else None
    )
    if not isinstance(gate, AuthenticatedSession):
        return gate
    session = gate
    cluster = str(values.get("cluster", ""))[:32]
    name = str(values.get("object", ""))[:40]
    rule_text = str(values.get("rule", ""))[:6]
    field = str(values.get("field", ""))[:256]
    offered = [str(path)[:1024] for path in values.getlist("path")][:20]
    if not _waf_target(request, config, cluster, name) or not is_digits(rule_text):
        return PlainTextResponse("Not found", status_code=404)
    rule = int(rule_text)
    if field and not proxy_model.waf_field(field):
        field = ""
    #
    # A path the engine could not be told exactly - percent-encoded, with an
    # empty segment - is not offered; the object or the field still is.
    #
    paths = [path for path in dict.fromkeys(offered) if proxy_model.WAF_PATH.fullmatch(path)]
    #
    # Why, in one line (26-10-10): a pasted line break becomes a space, and
    # the engine refuses whatever else a note may not hold, in its own words.
    #
    reason = " ".join(str(values.get("reason", ""))[: proxy_model.MAX_NOTE].split())
    problem = ""
    if form is not None:
        chosen = str(values.get("scope", ""))
        at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
            exception = waf.exception_for(
                chosen,
                rule=rule,
                field=field,
                paths=[path for path in values.getlist("chosen_path") if path in paths],
                by=session.username,
                at=at,
                reason=reason,
            )
        except ValueError as exc:
            problem = str(exc)
        else:
            problem = (
                _waf_save(
                    request,
                    config,
                    session,
                    cluster=cluster,
                    name=name,
                    change=lambda base: waf.with_exception(name, base, exception),
                    detail={"waf_exception": {k: v for k, v in exception.items() if k != "at"}},
                )
                or ""
            )
            if not problem:
                return RedirectResponse(
                    "/waf?" + urlencode({"saved": name, "in": cluster}), status_code=303
                )
    catalog = crs.installed_catalog().get(rule)
    kind, explanation = waf.kind(rule // 1000)
    token = request.cookies.get(auth.SESSION_COOKIE, "")
    return TEMPLATES.TemplateResponse(
        request,
        "waf-allow.html",
        {
            "username": session.username,
            "role": session.role,
            "csrf_token": auth.csrf_token(token),
            "section": "waf",
            "management_writes": config.management_writes,
            "cluster": cluster,
            "name": name,
            "rule": rule,
            "field": field,
            "shown_field": waf.shown_field(field) if field else "",
            "paths": paths,
            "kind": kind,
            "explanation": explanation,
            "message": catalog.message
            if catalog is not None and catalog.message
            else f"Rule {rule}",
            "severity": catalog.severity if catalog is not None else "",
            "matched": str(values.get("matched", ""))[:1024],
            "reason": reason,
            "scope": str(values.get("scope", ""))
            or (
                "field_paths"
                if field and paths
                else "field"
                if field
                else "paths"
                if paths
                else "object"
            ),
            "problem": problem,
        },
        status_code=409 if problem else 200,
    )


def _waf_remove(request: Request, config: Config, form: Any) -> Response:
    gate = _waf_write_gate(request, config, str(form.get("csrf_token", "")))
    if not isinstance(gate, AuthenticatedSession):
        return gate
    cluster = str(form.get("cluster", ""))[:32]
    name = str(form.get("object", ""))[:40]
    rule_text = str(form.get("rule", ""))[:6]
    if not _waf_target(request, config, cluster, name) or not is_digits(rule_text):
        return PlainTextResponse("Not found", status_code=404)
    field = str(form.get("field", ""))[:256]
    paths = [str(path)[:1024] for path in form.getlist("path")][:20]
    problem = _waf_save(
        request,
        config,
        gate,
        cluster=cluster,
        name=name,
        change=lambda base: waf.without_exception(
            name, base, rule=int(rule_text), field=field, paths=paths
        ),
        detail={"waf_exception_removed": {"rule": int(rule_text), "field": field, "paths": paths}},
    )
    if problem:
        return _waf_work_page(request, config, "exceptions", problem=problem)
    return RedirectResponse(
        "/waf?" + urlencode({"view": "exceptions", "saved": name, "in": cluster}), status_code=303
    )
