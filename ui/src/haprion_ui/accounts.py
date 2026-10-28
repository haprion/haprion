"""Signing in and the accounts behind it: passwords, the provider and the account list (K01, review 2026-10-28).

A password is proved against its hash off the event loop, with a throttle per
address and a bound on how many are hashed at once; failures all read the
same. Signing in through the identity provider starts and ends here, and an
account the provider names that may not sign in is told why on a page of its
own. The account list is what Settings shows.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from fastapi import Request, Response
from fastapi.responses import (
    RedirectResponse,
)

from haprion_ui import (
    auth,
    db,
    oidc_web,
    users,
)
from haprion_ui.config import Config
from haprion_ui.db import AuthenticatedSession
from haprion_ui.templates import TEMPLATES

SIGN_IN_FAILED = "Sign-in failed. Check the username and password and try again."

SIGN_IN_BUSY = "Too many sign-ins at once. Try again in a moment."

UNAVAILABLE_PROVIDER = "Sign-in through the provider is not available"


def listed_accounts(config: Config, request: Request) -> list[db.AccountRow]:
    with request.app.state.pool.connection() as connection:
        return db.account_rows(
            connection,
            window_minutes=config.throttle.window_minutes,
            max_failures=config.throttle.max_failures,
        )


def oidc_page(
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


def current_oidc_provider(request: Request) -> db.OidcProvider | None:
    with request.app.state.pool.connection() as connection:
        return db.oidc_provider(connection)


def oidc_redirect(request: Request) -> str:
    return oidc_web.redirect_uri(str(request.base_url))


def start_oidc(
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
    redirect = oidc_redirect(request)
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


def new_password_problem(new_password: str, repeat_password: str) -> str:
    """The sentence a new password is refused with, or ''. The CLI's same rules."""

    if len(new_password) < auth.MINIMUM_PASSWORD_LENGTH:
        return f"The new password must be at least {auth.MINIMUM_PASSWORD_LENGTH} characters."
    if len(new_password.encode("utf-8")) > auth.MAX_PASSWORD_BYTES:
        return f"The new password must be under {auth.MAX_PASSWORD_BYTES} bytes."
    if new_password != repeat_password:
        return "The two new passwords do not match."
    return ""


HASHING_BUSY = "Too many passwords are being checked at once. Try again in a moment."


def hashed_password(password: str) -> str | None:
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


def sign_in_throttled(connection: Any, config: Config, *, username: str, address: str) -> bool:
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


def count_sign_in_attempt(pool: Any, config: Config, *, username: str, address: str) -> bool:
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
        throttled = sign_in_throttled(connection, config, username=username, address=address)
        if not throttled:
            db.record_login_attempt(
                connection, username=username or "?", client_ip=address, succeeded=False
            )
        connection.commit()
    return throttled


def prove_password(
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
        throttled = sign_in_throttled(
            connection, config, username=session.username, address=address
        )
        account = None if throttled else db.account_by_username(connection, session.username)
    if not throttled:
        if not auth.HASHING.acquire(timeout=auth.HASHING_WAIT_SECONDS):
            return HASHING_BUSY
        try:
            throttled = count_sign_in_attempt(
                pool, config, username=session.username, address=address
            )
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


def password_page(
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


def sso_button(request: Request) -> str | None:
    """The provider button's text while sign-in goes through one, else None."""

    with request.app.state.pool.connection() as connection:
        provider = db.oidc_provider(connection)
    return provider.button_text if provider is not None and provider.enabled else None


def oidc_account_refusal(
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


def login_again(request: Request, config: Config, *, error: str | None = None) -> Response:
    """Render a fresh login form, with a fresh token to post it with."""

    pre_token = auth.new_session_token()
    response: Response = TEMPLATES.TemplateResponse(
        request,
        "login.html",
        {"error": error, "csrf_token": auth.csrf_token(pre_token), "sso": sso_button(request)},
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
