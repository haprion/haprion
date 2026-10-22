"""Signing in and out, and the account page."""

from __future__ import annotations

import hmac
import json

from fastapi import APIRouter, Form, Request, Response
from fastapi.responses import (
    HTMLResponse,
    PlainTextResponse,
    RedirectResponse,
)

from haprion_ui import (
    auth,
    db,
    oidc_web,
)
from haprion_ui.config import Config
from haprion_ui.db import AuthenticatedSession
from haprion_ui.views import (
    SIGN_IN_BUSY,
    SIGN_IN_FAILED,
    TEMPLATES,
    UNAVAILABLE_PROVIDER,
    _admin_write_gate,
    _cookie,
    _login_again,
    _new_password_problem,
    _oidc_account_refusal,
    _oidc_page,
    _oidc_provider,
    _oidc_redirect,
    _password_page,
    _prove_password,
    _sso_button,
    _start_oidc,
    client_address,
    current_session,
    forbidden_page,
)


def build_router(config: Config) -> APIRouter:
    router = APIRouter()

    @router.get("/login", response_class=HTMLResponse)
    def login_form(request: Request) -> Response:
        if current_session(request) is not None:
            return RedirectResponse("/", status_code=303)
        #
        # A token is needed to protect the login post itself, and there is no
        # session to derive one from yet. A short-lived cookie carries one, set
        # here and replaced by the real session cookie on success.
        #
        pre_token = auth.new_session_token()
        response: Response = TEMPLATES.TemplateResponse(
            request,
            "login.html",
            {"error": None, "csrf_token": auth.csrf_token(pre_token), "sso": _sso_button(request)},
        )
        response.set_cookie(
            auth.PRE_SESSION_COOKIE,
            pre_token,
            max_age=600,
            httponly=True,
            secure=config.session.cookie_secure,
            samesite="lax",
            path="/login",
        )
        return response

    @router.post("/login", response_class=HTMLResponse)
    def login(
        request: Request,
        username: str = Form(default="", max_length=64),
        password: str = Form(default="", max_length=auth.MAX_PASSWORD_BYTES),
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        pre_token = request.cookies.get(auth.PRE_SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(pre_token, csrf_token):
            #
            # Not an error page. A stale form is the ordinary cause - the tab was
            # open longer than the pre-session cookie lived - and the useful
            # answer is a fresh form, not a diagnosis.
            #
            return _login_again(request, config)

        address = client_address(request)
        window = config.throttle.window_minutes
        with request.app.state.pool.connection() as connection:
            failures = db.failures_since_last_success(
                connection, username=username, client_ip=address, window_minutes=window
            )
            throttled = failures >= config.throttle.max_failures or (
                db.account_failures_since_last_success(
                    connection, username=username, window_minutes=window
                )
                >= config.throttle.max_failures * auth.ACCOUNT_FAILURE_FACTOR
            )
            account = None if throttled else db.account_by_username(connection, username)
            provider = db.oidc_provider(connection)
        #
        # While sign-in goes through the provider, a password signs in a
        # break-glass account only (B195) - unless the installation chose all
        # local accounts. Refused exactly as a wrong password is, so the form
        # does not say which accounts are break-glass.
        #
        held_back = (
            account is not None
            and provider is not None
            and provider.enabled
            and provider.local_login == "break_glass_only"
            and not account.break_glass
        )
        #
        # The hash is computed holding no connection, and at most
        # auth.HASHING_AT_ONCE at a time: six connections serve every page, and
        # a stream of sign-ins held them through Argon2 (security review S01,
        # B305). A throttled attempt is refused without hashing - the throttle
        # counts names that do not exist the same way, so skipping it says
        # nothing about who has an account.
        #
        busy = False
        if throttled:
            accepted = False
        elif not auth.HASHING.acquire(timeout=auth.HASHING_WAIT_SECONDS):
            accepted, busy = False, True
        else:
            try:
                if (
                    account is None
                    or account.disabled
                    or account.password_hash is None
                    or held_back
                ):
                    #
                    # The same time is spent whether the account is missing,
                    # disabled, the provider's (which has no password) or held
                    # back, so none of them can be told apart from outside.
                    #
                    auth.burn_absent_user_time(password)
                    accepted = False
                else:
                    accepted = auth.verify_password(account.password_hash, password)
            finally:
                auth.HASHING.release()
        if busy:
            #
            # Not counted against the name or the address: the load is not
            # this person's doing, and a flood must not lock real users out.
            #
            return _login_again(request, config, error=SIGN_IN_BUSY)

        with request.app.state.pool.connection() as connection:
            if accepted:
                #
                # Read again before the session is made: the account may have
                # been disabled or its password changed while the hash ran.
                #
                current = db.account_by_username(connection, username)
                accepted = (
                    current is not None
                    and account is not None
                    and current.id == account.id
                    and not current.disabled
                    and current.password_hash == account.password_hash
                )
            db.record_login_attempt(
                connection, username=username or "?", client_ip=address, succeeded=accepted
            )
            if not accepted:
                db.record_audit_event(
                    connection,
                    actor=username or None,
                    action="login_failed",
                    detail={
                        "client_ip": address,
                        "reason": "throttled" if throttled else "rejected",
                    },
                )
                connection.commit()
                return _login_again(request, config, error=SIGN_IN_FAILED)

            assert account is not None  # noqa: S101 - accepted implies an account was found
            #
            # A new token on every login, which is what makes the rotation
            # requirement real: nothing a browser held before signing in is
            # still valid afterwards.
            #
            token = auth.new_session_token()
            expires_at = auth.absolute_expiry(config.session)
            db.create_session(
                connection,
                token_hash=auth.token_hash(token),
                user_id=account.id,
                expires_at=expires_at,
            )
            db.record_audit_event(
                connection,
                actor=account.username,
                action="login",
                detail={"client_ip": address, "role": account.role},
            )
            connection.commit()

        response = RedirectResponse("/", status_code=303)
        _cookie(response, config, token, expires_at)
        response.delete_cookie(auth.PRE_SESSION_COOKIE, path="/login")
        return response

    @router.get("/account/password", response_class=HTMLResponse)
    def account_password(request: Request) -> Response:
        session = current_session(request)
        if session is None:
            return RedirectResponse("/login", status_code=303)
        if session.source == "oidc":
            # The provider's account has no password here to change.
            return PlainTextResponse("Not found", status_code=404)
        return _password_page(
            request, config, session, changed=request.query_params.get("changed") == "1"
        )

    @router.post("/account/password", response_class=HTMLResponse)
    def change_password(
        request: Request,
        current_password: str = Form(default="", max_length=auth.MAX_PASSWORD_BYTES),
        new_password: str = Form(default="", max_length=auth.MAX_PASSWORD_BYTES),
        repeat_password: str = Form(default="", max_length=auth.MAX_PASSWORD_BYTES),
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        """An account's own new password, proved by the one it replaces (B189).

        Every role may, and it is not a management write: the switch that turns
        those off leaves a person able to change their own password. A wrong
        current password is a failed sign-in for this name and address - the
        same row, the same throttle - so a session somebody else is holding
        cannot be used to guess the password behind it.
        """

        session = current_session(request)
        if session is None:
            return RedirectResponse("/login", status_code=303)
        if session.source == "oidc":
            return PlainTextResponse("Not found", status_code=404)
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return forbidden_page(request, config)

        #
        # The new password is judged before the current one is tried, so a
        # typing mistake in the new one never spends a throttle attempt.
        #
        problem = _new_password_problem(new_password, repeat_password)
        if problem:
            return _password_page(request, config, session, problem=problem, status_code=400)

        address = client_address(request)
        with request.app.state.pool.connection() as connection:
            refused = _prove_password(
                connection,
                config,
                session,
                current_password,
                address=address,
                failed_action="password_change_failed",
                wrong="The current password is not correct.",
            )
            if refused:
                connection.commit()
                return _password_page(request, config, session, problem=refused, status_code=400)
            ended = db.change_password(
                connection,
                user_id=session.user_id,
                password_hash=auth.hash_password(new_password),
                keep=auth.token_hash(token),
            )
            db.record_audit_event(
                connection,
                actor=session.username,
                action="password_changed",
                detail={
                    "account": session.username,
                    "client_ip": address,
                    "sessions_revoked": ended,
                    "via": "web",
                },
            )
            connection.commit()

        # 303, so a refresh of the answer cannot send the form again.
        return RedirectResponse("/account/password?changed=1", status_code=303)

    @router.get("/login/oidc")
    def oidc_sign_in(request: Request) -> Response:
        """The provider button: off to the provider, bound to this browser."""

        if current_session(request) is not None:
            return RedirectResponse("/", status_code=303)
        provider = _oidc_provider(request)
        if provider is None or not provider.enabled:
            return RedirectResponse("/login", status_code=303)
        #
        # Always a fresh token, never the browser's own cookie sent back: the
        # tab leaves for the provider, and a login form still open in another
        # tab gets a fresh form, as a stale one always does.
        #
        pre_token = auth.new_session_token()
        try:
            started = _start_oidc(request, provider, mode="sign_in", bound_to=pre_token)
        except oidc_web.OidcProblem as error:
            return _login_again(request, config, error=f"{UNAVAILABLE_PROVIDER}: {error}")
        started.set_cookie(
            auth.PRE_SESSION_COOKIE,
            pre_token,
            max_age=600,
            httponly=True,
            secure=config.session.cookie_secure,
            samesite="lax",
            path="/login",
        )
        return started

    @router.get("/login/oidc/callback", response_class=HTMLResponse)
    def oidc_callback(request: Request) -> Response:
        """The provider's answer: a code to exchange, or why it said no (O5, B195-B199)."""

        state = request.query_params.get("state", "")[:128]
        code = request.query_params.get("code", "")[:4096]
        address = client_address(request)
        with request.app.state.pool.connection() as connection:
            pending = db.use_oidc_login(connection, state=state) if state else None
            connection.commit()
        if pending is None:
            return _login_again(
                request, config, error="That sign-in expired or was already used. Try again."
            )
        #
        # The answer must come back to the browser that asked: a sign-in to
        # the pre-sign-in cookie, a Test sign-in to the admin's session. Else
        # a code obtained elsewhere could be finished here.
        #
        bound = request.cookies.get(
            auth.SESSION_COOKIE if pending.mode == "test" else auth.PRE_SESSION_COOKIE, ""
        )
        if not bound or not hmac.compare_digest(auth.token_hash(bound), pending.pre_session_hash):
            return _login_again(
                request, config, error="That sign-in was started in another browser. Try again."
            )

        gate: AuthenticatedSession | Response | None = None
        if pending.mode == "test":
            gate = _admin_write_gate(config, request)
            if not isinstance(gate, AuthenticatedSession):
                return gate

        provider = _oidc_provider(request)
        if provider is None or provider.issuer is None:
            return _login_again(
                request, config, error="Sign-in through the provider is not set up."
            )
        refusal = request.query_params.get("error", "")[:64]
        if refusal:
            said = request.query_params.get("error_description", "")[:256] or refusal
            message = f"The provider did not sign you in: {said}"
            if isinstance(gate, AuthenticatedSession):
                return _oidc_page(config, request, gate, provider, problem=message, status_code=409)
            return _login_again(request, config, error=message)
        if not code:
            return _login_again(
                request, config, error="The provider answered without a code. Try again."
            )

        try:
            signed_in = oidc_web.ask(
                "exchange",
                provider,
                redirect=_oidc_redirect(request),
                code=code,
                verifier=pending.verifier,
                nonce=pending.nonce,
                username_claim=provider.username_claim,
                groups_claim=provider.groups_claim,
                claims=pending.mode == "test",
            )
        except oidc_web.OidcProblem as error:
            message = f"The provider's answer was refused: {error}"
            if isinstance(gate, AuthenticatedSession):
                return _oidc_page(config, request, gate, provider, problem=message, status_code=409)
            with request.app.state.pool.connection() as connection:
                db.record_audit_event(
                    connection,
                    actor=None,
                    action="login_failed",
                    detail={
                        "client_ip": address,
                        "reason": "oidc_refused",
                        "via": "oidc",
                        "error": str(error),
                    },
                )
                connection.commit()
            return _login_again(request, config, error=message)

        groups = [group for group in signed_in.get("groups", []) if isinstance(group, str)]
        role = oidc_web.role_for(provider, groups)
        username = str(signed_in.get("username", ""))[:64]
        issuer, subject = str(signed_in.get("issuer", "")), str(signed_in.get("subject", ""))

        if isinstance(gate, AuthenticatedSession):
            with request.app.state.pool.connection() as connection:
                # What a real sign-in would meet at the account step, so the
                # test does not promise a sign-in the account step refuses.
                refused = (
                    _oidc_account_refusal(
                        connection, issuer=issuer, subject=subject, username=username
                    )
                    if role is not None
                    else None
                )
                db.record_audit_event(
                    connection,
                    actor=gate.username,
                    action="oidc_tested",
                    detail={"issuer": issuer, "username": username, "role": role, "via": "web"},
                )
                connection.commit()
            return TEMPLATES.TemplateResponse(
                request,
                "settings-oidc-test.html",
                {
                    "username": gate.username,
                    "role": gate.role,
                    "csrf_token": auth.csrf_token(request.cookies.get(auth.SESSION_COOKIE, "")),
                    "section": "settings",
                    "management_writes": config.management_writes,
                    "result": signed_in,
                    "groups": groups,
                    "granted": role,
                    "refused": refused[0] if refused is not None else None,
                    "provider": provider,
                    "claims": json.dumps(
                        signed_in.get("claims", {}), indent=2, sort_keys=True, default=str
                    ),
                },
            )

        def refuse(message: str, reason: str) -> Response:
            with request.app.state.pool.connection() as connection:
                db.record_audit_event(
                    connection,
                    actor=username or None,
                    action="login_failed",
                    detail={
                        "client_ip": address,
                        "reason": reason,
                        "via": "oidc",
                        "issuer": issuer,
                    },
                )
                connection.commit()
            return _login_again(request, config, error=message)

        if not provider.enabled:
            return refuse("Sign-in through the provider is off.", "oidc_off")
        if role is None:
            return refuse(
                "Your account at the provider is in neither group that gives access here.",
                "no_group",
            )
        if not username or not subject:
            return refuse("The provider sent no name for you.", "no_username")

        with request.app.state.pool.connection() as connection:
            refused = _oidc_account_refusal(
                connection, issuer=issuer, subject=subject, username=username
            )
            if refused is not None:
                connection.rollback()
                return refuse(*refused)
            account = db.account_by_oidc(connection, issuer=issuer, subject=subject)
            if account is None:
                # The check above found the name free; one taken in between is
                # refused here by the insert.
                if not db.create_oidc_account(
                    connection, username=username, role=role, issuer=issuer, subject=subject
                ):
                    connection.rollback()
                    return refuse(f"An account named {username} already exists here.", "name_taken")
                account = db.account_by_oidc(connection, issuer=issuer, subject=subject)
            if account is None or account.disabled:
                connection.rollback()
                return refuse("That account is disabled here.", "disabled")
            if account.role != role:
                try:
                    db.set_role(connection, user_id=account.id, role=role)
                except db.LastAdmin:
                    connection.rollback()
                    return refuse(
                        "Your role at the provider changed, and this is the last active admin here.",
                        "last_admin",
                    )
                db.record_audit_event(
                    connection,
                    actor=account.username,
                    action="role_changed",
                    detail={
                        "account": account.username,
                        "role": role,
                        "previous": account.role,
                        "via": "oidc",
                    },
                )
            token = auth.new_session_token()
            expires_at = auth.absolute_expiry(config.session, through_provider=True)
            db.create_session(
                connection,
                token_hash=auth.token_hash(token),
                user_id=account.id,
                expires_at=expires_at,
                id_token=str(signed_in.get("id_token"))
                if provider.logout_mode == "provider"
                else None,
            )
            db.record_login_attempt(
                connection, username=account.username, client_ip=address, succeeded=True
            )
            db.record_audit_event(
                connection,
                actor=account.username,
                action="login",
                detail={"client_ip": address, "role": role, "via": "oidc", "issuer": issuer},
            )
            connection.commit()

        response = RedirectResponse("/", status_code=303)
        _cookie(response, config, token, expires_at)
        response.delete_cookie(auth.PRE_SESSION_COOKIE, path="/login")
        return response

    @router.post("/logout")
    def logout(
        request: Request,
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        response = RedirectResponse("/login", status_code=303)
        if not token or not auth.csrf_token_is_valid(token, csrf_token):
            return response

        with request.app.state.pool.connection() as connection:
            digest = auth.token_hash(token)
            session = db.session_by_hash(connection, digest)
            id_token = db.session_id_token(connection, digest)
            provider = db.oidc_provider(connection)
            db.revoke_session(connection, digest)
            db.record_audit_event(
                connection,
                actor=session.username if session else None,
                action="logout",
                detail={"client_ip": client_address(request)},
            )
            connection.commit()
        #
        # Signing out at the provider too, when the installation chose it
        # (B197): the session here is already ended; the provider's is its own
        # to end, and a provider that cannot be asked leaves this one done.
        #
        if (
            id_token
            and provider is not None
            and provider.enabled
            and provider.logout_mode == "provider"
        ):
            try:
                found = oidc_web.ask("discover", provider, redirect=_oidc_redirect(request))
            except oidc_web.OidcProblem:
                found = {}
            onward = oidc_web.end_session_url(
                found,
                provider,
                id_token=id_token,
                back_to=str(request.base_url).rstrip("/") + "/login",
            )
            if onward is not None:
                response = RedirectResponse(onward, status_code=303)
        response.delete_cookie(auth.SESSION_COOKIE, path="/")
        return response

    return router
