"""The DNS and NDES profiles a certificate is issued through."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import replace
from time import monotonic, sleep
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Form, Request, Response
from fastapi.responses import (
    HTMLResponse,
    PlainTextResponse,
    RedirectResponse,
)

from haprion_ui import (
    auth,
    certificates,
    db,
    dns_profile_form,
    jobs,
    ndes_profile_form,
)
from haprion_ui.config import Config
from haprion_ui.db import AuthenticatedSession
from haprion_ui.views import (
    DNS_PROFILE_APPLY_WAIT,
    TEMPLATES,
    _dns_public_key,
    _posted,
    current_session,
    forbidden_page,
    read_manager_certificates,
)


def build_router(config: Config) -> APIRouter:
    router = APIRouter()
    # - DNS provider profiles (P4) -----------------------------------------

    def _dns_profiles_gate(request: Request) -> AuthenticatedSession | Response:
        """The same three answers the certificate form gives before drawing."""

        session = current_session(request)
        if session is None:
            return RedirectResponse("/login", status_code=303)
        if not config.management_writes:
            return PlainTextResponse("Not found", status_code=404)
        if session.role != "admin":
            return forbidden_page(request, config)
        return session

    def _just_removed(request: Request, profile_ids: Sequence[str]) -> str:
        """The profile a removal was just asked for, if the address names one.

        The refused-removal banner is drawn once, on the page the removal
        lands on; after that the status column's "Removal refused" link
        carries the same fact without shouting it on every visit. Only an
        existing profile's ID is echoed, never the query string itself.
        """

        wanted = request.query_params.get("removed", "")
        return wanted if wanted in profile_ids else ""

    @router.get("/dns-profiles", response_class=HTMLResponse)
    def dns_profile_list(request: Request) -> Response:
        gate = _dns_profiles_gate(request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        with request.app.state.pool.connection() as connection:
            profiles = db.dns_profiles(connection)
            recent = db.profile_jobs(connection, "dns_profile_apply")
        public_key = _dns_public_key(config)
        catalogue = {provider.id: provider for provider in dns_profile_form.providers()}
        references = certificates.profile_references(
            read_manager_certificates(request, config), field="dns_profile"
        )
        statuses = {
            profile.id: dns_profile_form.without_stale_refusal(
                dns_profile_form.profile_status(profile.id, profile.revision, recent),
                profile.id,
                references,
            )
            for profile in profiles
        }
        rows = [
            {
                "profile": profile,
                "provider": catalogue.get(profile.provider_id),
                "status": statuses[profile.id],
                "current_key": public_key is not None and profile.key_id == public_key.key_id,
            }
            for profile in profiles
        ]
        return TEMPLATES.TemplateResponse(
            request,
            "dns-profiles.html",
            {
                "username": gate.username,
                "role": gate.role,
                "csrf_token": auth.csrf_token(token),
                "rows": rows,
                "just_removed": _just_removed(request, [profile.id for profile in profiles]),
                "public_key": public_key,
                "refresh": any(s.label in {"Applying", "Removing"} for s in statuses.values()),
                "certificate_job": jobs.certificate_in_flight(recent),
                "section": "certificates",
                "management_writes": config.management_writes,
                "demo_fixture": config.demo_fixture,
            },
        )

    @router.get("/dns-profiles/new", response_class=HTMLResponse)
    def dns_profile_new_form(request: Request, provider: str = "") -> Response:
        gate = _dns_profiles_gate(request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        form = replace(dns_profile_form.EMPTY_FORM, provider_id=provider[:32])
        return _dns_profile_form_page(request, gate, form, existing=None)

    @router.post("/dns-profiles/new", response_class=HTMLResponse)
    def dns_profile_new_submit(request: Request) -> Response:
        gate = _dns_profiles_gate(request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        return _dns_profile_submit(request, gate, existing=None)

    @router.get("/dns-profiles/{profile_id}/replace", response_class=HTMLResponse)
    def dns_profile_replace_form(request: Request, profile_id: str) -> Response:
        gate = _dns_profiles_gate(request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        with request.app.state.pool.connection() as connection:
            existing = db.dns_profile(connection, profile_id)
        if existing is None:
            return PlainTextResponse("Not found", status_code=404)
        form = dns_profile_form.ProfileForm(
            profile_id=existing.id, provider_id=existing.provider_id, values={}
        )
        return _dns_profile_form_page(request, gate, form, existing=existing)

    @router.post("/dns-profiles/{profile_id}/replace", response_class=HTMLResponse)
    def dns_profile_replace_submit(request: Request, profile_id: str) -> Response:
        gate = _dns_profiles_gate(request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        with request.app.state.pool.connection() as connection:
            existing = db.dns_profile(connection, profile_id)
        if existing is None:
            return PlainTextResponse("Not found", status_code=404)
        return _dns_profile_submit(request, gate, existing=existing)

    @router.get("/dns-profiles/{profile_id}/remove", response_class=HTMLResponse)
    def dns_profile_remove_form(request: Request, profile_id: str) -> Response:
        gate = _dns_profiles_gate(request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        with request.app.state.pool.connection() as connection:
            existing = db.dns_profile(connection, profile_id)
            recent = db.recent_jobs(connection)
        if existing is None:
            return PlainTextResponse("Not found", status_code=404)
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        return TEMPLATES.TemplateResponse(
            request,
            "dns-profile-remove.html",
            {
                "username": gate.username,
                "role": gate.role,
                "csrf_token": auth.csrf_token(token),
                "profile": existing,
                "certificate_job": jobs.certificate_in_flight(recent),
                "section": "certificates",
                "management_writes": config.management_writes,
                "demo_fixture": config.demo_fixture,
            },
        )

    @router.post("/dns-profiles/{profile_id}/remove")
    def dns_profile_remove_submit(
        request: Request,
        profile_id: str,
        csrf_token: Annotated[str, Form(max_length=128)],
        idempotency_key: Annotated[str, Form(max_length=64)],
    ) -> Response:
        gate = _dns_profiles_gate(request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return forbidden_page(request, config)
        try:
            key = UUID(idempotency_key)
        except ValueError:
            return PlainTextResponse("A request key is required", status_code=400)
        with request.app.state.pool.connection() as connection:
            existing = db.dns_profile(connection, profile_id)
            if existing is None:
                return PlainTextResponse("Not found", status_code=404)
            job = db.queue_job(
                connection,
                operation="dns_profile_apply",
                cluster=None,
                payload={"profile": existing.id, "revision": existing.revision, "remove": True},
                idempotency_key=key,
            )
            db.record_audit_event(
                connection,
                actor=gate.username,
                action="queue_job",
                cluster=None,
                request_id=job.request_id,
                detail={
                    "operation": "dns_profile_apply",
                    "job": job.id,
                    "profile": existing.id,
                    "revision": existing.revision,
                    "remove": True,
                },
            )
            connection.commit()
        _await_dns_profile_job(request, job.id)
        return RedirectResponse("/dns-profiles?removed=" + existing.id, status_code=303)

    def _dns_profile_submit(
        request: Request, session: AuthenticatedSession, *, existing: db.DnsProfile | None
    ) -> Response:
        """Seal one submission, store it, queue its apply job - or re-draw.

        Read as a raw form rather than through typed parameters, because the
        field names are the catalogue's, not this route's: which fields exist
        depends on the provider chosen, and only the catalogue knows.
        """

        posted = _posted(request)
        text = {key: value for key, value in posted.items() if isinstance(value, str)}
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, text.get(auth.CSRF_FIELD, "")):
            return forbidden_page(request, config)
        try:
            key = UUID(text.get("idempotency_key", ""))
        except ValueError:
            return PlainTextResponse("A request key is required", status_code=400)

        form = dns_profile_form.ProfileForm(
            profile_id=existing.id if existing else text.get("profile_id", "")[:64],
            provider_id=existing.provider_id if existing else text.get("provider_id", "")[:32],
            values={
                name.removeprefix("field."): value
                for name, value in text.items()
                if name.startswith("field.")
            },
        )
        public_key = _dns_public_key(config)
        if public_key is None:
            return _dns_profile_form_page(
                request,
                session,
                form,
                existing=existing,
                problem="This installation has no DNS profile key; see the installation "
                "guide, 1.4.5.",
            )
        revision = existing.revision + 1 if existing else 1
        with request.app.state.pool.connection() as connection:
            #
            # The secret is sealed again and the row written before the job,
            # so a second click under the same key met its own first one as
            # "already exists" (review 26-10-24, 02-06).
            #
            earlier = db.job_for_key(connection, key, operation="dns_profile_apply", cluster=None)
            taken = [profile.id for profile in db.dns_profiles(connection)]
        if earlier is not None:
            return RedirectResponse("/dns-profiles", status_code=303)
        try:
            sealed = dns_profile_form.seal_submission(
                form, public_key, revision=revision, taken=taken
            )
        except dns_profile_form.FormProblem as problem:
            return _dns_profile_form_page(
                request, session, form, existing=existing, problem=str(problem)
            )

        payload = {"profile": sealed.profile_id, "revision": revision}
        with request.app.state.pool.connection() as connection:
            try:
                if existing is None:
                    stored = db.create_dns_profile(
                        connection,
                        profile_id=sealed.profile_id,
                        name=sealed.name,
                        provider_id=sealed.provider_id,
                        key_id=sealed.key_id,
                        ciphertext=sealed.ciphertext,
                        actor=session.username,
                    )
                else:
                    stored = db.replace_dns_profile(
                        connection,
                        profile_id=sealed.profile_id,
                        revision=revision,
                        key_id=sealed.key_id,
                        ciphertext=sealed.ciphertext,
                        actor=session.username,
                        name=sealed.name,
                    )
            except db.ProfileExists:
                connection.rollback()
                return _dns_profile_form_page(
                    request,
                    session,
                    form,
                    existing=existing,
                    problem="Profile ID — a profile with this ID already exists.",
                )
            except db.ProfileMissing:
                connection.rollback()
                return _dns_profile_form_page(
                    request,
                    session,
                    form,
                    existing=existing,
                    problem="The profile changed while this form was open. Reload and try again.",
                )
            #
            # The row and the job are one transaction: a profile saved without
            # its apply job would look stored and never reach certbot, which
            # is the gap B147 closed.
            #
            try:
                job = db.queue_job(
                    connection,
                    operation="dns_profile_apply",
                    cluster=None,
                    payload=payload,
                    idempotency_key=key,
                )
            except db.CertificateBusy:
                connection.rollback()
                return _dns_profile_form_page(
                    request,
                    session,
                    form,
                    existing=existing,
                    problem="A certificate job is already running. Wait for it to finish "
                    "on the Jobs page, then save again.",
                )
            db.record_audit_event(
                connection,
                actor=session.username,
                action="queue_job",
                cluster=None,
                request_id=job.request_id,
                detail={
                    "operation": "dns_profile_apply",
                    "job": job.id,
                    "profile": stored.id,
                    "revision": stored.revision,
                },
            )
            connection.commit()
        _await_dns_profile_job(request, job.id)
        return RedirectResponse("/dns-profiles", status_code=303)

    def _await_dns_profile_job(request: Request, job_id: int) -> None:
        """Give the worker a moment before the list is drawn.

        Applying a profile is one helper call and takes about a second when
        the queue is idle, so the page after saving should say "In effect",
        not "Applying" with a pointer to another page. Waits a few seconds at
        most; a longer job is left to the list's own refresh.
        """

        deadline = monotonic() + DNS_PROFILE_APPLY_WAIT
        while monotonic() < deadline:
            sleep(0.25)
            with request.app.state.pool.connection() as connection:
                state = db.job_state(connection, job_id)
            if state not in {"pending", "running"}:
                return

    def _dns_profile_form_page(
        request: Request,
        session: AuthenticatedSession,
        form: dns_profile_form.ProfileForm,
        *,
        existing: db.DnsProfile | None,
        problem: str = "",
    ) -> Response:
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        chosen = dns_profile_form.provider(form.provider_id)
        with request.app.state.pool.connection() as connection:
            recent = db.recent_jobs(connection)
        return TEMPLATES.TemplateResponse(
            request,
            "dns-profile-form.html",
            {
                "username": session.username,
                "role": session.role,
                "csrf_token": auth.csrf_token(token),
                "form": form,
                "values": dns_profile_form.redraw_values(chosen, form.values),
                "chosen": chosen,
                "verification_label": (
                    dns_profile_form.verification_label(chosen) if chosen else ""
                ),
                "providers": dns_profile_form.providers(),
                "existing": existing,
                "public_key": _dns_public_key(config),
                "problem": problem,
                "certificate_job": jobs.certificate_in_flight(recent),
                "section": "certificates",
                "management_writes": config.management_writes,
                "demo_fixture": config.demo_fixture,
            },
        )

    def _ndes_profile_form_page(
        request: Request,
        session: AuthenticatedSession,
        form: ndes_profile_form.ProfileForm,
        *,
        existing: db.DnsProfile | None,
        problem: str = "",
    ) -> Response:
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        return TEMPLATES.TemplateResponse(
            request,
            "ndes-profile-form.html",
            {
                "username": session.username,
                "role": session.role,
                "csrf_token": auth.csrf_token(token),
                "form": form,
                "values": ndes_profile_form.redraw_values(form.values),
                "existing": existing,
                "public_key": _dns_public_key(config),
                "problem": problem,
                "section": "certificates",
                "management_writes": config.management_writes,
                "demo_fixture": config.demo_fixture,
            },
        )

    def _ndes_missing(request: Request) -> bool:
        """The manager's last reading says the runtime policy has no ndes block.

        Its helper refuses an NDES profile then, after the form had taken it
        (prod 26-10-28, F28). An older engine says nothing, and is not refused.
        """

        manager = read_manager_certificates(request, config)
        return manager is not None and manager.result.get("ndes_configured") is False

    @router.get("/ndes-profiles", response_class=HTMLResponse)
    def ndes_profile_list(request: Request) -> Response:
        gate = _dns_profiles_gate(request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        with request.app.state.pool.connection() as connection:
            profiles = db.ndes_profiles(connection)
            recent = db.profile_jobs(connection, "ndes_profile_apply")
        manager = read_manager_certificates(request, config)
        references = certificates.profile_references(manager, field="ndes_profile")
        statuses = {
            p.id: dns_profile_form.without_stale_refusal(
                ndes_profile_form.profile_status(p.id, p.revision, recent), p.id, references
            )
            for p in profiles
        }
        return TEMPLATES.TemplateResponse(
            request,
            "ndes-profiles.html",
            {
                "username": gate.username,
                "role": gate.role,
                "profiles": profiles,
                "statuses": statuses,
                "just_removed": _just_removed(request, [profile.id for profile in profiles]),
                "public_key": _dns_public_key(config),
                "ndes_missing": manager is not None
                and manager.result.get("ndes_configured") is False,
                "refresh": any(p.label in {"Applying", "Removing"} for p in statuses.values()),
                "section": "certificates",
                "management_writes": config.management_writes,
                "demo_fixture": config.demo_fixture,
            },
        )

    @router.get("/ndes-profiles/new", response_class=HTMLResponse)
    def ndes_profile_new_form(request: Request) -> Response:
        gate = _dns_profiles_gate(request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        if _ndes_missing(request):
            return RedirectResponse("/ndes-profiles", status_code=303)
        return _ndes_profile_form_page(request, gate, ndes_profile_form.EMPTY_FORM, existing=None)

    @router.post("/ndes-profiles/new", response_class=HTMLResponse)
    def ndes_profile_new_submit(request: Request) -> Response:
        gate = _dns_profiles_gate(request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        if _ndes_missing(request):
            return RedirectResponse("/ndes-profiles", status_code=303)
        return _ndes_profile_submit(request, gate, existing=None)

    @router.get("/ndes-profiles/{profile_id}/replace", response_class=HTMLResponse)
    def ndes_profile_replace_form(request: Request, profile_id: str) -> Response:
        gate = _dns_profiles_gate(request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        if _ndes_missing(request):
            return RedirectResponse("/ndes-profiles", status_code=303)
        with request.app.state.pool.connection() as connection:
            existing = db.ndes_profile(connection, profile_id)
        if existing is None:
            return PlainTextResponse("Not found", status_code=404)
        # The endpoint is not a secret and the row keeps a plain copy, so the
        # replace form starts with it; only the challenge is typed again.
        return _ndes_profile_form_page(
            request,
            gate,
            ndes_profile_form.ProfileForm(existing.id, values={"endpoint": existing.endpoint}),
            existing=existing,
        )

    @router.post("/ndes-profiles/{profile_id}/replace", response_class=HTMLResponse)
    def ndes_profile_replace_submit(request: Request, profile_id: str) -> Response:
        gate = _dns_profiles_gate(request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        if _ndes_missing(request):
            return RedirectResponse("/ndes-profiles", status_code=303)
        with request.app.state.pool.connection() as connection:
            existing = db.ndes_profile(connection, profile_id)
        if existing is None:
            return PlainTextResponse("Not found", status_code=404)
        return _ndes_profile_submit(request, gate, existing=existing)

    def _ndes_profile_submit(
        request: Request, session: AuthenticatedSession, *, existing: db.DnsProfile | None
    ) -> Response:
        """Seal one submission, store it, queue its apply job - or re-draw.

        Read as a raw form rather than through typed parameters, because the
        field names are the catalogue's, not this route's: which fields exist
        depends on the provider chosen, and only the catalogue knows.
        """

        posted = _posted(request)
        text = {key: value for key, value in posted.items() if isinstance(value, str)}
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, text.get(auth.CSRF_FIELD, "")):
            return forbidden_page(request, config)
        try:
            key = UUID(text.get("idempotency_key", ""))
        except ValueError:
            return PlainTextResponse("A request key is required", status_code=400)

        form = ndes_profile_form.ProfileForm(
            profile_id=existing.id if existing else text.get("profile_id", "")[:64],
            provider_id=existing.provider_id if existing else text.get("provider_id", "")[:32],
            values={
                name.removeprefix("field."): value
                for name, value in text.items()
                if name.startswith("field.")
            },
        )
        public_key = _dns_public_key(config)
        if public_key is None:
            return _ndes_profile_form_page(
                request,
                session,
                form,
                existing=existing,
                problem="This installation has no certificate profile key; see the installation "
                "guide, 1.4.8.",
            )
        revision = existing.revision + 1 if existing else 1
        with request.app.state.pool.connection() as connection:
            # Sealed again on every submission, as the DNS form says.
            earlier = db.job_for_key(connection, key, operation="ndes_profile_apply", cluster=None)
            taken = [profile.id for profile in db.ndes_profiles(connection)]
        if earlier is not None:
            return RedirectResponse("/ndes-profiles", status_code=303)
        try:
            sealed = ndes_profile_form.seal_submission(
                form, public_key, revision=revision, taken=taken
            )
        except ndes_profile_form.FormProblem as problem:
            return _ndes_profile_form_page(
                request, session, form, existing=existing, problem=str(problem)
            )

        payload = {"profile": sealed.profile_id, "revision": revision}
        with request.app.state.pool.connection() as connection:
            try:
                if existing is None:
                    stored = db.create_ndes_profile(
                        connection,
                        profile_id=sealed.profile_id,
                        name=sealed.name,
                        provider_id=sealed.provider_id,
                        key_id=sealed.key_id,
                        ciphertext=sealed.ciphertext,
                        actor=session.username,
                        endpoint=sealed.endpoint,
                    )
                else:
                    stored = db.replace_ndes_profile(
                        connection,
                        profile_id=sealed.profile_id,
                        revision=revision,
                        key_id=sealed.key_id,
                        ciphertext=sealed.ciphertext,
                        actor=session.username,
                        endpoint=sealed.endpoint,
                        name=sealed.name,
                    )
            except db.ProfileExists:
                connection.rollback()
                return _ndes_profile_form_page(
                    request,
                    session,
                    form,
                    existing=existing,
                    problem="Profile ID — a profile with this ID already exists.",
                )
            except db.ProfileMissing:
                connection.rollback()
                return _ndes_profile_form_page(
                    request,
                    session,
                    form,
                    existing=existing,
                    problem="The profile changed while this form was open. Reload and try again.",
                )
            #
            # The row and the job are one transaction: a profile saved without
            # its apply job would look stored and never reach certbot, which
            # is the gap B147 closed.
            #
            try:
                job = db.queue_job(
                    connection,
                    operation="ndes_profile_apply",
                    cluster=None,
                    payload=payload,
                    idempotency_key=key,
                )
            except db.CertificateBusy:
                connection.rollback()
                return _ndes_profile_form_page(
                    request,
                    session,
                    form,
                    existing=existing,
                    problem="A certificate job is already running. Wait for it to finish "
                    "on the Jobs page, then save again.",
                )
            db.record_audit_event(
                connection,
                actor=session.username,
                action="queue_job",
                cluster=None,
                request_id=job.request_id,
                detail={
                    "operation": "ndes_profile_apply",
                    "job": job.id,
                    "profile": stored.id,
                    "revision": stored.revision,
                },
            )
            connection.commit()
        _await_dns_profile_job(request, job.id)
        return RedirectResponse("/ndes-profiles", status_code=303)

    @router.get("/ndes-profiles/{profile_id}/remove", response_class=HTMLResponse)
    def ndes_profile_remove_form(request: Request, profile_id: str) -> Response:
        gate = _dns_profiles_gate(request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        with request.app.state.pool.connection() as connection:
            existing = db.ndes_profile(connection, profile_id)
            recent = db.recent_jobs(connection)
        if existing is None:
            return PlainTextResponse("Not found", status_code=404)
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        return TEMPLATES.TemplateResponse(
            request,
            "ndes-profile-remove.html",
            {
                "username": gate.username,
                "role": gate.role,
                "csrf_token": auth.csrf_token(token),
                "profile": existing,
                "certificate_job": jobs.certificate_in_flight(recent),
                "section": "certificates",
                "management_writes": config.management_writes,
                "demo_fixture": config.demo_fixture,
            },
        )

    @router.post("/ndes-profiles/{profile_id}/remove")
    def ndes_profile_remove_submit(
        request: Request,
        profile_id: str,
        csrf_token: Annotated[str, Form(max_length=128)],
        idempotency_key: Annotated[str, Form(max_length=64)],
    ) -> Response:
        gate = _dns_profiles_gate(request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return forbidden_page(request, config)
        try:
            key = UUID(idempotency_key)
        except ValueError:
            return PlainTextResponse("A request key is required", status_code=400)
        with request.app.state.pool.connection() as connection:
            existing = db.ndes_profile(connection, profile_id)
            if existing is None:
                return PlainTextResponse("Not found", status_code=404)
            job = db.queue_job(
                connection,
                operation="ndes_profile_apply",
                cluster=None,
                payload={"profile": existing.id, "revision": existing.revision, "remove": True},
                idempotency_key=key,
            )
            db.record_audit_event(
                connection,
                actor=gate.username,
                action="queue_job",
                cluster=None,
                request_id=job.request_id,
                detail={
                    "operation": "ndes_profile_apply",
                    "job": job.id,
                    "profile": existing.id,
                    "revision": existing.revision,
                    "remove": True,
                },
            )
            connection.commit()
        _await_dns_profile_job(request, job.id)
        return RedirectResponse("/ndes-profiles?removed=" + existing.id, status_code=303)

    return router
