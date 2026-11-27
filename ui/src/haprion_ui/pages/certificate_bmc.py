"""A certificate's BMC (B526, B536): Check, Save and install, Install now, Change… and Remove….

An external certificate can name the BMC it is installed on. The manager then
installs it there after every renewal and checks what the BMC serves. The web
has no network of its own: every question to the BMC goes through root over
`bmc.sock` (`haprion.bmc_socket`), and the account is sealed here, in the
request that typed it, against the installation's public key - only root opens
it. *Install now* is a `bmc_install` job, as the install a save starts is.
"""

from __future__ import annotations

import base64
import binascii
from collections.abc import Sequence
from typing import Any
from uuid import UUID, uuid4

from fastapi import APIRouter, Form, Request, Response
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from haprion import bmc_socket
from haprion.bmc_socket import BmcAskError
from haprion.bmc_targets import TargetError, seal_account
from haprion.config import CERTIFICATE_ID

from haprion_ui import auth, bmc_page, certificates, db, features, operations, refusals
from haprion_ui.access import admin_write_gate, forbidden_page
from haprion_ui.bmc_page import BmcProblem, Checked
from haprion_ui.certificate_reading import registry_views
from haprion_ui.config import Config
from haprion_ui.db import AuthenticatedSession
from haprion_ui.refusals import refusal_page
from haprion_ui.templates import TEMPLATES
from haprion_ui.views import read_dns_public_key

Row = certificates.RegistryCertificateView


def build_router(config: Config) -> APIRouter:
    router = APIRouter()

    def back_to(certificate_id: str) -> str:
        return "/certificates?view=registry&open=" + certificate_id

    def _gate(
        request: Request, certificate_id: str, csrf_token: str | None = None
    ) -> tuple[AuthenticatedSession, Row] | Response:
        """An admin where writes are on, the form's token, and an external certificate's row."""

        session = admin_write_gate(config, request)
        if not isinstance(session, AuthenticatedSession):
            return session
        if not features.is_on(features.CERT_RECEIVERS) or not CERTIFICATE_ID.fullmatch(
            certificate_id
        ):
            return PlainTextResponse("Not found", status_code=404)
        if csrf_token is not None and not auth.csrf_token_is_valid(
            request.cookies.get(auth.SESSION_COOKIE, ""), csrf_token
        ):
            return forbidden_page(request, config)
        row = registry_views(request, config).get(certificate_id)
        if row is None or not row.exportable:
            return refusal_page(
                request,
                config,
                f"{certificate_id} is not an external certificate.",
                back="/certificates?view=registry",
            )
        return session, row

    def _page(
        request: Request,
        session: AuthenticatedSession,
        row: Row,
        *,
        mode: str,
        address: str = "",
        bmc_username: str = "",
        port: int = bmc_page.DEFAULT_PORT,
        checked: Checked | None = None,
        sealed: tuple[str, str] | None = None,
        problem: str = "",
        status_code: int = 200,
    ) -> Response:
        """`mode`: `form` (add, or change, and the answer to Check), `show` or `remove`."""

        bmc = row.bmc
        state = certificates.bmc_state(bmc) if bmc is not None else None
        return TEMPLATES.TemplateResponse(
            request,
            "certificate-bmc.html",
            {
                "username": session.username,
                "role": session.role,
                "csrf_token": auth.csrf_token(request.cookies.get(auth.SESSION_COOKIE, "")),
                "row": row,
                "bmc": bmc,
                "mode": mode,
                "state_label": row.state_label if bmc is not None else "",
                "state_tone": row.state_tone if bmc is not None else "",
                "state_active": row.state_active,
                "state_detail": state[1] if state is not None else "",
                "last_install": bmc_page.last_install(bmc) if bmc is not None else "",
                "pinned": bmc_page.fingerprint(bmc.pinned_sha256) if bmc is not None else "",
                "values": {
                    "address": address,
                    "bmc_username": bmc_username,
                    "port": port,
                },
                "checked": checked,
                "served": bmc_page.fingerprint(checked.served_sha256) if checked else "",
                "sealed": sealed,
                "public_key": read_dns_public_key(config),
                "back": back_to(row.identifier),
                "problem": problem[:600],
                "section": "certificates",
                "management_writes": config.management_writes,
                "demo_fixture": config.demo_fixture,
            },
            status_code=status_code,
        )

    def _form_from(row: Row) -> dict[str, Any]:
        """Change…: the form filled in from the saved target; the password is typed again."""

        bmc = row.bmc
        if bmc is None:
            return {}
        return {"address": bmc.address, "bmc_username": bmc.username, "port": bmc.port}

    def _shown_port(port: str) -> int:
        """The port drawn back into a form that was refused: the one typed, if it is one."""

        try:
            return bmc_page.port_of(port)
        except BmcProblem:
            return bmc_page.DEFAULT_PORT

    # - the page ------------------------------------------------------------------

    @router.post("/certificates/bmc", response_class=HTMLResponse)
    def certificate_bmc_from_selection(
        request: Request,
        certificate: Sequence[str] = Form(default=()),
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        """*BMC…* in the registry's button row: one external certificate, to its own page."""

        chosen = tuple(certificate)
        if len(chosen) != 1 or not CERTIFICATE_ID.fullmatch(chosen[0]):
            session = admin_write_gate(config, request)
            if not isinstance(session, AuthenticatedSession):
                return session
            return refusal_page(
                request,
                config,
                "Choose one external certificate.",
                back="/certificates?view=registry",
            )
        gate = _gate(request, chosen[0], csrf_token)
        if not isinstance(gate, tuple):
            return gate
        return RedirectResponse("/certificates/" + chosen[0] + "/bmc", status_code=303)

    @router.get("/certificates/{certificate_id}/bmc", response_class=HTMLResponse)
    def certificate_bmc_page(request: Request, certificate_id: str) -> Response:
        gate = _gate(request, certificate_id)
        if not isinstance(gate, tuple):
            return gate
        session, row = gate
        if row.bmc is None:
            return _page(request, session, row, mode="form")
        asked = request.query_params.get("do")
        if asked == "change":
            return _page(request, session, row, mode="form", **_form_from(row))
        if asked == "remove":
            return _page(request, session, row, mode="remove")
        return _page(request, session, row, mode="show")

    # - Check ---------------------------------------------------------------------

    @router.post("/certificates/{certificate_id}/bmc/check", response_class=HTMLResponse)
    def certificate_bmc_check(
        request: Request,
        certificate_id: str,
        address: str = Form(default="", max_length=253),
        bmc_username: str = Form(default="", max_length=256),
        password: str = Form(default="", max_length=1024),
        port: str = Form(default="", max_length=5),
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        """Seal the account, ask the BMC through root, and show what it serves; nothing is saved."""

        gate = _gate(request, certificate_id, csrf_token)
        if not isinstance(gate, tuple):
            return gate
        session, row = gate
        try:
            target_port = bmc_page.port_of(port)
            target_address = bmc_page.address_of(address)
            public_key = read_dns_public_key(config)
            if public_key is None:
                raise BmcProblem("This installation has no key to seal the account with.")
            try:
                box = seal_account(
                    public_key,
                    certificate_id=certificate_id,
                    address=target_address,
                    username=bmc_username,
                    password=password,
                )
            except TargetError as refused:
                raise BmcProblem(f"{str(refused)[:1].upper()}{str(refused)[1:]}.") from None
            try:
                answer = bmc_socket.ask(
                    "check",
                    certificate_id,
                    address=target_address,
                    port=target_port,
                    key_id=public_key.key_id,
                    ciphertext=box,
                )
            except BmcAskError as refused:
                raise BmcProblem(
                    bmc_page.refusal(
                        refused.code, str(refused), address=target_address, port=target_port
                    )
                ) from None
            checked = bmc_page.checked(answer)
        except BmcProblem as problem:
            return _page(
                request,
                session,
                row,
                mode="form",
                port=_shown_port(port),
                problem=str(problem),
                address=address.strip(),
                bmc_username=bmc_username,
            )
        return _page(
            request,
            session,
            row,
            mode="form",
            port=target_port,
            checked=checked,
            sealed=(public_key.key_id, base64.b64encode(box).decode("ascii")),
            address=address.strip(),
            bmc_username=bmc_username,
        )

    # - Save and install ------------------------------------------------------------

    @router.post("/certificates/{certificate_id}/bmc/save", response_class=HTMLResponse)
    def certificate_bmc_save(
        request: Request,
        certificate_id: str,
        address: str = Form(default="", max_length=253),
        port: str = Form(default="", max_length=5),
        fingerprint_sha256: str = Form(default="", max_length=64),
        key_id: str = Form(default="", max_length=128),
        ciphertext_base64: str = Form(default="", max_length=8192),
        confirmed: str = Form(default="", max_length=8),
        idempotency_key: str = Form(default="", max_length=64),
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        """Write the confirmed target through root, then start its install as a job."""

        gate = _gate(request, certificate_id, csrf_token)
        if not isinstance(gate, tuple):
            return gate
        session, row = gate
        try:
            key = UUID(idempotency_key)
        except ValueError:
            return PlainTextResponse("A request key is required", status_code=400)
        try:
            target_port = bmc_page.port_of(port)
            target_address = bmc_page.address_of(address)
            if confirmed != "yes":
                raise BmcProblem(
                    "Confirm that the fingerprint is the one the BMC's own web page shows, "
                    "then save."
                )
            if not bmc_page.FINGERPRINT.fullmatch(fingerprint_sha256) or not key_id:
                raise BmcProblem("The BMC's answer was not read. Check it again.")
            try:
                box = base64.b64decode(ciphertext_base64, validate=True)
            except binascii.Error:
                raise BmcProblem("The account was not read. Check it again.") from None
        except BmcProblem as problem:
            return _page(
                request,
                session,
                row,
                mode="form",
                address=address.strip(),
                problem=str(problem),
            )
        try:
            saved = bmc_socket.ask(
                "save",
                certificate_id,
                address=target_address,
                port=target_port,
                fingerprint_sha256=fingerprint_sha256,
                key_id=key_id,
                ciphertext=box,
            )
        except BmcAskError as refused:
            detail = {
                "certificate": certificate_id,
                "address": target_address,
                "port": target_port,
                "fingerprint_sha256": fingerprint_sha256,
            }
            if refused.code == "unanswered":
                _audit(request, session, "bmc_target_saved", {**detail, "outcome": "unknown"})
            return _page(
                request,
                session,
                row,
                mode="form",
                address=target_address,
                port=target_port,
                problem=bmc_page.refusal(
                    refused.code, str(refused), address=target_address, port=target_port
                ),
            )
        _audit(
            request,
            session,
            "bmc_target_saved",
            {
                "certificate": certificate_id,
                "address": target_address,
                "port": target_port,
                "fingerprint_sha256": fingerprint_sha256,
                "user": saved.get("username"),
            },
        )
        #
        # Saved: the install the save starts. A certificate job already
        # running holds it back, and the timer installs it within its interval
        # instead (B536): the target is saved either way, and the page says so.
        #
        refusal = _queue_install(request, session, certificate_id, "save", key)
        if refusal is not None:
            return refusal_page(
                request,
                config,
                f"The BMC was saved, but its install was not started: {refusal} "
                "It installs automatically within 15 minutes, or use Install now.",
                back=back_to(certificate_id),
            )
        return RedirectResponse(back_to(certificate_id), status_code=303)

    # - Install now -------------------------------------------------------------------

    @router.post("/certificates/{certificate_id}/bmc/install", response_class=HTMLResponse)
    def certificate_bmc_install(
        request: Request,
        certificate_id: str,
        idempotency_key: str = Form(default="", max_length=64),
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        gate = _gate(request, certificate_id, csrf_token)
        if not isinstance(gate, tuple):
            return gate
        session, row = gate
        try:
            key = UUID(idempotency_key)
        except ValueError:
            return PlainTextResponse("A request key is required", status_code=400)
        if row.bmc is None:
            return refusal_page(
                request,
                config,
                f"{certificate_id} names no BMC.",
                back=back_to(certificate_id),
            )
        refusal = _queue_install(request, session, certificate_id, "install_now", key)
        if refusal is not None:
            return _page(request, session, row, mode="show", problem=refusal, status_code=409)
        return RedirectResponse(back_to(certificate_id), status_code=303)

    # - Remove… -----------------------------------------------------------------------

    @router.post("/certificates/{certificate_id}/bmc/remove", response_class=HTMLResponse)
    def certificate_bmc_remove(
        request: Request,
        certificate_id: str,
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        """Take the target and its account away; the certificate stays external."""

        gate = _gate(request, certificate_id, csrf_token)
        if not isinstance(gate, tuple):
            return gate
        session, row = gate
        try:
            bmc_socket.ask("remove", certificate_id)
        except BmcAskError as refused:
            if refused.code == "unanswered":
                _audit(
                    request,
                    session,
                    "bmc_target_removed",
                    {"certificate": certificate_id, "outcome": "unknown"},
                )
            return _page(
                request,
                session,
                row,
                mode="remove",
                problem=bmc_page.refusal(
                    refused.code,
                    str(refused),
                    address=row.bmc.address if row.bmc else "",
                    port=row.bmc.port if row.bmc else bmc_page.DEFAULT_PORT,
                ),
                status_code=409,
            )
        _audit(
            request,
            session,
            "bmc_target_removed",
            {"certificate": certificate_id, "address": row.bmc.address if row.bmc else None},
        )
        return RedirectResponse(back_to(certificate_id), status_code=303)

    # - shared ------------------------------------------------------------------------

    def _audit(
        request: Request,
        session: AuthenticatedSession,
        action: str,
        detail: dict[str, object],
    ) -> None:
        """The row, and the poller told: the listing it caches holds the target."""

        with request.app.state.pool.connection() as connection:
            db.record_audit_event(connection, actor=session.username, action=action, detail=detail)
            db.wake_poller(connection)
            connection.commit()

    def _queue_install(
        request: Request,
        session: AuthenticatedSession,
        certificate_id: str,
        by: str,
        key: UUID,
    ) -> str | None:
        """Queue the `bmc_install` job; the sentence that refused it, or None."""

        payload = {"id": certificate_id, "by": by}
        operations.prepare(
            operation="bmc_install", cluster=None, request_id=uuid4(), payload=payload
        )
        with request.app.state.pool.connection() as connection:
            try:
                job = db.queue_job(
                    connection,
                    operation="bmc_install",
                    cluster=None,
                    payload=payload,
                    idempotency_key=key,
                )
            except db.CertificateBusy as busy:
                connection.rollback()
                return refusals.conflict_sentence(busy)
            db.record_audit_event(
                connection,
                actor=session.username,
                action="queue_job",
                cluster=None,
                request_id=job.request_id,
                detail={
                    "operation": "bmc_install",
                    "job": job.id,
                    "certificate": certificate_id,
                    "by": by,
                },
            )
            connection.commit()
        return None

    return router
