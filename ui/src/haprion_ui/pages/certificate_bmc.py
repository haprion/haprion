"""A BMC receiver (B526, B536, B538): Add a BMC, Check, Save and install, Install now, Change… and Remove….

A BMC is a receiver the manager installs on instead of one that fetches: it is
listed under Receivers and carries one certificate. The manager installs that
certificate there after every renewal and checks what the BMC serves. The web
has no network of its own: every question to the BMC goes through root over
`bmc.sock` (`haprion.bmc_socket`), and the account is sealed here, in the
request that typed it, against the installation's public key - only root opens
it. *Install now* is a `bmc_install` job, as the install a save starts is.
"""

from __future__ import annotations

import base64
import binascii
from typing import Any
from uuid import UUID, uuid4

from fastapi import APIRouter, Form, Request, Response
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from haprion import bmc_socket
from haprion.bmc_socket import BmcAskError
from haprion.bmc_targets import TargetError, seal_account
from haprion.config import CERTIFICATE_ID, RECEIVER_ID, receiver_id_names_a_host

from haprion_ui import auth, bmc_page, certificates, db, features, operations, refusals
from haprion_ui.access import admin_write_gate, forbidden_page
from haprion_ui.bmc_page import BmcProblem, Checked
from haprion_ui.config import Config
from haprion_ui.db import AuthenticatedSession
from haprion_ui.refusals import refusal_page
from haprion_ui.templates import TEMPLATES
from haprion_ui.views import read_dns_public_key, registry_overview

Row = certificates.BmcReceiverRow
BACK = "/certificates/receivers"


def is_bmc_id(value: str) -> bool:
    """A BMC receiver's ID as the registry takes it: its name or address."""

    return bool(RECEIVER_ID.fullmatch(value)) and receiver_id_names_a_host(value)


def build_router(config: Config) -> APIRouter:
    router = APIRouter()

    def page_of(bmc_id: str) -> str:
        return "/certificates/receivers/bmc/" + bmc_id

    def _gate(request: Request, csrf_token: str | None = None) -> AuthenticatedSession | Response:
        """An admin where writes are on, and the form's token."""

        session = admin_write_gate(config, request)
        if not isinstance(session, AuthenticatedSession):
            return session
        if not features.is_on(features.CERT_RECEIVERS):
            return PlainTextResponse("Not found", status_code=404)
        if csrf_token is not None and not auth.csrf_token_is_valid(
            request.cookies.get(auth.SESSION_COOKIE, ""), csrf_token
        ):
            return forbidden_page(request, config)
        return session

    def _registry(request: Request) -> certificates.RegistryView | None:
        return registry_overview(config, request)

    def _row(registry: certificates.RegistryView | None, bmc_id: str) -> Row | None:
        if registry is None or not is_bmc_id(bmc_id):
            return None
        return next((row for row in registry.bmc_rows if row.identifier == bmc_id), None)

    def _choices(registry: certificates.RegistryView | None, bmc_id: str | None) -> tuple[str, ...]:
        """The certificates a BMC may carry: an external one, and no other BMC's (B536, B538)."""

        if registry is None:
            return ()
        return tuple(
            entry.identifier
            for entry in registry.certificates
            if entry.exportable and (entry.bmc is None or entry.bmc.address == bmc_id)
        )

    def _page(
        request: Request,
        session: AuthenticatedSession,
        row: Row | None,
        *,
        mode: str,
        registry: certificates.RegistryView | None = None,
        address: str = "",
        bmc_username: str = "",
        port: int = bmc_page.DEFAULT_PORT,
        certificate: str = "",
        checked: Checked | None = None,
        sealed: tuple[str, str] | None = None,
        problem: str = "",
        status_code: int = 200,
    ) -> Response:
        """`mode`: `form` (add, or change, and the answer to Check), `show` or `remove`."""

        registry = registry if registry is not None else _registry(request)
        view = row.view if row is not None else None
        state = certificates.bmc_state(view) if view is not None else None
        return TEMPLATES.TemplateResponse(
            request,
            "certificate-bmc.html",
            {
                "username": session.username,
                "role": session.role,
                "csrf_token": auth.csrf_token(request.cookies.get(auth.SESSION_COOKIE, "")),
                "row": row,
                "view": view,
                "mode": mode,
                "state_label": state[0] if state is not None else "",
                "state_tone": state[2] if state is not None else "",
                "state_detail": state[1] if state is not None else "",
                "last_install": bmc_page.last_install(view) if view is not None else "",
                "pinned": bmc_page.fingerprint(row.pinned_sha256) if row is not None else "",
                "choices": _choices(registry, row.identifier if row is not None else None),
                "values": {
                    "address": address,
                    "bmc_username": bmc_username,
                    "port": port,
                    "certificate": certificate,
                },
                "checked": checked,
                "served": bmc_page.fingerprint(checked.served_sha256) if checked else "",
                "sealed": sealed,
                "public_key": read_dns_public_key(config),
                "back": page_of(row.identifier) if row is not None else BACK,
                "problem": problem[:600],
                "section": "certificates",
                "management_writes": config.management_writes,
                "demo_fixture": config.demo_fixture,
            },
            status_code=status_code,
        )

    def _form_from(row: Row) -> dict[str, Any]:
        """Change…: the form filled in from the saved BMC; the password is typed again."""

        return {
            "address": row.identifier,
            "bmc_username": row.username,
            "port": row.port,
            "certificate": row.certificate or "",
        }

    def _shown_port(port: str) -> int:
        """The port drawn back into a form that was refused: the one typed, if it is one."""

        try:
            return bmc_page.port_of(port)
        except BmcProblem:
            return bmc_page.DEFAULT_PORT

    def _chosen(certificate: str, choices: tuple[str, ...]) -> str:
        if not CERTIFICATE_ID.fullmatch(certificate) or certificate not in choices:
            raise BmcProblem("Choose the certificate the BMC carries.")
        return certificate

    # - the pages -------------------------------------------------------------------

    @router.get("/certificates/receivers/bmc/new", response_class=HTMLResponse)
    def bmc_new(request: Request) -> Response:
        session = _gate(request)
        if not isinstance(session, AuthenticatedSession):
            return session
        return _page(request, session, None, mode="form")

    @router.get("/certificates/receivers/bmc/{bmc_id}", response_class=HTMLResponse)
    def bmc_receiver_page(request: Request, bmc_id: str) -> Response:
        session = _gate(request)
        if not isinstance(session, AuthenticatedSession):
            return session
        registry = _registry(request)
        row = _row(registry, bmc_id)
        if row is None:
            return refusal_page(request, config, f"{bmc_id} is not a BMC here.", back=BACK)
        asked = request.query_params.get("do")
        if asked == "change":
            return _page(request, session, row, mode="form", registry=registry, **_form_from(row))
        if asked == "remove":
            return _page(request, session, row, mode="remove", registry=registry)
        return _page(request, session, row, mode="show", registry=registry)

    # - Check -----------------------------------------------------------------------

    @router.post("/certificates/receivers/bmc/check", response_class=HTMLResponse)
    def bmc_check(
        request: Request,
        address: str = Form(default="", max_length=253),
        bmc_username: str = Form(default="", max_length=256),
        password: str = Form(default="", max_length=1024),
        port: str = Form(default="", max_length=5),
        certificate: str = Form(default="", max_length=253),
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        """Seal the account, ask the BMC through root, and show what it serves; nothing is saved."""

        session = _gate(request, csrf_token)
        if not isinstance(session, AuthenticatedSession):
            return session
        registry = _registry(request)
        row = _row(registry, address.strip().lower())
        try:
            target_port = bmc_page.port_of(port)
            bmc_id = bmc_page.address_of(address).lower()
            if not is_bmc_id(bmc_id):
                raise BmcProblem(f"{bmc_id} is not a name or IPv4 address a receiver can have.")
            public_key = read_dns_public_key(config)
            if public_key is None:
                raise BmcProblem("This installation has no key to seal the account with.")
            try:
                box = seal_account(
                    public_key, receiver_id=bmc_id, username=bmc_username, password=password
                )
            except TargetError as refused:
                raise BmcProblem(f"{str(refused)[:1].upper()}{str(refused)[1:]}.") from None
            try:
                answer = bmc_socket.ask(
                    "check",
                    bmc_id,
                    port=target_port,
                    key_id=public_key.key_id,
                    ciphertext=box,
                )
            except BmcAskError as refused:
                raise BmcProblem(
                    bmc_page.refusal(
                        refused.code, str(refused), address=bmc_id, port=target_port, asked="check"
                    )
                ) from None
            checked = bmc_page.checked(answer)
        except BmcProblem as problem:
            return _page(
                request,
                session,
                row,
                mode="form",
                registry=registry,
                port=_shown_port(port),
                problem=str(problem),
                address=address.strip(),
                bmc_username=bmc_username,
                certificate=certificate,
            )
        return _page(
            request,
            session,
            row,
            mode="form",
            registry=registry,
            port=target_port,
            checked=checked,
            sealed=(public_key.key_id, base64.b64encode(box).decode("ascii")),
            address=bmc_id,
            bmc_username=bmc_username,
            certificate=certificate,
        )

    # - Save and install ------------------------------------------------------------

    @router.post("/certificates/receivers/bmc/save", response_class=HTMLResponse)
    def bmc_save(
        request: Request,
        address: str = Form(default="", max_length=253),
        port: str = Form(default="", max_length=5),
        certificate: str = Form(default="", max_length=253),
        fingerprint_sha256: str = Form(default="", max_length=64),
        key_id: str = Form(default="", max_length=128),
        ciphertext_base64: str = Form(default="", max_length=8192),
        confirmed: str = Form(default="", max_length=8),
        idempotency_key: str = Form(default="", max_length=64),
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        """Register or change the confirmed BMC through root, then start its install as a job."""

        session = _gate(request, csrf_token)
        if not isinstance(session, AuthenticatedSession):
            return session
        try:
            key = UUID(idempotency_key)
        except ValueError:
            return PlainTextResponse("A request key is required", status_code=400)
        registry = _registry(request)
        row = _row(registry, address.strip().lower())
        try:
            target_port = bmc_page.port_of(port)
            bmc_id = bmc_page.address_of(address).lower()
            if not is_bmc_id(bmc_id):
                raise BmcProblem(f"{bmc_id} is not a name or IPv4 address a receiver can have.")
            chosen = _chosen(certificate, _choices(registry, bmc_id))
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
                registry=registry,
                address=address.strip(),
                certificate=certificate,
                problem=str(problem),
            )
        try:
            saved = bmc_socket.ask(
                "save",
                bmc_id,
                port=target_port,
                certificate=chosen,
                fingerprint_sha256=fingerprint_sha256,
                key_id=key_id,
                ciphertext=box,
            )
        except BmcAskError as refused:
            detail = {
                "bmc": bmc_id,
                "port": target_port,
                "certificate": chosen,
                "fingerprint_sha256": fingerprint_sha256,
            }
            if refused.code == "unanswered":
                _audit(request, session, "bmc_target_saved", {**detail, "outcome": "unknown"})
            return _page(
                request,
                session,
                row,
                mode="form",
                registry=registry,
                address=bmc_id,
                port=target_port,
                certificate=chosen,
                problem=bmc_page.refusal(
                    refused.code, str(refused), address=bmc_id, port=target_port, asked="save"
                ),
            )
        _audit(
            request,
            session,
            "bmc_target_saved",
            {
                "bmc": bmc_id,
                "port": target_port,
                "certificate": chosen,
                "fingerprint_sha256": fingerprint_sha256,
                "user": saved.get("username"),
            },
        )
        #
        # Saved: the install the save starts. A certificate job already
        # running holds it back, and the timer installs it within its interval
        # instead (B536): the BMC is saved either way, and the page says so.
        #
        refusal = _queue_install(request, session, bmc_id, chosen, "save", key)
        if refusal is not None:
            return refusal_page(
                request,
                config,
                f"The BMC was saved, but its install was not started: {refusal} "
                "It installs automatically within 15 minutes, or use Install now.",
                back=page_of(bmc_id),
            )
        return RedirectResponse(page_of(bmc_id), status_code=303)

    # - the certificate it carries ----------------------------------------------------

    @router.post("/certificates/receivers/bmc/{bmc_id}/assign", response_class=HTMLResponse)
    def bmc_assign(
        request: Request,
        bmc_id: str,
        certificate: str = Form(default="", max_length=253),
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        """Another certificate, without the account; the timer installs it within its interval."""

        session = _gate(request, csrf_token)
        if not isinstance(session, AuthenticatedSession):
            return session
        registry = _registry(request)
        row = _row(registry, bmc_id)
        if row is None:
            return refusal_page(request, config, f"{bmc_id} is not a BMC here.", back=BACK)
        try:
            chosen = _chosen(certificate, _choices(registry, bmc_id))
            try:
                bmc_socket.ask("assign", bmc_id, certificate=chosen)
            except BmcAskError as refused:
                raise BmcProblem(
                    bmc_page.refusal(
                        refused.code, str(refused), address=bmc_id, port=row.port, asked="assign"
                    )
                ) from None
        except BmcProblem as problem:
            return _page(
                request,
                session,
                row,
                mode="show",
                registry=registry,
                problem=str(problem),
                status_code=409,
            )
        _audit(request, session, "bmc_assigned", {"bmc": bmc_id, "certificate": chosen})
        return RedirectResponse(page_of(bmc_id), status_code=303)

    # - Install now -----------------------------------------------------------------

    @router.post("/certificates/receivers/bmc/{bmc_id}/install", response_class=HTMLResponse)
    def bmc_install(
        request: Request,
        bmc_id: str,
        idempotency_key: str = Form(default="", max_length=64),
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        session = _gate(request, csrf_token)
        if not isinstance(session, AuthenticatedSession):
            return session
        try:
            key = UUID(idempotency_key)
        except ValueError:
            return PlainTextResponse("A request key is required", status_code=400)
        registry = _registry(request)
        row = _row(registry, bmc_id)
        if row is None:
            return refusal_page(request, config, f"{bmc_id} is not a BMC here.", back=BACK)
        if row.certificate is None:
            return refusal_page(
                request, config, f"{bmc_id} carries no certificate.", back=page_of(bmc_id)
            )
        refusal = _queue_install(request, session, bmc_id, row.certificate, "install_now", key)
        if refusal is not None:
            return _page(
                request,
                session,
                row,
                mode="show",
                registry=registry,
                problem=refusal,
                status_code=409,
            )
        return RedirectResponse(page_of(bmc_id), status_code=303)

    # - Remove… ---------------------------------------------------------------------

    @router.post("/certificates/receivers/bmc/{bmc_id}/remove", response_class=HTMLResponse)
    def bmc_remove(
        request: Request,
        bmc_id: str,
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        """Take the BMC and its account away; the certificate stays as it is."""

        session = _gate(request, csrf_token)
        if not isinstance(session, AuthenticatedSession):
            return session
        registry = _registry(request)
        row = _row(registry, bmc_id)
        if row is None:
            return refusal_page(request, config, f"{bmc_id} is not a BMC here.", back=BACK)
        try:
            bmc_socket.ask("remove", bmc_id)
        except BmcAskError as refused:
            if refused.code == "unanswered":
                _audit(
                    request, session, "bmc_target_removed", {"bmc": bmc_id, "outcome": "unknown"}
                )
            return _page(
                request,
                session,
                row,
                mode="remove",
                registry=registry,
                problem=bmc_page.refusal(
                    refused.code, str(refused), address=bmc_id, port=row.port, asked="remove"
                ),
                status_code=409,
            )
        _audit(
            request,
            session,
            "bmc_target_removed",
            {"bmc": bmc_id, "certificate": row.certificate},
        )
        return RedirectResponse(BACK, status_code=303)

    # - shared ----------------------------------------------------------------------

    def _audit(
        request: Request,
        session: AuthenticatedSession,
        action: str,
        detail: dict[str, object],
    ) -> None:
        """The row, and the poller told: the listing it caches holds the BMC."""

        with request.app.state.pool.connection() as connection:
            db.record_audit_event(connection, actor=session.username, action=action, detail=detail)
            db.wake_poller(connection)
            connection.commit()

    def _queue_install(
        request: Request,
        session: AuthenticatedSession,
        bmc_id: str,
        certificate: str,
        by: str,
        key: UUID,
    ) -> str | None:
        """Queue the `bmc_install` job; the sentence that refused it, or None.

        `certificate` rides along for the rows that say the install is running;
        the helper reads which certificate the BMC carries from the registry.
        """

        payload = {"id": bmc_id, "certificate": certificate, "by": by}
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
                    "bmc": bmc_id,
                    "certificate": certificate,
                    "by": by,
                },
            )
            connection.commit()
        return None

    return router
