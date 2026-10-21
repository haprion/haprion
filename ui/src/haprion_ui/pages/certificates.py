"""The certificate pages: the registry, issue, import, renew, retarget, delete and the receivers."""

from __future__ import annotations

import secrets
from collections.abc import Mapping, Sequence
from dataclasses import replace
from datetime import timedelta
from typing import Annotated, Any
from uuid import UUID, uuid4

import anyio
from fastapi import APIRouter, Form, Request, Response, UploadFile
from fastapi.responses import (
    HTMLResponse,
    PlainTextResponse,
    RedirectResponse,
)
from haprion import (
    cert_export_socket,
    cert_receiver,
)
from haprion.cert_export import FORMATS as EXPORT_FORMATS
from haprion.cert_export import Export, ExportError
from haprion.config import CERTIFICATE_ID

from haprion_ui import (
    auth,
    certificate_activity,
    certificate_delete,
    certificate_form,
    certificate_import_form,
    certificate_receivers,
    certificate_renew,
    certificate_retarget,
    certificates,
    db,
    dns_profile_form,
    features,
    jobs,
    ndes_profile_form,
    operations,
)
from haprion_ui.config import Config
from haprion_ui.db import AuthenticatedSession
from haprion_ui.views import (
    CERTIFICATE_SOURCE,
    STATUS_SOURCE,
    TEMPLATES,
    UPLOADED_FILE,
    _admin_write_gate,
    _dns_public_key,
    _page_context,
    _public_files,
    _refusal_page,
    _registry_overview,
    _zip_response,
    current_session,
    read_certificate_takeouts,
    read_manager_certificates,
    read_source,
)


def build_router(config: Config) -> APIRouter:
    router = APIRouter()

    @router.get("/certificates", response_class=HTMLResponse)
    def certificate_overview(request: Request) -> Response:
        session = current_session(request)
        if session is None:
            return RedirectResponse("/login", status_code=303)
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        clusters, certificate_rows = read_source(request, config, CERTIFICATE_SOURCE)
        #
        # The node status too, for the one question the certificate listing
        # cannot answer: whether the nodes are carrying what was published. The
        # listing reads the manager's own directory, the nodes report their own
        # fingerprints, and the registry view needs both to say anything
        # truthful about a cluster target.
        #
        _, status_rows = read_source(request, config, STATUS_SOURCE)
        overview = certificates.build_certificate_overview(
            clusters,
            certificate_rows,
            manager=read_manager_certificates(request, config),
            status_readings=status_rows,
            stale_after=timedelta(seconds=config.poller.interval_seconds * 2),
            taken_out=read_certificate_takeouts(request, config),
        )
        with request.app.state.pool.connection() as connection:
            recent = db.recent_jobs(connection, limit=100)
        running = jobs.in_flight(recent)
        #
        # A row the queue is deleting says so in its State cell instead of
        # the page sending the person to the jobs list to watch; the page
        # refreshes itself while that is going on.
        #
        deleting = certificate_activity.deletion_states(recent)
        #
        # A cluster deploy asked for from a row is said on that row too, with
        # the page refreshing until it ends: the person who pressed Deploy to
        # nodes was looking at the row, not at the jobs page (2026-09-20).
        #
        if overview.registry is not None:
            for identifier, state in certificate_activity.deploy_states(
                overview.registry.certificates, recent
            ).items():
                deleting.setdefault(identifier, state)
        overview = certificates.with_deletion_states(overview, deleting)
        refresh = any(
            deleting[entry.identifier].active
            and entry.state_label == deleting[entry.identifier].label
            for entry in (overview.registry.certificates if overview.registry else ())
            if entry.identifier in deleting
        )
        #
        # Which view and which expanded row, in the query string rather than in
        # script: the page is read-only, the two views are two renderings of
        # cached readings, and a link is something an operator can send to
        # somebody else. The registry is the default since 2026-09-15: it is
        # the complete list, and the one the certificate actions return to.
        #
        chosen = "clusters" if request.query_params.get("view") == "clusters" else "registry"
        #
        # With receivers switched off the registry is the one view (B193): the
        # complete list, where every certificate action lives.
        #
        if not features.is_on(features.CERT_RECEIVERS):
            chosen = "registry"
        if overview.registry is None:
            chosen = "clusters"
        sort, asked = certificates.TABLE.chosen(request)
        response = TEMPLATES.TemplateResponse(
            request,
            "certificates.html",
            {
                "username": session.username,
                "role": session.role,
                "csrf_token": auth.csrf_token(token),
                "certificates": overview,
                "chosen_view": chosen,
                "refresh": refresh,
                "opened": request.query_params.get("open", ""),
                #
                # What this cluster is busy with, read the same way the
                # dashboard reads it. One job per cluster, so the buttons
                # below are replaced by it rather than left drawn to offer an
                # action the queue would refuse with a 409.
                #
                "in_flight": running,
                "management_writes": config.management_writes,
                "section": "certificates",
                "demo_fixture": config.demo_fixture,
                "certificate_sort": sort,
                "certificate_sorts": {
                    view: certificates.TABLE.links(sort, {"view": view})
                    for view in ("registry", "clusters")
                },
            },
        )
        if asked:
            certificates.TABLE.remember(response, sort, secure=config.session.cookie_secure)
        return response

    #
    # Phase 11's gate, as a page: a form, a button, a certificate. The page is
    # its own address rather than a panel on the listing for the reason the
    # object editor is - a refused submission has somewhere to be re-drawn
    # with what was typed still in place.
    #
    @router.get("/certificates/new", response_class=HTMLResponse)
    def new_certificate_form(request: Request) -> Response:
        if request.query_params.get("for") == "interface":
            #
            # The same form for the interface's own certificate (B188): the
            # name it is served on filled in, no targets.
            #
            manager = _certificate_choices(request, config).manager or ""
            return _certificate_form_page(
                request,
                config,
                replace(certificate_form.EMPTY_FORM, domain=manager, interface=True),
            )
        #
        # The kind switch carries what is already filled in (2026-10-06) -
        # the name, the CA and its profile - so changing kind does not empty
        # the form. Only drawn into the fields; the submission checks them
        # like any other.
        #
        query = request.query_params
        typed = replace(
            certificate_form.EMPTY_FORM,
            domain=query.get("domain", "")[:255],
            method=query.get("method") or certificate_form.EMPTY_FORM.method,
            dns_profile=query.get("dns_profile", "")[:255],
            ndes_profile=query.get("ndes_profile", "")[:255],
            key_type=query.get("key_type", "")[:255],
        )
        if request.query_params.get("for") == "external" and features.is_on(
            features.CERT_RECEIVERS
        ):
            #
            # A certificate to take out and install by hand (B255): one name,
            # no targets, its key downloaded from the row.
            #
            # No CSR here: the key must stay with the manager to be exported.
            method = certificate_form.EMPTY_FORM.method if typed.method == "csr" else typed.method
            return _certificate_form_page(
                request, config, replace(typed, method=method, key_type="", exportable=True)
            )
        return _certificate_form_page(request, config, typed)

    @router.post("/certificates/new", response_class=HTMLResponse)
    def new_certificate_submit(
        request: Request,
        domain: str = Form(default="", max_length=255),
        method: str = Form(default="", max_length=16),
        cluster: Sequence[str] = Form(default=()),
        receiver: Sequence[str] = Form(default=()),
        format: Sequence[str] = Form(default=()),
        dns_profile: str = Form(default="", max_length=32),
        ndes_profile: str = Form(default="", max_length=32),
        key_type: str = Form(default="", max_length=16),
        interface: str = Form(default="", max_length=1),
        exportable: str = Form(default="", max_length=1),
        idempotency_key: str = Form(default="", max_length=64),
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        """Queue one certificate job - issue, enrollment or signing request - or say why not.

        The same four refusals `/operations` makes, in the same order, and
        then the form's own. Not routed through `/operations`: that route
        answers a refusal with a bare 400, and the one page in the interface
        whose whole purpose is to be filled in deserves to be re-drawn with
        the sentence on it.
        """

        form = certificate_form.IssueForm(
            domain=domain,
            method=method,
            dns_profile=dns_profile,
            ndes_profile=ndes_profile,
            clusters=tuple(cluster),
            receivers=tuple(receiver),
            formats=tuple(format),
            key_type=key_type,
            interface=interface == "1",
            exportable=exportable == "1",
        )
        session = current_session(request)
        if session is None:
            return RedirectResponse("/login", status_code=303)
        if not config.management_writes:
            return PlainTextResponse("Not found", status_code=404)
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return PlainTextResponse("Refused", status_code=403)
        if session.role != "admin":
            return PlainTextResponse("Refused", status_code=403)
        try:
            key = UUID(idempotency_key)
        except ValueError:
            return PlainTextResponse("A request key is required", status_code=400)

        if form.exportable and not features.is_on(features.CERT_RECEIVERS):
            return PlainTextResponse("Not found", status_code=404)
        choices = _certificate_choices(request, config)
        try:
            payload = certificate_form.payload_from_form(form, choices)
        except certificate_form.FormProblem as problem:
            return _certificate_form_page(request, config, form, problem=str(problem))

        operation = certificate_form.operation_of(form)
        try:
            operations.prepare(
                operation=operation, cluster=None, request_id=uuid4(), payload=payload
            )
        except operations.BadPayload:
            return PlainTextResponse("Invalid operation parameters", status_code=400)

        with request.app.state.pool.connection() as connection:
            try:
                job = db.queue_job(
                    connection,
                    operation=operation,
                    cluster=None,
                    payload=payload,
                    idempotency_key=key,
                )
            except db.CertificateBusy:
                connection.rollback()
                return _certificate_form_page(
                    request,
                    config,
                    form,
                    problem="A certificate job is already running. Wait for it to "
                    "finish on the Jobs page, then ask again.",
                )
            except db.RequestConflict:
                connection.rollback()
                return PlainTextResponse("That request key asked for something else", 409)
            db.record_audit_event(
                connection,
                actor=session.username,
                action="queue_job",
                cluster=None,
                request_id=job.request_id,
                detail={"operation": operation, "job": job.id},
            )
            connection.commit()
        #
        # Back to the listing, where the request is the first row: it says
        # "Requesting" and refreshes until the CA has answered, and carries
        # the CA's own words if the answer is no. Not opened - the detail
        # under a row that has no material yet is empty. The jobs page keeps
        # the full record, but it is not where a person expects to land.
        # The interface's own certificate goes back to where it was asked for.
        #
        if form.interface:
            return RedirectResponse("/settings", status_code=303)
        return RedirectResponse("/certificates?view=registry", status_code=303)

    #
    # The signing request a waiting row exists to hand out (C9b). Served
    # from the same cached reading the page is drawn from, as a file the
    # browser saves: what a CA's form asks to be pasted or uploaded. The
    # CSR is public by construction - it holds the public key and the
    # names - and the row is on a page a viewer may read, so no role is
    # checked beyond the session.
    #
    @router.get("/certificates/{certificate_id}/csr")
    def certificate_signing_request(request: Request, certificate_id: str) -> Response:
        session = current_session(request)
        if session is None:
            return RedirectResponse("/login", status_code=303)
        if not CERTIFICATE_ID.fullmatch(certificate_id):
            return PlainTextResponse("Not found", status_code=404)
        row = _registry_views(request, config).get(certificate_id)
        if row is None or row.csr_pem is None:
            return PlainTextResponse("No signing request is waiting for this name", status_code=404)
        return PlainTextResponse(
            row.csr_pem,
            media_type="application/pkcs10",
            headers={"Content-Disposition": f'attachment; filename="{certificate_id}.csr"'},
        )

    #
    # An external certificate's public half (B255, as one zip 2026-10-07): the
    # chain as one file, the leaf alone and the issuers alone - the three a
    # device asks for. Drawn from the cached reading, as the CSR is. An admin
    # alone, like the key: a reader reads, and taking a certificate out to
    # install it somewhere is not reading (2026-10-07).
    #
    @router.post("/certificates/{certificate_id}/download")
    def certificate_download(
        request: Request,
        certificate_id: str,
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        gate = _external_certificate_gate(request, certificate_id, csrf_token)
        if not isinstance(gate, tuple):
            return gate
        session, row = gate
        #
        # Recorded like the export with its key (26-10-18): a renewed
        # certificate taken out without one still has its version taken out,
        # and the registry row reads which version that was.
        #
        with request.app.state.pool.connection() as connection:
            db.record_audit_event(
                connection,
                actor=session.username,
                action="certificate_download",
                cluster=None,
                request_id=uuid4(),
                detail={
                    "certificate": certificate_id,
                    "format": "zip",
                    "fingerprint_sha256": row.fingerprint,
                },
            )
            connection.commit()
        return _zip_response(
            _public_files(certificate_id, row.fullchain_pem or ""), f"{certificate_id}.zip"
        )

    #
    # The page behind *Export…* (B255): one external certificate, its public
    # files and its key, the way *Renew…* is one row and its renewal. The
    # export itself posts to the route below.
    #
    @router.post("/certificates/export", response_class=HTMLResponse)
    def certificate_export_review(
        request: Request,
        certificate: Sequence[str] = Form(default=()),
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        gate = _admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        if not features.is_on(features.CERT_RECEIVERS):
            return PlainTextResponse("Not found", status_code=404)
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return PlainTextResponse("Refused", status_code=403)
        chosen = tuple(certificate)
        row = _registry_views(request, config).get(chosen[0]) if len(chosen) == 1 else None
        problem = ""
        if len(chosen) != 1:
            problem = "Choose one certificate to export."
        elif row is None or not row.exportable:
            problem = f"{chosen[0]} is not an external certificate."
            row = None
        return TEMPLATES.TemplateResponse(
            request,
            "certificate-export.html",
            {
                "username": gate.username,
                "role": gate.role,
                "csrf_token": auth.csrf_token(token),
                "row": row,
                "back": f"/certificates?view=registry&open={row.identifier}"
                if row is not None
                else "/certificates?view=registry",
                "problem": problem,
                "section": "certificates",
                "management_writes": config.management_writes,
                "demo_fixture": config.demo_fixture,
            },
        )

    #
    # An external certificate with its key (B255, as one zip 2026-10-07): the
    # public files, the key as PEM, and both PKCS#12 forms under one password
    # the manager draws and puts beside them, the way a receiver gets a `.pfx`
    # and a `.password`. The password guards nothing the zip does not already
    # hold unencrypted - it is there because devices will not take a bundle
    # without one. The guard is the admin, the click and the audit row.
    #
    # Every form comes from the export helper, which gives out the key of an
    # exportable entry and of no other, and each must be the certificate the
    # page was drawn from: a renewal between the reading and the click would
    # otherwise put a new key beside an old chain. Served without a copy kept.
    #
    @router.post("/certificates/{certificate_id}/export")
    def certificate_export(
        request: Request,
        certificate_id: str,
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        gate = _external_certificate_gate(request, certificate_id, csrf_token)
        if not isinstance(gate, tuple):
            return gate
        session, row = gate
        back = f"/certificates?view=registry&open={certificate_id}"
        password = secrets.token_urlsafe(18)
        exported: dict[str, Export] = {}
        try:
            for form in EXPORT_FORMATS:
                exported[form] = cert_export_socket.ask(
                    certificate_id,
                    form,
                    None if form == "pem-key" else password,
                    requested_by=session.username,
                )
        except ExportError as refusal:
            return _refusal_page(request, config, f"{refusal} Nothing was exported.", back=back)
        if any(item.fingerprint != row.fingerprint for item in exported.values()):
            return _refusal_page(
                request,
                config,
                f"{certificate_id} changed since the page was read. Open it again; "
                "nothing was exported.",
                back=back,
            )
        with request.app.state.pool.connection() as connection:
            db.record_audit_event(
                connection,
                actor=session.username,
                action="certificate_export",
                cluster=None,
                request_id=uuid4(),
                detail={
                    "certificate": certificate_id,
                    "format": "zip",
                    "forms": list(EXPORT_FORMATS),
                    "fingerprint_sha256": row.fingerprint,
                },
            )
            connection.commit()
        #
        # Named here, from the ID this route checked, rather than taken from
        # the helper's answer into a header or a member name.
        #
        files = [
            *_public_files(certificate_id, row.fullchain_pem or ""),
            (f"{certificate_id}.key.pem", exported["pem-key"].content, True),
            (f"{certificate_id}.pfx", exported["pfx"].content, True),
            (f"{certificate_id}.compatible.pfx", exported["pfx-compatible"].content, True),
            (f"{certificate_id}.password", (password + "\n").encode("ascii"), True),
        ]
        return _zip_response(files, f"{certificate_id}.with-key.zip")

    #
    # What both routes above check before they give anything out: an admin
    # where management writes are on, the form's own CSRF token, and a row of
    # the registry marked external with its chain read. The admin and the
    # row, or the answer that refuses.
    #
    def _external_certificate_gate(
        request: Request, certificate_id: str, csrf_token: str
    ) -> tuple[AuthenticatedSession, certificates.RegistryCertificateView] | Response:
        session = _admin_write_gate(config, request)
        if not isinstance(session, AuthenticatedSession):
            return session
        if not features.is_on(features.CERT_RECEIVERS) or not CERTIFICATE_ID.fullmatch(
            certificate_id
        ):
            return PlainTextResponse("Not found", status_code=404)
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return PlainTextResponse("Refused", status_code=403)
        row = _registry_views(request, config).get(certificate_id)
        if row is None or not row.exportable or not row.fullchain_pem or not row.fingerprint:
            return _refusal_page(
                request,
                config,
                f"{certificate_id} is not an external certificate that can be read.",
                back="/certificates?view=registry",
            )
        return session, row

    #
    # A certificate somebody already has (C9, B165): a file, a name, the
    # targets. Its own page and its own button, because "import" and "new"
    # are different questions - one is a thing that exists, the other a
    # thing to be made - and the same page with a different middle.
    #
    @router.get("/certificates/import", response_class=HTMLResponse)
    def import_certificate_form(request: Request) -> Response:
        if request.query_params.get("for") == "interface":
            choices = _certificate_choices(request, config)
            name = (
                certificate_form.interface_id_for(choices.manager, choices.taken)
                if choices.manager
                else ""
            )
            return _certificate_import_page(
                request,
                config,
                replace(certificate_import_form.EMPTY_FORM, name=name, interface=True),
            )
        #
        # The name a switch between the two kinds carried over (B276).
        #
        carried = request.query_params.get("name", "")[:255]
        if request.query_params.get("kind") == "authority":
            return _certificate_import_page(
                request,
                config,
                replace(certificate_import_form.EMPTY_FORM, name=carried, kind="authority"),
            )
        return _certificate_import_page(
            request, config, replace(certificate_import_form.EMPTY_FORM, name=carried)
        )

    @router.post("/certificates/import", response_class=HTMLResponse)
    def import_certificate_submit(
        request: Request,
        name: str = Form(default="", max_length=255),
        password: str = Form(default="", max_length=256),
        cluster: Sequence[str] = Form(default=()),
        receiver: Sequence[str] = Form(default=()),
        format: Sequence[str] = Form(default=()),
        interface: str = Form(default="", max_length=1),
        kind: str = Form(default="certificate", max_length=16),
        source: str = Form(default="upload", max_length=16),
        idempotency_key: str = Form(default="", max_length=64),
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
        file: UploadFile | None = UPLOADED_FILE,
    ) -> Response:
        """Seal the file and queue one `cert_import` job, or draw the form again saying why not.

        The file is read once, bounded, into memory, sealed against the
        installation's public key, and dropped: the payload the job carries
        is the box. The same four refusals `/certificates/new` makes first.
        """

        data, filename = _uploaded_bytes(file)
        form = certificate_import_form.ImportForm(
            name=name,
            password=password,
            clusters=tuple(cluster),
            receivers=tuple(receiver),
            formats=tuple(format),
            filename=filename,
            data=data,
            interface=interface == "1",
            kind=kind,
            source=source,
        )
        session = current_session(request)
        if session is None:
            return RedirectResponse("/login", status_code=303)
        if not config.management_writes:
            return PlainTextResponse("Not found", status_code=404)
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return PlainTextResponse("Refused", status_code=403)
        if session.role != "admin":
            return PlainTextResponse("Refused", status_code=403)
        try:
            key = UUID(idempotency_key)
        except ValueError:
            return PlainTextResponse("A request key is required", status_code=400)

        public_key = _dns_public_key(config)
        choices = _certificate_choices(request, config)
        try:
            payload = certificate_import_form.payload_from_form(
                certificate_import_form.normalise(form),
                choices,
                public_key,
                replaceable=choices.imported,
            )
        except certificate_form.FormProblem as problem:
            return _certificate_import_page(request, config, form, problem=str(problem))
        return _queue_import(
            request, session, key, payload, form=form, after="/settings" if form.interface else ""
        )

    @router.post("/certificates/{certificate_id}/upload")
    def upload_certificate(
        request: Request,
        certificate_id: str,
        csrf_token: Annotated[str, Form(max_length=128)],
        idempotency_key: Annotated[str, Form(max_length=64)],
        file: UploadFile | None = UPLOADED_FILE,
    ) -> Response:
        """A certificate for a row whose key the manager holds: a renewal, or a CSR's answer.

        Only the file. The name is the row's and the targets stay as they
        are; a key in the file is refused here and pointed at the import
        page, where replacing the key is the stated intent.
        """

        data, _filename = _uploaded_bytes(file)
        session = current_session(request)
        if session is None:
            return RedirectResponse("/login", status_code=303)
        if not config.management_writes:
            return PlainTextResponse("Not found", status_code=404)
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token) or session.role != "admin":
            return PlainTextResponse("Refused", status_code=403)
        try:
            key = UUID(idempotency_key)
        except ValueError:
            return PlainTextResponse("A request key is required", status_code=400)

        row = _registry_views(request, config).get(certificate_id)
        if row is None or row.placeholder:
            return PlainTextResponse("Certificate is not in the registry", status_code=404)
        if row.source_kind != "import":
            return _refusal_page(
                request,
                config,
                f"{certificate_id} is not an imported certificate; its material is not "
                "replaced by an upload.",
                back=f"/certificates?view=registry&open={certificate_id}",
            )
        public_key = _dns_public_key(config)
        if public_key is None:
            return _refusal_page(
                request,
                config,
                "The installation's sealing key is not configured, so a file cannot be "
                "uploaded. Import it with haprion-cert-import on the manager.",
                back=f"/certificates?view=registry&open={certificate_id}",
            )
        back = (
            "/settings" if row.interface else f"/certificates?view=registry&open={certificate_id}"
        )
        try:
            certificate_import_form.check_file(data, key_allowed=False)
            payload = certificate_import_form.sealed_payload(
                public_key,
                certificate_id=certificate_id,
                data=data,
                clusters=[t.name for t in row.targets if t.kind == "cluster"],
                receivers=[t.name for t in row.targets if t.kind == "receiver"],
            )
        except certificate_form.FormProblem as problem:
            return _refusal_page(request, config, str(problem), back=back)
        if row.interface:
            #
            # The interface's own certificate (B188), or the answer to the
            # request made for it: no targets, the mark carried.
            #
            payload["interface"] = True
            return _queue_import(request, session, key, payload, after="/settings")
        return _queue_import(request, session, key, payload, open_row=certificate_id)

    def _uploaded_bytes(file: UploadFile | None) -> tuple[bytes, str]:
        """The file's bytes, read once and bounded one byte past the limit.

        One byte past, so the form can say "too large" rather than silently
        judging a truncated file. Reading stops there; the rest of a large
        upload is never held.
        """

        if file is None:
            return b"", ""
        data = anyio.from_thread.run(file.read, certificate_import_form.MAX_UPLOAD_BYTES + 1)
        anyio.from_thread.run(file.close)
        return data, file.filename or ""

    def _queue_import(
        request: Request,
        session: AuthenticatedSession,
        key: UUID,
        payload: dict[str, Any],
        *,
        form: certificate_import_form.ImportForm | None = None,
        open_row: str = "",
        after: str = "",
    ) -> Response:
        """Queue the sealed upload; the same refusals the issue form makes, said the same way."""

        try:
            operations.prepare(
                operation="cert_import", cluster=None, request_id=uuid4(), payload=payload
            )
        except operations.BadPayload:
            return PlainTextResponse("Invalid operation parameters", status_code=400)
        with request.app.state.pool.connection() as connection:
            try:
                job = db.queue_job(
                    connection,
                    operation="cert_import",
                    cluster=None,
                    payload=payload,
                    idempotency_key=key,
                )
            except db.CertificateBusy:
                connection.rollback()
                busy = (
                    "A certificate job is already running. Wait for it to finish, then try again."
                )
                if form is not None:
                    return _certificate_import_page(request, config, form, problem=busy)
                return PlainTextResponse(busy, status_code=409)
            except db.RequestConflict:
                connection.rollback()
                return PlainTextResponse("That request key asked for something else", 409)
            db.record_audit_event(
                connection,
                actor=session.username,
                action="queue_job",
                cluster=None,
                request_id=job.request_id,
                detail={"operation": "cert_import", "job": job.id, "certificate": payload["id"]},
            )
            connection.commit()
        if after:
            return RedirectResponse(after, status_code=303)
        if open_row:
            return RedirectResponse(f"/certificates?view=registry&open={open_row}", status_code=303)
        return RedirectResponse("/certificates?view=registry", status_code=303)

    def _certificate_import_page(
        request: Request,
        config: Config,
        form: certificate_import_form.ImportForm,
        *,
        problem: str = "",
    ) -> Response:
        session = current_session(request)
        if session is None:
            return RedirectResponse("/login", status_code=303)
        if not config.management_writes:
            return PlainTextResponse("Not found", status_code=404)
        if session.role != "admin":
            return PlainTextResponse("Refused", status_code=403)
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        choices = _certificate_choices(request, config)
        with request.app.state.pool.connection() as connection:
            recent = db.recent_jobs(connection)
        #
        # The file is never redrawn: a browser will not take a value for a
        # file input, and the bytes have no business in a page. The person
        # picks it again; everything typed is kept.
        #
        return TEMPLATES.TemplateResponse(
            request,
            "certificate-import.html",
            {
                "username": session.username,
                "role": session.role,
                "csrf_token": auth.csrf_token(token),
                "form": certificate_import_form.normalise(form),
                "choices": choices,
                "problem": problem,
                "accept": certificate_import_form.ACCEPT,
                "max_kb": certificate_import_form.MAX_UPLOAD_BYTES // 1024,
                "sealing_available": _dns_public_key(config) is not None,
                "certificate_job": jobs.certificate_in_flight(recent),
                "section": "certificates",
                "management_writes": config.management_writes,
                "demo_fixture": config.demo_fixture,
            },
        )

    @router.post("/certificates/{certificate_id}/resume")
    def resume_enrollment(
        request: Request,
        certificate_id: str,
        csrf_token: Annotated[str, Form(max_length=128)],
        idempotency_key: Annotated[str, Form(max_length=64)],
    ) -> Response:
        """Queue the resume of an NDES request the CA was still holding.

        The request's root-only record holds everything else - profile,
        names, targets - so the job carries only the ID (C6).
        """

        session = current_session(request)
        if session is None:
            return RedirectResponse("/login", status_code=303)
        if not config.management_writes:
            return PlainTextResponse("Not found", status_code=404)
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token) or session.role != "admin":
            return PlainTextResponse("Refused", status_code=403)
        try:
            key = UUID(idempotency_key)
        except ValueError:
            return PlainTextResponse("A request key is required", status_code=400)
        payload = {"id": certificate_id, "resume": True}
        try:
            operations.prepare(
                operation="cert_scep", cluster=None, request_id=uuid4(), payload=payload
            )
        except operations.BadPayload:
            return PlainTextResponse("Invalid operation parameters", status_code=400)
        with request.app.state.pool.connection() as connection:
            try:
                job = db.queue_job(
                    connection,
                    operation="cert_scep",
                    cluster=None,
                    payload=payload,
                    idempotency_key=key,
                )
            except db.CertificateBusy:
                connection.rollback()
                return PlainTextResponse(
                    "A certificate job is already running. Wait for it to finish, then try again.",
                    status_code=409,
                )
            except db.RequestConflict:
                connection.rollback()
                return PlainTextResponse("That request key asked for something else", 409)
            db.record_audit_event(
                connection,
                actor=session.username,
                action="queue_job",
                cluster=None,
                request_id=job.request_id,
                detail={"operation": "cert_scep", "job": job.id, "resume": certificate_id},
            )
            connection.commit()
        # A fixed address, with the row still open: the listing's State cell
        # follows the job from there, on the row the button was pressed on.
        return RedirectResponse(
            f"/certificates?view=registry&open={certificate_id}", status_code=303
        )

    @router.post("/certificates/{certificate_id}/publish")
    def publish_certificate(
        request: Request,
        certificate_id: str,
        csrf_token: Annotated[str, Form(max_length=128)],
        idempotency_key: Annotated[str, Form(max_length=64)],
    ) -> Response:
        """Publish one registered certificate to the targets it already has."""

        session = current_session(request)
        if session is None:
            return RedirectResponse("/login", status_code=303)
        if not config.management_writes:
            return PlainTextResponse("Not found", status_code=404)
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token) or session.role != "admin":
            return PlainTextResponse("Refused", status_code=403)
        try:
            key = UUID(idempotency_key)
        except ValueError:
            return PlainTextResponse("A request key is required", status_code=400)

        row = _registry_views(request, config).get(certificate_id)
        if row is None:
            return PlainTextResponse("Certificate is not in the registry", status_code=404)
        if not row.needs_publish:
            return PlainTextResponse("Certificate does not need publishing", status_code=409)

        payload = {"certificates": [certificate_id], "deploy": True}
        try:
            operations.prepare(
                operation="cert_publish", cluster=None, request_id=uuid4(), payload=payload
            )
        except operations.BadPayload:
            return PlainTextResponse("Invalid operation parameters", status_code=400)
        with request.app.state.pool.connection() as connection:
            try:
                job = db.queue_job(
                    connection,
                    operation="cert_publish",
                    cluster=None,
                    payload=payload,
                    idempotency_key=key,
                )
            except db.CertificateBusy:
                connection.rollback()
                return PlainTextResponse(
                    "A certificate job is already running. Wait for it to finish, then try again.",
                    status_code=409,
                )
            except db.RequestConflict:
                connection.rollback()
                return PlainTextResponse("That request key asked for something else", 409)
            db.record_audit_event(
                connection,
                actor=session.username,
                action="queue_job",
                cluster=None,
                request_id=job.request_id,
                detail={
                    "operation": "cert_publish",
                    "job": job.id,
                    "certificate": certificate_id,
                },
            )
            connection.commit()
        return RedirectResponse(
            f"/certificates?view=registry&open={certificate_id}", status_code=303
        )

    def _certificate_choices(request: Request, config: Config) -> certificate_form.IssueChoices:
        """The targets the form may offer, read the way the listing reads them."""

        clusters, certificate_rows = read_source(request, config, CERTIFICATE_SOURCE)
        overview = certificates.build_certificate_overview(
            clusters,
            certificate_rows,
            manager=read_manager_certificates(request, config),
            stale_after=timedelta(seconds=config.poller.interval_seconds * 2),
        )
        usable_profiles: tuple[str, ...] = ()
        profiles_required = config.dns_profiles_public_key is not None
        if profiles_required:
            with request.app.state.pool.connection() as connection:
                profile_rows = db.dns_profiles(connection)
                recent = db.profile_jobs(connection, "dns_profile_apply")
            usable_profiles = tuple(
                profile.id
                for profile in profile_rows
                if dns_profile_form.profile_status(profile.id, profile.revision, recent).usable
            )
        usable_ndes: tuple[str, ...] = ()
        if profiles_required:
            with request.app.state.pool.connection() as connection:
                ndes_rows = db.ndes_profiles(connection)
                recent = db.profile_jobs(connection, "ndes_profile_apply")
            usable_ndes = tuple(
                profile.id
                for profile in ndes_rows
                if ndes_profile_form.profile_status(profile.id, profile.revision, recent).usable
            )
        #
        # With receivers switched off (B193) no form offers one and every
        # form refuses one as not registered: the issue, import and upload
        # forms and Publish to... / Remove from... all read this.
        #
        offered = (
            overview.registry.receivers
            if overview.registry is not None and features.is_on(features.CERT_RECEIVERS)
            else ()
        )
        return certificate_form.IssueChoices(
            clusters=tuple(clusters),
            receivers=offered,
            dns_profiles=usable_profiles,
            profiles_required=profiles_required,
            ndes_profiles=usable_ndes,
            receiver_transports={
                row.identifier: row.transport_label for row in overview.registry.receiver_rows
            }
            if overview.registry
            else {},
            registered=tuple(
                entry.identifier
                for entry in (*overview.registry.certificates, overview.registry.interface)
                if entry is not None
            )
            if overview.registry
            else (),
            imported=tuple(
                entry.identifier
                for entry in overview.registry.certificates
                if entry.source_kind == "import" and not entry.placeholder
            )
            if overview.registry
            else (),
            authorities=tuple(
                entry.identifier
                for entry in overview.registry.certificates
                if entry.source_kind == "authority"
            )
            if overview.registry
            else (),
            waiting=tuple(
                entry.identifier for entry in overview.registry.certificates if entry.csr_pending
            )
            if overview.registry
            else (),
            manager=overview.registry.manager if overview.registry else None,
            interface_id=overview.registry.interface.identifier
            if overview.registry and overview.registry.interface
            else None,
            taken=tuple(
                view.identifier
                for view in (
                    *overview.registry.certificates,
                    overview.registry.interface,
                    overview.registry.interface_request,
                )
                if view is not None
            )
            if overview.registry
            else (),
        )

    def _certificate_form_page(
        request: Request,
        config: Config,
        form: certificate_form.IssueForm,
        *,
        problem: str = "",
    ) -> Response:
        session = current_session(request)
        if session is None:
            return RedirectResponse("/login", status_code=303)
        if not config.management_writes:
            #
            # 404 and not 403, for the reason `/operations` gives: an
            # installation that does not do management writes has no such
            # form, and saying "forbidden" would announce one waiting to be
            # switched on.
            #
            return PlainTextResponse("Not found", status_code=404)
        if session.role != "admin":
            return PlainTextResponse("Refused", status_code=403)
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        choices = _certificate_choices(request, config)
        with request.app.state.pool.connection() as connection:
            recent = db.recent_jobs(connection)
        return TEMPLATES.TemplateResponse(
            request,
            "certificate-new.html",
            {
                "username": session.username,
                "role": session.role,
                "csrf_token": auth.csrf_token(token),
                "form": certificate_form.normalise(form),
                "choices": choices,
                "key_types": certificate_form.KEY_TYPE_LABELS,
                "problem": problem,
                "certificate_job": jobs.certificate_in_flight(recent),
                "section": "certificates",
                "management_writes": config.management_writes,
                "demo_fixture": config.demo_fixture,
            },
        )

    # - Certificate cleanup (C5b, B139) ------------------------------------

    def _registry_views(
        request: Request, config: Config
    ) -> Mapping[str, certificates.RegistryCertificateView]:
        """The registry as the listing draws it, by ID, for the cleanup page."""

        clusters, certificate_rows = read_source(request, config, CERTIFICATE_SOURCE)
        overview = certificates.build_certificate_overview(
            clusters,
            certificate_rows,
            manager=read_manager_certificates(request, config),
            stale_after=timedelta(seconds=config.poller.interval_seconds * 2),
        )
        if overview.registry is None:
            return {}
        registry = overview.registry
        #
        # The interface's own entry and its waiting request are rows too, for
        # the routes that act on a row by ID - its CSR, its upload, its
        # renewal - though the listing draws them on the settings page.
        #
        extra = tuple(
            view for view in (registry.interface, registry.interface_request) if view is not None
        )
        return {view.identifier: view for view in (*registry.certificates, *extra)}

    def _certificate_delete_page(
        request: Request,
        session: AuthenticatedSession,
        *,
        chosen: Sequence[str],
        problem: str = "",
    ) -> Response:
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        registry = _registry_views(request, config)
        with request.app.state.pool.connection() as connection:
            drafts = db.live_drafts(connection)
            recent = db.recent_jobs(connection)
        picked: certificate_delete.Selection | None = None
        try:
            picked = certificate_delete.selection(chosen, registry, drafts)
        except certificate_delete.SelectionProblem as refused:
            problem = problem or str(refused)
        return TEMPLATES.TemplateResponse(
            request,
            "certificate-delete.html",
            {
                "username": session.username,
                "role": session.role,
                "csrf_token": auth.csrf_token(token),
                "selection": picked,
                "problem": problem,
                "certificate_job": jobs.certificate_in_flight(recent),
                "section": "certificates",
                "management_writes": config.management_writes,
                "demo_fixture": config.demo_fixture,
            },
        )

    # - Renew… (C9c) ------------------------------------------------------

    def _certificate_renew_page(
        request: Request,
        session: AuthenticatedSession,
        *,
        chosen: Sequence[str],
        problem: str = "",
    ) -> Response:
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        registry = _registry_views(request, config)
        with request.app.state.pool.connection() as connection:
            recent = db.recent_jobs(connection)
        renewal: certificate_renew.Renewal | None = None
        try:
            renewal = certificate_renew.selection(chosen, registry)
        except certificate_renew.SelectionProblem as refused:
            problem = problem or str(refused)
        return TEMPLATES.TemplateResponse(
            request,
            "certificate-renew.html",
            {
                "username": session.username,
                "role": session.role,
                "csrf_token": auth.csrf_token(token),
                "renewal": renewal,
                "back": "/settings"
                if renewal is not None and renewal.row.interface
                else f"/certificates?view=registry&open={renewal.identifier}"
                if renewal is not None
                else "/certificates?view=registry",
                "problem": problem,
                "certificate_job": jobs.certificate_in_flight(recent),
                "section": "settings"
                if renewal is not None and renewal.row.interface
                else "certificates",
                "management_writes": config.management_writes,
                "demo_fixture": config.demo_fixture,
            },
        )

    @router.post("/certificates/renew", response_class=HTMLResponse)
    def certificate_renew_review(
        request: Request,
        certificate: Sequence[str] = Form(default=()),
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        """The page behind *Renew…*: one row, renewed the way its source is made."""

        gate = _admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return PlainTextResponse("Refused", status_code=403)
        return _certificate_renew_page(request, gate, chosen=tuple(certificate))

    @router.post("/certificates/renew/confirm", response_class=HTMLResponse)
    def certificate_renew_confirm(
        request: Request,
        certificate: Sequence[str] = Form(default=()),
        idempotency_key: str = Form(default="", max_length=64),
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        """Queue the certbot or NDES renewal the page offered; a file goes to the upload route."""

        gate = _admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return PlainTextResponse("Refused", status_code=403)
        try:
            key = UUID(idempotency_key)
        except ValueError:
            return PlainTextResponse("A request key is required", status_code=400)
        registry = _registry_views(request, config)
        try:
            renewal = certificate_renew.selection(tuple(certificate), registry)
            operation, payload = certificate_renew.payload(renewal)
        except certificate_renew.SelectionProblem as refused:
            return _certificate_renew_page(
                request, gate, chosen=tuple(certificate), problem=str(refused)
            )
        try:
            operations.prepare(
                operation=operation, cluster=None, request_id=uuid4(), payload=payload
            )
        except operations.BadPayload:
            return PlainTextResponse("Invalid operation parameters", status_code=400)
        with request.app.state.pool.connection() as connection:
            try:
                job = db.queue_job(
                    connection,
                    operation=operation,
                    cluster=None,
                    payload=payload,
                    idempotency_key=key,
                )
            except db.CertificateBusy:
                connection.rollback()
                return _certificate_renew_page(
                    request,
                    gate,
                    chosen=tuple(certificate),
                    problem="A certificate job is already running. Wait for it to finish on "
                    "the Jobs page, then ask again.",
                )
            except db.RequestConflict:
                connection.rollback()
                return PlainTextResponse("That request key asked for something else", 409)
            db.record_audit_event(
                connection,
                actor=gate.username,
                action="queue_job",
                cluster=None,
                request_id=job.request_id,
                detail={
                    "operation": operation,
                    "job": job.id,
                    "certificate": renewal.identifier,
                    "renew": True,
                },
            )
            connection.commit()
        #
        # Back to the list, the row closed: its State cell says "Renewing"
        # from the table, and the detail was not asked for (2026-09-21).
        # The interface's own certificate is renewed from, and back to, Settings.
        #
        if renewal.row.interface:
            return RedirectResponse("/settings", status_code=303)
        return RedirectResponse("/certificates?view=registry", status_code=303)

    # - Publish to… / Remove from… (2026-09-15) ---------------------------

    def _certificate_retarget_page(
        request: Request,
        session: AuthenticatedSession,
        action: str,
        *,
        chosen: Sequence[str],
        problem: str = "",
    ) -> Response:
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        registry = _registry_views(request, config)
        choices = _certificate_choices(request, config)
        with request.app.state.pool.connection() as connection:
            drafts = db.live_drafts(connection)
            recent = db.recent_jobs(connection)
        picked: certificate_retarget.Selection | None = None
        try:
            picked = certificate_retarget.selection(
                action, chosen, registry, choices.clusters, choices.receivers, drafts
            )
        except certificate_retarget.SelectionProblem as refused:
            problem = problem or str(refused)
        return TEMPLATES.TemplateResponse(
            request,
            "certificate-retarget.html",
            {
                "receiver_transports": choices.receiver_transports,
                "username": session.username,
                "role": session.role,
                "csrf_token": auth.csrf_token(token),
                "selection": picked,
                "problem": problem,
                "certificate_job": jobs.certificate_in_flight(recent),
                "section": "certificates",
                "management_writes": config.management_writes,
                "demo_fixture": config.demo_fixture,
            },
        )

    @router.post("/certificates/targets/{action}", response_class=HTMLResponse)
    def certificate_retarget_review(
        request: Request,
        action: str,
        certificate: Sequence[str] = Form(default=()),
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        """The page that asks which targets: nothing is queued from here."""

        if action not in certificate_retarget.ACTIONS:
            return PlainTextResponse("Not found", status_code=404)
        gate = _admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return PlainTextResponse("Refused", status_code=403)
        return _certificate_retarget_page(request, gate, action, chosen=tuple(certificate))

    @router.post("/certificates/targets/{action}/confirm", response_class=HTMLResponse)
    def certificate_retarget_confirm(
        request: Request,
        action: str,
        certificate: Sequence[str] = Form(default=()),
        cluster: Sequence[str] = Form(default=()),
        receiver: Sequence[str] = Form(default=()),
        format: Sequence[str] = Form(default=()),
        idempotency_key: str = Form(default="", max_length=64),
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        """Queue one `cert_target` job for the selection and the ticked targets.

        The selection and the offered targets are evaluated again here, not
        trusted from the previous page; a target that stopped being offered
        in between is simply not in the job, and a draft written in between
        is a refusal now.
        """

        if action not in certificate_retarget.ACTIONS:
            return PlainTextResponse("Not found", status_code=404)
        gate = _admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return PlainTextResponse("Refused", status_code=403)
        try:
            key = UUID(idempotency_key)
        except ValueError:
            return PlainTextResponse("A request key is required", status_code=400)

        registry = _registry_views(request, config)
        choices = _certificate_choices(request, config)
        with request.app.state.pool.connection() as connection:
            drafts = db.live_drafts(connection)
        try:
            picked = certificate_retarget.selection(
                action, tuple(certificate), registry, choices.clusters, choices.receivers, drafts
            )
            payload = certificate_retarget.payload(
                picked, tuple(cluster), tuple(receiver), tuple(format)
            )
            operations.prepare(
                operation="cert_target",
                cluster=None,
                request_id=uuid4(),
                payload=payload,
                draft_references=lambda ids: certificate_delete.draft_references(drafts, ids),
            )
        except (certificate_retarget.SelectionProblem, operations.BadPayload) as refused:
            return _certificate_retarget_page(
                request, gate, action, chosen=tuple(certificate), problem=str(refused)
            )

        with request.app.state.pool.connection() as connection:
            try:
                job = db.queue_job(
                    connection,
                    operation="cert_target",
                    cluster=None,
                    payload=payload,
                    idempotency_key=key,
                )
            except db.CertificateBusy:
                connection.rollback()
                return _certificate_retarget_page(
                    request,
                    gate,
                    action,
                    chosen=tuple(certificate),
                    problem="A certificate job is already running. Wait for it to finish, "
                    "then ask again.",
                )
            except db.RequestConflict:
                connection.rollback()
                return PlainTextResponse("That request key asked for something else", 409)
            db.record_audit_event(
                connection,
                actor=gate.username,
                action="queue_job",
                cluster=None,
                request_id=job.request_id,
                detail={"operation": "cert_target", "job": job.id, **payload},
            )
            connection.commit()
        #
        # Back on the list as it was, also for one certificate: the change is
        # made from the selection, where no row was open, and the row's state
        # column follows the job (like a deletion or a renewal).
        #
        return RedirectResponse("/certificates?view=registry", status_code=303)

    # - Receivers (B142, 2026-09-18) ------------------------------------------

    def _receivers_page(
        request: Request,
        session: AuthenticatedSession,
        *,
        problem: str = "",
    ) -> Response:
        """The list: every receiver, its fetch commands, and the job on its row."""

        _token, registry, context = _page_context(config, request, session)
        rows = registry.receiver_rows if registry else ()
        manager = registry.manager if registry else None
        with request.app.state.pool.connection() as connection:
            own = db.operation_jobs(connection, "cert_receiver", limit=5)
        on_rows, ghosts = certificate_receivers.on_the_rows(
            rows, certificate_receivers.recent_activity(own)
        )
        return TEMPLATES.TemplateResponse(
            request,
            "certificate-receivers.html",
            {
                **context,
                "rows": tuple(
                    (row, certificate_receivers.fetch_steps(row, manager)) for row in rows
                ),
                "manager": manager,
                "on_rows": on_rows,
                "ghosts": ghosts,
                "problem": problem,
            },
        )

    def _receiver_password_page(
        request: Request, session: AuthenticatedSession, receiver: str, password: str
    ) -> Response:
        """An https receiver's new password, on the one answer that shows it (B306).

        It was made for this request, its hash went into the job, and nothing
        keeps it - not the database, not a cache.
        """

        _token, registry, context = _page_context(config, request, session)
        manager = registry.manager if registry else None
        return TEMPLATES.TemplateResponse(
            request,
            "certificate-receiver-password.html",
            {
                **context,
                "receiver": receiver,
                "step": certificate_receivers.password_step(
                    receiver, manager or "<manager>", password
                ),
            },
            headers={"Cache-Control": "no-store"},
        )

    def _receiver_form_page(
        request: Request,
        session: AuthenticatedSession,
        *,
        problem: str = "",
        form: Mapping[str, str] | None = None,
    ) -> Response:
        """The form: what is needed before the job, and nothing from after it."""

        _token, _registry, context = _page_context(config, request, session)
        entered = {"receiver": "", "transport": "sftp", "public_key": "", "allow": ""}
        if form:
            entered.update(form)
        return TEMPLATES.TemplateResponse(
            request,
            "certificate-receiver-new.html",
            {
                **context,
                "key_steps": certificate_receivers.key_steps(entered["receiver"]),
                "transports": certificate_receivers.TRANSPORT_HELP,
                "windows_transports": certificate_receivers.WINDOWS_TRANSPORTS,
                "windows": entered["transport"] in certificate_receivers.WINDOWS_TRANSPORTS,
                "form": entered,
                "problem": problem,
            },
        )

    @router.get("/certificates/receivers", response_class=HTMLResponse)
    def certificate_receivers_page(request: Request) -> Response:
        """Who fetches from this manager, and what each host runs to do it."""

        gate = _admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        return _receivers_page(request, gate)

    @router.get("/certificates/receivers/new", response_class=HTMLResponse)
    def certificate_receiver_form(request: Request) -> Response:
        """Register a receiver: its own page, like a new certificate is."""

        gate = _admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        if _registry_overview(config, request) is None:
            return RedirectResponse("/certificates/receivers", status_code=303)
        return _receiver_form_page(request, gate)

    def _queue_receiver_job(
        request: Request,
        session: AuthenticatedSession,
        payload: Mapping[str, Any],
        key: UUID,
        *,
        form: Mapping[str, str] | None,
        password: str | None = None,
    ) -> Response:
        def again(problem: str) -> Response:
            if form is None:
                return _receivers_page(request, session, problem=problem)
            return _receiver_form_page(request, session, problem=problem, form=form)

        try:
            operations.prepare(
                operation="cert_receiver", cluster=None, request_id=uuid4(), payload=payload
            )
        except operations.BadPayload as refused:
            return again(str(refused))
        with request.app.state.pool.connection() as connection:
            try:
                job = db.queue_job(
                    connection,
                    operation="cert_receiver",
                    cluster=None,
                    payload=payload,
                    idempotency_key=key,
                )
            except db.CertificateBusy:
                connection.rollback()
                return again(
                    "A certificate job is already running. Wait for it to finish, then ask again."
                )
            except db.RequestConflict:
                connection.rollback()
                return PlainTextResponse("That request key asked for something else", 409)
            #
            # The audit row names the receiver and the action, never the key:
            # a public key is not a secret, but the audit log is not where a
            # reader looks for one either.
            #
            db.record_audit_event(
                connection,
                actor=session.username,
                action="queue_job",
                cluster=None,
                request_id=job.request_id,
                detail={
                    "operation": "cert_receiver",
                    "job": job.id,
                    "receiver": payload["receiver"],
                    "action": payload["action"],
                },
            )
            connection.commit()
        if password is not None:
            #
            # Drawn here rather than after a redirect: a redirect's next page
            # would need the password from somewhere, and nothing holds it.
            #
            return _receiver_password_page(request, session, payload["receiver"], password)
        return RedirectResponse("/certificates/receivers", status_code=303)

    @router.post("/certificates/receivers/new", response_class=HTMLResponse)
    def certificate_receiver_add(
        request: Request,
        receiver: str = Form(default="", max_length=128),
        transport: str = Form(default="", max_length=16),
        public_key: str = Form(default="", max_length=8192),
        allow: str = Form(default="", max_length=2048),
        idempotency_key: str = Form(default="", max_length=64),
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        """Queue one `cert_receiver` add job, or draw the form again saying why not."""

        gate = _admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return PlainTextResponse("Refused", status_code=403)
        try:
            key = UUID(idempotency_key)
        except ValueError:
            return PlainTextResponse("A request key is required", status_code=400)
        entered = {
            "receiver": receiver,
            "transport": transport,
            "public_key": public_key,
            "allow": allow,
        }
        registry = _registry_overview(config, request)
        try:
            payload = certificate_receivers.payload(
                receiver, transport, public_key, allow, registry.receiver_rows if registry else ()
            )
        except certificate_receivers.ReceiverProblem as refused:
            return _receiver_form_page(request, gate, problem=str(refused), form=entered)
        password = None
        if payload.get("transport") == "https":
            password = cert_receiver.new_secret()
            payload = {**payload, "secret_hash": cert_receiver.secret_hash(password)}
        return _queue_receiver_job(request, gate, payload, key, form=entered, password=password)

    @router.post("/certificates/receivers/secret", response_class=HTMLResponse)
    def certificate_receiver_secret(
        request: Request,
        receiver: str = Form(default="", max_length=128),
        idempotency_key: str = Form(default="", max_length=64),
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        """Queue a new secret for an https receiver, and show its password once."""

        gate = _admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return PlainTextResponse("Refused", status_code=403)
        try:
            key = UUID(idempotency_key)
        except ValueError:
            return PlainTextResponse("A request key is required", status_code=400)
        registry = _registry_overview(config, request)
        rows = registry.receiver_rows if registry else ()
        if not any(row.identifier == receiver and row.transport == "https" for row in rows):
            return _receivers_page(request, gate, problem=f"{receiver} is not an https receiver.")
        password = cert_receiver.new_secret()
        payload = {
            "receiver": receiver,
            "action": "secret",
            "secret_hash": cert_receiver.secret_hash(password),
        }
        return _queue_receiver_job(request, gate, payload, key, form=None, password=password)

    #
    # A new public key for an rsync or sftp receiver (26-10-18): a host
    # installed again keeps its name, directory and certificates and has a new
    # key pair. Its own page, as registering is, for the key steps and the paste.
    #
    def _receiver_key_page(
        request: Request,
        session: AuthenticatedSession,
        receiver: str,
        transport: str,
        *,
        public_key: str = "",
        problem: str = "",
    ) -> Response:
        _token, _registry, context = _page_context(config, request, session)
        return TEMPLATES.TemplateResponse(
            request,
            "certificate-receiver-key.html",
            {
                **context,
                "receiver": receiver,
                "key_steps": certificate_receivers.key_steps(receiver),
                "windows": transport in certificate_receivers.WINDOWS_TRANSPORTS,
                "public_key": public_key,
                "problem": problem,
            },
        )

    def _ssh_transport(request: Request, receiver: str) -> str | None:
        """The receiver's transport when it fetches over ssh, else None."""

        registry = _registry_overview(config, request)
        rows = registry.receiver_rows if registry else ()
        return next(
            (
                row.transport
                for row in rows
                if row.identifier == receiver and row.transport != "https"
            ),
            None,
        )

    @router.get("/certificates/receivers/key", response_class=HTMLResponse)
    def certificate_receiver_key_form(request: Request) -> Response:
        gate = _admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        receiver = request.query_params.get("receiver", "")
        transport = _ssh_transport(request, receiver)
        if transport is None:
            return _receivers_page(request, gate, problem=f"{receiver} has no SSH key to replace.")
        return _receiver_key_page(request, gate, receiver, transport)

    @router.post("/certificates/receivers/key", response_class=HTMLResponse)
    def certificate_receiver_key(
        request: Request,
        receiver: str = Form(default="", max_length=128),
        public_key: str = Form(default="", max_length=8192),
        idempotency_key: str = Form(default="", max_length=64),
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        """Queue a new key for an ssh receiver; its lock, directory and certificates stay."""

        gate = _admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return PlainTextResponse("Refused", status_code=403)
        try:
            key = UUID(idempotency_key)
        except ValueError:
            return PlainTextResponse("A request key is required", status_code=400)
        transport = _ssh_transport(request, receiver)
        if transport is None:
            return _receivers_page(request, gate, problem=f"{receiver} has no SSH key to replace.")
        #
        # The helper's own shape check, here first, so a wrong paste is said
        # beside the field rather than as a failed job.
        #
        try:
            cert_receiver.parse_public_key(public_key, "The pasted text")
        except cert_receiver.ReceiverError as refused:
            return _receiver_key_page(
                request, gate, receiver, transport, public_key=public_key, problem=str(refused)
            )
        payload = {"receiver": receiver, "action": "key", "public_key": public_key}
        return _queue_receiver_job(request, gate, payload, key, form=None)

    @router.post("/certificates/receivers/remove", response_class=HTMLResponse)
    def certificate_receiver_remove(
        request: Request,
        receiver: str = Form(default="", max_length=128),
        idempotency_key: str = Form(default="", max_length=64),
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        """Queue one `cert_receiver` remove job for a receiver nothing publishes to."""

        gate = _admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return PlainTextResponse("Refused", status_code=403)
        try:
            key = UUID(idempotency_key)
        except ValueError:
            return PlainTextResponse("A request key is required", status_code=400)
        registry = _registry_overview(config, request)
        try:
            payload = certificate_receivers.removal(
                receiver, registry.receiver_rows if registry else ()
            )
        except certificate_receivers.ReceiverProblem as refused:
            return _receivers_page(request, gate, problem=str(refused))
        return _queue_receiver_job(request, gate, payload, key, form=None)

    @router.post("/certificates/delete", response_class=HTMLResponse)
    def certificate_delete_review(
        request: Request,
        certificate: Sequence[str] = Form(default=()),
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        """The confirmation page for a selection: nothing is queued from here.

        A POST rather than a GET with the IDs in the address, because the
        selection can be long and because the page it draws is a question
        about a change, not a view somebody should bookmark.
        """

        gate = _admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return PlainTextResponse("Refused", status_code=403)
        return _certificate_delete_page(request, gate, chosen=tuple(certificate))

    @router.post("/certificates/delete/confirm", response_class=HTMLResponse)
    def certificate_delete_confirm(
        request: Request,
        certificate: Sequence[str] = Form(default=()),
        idempotency_key: str = Form(default="", max_length=64),
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        """Queue one `cert_delete` job for what the confirmation page offered.

        The selection is evaluated again here, not trusted from the previous
        page: a draft written in between is a refusal now, and the question
        is asked again with it on the row rather than the job quietly
        carrying less than was confirmed. The helper's own refusals arrive
        on the job's rows.
        """

        gate = _admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return PlainTextResponse("Refused", status_code=403)
        try:
            key = UUID(idempotency_key)
        except ValueError:
            return PlainTextResponse("A request key is required", status_code=400)

        registry = _registry_views(request, config)
        with request.app.state.pool.connection() as connection:
            drafts = db.live_drafts(connection)
        try:
            picked = certificate_delete.selection(tuple(certificate), registry, drafts)
        except certificate_delete.SelectionProblem as refused:
            return _certificate_delete_page(
                request, gate, chosen=tuple(certificate), problem=str(refused)
            )
        if not picked.deletable:
            return _certificate_delete_page(
                request,
                gate,
                chosen=tuple(certificate),
                problem="Nothing in the selection can be deleted from here.",
            )
        if picked.refused:
            return _certificate_delete_page(
                request,
                gate,
                chosen=tuple(certificate),
                problem="Since you were asked, something changed for "
                + ", ".join(row.identifier for row in picked.refused)
                + "; nothing was queued. Read the rows and confirm again.",
            )
        payload = {"certificates": list(picked.deletable)}
        try:
            operations.prepare(
                operation="cert_delete",
                cluster=None,
                request_id=uuid4(),
                payload=payload,
                draft_references=lambda ids: certificate_delete.draft_references(drafts, ids),
            )
        except operations.BadPayload as refused:
            return _certificate_delete_page(
                request, gate, chosen=tuple(certificate), problem=str(refused)
            )

        with request.app.state.pool.connection() as connection:
            try:
                job = db.queue_job(
                    connection,
                    operation="cert_delete",
                    cluster=None,
                    payload=payload,
                    idempotency_key=key,
                )
            except db.CertificateBusy:
                connection.rollback()
                return _certificate_delete_page(
                    request,
                    gate,
                    chosen=tuple(certificate),
                    problem="A certificate job is already running. Wait for it to finish on "
                    "the Jobs page, then ask again.",
                )
            except db.RequestConflict:
                connection.rollback()
                return PlainTextResponse("That request key asked for something else", 409)
            db.record_audit_event(
                connection,
                actor=gate.username,
                action="queue_job",
                cluster=None,
                request_id=job.request_id,
                detail={
                    "operation": "cert_delete",
                    "job": job.id,
                    "certificates": list(picked.deletable),
                },
            )
            connection.commit()
        return RedirectResponse("/certificates?view=registry", status_code=303)

    return router
