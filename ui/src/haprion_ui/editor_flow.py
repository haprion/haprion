"""The proxy form from reading to saving: the editor's state, page and submissions (K01, review 2026-10-28).

The form reads an object as its saved layers show it over what was published,
draws the editor, and saves a draft, a change for the next publish, a removal
or an advanced block - each fenced on the reading it was drawn from, so a
second tab's newer work is kept rather than written away.
"""

from __future__ import annotations

from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any
from uuid import uuid4

from fastapi import HTTPException, Request, Response
from fastapi.responses import (
    PlainTextResponse,
    RedirectResponse,
)
from haprion import (
    crs,
    dnsdist_config,
    proxy_model,
    resolve_socket,
    server_names,
    status_collect,
)
from haprion.config import CLUSTER_ID, DEFAULT_ABUSE_WINDOW
from haprion.digits import is_digits
from haprion.proxy_model import (
    DEFAULT_DNS_FALL,
    DEFAULT_DNS_INTERVAL,
    DEFAULT_DNS_RISE,
    DEFAULT_DOWN_INTERVAL,
    DEFAULT_FALL,
    DEFAULT_FAST_INTERVAL,
    DEFAULT_INTERVAL,
    DEFAULT_RISE,
    SENDERS_ADDRESS,
    ModelError,
    load_proxy,
    load_written,
)
from pydantic import ValidationError

from haprion_ui import (
    advanced_dialog,
    auth,
    blocked,
    certificates,
    db,
    features,
    health,
    history,
    metrics,
    network,
    objects,
    waf,
)
from haprion_ui import editor as editor_module
from haprion_ui import preview as preview_module
from haprion_ui import probe as probe_module
from haprion_ui.access import current_session, forbidden_page
from haprion_ui.cluster_identity import accent_index
from haprion_ui.config import Config
from haprion_ui.reading import (
    CERTIFICATE_SOURCE,
    HISTORY_SOURCE,
    INVENTORY_SOURCE,
    NETWORK_SOURCE,
    OBJECTS_SOURCE,
    STATUS_SOURCE,
    read_manager_certificates,
    read_source,
)
from haprion_ui.refusals import refusal_page
from haprion_ui.saved_work import (
    ObjectsReading,
    ObjectWork,
    saved_network_rows,
    settled_draft,
    settled_work,
)
from haprion_ui.templates import TEMPLATES


def earlier_names(
    name: str,
    targets: Mapping[str, metrics.BackendTarget],
    aliases: Mapping[str, Sequence[db.EarlierName]],
) -> list[db.EarlierName]:
    """A backend's earlier names: recorded renames, and the generator's older form of each."""

    found = list(aliases.get(name, ()))
    found += [
        db.EarlierName(older)
        for older, target in targets.items()
        if target.current == name and older != name
    ]
    return found


@dataclass(frozen=True, slots=True)
class EditorState:
    """Everything the editor reads about one cluster before it draws anything.

    Gathered in one place because the page needs four of the poller's sources
    to answer one question, and a route that fetched them inline would read as
    plumbing with a form somewhere inside it. The four are not
    interchangeable: the objects say what is stored, the network and the
    certificates say what may be chosen, and the history says which version an
    edit is being made against.
    """

    cluster: str
    #
    # The commit the stored objects were read at. A draft records it, and a
    # publish refuses if the tree has moved since - so an edit is always made
    # against a base somebody can name.
    #
    commit: str | None
    base_version: int | None
    stored: tuple[objects.ObjectView, ...]
    choices: editor_module.EditorCluster
    available: bool


def _published_servers(stored: objects.ObjectView | None, networks: Collection[str]) -> list[str]:
    """The server addresses of the object as published, in their order, or none."""

    if stored is None:
        return []
    try:
        fields = preview_module.form_from_document(stored.document, networks=networks)
    except preview_module.Unexpressible:
        return []
    return str(fields.get("servers", "")).splitlines()


def editor_state(request: Request, config: Config, cluster: str) -> EditorState:
    clusters, object_rows = read_source(request, config, OBJECTS_SOURCE, cluster=cluster)
    if cluster not in clusters:
        raise HTTPException(status_code=404)
    stale_after = config.poller.stale_after
    reading = next((row for row in object_rows if row.cluster == cluster), None)
    result = reading.result if reading is not None and isinstance(reading.result, dict) else {}
    commit = result.get("commit")

    _, network_rows = read_source(
        request, config, NETWORK_SOURCE, cluster=cluster, clusters=clusters
    )
    #
    # Checked against the saved network when there is one (B257): an object
    # saved for a VIP the same publish adds would otherwise be refused for it.
    #
    with request.app.state.pool.connection() as connection:
        network_rows, _saved = saved_network_rows(connection, list(network_rows))
    described = next(
        (
            view
            for view in network.build_network_overview(
                (cluster,),
                network_rows,
                stale_after=stale_after,
            )
            if view.cluster == cluster
        ),
        None,
    )
    _, certificate_rows = read_source(
        request, config, CERTIFICATE_SOURCE, cluster=cluster, clusters=clusters
    )
    _, inventory_rows = read_source(
        request, config, INVENTORY_SOURCE, cluster=cluster, clusters=clusters
    )
    held = next(
        (
            view
            for view in certificates.build_certificate_overview(
                (cluster,),
                certificate_rows,
                stale_after=stale_after,
                #
                # The CA certificates a pool may verify against are the
                # registry's, which is the manager's own reading (B304).
                #
                manager=read_manager_certificates(request, config),
            ).clusters
            if view.cluster == cluster
        ),
        None,
    )
    _, history_rows = read_source(
        request, config, HISTORY_SOURCE, cluster=cluster, clusters=clusters
    )
    released = next(
        (
            version
            for view in history.build_history_overview(
                (cluster,),
                history_rows,
                stale_after=stale_after,
            ).clusters
            if view.cluster == cluster
            for version in view.versions
            if version.published
        ),
        None,
    )
    return EditorState(
        cluster=cluster,
        commit=commit if isinstance(commit, str) and commit else None,
        base_version=released.number if released else None,
        stored=objects.cluster_object_views(reading),
        choices=editor_module.editor_cluster(
            cluster,
            described,
            held,
            editor_module.reservations_from_inventory(
                next(
                    (
                        row.result
                        for row in inventory_rows
                        if row.cluster == cluster and row.outcome == "done"
                    ),
                    None,
                )
            ),
        ),
        available=reading is not None and reading.outcome == "done" and not reading.poll_error,
    )


def state_reading(state: EditorState) -> ObjectsReading:
    """The editor state's objects cache, as `_reflects` reads it."""

    return ObjectsReading({view.name for view in state.stored}, state.commit)


def _unresolved_servers(name: str, document: str) -> list[str]:
    """The pool members' names the manager cannot resolve, as warnings (finding 72).

    Never a refusal: the nodes may resolve what the manager does not, and their
    own check before a release is switched to stays the gate. An object the
    model does not read yet, and a lookup service that cannot be asked, say
    nothing here - the first is said by the check, the second is the
    installation's.
    """

    try:
        proxy = load_proxy(name or "editor", document.encode())
    except proxy_model.ModelError:
        return []
    missing = resolve_socket.unresolved(server_names.names([proxy])) or []
    return [server_names.warning(host) for host in missing]


#
# What the editor says after a save when there is no card to say it (B330).
#
SAVED_NOTICE = "Saved."


def editor_page(
    request: Request,
    config: Config,
    cluster: str,
    name: str,
    form: editor_module.ObjectForm | None,
    *,
    action: str = "check",
    draft_revision: str = "",
    notice: str = "",
    probe_asked: bool = False,
    open_group: str = "",
    answered: bool = True,
    object_fingerprint: str | None = None,
) -> Response:
    """Draw the editor, whether it was reached by a link or by a submission.

    One function for both because the page is the same page: a form, what it
    produces, and what is wrong with it. Splitting it would give a submission
    a second chance to disagree with the link about which cluster values it
    was judged against.
    """

    session = current_session(request)
    if session is None:
        return RedirectResponse("/login", status_code=303)
    if not config.management_writes:
        #
        # 404 and not 403, for the reason `/operations` gives: an installation
        # that does not do management writes has no editor, and saying
        # "forbidden" would announce one waiting to be switched on.
        #
        return PlainTextResponse("Not found", status_code=404)
    if session.role != "admin":
        return forbidden_page(request, config)
    token = request.cookies.get(auth.SESSION_COOKIE, "")
    state = editor_state(request, config, cluster)

    with request.app.state.pool.connection() as connection:
        work = (
            settled_work(connection, cluster, name, state_reading(state)) if name else ObjectWork()
        )
    draft = work.top

    stored = next((view for view in state.stored if view.name == name), None)
    unexpressible = ""
    #
    # Whether this page is an answer to a question about the object. Read
    # before `form` is replaced below, because from there on the two are
    # indistinguishable.
    #
    # "Test health" is a submission too, and it is not that question: it asks
    # the nodes about the backend, and a page that answered it with a verdict on
    # the document would be reporting on work the person did not ask about.
    #
    submitted = form is not None and form.action != "recheck" and answered
    if form is None:
        #
        # Opened rather than submitted. A draft is what the person was last
        # working on, so it wins over the stored document - and its absence is
        # what makes an untouched object open as it is written.
        #
        source = draft.yaml if draft is not None and not draft.deleted else None
        source = source or (stored.document if stored is not None else "")
        if not source:
            fields = dict(preview_module.DEFAULTS, **preview_module.NEW_POOL_CHECK, name=name)
        else:
            try:
                fields = preview_module.form_from_document(source, networks=state.choices.networks)
            except preview_module.Unexpressible as exc:
                fields = dict(preview_module.DEFAULTS, name=name)
                unexpressible = str(exc)
        try:
            form = editor_module.ObjectForm(
                **_form_defaults(fields),
                saved_revision=str(work.saved.revision) if work.saved is not None else "",
                object_fingerprint=editor_module.fingerprint(stored.document if stored else None),
            )
        except ValidationError as exc:
            #
            # Said when it is opened, as an object the form cannot say is: one
            # it could show and not save was an error page (review 26-10-24,
            # 15-08).
            #
            form = editor_module.ObjectForm(
                **_form_defaults(dict(preview_module.DEFAULTS, name=name)),
                saved_revision=str(work.saved.revision) if work.saved is not None else "",
                object_fingerprint=editor_module.fingerprint(stored.document if stored else None),
            )
            unexpressible = ".".join(str(part) for part in exc.errors()[0]["loc"])
        draft_revision = str(work.draft.revision) if work.draft is not None else ""

    fields = form.fields()
    #
    # What the nodes say about this object's backend right now. Read for the page
    # rather than for the check: it is an observation, not a verdict on the
    # document, and an object that has never been deployed simply has none.
    #
    _, status_rows = read_source(request, config, STATUS_SOURCE)
    backend = health.backend_health(
        status_rows,
        cluster=cluster,
        obj=str(fields.get("name", "")).strip() or name,
        backend=str(fields.get("backend", "")).strip()
        or str(fields.get("name", "")).strip()
        or name,
        #
        # The same address the probe binds, and read the same way. With one set,
        # only the node that carries it can answer for this backend - the other
        # runs the same check against an address it does not have.
        #
        source=probe_module.source_address(fields, editor_module.choices(state.choices)),
        #
        # As written in the form, so the card can say `198.51.100.10:8080`
        # instead of `s1`. The runtime name stays beside it: it is what appears
        # in the logs somebody will read next.
        #
        addresses=str(fields.get("servers", "")).splitlines(),
        deployed=_published_servers(stored, state.choices.networks),
        held_only=fields.get("protocol") in SENDERS_ADDRESS,
    )
    #
    # Only when somebody pressed the button. A page that probed on every open
    # would have every visit reach out to two nodes and to whatever they can
    # connect to, which is a lot of traffic for a page somebody is reading.
    #
    report = (
        probe_module.run(cluster, fields, editor_module.choices(state.choices))
        if probe_asked
        else None
    )
    #
    # A syslog check is tried from every node's own address, as keepalived
    # runs it, and shown for the node holding the VIP, as the rows above it
    # are (Fas 19b B5).
    #
    if report is not None and fields.get("protocol") in SENDERS_ADDRESS and backend.held_by:
        report = replace(
            report, nodes=tuple(node for node in report.nodes if node.node in backend.held_by)
        )
    result = editor_module.check(
        fields,
        state.choices,
        others=tuple((view.name, view.document) for view in state.stored),
    )
    dns_form = fields.get("protocol") == "dns"
    #
    # What a publish changed in this object after the work on it was written
    # (0080): shown above the form, and Save says it writes over it.
    #
    moved_under = (
        editor_module.moved(
            draft.base_document,
            published_document(state, draft.replaces or name),
            networks=state.choices.networks,
        )
        if draft is not None and object_moved(state, draft) and draft.base_document is not None
        else ()
    )
    held = blocked.object_card(status_rows, cluster=cluster, name=name) if name else None
    unresolved = (
        _unresolved_servers(str(fields.get("name", "") or name), result.document)
        if result.document and not dns_form
        else []
    )
    return TEMPLATES.TemplateResponse(
        request,
        "editor.html",
        {
            "blocked_here": held.count if held is not None else 0,
            "username": session.username,
            "role": session.role,
            "csrf_token": auth.csrf_token(token),
            "section": "proxies",
            "cluster": cluster,
            #
            # The same colour this cluster carries on every other page. The
            # editor is the one place a person writes rather than reads, and it
            # was the one page that did not say which cluster they are writing
            # to in the way the rest of the interface says it.
            #
            "accent": accent_index(cluster),
            "name": name,
            "existing": stored is not None,
            "form": fields,
            "choices": editor_module.choices(state.choices),
            "complete": state.choices.complete,
            "available": state.available,
            "suggested_cookie": preview_module.suggested_cookie(
                str(fields.get("name", "")).strip()
            ),
            #
            # Read from the model rather than written into the template. The
            # form has no field for the check interval, so every object it
            # writes carries the default - and a hint that names it has to name
            # the value the engine will actually use.
            #
            #
            # A dns check's are dnsdist's (Fas 19a B5), which the engine writes
            # for one when the document says nothing.
            #
            "check_interval": DEFAULT_DNS_INTERVAL if dns_form else DEFAULT_INTERVAL,
            "rate_window": DEFAULT_ABUSE_WINDOW,
            "check_fast_interval": DEFAULT_FAST_INTERVAL,
            "check_down_interval": DEFAULT_DOWN_INTERVAL,
            "check_rise": DEFAULT_DNS_RISE if dns_form else DEFAULT_RISE,
            "check_fall": DEFAULT_DNS_FALL if dns_form else DEFAULT_FALL,
            #
            # DNS is offered once every node of the cluster runs dnsdist (Fas 19a
            # B5): a release with a listener is refused by a node without it.
            #
            "dns_offered": health.dns_everywhere(status_rows, cluster=cluster),
            #
            # Syslog once every node's keepalived reads the file its virtual
            # servers are written to (Fas 19b B4); until then a node installs
            # the file and forwards nothing.
            #
            "syslog_offered": health.syslog_everywhere(status_rows, cluster=cluster),
            "check_protocols": preview_module.CHECK_PROTOCOLS,
            "unresolved_servers": unresolved,
            "result": result,
            "draft": draft,
            "moved_under": moved_under,
            "current_version": state.base_version,
            "work": work,
            "draft_revision": draft_revision,
            "saved_revision": form.saved_revision,
            #
            # Carried from the page that was opened, not read again here: a
            # submission redrawn with the current object's would quietly accept
            # the change it is there to notice. Only the refusal hands over the
            # new one (CR-01).
            #
            "object_fingerprint": (
                form.object_fingerprint if object_fingerprint is None else object_fingerprint
            ),
            "unexpressible": unexpressible,
            "submitted": submitted,
            "waf_offered": features.is_on(features.WAF_ENGINE),
            "waf_unavailable": waf.engine(
                read_source(request, config, OBJECTS_SOURCE)[1], status_rows
            ).unavailable(cluster),
            "backend_health": backend,
            "open_group": open_group,
            "waf_exceptions": waf.form_exceptions(
                cluster,
                name,
                str(fields.get("waf_exceptions", "") or ""),
                stored.document if stored is not None else "",
                crs.installed_catalog() if fields.get("waf_exceptions") else {},
            ),
            "probe": report,
            #
            # Saved changes have their card, which says it (B330): the notice
            # would be the same thing said twice.
            #
            "notice": ""
            if notice == SAVED_NOTICE and getattr(draft, "stage", None) == "saved"
            else notice,
            "action": action,
            "unchanged": editor_module.unchanged(
                result.document, stored.document if stored else None
            ),
            "management_writes": config.management_writes,
            "demo_fixture": config.demo_fixture,
        },
    )


def lookup_again(
    request: Request, config: Config, cluster: str, name: str, csrf_token: str
) -> Response:
    """The stored object saved with its dns server names looked up again (B252, B261)."""

    session = current_session(request)
    if session is None:
        return RedirectResponse("/login", status_code=303)
    if not config.management_writes:
        return PlainTextResponse("Not found", status_code=404)
    if session.role != "admin":
        return forbidden_page(request, config)
    token = request.cookies.get(auth.SESSION_COOKIE, "")
    if not auth.csrf_token_is_valid(token, csrf_token):
        return forbidden_page(request, config)
    state = editor_state(request, config, cluster)
    stored = next((view for view in state.stored if view.name == name), None)
    if stored is None:
        return refusal_page(
            request, config, "This cluster has no proxy of that name.", back="/proxies"
        )
    with request.app.state.pool.connection() as connection:
        draft = settled_draft(connection, cluster, name, state_reading(state))
    if draft is not None:
        #
        # Saving the stored object would throw the draft's work away. Saving
        # the draft looks the names up as well.
        #
        return refusal_page(
            request,
            config,
            f"{name} has unsaved or unpublished changes. Save them in the editor; that looks "
            "the names up too.",
            back=proxy_path(cluster, name, "edit"),
        )
    #
    # The names are looked up here, as every save of a dns object does (B261),
    # and the object saved with the addresses they give now. The publish is
    # Versions', with whatever else is saved, and the version says what moved.
    #
    try:
        document = dnsdist_config.with_addresses(
            stored.name, stored.document, resolve_socket.lookup
        )
        load_written(stored.name, document.encode())
    except (ValueError, ModelError) as refusal:
        return refusal_page(request, config, str(refusal), back=proxy_path(cluster, name))
    with request.app.state.pool.connection() as connection:
        saved = db.save_change(
            connection,
            cluster=cluster,
            object_id=stored.name,
            base_document=published_document(state, stored.name),
            yaml=document,
            base_version=state.base_version,
            base_hash=state.commit or "",
            updated_by=session.username,
            saved_revision=None,
            draft_revision=None,
        )
        db.record_audit_event(
            connection,
            actor=session.username,
            action="save_change",
            cluster=cluster,
            request_id=uuid4(),
            detail={"object": stored.name, "revision": saved.revision, "lookup": True},
        )
        connection.commit()
    return RedirectResponse("/proxies", status_code=303)


def moved_dns_servers(rows: Iterable[Any], *, cluster: str, pools: Collection[str]) -> list[str]:
    """The status's word that a pool's server name moved since publishing (B252).

    The status names the pool; the page of the object owning it repeats the
    sentence, since publishing the object again is the answer.
    """

    return [
        str(warning.get("message", ""))
        for row in rows
        if getattr(row, "cluster", None) == cluster
        for warning in (getattr(row, "warnings", None) or ())
        if isinstance(warning, Mapping)
        and warning.get("code") == status_collect.DNS_SERVER_MOVED
        and status_collect.moved_pool(str(warning.get("message", ""))) in pools
    ]


def _form_defaults(fields: dict[str, Any]) -> dict[str, Any]:
    """The form model's own view of a field mapping.

    `allow_from` is the only one that needs saying: the model holds a list and
    the mapping carries a tuple, and pydantic will not take the tuple for a
    field it was told is a list.
    """

    values = dict(fields)
    values["allow_from"] = list(values.get("allow_from") or ())
    values["deny_from"] = list(values.get("deny_from") or ())
    values["block_exempt_from"] = list(values.get("block_exempt_from") or ())
    return values


#
# Every address these pages send a browser to is built here, from segments that
# have been checked against the rules that define them: the engine's own object
# name rule, and the cluster id the configuration is read with.
#
# What keeps such a redirect on this site is the leading "/proxies" - a
# reference that begins with a single slash takes its host from the page it was
# served from, and no number of ".." segments can put an authority back. The
# checking is what makes that argument unnecessary rather than merely true: the
# only thing that can reach a `Location` header from here is forty characters of
# lowercase letters, digits, hyphens and underscores. A caller that gets this
# far with anything else has a bug, so it is a 404 and not a page - the readable
# refusal belongs where the name was typed, and is done there.
#
def published_document(state: Any, name: str | None) -> str:
    """The object `name` as the reading has it published; empty where nothing of that name is.

    What a draft keeps as its base (0080): the version it was written against
    moves with every publish of anything, and this moves only with the object.
    """

    stored = next((view for view in state.stored if view.name == name), None) if name else None
    return stored.document if stored is not None else ""


def object_moved(state: Any, row: db.ProxyDraft) -> bool:
    """Whether the object this row changes was published differently after the row was written.

    Unknown - False - on a row from before 0080, which `base_hash` judges.
    """

    if row.base_document is None:
        return False
    now = published_document(state, row.replaces or row.object_id)
    return now.strip() != row.base_document.strip()


def carried_base(state: Any, name: str | None, *rows: db.ProxyDraft | None) -> str | None:
    """The base a write on top of somebody's work keeps: that work's, not the object's now.

    Only a save from the whole form, where the page has shown what moved
    underneath, takes the object as it is published now. A draft saved again,
    an exception or a line of advanced config added to a saved change is
    written over the same base as the work it changes - taking the new one
    would call the work current without anybody having seen what moved. A row
    from before 0080 carries None, as it was.
    """

    for row in rows:
        if row is not None:
            return row.base_document
    return published_document(state, name)


def proxy_path(cluster: str, *segments: str) -> str:
    """The URL of a page under `/proxies`, from segments that may be used as one."""

    if not CLUSTER_ID.fullmatch(cluster):
        raise HTTPException(status_code=404)
    for segment in segments:
        if not proxy_model.NAME.fullmatch(segment):
            raise HTTPException(status_code=404)
    return "/proxies/" + "/".join((cluster, *segments))


def editor_submit(
    request: Request,
    config: Config,
    cluster: str,
    name: str,
    form: editor_module.ObjectForm,
) -> Response:
    """Check the object, save the draft, or throw the draft away.

    Saving is refused for a document the engine cannot read as an object at
    all. Whether it *fits the cluster* is a different question and does not
    block a draft: a hostname another object claims is answered at publish
    time, and a person who cannot save until every neighbour agrees cannot work
    incrementally.
    """

    session = current_session(request)
    if session is None:
        return RedirectResponse("/login", status_code=303)
    if not config.management_writes:
        return PlainTextResponse("Not found", status_code=404)
    token = request.cookies.get(auth.SESSION_COOKIE, "")
    if not auth.csrf_token_is_valid(token, form.csrf_token):
        return forbidden_page(request, config)
    if session.role != "admin":
        return forbidden_page(request, config)

    if is_digits(form.drop_exception):
        form = form.model_copy(
            update={
                "waf_exceptions": waf.without_form_exception(
                    form.waf_exceptions, int(form.drop_exception)
                ),
                "drop_exception": "",
            }
        )
        return editor_page(
            request,
            config,
            cluster,
            name,
            form,
            draft_revision=form.expected_revision,
            open_group="waf",
            #
            # A change to the form, not a question about the object: the page
            # answers nothing, so it shows no verdict and no stored object.
            #
            answered=False,
        )

    if form.action == "check":
        return editor_page(
            request, config, cluster, name, form, draft_revision=form.expected_revision
        )

    #
    # Asking the nodes to try the check the form describes, right now, against
    # the object as it is written on screen - published or not. The poller is
    # woken as well, because what it reports about a deployed backend is the other
    # half of the same question and it costs one notification.
    #
    if form.action == "recheck":
        with request.app.state.pool.connection() as connection:
            db.wake_poller(connection)
        return editor_page(
            request,
            config,
            cluster,
            name,
            form,
            draft_revision=form.expected_revision,
            probe_asked=True,
        )

    state = editor_state(request, config, cluster)
    typed = str(form.name or "").strip()
    object_id = name or typed
    if not object_id:
        return refusal_page(
            request, config, "A proxy needs a name before it can be saved.", back="/proxies"
        )
    #
    # Checked where the person typed it, and not only where it is used. The rule
    # is the engine's own, so a name refused here is one the publish would refuse
    # anyway - the difference is a page that says which character was the problem
    # rather than a job that fails an hour later. Everything after this point,
    # the draft's key and every link back to it, may treat the name as a name.
    #
    if not proxy_model.NAME.fullmatch(object_id):
        return refusal_page(
            request,
            config,
            f"{object_id} is not a usable proxy name - {proxy_model.name_refusal(object_id)}; "
            f"use {proxy_model.NAME_RULE}.",
            back="/proxies",
        )
    #
    # Renaming a *published* object really is a new object and a removal. The
    # name is not a label on the document: the generated file is named after it
    # and `guid` derives every section name in it, so no rename leaves the
    # HAProxy configuration untouched. What can be arranged is that the two
    # halves are one act - the publish below carries the new document and the
    # old name's removal in a single set, so the candidate `haproxy -c`
    # validates is the state afterwards and never the moment in between.
    #
    # This used to be refused, and the refusal sent people down a path that
    # does not work: publishing the new name first is refused for claiming a
    # hostname the old object still holds, and removing the old one first takes
    # the site down until the new one is published.
    #
    # A draft that has never been published needs no removal - nothing outside
    # the draft table carries its name yet - so it is only the key that moves,
    # handled below where the draft is written.
    #
    renaming = bool(name) and bool(typed) and typed != name
    published = any(view.name == name for view in state.stored)
    if renaming and not proxy_model.NAME.fullmatch(typed):
        return refusal_page(
            request,
            config,
            f"{typed} is not a usable proxy name - {proxy_model.name_refusal(typed)}; "
            f"use {proxy_model.NAME_RULE}.",
            back=proxy_path(cluster, name, "edit"),
        )

    draft_revision = int(form.expected_revision) if is_digits(form.expected_revision) else None
    saved_revision = int(form.saved_revision) if is_digits(form.saved_revision) else None
    #
    # A new object has no draft to be a revision of, so the fields are ignored
    # here rather than trusted. They are hidden inputs, and a browser restores
    # hidden inputs when somebody navigates back into a form - so a revision
    # from the object saved a moment ago survived into the new-object form and
    # turned the next save into an update of a row that had never existed. The
    # answer was "the draft changed since it was read", about a draft nobody
    # had ever made, and the work was refused with nowhere obvious to go.
    #
    if not name:
        draft_revision = saved_revision = None

    if form.action == "discard":
        #
        # The top of the work, which is what the page shows: the draft, or the
        # saved change when there is no draft over it (B257).
        #
        if draft_revision is not None:
            stage, discarded_revision = db.DRAFT, draft_revision
        elif saved_revision is not None:
            stage, discarded_revision = db.SAVED, saved_revision
        else:
            return refusal_page(
                request,
                config,
                "There is nothing to discard.",
                back=proxy_path(cluster, name, "edit"),
            )
        with request.app.state.pool.connection() as connection:
            db.discard_draft(
                connection,
                cluster=cluster,
                object_id=object_id,
                expected_revision=discarded_revision,
                stage=stage,
            )
            db.record_audit_event(
                connection,
                actor=session.username,
                action="discard_draft",
                cluster=cluster,
                request_id=uuid4(),
                detail={"object": object_id, "stage": stage},
            )
            connection.commit()
        #
        # The object's own page, but only while it still is one. A name that is
        # neither stored, served nor drafted is a 404 by design - and after
        # discarding the only draft of an object that was never published, that
        # is exactly what the name has become. Sending somebody to it made the
        # last step of a perfectly ordinary act answer "Not Found".
        #
        # The listing instead, which is where the object no longer is. The name
        # travels in the query so the page can say which one, and it has passed
        # the engine's name rule above, so it is a name and not a fragment of
        # something else.
        #
        if any(view.name == object_id for view in state.stored) or (
            stage == db.DRAFT and saved_revision is not None
        ):
            return RedirectResponse(
                proxy_path(cluster, object_id) + "?discarded=1", status_code=303
            )
        return RedirectResponse("/proxies?discarded=" + object_id, status_code=303)

    #
    # No publish here (B257): saved changes are published together, from
    # Versions. A request asking this page to publish is a stale page or a
    # hand-made one, and nothing is written for it.
    #
    if form.action not in ("draft", "save"):
        return PlainTextResponse("Unknown action", status_code=400)

    if state.commit is None:
        return refusal_page(
            request,
            config,
            "The stored proxies have not been read yet, so there is no base to edit against.",
            back=proxy_path(cluster, object_id, "edit"),
        )
    if not name and any(view.name == object_id for view in state.stored):
        return refusal_page(
            request,
            config,
            "A proxy of that name already exists in this cluster.",
            back=proxy_path(cluster, "new"),
        )
    #
    # The stored object has to be the one the page showed (CR-01). The draft's
    # revision only guards the draft, and with none the save and the publish
    # were made against whatever the cache held now - so a tab opened before
    # somebody else's publish wrote their change away with its old fields.
    # Answered with the form as submitted, and with the object as it now is, so
    # pressing save again is a decision rather than the same accident.
    #
    shown = next((view for view in state.stored if view.name == name), None) if name else None
    current = editor_module.fingerprint(shown.document if shown else None)
    if form.object_fingerprint != current:
        return editor_page(
            request,
            config,
            cluster,
            name,
            form,
            draft_revision=form.expected_revision,
            notice=(
                f"{name} was changed by a publish after this page was opened, so nothing "
                "was saved. Saving this form now replaces that change; to keep it, open the "
                "proxy again."
            ),
            answered=False,
            object_fingerprint=current,
        )

    with request.app.state.pool.connection() as connection:
        work = (
            settled_work(connection, cluster, name, state_reading(state)) if name else ObjectWork()
        )
    #
    # The published name this work takes the place of. A rename of a published
    # object records it on the row (B257), so the publish that eventually
    # carries the row removes the old name too - worked out at the moment of
    # publishing, as it was, a rename saved first and published later lost it
    # and the publish added the new object beside the old one.
    #
    # A name that has been renamed before keeps the first published name: the
    # names in between were never anywhere but here. Renamed back to that name,
    # it is an edit of the published object and replaces nothing.
    #
    replaces = next(
        (row.replaces for row in (work.draft, work.saved) if row is not None and row.replaces),
        None,
    )
    if renaming:
        if work.saved is not None and form.action == "draft":
            #
            # The two rows of one object carry one name. A draft that renamed
            # the object while its saved change kept the old name would make
            # them two objects, and saving the draft later would leave the
            # first in the next publish beside the second.
            #
            return refusal_page(
                request,
                config,
                f"{name} has saved changes, so its name can only change with Save.",
                back=proxy_path(cluster, name, "edit"),
            )
        with request.app.state.pool.connection() as connection:
            taken = settled_draft(connection, cluster, typed, state_reading(state))
        stored_elsewhere = any(view.name == typed for view in state.stored) and typed != replaces
        if stored_elsewhere or taken is not None:
            return refusal_page(
                request,
                config,
                f"{typed} is already taken in this cluster, as a proxy or as a draft.",
                back=proxy_path(cluster, name, "edit"),
            )
        if published and replaces is None:
            replaces = name
        object_id = typed
    if replaces == object_id:
        replaces = None

    #
    # A draft must be an object. Whether it fits beside its neighbours is a
    # publish question, and refusing to save until every clash is resolved
    # would stop somebody from working towards resolving them.
    #
    result = editor_module.check(form.fields(), state.choices)
    if result.about_the_object:
        return editor_page(
            request, config, cluster, name, form, draft_revision=form.expected_revision
        )

    key = name or object_id
    with request.app.state.pool.connection() as connection:
        if form.action != "draft":
            #
            # Save: the saved change is written and the draft it was
            # finished from goes, in one transaction (B257). A rename
            # moves the saved row's key.
            #
            saved = db.save_change(
                connection,
                cluster=cluster,
                object_id=key,
                new_object_id=object_id if object_id != key else None,
                yaml=result.document,
                base_version=state.base_version,
                base_hash=state.commit,
                updated_by=session.username,
                #
                # From the whole form, with what moved shown above it:
                # the one write that takes the object as it is now.
                #
                base_document=published_document(state, replaces or key),
                replaces=replaces,
                saved_revision=saved_revision,
                draft_revision=draft_revision,
            )
        elif object_id != key and draft_revision is not None:
            #
            # One statement, not a write and then a delete. `save_draft`
            # commits a transaction of its own, so a two-step rename left
            # the new row standing when the second step was refused - two
            # drafts where somebody had made one. The key moves or it does
            # not.
            #
            saved = db.rename_draft(
                connection,
                cluster=cluster,
                object_id=key,
                new_object_id=object_id,
                yaml=result.document,
                base_version=state.base_version,
                base_hash=state.commit,
                updated_by=session.username,
                base_document=carried_base(state, replaces or key, work.draft),
                replaces=replaces,
                expected_revision=draft_revision,
            )
        else:
            saved = db.save_draft(
                connection,
                cluster=cluster,
                object_id=object_id,
                yaml=result.document,
                base_version=state.base_version,
                base_hash=state.commit,
                updated_by=session.username,
                base_document=carried_base(state, replaces or key, work.draft, work.saved),
                replaces=replaces,
                expected_revision=draft_revision if object_id == key else None,
            )
        detail: dict[str, Any] = {
            "object": object_id,
            "revision": saved.revision,
            "stage": saved.stage,
        }
        if object_id != key:
            detail["renamed_from"] = key
        db.record_audit_event(
            connection,
            actor=session.username,
            action="save_draft" if form.action == "draft" else "save_change",
            cluster=cluster,
            request_id=uuid4(),
            detail=detail,
        )
        connection.commit()
    #
    # 303 rather than a rendered page, as everywhere else that writes: a
    # refresh of this response must not save a second time under a revision
    # that has since moved.
    #
    # A draft is unfinished work, so it goes back to the editor, under the
    # name it was saved as - a new object lands on the object it just created
    # rather than back on the empty form. A save is finished: back to the list,
    # as *Save and publish* went before B257, where the row says it is waiting.
    #
    #
    # Unless a server's name does not resolve from the manager (finding 72):
    # then back to the editor, which says so, rather than to a list that does
    # not - found before the deploy that a node would stop.
    #
    if form.action == "draft" or (
        result.document
        and form.fields().get("protocol") != "dns"
        and _unresolved_servers(object_id, result.document)
    ):
        return RedirectResponse(
            proxy_path(cluster, object_id, "edit") + "?saved=1", status_code=303
        )
    return RedirectResponse("/proxies", status_code=303)


def removal_bookkeeping(
    stored: Sequence[objects.ObjectView], published: Mapping[str, str | None]
) -> dict[str, dict[str, list[str]]]:
    """`removed_backends` for a publish that removes objects, or nothing (B250).

    A pool is named by itself, so once an object's document is gone the nodes'
    report of its backends says nothing about whose they were - and between the
    publish and the deploy the listing has to say the nodes still serve it.
    Written down here, from the objects helper's own account, as the interface's
    bookkeeping beside `draft`: checked by `operations.prepare` and never passed
    to the helper.
    """

    views = {view.name: view for view in stored}
    written = {
        name: list(view.runtime_backends)
        for name, document in published.items()
        if document is None
        and (view := views.get(name)) is not None
        and view.runtime_backends is not None
    }
    return {"removed_backends": written} if written else {}


def removal_submit(
    request: Request, config: Config, cluster: str, name: str, csrf_token: str
) -> Response:
    """Save the removal of one object, for the next publish (B257).

    A removal is a saved change like any other: the object leaves the
    repository with the publish that carries it, and the configuration
    generated from it leaves with it. `deleted` is what the row says: not
    that somebody abandoned an edit, but that they decided the object should
    go.
    """

    session = current_session(request)
    if session is None:
        return RedirectResponse("/login", status_code=303)
    if not config.management_writes:
        return PlainTextResponse("Not found", status_code=404)
    if session.role != "admin":
        return forbidden_page(request, config)
    token = request.cookies.get(auth.SESSION_COOKIE, "")
    if not token or not auth.csrf_token_is_valid(token, csrf_token):
        return refusal_page(
            request, config, "That form had expired. Open the page again.", back="/proxies"
        )

    state = editor_state(request, config, cluster)
    if state.commit is None:
        return refusal_page(
            request,
            config,
            "The stored proxies have not been read yet, so there is no base to remove from.",
            back="/proxies",
        )
    stored = next((view for view in state.stored if view.name == name), None)
    if stored is None:
        return refusal_page(
            request, config, "This cluster has no proxy of that name to remove.", back="/proxies"
        )

    with request.app.state.pool.connection() as connection:
        existing = settled_work(connection, cluster, name, state_reading(state))
        #
        # A removal is finished work, so it is a saved change (B257). A
        # draft over the object goes with it, as the removal replaced the
        # draft before there were two: there is nothing left to finish.
        #
        saved = db.save_change(
            connection,
            cluster=cluster,
            object_id=name,
            #
            # The stored document, kept as the draft's text. The publish
            # sends `null` and never this - it is here so the row says what
            # is being removed rather than being empty, and so a removal
            # that is refused leaves the object's own text to look at.
            #
            yaml=stored.document,
            base_version=state.base_version,
            base_hash=state.commit,
            updated_by=session.username,
            base_document=stored.document,
            deleted=True,
            saved_revision=existing.saved.revision if existing.saved else None,
            draft_revision=existing.draft.revision if existing.draft else None,
        )
        db.record_audit_event(
            connection,
            actor=session.username,
            action="save_change",
            cluster=cluster,
            request_id=uuid4(),
            detail={"object": name, "revision": saved.revision, "removed": True},
        )
        connection.commit()
    #
    # Saved, not published (B257): the removal goes out with the next publish,
    # and the listing says so on the object's row until then. Back to the list,
    # as every finished save is.
    #
    return RedirectResponse("/proxies", status_code=303)


def advanced_submit(
    request: Request,
    config: Config,
    cluster: str,
    name: str,
    *,
    action: str,
    text: str,
    handwritten: bool,
    expected_revision: str,
    csrf_token: str,
    object_fingerprint: str = "",
) -> Response:
    """Check the dialog's text, or save it into the object's draft (Fas 17, B223, B225).

    The draft is the editor's draft: the same row, the same revision check and
    the same refusal of a document that is not an object. What is saved is the
    draft's document - or the stored one when there is no draft - with only the
    text and the pool choice changed.
    """

    session = current_session(request)
    if session is None:
        return RedirectResponse("/login", status_code=303)
    if not config.management_writes or not features.is_on(features.ADVANCED_CONFIG):
        return PlainTextResponse("Not found", status_code=404)
    token = request.cookies.get(auth.SESSION_COOKIE, "")
    if not auth.csrf_token_is_valid(token, csrf_token):
        return forbidden_page(request, config)
    if session.role != "admin":
        return forbidden_page(request, config)
    #
    # Check and save; publishing is Versions' (B257).
    #
    if action not in ("check", "save") or not proxy_model.NAME.fullmatch(name):
        return PlainTextResponse("Unknown action", status_code=400)

    def answer(result: advanced_dialog.Answer, *, saved: str = "") -> Response:
        return TEMPLATES.TemplateResponse(
            request,
            "_advanced-answer.html",
            {"answer": result, "saved": saved},
        )

    if len(text) > advanced_dialog.MAX_TEXT:
        return answer(
            advanced_dialog.Answer(
                problem=f"The text is {len(text):,} characters; it may be at most "
                f"{advanced_dialog.MAX_TEXT:,}. Nothing was saved."
            )
        )

    state = editor_state(request, config, cluster)
    stored = next((view for view in state.stored if view.name == name), None)
    with request.app.state.pool.connection() as connection:
        work = settled_work(connection, cluster, name, state_reading(state))
    #
    # The dialog saves finished work (B257), so it starts from the saved change
    # or the stored object - never from a draft somebody has not finished,
    # which would go out with the next publish half-done.
    #
    if work.draft is not None:
        return answer(
            advanced_dialog.Answer(
                problem=f"{name} has a draft. Save or discard it in the editor first."
            )
        )
    draft = work.saved
    if draft is not None and draft.deleted:
        return answer(advanced_dialog.Answer(problem="The saved changes remove this proxy."))
    base = draft.yaml if draft is not None else (stored.document if stored is not None else "")
    if not base or state.commit is None:
        return answer(advanced_dialog.Answer(problem="The stored proxies have not been read yet."))
    try:
        document = advanced_dialog.apply(name, base, text, handwritten=handwritten)
    except (ValueError, ModelError) as exc:
        return answer(advanced_dialog.Answer(problem=str(exc)))
    result = advanced_dialog.check(name, document)
    if action == "check":
        return answer(result)
    if result.problem:
        return answer(result)
    #
    # The object the page showed, as the editor checks it (CR-01).
    #
    if object_fingerprint != editor_module.fingerprint(stored.document if stored else None):
        return answer(
            replace(
                result,
                problem=f"{name} was changed by a publish after this page was opened, so "
                "nothing was saved. Reload the page to see it as it is now.",
            )
        )
    #
    # Saving what is already there is nothing.
    #
    if editor_module.unchanged(document, base):
        return answer(replace(result, problem="Nothing changed."))

    revision = int(expected_revision) if is_digits(expected_revision) else None
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
                saved_revision=revision,
                draft_revision=None,
            )
        except db.DraftConflict as conflict:
            connection.rollback()
            return answer(
                replace(
                    result, problem=f"{conflict}. Reload the page to see the draft as it is now."
                )
            )
        db.record_audit_event(
            connection,
            actor=session.username,
            action="save_change",
            cluster=cluster,
            request_id=uuid4(),
            detail={"object": name, "revision": saved.revision, "advanced": True},
        )
        connection.commit()
    return answer(result, saved=proxy_path(cluster, name) + "?saved=1")
