"""*Settings → Path lists*: one list's form, its save and removal, and *Add to proxies* (B527, B532).

A path list is a set of paths only scanners ask for, named under an object's
*Denied paths — lists*. Saving stores the next revision and queues the
`path_list_apply` job, which has the root helper write the list where every
publish reads it; a cluster whose version carries another copy then says so in
*Needs attention*. A list an object, a saved change or a draft still names
cannot be removed. `haprion-path-lists` shares these, so the command and the
page refuse the same things.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from haprion import path_lists
from haprion.config import ConfigError
from haprion.proxy_model import MAX_DENIED_PATH, MAX_DENIED_PATHS, dump_document, read_document

from haprion_ui import db, list_sync, objects, refusals
from haprion_ui import jobs as queue
from haprion_ui.blocklist_form import unread_sentence

OPERATION = path_lists.OPERATION
CARD = "/settings#path-lists"
#
# The objects with a path to refuse on: http and https. A raw connection has
# none (`proxy_model`).
#
DENIED_PROTOCOLS = ("http", "https")
PATHS_MAX = MAX_DENIED_PATHS * (MAX_DENIED_PATH + 2)


class FormProblem(ValueError):
    """What is wrong with a submission, as one sentence the form shows, and its code.

    The codes are `haprion-path-lists`' own: `bad_input` for the submission,
    `expected_target_changed` for a row that moved on, `operation_locked` for a
    busy queue and `in_use` for a list still named.
    """

    def __init__(self, message: str, *, code: str = "bad_input") -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class Form:
    """A list as the form holds it: text, as typed."""

    name: str = ""
    description: str = ""
    paths: str = ""


EMPTY = Form()
FULL = f"Settings keeps at most {path_lists.MAX_LISTS} path lists. Remove one first."


def from_row(row: db.PathList) -> Form:
    return Form(
        name=row.name,
        description=row.description,
        paths="".join(f"{path}\n" for path in row.paths),
    )


def from_posted(text: Mapping[str, str], existing: db.PathList | None) -> Form:
    """The submission as typed; an existing list keeps its name."""

    return Form(
        name=existing.name if existing else text.get("name", "").strip()[:64],
        description=text.get("description", "").strip()[:400],
        paths=text.get("paths", ""),
    )


def checked(form: Form) -> path_lists.PathList:
    """The list the engine would read, or the field and what is wrong with it.

    Built by `path_lists.path_list`, as the apply job builds it, so a list the
    form accepts is one the job does not refuse (review 26-11-24, PW03).
    """

    try:
        path_lists.checked_name(form.name)
    except path_lists.PathListError as exc:
        raise FormProblem(f"Name — {exc}.") from None
    try:
        path_lists.checked_description(form.description)
    except path_lists.PathListError as exc:
        raise FormProblem(f"Description — {exc}.") from None
    #
    # Text over the limit is refused, not cut: a cut last path is a shorter one,
    # a wider prefix than was written (review 26-11-24, PW09).
    #
    if len(form.paths) > PATHS_MAX:
        raise FormProblem(
            f"Paths — at most {MAX_DENIED_PATHS} paths of {MAX_DENIED_PATH} characters."
        )
    written = path_lists.lines(form.paths)
    if not written:
        raise FormProblem("Paths — write at least one path, one to a line.")
    try:
        paths = path_lists.checked_paths(written, "a path")
    except path_lists.PathListError as exc:
        raise FormProblem(f"Paths — {_readable(str(exc))}.") from None
    try:
        return path_lists.path_list(form.name, list(paths), form.description)
    except path_lists.PathListError as exc:  # pragma: no cover - each part was checked above
        raise FormProblem(str(exc)) from None


def _readable(said: str) -> str:
    """The engine's words for one path, the line counted from 1 as the field shows it."""

    return re.sub(r"a path\[(\d+)\]", lambda found: f"line {int(found.group(1)) + 1}", said)


def usage(connection: Any) -> dict[str, dict[str, tuple[str, ...]]]:
    """Every list's users per cluster, in one reading: published, saved changes and drafts."""

    found: dict[str, dict[str, set[str]]] = {}

    def note(cluster: str, name: str, document: str) -> None:
        for listed in named_lists(name, document):
            found.setdefault(listed, {}).setdefault(cluster, set()).add(name)

    readings = db.cluster_objects(connection)
    for reading in readings:
        if objects.was_read(reading):
            for view in objects.cluster_object_views(reading):
                note(reading.cluster, view.name, view.document)
    for draft in db.live_drafts(connection, sorted({r.cluster for r in readings})):
        note(draft.cluster, draft.object_id, draft.yaml)
    return {
        listed: {cluster: tuple(sorted(names)) for cluster, names in clusters.items()}
        for listed, clusters in found.items()
    }


def users(connection: Any, name: str) -> dict[str, tuple[str, ...]]:
    """The objects that name the list, per cluster: published, saved changes and drafts."""

    return usage(connection).get(name, {})


def named_lists(name: str, document: str) -> tuple[str, ...]:
    """The lists a stored document names under *Denied paths*; none where it cannot be read."""

    try:
        data = read_document(name, document.encode())
    except ConfigError:
        return ()
    denied = data.get("deny_paths")
    lists = denied.get("lists") if isinstance(denied, dict) else None
    return tuple(str(item) for item in lists) if isinstance(lists, list) else ()


def in_use_sentence(name: str, used: Mapping[str, Sequence[str]]) -> str:
    where = "; ".join(f"{', '.join(names)} on {cluster}" for cluster, names in sorted(used.items()))
    return f"{name} is under Denied paths in {where}. Take it out there first, then remove it."


def _queue(connection: Any, *, payload: dict[str, Any], key: UUID, actor: str, via: str) -> db.Job:
    try:
        job = db.queue_job(
            connection, operation=OPERATION, cluster=None, payload=payload, idempotency_key=key
        )
    except db.CertificateBusy as busy:
        connection.rollback()
        raise FormProblem(refusals.conflict_sentence(busy), code="operation_locked") from None
    db.record_audit_event(
        connection,
        actor=actor,
        action="queue_job",
        cluster=None,
        request_id=job.request_id,
        detail={"operation": OPERATION, "job": job.id, "via": via, **payload},
    )
    connection.commit()
    return job


def save(
    connection: Any,
    item: path_lists.PathList,
    *,
    existing: db.PathList | None,
    actor: str,
    key: UUID,
    via: str = "web",
) -> db.Job:
    """Store the list's next revision and queue its apply job, committed together."""

    try:
        stored = db.save_path_list(
            connection,
            name=item.name,
            previous=existing.revision if existing else None,
            description=item.description,
            paths=item.paths,
            actor=actor,
        )
    except db.PathListsFull:
        connection.rollback()
        raise FormProblem(FULL) from None
    except db.PathListChanged:
        connection.rollback()
        if existing is None:
            raise FormProblem(
                f"Name — a path list called {item.name} already exists.",
                code="expected_target_changed",
            ) from None
        raise FormProblem(
            "The path list changed while this form was open. Reload and try again.",
            code="expected_target_changed",
        ) from None
    return _queue(
        connection,
        payload={"name": stored.name, "revision": stored.revision},
        key=key,
        actor=actor,
        via=via,
    )


def apply_again(connection: Any, existing: db.PathList, *, actor: str, via: str) -> db.Job:
    """Queue the stored revision's apply again: one whose last apply did not finish."""

    return _queue(
        connection,
        payload={"name": existing.name, "revision": existing.revision},
        key=uuid4(),
        actor=actor,
        via=via,
    )


def remove(
    connection: Any, existing: db.PathList, *, actor: str, key: UUID, via: str = "web"
) -> db.Job:
    """Queue the list's removal, or `FormProblem` while an object names it."""

    used = users(connection, existing.name)
    if used:
        raise FormProblem(in_use_sentence(existing.name, used), code="in_use")
    if unread := unread_sentence(connection):
        raise FormProblem(unread, code="in_use")
    return _queue(
        connection,
        payload={"name": existing.name, "revision": existing.revision, "remove": True},
        key=key,
        actor=actor,
        via=via,
    )


def take_in(connection: Any, entry: db.ListFile, *, actor: str, via: str = "web") -> db.PathList:
    """Make the row a file without one says: its description, paths and revision (review 26-11-24, PW02).

    The file is what publishes read, so the row is made to match it and no job
    is queued: nothing has to be written. Objects may already name the list.
    """

    if entry.paths is None:
        raise FormProblem("The list is gone from the manager.", code="expected_target_changed")
    try:
        item = path_lists.path_list(
            entry.name, list(entry.paths), entry.description or "", entry.revision
        )
    except path_lists.PathListError as exc:
        raise FormProblem(str(exc)) from None
    try:
        row = db.take_in_path_list(
            connection,
            name=item.name,
            description=item.description,
            paths=item.paths,
            revision=item.revision,
            actor=actor,
        )
    except db.PathListsFull:
        connection.rollback()
        raise FormProblem(FULL) from None
    except db.PathListChanged:
        connection.rollback()
        raise FormProblem(
            f"A path list called {item.name} already exists.", code="expected_target_changed"
        ) from None
    db.record_audit_event(
        connection,
        actor=actor,
        action="path_list_take_in",
        cluster=None,
        request_id=uuid4(),
        detail={"name": row.name, "revision": row.revision, "via": via},
    )
    connection.commit()
    return row


# - Add to proxies -----------------------------------------------------------


def with_list(list_name: str, name: str, document: str) -> str:
    """The object's document with the list under *Denied paths*; unchanged where it is, or cannot be.

    A new *Denied paths* starts by only looking (B527, as B227 for any new
    refusal): the list is added in `log` mode, so what it would refuse shows
    on the traffic page before it refuses anything.
    """

    data: dict[str, Any] = dict(read_document(name, document.encode()))
    listen = data.get("listen")
    protocol = listen.get("protocol") if isinstance(listen, dict) else None
    if protocol not in DENIED_PROTOCOLS:
        return document
    denied = data.get("deny_paths")
    if not isinstance(denied, dict):
        data["deny_paths"] = {"mode": "log", "lists": [list_name]}
        return dump_document(data)
    lists = list(denied.get("lists") or [])
    if list_name in lists:
        return document
    data["deny_paths"] = {**denied, "lists": [*lists, list_name]}
    return dump_document(data)


@dataclass(frozen=True)
class Reach:
    """One cluster on *Add to proxies*: the proxies a list can stand in, and how many name it."""

    cluster: str
    proxies: int
    named: int


def reach(connection: Any, name: str) -> dict[str, Reach]:
    """Each cluster read, with its http and https proxies and those already naming the list."""

    named = users(connection, name)
    found: dict[str, Reach] = {}
    for reading in db.cluster_objects(connection):
        if not objects.was_read(reading):
            continue
        proxies = {
            view.name
            for view in objects.cluster_object_views(reading)
            if view.protocol in DENIED_PROTOCOLS
        }
        found[reading.cluster] = Reach(
            reading.cluster, len(proxies), len(proxies & set(named.get(reading.cluster, ())))
        )
    return found


@dataclass(frozen=True)
class Added:
    """What *Add to proxies* did in one chosen cluster."""

    cluster: str
    added: tuple[str, ...]
    already: tuple[str, ...]
    skipped: tuple[tuple[str, str], ...]


# - the card ----------------------------------------------------------------

NOT_APPLIED = "Not applied"
ONLY_ON_THE_MANAGER = "Only on the manager"
KIND = "path_list"
"""What `list_file` calls a path list file."""


@dataclass(frozen=True)
class Row:
    """One list on *Settings → Path lists*."""

    name: str
    href: str
    """Where the row's own page is; `""` for a list only the manager's file has."""
    paths: str
    used_by: str
    status: str
    status_tone: str
    job_href: str
    button: str = ""
    """`apply_again` for a row the file does not match, `take_in` for a file without a row."""
    stored: bool = True
    """Whether the database has the row: false for a list only the manager's file has."""
    revision: int = 0
    proxies: int = 0
    count: int | None = None
    """How many paths the list holds; None for a file that could not be read."""


def _status(row: db.PathList, job: db.Job | None, *, writes: bool) -> tuple[str, str, str]:
    if job is None:
        return "", "", ""
    removing = job.payload.get("remove") is True
    if job.state in {"pending", "running"}:
        busy = queue.busy_with(job, writes=writes)
        if not busy.working:
            return busy.label, busy.tone, f"/jobs/{job.id}"
        return ("Removing" if removing else "Applying"), "info", f"/jobs/{job.id}"
    if job.state != "done" and (removing or job.payload.get("revision") == row.revision):
        return ("Remove failed" if removing else "Apply failed"), "critical", f"/jobs/{job.id}"
    return "", "", ""


def rows(
    lists: Iterable[db.PathList],
    used: Mapping[str, Mapping[str, Sequence[str]]],
    latest: Mapping[str, db.Job],
    files: Mapping[str, db.ListFile] | None = None,
    *,
    writes: bool,
    read_at: datetime | None = None,
) -> list[Row]:
    """The card's rows, by name; `used` is `users` per list, `latest` each list's newest job.

    `files` is what the poller last read of root's files. A row they do not
    match is *Not applied*; a file without a row is *Only on the manager*
    (review 26-11-24, PW02). The two actions are the row's own buttons. `read_at`
    is when the poller last made the reading; before it has, nothing is said.
    """

    found: list[tuple[str, Row]] = []
    lists = list(lists)
    known = {item.name for item in lists}
    files = files or {}
    for item in lists:
        proxies = sum(len(names) for names in used.get(item.name, {}).values())
        job = latest.get(item.name)
        status, tone, job_href = _status(item, job, writes=writes)
        button = ""
        if (
            read_at is not None
            and not status
            and not list_sync.in_step(
                revision=item.revision,
                digest=path_lists.content_digest(item.description, item.paths),
                file=files.get(item.name),
                job=job,
                read_at=read_at,
            )
        ):
            status, tone, job_href = NOT_APPLIED, "warning", ""
        if writes and status in {NOT_APPLIED, "Apply failed"}:
            button = "apply_again"
        found.append(
            (
                item.name,
                Row(
                    name=item.name,
                    href=f"/settings/path-lists/{item.name}/edit",
                    paths=str(len(item.paths)),
                    used_by=(
                        "" if proxies == 0 else f"{proxies} prox{'y' if proxies == 1 else 'ies'}"
                    ),
                    status=status,
                    status_tone=tone,
                    job_href=job_href,
                    button=button,
                    revision=item.revision,
                    proxies=proxies,
                    count=len(item.paths),
                ),
            )
        )
    for name, entry in (files or {}).items():
        if name in known:
            continue
        proxies = sum(len(names) for names in used.get(name, {}).values())
        found.append(
            (
                name,
                Row(
                    name=name,
                    href="",
                    paths=str(len(entry.paths)) if entry.paths else "",
                    used_by=(
                        "" if proxies == 0 else f"{proxies} prox{'y' if proxies == 1 else 'ies'}"
                    ),
                    status=ONLY_ON_THE_MANAGER,
                    status_tone="warning",
                    job_href="",
                    button="take_in" if writes and entry.paths else "",
                    stored=False,
                    revision=entry.revision,
                    proxies=proxies,
                    count=len(entry.paths) if entry.paths else None,
                ),
            )
        )
    return [row for _name, row in sorted(found, key=lambda pair: pair[0])]
