"""*Settings → Blocklists*: the form, the save, the removal and the card's rows (B496, 13; B500).

Shared by the web's pages and `haprion-blocklists`, so the two save a list
the same way. A list is checked with the engine's own `blocklists.definition`
- the rule the apply helper and the refresh timer hold it to - before
anything is stored. The password or token is sealed against the
installation's DNS profile key, bound to the list and its revision, and the
web cannot read it back: a save that leaves it empty keeps the stored one,
which is refused once the authorization changes. The row and its
`blocklist_apply` job are one transaction, as a DNS profile's are: a list
saved without its job would look defined and never be fetched.

A list is removed by the same job, and refused while an object of any cluster
still names it under *Denied*: the next refresh would take the list's file
from the clusters, and the generator would then refuse those objects at the
next deploy.
"""

from __future__ import annotations

import urllib.parse
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID, uuid4

from haprion import blocklist_store, blocklists
from haprion.dns_profile_keys import DnsProfilePublicKey

from haprion_ui import db, moments, network, objects, refusals
from haprion_ui import jobs as queue

OPERATION = "blocklist_apply"
SECRET_LABEL = {"basic": "Password", "bearer": "Token"}
AUTH_LABEL = {"none": "None", "basic": "Basic", "bearer": "Bearer"}
#
# How many characters of Except the form takes: the column holds 256 entries,
# and an entry is at most a network's text or a group's name.
#
EXCEPT_MAX = 256 * 50


class FormProblem(ValueError):
    """What is wrong with a submission, as one sentence the form shows, and its code.

    The code is what `haprion-blocklists` answers with: `bad_input` for the
    submission itself, `expected_target_changed` for a row that moved on,
    `operation_locked` for a busy queue and `in_use` for a list still named.
    """

    def __init__(self, message: str, *, code: str = "bad_input") -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class Form:
    """A list as the form holds it: text, as typed."""

    name: str = ""
    description: str = ""
    url: str = ""
    auth: str = "none"
    username: str = ""
    secret: str = field(default="", repr=False)
    every_hours: str = "24"
    excepts: str = ""

    @property
    def except_lines(self) -> tuple[str, ...]:
        return tuple(line.strip() for line in self.excepts.splitlines() if line.strip())


EMPTY = Form()


def from_row(row: db.Blocklist) -> Form:
    return Form(
        name=row.name,
        description=row.description,
        url=row.url,
        auth=row.auth,
        username=row.username,
        every_hours=str(row.every_hours),
        excepts="".join(f"{entry}\n" for entry in row.excepts),
    )


def from_posted(text: Mapping[str, str], existing: db.Blocklist | None) -> Form:
    """The submission as typed; an existing list keeps its name."""

    auth = text.get("auth", "none")
    return Form(
        name=existing.name if existing else text.get("name", "").strip()[:64],
        description=text.get("description", "").strip()[:400],
        url=text.get("url", "").strip()[:4096],
        auth=auth if auth in AUTH_LABEL else "none",
        username=text.get("username", "").strip()[:400] if auth == "basic" else "",
        secret=text.get("secret", "")[: blocklists.SECRET_MAX + 1] if auth != "none" else "",
        every_hours=text.get("every_hours", "")[:4],
        excepts=text.get("excepts", "")[:EXCEPT_MAX],
    )


def sentence(problem: Exception) -> str:
    text = str(problem).rstrip(".")
    return text[:1].upper() + text[1:] + "."


def checked(form: Form) -> blocklists.Definition:
    """The definition the helper will be sent, or `FormProblem`."""

    try:
        every = int(form.every_hours)
    except ValueError:
        raise FormProblem("Fetch every is 1, 6, 12 or 24 hours.") from None
    try:
        return blocklists.definition(
            name=form.name,
            url=form.url,
            every_hours=every,
            authorization=form.auth,
            username=form.username,
            description=form.description,
            excepts=form.except_lines,
        )
    except ValueError as problem:
        raise FormProblem(sentence(problem)) from None


def secret_choice(form: Form, existing: db.Blocklist | None) -> tuple[str, bool]:
    """The secret to seal, or that the stored one is kept: `(secret, keep)`."""

    if form.auth == "none":
        return "", False
    label = SECRET_LABEL[form.auth]
    if form.secret:
        if len(form.secret) > blocklists.SECRET_MAX or any(c in form.secret for c in "\r\n"):
            raise FormProblem(f"{label} is one line of at most {blocklists.SECRET_MAX} characters.")
        return form.secret, False
    if existing is not None and existing.auth == form.auth:
        return "", True
    raise FormProblem(f"{label} is needed for {AUTH_LABEL[form.auth]} authorization.")


def users(connection: Any, name: str) -> dict[str, tuple[str, ...]]:
    """The objects that name the list, per cluster, from the poller's object readings."""

    found: dict[str, tuple[str, ...]] = {}
    for reading in db.cluster_objects(connection):
        if reading.outcome != "done" or reading.poll_error:
            continue
        named = network.usage(objects.cluster_object_views(reading)).groups.get(name, ())
        if named:
            found[reading.cluster] = named
    return found


def in_use_sentence(name: str, used: Mapping[str, Sequence[str]]) -> str:
    where = "; ".join(f"{', '.join(names)} on {cluster}" for cluster, names in sorted(used.items()))
    return f"{name} is under Denied in {where}. Take it out there first, then remove it."


def _audit(
    connection: Any, job: db.Job, *, actor: str, name: str, revision: int, remove: bool, via: str
) -> None:
    detail: dict[str, Any] = {
        "operation": OPERATION,
        "job": job.id,
        "name": name,
        "revision": revision,
        "via": via,
    }
    if remove:
        detail["remove"] = True
    db.record_audit_event(
        connection,
        actor=actor,
        action="queue_job",
        cluster=None,
        request_id=job.request_id,
        detail=detail,
    )


def save(
    connection: Any,
    definition: blocklists.Definition,
    *,
    existing: db.Blocklist | None,
    secret: str,
    keep: bool,
    public_key: DnsProfilePublicKey,
    actor: str,
    key: UUID,
    via: str = "web",
) -> db.Job:
    """Store the list's next revision and queue its apply job, committed together.

    `FormProblem` when the name is taken, the row moved on since the form
    was drawn, or another certificate job holds the queue; nothing is kept then.
    """

    revision = existing.revision + 1 if existing else 1
    box = (
        blocklist_store.seal_secret(
            public_key, name=definition.name, revision=revision, secret=secret
        )
        if secret
        else None
    )
    try:
        stored = db.save_blocklist(
            connection,
            name=definition.name,
            previous=existing.revision if existing else None,
            description=definition.description,
            url=definition.url,
            auth=definition.authorization,
            username=definition.username,
            every_hours=definition.every_hours,
            excepts=definition.excepts,
            key_id=public_key.key_id if box is not None else None,
            ciphertext=box,
            keep_secret=keep,
            actor=actor,
        )
    except db.BlocklistChanged:
        connection.rollback()
        if existing is None:
            raise FormProblem(
                f"Name — a blocklist called {definition.name} already exists.",
                code="expected_target_changed",
            ) from None
        raise FormProblem(
            "The blocklist changed while this form was open. Reload and try again.",
            code="expected_target_changed",
        ) from None
    try:
        job = db.queue_job(
            connection,
            operation=OPERATION,
            cluster=None,
            payload={"name": stored.name, "revision": stored.revision},
            idempotency_key=key,
        )
    except db.CertificateBusy as busy:
        connection.rollback()
        raise FormProblem(refusals.conflict_sentence(busy), code="operation_locked") from None
    _audit(
        connection,
        job,
        actor=actor,
        name=stored.name,
        revision=stored.revision,
        remove=False,
        via=via,
    )
    connection.commit()
    return job


def apply_again(connection: Any, existing: db.Blocklist, *, actor: str, via: str) -> db.Job:
    """Queue the stored revision's apply again: one whose last apply did not finish."""

    try:
        job = db.queue_job(
            connection,
            operation=OPERATION,
            cluster=None,
            payload={"name": existing.name, "revision": existing.revision},
            idempotency_key=uuid4(),
        )
    except db.CertificateBusy as busy:
        connection.rollback()
        raise FormProblem(refusals.conflict_sentence(busy), code="operation_locked") from None
    _audit(
        connection,
        job,
        actor=actor,
        name=existing.name,
        revision=existing.revision,
        remove=False,
        via=via,
    )
    connection.commit()
    return job


def remove(
    connection: Any, existing: db.Blocklist, *, actor: str, key: UUID, via: str = "web"
) -> db.Job:
    """Queue the list's removal, or `FormProblem` while an object names it."""

    used = users(connection, existing.name)
    if used:
        raise FormProblem(in_use_sentence(existing.name, used), code="in_use")
    try:
        job = db.queue_job(
            connection,
            operation=OPERATION,
            cluster=None,
            payload={"name": existing.name, "revision": existing.revision, "remove": True},
            idempotency_key=key,
        )
    except db.CertificateBusy as busy:
        connection.rollback()
        raise FormProblem(refusals.conflict_sentence(busy), code="operation_locked") from None
    _audit(
        connection,
        job,
        actor=actor,
        name=existing.name,
        revision=existing.revision,
        remove=True,
        via=via,
    )
    connection.commit()
    return job


# - the card ----------------------------------------------------------------


@dataclass(frozen=True)
class Row:
    """One list on *Settings → Blocklists*."""

    name: str
    href: str
    source: str
    every: str
    addresses: str
    fetched: str
    fetched_tone: str
    """`""`, `muted` or `warning`."""
    fetched_title: str
    status: str
    """What a job is doing with the list, or that its last apply failed; `""` otherwise."""
    status_tone: str
    job_href: str


def _figure(count: int) -> str:
    return f"{count:,}".replace(",", " ")


def _host(url: str) -> str:
    return urllib.parse.urlsplit(url).hostname or url


def _fetched(state: db.BlocklistState | None) -> tuple[str, str, str]:
    if state is None or state.attempted_at is None:
        return "Not fetched yet", "muted", ""
    failing = state.failed_at is not None and state.failed_at == state.attempted_at
    if not failing:
        return moments.moment(state.fetched_at or state.attempted_at), "", ""
    title = f"Failed {moments.moment(state.failed_at)}: {state.error}" if state.failed_at else ""
    if state.fetched_at is None:
        return "Failed · never fetched", "warning", title
    return f"Failed · kept {moments.moment(state.fetched_at)}", "warning", title


def _status(row: db.Blocklist, job: db.Job | None, *, writes: bool) -> tuple[str, str, str]:
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
    lists: Iterable[db.Blocklist],
    states: Iterable[db.BlocklistState],
    latest: Mapping[str, db.Job],
    *,
    writes: bool,
) -> list[Row]:
    """The card's rows, by name; `latest` is each list's newest apply job."""

    by_name = {state.name: state for state in states}
    found: list[Row] = []
    for item in sorted(lists, key=lambda entry: entry.name):
        state = by_name.get(item.name)
        if state is None or state.fetched_at is None:
            addresses = ""
        else:
            addresses = _figure(state.entries)
            if item.excepts:
                addresses += f" · {len(item.excepts)} excepted"
        fetched, tone, title = _fetched(state)
        status, status_tone, job_href = _status(item, latest.get(item.name), writes=writes)
        found.append(
            Row(
                name=item.name,
                href=f"/settings/blocklists/{item.name}/edit",
                source=_host(item.url),
                every=f"{item.every_hours} h",
                addresses=addresses,
                fetched=fetched,
                fetched_tone=tone,
                fetched_title=title,
                status=status,
                status_tone=status_tone,
                job_href=job_href,
            )
        )
    return found
