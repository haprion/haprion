"""The certificate cleanup page: what was picked, what will happen, what is refused here.

The helper decides most of it (B139): whether a committed object still names
a certificate, whether it is a cluster's default or last one, and what the
four layers are. Two things are this side's to know, because they live in
the interface's database and nowhere the helper can see: which certificates
were ticked, and which of those a **draft** still names. A draft is a change
somebody has not published yet; deleting the certificate it names would make
that publish fail on a file that used to exist, so the page refuses such a
certificate before the job is queued and the worker refuses it once more at
run time in case a draft arrived in between.

The page shows every chosen certificate on its own row with what deleting it
means, and queues only the ones nothing here refuses. What the helper then
refuses arrives on the job's rows.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass

from haproxy_mgmt.config import CERTIFICATE_ID, ConfigError
from haproxy_mgmt.proxy_model import ModelError, load_proxy

from haproxy_ui.certificates import RegistryCertificateView
from haproxy_ui.db import ProxyDraft
from haproxy_ui.operations import MAX_DELETE_BATCH


def draft_references(
    drafts: Iterable[ProxyDraft], certificate_ids: Sequence[str]
) -> dict[str, tuple[str, ...]]:
    """Which of `certificate_ids` a live draft names, as ID -> `cluster/object` rows.

    Read with the engine's own `load_proxy`, never a second parser: a draft
    that does not parse could not be published either, so it names nothing a
    publish would then miss, and it is left out rather than guessed at.
    """

    wanted = set(certificate_ids)
    found: dict[str, list[str]] = {}
    for draft in drafts:
        try:
            proxy = load_proxy(draft.object_id, draft.yaml.encode("utf-8"))
        except (ModelError, ConfigError):
            continue
        certificate = proxy.listen.certificate
        if certificate in wanted:
            found.setdefault(certificate, []).append(f"{draft.cluster}/{draft.object_id}")
    return {key: tuple(sorted(rows)) for key, rows in found.items()}


class SelectionProblem(Exception):
    """The selection as a whole cannot become a job; the page says why."""


@dataclass(frozen=True, slots=True)
class DeletionRow:
    """One chosen certificate as the confirmation page draws it."""

    identifier: str
    source_label: str
    targets: tuple[str, ...]
    """Where it is published, `name (cluster)` / `name (receiver)`, for the reader."""

    lineage_note: str
    refusal: str | None = None
    """Why this side will not queue it. None means it goes into the job."""

    @property
    def deletable(self) -> bool:
        return self.refusal is None


@dataclass(frozen=True, slots=True)
class Selection:
    rows: tuple[DeletionRow, ...]

    @property
    def deletable(self) -> tuple[str, ...]:
        return tuple(row.identifier for row in self.rows if row.deletable)

    @property
    def refused(self) -> tuple[DeletionRow, ...]:
        return tuple(row for row in self.rows if not row.deletable)


def selection(
    chosen: Sequence[str],
    registry: Mapping[str, RegistryCertificateView],
    drafts: Iterable[ProxyDraft],
) -> Selection:
    """The rows for the confirmation page, in the order the registry lists them."""

    ids = tuple(dict.fromkeys(item.strip() for item in chosen if item.strip()))
    if not ids:
        raise SelectionProblem("Nothing is selected.")
    if any(not CERTIFICATE_ID.fullmatch(item) for item in ids):
        raise SelectionProblem("The selection contains something that is not a certificate ID.")
    if len(ids) > MAX_DELETE_BATCH:
        raise SelectionProblem(
            f"At most {MAX_DELETE_BATCH} certificates go in one job. Select fewer and run it twice."
        )
    referenced = draft_references(drafts, ids)
    rows: list[DeletionRow] = []
    ordered = [identifier for identifier in registry if identifier in ids]
    ordered += [identifier for identifier in ids if identifier not in registry]
    for identifier in ordered:
        view = registry.get(identifier)
        if view is None:
            rows.append(
                DeletionRow(
                    identifier, "—", (), "", refusal="Not in the registry; nothing to delete."
                )
            )
            continue
        refusal = None
        if identifier in referenced:
            refusal = "A draft still names it: " + ", ".join(referenced[identifier]) + "."
        #
        # `source_label` is the registry's `source.kind` as the page says it;
        # `lifecycle` is measured against certbot's archive and says
        # something else (a registered import that certbot happens to hold).
        #
        lineage = (
            "The Certbot lineage is deleted; it will not renew again."
            if view.source_label == "Certbot"
            else "The imported material under the manager's import store is removed."
        )
        rows.append(
            DeletionRow(
                identifier,
                view.source_label,
                tuple(f"{target.name} ({target.kind})" for target in view.targets),
                lineage,
                refusal=refusal,
            )
        )
    return Selection(tuple(rows))
