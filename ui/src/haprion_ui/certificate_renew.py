"""*Renew…* on the certificate list: one row, and the way its certificate is made again (C9c).

Three sources, three renewals, one button. The registry's word for where the
material comes from decides the page behind the button:

- **certbot** — the whole round again now: the same `certbot renew` the daily
  timer runs, forced before its time, through the same helper the form's
  *New certificate* uses. Let's Encrypt allows five identical certificates a
  week, and the page says so.
- **NDES** — enrolled again from the same profile with the same names and
  the same targets, as the scheduled renewal does it.
- **imported** — a file: the certificate the CA renewed on the key the
  manager holds, or a new pair. The row's upload route takes it; this page
  is its home, since 2026-09-21 the only one - the file field that sat in
  the row's detail was never found there.
- **a signing request waiting** — the same file field, worded for what the
  row waits for: the certificate the CA signed for the downloaded request.

Exactly one row. A renewal is a question about one certificate's source,
and a selection of several has no single answer to draw.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal

from haprion_ui.certificates import RegistryCertificateView

Way = Literal["certbot", "ndes", "upload", "signed"]


class SelectionProblem(Exception):
    """The selection is not one this page can draw; the sentence says why."""


@dataclass(frozen=True, slots=True)
class Renewal:
    row: RegistryCertificateView
    way: Way

    @property
    def identifier(self) -> str:
        return self.row.identifier

    @property
    def title(self) -> str:
        if self.way == "signed":
            return f"Install the signed certificate for {self.identifier}"
        return f"Renew {self.identifier}"


def selection(chosen: Sequence[str], registry: Mapping[str, RegistryCertificateView]) -> Renewal:
    """The one row and its way, or the sentence for why not."""

    names = tuple(dict.fromkeys(name for name in chosen if name))
    if not names:
        raise SelectionProblem("Select one certificate to renew.")
    if len(names) > 1:
        raise SelectionProblem(
            "Renew one certificate at a time: each is renewed the way its source is made."
        )
    row = registry.get(names[0])
    if row is None or row.placeholder:
        raise SelectionProblem(f"{names[0]} is not in the registry.")
    if row.state_active:
        raise SelectionProblem(f"{row.identifier} has a job running; wait for its row to settle.")
    if row.csr_pending:
        return Renewal(row, "signed")
    if row.source_kind == "acme":
        return Renewal(row, "certbot")
    if row.source_kind == "import":
        if row.ndes_profile:
            if row.state_label in {"Request pending", "Renewal pending"}:
                raise SelectionProblem(
                    f"{row.identifier} has an enrollment the CA is still holding; "
                    "resume it from its row instead of asking again."
                )
            return Renewal(row, "ndes")
        return Renewal(row, "upload")
    raise SelectionProblem(f"{row.identifier} comes from a source this page cannot renew.")


def payload(renewal: Renewal) -> tuple[str, dict[str, Any]]:
    """The job a confirmation queues for a certbot or NDES row; nothing for a file."""

    row = renewal.row
    if renewal.way == "certbot":
        return "cert_issue", {"domain": row.identifier, "renew": True}
    if renewal.way == "ndes":
        common = (
            row.common_name if row.common_name and not row.common_name.startswith("*.") else None
        )
        names = [common] if common else []
        names += [name for name in row.sans if name not in names]
        if not names or names[0].startswith("*."):
            #
            # The CN cannot be a wildcard; the base name it covers is the
            # one the enrollment names first, as the form does it.
            #
            base = next((name for name in names if not name.startswith("*.")), None)
            if base is None:
                raise SelectionProblem(f"{row.identifier} carries no name an enrollment can use.")
            names = [base, *[name for name in names if name != base]]
        body: dict[str, Any] = {
            "id": row.identifier,
            "profile": row.ndes_profile,
            "domains": names,
            "clusters": [t.name for t in row.targets if t.kind == "cluster"],
            "receivers": [t.name for t in row.targets if t.kind == "receiver"],
        }
        if row.interface:
            # The interface's own certificate (B188): no targets, the mark kept.
            body["interface"] = True
        return "cert_scep", body
    raise SelectionProblem("This certificate is renewed with a file, not a job.")


def waiting_selection(
    chosen: Sequence[str], registry: Mapping[str, RegistryCertificateView]
) -> RegistryCertificateView:
    """The one row whose NDES request the CA still holds, for *Abandon request…* (B388)."""

    names = tuple(dict.fromkeys(name for name in chosen if name))
    if len(names) != 1:
        raise SelectionProblem("Select the one certificate whose request to abandon.")
    row = registry.get(names[0])
    if (
        row is None
        or row.placeholder
        or not row.ndes_profile
        or row.state_label not in {"Request pending", "Renewal pending"}
    ):
        raise SelectionProblem(f"{names[0]} has no request waiting at the CA.")
    if row.state_active:
        raise SelectionProblem(f"{row.identifier} has a job running; wait for its row to settle.")
    return row
