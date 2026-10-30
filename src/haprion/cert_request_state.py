"""Where a signing request made here waits, and whether it is still waiting (C9b).

Its own module for the reason `ndes_state` is: the certificate listing and
the import both need to read a waiting request, and neither may import the
engine that makes one - the engine imports the inventory, which is the
listing.

A request lives in the import store under its certificate ID, beside the key
it was made for: `privkey.pem`, `request.csr`, `request.json` (the names and
the key type) and `targets.json` (where the certificate goes once signed).
No `fullchain.pem` - that is what the signature brings, and `write_store`
renames the imported material over the directory, taking these files away.
So a request beside a key, without material, is exactly a request waiting to
be signed.
"""

from __future__ import annotations

import json
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from haprion.config import CERTIFICATE_ID, CLUSTER_ID, RECEIVER_FORMATS, RECEIVER_ID
from haprion.ndes_state import request_is_pending

CSR = "request.csr"
RECORD = "request.json"
TARGETS = "targets.json"
#
# The file the signature brings; the same name `cert_inventory.FULLCHAIN`
# has, spelled here because this module must not import that one.
#
MATERIAL = "fullchain.pem"
MAX_RECORD_BYTES = 64 * 1024
#
# What `openssl genpkey` is told, by the name the form and the request use.
# EC P-256 first and default: the smallest handshake and the one every
# client this decade accepts. RSA for the CA that still requires it.
#
KEY_TYPES: Mapping[str, tuple[str, ...]] = {
    "ec-p256": ("-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"),
    "rsa-2048": ("-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"),
    "rsa-4096": ("-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:4096"),
}
DEFAULT_KEY_TYPE = "ec-p256"


@dataclass(frozen=True, slots=True)
class PendingCsr:
    """One request waiting for a signature, as the listing shows it."""

    certificate_id: str
    domains: tuple[str, ...]
    key_type: str
    requested_at: str
    csr_pem: str
    clusters: tuple[str, ...]
    receivers: tuple[str, ...]
    formats: Mapping[str, str]

    def as_row_fields(self) -> dict[str, Any]:
        """The additive `request` field of a listing row (schema v1, C9b)."""

        return {
            "kind": "csr",
            "domains": list(self.domains),
            "key_type": self.key_type,
            "requested_at": self.requested_at,
            "csr_pem": self.csr_pem,
        }


def _bounded_json(path: Path, maximum: int) -> Any:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError):
        return None


def _ids(value: Any, pattern: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(
        dict.fromkeys(item for item in value if isinstance(item, str) and pattern.fullmatch(item))
    )


def csr_is_pending(store: Path, certificate_id: str) -> bool:
    """A key and a request under this ID, and no certificate yet.

    The directory outlives the signature by nothing: `write_store` renames
    the imported material over it. So a request beside a key, without a
    `fullchain.pem`, is exactly a request waiting to be signed.
    """

    if not CERTIFICATE_ID.fullmatch(certificate_id):
        return False
    directory = store / certificate_id
    try:
        if directory.is_symlink() or not (directory / CSR).is_file():
            return False
        return not (directory / MATERIAL).exists()
    except OSError:
        return False


def pending_csr(store: Path, certificate_id: str) -> PendingCsr | None:
    """One waiting request, read as root by the listing helper; unreadable is none."""

    if not csr_is_pending(store, certificate_id):
        return None
    directory = store / certificate_id
    record = _bounded_json(directory / RECORD, MAX_RECORD_BYTES)
    if not isinstance(record, dict) or record.get("certificate") != certificate_id:
        return None
    domains = record.get("domains")
    kind = record.get("key_type")
    requested_at = record.get("requested_at")
    if (
        not isinstance(domains, list)
        or not isinstance(kind, str)
        or kind not in KEY_TYPES
        or not isinstance(requested_at, str)
    ):
        return None
    try:
        csr_pem = (directory / CSR).read_text(encoding="ascii")
    except (OSError, UnicodeError):
        return None
    clusters, receivers, formats = request_targets(store, certificate_id)
    return PendingCsr(
        certificate_id,
        tuple(name for name in domains if isinstance(name, str)),
        kind,
        requested_at,
        csr_pem,
        clusters,
        receivers,
        formats,
    )


def pending_csrs(store: Path) -> tuple[PendingCsr, ...]:
    """Every request waiting to be signed, for the listing."""

    try:
        entries = sorted(store.iterdir())
    except OSError:
        return ()
    found: list[PendingCsr] = []
    for entry in entries:
        if entry.name.startswith("."):
            continue  # staging and `.replaced` directories
        pending = pending_csr(store, entry.name)
        if pending is not None:
            found.append(pending)
    return tuple(found)


def request_targets(
    store: Path, certificate_id: str
) -> tuple[tuple[str, ...], tuple[str, ...], dict[str, str]]:
    """The targets a request was made with; empty when none were kept or none is pending.

    Read by the import when the signed certificate arrives, so the targets
    the form named at request time are the ones the certificate goes to -
    plus whatever the upload names, as a second import adds to the first.
    """

    if not csr_is_pending(store, certificate_id):
        return (), (), {}
    loaded = _bounded_json(store / certificate_id / TARGETS, MAX_RECORD_BYTES)
    if not isinstance(loaded, dict):
        return (), (), {}
    receivers = _ids(loaded.get("receivers"), RECEIVER_ID)
    raw = loaded.get("formats")
    formats = (
        {
            str(receiver_id): str(form)
            for receiver_id, form in raw.items()
            if isinstance(receiver_id, str)
            and receiver_id in receivers
            and form in RECEIVER_FORMATS
        }
        if isinstance(raw, dict)
        else {}
    )
    return _ids(loaded.get("clusters"), CLUSTER_ID), receivers, formats


def request_is_interface(store: Path, certificate_id: str) -> bool:
    """Whether a pending request was made for the manager's own interface (B188).

    Kept with the request's targets, because the answer arrives with the
    signed certificate, which may be months later and through another form.
    """

    if not csr_is_pending(store, certificate_id):
        return False
    loaded = _bounded_json(store / certificate_id / TARGETS, MAX_RECORD_BYTES)
    return isinstance(loaded, dict) and loaded.get("interface") is True


#
# Who can hold a certificate ID. There are five places, and each way a
# certificate arrives used to ask about its own subset (review 26-10-30, E4):
# an issuance never looked at a waiting signing request, an import never at a
# waiting NDES enrollment. `id_holder` is the one answer; it is asked under the
# certificate lock, and a caller names the holders it may share the ID with.
#
HELD_BY_ENTRY = "registered"  # a registry entry of a source that is not an import
HELD_BY_IMPORT_ENTRY = "import_entry"  # a registry entry whose material was imported
HELD_BY_LINEAGE = "lineage"  # certbot's `live/<id>`
HELD_BY_CSR = "csr_waiting"  # a signing request made here, not yet signed
HELD_BY_MATERIAL = "material"  # imported material in the store
HELD_BY_ENROLLMENT = "enrollment"  # an NDES enrollment still waiting on its CA


@dataclass(frozen=True, slots=True)
class IdHolder:
    kind: str
    message: str


def id_holder(
    certificate_id: str,
    *,
    registered_kind: str | None,
    live: Path | None,
    store: Path,
    request_root: Path | None,
    allow: Collection[str] = (),
) -> IdHolder | None:
    """What already holds this certificate ID, or None when it is free.

    `registered_kind` is the source kind of the registry entry of that name,
    None when there is none. `live` None leaves certbot's directory out: an
    issuance asks again after certbot has made its lineage. A holder whose kind
    is in `allow` is the caller's own and is not reported.
    """

    holders: list[IdHolder] = []
    if registered_kind is not None:
        if registered_kind == "import":
            holders.append(
                IdHolder(
                    HELD_BY_IMPORT_ENTRY,
                    f"{certificate_id!r} is already in the registry as 'import'. "
                    "Choose another name, or renew the certificate that exists.",
                )
            )
        else:
            holders.append(
                IdHolder(
                    HELD_BY_ENTRY,
                    f"{certificate_id!r} is already in the registry as {registered_kind!r}. "
                    "Choose another name, or renew the certificate that exists.",
                )
            )
    if live is not None and (live / certificate_id).exists():
        holders.append(
            IdHolder(
                HELD_BY_LINEAGE,
                f"certbot has a lineage named {certificate_id!r} that the registry does not "
                f"hold; choose another name, or remove it with 'haprion-cert-delete "
                f"{certificate_id}'",
            )
        )
    if (store / certificate_id).exists():
        if csr_is_pending(store, certificate_id):
            holders.append(
                IdHolder(
                    HELD_BY_CSR,
                    f"a signing request for {certificate_id!r} is already waiting; download it "
                    "from the certificate's row, or delete the row to start over",
                )
            )
        else:
            holders.append(
                IdHolder(
                    HELD_BY_MATERIAL,
                    f"the import store already holds material for {certificate_id!r}; "
                    "choose another name",
                )
            )
    if request_root is not None and request_is_pending(request_root, certificate_id):
        holders.append(
            IdHolder(
                HELD_BY_ENROLLMENT,
                f"an NDES enrollment for {certificate_id!r} is still waiting on its CA",
            )
        )
    return next((holder for holder in holders if holder.kind not in allow), None)
