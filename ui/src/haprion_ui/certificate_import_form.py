"""The import form (C9, B165): a file somebody already has, in, sealed, and queued.

Two pages submit here. `/certificates/import` takes a file, a name and the
targets - a certificate that does not exist on the manager yet, with its key
or (for a name whose key the manager holds) without. The row's *Upload
certificate* takes only a file for a name that exists, and lands on the same
payload with the row's own targets left as they are.

The file is judged for shape here - size, and that it is not obviously
something else - and for content in the root helper, which is the only
process that ever sees it in clear. What leaves this module is a payload
whose `ciphertext` the web cannot open.
"""

from __future__ import annotations

import base64
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from haprion import cert_import, cert_upload
from haprion.config import CERTIFICATE_ID, DEFAULT_RECEIVER_FORMAT, RECEIVER_FORMATS
from haprion.dns_profile_keys import DnsProfilePublicKey

from haprion_ui.certificate_form import (
    FormProblem,
    IssueChoices,
    formats_from_fields,
)

MAX_UPLOAD_BYTES = cert_import.MAX_UPLOAD_BYTES
#
# What the file input offers. Hints for the browser's picker only: the
# helper reads the bytes, not the name.
#
ACCEPT = ".pem,.crt,.cer,.der,.p7b,.p7c,.pfx,.p12,application/x-pkcs12,application/x-x509-ca-cert"
KEY_MARK = b"PRIVATE KEY"


@dataclass(frozen=True, slots=True)
class ImportForm:
    """One submission, as typed. `data` is the file's bytes and is never rendered."""

    name: str
    password: str
    clusters: tuple[str, ...]
    receivers: tuple[str, ...]
    formats: tuple[str, ...] = ()
    filename: str = ""
    data: bytes = b""
    interface: bool = False
    """For the manager's own interface certificate (B188): no targets, published to nginx."""

    def format_of(self, receiver_id: str) -> str:
        """What the page should show selected for a receiver when drawn again."""

        for value in self.formats:
            name, _, form = value.partition("=")
            if name.strip() == receiver_id and form.strip() in RECEIVER_FORMATS:
                return form.strip()
        return DEFAULT_RECEIVER_FORMAT


EMPTY_FORM = ImportForm(name="", password="", clusters=(), receivers=())


def normalise(form: ImportForm) -> ImportForm:
    """The submission as it will be judged: trimmed, lowercased, deduplicated."""

    return ImportForm(
        name=form.name.strip().lower().rstrip("."),
        password=form.password,
        clusters=tuple(dict.fromkeys(name.strip() for name in form.clusters if name.strip())),
        receivers=tuple(dict.fromkeys(name.strip() for name in form.receivers if name.strip())),
        formats=tuple(value.strip() for value in form.formats if value.strip()),
        filename=form.filename,
        data=form.data,
        interface=form.interface,
    )


def check_file(data: bytes, *, key_allowed: bool = True) -> None:
    """The refusals the page can make about the bytes without reading them as material."""

    if not data:
        raise FormProblem("Choose a certificate file.")
    if len(data) > MAX_UPLOAD_BYTES:
        raise FormProblem(
            f"The file is larger than {MAX_UPLOAD_BYTES // 1024} kB. A certificate with "
            "its key and chain is a few kilobytes; this is something else."
        )
    if not key_allowed and KEY_MARK in data:
        #
        # The row's upload is for a certificate on the key the manager
        # already holds. A key in that file is either a mistake or a new
        # pair, and a new pair is the import page's business - said here,
        # rather than letting the helper replace the key quietly.
        #
        raise FormProblem(
            "This file holds a private key. Upload only the certificate here; to "
            "replace the key as well, use Import certificate."
        )


def payload_from_form(
    form: ImportForm,
    choices: IssueChoices,
    public_key: DnsProfilePublicKey,
    *,
    replaceable: Iterable[str] = (),
) -> dict[str, Any]:
    """Judge the form, seal the file, and build the `cert_import` payload.

    The refusals are sentences about the form, in the order a person would
    fix them: the name, the file, the targets. The engine judges the material
    itself, as a job the row reports.
    """

    if not form.name:
        raise FormProblem("A name is required: what the certificate will be called here.")
    if not CERTIFICATE_ID.fullmatch(form.name):
        raise FormProblem(
            "The name may hold lower-case letters, digits, dots and dashes, and must "
            "start with a letter or digit."
        )
    if form.interface:
        return _interface_payload(form, choices, public_key)
    if form.name in choices.registered and form.name not in set(replaceable):
        raise FormProblem(
            f"{form.name} is already registered and its material is not imported; "
            "an import cannot replace it. Choose another name."
        )
    check_file(form.data)
    try:
        cert_upload.check_password(form.password)
    except cert_upload.UploadError as exc:
        raise FormProblem(f"The password could not be used: {exc}.") from exc
    if not form.clusters and not form.receivers:
        raise FormProblem("Choose at least one target: a cluster or a receiver.")
    if _unknown(form.clusters, choices.clusters):
        raise FormProblem("One of the chosen clusters is not a cluster this manager has.")
    if _unknown(form.receivers, choices.receivers):
        raise FormProblem(
            "One of the chosen receivers is not registered. A receiver is registered "
            "on the manager, not from this form."
        )
    formats = formats_from_fields(form.formats, form.receivers)
    return sealed_payload(
        public_key,
        certificate_id=form.name,
        data=form.data,
        password=form.password,
        clusters=form.clusters,
        receivers=form.receivers,
        formats=formats,
    )


def _interface_payload(
    form: ImportForm, choices: IssueChoices, public_key: DnsProfilePublicKey
) -> dict[str, Any]:
    """An import for the interface's own certificate (B188): no targets, the mark set.

    The name may be the interface certificate's own - a rotated pair for the
    one that serves - or one no other certificate uses. Whether the file
    names the interface's server name is the engine's check: the file is
    sealed here and read only by the helper.
    """

    if form.name != choices.interface_id and form.name in choices.taken:
        raise FormProblem(f"{form.name} is already in use. Choose another name.")
    check_file(form.data)
    try:
        cert_upload.check_password(form.password)
    except cert_upload.UploadError as exc:
        raise FormProblem(f"The password could not be used: {exc}.") from exc
    if form.clusters or form.receivers:
        raise FormProblem("The interface certificate has no targets.")
    payload = sealed_payload(
        public_key, certificate_id=form.name, data=form.data, password=form.password
    )
    payload["interface"] = True
    return payload


def sealed_payload(
    public_key: DnsProfilePublicKey,
    *,
    certificate_id: str,
    data: bytes,
    password: str = "",
    clusters: Iterable[str] = (),
    receivers: Iterable[str] = (),
    formats: dict[str, str] | None = None,
) -> dict[str, Any]:
    """The payload a `cert_import` job carries: the box, and what binds it."""

    try:
        box = cert_upload.seal_upload(
            public_key, certificate_id=certificate_id, data=data, password=password or None
        )
    except cert_upload.UploadError as exc:
        raise FormProblem(f"The file could not be sealed: {exc}.") from exc
    payload: dict[str, Any] = {
        "id": certificate_id,
        "key_id": public_key.key_id,
        "ciphertext": base64.b64encode(box).decode("ascii"),
        "clusters": list(clusters),
        "receivers": list(receivers),
    }
    if formats:
        payload["formats"] = formats
    return payload


def _unknown(chosen: Iterable[str], offered: Iterable[str]) -> tuple[str, ...]:
    known = set(offered)
    return tuple(name for name in chosen if name not in known)
