"""A certificate file uploaded in the interface, sealed for root (C9, B165).

The web process receives the file, seals it against the installation's public
key - the same pair and the same `crypto_box_seal` that carry DNS provider
credentials (B146) - and hands the ciphertext to a job. Nothing the web can
read holds the plaintext after the request ends: not the job row, not the
audit. The root helper opens it, takes the material
apart with `cert_import` and imports it.

What is sealed
--------------
One JSON line and then the raw bytes, not a JSON document with the bytes
base64 inside it: the request the worker sends is bounded at 64 KiB, and a
32 KiB file base64-encoded twice would not fit. The header binds the box to
the certificate ID and the key ID the job names, so a ciphertext moved to
another job is refused before its bytes are looked at - the four bindings
DNS profiles have, less the revision, which an upload does not carry.

A PKCS#12 password rides in the header, because it is a secret too and the
box is the one place a secret goes.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from haprion.cert_import import MAX_UPLOAD_BYTES
from haprion.config import CERTIFICATE_ID
from haprion.dns_profile_keys import (
    DnsProfilePrivateKey,
    DnsProfilePublicKey,
    KeyFileError,
    open_sealed,
    seal,
)

OPERATION = "cert_import"
HELPER = "/opt/haprion/current/bin/haprion-cert-import-helper"
SUDO = "/usr/bin/sudo"
SCHEMA_VERSION = 1
MAX_PASSWORD_BYTES = 256
#
# The box is the file plus a short header plus libsodium's 48 bytes of
# overhead. Anything larger was not sealed by `seal_upload`.
#
MAX_CIPHERTEXT = MAX_UPLOAD_BYTES + 1024
_HEADER_KEYS = frozenset({"schema_version", "certificate_id", "key_id", "password"})


class UploadError(ValueError):
    """The upload is not one this module seals or opens."""


@dataclass(frozen=True, slots=True)
class OpenedUpload:
    certificate_id: str
    key_id: str
    data: bytes
    password: str | None


def check_certificate_id(value: object) -> str:
    if not isinstance(value, str) or not CERTIFICATE_ID.fullmatch(value):
        raise UploadError("certificate ID must be lower-case letters, digits, dots and dashes")
    return value


def check_password(value: object) -> str | None:
    if value is None or value == "":
        return None
    if not isinstance(value, str) or len(value.encode("utf-8")) > MAX_PASSWORD_BYTES:
        raise UploadError(f"the password is longer than {MAX_PASSWORD_BYTES} bytes")
    if "\n" in value or "\r" in value:
        raise UploadError("the password holds a line break")
    return value


def seal_upload(
    public_key: DnsProfilePublicKey,
    *,
    certificate_id: str,
    data: bytes,
    password: str | None = None,
) -> bytes:
    """Bind the file to the ID and the key, then seal it for root."""

    check_certificate_id(certificate_id)
    password = check_password(password)
    if not data:
        raise UploadError("the file is empty")
    if len(data) > MAX_UPLOAD_BYTES:
        raise UploadError(f"the file is larger than {MAX_UPLOAD_BYTES // 1024} kB")
    header = {
        "schema_version": SCHEMA_VERSION,
        "certificate_id": certificate_id,
        "key_id": public_key.key_id,
        "password": password,
    }
    line = json.dumps(header, separators=(",", ":")).encode("utf-8")
    return seal(public_key, line + b"\n" + data)


def open_upload(
    key: DnsProfilePrivateKey, ciphertext: bytes, *, certificate_id: str
) -> OpenedUpload:
    """Open the box and hold it to what the job asked for.

    The checks run in the order a wrong box fails cheapest: the key, the
    shape, then each binding. A failure names the binding, so a moved
    ciphertext can be told from one sealed against another installation.
    """

    check_certificate_id(certificate_id)
    if len(ciphertext) > MAX_CIPHERTEXT:
        raise UploadError("ciphertext is larger than an upload can be")
    try:
        plaintext = open_sealed(key, ciphertext)
    except KeyFileError as exc:
        raise UploadError(f"the upload was not sealed against key {key.key_id}") from exc
    line, separator, data = plaintext.partition(b"\n")
    if not separator:
        raise UploadError("the opened upload does not have the upload shape")
    try:
        header = json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise UploadError("the opened upload's header is not a JSON line") from None
    if not isinstance(header, dict) or set(header) != _HEADER_KEYS:
        raise UploadError("the opened upload does not have the upload shape")
    if header["schema_version"] != SCHEMA_VERSION:
        raise UploadError("the opened upload has a schema version this helper does not read")
    if header["certificate_id"] != certificate_id:
        raise UploadError("the opened upload was sealed for another certificate")
    if header["key_id"] != key.key_id:
        raise UploadError("the opened upload names another key than the one that opened it")
    password = check_password(header["password"])
    if not data or len(data) > MAX_UPLOAD_BYTES:
        raise UploadError("the opened upload's file is empty or too large")
    return OpenedUpload(
        certificate_id=certificate_id, key_id=key.key_id, data=data, password=password
    )


def build_request(
    request_id: str,
    *,
    certificate_id: str,
    key_id: str | None = None,
    ciphertext: bytes | None = None,
    clusters: tuple[str, ...] = (),
    receivers: tuple[str, ...] = (),
    formats: Mapping[str, str] | None = None,
    interface: bool = False,
    authority: str | None = None,
    keep_key: bool = False,
) -> str:
    """The bounded request the worker sends. Null cluster, by contract.

    `authority` (B276) asks for a CA certificate: `upload` with the box as
    usual, `ndes` with no box at all. `keep_key` asks for a certificate on the
    key the manager already holds, and a file that carries a key of its own is
    then refused.
    """

    parameters: dict[str, Any] = {"certificate": certificate_id}
    if authority != "ndes":
        if key_id is None or ciphertext is None:
            raise UploadError("an upload carries its key ID and its box")
        parameters["key_id"] = key_id
        parameters["ciphertext"] = base64.b64encode(ciphertext).decode("ascii")
    parameters["clusters"] = list(clusters)
    parameters["receivers"] = list(receivers)
    if formats:
        parameters["formats"] = dict(formats)
    if interface:
        parameters["interface"] = True
    if authority is not None:
        parameters["authority"] = authority
    if keep_key:
        parameters["key"] = "keep"
    return json.dumps(
        {
            "schema_version": 1,
            "operation": OPERATION,
            "cluster": None,
            "request_id": request_id,
            "parameters": parameters,
        },
        separators=(",", ":"),
    )
