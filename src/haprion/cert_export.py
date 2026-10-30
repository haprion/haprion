"""Taking an exportable certificate's key out of the manager (B255, 2026-10-06).

Some places that want a certificate will never be connected to this manager - a
BMC, a NAS, a printer - and the certificate is installed there by hand. The
registry marks such an entry `exportable` when it is made: one name, no targets.
This is the only code that reads its key on behalf of somebody else, and it
refuses every entry without the mark: a certificate a cluster or a receiver
carries is never one whose key can be downloaded.

Three forms. The key alone as PEM, for a device that takes certificate and key
as two files (Supermicro). A PKCS#12 bundle with a password the person chose,
as OpenSSL writes one today (AES-256, PBKDF2, a SHA-256 MAC). And the same
bundle in the form older readers take (3DES and a SHA-1 MAC) - not OpenSSL's
`-legacy`, whose certificate part is 40-bit RC2 (measured 2026-10-06). The
certificate and its chain are public and travel through the listing instead.

Nothing is written. The key, the chain and the password reach openssl as
anonymous memory, as the receiver bundles do, and the result is handed back.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from haprion import exit_codes
from haprion.cert_inventory import (
    FULLCHAIN,
    IMPORT_STORE,
    LETSENCRYPT_LIVE,
    OPENSSL,
    PRIVKEY,
    source_directory,
)
from haprion.cert_publish import _memfd, _openssl, key_matches
from haprion.certificates import MAX_CERTIFICATE_BYTES, CertificateError, leaf_fingerprint
from haprion.config import Registry

FORMATS = ("pem-key", "pfx", "pfx-compatible")
MIN_PASSWORD = 8
MAX_PASSWORD = 128
#
# What older PKCS#12 readers take - 3DES for both bags and a SHA-1 MAC - written
# by OpenSSL's default provider, unlike `-legacy`.
#
COMPATIBLE = ("-certpbe", "PBE-SHA1-3DES", "-keypbe", "PBE-SHA1-3DES", "-macalg", "sha1")


class ExportError(Exception):
    """A refused export, with the code it is reported under."""

    def __init__(self, code: str, message: str, exit_code: int = exit_codes.REFUSED):
        super().__init__(message)
        self.code = code
        self.exit_code = exit_code


@dataclass(frozen=True, slots=True)
class Export:
    certificate_id: str
    form: str
    filename: str
    media_type: str
    content: bytes
    fingerprint: str


def check_password(form: str, password: object) -> str | None:
    """The bundle's password, held to what openssl can take; none for the bare key."""

    if form == "pem-key":
        if password not in (None, ""):
            raise ExportError("bad_input", "the key alone takes no password")
        return None
    if (
        not isinstance(password, str)
        or not MIN_PASSWORD <= len(password) <= MAX_PASSWORD
        or not password.isprintable()
    ):
        raise ExportError(
            "bad_input",
            f"a PKCS#12 bundle needs a password of {MIN_PASSWORD}-{MAX_PASSWORD} printable "
            "characters",
        )
    return password


def _read(path: Path) -> bytes:
    """A material file, held to the size the publisher and the listing hold theirs to."""

    if path.lstat().st_size > MAX_CERTIFICATE_BYTES:
        raise OSError(f"{path.name} is implausibly large")
    return path.read_bytes()


def export(
    registry: Registry | None,
    certificate_id: str,
    form: str,
    password: object = None,
    *,
    live: Path = LETSENCRYPT_LIVE,
    store: Path = IMPORT_STORE,
) -> Export:
    """One exportable certificate's key, in the form asked for."""

    if form not in FORMATS:
        raise ExportError("bad_input", f"format must be one of: {', '.join(FORMATS)}")
    secret = check_password(form, password)
    entry = registry.certificates.get(certificate_id) if registry is not None else None
    if entry is None:
        raise ExportError("not_registered", f"{certificate_id} is not in the registry")
    if not entry.exportable or entry.clusters or entry.receivers or entry.interface:
        raise ExportError(
            "not_exportable",
            f"{certificate_id} is not exportable; only a certificate made exportable, with no "
            "targets, gives its key out",
        )
    directory = source_directory(entry, live=live, store=store)
    try:
        fullchain = _read(directory / FULLCHAIN)
        privkey = _read(directory / PRIVKEY)
    except OSError as exc:
        raise ExportError(
            "dependency_unavailable",
            f"the material of {certificate_id} cannot be read: {exc}",
            exit_codes.CONFIG,
        ) from exc
    try:
        fingerprint = leaf_fingerprint(fullchain.decode("ascii"))
    except (UnicodeDecodeError, CertificateError) as exc:
        raise ExportError(
            "invalid_certificate", f"{certificate_id}: {exc}", exit_codes.CONFIG
        ) from exc
    if not key_matches(fullchain, privkey):
        raise ExportError(
            "key_mismatch", "the private key does not belong to the certificate", exit_codes.CONFIG
        )

    if form == "pem-key":
        return Export(
            certificate_id,
            form,
            f"{certificate_id}.key.pem",
            "application/x-pem-file",
            privkey,
            fingerprint,
        )
    assert secret is not None  # noqa: S101 - check_password gives one for a bundle
    descriptors = [
        _memfd("privkey", privkey),
        _memfd("fullchain", fullchain),
        _memfd("password", (secret + "\n").encode("utf-8")),
    ]
    key_fd, chain_fd, password_fd = descriptors
    try:
        bundle = _openssl(
            [
                OPENSSL,
                "pkcs12",
                "-export",
                *(COMPATIBLE if form == "pfx-compatible" else ()),
                "-inkey",
                f"/dev/fd/{key_fd}",
                "-in",
                f"/dev/fd/{chain_fd}",
                "-name",
                certificate_id,
                "-passout",
                f"file:/dev/fd/{password_fd}",
            ],
            pass_fds=tuple(descriptors),
        )
    finally:
        for descriptor in descriptors:
            os.close(descriptor)
    if bundle is None:
        raise ExportError(
            "export_failed", "openssl could not build the PKCS#12 bundle", exit_codes.INTERNAL
        )
    return Export(
        certificate_id,
        form,
        f"{certificate_id}.pfx",
        "application/x-pkcs12",
        bundle,
        fingerprint,
    )
