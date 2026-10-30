"""Importing a certificate somebody else issued: a pair in, a registered source out.

The second of the two ways a certificate reaches the registry (§14.3, B134).
ACME goes through certbot; everything else - an internal PKI, a purchased
certificate, a wildcard exported from a Windows CA - comes in here, as
material the maintainer already holds. The import store
(`/etc/haprion/certificates/<id>/`) is laid out like certbot's
`live/`, so the publisher and the listing read both sources the same way.

What an import is
-----------------
1. the material is read - a certificate, its private key and optionally a
   chain, as PEM files, or all of them out of one PKCS#12 - and taken apart
   into blocks;
2. the leaf is the one certificate whose public key is the key's; the chain
   is the certificates that link from it, in issuer order, without a
   self-signed root (clients hold the root already; serving it is noise);
3. the leaf is refused if it has expired, and its facts - names, issuer,
   validity - are what the result reports;
4. the four files certbot would have written are written to the store as
   one directory, root-only, replacing a previous import of the same ID in
   one rename;
5. the registry takes the entry - `source.kind: import` with the targets
   named, or the targets it already had - through the one writer the
   registry has;
6. the publisher runs for that certificate alone, and the clusters it
   changed are rolled out.

Nothing is written before step 3 is through: a pair that does not match, or
a certificate that has already expired, leaves the store and the registry
exactly as they were.

The key is read into memory once, written to the store and never reported,
logged or returned; every function that returns text returns the leaf, the
chain or facts about them. `openssl` does the parsing - the engine's only
X.509 tool, and a root-run path is the last place to add a second one.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Iterable, Mapping, Sequence
from contextlib import AbstractContextManager, nullcontext
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from haprion import (
    atomic_file,
    cert_delete,
    cert_registry,
    cert_request_state,
    exit_codes,
    labels,
    ui_interface,
)
from haprion.cert_inventory import (
    FULLCHAIN,
    IMPORT_STORE,
    LETSENCRYPT_LIVE,
    OPENSSL,
    OPENSSL_TIMEOUT,
    PRIVKEY,
    Facts,
    describe,
)
from haprion.cert_issue import certbot_binary
from haprion.cert_publish import (
    DEFAULT_LOCK_PATH,
    Deployer,
    Installer,
    PublishError,
    Report,
    publish,
    unpublished,
)
from haprion.certificates import (
    DELIMITER,
    MAX_CERTIFICATE_BYTES,
    CertificateError,
    leaf_fingerprint,
)
from haprion.config import (
    AUTHORITY,
    CERTIFICATE_ID,
    RECEIVER_FORMATS,
    ConfigError,
    NdesServer,
    PathPolicy,
    RuntimeConfig,
    load_runtime_config,
)

OPERATION = "cert_import"
CERT = "cert.pem"
CHAIN = "chain.pem"

#
# Assembled, not written out, for the reason `certificates.py` gives: the
# secret scanner refuses a literal PEM header in a tracked file, and this
# module has to name the key's header to find the key.
#
_BLOCK = re.compile(
    DELIMITER + r"BEGIN ([A-Z0-9 ]+)" + DELIMITER + r"(.+?)" + DELIMITER + r"END \1" + DELIMITER,
    re.DOTALL,
)
_KEY_KINDS = frozenset({"PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"})
_CERTIFICATE = "CERTIFICATE"


class ImportError_(Exception):  # `ImportError` is Python's; the trailing mark says so
    """The import is refused, or stopped after the store; `exit_code` says which."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        exit_code: int = exit_codes.REFUSED,
        details: dict[str, Any] | None = None,
    ):
        super().__init__(message)
        self.code = code
        self.exit_code = exit_code
        self.details = details or {}


@dataclass(frozen=True, slots=True)
class Material:
    """One certificate as the store will hold it. The key is here and nowhere else."""

    leaf: str
    chain: tuple[str, ...]
    key: str

    @property
    def fullchain(self) -> str:
        return "".join((self.leaf, *self.chain))


@dataclass(frozen=True, slots=True)
class ImportResult:
    certificate_id: str
    facts: Facts
    fingerprint: str
    chain_length: int
    replaced: bool
    """A previous import of the same ID was in the store and is gone."""

    publish: Report
    interface: bool = False
    exportable: bool = False
    authority: bool = False
    #
    # D5: the entry that served the interface before this one, and what
    # became of it. Both fields are absent from the answer for every other
    # import, so a certificate that is not the interface's reads as before.
    #
    retired: Mapping[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        extra: dict[str, Any] = {}
        if self.interface:
            extra["interface"] = True
        if self.exportable:
            extra["exportable"] = True
        if self.authority:
            extra["authority"] = True
        if self.retired is not None:
            extra["retired"] = dict(self.retired)
        return {
            "certificate": self.certificate_id,
            "fingerprint_sha256": self.fingerprint,
            "common_name": self.facts.common_name,
            "sans": list(self.facts.sans),
            "issuer": self.facts.issuer,
            "not_before": self.facts.not_before.isoformat(timespec="seconds"),
            "not_after": self.facts.not_after.isoformat(timespec="seconds"),
            "chain_length": self.chain_length,
            "replaced": self.replaced,
            "publish": self.publish.as_dict(),
            **extra,
        }


# - Reading ----------------------------------------------------------------


def _block(kind: str, body: str) -> str:
    lines = "\n".join(line for line in body.split() if line)
    return f"{DELIMITER}BEGIN {kind}{DELIMITER}\n{lines}\n{DELIMITER}END {kind}{DELIMITER}\n"


def split_blocks(text: str) -> tuple[list[str], list[str]]:
    """Every certificate block and every private-key block in `text`, re-wrapped.

    Anything between blocks - PKCS#12 bag attributes, comments, a Windows
    export's `Bag Attributes:` lines - is dropped. Encrypted keys are refused:
    the store holds the key as certbot holds it, and a passphrase the
    publisher would have to know is a secret in a second place.
    """

    certificates: list[str] = []
    keys: list[str] = []
    for match in _BLOCK.finditer(text):
        kind, body = match.group(1), match.group(2)
        if kind == _CERTIFICATE:
            certificates.append(_block(kind, body))
        elif kind in _KEY_KINDS:
            keys.append(_block(kind, body))
        elif kind == "ENCRYPTED PRIVATE KEY":
            raise ImportError_(
                "bad_input", "the private key is encrypted; decrypt it first (openssl pkey)"
            )
    return certificates, keys


#
# What Windows tools put first in a file saved as "UTF-8 with BOM". Only the
# base64 blocks are read, so it is dropped rather than refused.
#
UTF8_BOM = b"\xef\xbb\xbf"


def _read(path: Path, what: str) -> str:
    try:
        if path.stat().st_size > MAX_CERTIFICATE_BYTES:
            raise ImportError_("bad_input", f"{what} is implausibly large: {path}")
        return path.read_bytes().removeprefix(UTF8_BOM).decode("ascii")
    except FileNotFoundError:
        raise ImportError_("bad_input", f"{what} does not exist: {path}") from None
    except (OSError, UnicodeDecodeError) as exc:
        raise ImportError_("bad_input", f"{what} could not be read: {exc}") from exc


def _openssl(arguments: Sequence[str], *, stdin: str, what: str) -> str:
    try:
        completed = subprocess.run(  # noqa: S603 - fixed binary, fixed arguments
            [OPENSSL, *arguments],
            input=stdin,
            capture_output=True,
            text=True,
            timeout=OPENSSL_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ImportError_(
            "dependency_unavailable",
            f"openssl could not {what}: {exc}",
            exit_code=exit_codes.CONFIG,
        ) from exc
    if completed.returncode != 0:
        detail = (completed.stderr or "").strip().splitlines()
        raise ImportError_("bad_input", f"openssl could not {what}: {detail[-1] if detail else ''}")
    return completed.stdout


def public_key_of_certificate(leaf: str) -> str:
    return _openssl(["x509", "-noout", "-pubkey"], stdin=leaf, what="read the certificate")


def public_key_of_key(key: str) -> str:
    """The public half only. The private key goes in and does not come back out."""

    return _openssl(["pkey", "-pubout"], stdin=key, what="read the private key")


def _names(certificate: str) -> tuple[str, str]:
    """`(subject, issuer)` in one canonical form, to link a chain by."""

    text = _openssl(
        ["x509", "-noout", "-subject", "-issuer", "-nameopt", "RFC2253"],
        stdin=certificate,
        what="read a chain certificate",
    )
    subject = issuer = ""
    for line in text.splitlines():
        if line.startswith("subject="):
            subject = line.removeprefix("subject=").strip()
        elif line.startswith("issuer="):
            issuer = line.removeprefix("issuer=").strip()
    return subject, issuer


def read_pkcs12(path: Path, password_file: Path | None, *, password: str | None = None) -> str:
    """Everything in a PKCS#12 as PEM: the key unencrypted, the certificates as they are.

    The password reaches openssl from the operator's file, or - for the
    interface's upload, which has it in memory and nowhere on disk - down a
    pipe as `-passin fd:N`. Never argv, where every user on the host could
    read it, and never a file this function writes. OpenSSL 3 refuses the
    RC2-40 that older Windows exports use unless told `-legacy`; tried
    second, so a modern file is read the modern way.
    """

    if not path.is_file():
        raise ImportError_("bad_input", f"the PKCS#12 file does not exist: {path}")
    if path.stat().st_size > MAX_CERTIFICATE_BYTES:
        raise ImportError_("bad_input", f"the PKCS#12 file is implausibly large: {path}")
    if password_file is not None and password is not None:
        raise ImportError_("bad_input", "a password file and a password are two passwords")
    if password_file is not None and not password_file.is_file():
        raise ImportError_("bad_input", f"the password file does not exist: {password_file}")
    last = ""
    for extra in ((), ("-legacy",)):
        pass_fds: tuple[int, ...] = ()
        if password_file is not None:
            passin = f"file:{password_file}"
        elif password is not None:
            #
            # Written before the child starts, so the read never blocks: a
            # password is bounded far below the pipe's buffer. The write end
            # is closed here and the read end is closed after the run, so
            # neither outlives this call.
            #
            read_end, write_end = os.pipe()
            os.write(write_end, password.encode("utf-8") + b"\n")
            os.close(write_end)
            pass_fds = (read_end,)
            passin = f"fd:{read_end}"
        else:
            passin = "pass:"
        base = ["pkcs12", "-in", str(path), "-nodes", "-passin", passin]
        try:
            completed = subprocess.run(  # noqa: S603 - fixed binary, paths from the operator
                [OPENSSL, *base, *extra],
                capture_output=True,
                text=True,
                timeout=OPENSSL_TIMEOUT,
                check=False,
                pass_fds=pass_fds,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ImportError_(
                "dependency_unavailable",
                f"openssl could not read the PKCS#12: {exc}",
                exit_code=exit_codes.CONFIG,
            ) from exc
        finally:
            for descriptor in pass_fds:
                os.close(descriptor)
        if completed.returncode == 0:
            return completed.stdout
        lines = (completed.stderr or "").strip().splitlines()
        last = lines[-1] if lines else ""
        if "unsupported" not in last.lower() and "legacy" not in last.lower():
            break
    raise ImportError_("bad_input", f"openssl could not read the PKCS#12: {last}")


#
# One file from the interface (C9, B165): whatever the operator was handed.
# Bounded here as well as in the form, because the form is not the only
# caller and a root-run parser is the last place to read an unbounded file.
#
MAX_UPLOAD_BYTES = 32 * 1024
_PEM_MARK = (DELIMITER + "BEGIN ").encode("ascii")
_PKCS7 = "PKCS7"


def _pkcs7_certificates(text: str) -> list[str]:
    """The certificates inside a PEM PKCS#7 block (`.p7b`), as blocks."""

    printed = _openssl(["pkcs7", "-print_certs"], stdin=text, what="read the PKCS#7 bundle")
    certificates, _keys = split_blocks(printed)
    return certificates


def _openssl_file(arguments: Sequence[str], *, what: str) -> str | None:
    """Like `_openssl` for a file the caller named, or None when openssl refuses it.

    None rather than an error because the caller is trying forms in turn and
    the refusal of one is not the answer; a missing binary still raises.
    """

    try:
        completed = subprocess.run(  # noqa: S603 - fixed binary, a private temporary file
            [OPENSSL, *arguments],
            capture_output=True,
            text=True,
            timeout=OPENSSL_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ImportError_(
            "dependency_unavailable",
            f"openssl could not {what}: {exc}",
            exit_code=exit_codes.CONFIG,
        ) from exc
    return completed.stdout if completed.returncode == 0 else None


def read_bytes(data: bytes, *, password: str | None = None) -> tuple[list[str], list[str]]:
    """Steps 1 from one uploaded file: every certificate and key block in it.

    Four forms, told apart by what is in the bytes rather than by a name the
    browser sent: PEM (any mix of certificate, key and PKCS#7 blocks), and
    three binary DER forms tried in turn - PKCS#12 (`.pfx`/`.p12`, the only
    one that can carry a key and the only one that takes a password), a
    single X.509 certificate (`.cer`/`.crt`/`.der`), and a PKCS#7 bundle
    (`.p7b`). The bytes touch the disk once, in a private 0600 file that is
    gone before this returns, because `openssl pkcs12` reads a file; the
    password never does - it goes down a pipe.
    """

    if len(data) > MAX_UPLOAD_BYTES:
        raise ImportError_(
            "bad_input", f"the file is larger than {MAX_UPLOAD_BYTES // 1024} kB; nothing was read"
        )
    if not data.strip():
        raise ImportError_("bad_input", "the file is empty")
    if _PEM_MARK in data:
        try:
            text = data.removeprefix(UTF8_BOM).decode("ascii")
        except UnicodeDecodeError:
            raise ImportError_("bad_input", "the PEM file holds bytes that are not text") from None
        certificates, keys = split_blocks(text)
        for match in _BLOCK.finditer(text):
            if match.group(1) == _PKCS7:
                certificates.extend(_pkcs7_certificates(_block(_PKCS7, match.group(2))))
        if not certificates and not keys:
            raise ImportError_("bad_input", "no certificate or key block was found in the file")
        return certificates, keys

    directory = tempfile.mkdtemp(prefix="haproxy-cert-upload-")
    try:
        path = Path(directory) / "upload"
        with open(path, "wb", opener=lambda p, f: os.open(p, f, 0o600)) as handle:
            handle.write(data)
        try:
            return split_blocks(read_pkcs12(path, None, password=password or None))
        except ImportError_ as pkcs12_refusal:
            if pkcs12_refusal.code != "bad_input":
                raise
            if password:
                #
                # A password was given, so PKCS#12 was meant: say what openssl
                # said rather than sliding on to forms that take no password.
                #
                raise
        for arguments, what in (
            (["x509", "-inform", "DER", "-in", str(path)], "read the DER certificate"),
            (
                ["pkcs7", "-inform", "DER", "-in", str(path), "-print_certs"],
                "read the PKCS#7 bundle",
            ),
        ):
            printed = _openssl_file(arguments, what=what)
            if printed is not None:
                certificates, keys = split_blocks(printed)
                if certificates:
                    return certificates, keys
        raise ImportError_(
            "bad_input",
            "the file is not PEM, PKCS#12, a DER certificate or a PKCS#7 bundle "
            "(a PKCS#12 with a password needs the password)",
        )
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def stored_key(store: Path, certificate_id: str) -> str | None:
    """The key an earlier import of this ID left in the store, or None.

    For the upload that carries no key - a renewal on the key the manager
    already holds, or the certificate a CA returned for a CSR made here. Read
    as root, returned to be matched, never reported.
    """

    path = store / certificate_id / PRIVKEY
    if not path.is_file():
        return None
    try:
        return path.read_text(encoding="ascii")
    except (OSError, UnicodeDecodeError) as exc:
        raise ImportError_(
            "dependency_unavailable",
            f"the stored key could not be read: {exc}",
            exit_code=exit_codes.CONFIG,
        ) from exc


# - Assembling and checking ------------------------------------------------


def assemble(certificates: Sequence[str], keys: Sequence[str]) -> Material:
    """Match the key to its certificate and put the chain in order behind it.

    Exactly one key. The leaf is the certificate whose public key is the
    key's - so a chain handed in the wrong order, or a PKCS#12 with the CA
    certificates first, still comes out right. The chain is then followed by
    issuer from the leaf upward; a certificate that links to nothing is left
    out rather than served, and a self-signed one is the root and is left out
    too.
    """

    if len(keys) != 1:
        raise ImportError_(
            "bad_input",
            "exactly one private key is expected; found " + str(len(keys)),
        )
    if not certificates:
        raise ImportError_("bad_input", "no certificate was found")
    key = keys[0]
    public = public_key_of_key(key)
    leaves = [c for c in certificates if public_key_of_certificate(c) == public]
    if not leaves:
        raise ImportError_(
            "key_mismatch", "the private key does not belong to any of the certificates"
        )
    #
    # A file may carry an old and a renewed certificate for the one key (a PFX
    # exported with both): the one that runs longest is the one to serve.
    #
    leaf = max(leaves, key=lambda candidate: describe(candidate).not_after)
    others = [c for c in certificates if c != leaf]
    named = {c: _names(c) for c in others}
    chain: list[str] = []
    _subject, wanted = _names(leaf)
    while True:
        link = next((c for c in others if named[c][0] == wanted and c not in chain), None)
        if link is None:
            break
        subject, issuer = named[link]
        if subject == issuer:
            break  # the root: clients hold it, and it is not served
        chain.append(link)
        wanted = issuer
    return Material(leaf, tuple(chain), key)


def check(material: Material, *, now: datetime | None = None) -> tuple[Facts, str]:
    """The leaf's facts and fingerprint, refusing a certificate that has already run out."""

    moment = now or datetime.now(UTC)
    try:
        facts = describe(material.leaf)
        fingerprint = leaf_fingerprint(material.leaf)
    except CertificateError as exc:
        raise ImportError_("bad_input", f"the certificate could not be read: {exc}") from exc
    if facts.not_after < moment:
        raise ImportError_(
            "expired",
            f"the certificate expired {facts.not_after.isoformat(timespec='seconds')}; "
            "nothing was imported",
        )
    return facts, fingerprint


# - Writing ----------------------------------------------------------------


def _held(lock_path: Path | None) -> AbstractContextManager[None]:
    """The certificate lock, or nothing when the caller holds it."""

    return nullcontext() if lock_path is None else cert_registry.locked(lock_path)


def _recover_replaced(store: Path, certificate_id: str) -> None:
    """Put a directory the last swap set aside back, when the swap never put its successor in.

    `write_store` moves `<id>/` to `.<id>.replaced` and then the new one in; a
    process that died between the two, or a second move that failed, leaves the
    registered material under the old name and nothing under the new.
    """

    final = store / certificate_id
    previous = store / f".{certificate_id}.replaced"
    if previous.is_dir() and not final.exists():
        atomic_file.move(previous, final)


def _swap_into_place(store: Path, certificate_id: str, staging: Path) -> None:
    """`staging` becomes `<store>/<id>`; the directory it replaces is put back if that fails."""

    final = store / certificate_id
    previous: Path | None = None
    if final.is_dir():
        previous = store / f".{certificate_id}.replaced"
        shutil.rmtree(previous, ignore_errors=True)
        atomic_file.move(final, previous)
    try:
        atomic_file.move(staging, final)
    except OSError:
        if previous is not None:
            atomic_file.move(previous, final)
        raise
    if previous is not None:
        shutil.rmtree(previous, ignore_errors=True)


def write_store(store: Path, certificate_id: str, material: Material) -> bool:
    """The four files under `<store>/<id>/`, root-only, in one rename. True if replaced."""

    if not CERTIFICATE_ID.fullmatch(certificate_id):
        raise ImportError_("bad_input", f"invalid certificate ID: {certificate_id!r}")
    store.mkdir(mode=0o700, parents=True, exist_ok=True)
    final = store / certificate_id
    staging = Path(tempfile.mkdtemp(prefix=f".{certificate_id}.", dir=store))
    try:
        os.chmod(staging, 0o700)
        for name, content in (
            (PRIVKEY, material.key),
            (CERT, material.leaf),
            (CHAIN, "".join(material.chain)),
            (FULLCHAIN, material.fullchain),
        ):
            target = staging / name
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="ascii") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
        #
        # A directory holding a request and no certificate (C9b) is not a
        # previous import: the signature is the first material under the ID.
        #
        _recover_replaced(store, certificate_id)
        replaced = final.is_dir() and (final / FULLCHAIN).exists()
        _swap_into_place(store, certificate_id, staging)
        return replaced
    except OSError as exc:
        shutil.rmtree(staging, ignore_errors=True)
        raise ImportError_(
            "dependency_unavailable",
            f"the import store could not be written: {exc}",
            exit_code=exit_codes.CONFIG,
        ) from exc


def register(
    path: Path,
    certificate_id: str,
    runtime: RuntimeConfig,
    *,
    clusters: Sequence[str],
    receivers: Sequence[str],
    require_secure: bool,
    ndes_profile: str | None = None,
    formats: Mapping[str, str] | None = None,
    lock_path: Path | None = DEFAULT_LOCK_PATH,
    interface: bool = False,
    exportable: bool = False,
) -> str | None:
    """The entry, through the one writer the registry has, under the certificate lock.

    `lock_path` None means the caller holds the lock already, around the store
    write too (`import_certificate`); a second hold of the same file from this
    process would wait for itself.

    An entry that exists already keeps every target it has, and the targets
    named here are added to them: re-importing a rotated certificate - or
    enrolling it again over NDES with one more receiver - is the material and
    an addition, never a replacement. Taking a target away is a retarget's
    job (Remove from...), which is the operation that says what that costs.
    It used to replace: an enrollment of an installation's default
    certificate named one receiver and no cluster, the clusters were dropped,
    and every command on the manager refused its configuration (2026-09-19).
    An entry of another kind is refused: an ACME certificate's material
    belongs to certbot, and importing over it would give the publisher two
    sources for one ID.

    An entry that is the interface's stays the interface's; one imported with
    `interface` takes the mark, and the entry that had it is returned (D5).
    """

    try:
        with _held(lock_path):
            return _register_entry(
                path,
                certificate_id,
                runtime,
                clusters=clusters,
                receivers=receivers,
                require_secure=require_secure,
                ndes_profile=ndes_profile,
                formats=formats,
                interface=interface,
                exportable=exportable,
            )
    except cert_registry.RegistryError as exc:
        raise ImportError_(
            exc.code,
            f"the material is in the store but the registry did not take {certificate_id!r}: "
            f"{str(exc).rstrip('.')}. Fix the targets and import again.",
            exit_code=exit_codes.after_a_change(exc.exit_code),
        ) from exc


def _register_entry(
    path: Path,
    certificate_id: str,
    runtime: RuntimeConfig,
    *,
    clusters: Sequence[str],
    receivers: Sequence[str],
    require_secure: bool,
    ndes_profile: str | None,
    formats: Mapping[str, str] | None,
    interface: bool = False,
    exportable: bool = False,
) -> str | None:
    document = cert_registry.read_document(path)
    certificates = dict(document.get("certificates") or {})
    existing = certificates.get(certificate_id)
    entry: dict[str, Any] = {"source": {"kind": "import"}}
    if ndes_profile is not None:
        entry["source"]["ndes_profile"] = ndes_profile
    kept_clusters: list[str] = []
    kept_receivers: tuple[str, ...] = ()
    kept_formats: dict[str, str] = {}
    if isinstance(existing, dict):
        kind = (existing.get("source") or {}).get("kind")
        if kind != "import":
            if kind == AUTHORITY:
                raise ImportError_(
                    "not_import",
                    f"{certificate_id!r} is a CA certificate; import a certificate under "
                    "another ID.",
                )
            raise ImportError_(
                "not_import",
                f"{certificate_id!r} is registered as {kind!r}; its material is not "
                "imported. Choose another ID.",
            )
        kept_clusters = [str(item) for item in existing.get("clusters") or ()]
        kept_receivers, kept_formats = cert_registry.named_receivers(existing)
        #
        # A rotated or renewed interface certificate is still the interface's.
        # Rewriting the entry without the mark would have the next publish
        # skip nginx and the listing show it as an ordinary certificate.
        #
        interface = interface or existing.get("interface") is True
        #
        # So is an exportable one (B255): the mark is decided once, when the
        # entry is made, and a renewal arrives here as an import.
        #
        exportable = exportable or existing.get("exportable") is True
    all_clusters = kept_clusters + [c for c in clusters if c not in kept_clusters]
    all_receivers = list(kept_receivers) + [r for r in receivers if r not in kept_receivers]
    #
    # A format named now wins over the one on file: the operator chose it
    # on this request, and a receiver kept from before keeps its own.
    #
    all_formats = {**kept_formats, **(formats or {})}
    if all_clusters:
        entry["clusters"] = all_clusters
    if all_receivers:
        entry["receivers"] = cert_registry.receiver_elements(all_receivers, all_formats)
    if exportable:
        entry["exportable"] = True
    certificates[certificate_id] = entry
    displaced = cert_registry.claim_interface(certificates, certificate_id) if interface else None
    cert_registry.write(
        path,
        document=document,
        certificates=certificates,
        runtime=runtime,
        require_secure=require_secure,
    )
    return displaced


def _refuse_held(
    certificate_id: str,
    material: Material,
    *,
    policy: PathPolicy,
    live: Path,
    store: Path,
    ndes_profile: str | None,
) -> None:
    """The ID is free everywhere but where an import may share it, asked under the lock.

    Its own earlier material and the entry that names it, a signing request it
    answers, and - from NDES - the enrollment that is being finished. Anything
    else is another way's, and writing the store would take it away.
    """

    holder = cert_request_state.id_holder(
        certificate_id,
        registered_kind=None,
        live=live,
        store=store,
        request_root=policy.ndes.state_root if policy.ndes is not None else None,
        allow=(
            cert_request_state.HELD_BY_CSR,
            cert_request_state.HELD_BY_MATERIAL,
            *((cert_request_state.HELD_BY_ENROLLMENT,) if ndes_profile else ()),
        ),
    )
    if holder is not None:
        raise ImportError_("already_exists", holder.message)
    if cert_request_state.csr_is_pending(store, certificate_id) and material.key != stored_key(
        store, certificate_id
    ):
        raise ImportError_(
            "already_exists",
            f"a signing request for {certificate_id!r} is waiting for its signature; import "
            "the certificate the CA returned for it, without a key, or choose another ID",
        )


def import_certificate(
    *,
    certificate_id: str,
    material: Material,
    clusters: Sequence[str],
    receivers: Sequence[str],
    policy: PathPolicy,
    runtime: RuntimeConfig,
    deployer: Deployer | None = None,
    live: Path = LETSENCRYPT_LIVE,
    store: Path = IMPORT_STORE,
    lock_path: Path = DEFAULT_LOCK_PATH,
    require_secure: bool = True,
    now: datetime | None = None,
    ndes_profile: str | None = None,
    formats: Mapping[str, str] | None = None,
    interface: bool = False,
    installer: Installer | None = None,
    exportable: bool = False,
) -> ImportResult:
    """Steps 3-6: check, write, register, publish."""

    if policy.certificate_registry is None:
        raise ImportError_(
            "dependency_unavailable",
            "no certificate registry is configured. Add certificate_registry to the "
            "runtime policy.",
            exit_code=exit_codes.CONFIG,
        )
    if not CERTIFICATE_ID.fullmatch(certificate_id):
        raise ImportError_("bad_input", f"invalid certificate ID: {certificate_id!r}")
    facts, fingerprint = check(material, now=now)
    #
    # The ID and the targets are checked against the registry before the store
    # is written, so a wrong one leaves nothing behind; the entry is written
    # after the store, so the registry never names material that is not there.
    #
    existing = runtime.registry.certificates.get(certificate_id) if runtime.registry else None
    if existing is not None and existing.source.kind == AUTHORITY:
        raise ImportError_(
            "not_import",
            f"{certificate_id!r} is a CA certificate; import a certificate under another ID.",
        )
    if existing is not None and existing.source.kind != "import":
        raise ImportError_(
            "not_import",
            f"{certificate_id!r} is registered as {existing.source.kind!r}; its material is "
            "not imported. Choose another ID.",
        )
    unknown_clusters = sorted(set(clusters) - set(runtime.clusters))
    if unknown_clusters:
        raise ImportError_(
            "unknown_cluster",
            f"unknown {labels.noun(len(unknown_clusters), 'cluster')}: "
            + ", ".join(unknown_clusters),
        )
    known_receivers = set(runtime.registry.receivers) if runtime.registry else set()
    unknown_receivers = sorted(set(receivers) - known_receivers)
    if unknown_receivers:
        raise ImportError_(
            "unknown_receiver",
            f"unknown {labels.noun(len(unknown_receivers), 'receiver')}: "
            + ", ".join(unknown_receivers)
            + ". Register a receiver "
            "during installation before publishing to it.",
        )
    for receiver_id, form in (formats or {}).items():
        if receiver_id not in receivers:
            raise ImportError_("bad_input", f"format for a receiver not targeted: {receiver_id!r}")
        if form not in RECEIVER_FORMATS:
            raise ImportError_("bad_input", f"invalid receiver format: {form!r}")
    #
    # The answer to a request made here (C9b): the targets named when the
    # key was made are the certificate's, and the ones named now are added
    # to them - as a second import adds to a first. Read before the store is
    # written, because writing it takes the request's files away.
    #
    kept_clusters, kept_receivers, kept_formats = cert_request_state.request_targets(
        store, certificate_id
    )
    interface = interface or cert_request_state.request_is_interface(store, certificate_id)
    #
    # The interface certificate has no targets: not the ones named now, and
    # not the ones an entry of the same ID already had (B188). Refused before
    # the store is written.
    #
    if interface and (
        clusters
        or receivers
        or (existing is not None and (existing.clusters or existing.receivers))
    ):
        raise ImportError_(
            "bad_input",
            "the interface certificate has no targets; name no cluster or receiver, and "
            "import it under an ID no other certificate uses",
        )
    #
    # Exportable (B255): no targets, now or before, and one host - its key
    # leaves the manager, and a wildcard's answers for every name under it.
    # An entry that already carries the mark keeps it; one that does not
    # never gains it here.
    #
    exportable = exportable or bool(existing is not None and existing.exportable)
    if exportable and (
        clusters
        or receivers
        or interface
        or (existing is not None and (existing.clusters or existing.receivers))
    ):
        raise ImportError_(
            "bad_input",
            "an exportable certificate has no targets and does not serve the interface; "
            "name no cluster or receiver",
        )
    if exportable and any(name.startswith("*.") for name in (facts.common_name or "", *facts.sans)):
        raise ImportError_("bad_input", "an exportable certificate names one host; no wildcard")
    #
    # A target that has gone since the request was made is simply not one
    # any more; the request may have waited months for its signature.
    #
    kept_clusters = tuple(c for c in kept_clusters if c in runtime.clusters)
    kept_receivers = tuple(r for r in kept_receivers if r in known_receivers)
    kept_formats = {r: f for r, f in kept_formats.items() if r in kept_receivers}
    if kept_clusters or kept_receivers:
        clusters = [*kept_clusters, *(c for c in clusters if c not in kept_clusters)]
        receivers = [*kept_receivers, *(r for r in receivers if r not in kept_receivers)]
        formats = {**kept_formats, **(formats or {})}
    #
    # Somewhere to go: the same rule the web holds an import to, and the issuance
    # in the engine. A certificate with no target and neither mark is served to
    # nobody and exportable by nobody. An entry that already has targets keeps
    # them when a renewal names none.
    #
    if not (
        interface
        or exportable
        or clusters
        or receivers
        or (
            existing is not None
            and (
                existing.interface or existing.exportable or existing.clusters or existing.receivers
            )
        )
    ):
        raise ImportError_("bad_input", "at least one target (cluster or receiver) is required")
    #
    # The interface's name is asked before the store is written, as the other
    # ways in ask it before a CA is: `install` refuses a certificate that does
    # not name the interface, but only after the mark has moved to it, and the
    # certificate nginx still serves is then left without one.
    #
    if interface or (existing is not None and existing.interface):
        try:
            ui_interface.refuse_unserved(
                tuple(name for name in (facts.common_name, *facts.sans) if name)
            )
        except PublishError as exc:
            raise ImportError_(
                exc.code,
                str(exc),
                exit_code=exit_codes.REFUSED if exc.code == "bad_input" else exit_codes.CONFIG,
            ) from exc
    #
    # One step under the certificate lock: the ID is asked, the store written
    # and the entry registered. A publisher that reads under the lock then sees
    # the material and the entry together or neither, and not the instant the
    # old directory is aside and the new one not yet in.
    #
    try:
        with cert_registry.locked(lock_path):
            _refuse_held(
                certificate_id,
                material,
                policy=policy,
                live=live,
                store=store,
                ndes_profile=ndes_profile,
            )
            replaced = write_store(store, certificate_id, material)
            displaced = register(
                policy.certificate_registry,
                certificate_id,
                runtime,
                clusters=clusters,
                receivers=receivers,
                require_secure=require_secure,
                ndes_profile=ndes_profile,
                formats=formats,
                lock_path=None,
                interface=interface,
                exportable=exportable,
            )
    except cert_registry.RegistryError as exc:
        raise ImportError_(exc.code, str(exc), exit_code=exc.exit_code) from exc
    try:
        refreshed = load_runtime_config(policy, require_secure=require_secure)
    except ConfigError as exc:
        raise ImportError_("dependency_unavailable", str(exc), exit_code=exc.exit_code) from exc
    try:
        report = publish(
            refreshed,
            policy,
            only=[certificate_id],
            live=live,
            store=store,
            lock_path=lock_path,
            deployer=deployer,
            installer=installer,
            now=now,
        )
    except PublishError as exc:
        #
        # Stored and registered: the answer an unfinished publish has. It was
        # raised past the command, with no answer at all (26-10-29, C01).
        #
        report = unpublished(certificate_id, exc)
    marked = interface or bool(existing is not None and existing.interface)
    retired = cert_delete.retire_displaced_interface(
        displaced,
        served=ui_interface.served(report, certificate_id),
        policy=policy,
        certbot=certbot_binary(policy),
        require_secure=require_secure,
        store=store,
        lock_path=lock_path,
    )
    return ImportResult(
        certificate_id,
        facts,
        fingerprint,
        len(material.chain),
        replaced,
        report,
        interface=marked,
        exportable=exportable,
        retired=retired,
    )


def read_material(
    *,
    certificate: Path | None,
    key: Path | None,
    chain: Path | None,
    pkcs12: Path | None,
    password_file: Path | None,
    stored: str | None = None,
) -> Material:
    """Steps 1-2 from the operator's files, whichever form they come in.

    `stored` is the key an earlier import - or a signing request made here
    (C9b) - left in the store for this ID; with it, `--certificate` alone is
    the answer to that request, or a renewal on the same key, exactly as the
    interface's keyless upload is.
    """

    if pkcs12 is not None:
        if certificate is not None or key is not None or chain is not None:
            raise ImportError_(
                "bad_input", "--pkcs12 carries the certificate, key and chain; name nothing else"
            )
        certificates, keys = split_blocks(read_pkcs12(pkcs12, password_file))
        return assemble(certificates, keys)
    if certificate is None:
        raise ImportError_("bad_input", "--certificate is required without --pkcs12")
    if key is None and stored is None:
        raise ImportError_(
            "bad_input",
            "--key is required: no key is stored on the manager for this ID (a signing "
            "request made here, or an earlier import, would have left one)",
        )
    if password_file is not None:
        raise ImportError_("bad_input", "--password-file belongs to --pkcs12 only")
    text = _read(certificate, "the certificate")
    if chain is not None:
        text += "\n" + _read(chain, "the chain")
    certificates, found_in_certificate = split_blocks(text)
    if found_in_certificate:
        raise ImportError_(
            "bad_input", "the certificate file contains a private key; keep the key in --key"
        )
    if key is not None:
        _no_certificates, keys = split_blocks(_read(key, "the private key"))
    else:
        keys = [stored] if stored is not None else []
    return assemble_for(certificates, keys, pending=stored is not None and key is None)


def assemble_for(certificates: Sequence[str], keys: Sequence[str], *, pending: bool) -> Material:
    """`assemble`, with the refusal worded for the key the store already holds."""

    try:
        return assemble(certificates, keys)
    except ImportError_ as exc:
        if exc.code == "key_mismatch" and pending:
            raise ImportError_(
                "key_mismatch",
                "the certificate does not belong to the key the manager holds for this ID. "
                "For a signing request made here, upload the certificate the CA signed for "
                "the downloaded request; to replace the key, import the pair.",
            ) from exc
        raise


# - Authorities (B276) ------------------------------------------------------
#
# A CA certificate - or several: a root and its intermediates, or an old root
# beside its successor - that a cluster's pools verify their servers against.
# Imported like a certificate, from the same uploads, but there is no key:
# a file with one is refused, since a CA's key on this manager would be a
# secret nobody asked it to keep. Every certificate must say it is a CA.
#


def authority_blocks(certificates: Sequence[str], keys: Sequence[str]) -> tuple[str, ...]:
    """The CA certificates in a file, refused unless every one of them is a CA."""

    if keys:
        raise ImportError_(
            "bad_input",
            "the file holds a private key; a CA certificate is imported without its key",
        )
    if not certificates:
        raise ImportError_("bad_input", "no certificate was found")
    for certificate in certificates:
        text = _openssl(
            ["x509", "-noout", "-ext", "basicConstraints"],
            stdin=certificate,
            what="read a CA certificate",
        )
        if "CA:TRUE" not in text.replace(" ", ""):
            subject, _issuer = _names(certificate)
            raise ImportError_(
                "not_authority",
                f"{subject or 'a certificate in the file'} is not a CA certificate "
                "(basicConstraints CA:TRUE); a server certificate is imported with its key",
            )
    return tuple(dict.fromkeys(certificates))


def write_authority_store(store: Path, certificate_id: str, blocks: Sequence[str]) -> bool:
    """`<store>/<id>/fullchain.pem`, root-only, in one rename. True if replaced."""

    if not CERTIFICATE_ID.fullmatch(certificate_id):
        raise ImportError_("bad_input", f"invalid certificate ID: {certificate_id!r}")
    store.mkdir(mode=0o700, parents=True, exist_ok=True)
    final = store / certificate_id
    staging = Path(tempfile.mkdtemp(prefix=f".{certificate_id}.", dir=store))
    try:
        os.chmod(staging, 0o700)
        fd = os.open(staging / FULLCHAIN, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as handle:
            handle.write("".join(blocks))
            handle.flush()
            os.fsync(handle.fileno())
        _recover_replaced(store, certificate_id)
        replaced = final.is_dir()
        _swap_into_place(store, certificate_id, staging)
        return replaced
    except OSError as exc:
        shutil.rmtree(staging, ignore_errors=True)
        raise ImportError_(
            "dependency_unavailable",
            f"the import store could not be written: {exc}",
            exit_code=exit_codes.CONFIG,
        ) from exc


def _register_authority(
    path: Path,
    certificate_id: str,
    runtime: RuntimeConfig,
    *,
    clusters: Sequence[str],
    require_secure: bool,
    lock_path: Path | None,
) -> None:
    """The entry, kept clusters and new ones together, through the registry's one writer."""

    try:
        with _held(lock_path):
            document = cert_registry.read_document(path)
            certificates = dict(document.get("certificates") or {})
            existing = certificates.get(certificate_id)
            kept: list[str] = []
            if isinstance(existing, dict):
                kind = (existing.get("source") or {}).get("kind")
                if kind != AUTHORITY:
                    raise ImportError_(
                        "not_import",
                        f"{certificate_id!r} is registered as {kind!r}; a CA certificate needs "
                        "an ID of its own.",
                    )
                kept = [str(item) for item in existing.get("clusters") or ()]
            entry: dict[str, Any] = {"source": {"kind": AUTHORITY}}
            every = kept + [c for c in clusters if c not in kept]
            if every:
                entry["clusters"] = every
            certificates[certificate_id] = entry
            cert_registry.write(
                path,
                document=document,
                certificates=certificates,
                runtime=runtime,
                require_secure=require_secure,
            )
    except cert_registry.RegistryError as exc:
        raise ImportError_(
            exc.code,
            f"the CA file is in the store but the registry did not take {certificate_id!r}: "
            f"{str(exc).rstrip('.')}. Fix the targets and import again.",
            exit_code=exit_codes.after_a_change(exc.exit_code),
        ) from exc


def import_authority(
    *,
    certificate_id: str,
    blocks: Sequence[str],
    clusters: Sequence[str],
    policy: PathPolicy,
    runtime: RuntimeConfig,
    deployer: Deployer | None = None,
    live: Path = LETSENCRYPT_LIVE,
    store: Path = IMPORT_STORE,
    lock_path: Path = DEFAULT_LOCK_PATH,
    require_secure: bool = True,
    now: datetime | None = None,
) -> ImportResult:
    """Check, write, register and publish one CA file, as `import_certificate` does a pair."""

    if policy.certificate_registry is None:
        raise ImportError_(
            "dependency_unavailable",
            "no certificate registry is configured. Add certificate_registry to the "
            "runtime policy.",
            exit_code=exit_codes.CONFIG,
        )
    if not CERTIFICATE_ID.fullmatch(certificate_id):
        raise ImportError_("bad_input", f"invalid certificate ID: {certificate_id!r}")
    if (live / certificate_id).exists():
        raise ImportError_(
            "already_exists",
            f"certbot has a lineage named {certificate_id!r}; choose another ID.",
        )
    existing = runtime.registry.certificates.get(certificate_id) if runtime.registry else None
    if existing is not None and existing.source.kind != AUTHORITY:
        raise ImportError_(
            "not_import",
            f"{certificate_id!r} is registered as {existing.source.kind!r}; a CA certificate "
            "needs an ID of its own.",
        )
    unknown_clusters = sorted(set(clusters) - set(runtime.clusters))
    if unknown_clusters:
        raise ImportError_(
            "unknown_cluster",
            f"unknown {labels.noun(len(unknown_clusters), 'cluster')}: "
            + ", ".join(unknown_clusters),
        )
    moment = now or datetime.now(UTC)
    try:
        described = [describe(block) for block in blocks]
        fingerprint = leaf_fingerprint(blocks[0])
    except CertificateError as exc:
        raise ImportError_("bad_input", f"a CA certificate could not be read: {exc}") from exc
    if all(facts.not_after < moment for facts in described):
        latest = max(facts.not_after for facts in described)
        raise ImportError_(
            "expired",
            f"every certificate in the file has expired (the last "
            f"{latest.isoformat(timespec='seconds')}); nothing was imported",
        )
    try:
        with cert_registry.locked(lock_path):
            # Asked under the lock, as an import of a pair asks: material in the
            # store that is not an authority's own is a waiting signing request's
            # key or another way's, and writing the store would take it away.
            holder = cert_request_state.id_holder(
                certificate_id,
                registered_kind=None,
                live=live,
                store=store,
                request_root=policy.ndes.state_root if policy.ndes is not None else None,
                allow=(cert_request_state.HELD_BY_MATERIAL,) if existing is not None else (),
            )
            if holder is not None:
                raise ImportError_("already_exists", holder.message)
            replaced = write_authority_store(store, certificate_id, blocks)
            _register_authority(
                policy.certificate_registry,
                certificate_id,
                runtime,
                clusters=clusters,
                require_secure=require_secure,
                lock_path=None,
            )
    except cert_registry.RegistryError as exc:
        raise ImportError_(exc.code, str(exc), exit_code=exc.exit_code) from exc
    try:
        refreshed = load_runtime_config(policy, require_secure=require_secure)
    except ConfigError as exc:
        raise ImportError_("dependency_unavailable", str(exc), exit_code=exc.exit_code) from exc
    try:
        report = publish(
            refreshed,
            policy,
            only=[certificate_id],
            live=live,
            store=store,
            lock_path=lock_path,
            deployer=deployer,
            now=now,
        )
    except PublishError as exc:
        report = unpublished(certificate_id, exc)
    return ImportResult(
        certificate_id,
        described[0],
        fingerprint,
        len(blocks) - 1,
        replaced,
        report,
        authority=True,
    )


def read_authority_file(path: Path) -> tuple[str, ...]:
    """The CA certificates in a file on the manager, in any form an upload may take."""

    try:
        if path.stat().st_size > MAX_UPLOAD_BYTES:
            raise ImportError_("bad_input", f"the CA file is implausibly large: {path}")
        data = path.read_bytes()
    except FileNotFoundError:
        raise ImportError_("bad_input", f"the CA file does not exist: {path}") from None
    except OSError as exc:
        raise ImportError_("bad_input", f"the CA file could not be read: {exc}") from exc
    certificates, keys = read_bytes(data)
    return authority_blocks(certificates, keys)


def ndes_authority_blocks(servers: Iterable[NdesServer]) -> tuple[str, ...]:
    """The issuing CAs of every confirmed NDES server, each once (B385)."""

    return tuple(
        dict.fromkeys(
            block for server in servers for block in read_authority_file(server.issuing_ca)
        )
    )
