"""Importing a certificate somebody else issued: a pair in, a registered source out.

The second of the two ways a certificate reaches the registry (§14.3, B134).
ACME goes through certbot; everything else - an internal PKI, a purchased
certificate, a wildcard exported from a Windows CA - comes in here, as
material the maintainer already holds. The import store
(`/etc/haproxy-manager/certificates/<id>/`) is laid out like certbot's
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
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from haproxy_mgmt import cert_registry
from haproxy_mgmt.cert_inventory import (
    FULLCHAIN,
    IMPORT_STORE,
    LETSENCRYPT_LIVE,
    OPENSSL,
    OPENSSL_TIMEOUT,
    PRIVKEY,
    Facts,
    describe,
)
from haproxy_mgmt.cert_publish import DEFAULT_LOCK_PATH, Deployer, Report, publish
from haproxy_mgmt.certificates import (
    DELIMITER,
    MAX_CERTIFICATE_BYTES,
    CertificateError,
    leaf_fingerprint,
)
from haproxy_mgmt.config import (
    CERTIFICATE_ID,
    RECEIVER_FORMATS,
    ConfigError,
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


class ImportError_(Exception):  # noqa: N801 - `ImportError` is Python's; the trailing mark says so
    """The import is refused; nothing was written."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        exit_code: int = 65,
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

    def as_dict(self) -> dict[str, Any]:
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


def _read(path: Path, what: str) -> str:
    try:
        if path.stat().st_size > MAX_CERTIFICATE_BYTES:
            raise ImportError_("bad_input", f"{what} is implausibly large: {path}")
        return path.read_text(encoding="ascii", errors="strict")
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
            "dependency_unavailable", f"openssl could not {what}: {exc}", exit_code=78
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


def read_pkcs12(path: Path, password_file: Path | None) -> str:
    """Everything in a PKCS#12 as PEM: the key unencrypted, the certificates as they are.

    The password is read by openssl from the file - never from argv, where
    every user on the host could read it. OpenSSL 3 refuses the RC2-40 that
    older Windows exports use unless told `-legacy`; tried second, so a
    modern file is read the modern way.
    """

    if not path.is_file():
        raise ImportError_("bad_input", f"the PKCS#12 file does not exist: {path}")
    if path.stat().st_size > MAX_CERTIFICATE_BYTES:
        raise ImportError_("bad_input", f"the PKCS#12 file is implausibly large: {path}")
    if password_file is not None and not password_file.is_file():
        raise ImportError_("bad_input", f"the password file does not exist: {password_file}")
    passin = f"file:{password_file}" if password_file is not None else "pass:"
    base = ["pkcs12", "-in", str(path), "-nodes", "-passin", passin]
    last = ""
    for extra in ((), ("-legacy",)):
        try:
            completed = subprocess.run(  # noqa: S603 - fixed binary, paths from the operator
                [OPENSSL, *base, *extra],
                capture_output=True,
                text=True,
                timeout=OPENSSL_TIMEOUT,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ImportError_(
                "dependency_unavailable", f"openssl could not read the PKCS#12: {exc}", exit_code=78
            ) from exc
        if completed.returncode == 0:
            return completed.stdout
        lines = (completed.stderr or "").strip().splitlines()
        last = lines[-1] if lines else ""
        if "unsupported" not in last.lower() and "legacy" not in last.lower():
            break
    raise ImportError_("bad_input", f"openssl could not read the PKCS#12: {last}")


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
    leaf = leaves[0]
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
        replaced = final.is_dir()
        previous: Path | None = None
        if replaced:
            previous = store / f".{certificate_id}.replaced"
            shutil.rmtree(previous, ignore_errors=True)
            os.rename(final, previous)
        os.rename(staging, final)
        if previous is not None:
            shutil.rmtree(previous, ignore_errors=True)
        return replaced
    except OSError as exc:
        shutil.rmtree(staging, ignore_errors=True)
        raise ImportError_(
            "dependency_unavailable", f"the import store could not be written: {exc}", exit_code=78
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
) -> None:
    """The entry, through the one writer the registry has.

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
    """

    try:
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
                raise ImportError_(
                    "not_import",
                    f"{certificate_id!r} is registered as {kind!r}; its material is not "
                    "imported. Choose another ID.",
                )
            kept_clusters = [str(item) for item in existing.get("clusters") or ()]
            kept_receivers, kept_formats = cert_registry.named_receivers(existing)
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
            f"the material is in the store but the registry did not take {certificate_id!r}: "
            f"{exc} Fix the targets and import again.",
            exit_code=exc.exit_code,
        ) from exc


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
) -> ImportResult:
    """Steps 3-6: check, write, register, publish."""

    if policy.certificate_registry is None:
        raise ImportError_(
            "dependency_unavailable",
            "no certificate registry is configured. Add certificate_registry to the "
            "runtime policy.",
            exit_code=78,
        )
    if not CERTIFICATE_ID.fullmatch(certificate_id):
        raise ImportError_("bad_input", f"invalid certificate ID: {certificate_id!r}")
    if (live / certificate_id).exists():
        raise ImportError_(
            "already_exists",
            f"certbot has a lineage named {certificate_id!r}; an imported certificate "
            "cannot share the ID. Choose another.",
        )
    facts, fingerprint = check(material, now=now)
    #
    # The ID and the targets are checked against the registry before the store
    # is written, so a wrong one leaves nothing behind; the entry is written
    # after the store, so the registry never names material that is not there.
    #
    existing = runtime.registry.certificates.get(certificate_id) if runtime.registry else None
    if existing is not None and existing.source.kind != "import":
        raise ImportError_(
            "not_import",
            f"{certificate_id!r} is registered as {existing.source.kind!r}; its material is "
            "not imported. Choose another ID.",
        )
    unknown_clusters = sorted(set(clusters) - set(runtime.clusters))
    if unknown_clusters:
        raise ImportError_("unknown_cluster", "unknown cluster(s): " + ", ".join(unknown_clusters))
    known_receivers = set(runtime.registry.receivers) if runtime.registry else set()
    unknown_receivers = sorted(set(receivers) - known_receivers)
    if unknown_receivers:
        raise ImportError_(
            "unknown_receiver",
            "unknown receiver(s): " + ", ".join(unknown_receivers) + ". Register a receiver "
            "during installation before publishing to it.",
        )
    for receiver_id, form in (formats or {}).items():
        if receiver_id not in receivers:
            raise ImportError_("bad_input", f"format for a receiver not targeted: {receiver_id!r}")
        if form not in RECEIVER_FORMATS:
            raise ImportError_("bad_input", f"invalid receiver format: {form!r}")
    replaced = write_store(store, certificate_id, material)
    register(
        policy.certificate_registry,
        certificate_id,
        runtime,
        clusters=clusters,
        receivers=receivers,
        require_secure=require_secure,
        ndes_profile=ndes_profile,
        formats=formats,
    )
    try:
        refreshed = load_runtime_config(policy, require_secure=require_secure)
    except ConfigError as exc:
        raise ImportError_("dependency_unavailable", str(exc), exit_code=exc.exit_code) from exc
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
    return ImportResult(certificate_id, facts, fingerprint, len(material.chain), replaced, report)


def read_material(
    *,
    certificate: Path | None,
    key: Path | None,
    chain: Path | None,
    pkcs12: Path | None,
    password_file: Path | None,
) -> Material:
    """Steps 1-2 from the operator's files, whichever form they come in."""

    if pkcs12 is not None:
        if certificate is not None or key is not None or chain is not None:
            raise ImportError_(
                "bad_input", "--pkcs12 carries the certificate, key and chain; name nothing else"
            )
        certificates, keys = split_blocks(read_pkcs12(pkcs12, password_file))
        return assemble(certificates, keys)
    if certificate is None or key is None:
        raise ImportError_(
            "bad_input", "--certificate and --key are both required without --pkcs12"
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
    _no_certificates, keys = split_blocks(_read(key, "the private key"))
    return assemble(certificates, keys)
