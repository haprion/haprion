"""A key made here and a CSR for somebody else to sign (C9b).

The fourth way to ask for a certificate on the *New certificate* page, and
the one that involves no CA the manager can talk to: the key is born on the
manager, the request leaves as text, and what comes back - from a purchase,
from an internal PKI without SCEP, from whoever signs things - is uploaded
as a certificate without a key. That upload is `cert_import`'s keyless
path: the key waits in the import store under the ID the request was made
for, and `stored_key` finds it there (B165).

What a request is
-----------------
1. the ID and the names are checked the way an issue checks them: the base
   name is the ID and the CN, a wildcard a SAN beside it;
2. the ID must be free everywhere a certificate can be - the registry, the
   certbot lineages, the import store, an NDES request in flight - because
   a key made under a name something else owns is a key nothing can use;
3. `openssl` makes the key and the CSR into a private staging directory,
   root-only, and the directory is renamed into the store in one step, with
   the request's own record and the targets the form named kept beside it;
4. the result carries the CSR, which is public by construction, and never
   the key.

Nothing is written before step 2 is through, and a request that fails in
step 3 leaves nothing behind.

Why the store and not the registry
----------------------------------
A request waiting on a signature is not a certificate: it has no material
to publish, and a registry entry without material refused every rollout to
the clusters it named (review 2026-09-17, finding 1). NDES requests moved
out of the registry for exactly that reason, and this follows them: the
request lives beside its key, `cert_inventory` lists it from there as
*pending*, and the registry names the certificate once the signed one has
been imported over the same directory - which `write_store` does in one
rename, taking the request's files away with it.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from haprion import atomic_file, cert_registry, exit_codes, labels, ui_interface
from haprion.cert_inventory import (
    IMPORT_STORE,
    LETSENCRYPT_LIVE,
    OPENSSL,
    OPENSSL_TIMEOUT,
    PRIVKEY,
)
from haprion.cert_publish import DEFAULT_LOCK_PATH, PublishError
from haprion.cert_request_state import (
    CSR,
    DEFAULT_KEY_TYPE,
    KEY_TYPES,
    RECORD,
    TARGETS,
    csr_is_pending,
)
from haprion.config import (
    CERTIFICATE_ID,
    HOSTNAME,
    RECEIVER_FORMATS,
    PathPolicy,
    RuntimeConfig,
)
from haprion.ndes_state import request_is_pending

OPERATION = "cert_request"
MAX_DOMAINS = 32


class RequestError(Exception):
    """The request is refused; nothing was written."""

    def __init__(self, code: str, message: str, *, exit_code: int = exit_codes.REFUSED):
        super().__init__(message)
        self.code = code
        self.exit_code = exit_code


@dataclass(frozen=True, slots=True)
class RequestResult:
    certificate_id: str
    domains: tuple[str, ...]
    key_type: str
    requested_at: str
    csr_pem: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.certificate_id,
            "domains": list(self.domains),
            "key_type": self.key_type,
            "requested_at": self.requested_at,
            "state": "pending",
            "csr_pem": self.csr_pem,
        }


# - Checking ---------------------------------------------------------------


def names(values: Sequence[str]) -> tuple[str, ...]:
    """The DNS names the certificate must cover: the CN first, no wildcard there.

    The same rule the NDES engine applies, restated here rather than imported
    from it because the two must not share an error type; a wildcard is a
    SAN beside its base name, never the CN.
    """

    if not values or len(values) > MAX_DOMAINS:
        raise RequestError("bad_input", f"specify between one and {MAX_DOMAINS} DNS names")
    checked: list[str] = []
    for value in values:
        if not isinstance(value, str):
            raise RequestError("bad_input", "invalid DNS name")
        bare = value[2:] if value.startswith("*.") else value
        if not HOSTNAME.fullmatch(bare):
            raise RequestError("bad_input", "invalid DNS name")
        if value not in checked:
            checked.append(value)
    if checked[0].startswith("*."):
        raise RequestError(
            "bad_input", "use the base DNS name as primary CN and list the wildcard as a SAN"
        )
    return tuple(checked)


def key_type(value: object) -> str:
    if value is None or value == "":
        return DEFAULT_KEY_TYPE
    if not isinstance(value, str) or value not in KEY_TYPES:
        raise RequestError("bad_input", "key type must be one of: " + ", ".join(KEY_TYPES))
    return value


def _refuse_taken(
    certificate_id: str,
    runtime: RuntimeConfig,
    *,
    live: Path,
    store: Path,
    request_root: Path | None,
) -> None:
    """Step 2: the ID is free everywhere, or the request says which place has it."""

    registered = runtime.registry.certificates.get(certificate_id) if runtime.registry else None
    if registered is not None:
        raise RequestError(
            "already_exists",
            f"{certificate_id!r} is already in the registry as {registered.source.kind!r}. "
            "Choose another name, or renew the certificate that exists.",
        )
    if (live / certificate_id).exists():
        raise RequestError(
            "already_exists",
            f"certbot has a lineage named {certificate_id!r}; choose another name",
        )
    if (store / certificate_id).exists():
        if csr_is_pending(store, certificate_id):
            raise RequestError(
                "already_exists",
                f"a signing request for {certificate_id!r} is already waiting; download it "
                "from the certificate's row, or delete the row to start over",
            )
        raise RequestError(
            "already_exists",
            f"the import store already holds material for {certificate_id!r}; choose another name",
        )
    if request_root is not None and request_is_pending(request_root, certificate_id):
        raise RequestError(
            "already_exists",
            f"an NDES enrollment for {certificate_id!r} is still waiting on its CA",
        )


# - Making -----------------------------------------------------------------


def _openssl(arguments: Sequence[str], *, what: str, cwd: Path) -> str:
    try:
        completed = subprocess.run(  # noqa: S603 - fixed binary, fixed arguments, private directory
            [OPENSSL, *arguments],
            capture_output=True,
            text=True,
            timeout=OPENSSL_TIMEOUT * 6,  # a 4096-bit RSA key can take a while on a small VM
            check=False,
            cwd=cwd,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RequestError(
            "dependency_unavailable",
            f"openssl could not {what}: {exc}",
            exit_code=exit_codes.CONFIG,
        ) from exc
    if completed.returncode != 0:
        detail = (completed.stderr or "").strip().splitlines()
        raise RequestError(
            "dependency_unavailable",
            f"openssl could not {what}: {detail[-1] if detail else ''}",
            exit_code=exit_codes.CONFIG,
        )
    return completed.stdout


def _write_private(path: Path, content: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())


def make_request(
    *,
    certificate_id: str,
    domains: Sequence[str],
    key_kind: str,
    clusters: Sequence[str],
    receivers: Sequence[str],
    formats: Mapping[str, str] | None,
    policy: PathPolicy,
    runtime: RuntimeConfig,
    live: Path = LETSENCRYPT_LIVE,
    store: Path = IMPORT_STORE,
    lock_path: Path = DEFAULT_LOCK_PATH,
    request_root: Path | None = None,
    now: datetime | None = None,
    interface: bool = False,
) -> RequestResult:
    """Steps 1-4: check, make the key and the CSR into the store, report the CSR."""

    if policy.certificate_registry is None:
        raise RequestError(
            "dependency_unavailable",
            "no certificate registry is configured. Add certificate_registry to the "
            "runtime policy.",
            exit_code=exit_codes.CONFIG,
        )
    if not CERTIFICATE_ID.fullmatch(certificate_id):
        raise RequestError("bad_input", f"invalid certificate ID: {certificate_id!r}")
    requested = names(domains)
    kind = key_type(key_kind)
    if interface and (clusters or receivers):
        raise RequestError(
            "bad_input", "the interface certificate has no targets; name no cluster or receiver"
        )
    if interface:
        try:
            ui_interface.refuse_unserved(requested)
        except PublishError as exc:
            raise RequestError(
                exc.code,
                str(exc),
                exit_code=exit_codes.REFUSED if exc.code == "bad_input" else exit_codes.CONFIG,
            ) from exc
    #
    # The targets are held to the same rule an import holds them to, before
    # anything is made: a request for a receiver that does not exist would
    # otherwise wait months for a signature and then refuse to publish.
    #
    unknown_clusters = sorted(set(clusters) - set(runtime.clusters))
    if unknown_clusters:
        raise RequestError(
            "unknown_cluster",
            f"unknown {labels.noun(len(unknown_clusters), 'cluster')}: "
            + ", ".join(unknown_clusters),
        )
    known_receivers = set(runtime.registry.receivers) if runtime.registry else set()
    unknown_receivers = sorted(set(receivers) - known_receivers)
    if unknown_receivers:
        raise RequestError(
            "unknown_receiver",
            f"unknown {labels.noun(len(unknown_receivers), 'receiver')}: "
            + ", ".join(unknown_receivers),
        )
    for receiver_id, form in (formats or {}).items():
        if receiver_id not in receivers:
            raise RequestError("bad_input", f"format for a receiver not targeted: {receiver_id!r}")
        if form not in RECEIVER_FORMATS:
            raise RequestError("bad_input", f"invalid receiver format: {form!r}")

    moment = (now or datetime.now(UTC)).replace(microsecond=0)
    try:
        with cert_registry.locked(lock_path):
            _refuse_taken(
                certificate_id, runtime, live=live, store=store, request_root=request_root
            )
            csr_pem = _make(
                store,
                certificate_id,
                requested,
                kind,
                record={
                    "certificate": certificate_id,
                    "domains": list(requested),
                    "key_type": kind,
                    "requested_at": moment.isoformat(timespec="seconds"),
                },
                targets={
                    "clusters": list(clusters),
                    "receivers": list(receivers),
                    "formats": dict(formats or {}),
                    #
                    # Read back by the import when the signed certificate
                    # arrives (B188): the request was made for the interface.
                    #
                    **({"interface": True} if interface else {}),
                },
            )
    except cert_registry.RegistryError as exc:
        raise RequestError(exc.code, str(exc), exit_code=exc.exit_code) from exc
    return RequestResult(
        certificate_id, requested, kind, moment.isoformat(timespec="seconds"), csr_pem
    )


def _make(
    store: Path,
    certificate_id: str,
    requested: Sequence[str],
    kind: str,
    *,
    record: Mapping[str, Any],
    targets: Mapping[str, Any],
) -> str:
    """Step 3: the key, the CSR and the two records into `<store>/<id>/`, in one rename."""

    try:
        store.mkdir(mode=0o700, parents=True, exist_ok=True)
        staging = Path(tempfile.mkdtemp(prefix=f".{certificate_id}.", dir=store))
    except OSError as exc:
        raise RequestError(
            "dependency_unavailable",
            f"the import store could not be written: {exc}",
            exit_code=exit_codes.CONFIG,
        ) from exc
    try:
        os.chmod(staging, 0o700)
        key_path = staging / PRIVKEY
        #
        # `-out` rather than stdout for the key: openssl creates the file
        # 0600 under the 0700 staging directory, and the key never passes
        # through this process's memory at all.
        #
        _openssl(
            ["genpkey", *KEY_TYPES[kind], "-out", str(key_path)],
            what="make the private key",
            cwd=staging,
        )
        os.chmod(key_path, 0o600)
        csr_pem = _openssl(
            [
                "req",
                "-new",
                "-key",
                str(key_path),
                "-subj",
                "/CN=" + requested[0],
                "-addext",
                "subjectAltName=" + ",".join("DNS:" + name for name in requested),
            ],
            what="make the signing request",
            cwd=staging,
        )
        _write_private(staging / CSR, csr_pem)
        _write_private(staging / RECORD, json.dumps(record))
        _write_private(staging / TARGETS, json.dumps(targets))
        atomic_file.move(staging, store / certificate_id)
    except (OSError, RequestError):
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return csr_pem
