"""The certificate publisher: registry in, every target out.

One certificate has one source and any number of targets. The source is where
the material is renewed or imported; a target is a place it is published to,
in the format that place reads. This module reads the registry (B135), reads
each certificate's material, checks it, and writes it to each of its targets -
idempotently, so a run that finds nothing new changes nothing and says so.

What replaces what
------------------
Two hand-built publishers did this before: one for the HAProxy wildcard with a
hardcoded lineage and file name, one for the PVE hosts with a list file. They
agreed on the checks (certificate parses, key matches, at least a week left)
and on `cmp` before write, and differed only in dispatch and format. That
difference is now a `Target`: a cluster gets one combined PEM, group-readable
by the pull account's group; a receiver gets `fullchain.pem` and `privkey.pem`
owned by its fetch account. The checks are one function.

Two kinds of source
-------------------
`acme` material is read from certbot's live directory, under the lineage the
registry names. `import` material is read from the import store, where the
import helper (C6) puts what the maintainer's CA signed; an entry whose store
directory does not exist yet is what a certificate published by hand before the
store existed looks like, and it is reported as skipped rather than treated as
an error - its published copy stays exactly as it is.

Atomicity and concurrency
-------------------------
Every file is written as a temporary in the target directory, fsynced, and
renamed over the old one, so a reader sees either the previous version or the
new one and never a partial file. A receiver's pair is two renames rather than
one; the reference receiver script verifies that the two files it fetched
belong together and tries again at the next timer if they do not, so the
window between the renames costs at most one fetch.

The whole run holds one lock. Unlike the per-cluster deploy lock it waits:
the publisher is idempotent, so a second caller that runs after the first
finishes does exactly the right thing, whereas a certbot renewal refused
because the interface was publishing at that moment would be a renewal lost
until the next day.

The key never leaves through this module's reports. Results name files,
fingerprints and outcomes, never contents.
"""

from __future__ import annotations

import contextlib
import fcntl
import os
import pwd
import stat
import subprocess
import tempfile
import time
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from haproxy_mgmt.cert_inventory import (
    FULLCHAIN,
    IMPORT_STORE,
    LETSENCRYPT_LIVE,
    OPENSSL,
    OPENSSL_TIMEOUT,
    PRIVKEY,
    Facts,
    describe,
    source_directory,
)
from haproxy_mgmt.certificates import (
    MAX_CERTIFICATE_BYTES,
    CertificateError,
    certificate_path,
    leaf_block,
    leaf_fingerprint,
)
from haproxy_mgmt.config import (
    PathPolicy,
    Receiver,
    RegisteredCertificate,
    RuntimeConfig,
)

DEFAULT_LOCK_PATH = Path("/run/haproxy-mgmt/locks/cert-publish.lock")
LOCK_WAIT_SECONDS = 120

#
# The same margin the hand-built publishers used: a certificate this close to
# expiry is not published, because publishing it would replace a working file
# with one about to fail, and certbot renews thirty days out - so reaching
# this margin means renewal has been failing for weeks and needs a person.
#
MIN_REMAINING = timedelta(days=7)

#
# The cluster PEM's owner. A name rather than a literal so a test that cannot
# become root can publish as itself and still exercise every other check.
#
ROOT_UID = 0
CLUSTER_MODE = 0o640
RECEIVER_MODE = 0o600

type SourceStatus = Literal["published", "unchanged", "skipped", "failed"]


class PublishError(Exception):
    """One certificate could not be read, checked or written."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class Material:
    """One certificate's bytes and what was learned about them. Never reported."""

    certificate_id: str
    fullchain: bytes
    privkey: bytes
    facts: Facts
    fingerprint: str


@dataclass(frozen=True, slots=True)
class Target:
    """One place a certificate is published to, in that place's format."""

    kind: Literal["cluster", "receiver"]
    name: str
    directory: Path
    uid: int
    gid: int
    mode: int

    def files(self, certificate_id: str, material: Material) -> tuple[tuple[Path, bytes], ...]:
        """The files this target reads, with their contents.

        A cluster reads one combined PEM - HAProxy's own format, key first,
        then the chain - named by the certificate ID. A receiver reads the two
        files certbot writes, under fixed names, in a directory of its own.
        """

        if self.kind == "cluster":
            path = certificate_path(self.directory, certificate_id)
            return ((path, material.privkey + material.fullchain),)
        return (
            (self.directory / FULLCHAIN, material.fullchain),
            (self.directory / PRIVKEY, material.privkey),
        )


@dataclass(frozen=True, slots=True)
class TargetResult:
    kind: str
    name: str
    changed: bool

    def as_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "name": self.name, "changed": self.changed}


@dataclass(frozen=True, slots=True)
class CertificateResult:
    certificate_id: str
    status: SourceStatus
    targets: tuple[TargetResult, ...] = ()
    fingerprint: str | None = None
    not_after: datetime | None = None
    error: tuple[str, str] | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.certificate_id,
            "status": self.status,
            "fingerprint_sha256": self.fingerprint,
            "not_after": (
                self.not_after.strftime("%Y-%m-%dT%H:%M:%SZ") if self.not_after else None
            ),
            "targets": [target.as_dict() for target in self.targets],
            "error": ({"code": self.error[0], "message": self.error[1]} if self.error else None),
        }


@dataclass(frozen=True, slots=True)
class DeployResult:
    cluster: str
    exit_code: int

    def as_dict(self) -> dict[str, Any]:
        return {"cluster": self.cluster, "exit_code": self.exit_code}


@dataclass(frozen=True, slots=True)
class Report:
    certificates: tuple[CertificateResult, ...]
    changed_clusters: tuple[str, ...]
    deployments: tuple[DeployResult, ...] = ()

    @property
    def failed(self) -> tuple[CertificateResult, ...]:
        return tuple(entry for entry in self.certificates if entry.status == "failed")

    @property
    def skipped(self) -> tuple[CertificateResult, ...]:
        return tuple(entry for entry in self.certificates if entry.status == "skipped")

    def as_dict(self) -> dict[str, Any]:
        return {
            "certificates": [entry.as_dict() for entry in self.certificates],
            "changed_clusters": list(self.changed_clusters),
            "deployments": [deployment.as_dict() for deployment in self.deployments],
        }


#
# Reading and checking
#


def _read_file(path: Path, what: str) -> bytes:
    try:
        if path.lstat().st_size > MAX_CERTIFICATE_BYTES:
            raise PublishError("invalid_certificate", f"{what} is implausibly large: {path}")
        return path.read_bytes()
    except FileNotFoundError as exc:
        raise PublishError("source_missing", f"{what} is missing: {path}") from exc
    except OSError as exc:
        raise PublishError("source_missing", f"{what} could not be read: {path}: {exc}") from exc


def _public_key_digest(argv: Sequence[str], material: bytes, what: str) -> bytes:
    try:
        completed = subprocess.run(  # noqa: S603 - fixed path, no caller argv
            argv,
            input=material,
            capture_output=True,
            timeout=OPENSSL_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PublishError("invalid_certificate", f"openssl could not read the {what}") from exc
    if completed.returncode != 0 or not completed.stdout:
        raise PublishError("invalid_certificate", f"openssl could not read the {what}")
    return completed.stdout


def key_matches(fullchain: bytes, privkey: bytes) -> bool:
    """Whether the private key belongs to the leaf. RSA and ECDSA alike.

    Compared as DER-encoded public keys, which is what both the hand-built
    publishers did; a mismatch here is a renewal that wrote one file and not
    the other, and publishing it would take a working service down.
    """

    from_certificate = _public_key_digest(
        [OPENSSL, "x509", "-pubkey", "-noout"], fullchain, "certificate"
    )
    certificate_der = _public_key_digest(
        [OPENSSL, "pkey", "-pubin", "-outform", "DER"], from_certificate, "certificate"
    )
    key_der = _public_key_digest([OPENSSL, "pkey", "-pubout", "-outform", "DER"], privkey, "key")
    return certificate_der == key_der


def read_material(
    entry: RegisteredCertificate,
    *,
    live: Path = LETSENCRYPT_LIVE,
    store: Path = IMPORT_STORE,
    now: datetime | None = None,
) -> Material:
    """The certificate's bytes, checked the way both old publishers checked them."""

    directory = source_directory(entry, live=live, store=store)
    fullchain = _read_file(directory / FULLCHAIN, "the certificate chain")
    privkey = _read_file(directory / PRIVKEY, "the private key")

    try:
        text = fullchain.decode("ascii")
        leaf = leaf_block(text)
        fingerprint = leaf_fingerprint(text)
        facts = describe(leaf)
    except (UnicodeDecodeError, CertificateError) as exc:
        raise PublishError("invalid_certificate", f"{directory / FULLCHAIN}: {exc}") from exc

    remaining = facts.not_after - (now or datetime.now(UTC))
    if remaining < MIN_REMAINING:
        raise PublishError(
            "certificate_expiring",
            f"the certificate expires {facts.not_after.strftime('%Y-%m-%d')}, "
            f"less than {MIN_REMAINING.days} days away; not published",
        )
    if not key_matches(fullchain, privkey):
        raise PublishError("key_mismatch", "the private key does not belong to the certificate")

    return Material(
        certificate_id=entry.certificate_id,
        fullchain=fullchain,
        privkey=privkey,
        facts=facts,
        fingerprint=fingerprint,
    )


#
# Targets
#


def _account(name: str, what: str) -> tuple[int, int]:
    try:
        record = pwd.getpwnam(name)
    except KeyError as exc:
        raise PublishError("target_missing", f"{what}: account {name!r} does not exist") from exc
    return record.pw_uid, record.pw_gid


def cluster_target(certificate_root: Path, cluster_id: str) -> Target:
    """The distribution directory, owned by root and readable by the pull group.

    The group is the directory's own: whoever may list the directory may read
    the files in it, and that group was chosen when the directory was created
    by the person who created the pull account. Reading it back here keeps one
    decision in one place rather than repeating the group name in the policy.
    """

    try:
        metadata = certificate_root.lstat()
    except OSError as exc:
        raise PublishError(
            "target_missing", f"certificate root {certificate_root} is missing: {exc}"
        ) from exc
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise PublishError(
            "target_missing", f"certificate root {certificate_root} is not a directory"
        )
    return Target(
        kind="cluster",
        name=cluster_id,
        directory=certificate_root,
        uid=ROOT_UID,
        gid=metadata.st_gid,
        mode=CLUSTER_MODE,
    )


def receiver_target(receiver: Receiver) -> Target:
    """A receiver's directory, which registration (root work) created.

    Not created here. The directory, the account and the fetch key are what
    let anyone fetch key material at all, and they are made together by whoever
    registers the receiver; a publisher that made directories on its own would
    quietly turn a typo in the registry into a new place key material lands.
    """

    uid, gid = _account(receiver.owner, f"receiver {receiver.receiver_id}")
    try:
        metadata = receiver.path.lstat()
    except OSError as exc:
        raise PublishError(
            "target_missing",
            f"receiver {receiver.receiver_id}: directory {receiver.path} is missing: {exc}",
        ) from exc
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise PublishError(
            "target_missing",
            f"receiver {receiver.receiver_id}: {receiver.path} is not a directory",
        )
    #
    # The directory may belong to root or to the account; the files in it
    # belong to the account. Root-owned is the better of the two - the fetch
    # account can read what is published to it and cannot replace it - and it
    # is what a directory made by hand as root looks like. What is refused is
    # a directory anyone else could write into, which would let a third party
    # put key material where a receiver fetches from.
    #
    if metadata.st_uid not in (0, uid):
        owner = _owner_name(metadata.st_uid)
        raise PublishError(
            "target_missing",
            f"receiver {receiver.receiver_id}: {receiver.path} is owned by {owner}, "
            f"not by root or {receiver.owner}",
        )
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        raise PublishError(
            "target_missing",
            f"receiver {receiver.receiver_id}: {receiver.path} is group- or world-writable",
        )
    return Target(
        kind="receiver",
        name=receiver.receiver_id,
        directory=receiver.path,
        uid=uid,
        gid=gid,
        mode=RECEIVER_MODE,
    )


def _owner_name(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def targets_for(
    entry: RegisteredCertificate, runtime: RuntimeConfig, policy: PathPolicy
) -> list[Target]:
    """Every target the registry names for this certificate, resolved before any write."""

    registry = runtime.registry
    assert registry is not None  # noqa: S101 - callers check; stated for the reader
    targets: list[Target] = []
    for cluster_id in entry.clusters:
        if policy.certificate_root is None:
            raise PublishError(
                "dependency_unavailable",
                "no certificate root is configured. Add certificate_root to the runtime policy.",
            )
        targets.append(cluster_target(policy.certificate_root, cluster_id))
    for receiver_id in entry.receivers:
        targets.append(receiver_target(registry.receivers[receiver_id]))
    return targets


#
# Writing
#


def _current(path: Path) -> bytes | None:
    try:
        return path.read_bytes()
    except FileNotFoundError:
        return None
    except OSError:
        #
        # Unreadable is not "unchanged". Treated as absent so the file is
        # rewritten, which is the state the registry says it should be in.
        #
        return None


def write_file(path: Path, content: bytes, *, uid: int, gid: int, mode: int) -> bool:
    """Replace `path` with `content` atomically; False when it already matched.

    The temporary is created in the target directory so the rename is within
    one filesystem, owned and moded before it has any content a reader could
    want, and fsynced before the rename so a crash leaves either the old file
    or the complete new one. The directory is fsynced after, so the rename
    itself is durable.
    """

    if _current(path) == content:
        return False

    handle, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchown(handle, uid, gid)
        os.fchmod(handle, mode)
        with os.fdopen(handle, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(temporary)
        raise
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return True


def publish_to(targets: Sequence[Target], material: Material) -> tuple[TargetResult, ...]:
    """Write every file the targets read, each path once, and say which targets changed.

    Clusters share one distribution directory, so two clusters naming the
    same certificate read the same file. It is written once, and the change
    belongs to every target that reads it - otherwise the second cluster
    would see "unchanged" and never be rolled out.
    """

    written: dict[Path, bool] = {}
    for target in targets:
        for path, content in target.files(material.certificate_id, material):
            if path in written:
                continue
            try:
                written[path] = write_file(
                    path, content, uid=target.uid, gid=target.gid, mode=target.mode
                )
            except OSError as exc:
                raise PublishError("write_failed", f"{path}: {exc}") from exc
    return tuple(
        TargetResult(
            target.kind,
            target.name,
            any(written[path] for path, _ in target.files(material.certificate_id, material)),
        )
        for target in targets
    )


#
# The run
#


@contextmanager
def publish_lock(path: Path = DEFAULT_LOCK_PATH, *, wait: int | None = None) -> Iterator[None]:
    """Hold the publisher's lock, waiting a bounded time for another run to finish."""

    wait = LOCK_WAIT_SECONDS if wait is None else wait
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    handle = os.open(path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
    try:
        deadline = datetime.now(UTC) + timedelta(seconds=wait)
        while True:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError:
                if datetime.now(UTC) >= deadline:
                    raise PublishError(
                        "operation_locked",
                        f"another publish has held {path} for more than {wait} seconds",
                    ) from None
                time.sleep(0.5)
        yield
    finally:
        os.close(handle)


def _select(runtime: RuntimeConfig, only: Sequence[str] | None) -> list[RegisteredCertificate]:
    registry = runtime.registry
    if registry is None:
        raise PublishError(
            "dependency_unavailable",
            "no certificate registry is configured. Add certificate_registry to the "
            "runtime policy.",
        )
    if only is None:
        return list(registry.certificates.values())
    unknown = sorted(set(only) - set(registry.certificates))
    if unknown:
        raise PublishError("bad_input", f"not in the certificate registry: {', '.join(unknown)}")
    return [registry.certificates[certificate_id] for certificate_id in only]


type Deployer = Callable[[str], int]


def publish(
    runtime: RuntimeConfig,
    policy: PathPolicy,
    *,
    only: Sequence[str] | None = None,
    live: Path = LETSENCRYPT_LIVE,
    store: Path = IMPORT_STORE,
    lock_path: Path = DEFAULT_LOCK_PATH,
    deployer: Deployer | None = None,
    now: datetime | None = None,
) -> Report:
    """Publish every selected certificate to every target it names.

    Per certificate, all of its targets are resolved and its material checked
    before its first file is written, so a certificate that cannot be
    published leaves nothing half-done. Certificates are independent: one
    failing does not stop the next, and the report says which did what.

    With a deployer, every cluster that received a new version is rolled out
    afterwards, once, after all publishing is done - so a certificate that
    reaches two clusters costs two rollouts, not four.
    """

    entries = _select(runtime, only)
    results: list[CertificateResult] = []
    changed_clusters: list[str] = []

    with publish_lock(lock_path):
        for entry in entries:
            source = source_directory(entry, live=live, store=store)
            if entry.source.kind == "import" and not source.is_dir():
                results.append(
                    CertificateResult(
                        entry.certificate_id,
                        "skipped",
                        error=(
                            "source_missing",
                            f"no imported material under {source}; the published copy is "
                            "left as it is",
                        ),
                    )
                )
                continue
            try:
                targets = targets_for(entry, runtime, policy)
                material = read_material(entry, live=live, store=store, now=now)
                outcomes = publish_to(targets, material)
            except PublishError as exc:
                results.append(
                    CertificateResult(entry.certificate_id, "failed", error=(exc.code, str(exc)))
                )
                continue
            for outcome in outcomes:
                if (
                    outcome.kind == "cluster"
                    and outcome.changed
                    and outcome.name not in changed_clusters
                ):
                    changed_clusters.append(outcome.name)
            results.append(
                CertificateResult(
                    entry.certificate_id,
                    "published" if any(o.changed for o in outcomes) else "unchanged",
                    targets=outcomes,
                    fingerprint=material.fingerprint,
                    not_after=material.facts.not_after,
                )
            )

    deployments: list[DeployResult] = []
    if deployer is not None:
        for cluster_id in changed_clusters:
            deployments.append(DeployResult(cluster_id, deployer(cluster_id)))

    return Report(
        certificates=tuple(results),
        changed_clusters=tuple(changed_clusters),
        deployments=tuple(deployments),
    )
