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
import os
import pwd
import secrets
import stat
import string
import subprocess
import tempfile
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
    PASSWORD_SUFFIX,
    PKCS12_SUFFIX,
    PRIVKEY,
    Facts,
    describe,
    receiver_directory,
    source_directory,
)
from haproxy_mgmt.cert_lock import DEFAULT_LOCK_PATH as DEFAULT_LOCK_PATH
from haproxy_mgmt.cert_lock import LOCK_WAIT_SECONDS as LOCK_WAIT_SECONDS
from haproxy_mgmt.cert_lock import hold
from haproxy_mgmt.certificates import (
    MAX_CERTIFICATE_BYTES,
    CertificateError,
    certificate_path,
    leaf_block,
    leaf_fingerprint,
)
from haproxy_mgmt.config import (
    DEFAULT_RECEIVER_FORMAT,
    PathPolicy,
    Receiver,
    RegisteredCertificate,
    RuntimeConfig,
)

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
    """One certificate could not be read, checked or written.

    `written` is what was written before or despite the failure. A cluster
    among them has a new file its nodes have not been told about, and that
    does not stop being true because a receiver's directory refused a write.
    """

    def __init__(self, code: str, message: str, *, written: tuple[TargetResult, ...] = ()):
        super().__init__(message)
        self.code = code
        self.written = written


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
    #
    # Receivers only (B138, B159). `transport` says how the receiver fetches,
    # and `form` makes a target that wants a PKCS#12 bundle one field rather
    # than a second kind of Target. Neither refuses anything: what an https
    # receiver may hold is the operator's call (B164).
    #
    transport: str | None = None
    form: str = DEFAULT_RECEIVER_FORMAT

    def files(self, certificate_id: str, material: Material) -> tuple[tuple[Path, bytes], ...]:
        """The files this target reads, with their contents.

        A cluster reads one combined PEM - HAProxy's own format, key first,
        then the chain - named by the certificate ID. A receiver reads the two
        files certbot writes, under fixed names, in the directory its layout
        gives it.

        A PKCS#12 target has no answer here: its bundle is salted, so it is
        built and compared by `publish_bundle` rather than by content.
        """

        if self.kind == "cluster":
            path = certificate_path(self.directory, certificate_id)
            return ((path, material.privkey + material.fullchain),)
        if self.form == "pkcs12":
            return ()
        chain, key = self.directory / FULLCHAIN, self.directory / PRIVKEY
        return ((chain, material.fullchain), (key, material.privkey))


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


def _checked_directory(path: Path, receiver: Receiver, uid: int) -> os.stat_result:
    """The one set of rules a directory key material is written into must meet."""

    try:
        metadata = path.lstat()
    except OSError as exc:
        raise PublishError(
            "target_missing",
            f"receiver {receiver.receiver_id}: directory {path} is missing: {exc}",
        ) from exc
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise PublishError(
            "target_missing",
            f"receiver {receiver.receiver_id}: {path} is not a directory",
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
            f"receiver {receiver.receiver_id}: {path} is owned by {owner}, "
            f"not by root or {receiver.owner}",
        )
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        raise PublishError(
            "target_missing",
            f"receiver {receiver.receiver_id}: {path} is group- or world-writable",
        )
    return metadata


def receiver_target(
    receiver: Receiver, certificate_id: str, *, form: str = DEFAULT_RECEIVER_FORMAT
) -> Target:
    """A receiver's directory, which registration (root work) created.

    The registered directory is not created here. It, the account and the
    fetch key are what let anyone fetch key material at all, and they are made
    together by whoever registers the receiver; a publisher that made those on
    its own would quietly turn a typo in the registry into a new place key
    material lands.

    The per-certificate sub-directory under it is a different thing and is
    created here (B138). Which certificates a registered receiver holds is
    exactly what the interface may change, so it is the publisher that has to
    make room for one - and the room it makes is inside a directory root
    already decided on, named after a certificate the registry already has.
    """

    uid, gid = _account(receiver.owner, f"receiver {receiver.receiver_id}")
    registered = _checked_directory(receiver.path, receiver, uid)
    directory = receiver_directory(receiver, certificate_id)
    if directory != receiver.path and not directory.exists():
        try:
            #
            # Owned like its parent - root in an installation, the calling
            # account in a test that cannot become root - and traversable by
            # the fetch account alone. The files inside stay 0600, so this
            # mode decides who may see that the certificate is there at all.
            #
            directory.mkdir(mode=0o750)
            # mkdir() is subject to the umask; this is the mode that is meant.
            # Mode before owner, as in write_file: the directory is still ours.
            os.chmod(directory, 0o750)  # noqa: S103 - root:fetch-account, files stay 0600
            os.chown(directory, registered.st_uid, gid)
        except OSError as exc:
            raise PublishError(
                "write_failed",
                f"receiver {receiver.receiver_id}: {directory} could not be created: {exc}",
            ) from exc
    _checked_directory(directory, receiver, uid)
    return Target(
        kind="receiver",
        name=receiver.receiver_id,
        directory=directory,
        uid=uid,
        gid=gid,
        mode=RECEIVER_MODE,
        transport=receiver.transport,
        form=form,
    )


def _owner_name(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def prune_receiver_directory(receiver: Receiver, certificate_id: str) -> None:
    """Take away a per-certificate directory once its files are gone.

    Here because this module is what creates it. Best effort and silent: an
    empty directory holds nothing an operator or a receiver needs to hear
    about, and it is exactly what an `sftp` receiver's chroot would otherwise
    keep showing as a certificate it no longer has. Anything still in it - a
    file the receiver's own script left - is reason enough to leave it alone,
    and `rmdir` refusing a directory that is not empty is that decision.
    """

    directory = receiver_directory(receiver, certificate_id)
    if directory == receiver.path:
        return
    with contextlib.suppress(OSError):
        directory.rmdir()


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
        targets.append(
            receiver_target(
                registry.receivers[receiver_id],
                entry.certificate_id,
                form=entry.format_for(receiver_id),
            )
        )
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


def write_file(
    path: Path, content: bytes, *, uid: int, gid: int, mode: int, compare: bool = True
) -> bool:
    """Replace `path` with `content` atomically; False when it already matched.

    `compare` is false for a PKCS#12 bundle, whose bytes differ every time it
    is built from the same certificate; that target decides for itself whether
    anything changed, and by then the answer is yes.

    The temporary is created in the target directory so the rename is within
    one filesystem, moded and owned before it has any content a reader could
    want, and fsynced before the rename so a crash leaves either the old file
    or the complete new one. The directory is fsynced after, so the rename
    itself is durable.

    Mode first, then owner. Changing the mode of a file needs ownership of it
    or CAP_FOWNER, and the worker's sandbox grants root CAP_CHOWN alone: once
    the file belongs to a receiver's fetch account, root inside that sandbox
    may no longer chmod it. Found on the machine when the first receiver file
    ended `write_failed: Operation not permitted`; a cluster file never showed
    it because its owner stays root.
    """

    if compare and _current(path) == content:
        return False

    handle, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(handle, mode)
        os.fchown(handle, uid, gid)
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


#
# PKCS#12 (B159)
#


def _memfd(name: str, content: bytes) -> int:
    handle = os.memfd_create(name)
    os.write(handle, content)
    os.lseek(handle, 0, os.SEEK_SET)
    return handle


def _openssl(argv: Sequence[str], *, pass_fds: Sequence[int] = ()) -> bytes | None:
    """Run openssl and return what it wrote, or None if it could not.

    The password is never in `argv`: `ps` shows everyone the argument list,
    so openssl is pointed at the password file that is published beside the
    bundle anyway (B159), and reads the first line of it itself.
    """

    try:
        completed = subprocess.run(  # noqa: S603 - fixed path, arguments built here
            list(argv),
            capture_output=True,
            timeout=OPENSSL_TIMEOUT,
            check=False,
            pass_fds=tuple(pass_fds),
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0 or not completed.stdout:
        return None
    return completed.stdout


def new_password() -> str:
    """A bundle's password: letters and digits, long enough to be one (B159).

    No punctuation, deliberately. This string is read back out of a file by
    whatever script the receiver's operator wrote, and every character that
    needs quoting somewhere is a way for that script to install the wrong
    password and report success.
    """

    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(32))


def bundle_bytes(material: Material, password_path: Path) -> bytes:
    """The PKCS#12 bundle, built without the key ever reaching a file.

    The key and the chain are handed to openssl as anonymous memory the child
    inherits, not as temporary files: a private key written to a temporary
    directory is a private key that outlives a crash, and the point of this
    module is that material only lands where the registry says it goes.
    """

    key_fd = _memfd("privkey", material.privkey)
    chain_fd = _memfd("fullchain", material.fullchain)
    try:
        bundle = _openssl(
            [
                OPENSSL,
                "pkcs12",
                "-export",
                "-inkey",
                f"/dev/fd/{key_fd}",
                "-in",
                f"/dev/fd/{chain_fd}",
                "-name",
                material.certificate_id,
                "-passout",
                f"file:{password_path}",
            ],
            pass_fds=(key_fd, chain_fd),
        )
    finally:
        os.close(key_fd)
        os.close(chain_fd)
    if bundle is None:
        raise PublishError("write_failed", "openssl could not build the PKCS#12 bundle")
    return bundle


def bundle_fingerprint(path: Path, password_path: Path) -> str | None:
    """The leaf fingerprint inside a bundle already on disk, or None.

    This is what makes a PKCS#12 target idempotent. The bundle's own bytes
    cannot be compared: PKCS#12 is salted, so exporting the same certificate
    twice gives two different files, and a publisher that compared bytes would
    rewrite every receiver on every run - new mtime, new fetch, every minute
    of every day. What is compared instead is the certificate inside it.
    """

    certificates = _openssl(
        [
            OPENSSL,
            "pkcs12",
            "-in",
            str(path),
            "-nokeys",
            "-passin",
            f"file:{password_path}",
        ],
    )
    if certificates is None:
        return None
    try:
        return leaf_fingerprint(certificates.decode("ascii"))
    except (UnicodeDecodeError, CertificateError):
        return None


def _bundle_password(path: Path, *, uid: int, gid: int) -> bool:
    """Make this pair's password if it has none, and say whether it is new (B159).

    Kept, not regenerated: a receiver that imported the bundle into a
    certificate store did so with the password it fetched, and a renewal that
    changed it would mean every renewal is also a manual re-import. So the
    password belongs to the pair - one receiver, one certificate - and only a
    lost or empty file makes a new one.
    """

    try:
        if path.read_text(encoding="ascii").strip():
            return False
    except (OSError, UnicodeDecodeError):
        pass
    try:
        write_file(
            path,
            (new_password() + "\n").encode("ascii"),
            uid=uid,
            gid=gid,
            mode=RECEIVER_MODE,
            compare=False,
        )
    except OSError as exc:
        raise PublishError("write_failed", f"{path}: {exc}") from exc
    return True


def publish_bundle(target: Target, material: Material) -> bool:
    """Write this pair's bundle unless the one already there holds the same certificate."""

    bundle_path, password_path = receiver_bundle_paths(target, material.certificate_id)
    password_written = _bundle_password(password_path, uid=target.uid, gid=target.gid)
    if (
        not password_written
        and bundle_fingerprint(bundle_path, password_path) == material.fingerprint
    ):
        return False
    try:
        write_file(
            bundle_path,
            bundle_bytes(material, password_path),
            uid=target.uid,
            gid=target.gid,
            mode=RECEIVER_MODE,
            compare=False,
        )
    except OSError as exc:
        raise PublishError("write_failed", f"{bundle_path}: {exc}") from exc
    return True


def receiver_bundle_paths(target: Target, certificate_id: str) -> tuple[Path, Path]:
    """The bundle and its password file, named the way every reader names them."""

    return (
        target.directory / f"{certificate_id}{PKCS12_SUFFIX}",
        target.directory / f"{certificate_id}{PASSWORD_SUFFIX}",
    )


def publish_to(targets: Sequence[Target], material: Material) -> tuple[TargetResult, ...]:
    """Write every file the targets read, each path once, and say which targets changed.

    Clusters share one distribution directory, so two clusters naming the
    same certificate read the same file. It is written once, and the change
    belongs to every target that reads it - otherwise the second cluster
    would see "unchanged" and never be rolled out.
    """

    written: dict[Path, bool] = {}
    bundles: dict[str, bool] = {}
    failed: set[tuple[str, str]] = set()
    first: PublishError | None = None
    #
    # A failing target does not stop the others. Stopping would leave the
    # targets after it on the old certificate for no reason of their own, and
    # the ones before it already written - so the report has to say which
    # were, whichever way it goes.
    #
    for target in targets:
        try:
            if target.form == "pkcs12":
                #
                # Its own idempotence, and its own entry: two receivers wanting a
                # bundle of the same certificate get two bundles, in two
                # directories, with two passwords - the password belongs to the
                # pair, not to the certificate.
                #
                bundles[target.name] = publish_bundle(target, material)
                continue
            for path, content in target.files(material.certificate_id, material):
                if path in written:
                    continue
                try:
                    written[path] = write_file(
                        path, content, uid=target.uid, gid=target.gid, mode=target.mode
                    )
                except OSError as exc:
                    raise PublishError("write_failed", f"{path}: {exc}") from exc
        except PublishError as exc:
            failed.add((target.kind, target.name))
            first = first or exc

    def changed(target: Target) -> bool:
        if target.form == "pkcs12":
            return bundles[target.name]
        return any(written[path] for path, _ in target.files(material.certificate_id, material))

    outcomes = tuple(
        TargetResult(target.kind, target.name, changed(target))
        for target in targets
        if (target.kind, target.name) not in failed
    )
    if first is not None:
        raise PublishError(first.code, str(first), written=outcomes) from first
    return outcomes


#
# The run
#


@contextmanager
def publish_lock(path: Path = DEFAULT_LOCK_PATH, *, wait: int | None = None) -> Iterator[None]:
    """Hold the publisher's lock, waiting a bounded time for another run to finish.

    The lock itself is `cert_lock.hold`, shared with every registry writer;
    only the refusal is the publisher's.
    """

    with hold(
        path,
        wait=LOCK_WAIT_SECONDS if wait is None else wait,
        refuse=lambda message: PublishError("operation_locked", message),
    ):
        yield


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
#
# Makes nginx serve the interface certificate (B188) and says whether anything
# changed. Injected like the deployer, because where it can run is the
# caller's to know: root outside the worker's sandbox runs
# `ui_interface.install` directly, the sandboxed helpers ask its socket.
#
type Installer = Callable[[Material], bool]


def publish(
    runtime: RuntimeConfig,
    policy: PathPolicy,
    *,
    only: Sequence[str] | None = None,
    live: Path = LETSENCRYPT_LIVE,
    store: Path = IMPORT_STORE,
    lock_path: Path = DEFAULT_LOCK_PATH,
    deployer: Deployer | None = None,
    installer: Installer | None = None,
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
                #
                # The material first and only then the targets: resolving a
                # target makes its per-certificate directory, and a certificate
                # whose material is refused must not leave one behind.
                #
                material = read_material(entry, live=live, store=store, now=now)
                outcomes: tuple[TargetResult, ...]
                if entry.interface:
                    if installer is None:
                        results.append(
                            CertificateResult(
                                entry.certificate_id,
                                "skipped",
                                fingerprint=material.fingerprint,
                                not_after=material.facts.not_after,
                                error=(
                                    "installer_unavailable",
                                    "the interface certificate is installed by root, not by "
                                    "this caller",
                                ),
                            )
                        )
                        continue
                    outcomes = (TargetResult("interface", "interface", installer(material)),)
                else:
                    targets = targets_for(entry, runtime, policy)
                    outcomes = publish_to(targets, material)
            except PublishError as exc:
                for outcome in exc.written:
                    if (
                        outcome.kind == "cluster"
                        and outcome.changed
                        and outcome.name not in changed_clusters
                    ):
                        changed_clusters.append(outcome.name)
                results.append(
                    CertificateResult(
                        entry.certificate_id,
                        "failed",
                        targets=exc.written,
                        error=(exc.code, str(exc)),
                    )
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
