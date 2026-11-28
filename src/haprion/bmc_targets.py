"""The BMC receivers certificates are installed on, as root keeps them (B526, B536, B538).

Everything here is keyed by the BMC receiver's ID, its name or address. Three
things live here, and nothing else touches them:

- **The account** a BMC is signed in to with, sealed by the web against the
  installation's public key (B165) and kept as a root-only file per BMC. The
  box is bound to the BMC's ID, so it cannot be moved to another BMC; only
  root opens it, when it signs in. A box sealed before B538 is bound to the
  certificate and the address instead, and opens for the BMC at that address.
- **The install**: the certificate the BMC carries, read the one way a key
  leaves the manager for a host (`cert_export.material`), handed to the BMC
  (`bmc_redfish.install`), and the
  pinned fingerprint moved to the certificate the BMC now serves. One install
  at a time, under one lock.
- **The sweep** the timer runs: each BMC asked what it serves, and the
  certificate installed where it answers with anything but the current one.
  A BMC that does not answer is no fault, however long (B536): the sweep notes
  when it asked and goes on. A BMC that serves a certificate nobody confirmed
  is sent nothing. An install that failed for a certificate is not tried again
  for that certificate until somebody asks (*Install now*).

What the sweep and the installs did is kept in one state file the poller
reads; the registry says where each BMC is.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import fcntl
import json
import os
import stat
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from pathlib import Path

from haprion import atomic_file, bmc_redfish, cert_registry, exit_codes
from haprion.bmc_redfish import BmcError
from haprion.cert_export import ExportError, bmc_material
from haprion.cert_inventory import IMPORT_STORE, LETSENCRYPT_LIVE
from haprion.cert_lock import DEFAULT_LOCK_PATH
from haprion.config import (
    BMC_USERNAME_MAX,
    CERTIFICATE_ID,
    BmcTarget,
    Registry,
    RuntimeConfig,
    load_registry,
    receiver_id_names_a_host,
)
from haprion.dns_profile_keys import (
    DnsProfilePrivateKey,
    DnsProfilePublicKey,
    KeyFileError,
    open_sealed,
    seal,
)

ACCOUNTS = Path("/etc/haprion/bmc-accounts")
STATE_DIRECTORY = Path("/var/lib/haprion/bmc")
STATE_FILE = "state.json"
LOCK_FILE = "install.lock"
STATE_LOCK_FILE = "state.lock"
#
# The code of a fault in reading what a BMC serves, as opposed to an install:
# `reading_tls_failed`, `reading_bad_answer`. Cleared by the next reading.
#
READING_FAULT = "reading_"
SCHEMA_VERSION = 1
#
# The account box and its file: 2 is bound to the BMC receiver (B538), 1 to the
# certificate and the address it had before.
#
ACCOUNT_SCHEMA = 2
#
# The registry keeps the user in the clear for the page; one rule for both.
#
USERNAME_MAX = BMC_USERNAME_MAX
PASSWORD_MAX = 256
MAX_CIPHERTEXT = 4096
MAX_FILE = 16384
#
# Who started an install, for the record and the row: the timer, *Install now*
# in the interface or the command, or the save that added the target.
#
BY = ("timer", "install_now", "save")


class TargetError(Exception):
    """A refused or failed step, with the code it is reported under."""

    def __init__(self, code: str, message: str, exit_code: int = exit_codes.REFUSED) -> None:
        super().__init__(message)
        self.code = code
        self.exit_code = exit_code


# --- the account ---------------------------------------------------------------------------


def check_account(username: object, password: object) -> tuple[str, str]:
    if not isinstance(username, str) or not 1 <= len(username) <= USERNAME_MAX:
        raise TargetError("bad_input", f"the user is 1-{USERNAME_MAX} characters")
    if not username.isprintable() or username != username.strip():
        raise TargetError(
            "bad_input", "the user has no spaces at its ends and no control characters"
        )
    if not isinstance(password, str) or not 1 <= len(password) <= PASSWORD_MAX:
        raise TargetError("bad_input", f"the password is 1-{PASSWORD_MAX} characters")
    if not password.isprintable():
        raise TargetError("bad_input", "the password has no control characters")
    return username, password


def seal_account(
    key: DnsProfilePublicKey,
    *,
    receiver_id: str,
    username: str,
    password: str,
) -> bytes:
    """The box the web hands root: the account, bound to the BMC receiver."""

    check_account(username, password)
    record = {
        "schema_version": ACCOUNT_SCHEMA,
        "receiver_id": _receiver_id(receiver_id),
        "key_id": key.key_id,
        "username": username,
        "password": password,
    }
    return seal(key, json.dumps(record, separators=(",", ":")).encode("utf-8"))


def open_account(
    keys: Sequence[DnsProfilePrivateKey],
    key_id: str,
    ciphertext: bytes,
    *,
    receiver_id: str,
) -> tuple[str, str]:
    """The user and password, when the box is this BMC's and one of `keys` opens it."""

    if not 48 <= len(ciphertext) <= MAX_CIPHERTEXT:
        raise TargetError("account_unreadable", "the sealed account has an invalid size")
    key = next((candidate for candidate in keys if candidate.key_id == key_id), None)
    if key is None:
        raise TargetError(
            "account_unreadable",
            "the key the account was sealed with is not this installation's",
            exit_codes.CONFIG,
        )
    try:
        record = json.loads(open_sealed(key, ciphertext))
    except (KeyFileError, ValueError, UnicodeError):
        raise TargetError("account_unreadable", "the sealed account could not be opened") from None
    if not isinstance(record, dict):
        raise TargetError("account_unreadable", "the opened account has an invalid shape")
    if record.get("schema_version") == ACCOUNT_SCHEMA:
        expected = {"schema_version", "receiver_id", "key_id", "username", "password"}
        bound = record.get("receiver_id") == receiver_id
    else:
        #
        # Sealed before B538, for a certificate and the BMC's address: it is
        # this BMC's when the address is the BMC's ID.
        #
        expected = {"schema_version", "certificate_id", "address", "key_id", "username", "password"}
        bound = (
            record.get("schema_version") == SCHEMA_VERSION and record.get("address") == receiver_id
        )
    if set(record) != expected:
        raise TargetError("account_unreadable", "the opened account has an invalid shape")
    if not bound or record["key_id"] != key_id:
        raise TargetError("account_unreadable", "the sealed account belongs to another BMC")
    return check_account(record["username"], record["password"])


def _receiver_id(receiver_id: str) -> str:
    if not receiver_id_names_a_host(receiver_id):
        raise TargetError("bad_input", "not a BMC's name or address")
    return receiver_id


def _state_key(key: str) -> str:
    """A key of the state file: a BMC's ID, or a certificate's from before B538."""

    if not (receiver_id_names_a_host(key) or CERTIFICATE_ID.fullmatch(key)):
        raise TargetError("bad_input", "not a BMC's name or address")
    return key


def _read_root_file(path: Path, *, require_secure: bool) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise TargetError(
            "dependency_unavailable", f"{path} cannot be read: {exc.strerror}", exit_codes.CONFIG
        ) from exc
    with os.fdopen(descriptor, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE:
            raise TargetError("dependency_unavailable", f"{path} is not a bounded regular file")
        if require_secure and (info.st_uid != 0 or info.st_mode & 0o077):
            raise TargetError(
                "dependency_unavailable", f"{path} must be root's alone (0600)", exit_codes.CONFIG
            )
        return handle.read(MAX_FILE + 1)


def write_account(
    receiver_id: str, key_id: str, ciphertext: bytes, *, directory: Path = ACCOUNTS
) -> None:
    _receiver_id(receiver_id)
    if not 48 <= len(ciphertext) <= MAX_CIPHERTEXT:
        raise TargetError("bad_input", "the sealed account has an invalid size")
    directory.mkdir(mode=0o700, exist_ok=True)
    document = {
        "schema_version": ACCOUNT_SCHEMA,
        "receiver_id": receiver_id,
        "key_id": key_id,
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }
    atomic_file.write(
        directory / f"{receiver_id}.json",
        (json.dumps(document, indent=2) + "\n").encode(),
        mode=0o600,
    )


def read_account(
    receiver_id: str, *, directory: Path = ACCOUNTS, require_secure: bool = True
) -> tuple[str, bytes]:
    """The key ID and the box kept for a BMC."""

    path = directory / f"{_receiver_id(receiver_id)}.json"
    try:
        return _account_file(path, require_secure=require_secure)
    except FileNotFoundError:
        raise TargetError(
            "account_missing", f"no account is kept for the BMC {receiver_id}", exit_codes.CONFIG
        ) from None


def _account_file(path: Path, *, require_secure: bool) -> tuple[str, bytes]:
    """An account file named for what it is kept for: a BMC, or before B538 a certificate."""

    content = _read_root_file(path, require_secure=require_secure)
    try:
        document = json.loads(content)
        if not isinstance(document, dict) or not isinstance(document.get("key_id"), str):
            raise ValueError("shape")
        named = (
            document.get("receiver_id")
            if document.get("schema_version") == ACCOUNT_SCHEMA
            else document.get("certificate_id")
            if document.get("schema_version") == SCHEMA_VERSION
            else None
        )
        if named != path.stem:
            raise ValueError("shape")
        return document["key_id"], base64.b64decode(document["ciphertext"], validate=True)
    except (ValueError, KeyError, TypeError, binascii.Error):
        raise TargetError(
            "account_unreadable", f"{path} is not an account file", exit_codes.CONFIG
        ) from None


def remove_account(receiver_id: str, *, directory: Path = ACCOUNTS) -> None:
    with contextlib.suppress(FileNotFoundError):
        (directory / f"{_receiver_id(receiver_id)}.json").unlink()


# --- what happened -------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Attempt:
    """One install: of which certificate, how it ended and what the BMC said."""

    fingerprint_sha256: str
    at: str
    by: str
    outcome: str
    code: str | None = None
    message: str | None = None
    seconds: float | None = None
    firmware: str | None = None


@dataclass(frozen=True, slots=True)
class TargetState:
    """What is known of one BMC: when it was asked, when it answered, what it served."""

    address: str
    port: int
    checked_at: str | None = None
    answered_at: str | None = None
    served_sha256: str | None = None
    attempt: Attempt | None = None


def _iso(moment: datetime) -> str:
    return moment.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def read_state(directory: Path = STATE_DIRECTORY) -> dict[str, TargetState]:
    """The state file; empty when there is none yet. A damaged one is said, not guessed at."""

    path = directory / STATE_FILE
    try:
        content = _read_root_file(path, require_secure=False)
    except FileNotFoundError:
        return {}
    try:
        document = json.loads(content)
        if not isinstance(document, dict) or document.get("schema_version") != SCHEMA_VERSION:
            raise ValueError("shape")
        found: dict[str, TargetState] = {}
        for key, raw in document["targets"].items():
            attempt = raw.get("attempt")
            found[_state_key(key)] = TargetState(
                **{**raw, "attempt": Attempt(**attempt) if attempt else None}
            )
        return found
    except (ValueError, KeyError, TypeError, AttributeError, TargetError):
        raise TargetError(
            "state_unreadable", f"{path} is not the BMC state file", exit_codes.CONFIG
        ) from None


def write_state(states: Mapping[str, TargetState], directory: Path = STATE_DIRECTORY) -> None:
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    document = {
        "schema_version": SCHEMA_VERSION,
        "targets": {name: asdict(states[name]) for name in sorted(states)},
    }
    atomic_file.write(
        directory / STATE_FILE, (json.dumps(document, indent=2) + "\n").encode(), mode=0o600
    )


@contextlib.contextmanager
def install_lock(directory: Path = STATE_DIRECTORY, *, wait: bool = True) -> Iterator[None]:
    """One install at a time, from the timer, *Install now* or a save.

    The timer waits its turn. A job does not (`wait` False): behind an install
    of minutes it would outlast its unit and end with no answer, so it is told
    the lock is held, before anything is read or sent.
    """

    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(directory / LOCK_FILE, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX if wait else fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise TargetError(
                "bmc_busy",
                "another install on a BMC is running; ask again when it has ended",
                exit_codes.BLOCKED,
            ) from None
        yield
    finally:
        os.close(descriptor)


def status(state: TargetState | None, *, current: str | None, pinned: str) -> str:
    """One word for the row, derived from the state and nothing else (B536).

    `installed` - it answered serving the current certificate. `waiting` - it
    has not been seen serving it, and nothing failed: switched off, behind a
    firewall, or not reached yet; never a fault. `failed` - an install of the
    current certificate failed where the BMC answered. `untrusted` - it
    answered with a certificate nobody confirmed. `unknown` - never asked.
    """

    if state is None or state.checked_at is None:
        return "unknown"
    if state.served_sha256 is not None and state.served_sha256 == current:
        return "installed"
    if state.served_sha256 is not None and state.served_sha256 not in {pinned, current}:
        return "untrusted"
    attempt = state.attempt
    if (
        attempt is not None
        and attempt.fingerprint_sha256 == current
        and attempt.outcome == "failed"
    ):
        return "failed"
    return "waiting"


# --- installing ----------------------------------------------------------------------------

Installer = Callable[..., bmc_redfish.Installed]
Reader = Callable[[str, int], bmc_redfish.Served]


@dataclass(frozen=True, slots=True)
class Root:
    """Where the root side reads and writes, and with what; tests give their own."""

    runtime: RuntimeConfig
    registry_path: Path
    private_keys: Sequence[DnsProfilePrivateKey]
    accounts: Path = ACCOUNTS
    state: Path = STATE_DIRECTORY
    live: Path = LETSENCRYPT_LIVE
    store: Path = IMPORT_STORE
    require_secure: bool = True
    lock_path: Path = DEFAULT_LOCK_PATH


def _registry(root: Root) -> Registry:
    """The registry as it is on file now: an install moves a target's pin."""

    return load_registry(root.registry_path, require_secure=root.require_secure)


def _target(registry: Registry | None, receiver_id: str) -> BmcTarget:
    target = registry.bmcs.get(receiver_id) if registry is not None else None
    if target is None:
        raise TargetError("not_registered", f"{receiver_id} is not a BMC in the registry")
    return target


def _carried(registry: Registry, receiver_id: str) -> str:
    """The certificate the BMC carries; a BMC that carries none has nothing to install."""

    certificate_id = registry.certificate_of(receiver_id)
    if certificate_id is None:
        raise TargetError(
            "no_certificate", f"the BMC {receiver_id} carries no certificate; choose one"
        )
    return certificate_id


def install(
    root: Root,
    receiver_id: str,
    *,
    by: str,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
    installer: Installer = bmc_redfish.install,
) -> Attempt:
    """Install the certificate on its BMC, record what happened, and pin what it serves."""

    if by not in BY:
        raise TargetError("bad_input", f"by is one of: {', '.join(BY)}")
    with install_lock(root.state, wait=by == "timer"):
        registry = _registry(root)
        target = _target(registry, receiver_id)
        certificate_id = _carried(registry, receiver_id)
        try:
            read = bmc_material(registry, certificate_id, live=root.live, store=root.store)
        except ExportError as exc:
            raise TargetError(exc.code, str(exc), exc.exit_code) from exc
        key_id, ciphertext = read_account(
            receiver_id, directory=root.accounts, require_secure=root.require_secure
        )
        username, password = open_account(
            root.private_keys, key_id, ciphertext, receiver_id=receiver_id
        )
        started = now()
        try:
            installed = installer(
                target.address,
                target.port,
                trusted={target.fingerprint_sha256, read.fingerprint},
                username=username,
                password=password,
                fullchain=read.fullchain.decode("ascii"),
                key_pem=read.privkey.decode("ascii"),
            )
        except BmcError as exc:
            #
            # Nothing answered before anything was sent: not a failure (B536),
            # and the next sweep tries again.
            #
            attempt = Attempt(
                fingerprint_sha256=read.fingerprint,
                at=_iso(started),
                by=by,
                outcome="unreached" if exc.code == "unreachable" else "failed",
                code=exc.code,
                message=str(exc),
            )
            _record(root, receiver_id, target, attempt, None, now())
            return attempt
        attempt = Attempt(
            fingerprint_sha256=read.fingerprint,
            at=_iso(started),
            by=by,
            outcome="done",
            message=installed.upload_said,
            seconds=round(installed.seconds, 1),
            firmware=" ".join(
                part for part in (installed.firmware.model, installed.firmware.version) if part
            )
            or None,
        )
        #
        # The certificate the BMC serves is now the one to trust (B526): the
        # one confirmed when the target was added is not served any more.
        #
        cert_registry.set_bmc_receiver(
            root.registry_path,
            receiver_id=receiver_id,
            target=replace(target, fingerprint_sha256=read.fingerprint),
            runtime=root.runtime,
            require_secure=root.require_secure,
            lock_path=root.lock_path,
        )
        _record(root, receiver_id, target, attempt, read.fingerprint, now())
        return attempt


@contextlib.contextmanager
def _state_lock(directory: Path) -> Iterator[None]:
    """One read-and-write of the state file at a time.

    The timer records what a BMC served outside the install lock, and a job
    records its attempt inside it: without this, one could write over the
    other's change, and a failed *Install now* would read as waiting.
    """

    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(directory / STATE_LOCK_FILE, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        os.close(descriptor)


def _record(
    root: Root,
    receiver_id: str,
    target: BmcTarget,
    attempt: Attempt | None,
    served: str | None,
    moment: datetime,
) -> None:
    with _state_lock(root.state):
        _record_unlocked(root, receiver_id, target, attempt, served, moment)


def _record_unlocked(
    root: Root,
    receiver_id: str,
    target: BmcTarget,
    attempt: Attempt | None,
    served: str | None,
    moment: datetime,
) -> None:
    states = read_state(root.state)
    before = states.get(receiver_id) or TargetState(target.address, target.port)
    answered = served is not None or (
        attempt is not None and attempt.code not in (None, "unreachable")
    )
    states[receiver_id] = TargetState(
        address=target.address,
        port=target.port,
        checked_at=_iso(moment),
        answered_at=_iso(moment) if answered else before.answered_at,
        served_sha256=served if served is not None else before.served_sha256,
        attempt=attempt if attempt is not None else before.attempt,
    )
    write_state(states, root.state)


def sweep(
    root: Root,
    *,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
    reader: Reader = lambda address, port: bmc_redfish.served(address, port),
    installer: Installer = bmc_redfish.install,
) -> dict[str, str]:
    """Ask every BMC what it serves and install where it needs it; the status of each, by BMC."""

    migrate(root)
    registry = _registry(root)
    said: dict[str, str] = {}
    states = read_state(root.state)
    for receiver_id, target in sorted(registry.bmcs.items()):
        certificate_id = registry.certificate_of(receiver_id)
        if certificate_id is None:
            #
            # A BMC that carries no certificate has nothing to be told.
            #
            continue
        try:
            current: str | None = bmc_material(
                registry, certificate_id, live=root.live, store=root.store
            ).fingerprint
        except ExportError:
            current = None
        try:
            served = reader(target.address, target.port).fingerprint_sha256
        except BmcError as exc:
            if exc.code == "unreachable":
                #
                # Switched off, or a firewall in the way: asked, and nothing
                # more (B536). What it served when it last answered stays.
                #
                _record(root, receiver_id, target, None, None, now())
            else:
                #
                # It answered and could not be read - no certificate, no TLS it
                # will agree to: this BMC's fault, said on its row, and the
                # sweep goes on to the others.
                #
                moment = now()
                _record(
                    root,
                    receiver_id,
                    target,
                    Attempt(
                        fingerprint_sha256=current or target.fingerprint_sha256,
                        at=_iso(moment),
                        by="timer",
                        outcome="failed",
                        code=READING_FAULT + exc.code,
                        message=str(exc),
                    ),
                    None,
                    moment,
                )
            states = read_state(root.state)
            said[receiver_id] = status(
                states.get(receiver_id), current=current, pinned=target.fingerprint_sha256
            )
            continue
        _record(root, receiver_id, target, None, served, now())
        _clear_reading_fault(root, receiver_id)
        if current is not None and served == current and target.fingerprint_sha256 != current:
            _trust_served(root, receiver_id, target, current)
        states = read_state(root.state)
        state = states[receiver_id]
        word = status(state, current=current, pinned=target.fingerprint_sha256)
        #
        # `waiting` is never a failed install of this certificate: `status` says
        # `failed` for that, and the next install is the one somebody asks for.
        #
        if word == "waiting" and current is not None and served != current:
            try:
                install(root, receiver_id, by="timer", now=now, installer=installer)
            except TargetError as exc:
                #
                # Removed, or given no certificate, since the registry was
                # read: nothing to install, and no reason to stop the sweep.
                #
                if exc.code in ("not_registered", "no_certificate"):
                    continue
                #
                # Nothing sent: the account cannot be opened (a key replaced
                # without the account entered again) or the material cannot be
                # read. This BMC's install failed, in those words, and the
                # sweep goes on to the others.
                #
                moment = now()
                _record(
                    root,
                    receiver_id,
                    target,
                    Attempt(
                        fingerprint_sha256=current,
                        at=_iso(moment),
                        by="timer",
                        outcome="failed",
                        code=exc.code,
                        message=str(exc),
                    ),
                    None,
                    moment,
                )
            states = read_state(root.state)
            word = status(
                states.get(receiver_id),
                current=current,
                pinned=_target(_registry(root), receiver_id).fingerprint_sha256,
            )
        said[receiver_id] = word
    return said


def migrate(root: Root) -> None:
    """What was kept per certificate before B538, moved to its BMC receiver; once, and safe to repeat.

    The registry's own half moves with the first write of it (`settled_bmcs`);
    this writes it if nothing else has. The account file and the state's entry
    are renamed from the certificate's ID to the BMC's, when the two differ.
    The box itself stays as it was sealed: it opens for the BMC at its address.
    """

    registry = _registry(root)
    for receiver_id in registry.bmcs:
        certificate_id = registry.certificate_of(receiver_id)
        if certificate_id is None or certificate_id == receiver_id:
            continue
        old = root.accounts / f"{certificate_id}.json"
        if old.exists() and not (root.accounts / f"{receiver_id}.json").exists():
            key_id, box = _account_file(old, require_secure=root.require_secure)
            write_account(receiver_id, key_id, box, directory=root.accounts)
            old.unlink()
        with _state_lock(root.state):
            states = read_state(root.state)
            if certificate_id in states and receiver_id not in states:
                states[receiver_id] = states.pop(certificate_id)
                write_state(states, root.state)
    if registry.legacy_bmcs:
        receiver_id = next(
            entry.bmc.address
            for entry in registry.certificates.values()
            if entry.certificate_id in registry.legacy_bmcs and entry.bmc is not None
        )
        with install_lock(root.state):
            cert_registry.set_bmc_receiver(
                root.registry_path,
                receiver_id=receiver_id,
                target=registry.bmcs[receiver_id],
                runtime=root.runtime,
                require_secure=root.require_secure,
                lock_path=root.lock_path,
            )


def _clear_reading_fault(root: Root, receiver_id: str) -> None:
    """A BMC read again after a reading fault: the fault is over, and installs go on.

    A reading fault is no install - nothing was sent - so it must not hold the
    next install back until *Install now*, as a failed install does (review
    26-11-27, om-vända).
    """

    with _state_lock(root.state):
        states = read_state(root.state)
        known = states.get(receiver_id)
        if (
            known is None
            or known.attempt is None
            or not (known.attempt.code or "").startswith(READING_FAULT)
        ):
            return
        states[receiver_id] = replace(known, attempt=None)
        write_state(states, root.state)


def _trust_served(root: Root, receiver_id: str, seen: BmcTarget, current: str) -> None:
    """Pin the certificate the BMC serves when it is the one the manager holds.

    An install pins what it installed only when its wait succeeds. A BMC slower
    to come back than the wait serves it a little later, and kept the old pin:
    at the next renewal it served neither the pin nor the new certificate and
    read as untrusted (review 26-11-27, BX04). It serves our own certificate, the
    key is here, so it is the one to trust. Under the install lock, against the
    registry as it is now: a save or a removal since the sweep read it stands.
    """

    with install_lock(root.state):
        registry = _registry(root)
        target = registry.bmcs.get(receiver_id) if registry is not None else None
        if (
            target is None
            or (target.address, target.port) != (seen.address, seen.port)
            or target.fingerprint_sha256 == current
        ):
            return
        cert_registry.set_bmc_receiver(
            root.registry_path,
            receiver_id=receiver_id,
            target=replace(target, fingerprint_sha256=current),
            runtime=root.runtime,
            require_secure=root.require_secure,
            lock_path=root.lock_path,
        )


def forget(receiver_id: str, *, directory: Path = STATE_DIRECTORY) -> None:
    """Take a BMC that is gone out of the state file."""

    with _state_lock(directory):
        states = read_state(directory)
        if states.pop(receiver_id, None) is not None:
            write_state(states, directory)


def row_state(
    states: Mapping[str, TargetState] | None,
) -> Callable[[str, str | None, str], dict[str, object]]:
    """What a BMC's row carries: the word and what it rests on (B536), by the BMC's ID.

    `states` None is a state file that could not be read: every BMC is then
    `unknown`, and the listing is otherwise as it was.
    """

    def state(receiver_id: str, current: str | None, pinned: str) -> dict[str, object]:
        known = (states or {}).get(receiver_id)
        return {
            "status": status(known, current=current, pinned=pinned),
            "checked_at": known.checked_at if known else None,
            "answered_at": known.answered_at if known else None,
            "served_sha256": known.served_sha256 if known else None,
            "attempt": asdict(known.attempt) if known and known.attempt else None,
        }

    return state
