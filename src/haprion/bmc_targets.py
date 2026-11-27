"""The BMCs exportable certificates are installed on, as root keeps them (B526, B536).

Three things live here, and nothing else touches them:

- **The account** a BMC is signed in to with, sealed by the web against the
  installation's public key (B165) and kept as a root-only file per
  certificate. The box is bound to the certificate and the BMC's address, so
  it cannot be moved to another target; only root opens it, when it signs in.
- **The install**: the certificate read the one way an exportable key is read
  (`cert_export.material`), handed to the BMC (`bmc_redfish.install`), and the
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
from haprion.cert_export import ExportError, material
from haprion.cert_inventory import IMPORT_STORE, LETSENCRYPT_LIVE
from haprion.cert_lock import DEFAULT_LOCK_PATH
from haprion.config import (
    BMC_USERNAME_MAX,
    CERTIFICATE_ID,
    BmcTarget,
    Registry,
    RuntimeConfig,
    load_registry,
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
SCHEMA_VERSION = 1
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
    certificate_id: str,
    address: str,
    username: str,
    password: str,
) -> bytes:
    """The box the web hands root: the account, bound to the certificate and the address."""

    check_account(username, password)
    record = {
        "schema_version": SCHEMA_VERSION,
        "certificate_id": certificate_id,
        "address": address,
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
    certificate_id: str,
    address: str,
) -> tuple[str, str]:
    """The user and password, when the box is this target's and one of `keys` opens it."""

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
    expected = {"schema_version", "certificate_id", "address", "key_id", "username", "password"}
    if not isinstance(record, dict) or set(record) != expected:
        raise TargetError("account_unreadable", "the opened account has an invalid shape")
    if (
        record["schema_version"] != SCHEMA_VERSION
        or record["certificate_id"] != certificate_id
        or record["address"] != address
        or record["key_id"] != key_id
    ):
        raise TargetError(
            "account_unreadable", "the sealed account belongs to another certificate or BMC"
        )
    return check_account(record["username"], record["password"])


def _certificate_id(certificate_id: str) -> str:
    if not CERTIFICATE_ID.fullmatch(certificate_id):
        raise TargetError("bad_input", "not a certificate ID")
    return certificate_id


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
    certificate_id: str, key_id: str, ciphertext: bytes, *, directory: Path = ACCOUNTS
) -> None:
    _certificate_id(certificate_id)
    if not 48 <= len(ciphertext) <= MAX_CIPHERTEXT:
        raise TargetError("bad_input", "the sealed account has an invalid size")
    directory.mkdir(mode=0o700, exist_ok=True)
    document = {
        "schema_version": SCHEMA_VERSION,
        "certificate_id": certificate_id,
        "key_id": key_id,
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }
    atomic_file.write(
        directory / f"{certificate_id}.json",
        (json.dumps(document, indent=2) + "\n").encode(),
        mode=0o600,
    )


def read_account(
    certificate_id: str, *, directory: Path = ACCOUNTS, require_secure: bool = True
) -> tuple[str, bytes]:
    """The key ID and the box kept for a certificate's BMC."""

    path = directory / f"{_certificate_id(certificate_id)}.json"
    try:
        content = _read_root_file(path, require_secure=require_secure)
    except FileNotFoundError:
        raise TargetError(
            "account_missing", f"no account is kept for {certificate_id}'s BMC", exit_codes.CONFIG
        ) from None
    try:
        document = json.loads(content)
        if (
            not isinstance(document, dict)
            or document.get("schema_version") != SCHEMA_VERSION
            or document.get("certificate_id") != certificate_id
            or not isinstance(document.get("key_id"), str)
        ):
            raise ValueError("shape")
        return document["key_id"], base64.b64decode(document["ciphertext"], validate=True)
    except (ValueError, KeyError, TypeError, binascii.Error):
        raise TargetError(
            "account_unreadable", f"{path} is not an account file", exit_codes.CONFIG
        ) from None


def remove_account(certificate_id: str, *, directory: Path = ACCOUNTS) -> None:
    with contextlib.suppress(FileNotFoundError):
        (directory / f"{_certificate_id(certificate_id)}.json").unlink()


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
        for certificate_id, raw in document["targets"].items():
            attempt = raw.get("attempt")
            found[_certificate_id(certificate_id)] = TargetState(
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


def _target(registry: Registry | None, certificate_id: str) -> BmcTarget:
    entry = registry.certificates.get(certificate_id) if registry is not None else None
    if entry is None:
        raise TargetError("not_registered", f"{certificate_id} is not in the registry")
    if entry.bmc is None:
        raise TargetError("no_bmc", f"{certificate_id} names no BMC")
    return entry.bmc


def install(
    root: Root,
    certificate_id: str,
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
        target = _target(registry, certificate_id)
        try:
            read = material(registry, certificate_id, live=root.live, store=root.store)
        except ExportError as exc:
            raise TargetError(exc.code, str(exc), exc.exit_code) from exc
        key_id, ciphertext = read_account(
            certificate_id, directory=root.accounts, require_secure=root.require_secure
        )
        username, password = open_account(
            root.private_keys,
            key_id,
            ciphertext,
            certificate_id=certificate_id,
            address=target.address,
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
            _record(root, certificate_id, target, attempt, None, now())
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
        cert_registry.set_bmc(
            root.registry_path,
            certificate_id=certificate_id,
            target=replace(target, fingerprint_sha256=read.fingerprint),
            runtime=root.runtime,
            require_secure=root.require_secure,
            lock_path=root.lock_path,
        )
        _record(root, certificate_id, target, attempt, read.fingerprint, now())
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
    certificate_id: str,
    target: BmcTarget,
    attempt: Attempt | None,
    served: str | None,
    moment: datetime,
) -> None:
    with _state_lock(root.state):
        _record_unlocked(root, certificate_id, target, attempt, served, moment)


def _record_unlocked(
    root: Root,
    certificate_id: str,
    target: BmcTarget,
    attempt: Attempt | None,
    served: str | None,
    moment: datetime,
) -> None:
    states = read_state(root.state)
    before = states.get(certificate_id) or TargetState(target.address, target.port)
    answered = served is not None or (
        attempt is not None and attempt.code not in (None, "unreachable")
    )
    states[certificate_id] = TargetState(
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
    """Ask every BMC what it serves and install where it needs it; the status of each."""

    registry = _registry(root)
    said: dict[str, str] = {}
    states = read_state(root.state)
    for certificate_id, entry in sorted((registry.certificates if registry else {}).items()):
        target = entry.bmc
        if target is None:
            continue
        try:
            current: str | None = material(
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
                _record(root, certificate_id, target, None, None, now())
            else:
                #
                # It answered and could not be read - no certificate, no TLS it
                # will agree to: this BMC's fault, said on its row, and the
                # sweep goes on to the others.
                #
                moment = now()
                _record(
                    root,
                    certificate_id,
                    target,
                    Attempt(
                        fingerprint_sha256=current or target.fingerprint_sha256,
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
            said[certificate_id] = status(
                states.get(certificate_id), current=current, pinned=target.fingerprint_sha256
            )
            continue
        _record(root, certificate_id, target, None, served, now())
        if current is not None and served == current and target.fingerprint_sha256 != current:
            _trust_served(root, certificate_id, target, current)
        states = read_state(root.state)
        state = states[certificate_id]
        word = status(state, current=current, pinned=target.fingerprint_sha256)
        #
        # `waiting` is never a failed install of this certificate: `status` says
        # `failed` for that, and the next install is the one somebody asks for.
        #
        if word == "waiting" and current is not None and served != current:
            try:
                install(root, certificate_id, by="timer", now=now, installer=installer)
            except TargetError as exc:
                #
                # Removed since the registry was read: nothing to install, and
                # no reason to stop the sweep of the others.
                #
                if exc.code == "no_bmc":
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
                    certificate_id,
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
                states.get(certificate_id),
                current=current,
                pinned=_target(_registry(root), certificate_id).fingerprint_sha256,
            )
        said[certificate_id] = word
    return said


def _trust_served(root: Root, certificate_id: str, seen: BmcTarget, current: str) -> None:
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
        entry = registry.certificates.get(certificate_id) if registry is not None else None
        target = entry.bmc if entry is not None else None
        if (
            target is None
            or (target.address, target.port) != (seen.address, seen.port)
            or target.fingerprint_sha256 == current
        ):
            return
        cert_registry.set_bmc(
            root.registry_path,
            certificate_id=certificate_id,
            target=replace(target, fingerprint_sha256=current),
            runtime=root.runtime,
            require_secure=root.require_secure,
            lock_path=root.lock_path,
        )


def forget(certificate_id: str, *, directory: Path = STATE_DIRECTORY) -> None:
    """Take a target that is gone out of the state file."""

    with _state_lock(directory):
        states = read_state(directory)
        if states.pop(certificate_id, None) is not None:
            write_state(states, directory)


def row_state(
    states: Mapping[str, TargetState] | None,
) -> Callable[[str, str | None, str], dict[str, object]]:
    """What a certificate's row carries of its BMC: the word and what it rests on (B536).

    `states` None is a state file that could not be read: every BMC is then
    `unknown`, and the listing is otherwise as it was.
    """

    def state(certificate_id: str, current: str | None, pinned: str) -> dict[str, object]:
        known = (states or {}).get(certificate_id)
        return {
            "status": status(known, current=current, pinned=pinned),
            "checked_at": known.checked_at if known else None,
            "answered_at": known.answered_at if known else None,
            "served_sha256": known.served_sha256 if known else None,
            "attempt": asdict(known.attempt) if known and known.attempt else None,
        }

    return state
