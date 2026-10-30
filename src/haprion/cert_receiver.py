"""Registering a receiver: an account, a directory, a lock and a registry entry.

C7, and the whole of it below the command. A receiver is the one kind of
target this project does not create by writing a line somewhere: it is a
machine outside the installation that fetches private key material, so what
makes it exist is an account, a directory only that account can read, a lock
that binds its key to that directory, and an entry in the registry naming it.

Why one command rather than three steps
---------------------------------------
Because none of the layers is safe without the others, and each was a manual
step once. A registry entry without a directory
makes every publish fail on that entry; a key without a registry entry is a
way in that nothing names; a directory without a lock is key material with no
door. So `add` writes them in order - account, directory, lock, entry - and a
failure in any layer takes back exactly what this run created, leaving the
machine as it was found.

What is not here
----------------
Editing a receiver. A transport or a layout that changed under a receiver
would be discovered by that receiver at its next fetch, which is a renewal
away (B138), so a change is `remove` and `add` again - two decisions, both
visible. And the private key: the pair is made on the receiver and only its
public half is given to this command (B157). A private key that passed
through the manager has passed through one machine too many.

Root work, and root only. B142's interface helper will call these same
functions rather than grow a second implementation.
"""

from __future__ import annotations

import ctypes
import grp
import ipaddress
import os
import pwd
import re
import secrets
import shutil
import socket
import subprocess
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from haprion import atomic_file, cert_registry, exit_codes, ui_interface
from haprion.cert_lock import DEFAULT_LOCK_PATH
from haprion.cert_publish import PublishError
from haprion.config import (
    RECEIVER_ID,
    RECEIVER_TRANSPORTS,
    USERNAME,
    ConfigError,
    PathPolicy,
    Receiver,
    Registry,
    RuntimeConfig,
    check_allow_entries,
    load_runtime_config,
    receiver_id_names_a_host,
)
from haprion.envelope import Message, Outcome, envelope

USERADD = "/usr/sbin/useradd"
USERDEL = "/usr/sbin/userdel"
PASSWD_BIN = "/usr/bin/passwd"  # noqa: S105 - the binary that locks an account
SSHD = "/usr/sbin/sshd"
NGINX = "/usr/sbin/nginx"
SYSTEMCTL = "/usr/bin/systemctl"
RRSYNC = "/usr/bin/rrsync"
NOLOGIN = "/usr/sbin/nologin"
COMMAND_SHELL = "/bin/sh"
COMMAND_TIMEOUT = 30

#
# Who owns what this command creates. Named rather than written as 0 so a test
# that cannot become root can create the same layers as itself and still have
# every mode and every owner checked - the same patch `cert_publish` uses.
#
ROOT_UID = 0
ROOT_GID = 0

#
# The account name derived from the ID, and the limit Linux holds it to. A
# name that would be cut off is refused rather than truncated: two receivers
# whose IDs differ late in a long name would otherwise share one account.
#
OWNER_PREFIX = "crx-"
MAX_OWNER = 32
HTTPS_OWNER = "www-data"

#
# Where an `https` receiver is served from: the interface's own server block
# on 443, through one `include` of a file only this command writes (B160).
# Not a second server block - nginx serves the first block for a name and
# port and ignores the rest, with a warning `nginx -t` does not fail on, so
# a block beside the interface's would test clean and never answer. The
# prefix is one the interface does not route: it owns `/certificates/...`.
#
HTTPS_PREFIX = "/certdist"

#
# An https receiver's own secret (B306, security review S03): an address list
# alone let any host on an allowed network fetch private keys. The password is
# made by whoever asks - this command, or the interface - and shown to them
# once; what reaches this module, and the job that carries it, is the hash
# nginx checks, never the password. yescrypt (`$y$`), Debian's own form for
# account passwords: deliberately slow, and made and checked by the same C
# library nginx checks it through (libxcrypt's crypt(3)), since Python's crypt
# module is gone from 3.13.
#
SECRET_HASH = re.compile(r"\$y\$[./0-9A-Za-z]{3,8}\$[./0-9A-Za-z]{22}\$[./0-9A-Za-z]{43}")
SECRET_BYTES = 24
LIBCRYPT = "libcrypt.so.1"
#
# libxcrypt's own limits: CRYPT_OUTPUT_SIZE for a setting or a hash, and
# sizeof(struct crypt_data) for crypt_rn's work area.
#
_CRYPT_OUTPUT_SIZE = 384
_CRYPT_DATA_SIZE = 32768

type Runner = Callable[[Sequence[str]], tuple[int, str]]
# One step that takes back what a registration did, and what it names.
type Undo = tuple[str, Callable[[], None]]


class ReceiverError(Exception):
    """A registration that was refused or failed, with the code it is reported under."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        exit_code: int = exit_codes.USAGE,
        details: dict[str, Any] | None = None,
    ):
        super().__init__(message)
        self.code = code
        self.exit_code = exit_code
        self.details = details


#
# What the result is called, by the helper and by the command alike.
#
OPERATION = "cert_receiver"


@dataclass(frozen=True, slots=True)
class Layer:
    """One of the four things a receiver is, and what this run did to it."""

    name: str
    state: str
    detail: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {"layer": self.name, "state": self.state, "detail": self.detail}


@dataclass(frozen=True, slots=True)
class Locations:
    """The files this command owns outside the registry, injectable for the tests."""

    sshd_dropin: Path = Path("/etc/ssh/sshd_config.d/haprion-receivers.conf")
    nginx_snippet: Path = Path("/etc/nginx/snippets/haprion-receivers.conf")
    ui_site: Path = Path("/etc/nginx/sites-available/haprion")
    ui_tls: Path = Path("/etc/haprion/ui-tls.conf")
    receiver_secrets: Path = Path("/etc/nginx/haprion-receivers")


def run_command(argv: Sequence[str]) -> tuple[int, str]:
    """Run one of the fixed binaries above and return what it said."""

    try:
        completed = subprocess.run(  # noqa: S603 - fixed paths, arguments built here
            list(argv),
            capture_output=True,
            text=True,
            timeout=COMMAND_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, str(exc)
    return completed.returncode, (completed.stdout + completed.stderr).strip()


def resolve_forward(name: str) -> tuple[str, ...]:
    try:
        answers = socket.getaddrinfo(name, None)
    except OSError:
        return ()
    return tuple(sorted({str(answer[4][0]) for answer in answers}))


def account_home(owner: str) -> Path | None:
    """Where sshd will look for the account's lock: its home, as the system has it."""

    try:
        return Path(pwd.getpwnam(owner).pw_dir)
    except KeyError:
        return None


@dataclass(frozen=True, slots=True)
class Tools:
    """Everything that reaches outside this process, so a test can hold it still."""

    run: Runner = run_command
    forward: Callable[[str], tuple[str, ...]] = resolve_forward
    now: Callable[[], datetime] = lambda: datetime.now(UTC)
    home: Callable[[str], Path | None] = account_home


@dataclass(frozen=True, slots=True)
class Result:
    """What a registration or a removal did, layer by layer."""

    receiver_id: str
    action: str
    layers: tuple[Layer, ...] = ()
    instructions: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.receiver_id,
            "action": self.action,
            "layers": [layer.as_dict() for layer in self.layers],
            "instructions": list(self.instructions),
        }


def answer(
    result: Result, *, request_id: str, extra: Mapping[str, Any] | None = None
) -> tuple[dict[str, Any], int]:
    """A result as its envelope and exit code, the helper's and `--json`'s alike.

    A layer that failed is a warning, and the whole is `partial`: the rest was
    done, and that one is left for a person (review 26-10-24, 13-02). The two
    used to build this each their own way - the helper crashed in the envelope
    and the command said `done`.
    """

    failed = tuple(layer for layer in result.layers if layer.state == "failed")
    outcome: Outcome = "partial" if failed else "done"
    document = envelope(
        operation=OPERATION,
        outcome=outcome,
        cluster=None,
        request_id=request_id,
        result=result.as_dict() | dict(extra or {}),
        warnings=tuple(
            Message(code=f"{layer.name}_failed", message=layer.detail or layer.name)
            for layer in failed
        ),
    )
    return document, exit_codes.for_outcome(outcome)


#
# What the caller may say
#


def default_owner(receiver_id: str) -> str:
    """`crx-` and the ID with its dots turned into dashes, or a refusal.

    Derived rather than asked for, so `ls -l` in a receiver's directory names
    the receiver. Refused rather than shortened when it does not fit: the
    operator then chooses a name, and two long IDs cannot quietly become one
    account.
    """

    candidate = OWNER_PREFIX + receiver_id.replace(".", "-")
    if len(candidate) > MAX_OWNER or not USERNAME.fullmatch(candidate):
        raise ReceiverError(
            "bad_input",
            f"no account name can be derived from {receiver_id!r} "
            f"({candidate!r} is not a usable account name). Name one with --owner.",
        )
    return candidate


def check_identity(receiver_id: str, tools: Tools) -> None:
    """B141: the ID is the fetching host, because the lock binds to it.

    `from=` in `authorized_keys` is what makes a stolen key useless from
    another host; an https receiver is held to its own `--allow` list and
    password instead. A name has to resolve, because
    its addresses are what the lock is written with (`from_patterns`, B162);
    its PTR record is not asked about. sshd compares `from=` against the
    peer's address unless `UseDNS yes` is set, and against the address as
    well as the name when it is, so a host whose reverse lookup answers with
    a sibling name - one address carrying several service names is the
    common shape of a DNS zone - is accepted by the address half of the
    lock either way. Refusing it here would refuse ordinary DNS.
    """

    if not RECEIVER_ID.fullmatch(receiver_id):
        raise ReceiverError("bad_input", f"{receiver_id!r} is not a receiver ID")
    if not receiver_id_names_a_host(receiver_id):
        raise ReceiverError(
            "bad_input",
            f"{receiver_id!r} is neither a hostname nor an IP address. A receiver is named "
            "by the host that fetches, because that is what its key and its whitelist are "
            "bound to.",
        )
    from_patterns(receiver_id, tools)


def from_patterns(receiver_id: str, tools: Tools) -> tuple[str, ...]:
    """What `from=` may hold for this receiver: the ID, and its addresses.

    sshd's `UseDNS` is off by default, and then `from=` matches addresses
    only - a lock naming the host alone refuses the very host it was issued
    for, with a log line about a correct key from an unpermitted host. The
    address is what sshd always has, and the name is what an operator reads
    and what `UseDNS yes` would match, so the lock carries both (B162). A host
    that changes address is `remove` and `add` again, as for any other field
    of a receiver (B138).
    """

    try:
        ipaddress.ip_address(receiver_id)
    except ValueError:
        pass
    else:
        return (receiver_id,)
    addresses = tools.forward(receiver_id)
    if not addresses:
        raise ReceiverError(
            "receiver_unresolvable", f"{receiver_id} does not resolve; sshd could not match from="
        )
    return (receiver_id, *addresses)


def read_public_key(path: Path) -> str:
    """The receiver's public key from the `.pub` file its ssh-keygen wrote."""

    try:
        text = path.read_text(encoding="ascii")
    except (OSError, UnicodeDecodeError) as exc:
        raise ReceiverError("bad_input", f"the public key could not be read: {exc}") from exc
    return parse_public_key(text, str(path))


def parse_public_key(text: str, source: str) -> str:
    """One line of the shapes OpenSSH writes, and nothing after it.

    One line, because this text is written into `authorized_keys` in front of
    a forced command: a second line would be a second key, with no
    restrictions and nobody's decision behind it. `source` names where the
    text came from - the file, or the interface's form - in the refusal.
    """

    try:
        text.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ReceiverError(
            "bad_input", f"{source} is not ASCII; a public key in OpenSSH's own form is"
        ) from exc
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if len(lines) != 1:
        raise ReceiverError(
            "bad_input", f"{source} holds {len(lines)} keys; a receiver registers exactly one"
        )
    line = lines[0]
    if not re.fullmatch(
        r"(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)) [A-Za-z0-9+/=]+( [^\r\n]{0,128})?",
        line,
    ):
        raise ReceiverError(
            "bad_input",
            f"{source} does not hold a public key in OpenSSH's own form. Give the .pub file "
            "the receiver's ssh-keygen wrote, not a private key and not a certificate.",
        )
    return line


def authorized_keys_line(receiver: Receiver, public_key: str, tools: Tools) -> str:
    """The one line that is the whole of what a receiver may do over ssh.

    `restrict` first, which is OpenSSH's own way of saying "everything off",
    so a future option this project has not heard of is off as well.
    `from=` binds the key to the host it was issued for - by name and by
    address, see `from_patterns` - and for `rsync` the forced `rrsync -ro`
    binds it to one directory, read-only - the key cannot run a shell,
    cannot write, and cannot read a neighbour's certificate.
    """

    options = ["restrict", f'from="{",".join(from_patterns(receiver.receiver_id, tools))}"']
    if receiver.transport == "rsync":
        options.append(f'command="{RRSYNC} -ro {receiver.path}"')
    return ",".join(options) + " " + public_key


#
# The layers
#


def account_exists(owner: str) -> bool:
    try:
        pwd.getpwnam(owner)
    except KeyError:
        return False
    return True


def create_account(owner: str, home: Path, transport: str, tools: Tools) -> None:
    """Make the account able to run exactly the transport its key permits.

    OpenSSH runs an ``authorized_keys command=`` through the account's login
    shell with ``-c``. The rsync lock therefore needs a real shell or it can
    never start rrsync; the key's ``restrict``, ``from=`` and forced command
    remain the boundary. ``internal-sftp`` is sshd's in-process server and
    keeps ``nologin``. The root-owned home and key file stop either account
    changing that boundary.
    """

    shell = COMMAND_SHELL if transport == "rsync" else NOLOGIN

    code, output = tools.run(
        [USERADD, "--system", "--home-dir", str(home), "--shell", shell, owner]
    )
    if code != 0:
        raise ReceiverError(
            "account_failed", f"useradd {owner} failed: {output}", exit_code=exit_codes.IO_ERROR
        )
    code, output = tools.run([PASSWD_BIN, "--lock", owner])
    if code != 0:
        raise ReceiverError(
            "account_failed",
            f"{PASSWD_BIN} --lock {owner} failed: {output}",
            exit_code=exit_codes.IO_ERROR,
        )


def remove_account(owner: str, tools: Tools) -> Layer:
    if not account_exists(owner):
        return Layer("account", "absent", owner)
    code, output = tools.run([USERDEL, owner])
    if code != 0:
        return Layer("account", "failed", f"userdel {owner}: {output}")
    return Layer("account", "removed", owner)


def _own(path: Path, owner: str, mode: int) -> None:
    """Root's directory, readable by one account and by nobody else.

    Root-owned rather than account-owned on purpose: what is published into it
    is the manager's statement of what that receiver should have, and an
    account that owned the directory could replace it. The group is the
    account's own, created with it, so group read reaches one receiver.
    """

    record = pwd.getpwnam(owner)
    os.chown(path, ROOT_UID, record.pw_gid)
    os.chmod(path, mode)


def create_directory(path: Path, owner: str) -> Layer:
    """The directory a receiver fetches from, made the way the publisher demands it."""

    if path.exists():
        if not path.is_dir() or path.is_symlink():
            raise ReceiverError("bad_input", f"{path} exists and is not a directory")
        if any(path.iterdir()):
            raise ReceiverError(
                "bad_input",
                f"{path} already holds files. A receiver's directory is made by this "
                "command; point --path somewhere new or empty it first.",
            )
        _own(path, owner, 0o750)
        return Layer("directory", "present", str(path))
    try:
        path.mkdir(parents=True, mode=0o750)
        _own(path, owner, 0o750)
    except OSError as exc:
        raise ReceiverError(
            "write_failed", f"{path} could not be created: {exc}", exit_code=exit_codes.IO_ERROR
        ) from exc
    return Layer("directory", "created", str(path))


LOCK_HEADER = "# Written by haprion-cert-receiver. One receiver, one key, one directory."
LOCK_FROM = re.compile(r'(?:^|,)from="([^"]*)"')


def write_authorized_keys(home: Path, line: str) -> Layer:
    """The lock itself: one root-owned line the account cannot change.

    `.ssh` sits inside the receiver's directory, which is the account's home
    (B160). Root-owned and traversable, the shape B131 gave the node accounts:
    sshd reads the lock as root, and the account may reach nothing but read it.
    """

    ssh_directory = home / ".ssh"
    ssh_directory.mkdir(parents=True, exist_ok=True)
    os.chown(ssh_directory, ROOT_UID, ROOT_GID)
    os.chmod(ssh_directory, 0o755)  # noqa: S103 - root-owned, as B131 left the nodes
    keys = ssh_directory / "authorized_keys"
    content = f"{LOCK_HEADER}\n{line}\n"
    #
    # Written beside it and moved into place (26-10-18): a key replaced over
    # a working one must leave the old lock whole if the write stops half way.
    #
    atomic_file.write(keys, content.encode("ascii"), mode=0o644, uid=ROOT_UID, gid=ROOT_GID)
    return Layer("lock", "created", str(keys))


def _sftp_receivers(registry: Registry) -> tuple[Receiver, ...]:
    return tuple(
        receiver
        for _, receiver in sorted(registry.receivers.items())
        if receiver.transport == "sftp"
    )


def _https_receivers(registry: Registry) -> tuple[Receiver, ...]:
    return tuple(
        receiver
        for _, receiver in sorted(registry.receivers.items())
        if receiver.transport == "https"
    )


def render_sshd_dropin(registry: Registry) -> str:
    """Every `sftp` receiver's Match block, rendered from the registry as a whole.

    Rendered whole rather than appended to, so removing a receiver is the same
    operation as adding one: the file is what the registry says, every time.
    """

    lines = [
        "# Written by haprion-cert-receiver from the certificate registry.",
        "# One block per sftp receiver. Hand edits are lost at the next change.",
        "",
    ]
    for receiver in _sftp_receivers(registry):
        lines += [
            f"Match User {receiver.owner}",
            f"    ChrootDirectory {receiver.path}",
            "    ForceCommand internal-sftp -R",
            "    AllowTcpForwarding no",
            "    AllowAgentForwarding no",
            "    X11Forwarding no",
            "    PermitTunnel no",
            "",
        ]
    return "\n".join(lines).rstrip("\n") + "\n"


def read_ui_tls(locations: Locations) -> dict[str, str]:
    """The hostname and certificate the interface is served under (05-platform-nginx).

    Read by `ui_interface.read_config`, the one reader of that file: the
    interface certificate's installer (B188) and this module must agree on
    what it says, down to which lines they refuse.
    """

    try:
        config = ui_interface.read_config(locations.ui_tls)
    except PublishError as exc:
        raise ReceiverError(
            "dependency_unavailable",
            f"{exc}; an https receiver is served under the interface's own certificate, "
            "which that file names.",
            exit_code=exit_codes.CONFIG,
        ) from exc
    return {
        "TLS_CERT": str(config.cert),
        "TLS_KEY": str(config.key),
        "SERVER_NAME": config.server_name,
    }


def new_secret() -> str:
    """A receiver's password: random, URL-safe, shown once by whoever made it."""

    return secrets.token_urlsafe(SECRET_BYTES)


def secret_hash(password: str) -> str:
    """The `$y$` form nginx's auth_basic_user_file reads, with a fresh salt."""

    library = _libcrypt()
    setting = ctypes.create_string_buffer(_CRYPT_OUTPUT_SIZE)
    #
    # No random bytes passed: libxcrypt takes them from the kernel itself.
    #
    if not library.crypt_gensalt_rn(b"$y$", 0, None, 0, setting, _CRYPT_OUTPUT_SIZE):
        raise ReceiverError(
            "dependency_unavailable",
            "libcrypt made no yescrypt salt",
            exit_code=exit_codes.UNAVAILABLE,
        )
    hashed = crypt(password, setting.value.decode("ascii"))
    if not SECRET_HASH.fullmatch(hashed):
        raise ReceiverError(
            "dependency_unavailable",
            "libcrypt made no yescrypt hash",
            exit_code=exit_codes.UNAVAILABLE,
        )
    return hashed


def crypt(password: str, setting: str) -> str:
    """crypt(3) as nginx calls it: a stored hash as the setting gives it back on a match."""

    library = _libcrypt()
    data = ctypes.create_string_buffer(_CRYPT_DATA_SIZE)
    result = library.crypt_rn(
        password.encode("utf-8"), setting.encode("ascii"), data, _CRYPT_DATA_SIZE
    )
    #
    # A failure is NULL or a string starting with '*', never a hash.
    #
    hashed = ctypes.string_at(result).decode("ascii") if result else "*"
    if hashed.startswith("*"):
        raise ReceiverError(
            "dependency_unavailable",
            "libcrypt refused the setting",
            exit_code=exit_codes.UNAVAILABLE,
        )
    return hashed


def _libcrypt() -> ctypes.CDLL:
    library = ctypes.CDLL(LIBCRYPT)
    library.crypt_gensalt_rn.restype = ctypes.c_char_p
    library.crypt_gensalt_rn.argtypes = (
        ctypes.c_char_p, ctypes.c_ulong, ctypes.c_char_p, ctypes.c_int,
        ctypes.c_char_p, ctypes.c_int,
    )  # fmt: skip
    library.crypt_rn.restype = ctypes.c_void_p
    library.crypt_rn.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_int)
    return library


def secret_file(receiver_id: str, locations: Locations) -> Path:
    return locations.receiver_secrets / f"{receiver_id}.htpasswd"


def write_secret(receiver_id: str, hashed: str, locations: Locations) -> Layer:
    """The receiver's user file: root's, readable by the account nginx serves as.

    Written to a new name and moved into place, so nginx - which reads the file
    on every request - never sees half of it.
    """

    if not SECRET_HASH.fullmatch(hashed):
        raise ReceiverError("bad_input", "the receiver's secret is not a yescrypt hash")
    group = grp.getgrnam(HTTPS_OWNER).gr_gid
    directory = locations.receiver_secrets
    directory.mkdir(mode=0o750, parents=True, exist_ok=True)
    os.chown(directory, ROOT_UID, group)
    os.chmod(directory, 0o750)  # noqa: S103 - nginx's group reads the files in it
    target = secret_file(receiver_id, locations)
    atomic_file.write(
        target, f"{receiver_id}:{hashed}\n".encode("ascii"), mode=0o640, uid=ROOT_UID, gid=group
    )
    return Layer("secret", "created", str(target))


def render_nginx_snippet(registry: Registry, locations: Locations | None = None) -> str:
    """One location per `https` receiver, whitelisted per line, for the interface's block.

    Rendered whole from the registry like the sshd drop-in, and holding only
    `location` blocks: the server block - port, certificate, hostname - is the
    interface's own, and this file reaches it through one `include` line that
    `05-platform-nginx` puts there. A receiver never edits that block (B157).
    """

    lines = [
        "# Written by haprion-cert-receiver from the certificate registry.",
        "# Included by the interface's server block. Hand edits are lost at the next change.",
        "",
    ]
    for receiver in _https_receivers(registry):
        lines.append(f"location {HTTPS_PREFIX}/{receiver.receiver_id}/ {{")
        lines.append(f"    alias {receiver.path}/;")
        lines.append("    autoindex off;")
        #
        # Both, not either: the address list and the receiver's own secret.
        #
        lines.append("    satisfy all;")
        for entry in receiver.allow:
            lines.append(f"    allow {entry};")
        lines.append("    deny all;")
        lines.append(f'    auth_basic "{receiver.receiver_id}";')
        lines.append(
            f"    auth_basic_user_file {secret_file(receiver.receiver_id, locations or Locations())};"
        )
        lines.append("}")
        lines.append("")
    return "\n".join(lines).rstrip("\n") + "\n"


def check_snippet_included(locations: Locations) -> None:
    """Refuse an `https` receiver whose locations nothing would serve.

    The same failure Ö21 measured, from the other side: a snippet nginx never
    includes tests clean and never answers. So the interface's site is read,
    and a site without the include line - an installation older than B160 that
    has not rerun `05-platform-nginx` - is a refusal, not a silent receiver.
    """

    try:
        site = locations.ui_site.read_text(encoding="utf-8")
    except OSError as exc:
        raise ReceiverError(
            "dependency_unavailable",
            f"{locations.ui_site} could not be read; an https receiver is served from the "
            "interface's own server block, and that is the file it lives in.",
            exit_code=exit_codes.CONFIG,
        ) from exc
    wanted = f"include {locations.nginx_snippet};"
    if not any(line.strip() == wanted for line in site.splitlines()):
        raise ReceiverError(
            "dependency_unavailable",
            f"{locations.ui_site} does not include {locations.nginx_snippet}, so nginx would "
            "never serve the receiver. Rerun install/platform/05-platform-nginx, which adds "
            "the include line to the interface's server block.",
            exit_code=exit_codes.CONFIG,
        )


def _write_service_file(path: Path, content: str) -> None:
    """A drop-in sshd or nginx reads, root's and world-readable, whole or not at all.

    It was truncated and written in place: a write that stopped half way left
    sshd a drop-in it refuses, which is the lock-out `_write_checked` exists
    to prevent (review 2026-10-22, 4-7).
    """

    atomic_file.write(path, content.encode("utf-8"), mode=0o644, uid=ROOT_UID, gid=ROOT_GID)


def _write_checked(
    path: Path,
    content: str,
    *,
    check: Sequence[str],
    reload: Sequence[str] | None,
    tools: Tools,
    what: str,
) -> Layer:
    """Write a service's configuration, test it, and put the old one back if it fails.

    A drop-in that sshd refuses locks out everyone, not only the receiver that
    was being registered, and an nginx that will not start takes the interface
    with it. So the previous content is held, the test is run, and a failure
    restores the file before the refusal is reported.
    """

    before = path.read_text(encoding="utf-8") if path.exists() else None
    path.parent.mkdir(parents=True, exist_ok=True)
    _write_service_file(path, content)
    code, output = tools.run(check)
    if code != 0:
        if before is None:
            path.unlink(missing_ok=True)
        else:
            _write_service_file(path, before)
        raise ReceiverError(
            "config_refused",
            f"{what} refused the change and it was taken back: {output}",
            exit_code=exit_codes.IO_ERROR,
        )
    if reload is not None:
        code, output = tools.run(reload)
        if code != 0:
            raise ReceiverError(
                "config_refused",
                f"{what} could not be reloaded: {output}",
                exit_code=exit_codes.IO_ERROR,
            )
    return Layer("lock", "created", str(path))


#
# The operations
#


def _registry_path(policy: PathPolicy) -> Path:
    if policy.certificate_registry is None:
        raise ReceiverError(
            "dependency_unavailable",
            "no certificate registry is configured. Add certificate_registry to the runtime "
            "policy.",
            exit_code=exit_codes.CONFIG,
        )
    return policy.certificate_registry


def _candidate(registry: Registry, receiver: Receiver) -> Registry:
    """The registry as it will be, for rendering a lock before the entry is written."""

    return Registry(
        receivers={**registry.receivers, receiver.receiver_id: receiver},
        certificates=registry.certificates,
    )


def _without(registry: Registry, receiver_id: str) -> Registry:
    return Registry(
        receivers={k: v for k, v in registry.receivers.items() if k != receiver_id},
        certificates=registry.certificates,
    )


def check_request(
    transport: str,
    allow: Sequence[str],
    public_key: Path | str | None,
    hashed_secret: str | None = None,
) -> None:
    """What the command will not do, said before anything is written.

    `public_key` is the `.pub` file's path from the command line, or the key
    text itself from the interface's form; here only its presence matters.
    """

    if transport not in RECEIVER_TRANSPORTS:
        raise ReceiverError(
            "bad_input", f"--transport must be one of: {', '.join(RECEIVER_TRANSPORTS)}"
        )
    if transport == "https":
        if not allow:
            raise ReceiverError(
                "bad_input",
                "an https receiver fetches with no key at all, so --allow is what stands "
                "between its directory and everyone. Name at least one address or network.",
            )
        #
        # The loader's rule, before the first side effect. Until 2026-09-20
        # the registry write was the first thing to judge an entry, and by
        # then nginx had been reloaded with it: `allow all;` is valid nginx.
        #
        try:
            check_allow_entries(allow)
        except ValueError as exc:
            raise ReceiverError("bad_input", f"--allow{exc}") from None
        if public_key is not None:
            raise ReceiverError("bad_input", "an https receiver has no key; leave out --public-key")
        if hashed_secret is None or not SECRET_HASH.fullmatch(hashed_secret):
            raise ReceiverError(
                "bad_input",
                "an https receiver fetches with a secret of its own as well as from its "
                "addresses; the request carries no valid one",
            )
        return
    if hashed_secret is not None:
        raise ReceiverError("bad_input", "a secret belongs to an https receiver only")
    if allow:
        raise ReceiverError("bad_input", "--allow belongs to an https receiver only")
    if public_key is None:
        raise ReceiverError(
            "bad_input",
            "--public-key is required: the pair is made on the receiver and only its public "
            "half is given to the manager.",
        )


@contextmanager
def exclusive(
    policy: PathPolicy, *, require_secure: bool, lock_path: Path
) -> Iterator[RuntimeConfig]:
    """The certificate lock, and the configuration as it reads once it is held.

    Every receiver change renders the nginx snippet and the sshd drop-in whole
    from the registry it started from, so a change that read the registry
    before another one wrote it would write its own view over the other's
    block. The reading is made here, under the lock, and nothing outside it is
    trusted. The lock is held for the whole change, which is why the registry
    writes it ends in are told not to take it again.
    """

    with ExitStack() as stack:
        try:
            stack.enter_context(cert_registry.locked(lock_path))
        except cert_registry.RegistryError as exc:
            code, exit_code = _write_refusal(exc)
            raise ReceiverError(code, str(exc), exit_code=exit_code) from exc
        try:
            runtime = load_runtime_config(policy, require_secure=require_secure)
        except ConfigError as exc:
            raise ReceiverError(
                "bad_input" if exc.exit_code == exit_codes.USAGE else "dependency_unavailable",
                str(exc),
                exit_code=exc.exit_code,
            ) from exc
        if runtime.registry is None:
            raise ReceiverError(
                "dependency_unavailable",
                "no certificate registry is configured",
                exit_code=exit_codes.CONFIG,
            )
        yield runtime


def add(
    policy: PathPolicy,
    *,
    receiver_id: str,
    transport: str,
    public_key: Path | str | None = None,
    owner: str | None = None,
    path: Path | None = None,
    allow: Sequence[str] = (),
    hashed_secret: str | None = None,
    tools: Tools | None = None,
    locations: Locations | None = None,
    require_secure: bool = True,
    lock_path: Path = DEFAULT_LOCK_PATH,
) -> Result:
    """Make a receiver whole, or leave the machine as it was found.

    `public_key` is a path to the `.pub` file (the command line) or the key
    text itself (the interface, which has the operator paste it and never
    has a file the helper could be pointed at).
    """

    tools = tools or Tools()
    locations = locations or Locations()
    check_request(transport, allow, public_key, hashed_secret)
    check_identity(receiver_id, tools)

    with exclusive(policy, require_secure=require_secure, lock_path=lock_path) as runtime:
        return _add(
            policy,
            runtime,
            receiver_id=receiver_id,
            transport=transport,
            public_key=public_key,
            owner=owner,
            path=path,
            allow=allow,
            hashed_secret=hashed_secret,
            tools=tools,
            locations=locations,
            require_secure=require_secure,
        )


def _add(
    policy: PathPolicy,
    runtime: RuntimeConfig,
    *,
    receiver_id: str,
    transport: str,
    public_key: Path | str | None,
    owner: str | None,
    path: Path | None,
    allow: Sequence[str],
    hashed_secret: str | None,
    tools: Tools,
    locations: Locations,
    require_secure: bool,
) -> Result:
    """`add`, with the lock held and the registry read under it."""

    registry = runtime.registry
    if registry is None:
        raise ReceiverError(
            "dependency_unavailable",
            "no certificate registry is configured",
            exit_code=exit_codes.CONFIG,
        )
    if receiver_id in registry.receivers:
        raise ReceiverError(
            "already_exists",
            f"receiver {receiver_id} is already registered. A transport or a directory is "
            "not edited under a receiver; remove it and register it again.",
        )

    if transport == "https":
        account = HTTPS_OWNER
        if not account_exists(account):
            raise ReceiverError(
                "dependency_unavailable",
                f"an https receiver is served by nginx as {HTTPS_OWNER}, and that account "
                "does not exist",
                exit_code=exit_codes.CONFIG,
            )
    else:
        account = owner or default_owner(receiver_id)
        if not USERNAME.fullmatch(account):
            raise ReceiverError("bad_input", f"{account!r} is not a valid account name")
        if account_exists(account):
            raise ReceiverError(
                "already_exists",
                f"account {account} already exists. A receiver's account is created by this "
                "command, so give --owner a name that is not in use.",
            )

    directory = path
    if directory is None:
        if policy.receiver_root is None:
            raise ReceiverError(
                "dependency_unavailable",
                "no receiver_root is configured, so there is nowhere to put the directory. "
                "Add receiver_root to the runtime policy or pass --path.",
                exit_code=exit_codes.CONFIG,
            )
        directory = policy.receiver_root / receiver_id
    if not directory.is_absolute():
        raise ReceiverError("bad_input", "--path must be absolute")

    if public_key is None:
        key_line = ""
    elif isinstance(public_key, Path):
        key_line = read_public_key(public_key)
    else:
        key_line = parse_public_key(public_key, "the public key given")
    receiver = Receiver(
        receiver_id=receiver_id,
        path=directory,
        owner=account,
        transport=transport,
        layout="per-certificate",
        allow=tuple(allow),
    )

    undo: list[Undo] = []
    layers: list[Layer] = []
    try:
        if transport != "https" and not account_exists(account):
            create_account(account, directory, transport, tools)
            undo.append((f"account {account}", lambda: _checked(tools.run([USERDEL, account]))))
            layers.append(Layer("account", "created", account))
        else:
            layers.append(Layer("account", "present", account))

        existed = directory.exists()
        layers.append(create_directory(directory, account))
        if not existed:
            undo.append((f"directory {directory}", lambda: shutil.rmtree(directory)))

        if transport == "https":
            assert hashed_secret is not None  # noqa: S101 - check_request requires it
            layers.append(write_secret(receiver_id, hashed_secret, locations))
            undo.append(
                (
                    f"secret {secret_file(receiver_id, locations)}",
                    lambda: secret_file(receiver_id, locations).unlink(missing_ok=True),
                )
            )
        layers.append(_write_lock(receiver, key_line, registry, locations, tools, undo))

        cert_registry.set_receiver(
            _registry_path(policy),
            receiver_id=receiver_id,
            fields=_entry_fields(receiver),
            runtime=runtime,
            require_secure=require_secure,
            lock_held=True,
        )
        layers.append(Layer("registry", "created", receiver_id))
    except (ReceiverError, OSError, cert_registry.RegistryError) as exc:
        left = _undo(undo)
        if isinstance(exc, ReceiverError) and not left:
            raise
        code, exit_code = (
            (exc.code, exc.exit_code) if isinstance(exc, ReceiverError) else _write_refusal(exc)
        )
        message = str(exc)
        if left:
            message += "; not undone: " + "; ".join(left)
        raise ReceiverError(
            code,
            message,
            exit_code=exit_code,
            details={"not_undone": left} if left else None,
        ) from exc

    return Result(receiver_id, "added", tuple(layers), instructions(receiver, locations))


def _write_refusal(exc: OSError | cert_registry.RegistryError) -> tuple[str, int]:
    """The code and exit code a file or registry error is answered with.

    A registry another run held past the wait is that, and not a write that
    failed (review 26-10-29, O06). `failed` rather than `blocked`: the
    receiver's contract has no `blocked`.
    """

    if isinstance(exc, cert_registry.RegistryError) and exc.code == "operation_locked":
        return exc.code, exit_codes.FAILED
    return "write_failed", exit_codes.IO_ERROR


def _entry_fields(receiver: Receiver) -> dict[str, Any]:
    fields: dict[str, Any] = {"path": str(receiver.path), "owner": receiver.owner}
    fields["transport"] = receiver.transport
    fields["layout"] = receiver.layout
    if receiver.allow:
        fields["allow"] = list(receiver.allow)
    return fields


def _write_lock(
    receiver: Receiver,
    key_line: str,
    registry: Registry,
    locations: Locations,
    tools: Tools,
    undo: list[Undo],
) -> Layer:
    """The lock for this transport, with the undo that takes it off again."""

    if receiver.transport == "https":
        check_snippet_included(locations)
        before = (
            locations.nginx_snippet.read_text(encoding="utf-8")
            if locations.nginx_snippet.exists()
            else None
        )
        layer = _write_checked(
            locations.nginx_snippet,
            render_nginx_snippet(_candidate(registry, receiver), locations),
            check=[NGINX, "-t"],
            reload=[SYSTEMCTL, "reload", "nginx"],
            tools=tools,
            what="nginx",
        )
        undo.append(
            (
                f"nginx snippet {locations.nginx_snippet}",
                lambda: _restore(
                    locations.nginx_snippet, before, [SYSTEMCTL, "reload", "nginx"], tools
                ),
            )
        )
        return layer

    home = receiver.path
    keys_layer = write_authorized_keys(home, authorized_keys_line(receiver, key_line, tools))
    undo.append((f"keys {home / '.ssh'}", lambda: shutil.rmtree(home / ".ssh")))
    if receiver.transport == "sftp":
        before = (
            locations.sshd_dropin.read_text(encoding="utf-8")
            if locations.sshd_dropin.exists()
            else None
        )
        _write_checked(
            locations.sshd_dropin,
            render_sshd_dropin(_candidate(registry, receiver)),
            check=[SSHD, "-t"],
            reload=[SYSTEMCTL, "reload", "ssh"],
            tools=tools,
            what="sshd",
        )
        undo.append(
            (
                f"sshd drop-in {locations.sshd_dropin}",
                lambda: _restore(
                    locations.sshd_dropin, before, [SYSTEMCTL, "reload", "ssh"], tools
                ),
            )
        )
    return keys_layer


def _undo(steps: Sequence[Undo]) -> list[str]:
    """Take back each step, newest first, and say which could not be.

    Every step is tried whatever the one before it did. Each used to be run
    under `suppress(Exception)`, so an account or a directory left behind was
    seen by nobody (review 2026-10-22, 4-12).
    """

    left = []
    for name, step in reversed(steps):
        try:
            step()
        except Exception as exc:  # noqa: BLE001 - every step is tried; what failed is reported
            left.append(f"{name}: {exc}")
    return left


def _checked(result: tuple[int, str]) -> None:
    code, said = result
    if code != 0:
        raise RuntimeError(said.strip() or f"exit {code}")


def _restore(path: Path, before: str | None, reload: Sequence[str], tools: Tools) -> None:
    """Put the service's previous configuration back, and make the service run it.

    The reload is the point: a file put back without one leaves sshd or nginx
    running the configuration that was just refused, until something else
    reloads it (review 2026-09-20). A reload that fails is said with the
    failure being undone.
    """

    if before is None:
        path.unlink(missing_ok=True)
    else:
        _write_service_file(path, before)
    _checked(tools.run(reload))


def manager_name(locations: Locations | None = None) -> str:
    """The name a receiver reaches this manager by.

    The interface's `SERVER_NAME` (05-platform-nginx): it is the name the
    operator already resolves and pins a certificate to, and the receivers
    fetch by it. The bare hostname only where that file is absent,
    which is an installation without the interface.
    """

    try:
        return read_ui_tls(locations or Locations())["SERVER_NAME"]
    except ReceiverError:
        return socket.gethostname()


def instructions(receiver: Receiver, locations: Locations) -> tuple[str, ...]:
    """What the receiver's operator needs, in the words `04-node-prepare` uses."""

    host = manager_name(locations)
    if receiver.transport == "https":
        server_name = read_ui_tls(locations)["SERVER_NAME"]
        return (
            f"transport: https, from {', '.join(receiver.allow)} and with its own secret",
            f"url: https://{server_name}{HTTPS_PREFIX}/{receiver.receiver_id}/"
            "<certificate>/fullchain.pem",
            f"user: {receiver.receiver_id}; the password is the one shown when the secret was made",
            "the private key is beside it as privkey.pem, under the same two locks",
        )
    if receiver.transport == "sftp":
        return (
            "transport: sftp, read-only, chrooted into its own directory",
            f"user: {receiver.owner}@{host}",
            "path: / inside the chroot is one directory per certificate",
            f"the key you gave is bound to {receiver.receiver_id} and its addresses; fetch from there",
        )
    return (
        "transport: rsync over ssh, read-only",
        f"user: {receiver.owner}@{host}",
        f"fetch: rsync -rt --no-owner --no-group --chmod=D700,F600 "
        f"{receiver.owner}@{host}:<certificate>/ /local/staging/ "
        "(examples/receivers/fetch-rsync installs the files as root's)",
        f"the key you gave is bound to {receiver.receiver_id} and its addresses; fetch from there",
    )


def set_secret(
    policy: PathPolicy,
    *,
    receiver_id: str,
    hashed_secret: str,
    tools: Tools | None = None,
    locations: Locations | None = None,
    require_secure: bool = True,
    lock_path: Path = DEFAULT_LOCK_PATH,
) -> Result:
    """Give an https receiver a new secret; the old one stops working at once.

    Also how a receiver registered before B306 gets its first: the location is
    rendered again with the secret's lines and nginx reloaded, checked first
    and put back if nginx refuses it.
    """

    tools = tools or Tools()
    locations = locations or Locations()
    with exclusive(policy, require_secure=require_secure, lock_path=lock_path) as runtime:
        return _set_secret(
            runtime,
            receiver_id=receiver_id,
            hashed_secret=hashed_secret,
            tools=tools,
            locations=locations,
        )


def _set_secret(
    runtime: RuntimeConfig,
    *,
    receiver_id: str,
    hashed_secret: str,
    tools: Tools,
    locations: Locations,
) -> Result:
    """`set_secret`, with the lock held and the registry read under it."""

    tools = tools or Tools()
    locations = locations or Locations()
    registry = runtime.registry
    if registry is None:
        raise ReceiverError(
            "dependency_unavailable",
            "no certificate registry is configured",
            exit_code=exit_codes.CONFIG,
        )
    receiver = registry.receivers.get(receiver_id)
    if receiver is None:
        raise ReceiverError("unknown_receiver", f"receiver {receiver_id} is not registered")
    if receiver.transport != "https":
        raise ReceiverError(
            "bad_input", f"{receiver_id} fetches over {receiver.transport}, with its own key"
        )
    target = secret_file(receiver_id, locations)
    before = target.read_text(encoding="ascii") if target.exists() else None
    layers = [write_secret(receiver_id, hashed_secret, locations)]
    try:
        layers.append(
            _write_checked(
                locations.nginx_snippet,
                render_nginx_snippet(registry, locations),
                check=[NGINX, "-t"],
                reload=[SYSTEMCTL, "reload", "nginx"],
                tools=tools,
                what="nginx",
            )
        )
    except ReceiverError:
        if before is None:
            target.unlink(missing_ok=True)
        else:
            _restore_secret(target, before)
        raise
    return Result(receiver_id, "secret", tuple(layers), instructions(receiver, locations))


def set_key(
    policy: PathPolicy,
    *,
    receiver_id: str,
    public_key: Path | str,
    tools: Tools | None = None,
    require_secure: bool = True,
    lock_path: Path = DEFAULT_LOCK_PATH,
) -> Result:
    """Give an rsync or sftp receiver a new public key; the old one stops working at once.

    A host installed again keeps its name, its directory and its certificates
    and has a new key pair (26-10-18). Only the key changes: the `from=` lock
    is read from the line already written rather than worked out again, so a
    DNS change does not move it, and the forced command is the registry's,
    as at registration. The same key again changes nothing.
    """

    tools = tools or Tools()
    with exclusive(policy, require_secure=require_secure, lock_path=lock_path) as runtime:
        return _set_key(runtime, receiver_id=receiver_id, public_key=public_key, tools=tools)


def _set_key(
    runtime: RuntimeConfig,
    *,
    receiver_id: str,
    public_key: Path | str,
    tools: Tools,
) -> Result:
    """`set_key`, with the lock held and the registry read under it."""

    tools = tools or Tools()
    registry = runtime.registry
    if registry is None:
        raise ReceiverError(
            "dependency_unavailable",
            "no certificate registry is configured",
            exit_code=exit_codes.CONFIG,
        )
    receiver = registry.receivers.get(receiver_id)
    if receiver is None:
        raise ReceiverError("unknown_receiver", f"receiver {receiver_id} is not registered")
    if receiver.transport == "https":
        raise ReceiverError(
            "bad_input", f"{receiver_id} fetches over https with a password; give it a new secret"
        )
    key_line = (
        read_public_key(public_key)
        if isinstance(public_key, Path)
        else parse_public_key(public_key, "the public key given")
    )
    keys = receiver.path / ".ssh" / "authorized_keys"
    try:
        written = [
            line
            for line in keys.read_text(encoding="ascii").splitlines()
            if line.strip() and not line.startswith("#")
        ]
    except (OSError, UnicodeDecodeError) as exc:
        raise ReceiverError(
            "write_failed",
            f"{keys} could not be read ({exc}); remove the receiver and register it again",
            exit_code=exit_codes.IO_ERROR,
        ) from exc
    lock = LOCK_FROM.search(written[0]) if len(written) == 1 else None
    if lock is None:
        raise ReceiverError(
            "write_failed",
            f"{keys} does not hold the one locked line it was written with; remove the "
            "receiver and register it again",
            exit_code=exit_codes.IO_ERROR,
        )
    options = ["restrict", f'from="{lock.group(1)}"']
    if receiver.transport == "rsync":
        options.append(f'command="{RRSYNC} -ro {receiver.path}"')
    line = ",".join(options) + " " + key_line
    if written[0] == line:
        layer = Layer("lock", "kept", str(keys))
    else:
        try:
            layer = write_authorized_keys(receiver.path, line)
        except OSError as exc:
            raise ReceiverError("write_failed", str(exc), exit_code=exit_codes.IO_ERROR) from exc
    return Result(receiver_id, "key", (layer,), ())


def _restore_secret(target: Path, before: str) -> None:
    group = grp.getgrnam(HTTPS_OWNER).gr_gid
    atomic_file.write(target, before.encode("ascii"), mode=0o640, uid=ROOT_UID, gid=group)


def listing(
    policy: PathPolicy, runtime: RuntimeConfig, locations: Locations | None = None
) -> list[dict[str, Any]]:
    """Every registered receiver, what it fetches with, what it holds and how it fetches."""

    locations = locations or Locations()
    registry = runtime.registry
    if registry is None:
        raise ReceiverError(
            "dependency_unavailable",
            "no certificate registry is configured",
            exit_code=exit_codes.CONFIG,
        )
    rows: list[dict[str, Any]] = []
    for receiver_id, receiver in sorted(registry.receivers.items()):
        #
        # What `add` printed once, for a receiver whose host is installed
        # again later. A manager whose own address cannot be read leaves the
        # lines out; the table is still true.
        #
        try:
            how = list(instructions(receiver, locations))
        except ReceiverError:
            how = []
        rows.append(
            {
                "id": receiver_id,
                "transport": receiver.transport,
                "layout": receiver.layout,
                "path": str(receiver.path),
                "owner": receiver.owner,
                "allow": list(receiver.allow),
                "certificates": list(cert_registry.receiver_in_use(registry, receiver_id)),
                "instructions": how,
            }
        )
    return rows


def remove(
    policy: PathPolicy,
    *,
    receiver_id: str,
    tools: Tools | None = None,
    locations: Locations | None = None,
    require_secure: bool = True,
    lock_path: Path = DEFAULT_LOCK_PATH,
) -> Result:
    """Take the four layers away in the order that never leaves a door open.

    The lock first, so the key stops working before the material is gone;
    then the directory and the account; the registry last. The registry is
    last for the same reason `add()` writes it last: it is the one layer the
    other three are rebuilt from. A removal that wrote the registry first and
    then failed at the lock left a receiver nginx still served and nothing
    named - which is what job 776 did before B163. A certificate still naming
    the receiver refuses the whole thing - Remove from... is how a certificate
    lets go of a target, and it is the operation that knows what else that
    costs.

    A layer that fails to go is `partial`, not an exception: the layers that
    did go are gone, and the caller needs to know which. An `OSError` on the
    way is the same refusal `add()` gives, as an envelope rather than a
    traceback the worker cannot read.
    """

    tools = tools or Tools()
    locations = locations or Locations()
    with exclusive(policy, require_secure=require_secure, lock_path=lock_path) as runtime:
        return _remove(
            policy,
            runtime,
            receiver_id=receiver_id,
            tools=tools,
            locations=locations,
            require_secure=require_secure,
        )


def _remove(
    policy: PathPolicy,
    runtime: RuntimeConfig,
    *,
    receiver_id: str,
    tools: Tools,
    locations: Locations,
    require_secure: bool,
) -> Result:
    """`remove`, with the lock held and the registry read under it."""

    tools = tools or Tools()
    locations = locations or Locations()
    registry = runtime.registry
    if registry is None:
        raise ReceiverError(
            "dependency_unavailable",
            "no certificate registry is configured",
            exit_code=exit_codes.CONFIG,
        )
    receiver = registry.receivers.get(receiver_id)
    if receiver is None:
        raise ReceiverError("unknown_receiver", f"receiver {receiver_id} is not registered")
    holders = cert_registry.receiver_in_use(registry, receiver_id)
    if holders:
        raise ReceiverError(
            "receiver_in_use",
            f"{', '.join(holders)} still publishes to {receiver_id}. Take the receiver off "
            "those certificates first (Remove from...), which also says what that costs.",
        )

    layers: list[Layer] = []
    remaining = _without(registry, receiver_id)
    try:
        if receiver.transport == "https":
            layers.append(
                _write_checked(
                    locations.nginx_snippet,
                    render_nginx_snippet(remaining, locations),
                    check=[NGINX, "-t"],
                    reload=[SYSTEMCTL, "reload", "nginx"],
                    tools=tools,
                    what="nginx",
                )
            )
            secret_file(receiver_id, locations).unlink(missing_ok=True)
            layers.append(Layer("secret", "removed", str(secret_file(receiver_id, locations))))
        else:
            home = _own_home(policy, receiver, tools)
            layers.append(_remove_lock(home))
            if receiver.transport == "sftp":
                _write_checked(
                    locations.sshd_dropin,
                    render_sshd_dropin(remaining),
                    check=[SSHD, "-t"],
                    reload=[SYSTEMCTL, "reload", "ssh"],
                    tools=tools,
                    what="sshd",
                )

        layers.append(_remove_directory(receiver.path))
        if receiver.transport != "https":
            layers.append(_remove_account(receiver.owner, home, tools))

        cert_registry.drop_receiver(
            _registry_path(policy),
            receiver_id=receiver_id,
            runtime=runtime,
            require_secure=require_secure,
            lock_held=True,
        )
        layers.append(Layer("registry", "removed", receiver_id))
    except ReceiverError:
        raise
    except (OSError, cert_registry.RegistryError) as exc:
        #
        # With the layers that did go: the registry still names the receiver,
        # rightly, and a second attempt finishes it, but what this one took
        # away is gone and the answer says so (review 26-10-24, 13-08).
        #
        code, exit_code = _write_refusal(exc)
        raise ReceiverError(
            code,
            str(exc),
            exit_code=exit_code,
            details={"removed": [layer.as_dict() for layer in layers]},
        ) from exc
    return Result(receiver_id, "removed", tuple(layers))


def _own_home(policy: PathPolicy, receiver: Receiver, tools: Tools) -> Path:
    """The account's home when it is the receiver's own, otherwise the receiver's directory.

    The lock and the home are removed on this answer. An account whose home is
    somewhere the receiver does not own (a registry entry from before accounts
    were refused when they already existed) must not have that home cleared.
    """

    home = tools.home(receiver.owner)
    if home is None:
        return receiver.path
    root = policy.receiver_root
    if home == receiver.path or (root is not None and home.is_relative_to(root)):
        return home
    return receiver.path


def _remove_lock(home: Path) -> Layer:
    """The lock goes first, so the key stops working before the material is gone."""

    keys = home / ".ssh" / "authorized_keys"
    if not keys.exists():
        return Layer("lock", "absent", str(keys))
    keys.unlink()
    return Layer("lock", "removed", str(keys))


def _remove_account(owner: str, home: Path, tools: Tools) -> Layer:
    """The account goes with its receiver, and its home with the account.

    A home that is the receiver's directory is already gone by now.
    """

    layer = remove_account(owner, tools)
    if layer.state == "removed":
        shutil.rmtree(home, ignore_errors=True)
    return layer


def _remove_directory(path: Path) -> Layer:
    if not path.exists():
        return Layer("directory", "absent", str(path))
    try:
        shutil.rmtree(path)
    except OSError as exc:
        return Layer("directory", "failed", f"{path}: {exc}")
    return Layer("directory", "removed", str(path))
