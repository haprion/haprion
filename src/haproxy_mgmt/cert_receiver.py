"""Registering a receiver: an account, a directory, a lock and a registry entry.

C7, and the whole of it below the command. A receiver is the one kind of
target this project does not create by writing a line somewhere: it is a
machine outside the installation that fetches private key material, so what
makes it exist is an account, a directory only that account can read, a lock
that binds its key to that directory, and an entry in the registry naming it.

Why one command rather than three steps
---------------------------------------
Because none of the layers is safe without the others, and each was a manual
step until now (INSTALLATION 1.4.1). A registry entry without a directory
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

import contextlib
import ipaddress
import json
import os
import pwd
import re
import shutil
import socket
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from haproxy_mgmt import cert_registry
from haproxy_mgmt.cert_inventory import IMPORT_STORE, LETSENCRYPT_LIVE, measure_registered
from haproxy_mgmt.config import (
    RECEIVER_ID,
    RECEIVER_TRANSPORTS,
    USERNAME,
    PathPolicy,
    Receiver,
    Registry,
    RuntimeConfig,
    receiver_id_names_a_host,
)

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
# whose IDs differ late in a long name would otherwise share one account, and
# a shared account is what §4 of the design exists to end.
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

type Runner = Callable[[Sequence[str]], tuple[int, str]]


class ReceiverError(Exception):
    """A registration that was refused or failed, with the code it is reported under."""

    def __init__(self, code: str, message: str, *, exit_code: int = 64):
        super().__init__(message)
        self.code = code
        self.exit_code = exit_code


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

    sshd_dropin: Path = Path("/etc/ssh/sshd_config.d/haproxy-manager-receivers.conf")
    nginx_snippet: Path = Path("/etc/nginx/snippets/haproxy-manager-receivers.conf")
    ui_site: Path = Path("/etc/nginx/sites-available/haproxy-ui")
    ui_tls: Path = Path("/etc/haproxy-manager/ui-tls.conf")


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


def resolve_reverse(address: str) -> tuple[str, ...]:
    try:
        host, aliases, _ = socket.gethostbyaddr(address)
    except OSError:
        return ()
    return tuple(name.rstrip(".").lower() for name in (host, *aliases))


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
    reverse: Callable[[str], tuple[str, ...]] = resolve_reverse
    now: Callable[[], datetime] = lambda: datetime.now(UTC)
    home: Callable[[str], Path | None] = account_home


@dataclass(frozen=True, slots=True)
class Result:
    """What a registration, a removal or a migration did, layer by layer."""

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

    `from="<id>"` in `authorized_keys` and `allow <id>` in nginx are what
    make a stolen key or a guessed address useless, and both are the ID
    itself. A name that does not resolve back to itself would leave sshd
    refusing every connection from the host that is supposed to fetch - a
    failure that looks like a broken key and is not - so it is refused here,
    where the name can still be changed.
    """

    if not RECEIVER_ID.fullmatch(receiver_id):
        raise ReceiverError("bad_input", f"{receiver_id!r} is not a receiver ID")
    if not receiver_id_names_a_host(receiver_id):
        raise ReceiverError(
            "bad_input",
            f"{receiver_id!r} is neither a hostname nor an IP address. A receiver is named "
            "by the host that fetches, because that is what its key and its whitelist are "
            "bound to (B141).",
        )
    try:
        ipaddress.ip_address(receiver_id)
    except ValueError:
        pass
    else:
        #
        # An address is its own reverse lookup: sshd compares `from=` against
        # the peer address directly, so there is nothing to check.
        #
        return
    addresses = tools.forward(receiver_id)
    if not addresses:
        raise ReceiverError(
            "receiver_unresolvable", f"{receiver_id} does not resolve; sshd could not match from="
        )
    for address in addresses:
        if receiver_id in tools.reverse(address):
            return
    raise ReceiverError(
        "receiver_unresolvable",
        f"{receiver_id} resolves to {', '.join(addresses)}, and none of those resolves back "
        f'to {receiver_id}. sshd matches from="{receiver_id}" by reverse lookup, so the '
        "PTR record has to agree before the key would ever be accepted.",
    )


def read_public_key(path: Path) -> str:
    """The receiver's public key, held to one line of the shapes OpenSSH writes.

    One line and nothing after it, because this text is written into
    `authorized_keys` in front of a forced command: a second line would be a
    second key, with no restrictions and nobody's decision behind it.
    """

    try:
        text = path.read_text(encoding="ascii")
    except (OSError, UnicodeDecodeError) as exc:
        raise ReceiverError("bad_input", f"the public key could not be read: {exc}") from exc
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if len(lines) != 1:
        raise ReceiverError(
            "bad_input", f"{path} holds {len(lines)} keys; a receiver registers exactly one"
        )
    line = lines[0]
    if not re.fullmatch(
        r"(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)) [A-Za-z0-9+/=]+( [^\r\n]{0,128})?",
        line,
    ):
        raise ReceiverError(
            "bad_input",
            f"{path} does not hold a public key in OpenSSH's own form. Give the .pub file "
            "the receiver's ssh-keygen wrote, not a private key and not a certificate.",
        )
    return line


def authorized_keys_line(receiver: Receiver, public_key: str) -> str:
    """The one line that is the whole of what a receiver may do over ssh.

    `restrict` first, which is OpenSSH's own way of saying "everything off",
    so a future option this project has not heard of is off as well.
    `from=` binds the key to the host it was issued for, and for `rsync` the
    forced `rrsync -ro` binds it to one directory, read-only - the key cannot
    run a shell, cannot write, and cannot read a neighbour's certificate.
    """

    options = ["restrict", f'from="{receiver.receiver_id}"']
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
        raise ReceiverError("account_failed", f"useradd {owner} failed: {output}", exit_code=74)
    code, output = tools.run([PASSWD_BIN, "--lock", owner])
    if code != 0:
        raise ReceiverError(
            "account_failed", f"{PASSWD_BIN} --lock {owner} failed: {output}", exit_code=74
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
            "write_failed", f"{path} could not be created: {exc}", exit_code=74
        ) from exc
    return Layer("directory", "created", str(path))


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
    content = f"# Written by haproxy-cert-receiver. One receiver, one key, one directory.\n{line}\n"
    keys.write_text(content, encoding="ascii")
    os.chown(keys, ROOT_UID, ROOT_GID)
    os.chmod(keys, 0o644)
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
        "# Written by haproxy-cert-receiver from the certificate registry.",
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
    """The hostname and certificate the interface is served under (05-platform-nginx)."""

    values: dict[str, str] = {}
    try:
        for line in locations.ui_tls.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.startswith("#"):
                key, _, value = line.partition("=")
                values[key.strip()] = value.strip()
    except OSError as exc:
        raise ReceiverError(
            "dependency_unavailable",
            f"{locations.ui_tls} could not be read; an https receiver is served under the "
            "interface's own certificate, which that file names.",
            exit_code=78,
        ) from exc
    missing = sorted({"TLS_CERT", "TLS_KEY", "SERVER_NAME"} - set(values))
    if missing:
        raise ReceiverError(
            "dependency_unavailable",
            f"{locations.ui_tls} does not name {', '.join(missing)}",
            exit_code=78,
        )
    return values


def render_nginx_snippet(registry: Registry) -> str:
    """One location per `https` receiver, whitelisted per line, for the interface's block.

    Rendered whole from the registry like the sshd drop-in, and holding only
    `location` blocks: the server block - port, certificate, hostname - is the
    interface's own, and this file reaches it through one `include` line that
    `05-platform-nginx` puts there. A receiver never edits that block (B157).
    """

    lines = [
        "# Written by haproxy-cert-receiver from the certificate registry.",
        "# Included by the interface's server block. Hand edits are lost at the next change.",
        "",
    ]
    for receiver in _https_receivers(registry):
        lines.append(f"location {HTTPS_PREFIX}/{receiver.receiver_id}/ {{")
        lines.append(f"    alias {receiver.path}/;")
        lines.append("    autoindex off;")
        for entry in receiver.allow:
            lines.append(f"    allow {entry};")
        lines.append("    deny all;")
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
            exit_code=78,
        ) from exc
    wanted = f"include {locations.nginx_snippet};"
    if not any(line.strip() == wanted for line in site.splitlines()):
        raise ReceiverError(
            "dependency_unavailable",
            f"{locations.ui_site} does not include {locations.nginx_snippet}, so nginx would "
            "never serve the receiver. Rerun install/platform/05-platform-nginx, which adds "
            "the include line to the interface's server block.",
            exit_code=78,
        )


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
    path.write_text(content, encoding="utf-8")
    os.chown(path, ROOT_UID, ROOT_GID)
    os.chmod(path, 0o644)
    code, output = tools.run(check)
    if code != 0:
        if before is None:
            path.unlink(missing_ok=True)
        else:
            path.write_text(before, encoding="utf-8")
        raise ReceiverError(
            "config_refused",
            f"{what} refused the change and it was taken back: {output}",
            exit_code=74,
        )
    if reload is not None:
        code, output = tools.run(reload)
        if code != 0:
            raise ReceiverError(
                "config_refused", f"{what} could not be reloaded: {output}", exit_code=74
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
            exit_code=78,
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


def migration_record(policy: PathPolicy, receiver_id: str) -> Path:
    """Where a half-finished migration is remembered (B158).

    Beside the receivers rather than in the registry: the old account and the
    old directory are not a target anyone may publish to, they are a layer
    waiting to be taken away, and a field in the registry would have to be
    read by every command that reads the registry at all.
    """

    root = policy.receiver_root
    if root is None:
        raise ReceiverError(
            "dependency_unavailable",
            "no receiver_root is configured. Add it to the runtime policy.",
            exit_code=78,
        )
    return root / ".migrations" / f"{receiver_id}.json"


def check_request(
    transport: str,
    layout: str,
    allow: Sequence[str],
    public_key: Path | None,
) -> None:
    """What the command will not do, said before anything is written."""

    if transport not in RECEIVER_TRANSPORTS:
        raise ReceiverError(
            "bad_input", f"--transport must be one of: {', '.join(RECEIVER_TRANSPORTS)}"
        )
    if layout != "per-certificate":
        raise ReceiverError(
            "bad_input",
            "a new receiver is per-certificate. `flat` is the form the receivers registered "
            "before C7 have, and it holds one certificate at a time (B138).",
        )
    if transport == "https":
        if not allow:
            raise ReceiverError(
                "bad_input",
                "an https receiver fetches with no key at all, so --allow is what stands "
                "between its directory and everyone. Name at least one address or network.",
            )
        if public_key is not None:
            raise ReceiverError("bad_input", "an https receiver has no key; leave out --public-key")
        return
    if allow:
        raise ReceiverError("bad_input", "--allow belongs to an https receiver only")
    if public_key is None:
        raise ReceiverError(
            "bad_input",
            "--public-key is required: the pair is made on the receiver and only its public "
            "half is given to the manager (B157).",
        )


def add(
    policy: PathPolicy,
    runtime: RuntimeConfig,
    *,
    receiver_id: str,
    transport: str,
    public_key: Path | None = None,
    owner: str | None = None,
    path: Path | None = None,
    allow: Sequence[str] = (),
    layout: str = "per-certificate",
    tools: Tools | None = None,
    locations: Locations | None = None,
    require_secure: bool = True,
) -> Result:
    """Make a receiver whole, or leave the machine as it was found."""

    tools = tools or Tools()
    locations = locations or Locations()
    check_request(transport, layout, allow, public_key)
    check_identity(receiver_id, tools)

    registry = runtime.registry
    if registry is None:
        raise ReceiverError(
            "dependency_unavailable", "no certificate registry is configured", exit_code=78
        )
    if receiver_id in registry.receivers:
        raise ReceiverError(
            "already_exists",
            f"receiver {receiver_id} is already registered. A transport or a directory is "
            "not edited under a receiver (B138); remove it and register it again.",
        )

    if transport == "https":
        account = HTTPS_OWNER
        if not account_exists(account):
            raise ReceiverError(
                "dependency_unavailable",
                f"an https receiver is served by nginx as {HTTPS_OWNER}, and that account "
                "does not exist",
                exit_code=78,
            )
    else:
        account = owner or default_owner(receiver_id)
        if not USERNAME.fullmatch(account):
            raise ReceiverError("bad_input", f"{account!r} is not a valid account name")
        if account_exists(account) and any(
            other.owner == account for other in registry.receivers.values()
        ):
            raise ReceiverError(
                "already_exists",
                f"account {account} already fetches for another receiver. One account per "
                "receiver, or a receiver reads its neighbour's key material (§4).",
            )

    directory = path
    if directory is None:
        if policy.receiver_root is None:
            raise ReceiverError(
                "dependency_unavailable",
                "no receiver_root is configured, so there is nowhere to put the directory. "
                "Add receiver_root to the runtime policy or pass --path.",
                exit_code=78,
            )
        directory = policy.receiver_root / receiver_id
    if not directory.is_absolute():
        raise ReceiverError("bad_input", "--path must be absolute")

    key_line = read_public_key(public_key) if public_key is not None else ""
    receiver = Receiver(
        receiver_id=receiver_id,
        path=directory,
        owner=account,
        transport=transport,
        layout=layout,
        allow=tuple(allow),
    )

    undo: list[Callable[[], None]] = []
    layers: list[Layer] = []
    try:
        if transport != "https" and not account_exists(account):
            create_account(account, directory, transport, tools)
            undo.append(lambda: _discard(tools.run([USERDEL, account])))
            layers.append(Layer("account", "created", account))
        else:
            layers.append(Layer("account", "present", account))

        existed = directory.exists()
        layers.append(create_directory(directory, account))
        if not existed:
            undo.append(lambda: shutil.rmtree(directory, ignore_errors=True))

        layers.append(_write_lock(receiver, key_line, registry, locations, tools, undo))

        cert_registry.set_receiver(
            _registry_path(policy),
            receiver_id=receiver_id,
            fields=_entry_fields(receiver),
            runtime=runtime,
            require_secure=require_secure,
        )
        layers.append(Layer("registry", "created", receiver_id))
    except (ReceiverError, OSError, cert_registry.RegistryError) as exc:
        for step in reversed(undo):
            with contextlib.suppress(Exception):
                step()
        if isinstance(exc, ReceiverError):
            raise
        raise ReceiverError("write_failed", str(exc), exit_code=74) from exc

    return Result(receiver_id, "added", tuple(layers), instructions(receiver, locations))


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
    undo: list[Callable[[], None]],
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
            render_nginx_snippet(_candidate(registry, receiver)),
            check=[NGINX, "-t"],
            reload=[SYSTEMCTL, "reload", "nginx"],
            tools=tools,
            what="nginx",
        )
        undo.append(lambda: _restore(locations.nginx_snippet, before))
        return layer

    home = receiver.path
    keys_layer = write_authorized_keys(home, authorized_keys_line(receiver, key_line))
    undo.append(lambda: shutil.rmtree(home / ".ssh", ignore_errors=True))
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
        undo.append(lambda: _restore(locations.sshd_dropin, before))
    return keys_layer


def _discard(_result: tuple[int, str]) -> None:
    """An undo step's answer is not a report: the failure it undoes is."""


def _restore(path: Path, before: str | None) -> None:
    if before is None:
        path.unlink(missing_ok=True)
    else:
        path.write_text(before, encoding="utf-8")


def instructions(receiver: Receiver, locations: Locations) -> tuple[str, ...]:
    """What the receiver's operator needs, in the words `04-node-prepare` uses."""

    host = socket.gethostname()
    if receiver.transport == "https":
        server_name = read_ui_tls(locations)["SERVER_NAME"]
        return (
            f"transport: https (no key; the whitelist is {', '.join(receiver.allow)})",
            f"url: https://{server_name}{HTTPS_PREFIX}/{receiver.receiver_id}/"
            "<certificate>/fullchain.pem",
            "the private key is beside it as privkey.pem, under the same whitelist",
        )
    if receiver.transport == "sftp":
        return (
            "transport: sftp, read-only, chrooted into its own directory",
            f"user: {receiver.owner}@{host}",
            "path: / inside the chroot is one directory per certificate",
            f"the key you gave is bound to {receiver.receiver_id}; its PTR record must agree",
        )
    return (
        "transport: rsync over ssh, read-only",
        f"user: {receiver.owner}@{host}",
        f"fetch: rsync -a {receiver.owner}@{host}:<certificate>/ /local/path/",
        f"the key you gave is bound to {receiver.receiver_id}; its PTR record must agree",
    )


def listing(policy: PathPolicy, runtime: RuntimeConfig) -> list[dict[str, Any]]:
    """Every registered receiver, what it fetches with, and what it holds.

    `state` is the one word an operator reads first: `legacy` for a receiver
    still in the form the three PVE hosts have, `migrating` for one whose old
    account is waiting to be taken away, `ready` for the rest.
    """

    registry = runtime.registry
    if registry is None:
        raise ReceiverError(
            "dependency_unavailable", "no certificate registry is configured", exit_code=78
        )
    rows: list[dict[str, Any]] = []
    for receiver_id, receiver in sorted(registry.receivers.items()):
        state = "ready"
        if receiver.layout == "flat":
            state = "legacy"
        if policy.receiver_root is not None and migration_record(policy, receiver_id).exists():
            state = "migrating"
        rows.append(
            {
                "id": receiver_id,
                "transport": receiver.transport,
                "layout": receiver.layout,
                "path": str(receiver.path),
                "owner": receiver.owner,
                "allow": list(receiver.allow),
                "state": state,
                "certificates": list(cert_registry.receiver_in_use(registry, receiver_id)),
            }
        )
    return rows


def remove(
    policy: PathPolicy,
    runtime: RuntimeConfig,
    *,
    receiver_id: str,
    tools: Tools | None = None,
    locations: Locations | None = None,
    require_secure: bool = True,
) -> Result:
    """Take the four layers away in the order that never leaves a door open.

    The registry first, so nothing publishes into a directory that is about to
    go; then the lock, so the key stops working before the material is gone;
    then the directory and the account. A certificate still naming the
    receiver refuses the whole thing - Remove from... is how a certificate
    lets go of a target, and it is the operation that knows what else that
    costs.
    """

    tools = tools or Tools()
    locations = locations or Locations()
    registry = runtime.registry
    if registry is None:
        raise ReceiverError(
            "dependency_unavailable", "no certificate registry is configured", exit_code=78
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
    cert_registry.drop_receiver(
        _registry_path(policy),
        receiver_id=receiver_id,
        runtime=runtime,
        require_secure=require_secure,
    )
    layers.append(Layer("registry", "removed", receiver_id))
    remaining = _without(registry, receiver_id)

    if receiver.transport == "https":
        layers.append(
            _write_checked(
                locations.nginx_snippet,
                render_nginx_snippet(remaining),
                check=[NGINX, "-t"],
                reload=[SYSTEMCTL, "reload", "nginx"],
                tools=tools,
                what="nginx",
            )
        )
    else:
        home = tools.home(receiver.owner) or receiver.path
        layers.append(_remove_lock(home, receiver.path, shared=_shared(receiver.owner, remaining)))
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
        layers.append(_remove_account_unless_shared(receiver.owner, remaining, home, tools))
    return Result(receiver_id, "removed", tuple(layers))


def _shared(owner: str, registry: Registry) -> bool:
    """Whether another receiver still fetches as this account.

    True only of the receivers registered before this command, which share
    one account and one `authorized_keys` with a line per host (the `legacy`
    ones `list` shows). Taking the account or the file with the first of them
    would stop the others fetching without a word.
    """

    return any(other.owner == owner for other in registry.receivers.values())


def _remove_lock(home: Path, path: Path, *, shared: bool) -> Layer:
    """The lock goes; with a shared account, only the line that names this directory."""

    keys = home / ".ssh" / "authorized_keys"
    if not keys.exists():
        return Layer("lock", "absent", str(keys))
    if not shared:
        keys.unlink()
        return Layer("lock", "removed", str(keys))
    lines = keys.read_text(encoding="utf-8").splitlines()
    kept = [line for line in lines if str(path) not in line]
    if len(kept) == len(lines):
        return Layer("lock", "absent", f"no line in {keys} names {path}")
    keys.write_text("".join(f"{line}\n" for line in kept), encoding="utf-8")
    return Layer("lock", "removed", f"the line naming {path} in {keys}")


def _remove_account_unless_shared(
    owner: str, registry: Registry, home: Path, tools: Tools
) -> Layer:
    """The account goes with its last receiver, and its home with the account.

    A home that is the receiver's directory (B160) is already gone by now; an
    older account's separate home goes here, and only once nothing fetches
    as it.
    """

    if _shared(owner, registry):
        return Layer("account", "kept", f"{owner} still fetches for another")
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


def migrate(
    policy: PathPolicy,
    runtime: RuntimeConfig,
    *,
    receiver_id: str,
    public_key: Path,
    owner: str | None = None,
    path: Path | None = None,
    tools: Tools | None = None,
    locations: Locations | None = None,
    require_secure: bool = True,
    min_remaining_days: int = 7,
    live: Path = LETSENCRYPT_LIVE,
    store: Path = IMPORT_STORE,
) -> Result:
    """Build the new layer beside the old one and point the registry at it (B158).

    Nothing is taken away here. The receiver goes on fetching from its old
    account and its old directory until its operator has changed key, account
    and path and fetched once; `--finish` is what removes the old layer, and
    an operator who never runs it has a machine with one account too many
    rather than a receiver that stopped fetching without knowing why.

    Refused close to expiry, for a reason that is only obvious once: the new
    directory is empty until the next publish, and the publisher will not
    write a certificate with less than a week left (`MIN_REMAINING`). A
    migration started there would point the registry at a directory that
    stays empty until the certificate is renewed.
    """

    tools = tools or Tools()
    locations = locations or Locations()
    registry = runtime.registry
    if registry is None:
        raise ReceiverError(
            "dependency_unavailable", "no certificate registry is configured", exit_code=78
        )
    receiver = registry.receivers.get(receiver_id)
    if receiver is None:
        raise ReceiverError("unknown_receiver", f"receiver {receiver_id} is not registered")
    #
    # The record first: once the registry has been pointed at the new layer,
    # the entry looks finished, and "already per-certificate" would be a
    # worse answer than "a migration is under way and has not been finished".
    #
    record = migration_record(policy, receiver_id)
    if record.exists():
        raise ReceiverError(
            "already_exists",
            f"a migration of {receiver_id} is already under way. Finish it with --finish "
            "once the receiver has fetched from its new account.",
        )
    if receiver.layout != "flat":
        raise ReceiverError(
            "bad_input", f"receiver {receiver_id} is already per-certificate; nothing to migrate"
        )
    _refuse_near_expiry(
        policy, registry, receiver_id, min_remaining_days, tools, live=live, store=store
    )

    account = owner or default_owner(receiver_id)
    if account == receiver.owner:
        raise ReceiverError(
            "bad_input",
            f"the new account would be the old one ({account}). One account per receiver is "
            "the point of the migration; name a different one with --owner.",
        )
    directory = path or (
        policy.receiver_root / receiver_id
        if policy.receiver_root is not None
        else receiver.path.parent / f"{receiver_id}-per-certificate"
    )
    if directory == receiver.path:
        raise ReceiverError("bad_input", "the new directory would be the old one")

    moved = Receiver(
        receiver_id=receiver_id,
        path=directory,
        owner=account,
        transport=receiver.transport,
        layout="per-certificate",
        allow=receiver.allow,
    )
    key_line = read_public_key(public_key)
    old_home = tools.home(receiver.owner) or receiver.path

    undo: list[Callable[[], None]] = []
    layers: list[Layer] = []
    try:
        if not account_exists(account):
            create_account(account, directory, moved.transport, tools)
            undo.append(lambda: _discard(tools.run([USERDEL, account])))
            layers.append(Layer("account", "created", account))
        else:
            layers.append(Layer("account", "present", account))
        layers.append(create_directory(directory, account))
        undo.append(lambda: shutil.rmtree(directory, ignore_errors=True))
        layers.append(
            _write_lock(moved, key_line, _without(registry, receiver_id), locations, tools, undo)
        )
        cert_registry.set_receiver(
            _registry_path(policy),
            receiver_id=receiver_id,
            fields=_entry_fields(moved),
            runtime=runtime,
            require_secure=require_secure,
        )
        layers.append(Layer("registry", "created", receiver_id))
        record.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(record.parent, 0o700)
        record.write_text(
            json.dumps(
                {
                    "id": receiver_id,
                    "old_owner": receiver.owner,
                    "old_path": str(receiver.path),
                    "old_home": str(old_home),
                    "started": tools.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        os.chmod(record, 0o600)
        layers.append(Layer("old layer", "kept", f"{receiver.owner} at {receiver.path}"))
    except (ReceiverError, OSError, cert_registry.RegistryError) as exc:
        for step in reversed(undo):
            with contextlib.suppress(Exception):
                step()
        if isinstance(exc, ReceiverError):
            raise
        raise ReceiverError("write_failed", str(exc), exit_code=74) from exc

    return Result(receiver_id, "migrated", tuple(layers), instructions(moved, locations))


def _refuse_near_expiry(
    policy: PathPolicy,
    registry: Registry,
    receiver_id: str,
    days: int,
    tools: Tools,
    *,
    live: Path,
    store: Path,
) -> None:
    """B158's seven days, measured on the certificates this receiver holds."""

    if policy.certificate_root is None:
        return
    for certificate_id in cert_registry.receiver_in_use(registry, receiver_id):
        measured = measure_registered(
            registry.certificates[certificate_id],
            certificate_root=policy.certificate_root,
            live=live,
            store=store,
        )
        if isinstance(measured, str):
            continue
        _, facts, _ = measured
        remaining = (facts.not_after - tools.now()).days
        if remaining < days:
            raise ReceiverError(
                "certificate_expiring",
                f"{certificate_id} has {remaining} days left, and the publisher does not "
                f"write a certificate with less than {days}. The new directory would stay "
                "empty until it is renewed; migrate after the renewal.",
            )


def finish(
    policy: PathPolicy,
    runtime: RuntimeConfig,
    *,
    receiver_id: str,
    tools: Tools | None = None,
    locations: Locations | None = None,
) -> Result:
    """Take away the layer the migration left standing."""

    tools = tools or Tools()
    locations = locations or Locations()
    record = migration_record(policy, receiver_id)
    try:
        held = json.loads(record.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReceiverError(
            "unknown_receiver",
            f"no migration of {receiver_id} is under way",
        ) from exc

    layers: list[Layer] = []
    old_owner = str(held.get("old_owner", ""))
    old_path = Path(str(held.get("old_path", "")))
    old_home = Path(str(held.get("old_home", old_path)))
    registry = runtime.registry
    remaining = registry if registry is not None else Registry(receivers={}, certificates={})
    if old_owner and old_owner != HTTPS_OWNER:
        shared = _shared(old_owner, remaining)
        layers.append(_remove_lock(old_home, old_path, shared=shared))
        layers.append(_remove_directory(old_path))
        layers.append(_remove_account_unless_shared(old_owner, remaining, old_home, tools))
    else:
        layers.append(_remove_directory(old_path))
    record.unlink(missing_ok=True)
    layers.append(Layer("migration", "removed", str(record)))
    return Result(receiver_id, "finished", tuple(layers))
