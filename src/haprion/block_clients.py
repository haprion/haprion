"""Who may block an address from outside, and on which objects (B412).

An intrusion detector on an application's host - fail2ban beside Authentik -
sees an address fail and wants it stopped at the edge. Behind Haprion it can
neither firewall the nodes nor see the visitor's own connection, so it asks
the manager - `ssh _haprion-block@<manager> block <object> <address>` - and the
address goes into the object's blocked table on every node, as if it had gone
over the object's own limit.

A *block client* is one such host: a name, the host it connects from, one
cluster, the objects it may block on, and its ed25519 key. Each is one line in
`_haprion-block`'s `authorized_keys`:

    from="<host>,<its addresses>",restrict,command="haprion-block-ask <id>" <key> <id> block-client

`restrict` turns everything off, `from=` binds the key to its host as a node's
fetch key is bound (`node_enrollment.pull_sources`), and the forced command
names the client - which is how the helper knows who asks, since every client
shares the one account. The key can place a block on its own objects and do
nothing else: not lift one, not touch a server, not read anything.

The registry is `clients.yaml` beside the key file's source of truth: written
whole by the client helper, root's, world-readable - it names hosts, objects
and key fingerprints, which the interface's settings page lists. The key file
is rendered from it, so a removal and an addition are the same operation.
"""

from __future__ import annotations

import ipaddress
import os
import re
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from haprion import exit_codes
from haprion.node_enrollment import EnrollmentError, fingerprint, host_name, public_key
from haprion.proxy_model import NAME

ACCOUNT = "_haprion-block"
#
# The account's home is the directory both files live in: root's, outside
# /home (which the worker's sandbox hides), and one entry in its ReadWritePaths.
#
HOME = Path("/etc/haprion/block-clients")
CLIENTS_FILE = HOME / "clients.yaml"
KEYS_FILE = HOME / ".ssh" / "authorized_keys"
ASK = "/opt/haprion/current/bin/haprion-block-ask"
PURPOSE = "block-client"
SCHEMA_VERSION = 1
#
# A client's ID is the word the forced command carries, so it is held to what
# a shell would never split or expand.
#
CLIENT_ID = re.compile(r"^[a-z][a-z0-9-]{0,39}$")
MAX_CLIENTS = 64
MAX_OBJECTS = 64


type Forward = Callable[[str], tuple[str, ...]]


class BlockClientError(Exception):
    def __init__(self, code: str, message: str, *, exit_code: int = exit_codes.REFUSED):
        super().__init__(message)
        self.code = code
        self.exit_code = exit_code


@dataclass(frozen=True, slots=True)
class Client:
    client_id: str
    host: str
    cluster: str
    objects: tuple[str, ...]
    key: str
    added_by: str = ""
    added_at: str = ""

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.key)

    def as_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "cluster": self.cluster,
            "objects": list(self.objects),
            "key": self.key,
            "fingerprint": self.fingerprint,
            "added_by": self.added_by,
            "added_at": self.added_at,
        }

    def shown(self) -> dict[str, Any]:
        """What a listing says: everything but the key itself."""

        shown = {"id": self.client_id, **self.as_dict()}
        del shown["key"]
        return shown


def client_id(value: object) -> str:
    if not isinstance(value, str) or not CLIENT_ID.fullmatch(value):
        raise BlockClientError(
            "bad_input",
            "a block client is named by lowercase letters, digits and hyphens, "
            "starting with a letter, at most 40",
        )
    return value


def object_names(value: object) -> tuple[str, ...]:
    if not isinstance(value, list | tuple) or not value:
        raise BlockClientError("bad_input", "name at least one object the client may block on")
    if len(value) > MAX_OBJECTS:
        raise BlockClientError("bad_input", f"at most {MAX_OBJECTS} objects")
    names: list[str] = []
    for entry in value:
        if not isinstance(entry, str) or not NAME.fullmatch(entry):
            raise BlockClientError("bad_input", f"{entry!r} is not an object name")
        if entry not in names:
            names.append(entry)
    return tuple(sorted(names))


def client(
    identifier: object,
    *,
    host: object,
    cluster: object,
    objects: object,
    key: object,
    added_by: str = "",
    added_at: str = "",
) -> Client:
    """One client, every field validated - from a request or from the file."""

    try:
        checked_host = host_name(host, "the client's host")
        checked_key = public_key(key, "the client's key")
    except EnrollmentError as exc:
        raise BlockClientError("bad_input", str(exc)) from None
    if not isinstance(cluster, str) or not NAME.fullmatch(cluster):
        raise BlockClientError("bad_input", "name the cluster the objects are in")
    return Client(
        client_id(identifier),
        checked_host,
        cluster,
        object_names(objects),
        checked_key,
        added_by,
        added_at,
    )


def parse(text: str) -> dict[str, Client]:
    """The registry, or a refusal naming what is wrong with it."""

    document = yaml.safe_load(text) if text.strip() else {}
    if document is None:
        document = {}
    if not isinstance(document, Mapping):
        raise BlockClientError("registry_invalid", "the block client registry is not a mapping")
    if document and document.get("schema_version") != SCHEMA_VERSION:
        raise BlockClientError("registry_invalid", "the block client registry has no schema 1")
    raw = document.get("clients") or {}
    if not isinstance(raw, Mapping):
        raise BlockClientError("registry_invalid", "the block client registry's clients")
    clients: dict[str, Client] = {}
    for identifier, entry in raw.items():
        if not isinstance(entry, Mapping):
            raise BlockClientError("registry_invalid", f"block client {identifier!r}")
        clients[str(identifier)] = client(
            identifier,
            host=entry.get("host"),
            cluster=entry.get("cluster"),
            objects=entry.get("objects"),
            key=entry.get("key"),
            added_by=str(entry.get("added_by") or ""),
            added_at=str(entry.get("added_at") or ""),
        )
    return clients


def render(clients: Mapping[str, Client]) -> str:
    """The registry file, whole."""

    document = {
        "schema_version": SCHEMA_VERSION,
        "clients": {identifier: clients[identifier].as_dict() for identifier in sorted(clients)},
    }
    header = (
        "# Written by haprion-block-client. Hand edits are lost at the next change,\n"
        "# and the key file is rendered from this one.\n"
    )
    return header + yaml.safe_dump(document, sort_keys=False)


def render_keys(clients: Mapping[str, Client], forward: Forward) -> str:
    """`_haprion-block`'s `authorized_keys`, one locked line per client."""

    lines = [
        "# Written by haprion-block-client from the block client registry.",
        "# One line per client. Hand edits are lost at the next change.",
    ]
    for identifier in sorted(clients):
        entry = clients[identifier]
        sources = from_sources(entry.host, forward)
        lines.append(
            f'from="{",".join(sources)}",restrict,command="{ASK} {identifier}" '
            f"{entry.key} {identifier} {PURPOSE}"
        )
    return "\n".join(lines) + "\n"


def from_sources(host: str, forward: Forward) -> tuple[str, ...]:
    """The host, and the addresses it resolves to: sshd matches `from=` by address (B162)."""

    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return (host,)
    addresses = forward(host)
    if not addresses:
        raise BlockClientError(
            "host_unresolvable",
            f"{host} does not resolve, so the client's key cannot be bound to its address",
        )
    return (host, *addresses)


def read(path: Path = CLIENTS_FILE) -> dict[str, Client]:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return {}
    except OSError as exc:
        raise BlockClientError(
            "dependency_unavailable",
            f"{path} could not be read: {exc}",
            exit_code=exit_codes.IO_ERROR,
        ) from exc
    return parse(text)


def added(
    clients: Mapping[str, Client], new: Client, *, by: str, now: datetime | None = None
) -> dict[str, Client]:
    if new.client_id in clients:
        raise BlockClientError(
            "already_exists", f"{new.client_id} is a block client already; remove it first"
        )
    if len(clients) >= MAX_CLIENTS:
        raise BlockClientError("bad_input", f"at most {MAX_CLIENTS} block clients")
    when = (now or datetime.now(UTC)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        **clients,
        new.client_id: Client(new.client_id, new.host, new.cluster, new.objects, new.key, by, when),
    }


def removed(clients: Mapping[str, Client], identifier: str) -> dict[str, Client]:
    if identifier not in clients:
        raise BlockClientError(
            "not_found", f"{identifier} is not a block client", exit_code=exit_codes.NOT_FOUND
        )
    return {name: entry for name, entry in clients.items() if name != identifier}


def may_block(clients: Mapping[str, Client], identifier: str, cluster: str, name: str) -> Client:
    """The client, if it may block on this object; refused otherwise, naming why."""

    entry = clients.get(identifier)
    if entry is None:
        raise BlockClientError("forbidden", f"{identifier} is not a block client")
    if entry.cluster != cluster or name not in entry.objects:
        raise BlockClientError(
            "forbidden", f"{identifier} may not block on {name}; add the object to the client"
        )
    return entry


def write(path: Path, text: str, mode: int) -> None:
    """Root's file, replaced whole or not at all."""

    path.parent.mkdir(parents=True, exist_ok=True)
    handle, staging = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as staged:
            staged.write(text)
            staged.flush()
            os.fsync(staged.fileno())
        os.chmod(staging, mode)
        os.replace(staging, path)
    except BaseException:
        Path(staging).unlink(missing_ok=True)
        raise


def store(
    clients: Mapping[str, Client],
    forward: Forward,
    *,
    clients_file: Path = CLIENTS_FILE,
    keys_file: Path = KEYS_FILE,
) -> None:
    """Both files from one registry: the keys first, rendered before anything is written.

    Rendering resolves every host, so a client whose host stopped resolving
    refuses the change before either file is touched. The key file is written
    first: a registry that names a client the keys do not yet carry is the
    harmless half of a failure between the two.
    """

    keys = render_keys(clients, forward)
    write(keys_file, keys, 0o644)
    write(clients_file, render(clients), 0o644)
