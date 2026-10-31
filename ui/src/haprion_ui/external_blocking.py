"""Settings -> External blocking: who may block an address from outside (B412).

A block client is a host - an intrusion detector beside an application, such
as fail2ban - whose key may ask the manager to block an address on some of
one cluster's objects. The rows are the registry itself, which is
world-readable (`block_clients.CLIENTS_FILE`); a change is a `block_client`
job, which the worker hands to the root helper that writes the registry and
the key file.

The choices are the cluster's objects that block, from its newest objects
reading: an object without dynamic blocking has no table to put an address in.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from haprion import block_clients
from haprion.block_clients import BlockClientError

from haprion_ui.db import ClusterObjects
from haprion_ui.objects import cluster_object_views

OPERATION = "block_client"


@dataclass(frozen=True, slots=True)
class ClientRow:
    client_id: str
    host: str
    cluster: str
    objects: tuple[str, ...]
    fingerprint: str
    added_by: str
    added_at: datetime | None


@dataclass(frozen=True, slots=True)
class Clients:
    rows: tuple[ClientRow, ...]
    problem: str = ""


def read(path: Path = block_clients.CLIENTS_FILE) -> Clients:
    """Every client, by name, or why the registry could not be read."""

    try:
        clients = block_clients.read(path)
    except BlockClientError as exc:
        return Clients((), str(exc))
    return Clients(
        tuple(
            ClientRow(
                entry.client_id,
                entry.host,
                entry.cluster,
                entry.objects,
                entry.fingerprint,
                entry.added_by,
                _moment(entry.added_at),
            )
            for _, entry in sorted(clients.items())
        )
    )


def _moment(written: str) -> datetime | None:
    try:
        return datetime.strptime(written, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError:
        return None


def blocking_objects(readings: Iterable[ClusterObjects], cluster: str) -> tuple[str, ...]:
    """The cluster's objects with dynamic blocking, by name, from its newest reading."""

    reading = next((entry for entry in readings if entry.cluster == cluster), None)
    names: list[str] = []
    for view in cluster_object_views(reading):
        try:
            document: Any = yaml.safe_load(view.document)
        except yaml.YAMLError:
            continue
        if isinstance(document, dict) and isinstance(document.get("dynamic_block"), dict):
            names.append(view.name)
    return tuple(sorted(names))
