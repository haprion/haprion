"""Which clusters have certificate material published but not confirmed on their nodes.

Publishing and rolling out are two steps, and only the first one is visible in
the files: a cluster's PEM under the certificate root is the same whether its
nodes took it or not. Without a note of the second, a run that published and
then failed to deploy left nothing for the next run to find - the material was
already in place, so the publisher saw nothing changed and deployed nothing,
and answered `done` (review 2026-09-30, R1). This file is that note.

One small JSON document beside the registry: cluster ID -> a serial. A cluster
is marked before its material is written, so a run interrupted anywhere after
that leaves it marked, and it is settled only after `haprion-cert-deploy`
answered 0 for it. The serial is what makes settling safe while another run
publishes: a rollout clears the mark only if nobody marked the cluster again
since the rollout read it, because that later change is one the rollout may not
have carried.

Every mark draws a new random serial rather than counting up. A count started
again at 1 once a settle removed the cluster, so a rollout that settled late
could clear a later run's mark that happened to have its number (review
2026-10-18, L2). A drawn serial is not reused, and the file keeps its shape.

Every read-modify-write happens under the publisher's lock. A file that cannot
be read is not a reason to stop publishing certificates: it is read as "every
cluster may be behind", which costs at most a rollout per cluster that finds its
nodes current and skips them, and the file is written whole again.
"""

from __future__ import annotations

import contextlib
import json
import os
import secrets
import stat
from collections.abc import Callable, Collection, Iterable, Mapping, Sequence
from pathlib import Path

from haprion import atomic_file

PENDING_NAME = "certificates.pending-deploy.json"
SCHEMA_VERSION = 1
MAX_BYTES = 64 * 1024


#
# Below 2**53, so the serial survives any JSON reader as an exact number.
#
SERIAL_BOUND = 2**53


def fresh_serial(other_than: int | None = None) -> int:
    """A serial for a new mark: random, at least 1, and never the one it replaces."""

    while True:
        serial = secrets.randbelow(SERIAL_BOUND - 1) + 1
        if serial != other_than:
            return serial


def pending_path(registry: Path) -> Path:
    """Beside the registry: root-owned, persistent, and already where the publisher may write."""

    return registry.with_name(PENDING_NAME)


def read(path: Path) -> dict[str, int] | None:
    """The marked clusters and their serials; empty when there is no file, None when it is unreadable."""

    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return {}
    except OSError:
        return None
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_BYTES:
            return None
        raw = os.read(descriptor, MAX_BYTES + 1)
    except OSError:
        return None
    finally:
        os.close(descriptor)
    try:
        document = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(document, dict) or document.get("schema_version") != SCHEMA_VERSION:
        return None
    clusters = document.get("clusters")
    if not isinstance(clusters, dict):
        return None
    marked: dict[str, int] = {}
    for cluster_id, serial in clusters.items():
        if not isinstance(cluster_id, str) or type(serial) is not int or serial < 1:
            return None
        marked[cluster_id] = serial
    return marked


def write(path: Path, clusters: Mapping[str, int], *, like: Path) -> None:
    """Replace the file atomically, owned and moded like `like` (the registry)."""

    metadata = like.stat()
    rendered = json.dumps(
        {"schema_version": SCHEMA_VERSION, "clusters": dict(sorted(clusters.items()))},
        indent=2,
    )
    atomic_file.write(
        path,
        (rendered + "\n").encode("utf-8"),
        mode=metadata.st_mode & 0o640,
        uid=metadata.st_uid,
        gid=metadata.st_gid,
    )


class Ledger:
    """The note for one run, held under the publisher's lock while publishing.

    `known` is every cluster the runtime configuration still has. A mark for a
    cluster that has since been removed is dropped rather than rolled out, and
    an unreadable file stands for all of them.
    """

    def __init__(self, path: Path, *, like: Path, known: Collection[str]) -> None:
        self.path = path
        self.like = like
        self.known = frozenset(known)
        found = read(path)
        if found is None:
            self.before = {cluster_id: fresh_serial() for cluster_id in sorted(self.known)}
            self._written: dict[str, int] | None = None
        else:
            self.before = {c: s for c, s in found.items() if c in self.known}
            self._written = found
        self.current = dict(self.before)

    def _store(self) -> None:
        if self.current != self._written:
            write(self.path, self.current, like=self.like)
            self._written = dict(self.current)

    def mark(self, clusters: Iterable[str]) -> None:
        """Before any material for these clusters is written."""

        for cluster_id in clusters:
            if cluster_id in self.known:
                self.current[cluster_id] = fresh_serial(self.current.get(cluster_id))
        self._store()

    def keep(self, changed: Collection[str]) -> None:
        """After writing: a cluster stays marked if it was already, or if its material changed."""

        self.current = {
            cluster_id: serial
            for cluster_id, serial in self.current.items()
            if cluster_id in self.before or cluster_id in changed
        }
        self._store()

    def order(self, first: Sequence[str]) -> list[tuple[str, int]]:
        """The clusters to roll out, `first` in its own order, then the rest carried from earlier runs."""

        leading = [c for c in first if c in self.current]
        rest = sorted(c for c in self.current if c not in leading)
        return [(cluster_id, self.current[cluster_id]) for cluster_id in leading + rest]


def settle(
    path: Path,
    cluster_id: str,
    serial: int,
    *,
    like: Path,
    locked: Callable[[], contextlib.AbstractContextManager[None]],
) -> None:
    """Clear one cluster's mark after a rollout answered 0 - unless it was marked again meanwhile."""

    with locked():
        found = read(path)
        if found is None or found.get(cluster_id) != serial:
            return
        del found[cluster_id]
        write(path, found, like=like)
