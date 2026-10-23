"""Which of the manager's own packages has a newer version waiting (B357).

The security review (26-10-22) asked for "fixed in the source, not yet
installed" as a state of its own. Without asking the internet (B333): apt has
already fetched what the configured repositories offer, into its lists, when
the machine's own `apt update` ran. This compares that with what dpkg says is
installed, for the project's packages - `haprion-*` - and nothing else; the
distribution's packages are the distribution's updater's to report.

Both files are world-readable and only read here. The lists are large (some
150 MB on a manager), so they are read again only when one has changed: a
pass that finds the same files at the same size and time reuses the last
answer.

The nodes are not read here. Their packages are in their status, and a node
behind another node, or behind the node package the CLI release carries, is
already said (`haproxy_versions.packages_behind`, the update's compatibility
check).
"""

from __future__ import annotations

import gzip
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

from haprion.haproxy_versions import compare

DPKG_STATUS = Path("/var/lib/dpkg/status")
APT_LISTS = Path("/var/lib/apt/lists")
PREFIX = b"haprion-"
INSTALLED = b"install ok installed"


@dataclass(frozen=True, slots=True)
class Behind:
    """One package with a newer version in the repository than the one installed."""

    name: str
    installed: str
    available: str


def _stanzas(lines: Iterator[bytes]) -> Iterator[dict[bytes, bytes]]:
    """The `Field: value` paragraphs of a dpkg or apt index, the project's packages only.

    A paragraph is read into a mapping only once its `Package` line names one
    of them, so the distribution's tens of thousands cost a comparison each.
    """

    fields: dict[bytes, bytes] | None = None
    for raw in lines:
        line = raw.rstrip(b"\r\n")
        if not line:
            if fields is not None:
                yield fields
            fields = None
        elif line.startswith(b"Package: "):
            name = line[9:].strip()
            fields = {b"Package": name} if name.startswith(PREFIX) else None
        elif fields is not None and not line[:1].isspace() and b": " in line:
            key, _, value = line.partition(b": ")
            fields[key] = value.strip()
    if fields is not None:
        yield fields


def _open(path: Path) -> BinaryIO:
    if path.suffix == ".gz":
        return gzip.open(path, "rb")  # type: ignore[return-value]
    return path.open("rb")


def installed(status: Path = DPKG_STATUS) -> dict[str, str]:
    """Each project package dpkg has installed, with its version."""

    found: dict[str, str] = {}
    with status.open("rb") as stream:
        for fields in _stanzas(stream):
            version = fields.get(b"Version")
            if fields.get(b"Status") == INSTALLED and version:
                found[fields[b"Package"].decode()] = version.decode()
    return found


def _lists(directory: Path) -> list[Path]:
    """apt's package indexes: plain, or gzip where apt keeps them compressed."""

    try:
        entries = sorted(directory.iterdir())
    except OSError:
        return []
    return [
        path
        for path in entries
        if path.name.endswith(("_Packages", "_Packages.gz")) and path.is_file()
    ]


def available(lists: Sequence[Path]) -> dict[str, str]:
    """The newest version of each project package the indexes offer."""

    newest: dict[str, str] = {}
    for path in lists:
        try:
            with _open(path) as stream:
                for fields in _stanzas(stream):
                    version = fields.get(b"Version")
                    if not version:
                        continue
                    name, text = fields[b"Package"].decode(), version.decode()
                    if name not in newest or compare(text, newest[name]) > 0:
                        newest[name] = text
        except (OSError, EOFError):
            continue
    return newest


def behind(installed_now: Mapping[str, str], offered: Mapping[str, str]) -> list[Behind]:
    """Each installed package the repository has a newer version of, by name."""

    return [
        Behind(name, version, offered[name])
        for name, version in sorted(installed_now.items())
        if name in offered and compare(offered[name], version) > 0
    ]


@dataclass(slots=True)
class Reader:
    """The comparison, read again only when dpkg's status or one of apt's lists changed."""

    status: Path = DPKG_STATUS
    lists: Path = APT_LISTS
    _seen: tuple[tuple[str, int, int], ...] = ()
    _answer: list[Behind] = field(default_factory=list)

    def _fingerprint(self, paths: list[Path]) -> tuple[tuple[str, int, int], ...]:
        seen = []
        for path in (self.status, *paths):
            try:
                found = path.stat()
            except OSError:
                continue
            seen.append((str(path), found.st_size, found.st_mtime_ns))
        return tuple(seen)

    def read(self) -> list[Behind]:
        paths = _lists(self.lists)
        fingerprint = self._fingerprint(paths)
        if fingerprint != self._seen:
            self._answer = behind(installed(self.status), available(paths))
            self._seen = fingerprint
        return list(self._answer)
