"""The project's own package repository, for a node restored to a new VM (B339).

A node installed from the repository gets the WAF engine and the repository
key from there, and the engine moves on there between releases (B323). A
restore of such a node gives the target the same source, written as
docs/install.md writes it, so the node package's dependencies come from where
they came from before - the engine as new as the repository's, not the one the
manager's CLI release was built with. A node installed from a release's files
had no such source, and its restore sends those packages from the CLI release
instead.

The key ships with the product and is held to its fingerprint, as the HAProxy
repositories' are (B179): a key is never fetched at restore time.
"""

from __future__ import annotations

from importlib.resources import files

from haprion import haproxy_repository
from haprion.haproxy_repository import RepositoryError, RepositoryFile
from haprion.restore_source import RestoreSource, content

__all__ = [
    "FINGERPRINT",
    "KEY_PATH",
    "SOURCE_PATH",
    "URI",
    "RepositoryError",
    "in_archive",
    "key",
    "repository_files",
]

URI = "https://haprion.github.io/haprion/"
FINGERPRINT = "927422B0C5F005E0B710E4FFF30F5055A9FC0A53"
#
# Where docs/install.md puts them. The key file then belongs to
# haprion-archive-keyring, which the node package depends on, so a renewed key
# reaches the restored node like any other.
#
KEY_PATH = "/usr/share/keyrings/haprion-archive-keyring.asc"
SOURCE_PATH = "/etc/apt/sources.list.d/haprion.sources"
SUITES = {("debian", "13"): "deb13", ("ubuntu", "26.04"): "ubuntu26.04"}


def in_archive(source: RestoreSource) -> bool:
    """Whether the archived node had this repository among its APT sources."""

    for entry in source.entries:
        if entry.kind != "file" or not entry.path.startswith("/etc/apt/sources.list.d/"):
            continue
        for line in content(source, entry).decode("utf-8", "replace").splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if URI.rstrip("/") in stripped:
                return True
    return False


def key() -> bytes:
    """The shipped key, refused unless it is the pinned one."""

    data = files("haprion").joinpath("apt-keys", "haprion-archive.asc").read_bytes()
    if haproxy_repository.fingerprint(data) != FINGERPRINT:
        raise RepositoryError(
            "haprion-archive.asc is not the key "
            f"{FINGERPRINT}; the repository key was changed without its fingerprint"
        )
    return data


def repository_files(os_release: dict[str, str]) -> tuple[RepositoryFile, ...]:
    """The key and the deb822 source, for this target's distribution."""

    suite = SUITES.get((os_release.get("ID", ""), os_release.get("VERSION_ID", "")))
    if suite is None:
        raise RepositoryError(
            f"{os_release.get('ID', '')} {os_release.get('VERSION_ID', '')} has no suite "
            "in the haprion repository; restore onto Ubuntu 26.04 or Debian 13"
        )
    source = f"Types: deb\nURIs: {URI}\nSuites: {suite}\nComponents: main\nSigned-By: {KEY_PATH}\n"
    return (RepositoryFile(KEY_PATH, key()), RepositoryFile(SOURCE_PATH, source.encode()))
