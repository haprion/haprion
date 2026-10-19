"""The repository key package a CLI release carries for restored nodes (B339).

The node package depends on `haprion-archive-keyring`, so that a renewed key
reaches every node installed from the project's repository. A node installed
from a release's files has no repository to take it from, and a restore to a
new VM sends the node package with nothing to satisfy that - apt refused it
from 0.9.0 until this (measured 26-10-19). The CLI release therefore carries
the key package as it carries the WAF engine, and a restore of such a node
sends both.
"""

from __future__ import annotations

import re
from pathlib import Path

from haprion import carried_package
from haprion.carried_package import PackageError, ReleasePackage

__all__ = [
    "PACKAGE",
    "RELEASE_PACKAGE",
    "PackageError",
    "ReleasePackage",
    "release_package",
    "verify_package",
]

PACKAGE = "haprion-archive-keyring"
#
# Its version is the day its key last changed (tools/build-keyring-package.py).
#
VERSION = re.compile(r"\d{4}\.\d{1,2}\.\d{1,2}")
RELEASE_PACKAGE = "haprion-archive-keyring.deb"
CARRIED = carried_package.Carried(
    package=PACKAGE,
    architecture="all",
    contains="usr/share/keyrings/haprion-archive-keyring.asc",
    version=VERSION,
    release_file=RELEASE_PACKAGE,
    record="keyring_package",
    max_bytes=1024 * 1024,
)


def verify_package(deb: Path, expected_sha256: str | None = None) -> tuple[str, str]:
    """The package's version and SHA-256, refused unless it is the repository key package."""

    return carried_package.verify(CARRIED, deb, expected_sha256)


def release_package(release: Path | None = None) -> ReleasePackage | None:
    """The key package the running release carries, verified; None when it carries none."""

    return carried_package.in_release(CARRIED, release)
