"""A package a CLI release carries beside itself, for nodes restored to a new VM.

The release keeps each such package as a file beside INSTALLATION.json, with
its digest recorded there by tools/install-release.py; a restore sends it to
the target and installs it. What may be carried is described once per package
(`Carried`), and the same checks hold for every one: a regular file of bounded
size, the recorded digest, the package's name and architecture, a version this
project builds, and the one file that makes it the package it says it is.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

SHA256 = re.compile(r"[0-9a-f]{64}")
DPKG_DEB = "/usr/bin/dpkg-deb"


class PackageError(RuntimeError):
    """A carried package cannot be used."""


@dataclass(frozen=True, slots=True)
class Carried:
    package: str
    architecture: str
    contains: str
    """The file that makes it this package, as `dpkg-deb --contents` names it."""
    version: re.Pattern[str]
    release_file: str
    """Its name beside INSTALLATION.json in a CLI release."""
    record: str
    """Its key in INSTALLATION.json."""
    max_bytes: int


@dataclass(frozen=True, slots=True)
class ReleasePackage:
    path: Path
    version: str
    sha256: str


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _dpkg_deb(*arguments: str) -> bytes:
    try:
        return subprocess.run(  # noqa: S603 - fixed binary, a verified path
            [DPKG_DEB, *arguments],
            check=True,
            capture_output=True,
            timeout=60,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        ).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        raise PackageError(f"dpkg-deb cannot read the package: {exc}") from exc


def verify(carried: Carried, deb: Path, expected_sha256: str | None = None) -> tuple[str, str]:
    """The package's version and SHA-256, refused unless it is the package `carried` names."""

    if not deb.is_file() or deb.is_symlink():
        raise PackageError("package must be a regular non-symlink file")
    if deb.stat().st_size > carried.max_bytes:
        raise PackageError("package exceeds its size limit")
    actual = _sha256(deb)
    if expected_sha256 is not None and (
        SHA256.fullmatch(expected_sha256) is None or actual != expected_sha256
    ):
        raise PackageError("package SHA-256 does not match the expected value")
    fields = {
        name: _dpkg_deb("--field", str(deb), name).decode().strip()
        for name in ("Package", "Version", "Architecture")
    }
    if fields["Package"] != carried.package or fields["Architecture"] != carried.architecture:
        raise PackageError(f"not a {carried.package} {carried.architecture} package")
    if carried.version.fullmatch(fields["Version"]) is None:
        raise PackageError("package version is not one this project builds")
    listed = {
        line.split()[-1].removeprefix("./")
        for line in _dpkg_deb("--contents", str(deb)).decode().splitlines()
        if line.strip()
    }
    if carried.contains not in listed:
        raise PackageError(f"package does not carry {carried.contains}")
    return fields["Version"], actual


def in_release(carried: Carried, release: Path | None = None) -> ReleasePackage | None:
    """The package the running release carries, verified; None when it carries none.

    The release directory is the one this module was installed into:
    ``<release>/lib/haprion/carried_package.py``. A checkout, or a release
    installed without the package, answers None.
    """

    release = release or Path(__file__).resolve().parents[2]
    installation = release / "INSTALLATION.json"
    if not installation.is_file():
        return None
    try:
        document = json.loads(installation.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PackageError(f"cannot read {installation}: {exc}") from exc
    record = document.get(carried.record) if isinstance(document, dict) else None
    if record is None:
        return None
    if (
        not isinstance(record, dict)
        or record.get("file") != carried.release_file
        or not isinstance(record.get("sha256"), str)
    ):
        raise PackageError(f"{installation} has an unusable {carried.record} record")
    path = release / carried.release_file
    version, sha256 = verify(carried, path, record["sha256"])
    return ReleasePackage(path=path, version=version, sha256=sha256)
