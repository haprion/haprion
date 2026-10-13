"""The WAF engine package a CLI release carries for restored nodes.

A node that ran the WAF engine needs it again before the cluster's release
can be deployed to it: `haprion-pull-deploy` refuses a release with WAF rules
on a node without the engine. The engine is not in any distribution's
repository - it is built from pinned sources (tools/build-coraza-package.py)
and installed by hand - so a node restored to a new VM had no way to get it
back. The CLI release therefore carries the package beside the node package,
put there by tools/install-release.py, and a restore installs it when the
archive shows the node had it.

The engine is one statically linked binary, so the one package serves every
distribution a node may run.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

PACKAGE = "haprion-coraza-spoa"
ARCHITECTURE = "amd64"
ENGINE = "usr/sbin/coraza-spoa"
MAX_PACKAGE_BYTES = 64 * 1024 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}")
VERSION = re.compile(r"\d+\.\d+\.\d+-\d+")
DPKG_DEB = "/usr/bin/dpkg-deb"
#
# Where a CLI release carries it: beside INSTALLATION.json, as the node package.
#
RELEASE_PACKAGE = "haprion-coraza-spoa.deb"


class PackageError(RuntimeError):
    """The WAF engine package cannot be used."""


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


def verify_package(deb: Path, expected_sha256: str | None = None) -> tuple[str, str]:
    """The package's version and SHA-256, refused unless it is the WAF engine package."""

    if not deb.is_file() or deb.is_symlink():
        raise PackageError("package must be a regular non-symlink file")
    if deb.stat().st_size > MAX_PACKAGE_BYTES:
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
    if fields["Package"] != PACKAGE or fields["Architecture"] != ARCHITECTURE:
        raise PackageError(f"not a {PACKAGE} {ARCHITECTURE} package")
    if VERSION.fullmatch(fields["Version"]) is None:
        raise PackageError("package version is not one this project builds")
    listed = {
        line.split()[-1].removeprefix("./")
        for line in _dpkg_deb("--contents", str(deb)).decode().splitlines()
        if line.strip()
    }
    if ENGINE not in listed:
        raise PackageError(f"package does not carry {ENGINE}")
    return fields["Version"], actual


def release_package(release: Path | None = None) -> ReleasePackage | None:
    """The WAF engine package the running release carries, verified; None when it carries none.

    The release directory is the one this module was installed into:
    ``<release>/lib/haprion/waf_engine_package.py``. A checkout, or a release
    installed without ``--waf-engine-package``, answers None.
    """

    release = release or Path(__file__).resolve().parents[2]
    installation = release / "INSTALLATION.json"
    if not installation.is_file():
        return None
    try:
        document = json.loads(installation.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PackageError(f"cannot read {installation}: {exc}") from exc
    record = document.get("waf_engine_package") if isinstance(document, dict) else None
    if record is None:
        return None
    if (
        not isinstance(record, dict)
        or record.get("file") != RELEASE_PACKAGE
        or not isinstance(record.get("sha256"), str)
    ):
        raise PackageError(f"{installation} has an unusable waf_engine_package record")
    path = release / RELEASE_PACKAGE
    version, sha256 = verify_package(path, record["sha256"])
    return ReleasePackage(path=path, version=version, sha256=sha256)
