"""The WAF engine package a CLI release carries for restored nodes.

A node that ran the WAF engine needs it again before the cluster's release
can be deployed to it: `haprion-pull-deploy` refuses a release with WAF rules
on a node without the engine. A node installed from the project's repository
gets it back from there (B339); one installed from a release's files has only
the files, so the CLI release carries the package beside the node package,
put there by tools/install-release.py, and a restore of such a node installs
this one.

The engine is one statically linked binary, so the one package serves every
distribution a node may run.
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

PACKAGE = "haprion-coraza-spoa"
VERSION = re.compile(r"\d+\.\d+\.\d+-\d+")
#
# Where a CLI release carries it: beside INSTALLATION.json, as the node package.
#
RELEASE_PACKAGE = "haprion-coraza-spoa.deb"
CARRIED = carried_package.Carried(
    package=PACKAGE,
    architecture="amd64",
    contains="usr/sbin/coraza-spoa",
    version=VERSION,
    release_file=RELEASE_PACKAGE,
    record="waf_engine_package",
    max_bytes=64 * 1024 * 1024,
)


def verify_package(deb: Path, expected_sha256: str | None = None) -> tuple[str, str]:
    """The package's version and SHA-256, refused unless it is the WAF engine package."""

    return carried_package.verify(CARRIED, deb, expected_sha256)


def release_package(release: Path | None = None) -> ReleasePackage | None:
    """The WAF engine package the running release carries, verified; None when it carries none."""

    return carried_package.in_release(CARRIED, release)
