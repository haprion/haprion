"""Build and verify the node package, `haprion-node`, from one commit.

The package is how node software travels (B266, D4): the node scripts in
/usr/sbin, owned by dpkg, and the configuration step with what it reads under
/usr/share/haprion-node/install. Installing it changes nothing a node does;
04-node-prepare, run from where the package put it, does that with the answers.

The operator's `tools/install-node-package` verifies a package with this module
before it sends one to a node, the release installer verifies the package a CLI
release carries with it (B180), and a node restore verifies it again before it
sends it to the restored node. One implementation for all three, run from a
checkout by `tools/node-package.py`.

The same commit gives the same bytes: every file comes from the commit, not the
working tree, and every time is the commit's.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import subprocess
import sys
import tarfile
import tempfile
import tomllib
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from haprion.debian_package import package, write

PACKAGE = "haprion-node"
ARCHITECTURE = "all"
SBIN = "/usr/sbin"
INSTALL_DIR = "/usr/share/haprion-node/install"
BUILD_FILE = "usr/share/doc/haprion-node/BUILD"
COPYRIGHT_FILE = "usr/share/doc/haprion-node/copyright"
#
# Debian's copyright file: who, under what, and the licence in full - AGPL-3.0
# is not among /usr/share/common-licenses to refer to.
#
COPYRIGHT_HEADER = (
    b"Haprion - Copyright the Haprion contributors.\n"
    b"License: AGPL-3.0-or-later. The full text follows.\n\n"
)
MAX_PACKAGE_BYTES = 4 * 1024 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}")
COMMIT = re.compile(r"[0-9a-f]{40}")
#
# Upstream version, then the commit's time and hash: a later commit sorts
# later, which is what lets apt take a newer package over an older one.
#
VERSION = re.compile(r"(\d+\.\d+\.\d+)\+git(\d{14})\.([0-9a-f]{12})")
NODE_SCRIPTS = (
    "haprion-pull-deploy",
    "haprion-cert-pull",
    "haprion-cert-remove",
    "haprion-cert-trigger",
    "haprion-node-status",
    "haprion-health-probe",
    "haprion-keepalived-state",
    "haprion-state-export",
    "haprion-traffic-log-read",
    "haprion-traffic-log-enable",
    "haprion-traffic-log-prune",
    "haprion-server-state",
    "haprion-server-state-trigger",
)
#
# Path in the package -> (path in the commit, mode). Data rather than programs
# is 0644: the shell library the step sources, the fixed account names and the
# defaults it reads (B266, B302), the node's sysusers fragment, and the repository key `lib.sh`
# installs dnsdist with (B249).
#
CONTENTS: dict[str, tuple[str, int]] = {
    **{f"usr/sbin/{name}": (f"install/node/{name}", 0o755) for name in NODE_SCRIPTS},
    f"{INSTALL_DIR[1:]}/04-node-prepare": ("install/04-node-prepare", 0o755),
    f"{INSTALL_DIR[1:]}/lib.sh": ("install/lib.sh", 0o644),
    f"{INSTALL_DIR[1:]}/accounts.sh": ("install/accounts.sh", 0o644),
    f"{INSTALL_DIR[1:]}/defaults.sh": ("install/defaults.sh", 0o644),
    f"{INSTALL_DIR[1:]}/sysusers/haprion-node.conf": (
        "install/sysusers/haprion-node.conf",
        0o644,
    ),
    f"{INSTALL_DIR[1:]}/apt-keys/powerdns-dnsdist.asc": (
        "install/apt-keys/powerdns-dnsdist.asc",
        0o644,
    ),
    #
    # HAProxy's repository keys, the ones a restore installs (B179), for the
    # node step's ensure_haproxy.
    #
    f"{INSTALL_DIR[1:]}/apt-keys/haproxy-debian-net.asc": (
        "src/haprion/apt-keys/haproxy-debian-net.asc",
        0o644,
    ),
    f"{INSTALL_DIR[1:]}/apt-keys/haproxy-ubuntu-ppa.asc": (
        "src/haprion/apt-keys/haproxy-ubuntu-ppa.asc",
        0o644,
    ),
    COPYRIGHT_FILE: ("LICENSE", 0o644),
}
FILES: dict[str, int] = {
    **{path: mode for path, (_, mode) in CONTENTS.items()},
    BUILD_FILE: 0o644,
}
#
# keepalived is a dependency since the product writes its configuration on the
# nodes of a cluster it created (B313); before, a person did, and it was only
# recommended.
#
DEPENDS = "python3, sudo, rsyslog, rsyslog-gnutls, haproxy, ipvsadm, keepalived"
#
# Nothing to start and nothing to stop: the scripts run when the manager asks.
# The first installation says what comes next, and an upgrade is complete when
# dpkg has replaced the files - 04-node-prepare reruns to record their digests.
#
POSTINST = f"""\
#!/bin/sh
set -e
if [ "$1" = configure ] && [ -z "$2" ]; then
    echo "{PACKAGE}: next, {INSTALL_DIR}/04-node-prepare <answers-file> <cluster-id>"
fi
"""


class PackageError(RuntimeError):
    """A fail-closed node package error."""


@dataclass(frozen=True, slots=True)
class PackageFacts:
    version: str
    commit: str
    sha256: str


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git(source: Path, *arguments: str) -> bytes:
    try:
        return subprocess.run(  # noqa: S603 -- fixed executable and internal git arguments
            ["/usr/bin/git", "-C", str(source), *arguments],
            check=True,
            capture_output=True,
            timeout=30,
        ).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        raise PackageError(f"cannot read the source commit: {exc}") from exc


def source_commit(source: Path) -> str:
    commit = _git(source, "rev-parse", "HEAD").decode().strip()
    if COMMIT.fullmatch(commit) is None:
        raise PackageError("source tree did not report a full commit hash")
    if _git(source, "status", "--porcelain").strip():
        raise PackageError("source tree has uncommitted changes; a release is a commit")
    return commit


def version_for(upstream: str, epoch: int, commit: str) -> str:
    stamp = datetime.fromtimestamp(epoch, UTC).strftime("%Y%m%d%H%M%S")
    version = f"{upstream}+git{stamp}.{commit[:12]}"
    if VERSION.fullmatch(version) is None:
        raise PackageError(f"cannot form a package version from {upstream!r}")
    return version


def _committed(source: Path, commit: str, relative: str, mode: int) -> bytes:
    fields = _git(source, "ls-tree", commit, "--", relative).decode().rstrip("\n").split(maxsplit=3)
    if len(fields) != 4 or fields[1] != "blob" or fields[3] != relative:
        raise PackageError(f"payload path is missing or not a regular file: {relative}")
    expected = "100755" if mode == 0o755 else "100644"
    if fields[0] != expected:
        raise PackageError(f"payload file {relative} has Git mode {fields[0]}, expected {expected}")
    return _git(source, "show", f"{commit}:{relative}")


def build_package(source: Path, output_dir: Path) -> tuple[Path, PackageFacts]:
    """Build the package of the source tree's commit into output_dir."""

    source = source.resolve(strict=True)
    commit = source_commit(source)
    epoch = int(_git(source, "show", "-s", "--format=%ct", commit).decode().strip())
    try:
        project = tomllib.loads(_git(source, "show", f"{commit}:pyproject.toml").decode())
        upstream = str(project["project"]["version"])
    except (tomllib.TOMLDecodeError, KeyError, UnicodeError) as exc:
        raise PackageError(f"cannot read the project version: {exc}") from exc
    files = {
        path: _committed(source, commit, relative, mode)
        for path, (relative, mode) in CONTENTS.items()
    }
    files[COPYRIGHT_FILE] = COPYRIGHT_HEADER + files[COPYRIGHT_FILE]
    target = write_package(output_dir, files, upstream=upstream, epoch=epoch, commit=commit)
    return target, verify_package(target)


def write_package(
    output_dir: Path, files: dict[str, bytes], *, upstream: str, epoch: int, commit: str
) -> Path:
    """Write the package of these node files, one per path in CONTENTS."""

    if set(files) != set(CONTENTS):
        raise PackageError("the files are not exactly the node package's")
    if COMMIT.fullmatch(commit) is None:
        raise PackageError("a package is built from a full commit hash")
    version = version_for(upstream, epoch, commit)
    output_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="haprion-node-package-") as directory:
        root = Path(directory) / "root"
        for path, data in sorted(files.items()):
            write(root, path, data, CONTENTS[path][1])
        write(root, BUILD_FILE, f"commit: {commit}\n".encode(), 0o644)
        write(root, "DEBIAN/postinst", POSTINST.encode(), 0o755)
        try:
            return package(
                root,
                {
                    "Package": PACKAGE,
                    "Version": version,
                    "Architecture": ARCHITECTURE,
                    "Depends": DEPENDS,
                    "Section": "net",
                    "Priority": "optional",
                    "Description": "Haprion node scripts and configuration step\n"
                    " The commands the manager's keys run on a load balancer node, and\n"
                    " the step that configures the node from the installation's answers.",
                },
                output_dir,
                epoch,
            )
        except (ValueError, OSError, subprocess.SubprocessError) as exc:
            raise PackageError(f"cannot build the package: {exc}") from exc


def _dpkg_deb(*arguments: str) -> bytes:
    try:
        return subprocess.run(  # noqa: S603 -- fixed executable, verified path
            ["/usr/bin/dpkg-deb", *arguments],
            check=True,
            capture_output=True,
            timeout=60,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        ).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        raise PackageError(f"dpkg-deb cannot read the package: {exc}") from exc


def verify_package(deb: Path, expected_sha256: str | None = None) -> PackageFacts:
    """The package's facts, refused unless it is exactly a node package."""

    if not deb.is_file() or deb.is_symlink():
        raise PackageError("package must be a regular non-symlink file")
    if deb.stat().st_size > MAX_PACKAGE_BYTES:
        raise PackageError("package exceeds its size limit")
    actual = sha256_file(deb)
    if expected_sha256 is not None and (
        SHA256.fullmatch(expected_sha256) is None or actual != expected_sha256
    ):
        raise PackageError("package SHA-256 does not match the expected value")
    fields = {}
    for name in ("Package", "Version", "Architecture"):
        fields[name] = _dpkg_deb("--field", str(deb), name).decode().strip()
    if fields["Package"] != PACKAGE or fields["Architecture"] != ARCHITECTURE:
        raise PackageError(f"not a {PACKAGE} {ARCHITECTURE} package")
    version = VERSION.fullmatch(fields["Version"])
    if version is None:
        raise PackageError("package version is not one this project builds")
    found: dict[str, int] = {}
    build = b""
    try:
        with tarfile.open(fileobj=io.BytesIO(_dpkg_deb("--fsys-tarfile", str(deb)))) as tree:
            for member in tree.getmembers():
                name = member.name.removeprefix("./")
                if member.isdir():
                    continue
                if not member.isreg():
                    raise PackageError(f"package member is not a regular file: {name}")
                if (member.uid, member.gid) != (0, 0):
                    raise PackageError(f"package member is not owned by root: {name}")
                found[name] = member.mode
                if name == BUILD_FILE:
                    extracted = tree.extractfile(member)
                    build = extracted.read() if extracted is not None else b""
    except tarfile.TarError as exc:
        raise PackageError(f"cannot read the package's files: {exc}") from exc
    if found != FILES:
        raise PackageError("package does not hold exactly the node files with their modes")
    recorded = re.fullmatch(rb"commit: ([0-9a-f]{40})\n", build)
    if recorded is None or not recorded.group(1).decode().startswith(version.group(3)):
        raise PackageError("package does not record the commit its version names")
    return PackageFacts(version=fields["Version"], commit=recorded.group(1).decode(), sha256=actual)


#
# Where a CLI release carries its node package (B180): beside INSTALLATION.json,
# put there by tools/install-release.py from the same commit as the wheel.
#
RELEASE_PACKAGE = "haprion-node.deb"


@dataclass(frozen=True, slots=True)
class ReleasePackage:
    path: Path
    version: str
    commit: str
    sha256: str


def release_package(release: Path | None = None) -> ReleasePackage | None:
    """The node package the running release carries, verified; None when it carries none.

    The release directory is the one this module was installed into:
    ``<release>/lib/haprion/node_package.py``. A checkout, or a release
    installed without ``--node-package``, has no INSTALLATION.json record and
    answers None.
    """

    release = release or Path(__file__).resolve().parents[2]
    installation = release / "INSTALLATION.json"
    if not installation.is_file():
        return None
    try:
        document = json.loads(installation.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PackageError(f"cannot read {installation}: {exc}") from exc
    record = document.get("node_package") if isinstance(document, dict) else None
    if record is None:
        return None
    if (
        not isinstance(record, dict)
        or record.get("file") != RELEASE_PACKAGE
        or not isinstance(record.get("sha256"), str)
    ):
        raise PackageError(f"{installation} has an unusable node_package record")
    path = release / RELEASE_PACKAGE
    facts = verify_package(path, record["sha256"])
    return ReleasePackage(
        path=path, version=facts.version, commit=facts.commit, sha256=facts.sha256
    )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    subparsers = result.add_subparsers(dest="operation", required=True)
    build = subparsers.add_parser("build")
    build.add_argument("--source", type=Path, required=True)
    build.add_argument("--output-dir", type=Path, required=True)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--package", type=Path, required=True)
    verify.add_argument("--sha256")
    return result


def main() -> int:
    arguments = parser().parse_args()
    try:
        if arguments.operation == "build":
            target, facts = build_package(arguments.source, arguments.output_dir)
            print(f"package: {target}")
        else:
            facts = verify_package(arguments.package, arguments.sha256)
        print(f"version: {facts.version}")
        print(f"commit: {facts.commit}")
        print(f"sha256: {facts.sha256}")
    except PackageError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
