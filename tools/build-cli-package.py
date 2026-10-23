#!/usr/bin/env python3
"""Build the CLI package, `haprion-cli`, from one commit (B266, model C).

The package is transport for the release installer, not the release itself:

    /usr/lib/haprion/cli/          the wheel, the node package the release
                                   carries (B180), tools/install-release.py
                                   and PAYLOAD, which names both with digests
    /usr/bin/haprion-<command>     one line per operator command, into
                                   /opt/haprion/current/bin - on sudo's path,
                                   which current/bin is not
    /etc/sudoers.d/haprion         the operators' rules (install/sudoers/haprion)

`postinst` runs the installer with what PAYLOAD names, which verifies the wheel
and the node package, makes a release under /opt/haprion/releases and switches
`current` - the versioned releases, rollback and INSTALLATION.json stay what
they were. Root helpers get no command in /usr/bin: they are run through their
exact sudo rule by a calling half, and neither are the worker's `-ask`
commands or what a service runs.

The same commit gives the same bytes: the wheel is built from `git archive`
with SOURCE_DATE_EPOCH set to the commit's time (measured 26-10-09: two builds,
one digest), the node package is reproducible on its own, and every file time
in the package is the commit's.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from haprion import (  # the path above comes first
    keyring_package,
    node_package,
    waf_engine_package,
)
from haprion.debian_package import package, write

PACKAGE = "haprion-cli"
LIB = "usr/lib/haprion/cli"
TARGET = "/opt/haprion"
SUDOERS = "etc/sudoers.d/haprion"
#
# What the engine imports and runs, named directly (tests/test_package_commands.py
# holds the list to the code). libcrypt1 is loaded through ctypes for an https
# receiver's yescrypt hash (cert_receiver.secret_hash), which no shared-library
# scan would see. python3-cryptography is PyJWT's `crypto` extra, which
# Debian's python3-jwt only recommends: OIDC's signatures need it. The system
# bus is systemd-run's, which the candidate's sandbox is started with. The WAF
# engine and rules compile an object's rules before they leave the manager, and
# come from the project's apt repository with the key that signs it (B325).
#
DEPENDS = (
    "python3 (>= 3.13), python3-yaml, python3-nacl, python3-psycopg, python3-jwt, "
    "python3-cryptography, sudo, git, rsync, openssh-client, openssl, haproxy, passwd, "
    "iproute2, systemd, default-dbus-system-bus | dbus-system-bus, libcrypt1, "
    "haprion-coraza-spoa, haprion-crs, haprion-archive-keyring"
)
#
# sshd checks a certificate receiver's account (cert_receiver) - a manager
# without receivers never runs it. Countries in address groups read the
# Location database (geo.py), imported only when an object names a country:
# recommended, so apt installs it unless told not to, and the package's own
# timer keeps the database current from then on (B322, 26-10-17). Nothing
# installs it later, when a country is first named - that would be root running
# apt in the middle of a publish.
#
RECOMMENDS = "openssh-server, location, python3-location"
#
# Entry points that are not operator commands, besides every `-helper`: what
# the worker runs to reach a socket, and what a service or timer runs.
#
NOT_COMMANDS = frozenset({"haprion-cert-renew", "haprion-traffic-collector"})
POSTINST = f"""\
#!/bin/sh
set -e
if [ "$1" = configure ]; then
    . /{LIB}/PAYLOAD
    /usr/bin/python3 /{LIB}/install-release.py \\
        --wheel "/{LIB}/$WHEEL" --sha256 "$WHEEL_SHA256" \\
        --node-package "/{LIB}/$NODE_PACKAGE" --node-package-sha256 "$NODE_PACKAGE_SHA256" \\
        --waf-engine-package "/{LIB}/$WAF_ENGINE_PACKAGE" \\
        --waf-engine-package-sha256 "$WAF_ENGINE_PACKAGE_SHA256" \\
        --keyring-package "/{LIB}/$KEYRING_PACKAGE" \\
        --keyring-package-sha256 "$KEYRING_PACKAGE_SHA256" \\
        --target {TARGET}
fi
"""
#
# The releases under /opt/haprion are the installer's, not dpkg's (model C);
# purge is what removes them, and nothing else does.
#
POSTRM = f"""\
#!/bin/sh
set -e
if [ "$1" = purge ]; then
    rm -rf {TARGET}
fi
"""


class BuildError(RuntimeError):
    """A fail-closed package build error."""


def operator_commands(wheel: Path) -> list[str]:
    """The wheel's console scripts that an operator types."""

    with zipfile.ZipFile(wheel) as archive:
        names = [n for n in archive.namelist() if n.endswith(".dist-info/entry_points.txt")]
        if len(names) != 1:
            raise BuildError("the wheel has no single entry_points.txt")
        text = archive.read(names[0]).decode()
    commands, section = [], ""
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("["):
            section = line
        elif section == "[console_scripts]" and "=" in line:
            name = line.split("=", 1)[0].strip()
            if not (name.endswith(("-helper", "-ask")) or name in NOT_COMMANDS):
                commands.append(name)
    return sorted(commands)


def command_line(name: str) -> bytes:
    return f'#!/bin/sh\nexec {TARGET}/current/bin/{name} "$@"\n'.encode()


def visudo_accepts(path: Path) -> None:
    checked = subprocess.run(  # noqa: S603 - fixed checker, generated file
        ["/usr/sbin/visudo", "-cf", str(path)], capture_output=True, text=True, check=False
    )
    if checked.returncode != 0:
        raise BuildError(f"visudo refuses {path.name}: {checked.stderr.strip()}")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def assemble(
    root: Path,
    *,
    wheel: Path,
    node_deb: Path,
    waf_engine_deb: Path,
    keyring_deb: Path,
    installer: bytes,
    sudoers: bytes,
    licence: bytes,
    commit: str,
) -> None:
    """The package tree, from artifacts already built."""

    write(root, f"{LIB}/{wheel.name}", wheel.read_bytes(), 0o644)
    write(root, f"{LIB}/{node_deb.name}", node_deb.read_bytes(), 0o644)
    write(root, f"{LIB}/{waf_engine_deb.name}", waf_engine_deb.read_bytes(), 0o644)
    write(root, f"{LIB}/{keyring_deb.name}", keyring_deb.read_bytes(), 0o644)
    write(root, f"{LIB}/install-release.py", installer, 0o755)
    payload = (
        f"WHEEL={wheel.name}\nWHEEL_SHA256={sha256(wheel)}\n"
        f"NODE_PACKAGE={node_deb.name}\nNODE_PACKAGE_SHA256={sha256(node_deb)}\n"
        f"WAF_ENGINE_PACKAGE={waf_engine_deb.name}\n"
        f"WAF_ENGINE_PACKAGE_SHA256={sha256(waf_engine_deb)}\n"
        f"KEYRING_PACKAGE={keyring_deb.name}\n"
        f"KEYRING_PACKAGE_SHA256={sha256(keyring_deb)}\n"
    )
    write(root, f"{LIB}/PAYLOAD", payload.encode(), 0o644)
    for name in operator_commands(wheel):
        write(root, f"usr/bin/{name}", command_line(name), 0o755)
    write(root, SUDOERS, sudoers, 0o440)
    visudo_accepts(root / SUDOERS)
    write(
        root,
        "usr/share/doc/haprion-cli/copyright",
        node_package.COPYRIGHT_HEADER + licence,
        0o644,
    )
    write(
        root,
        "usr/share/doc/haprion-cli/BUILD",
        (
            f"commit: {commit}\nwheel_sha256: {sha256(wheel)}\n"
            f"node_package_sha256: {sha256(node_deb)}\n"
            f"waf_engine_package_sha256: {sha256(waf_engine_deb)}\n"
            f"keyring_package_sha256: {sha256(keyring_deb)}\n"
        ).encode(),
        0o644,
    )
    write(root, "DEBIAN/conffiles", f"/{SUDOERS}\n".encode(), 0o644)
    write(root, "DEBIAN/postinst", POSTINST.encode(), 0o755)
    write(root, "DEBIAN/postrm", POSTRM.encode(), 0o755)


def _git(source: Path, *arguments: str) -> bytes:
    return subprocess.run(  # noqa: S603 - fixed executable and internal git arguments
        ["/usr/bin/git", "-C", str(source), *arguments], check=True, capture_output=True
    ).stdout


def build_wheel(source: Path, commit: str, epoch: int, uv: Path, work: Path) -> Path:
    tree = work / "wheel-source"
    tree.mkdir()
    with tarfile.open(fileobj=io.BytesIO(_git(source, "archive", "--format=tar", commit))) as tar:
        tar.extractall(tree, filter="data")
    out = work / "wheel"
    subprocess.run(  # noqa: S603 - the operator's uv, fixed arguments
        [str(uv), "build", "--wheel", "--out-dir", str(out), "."],
        cwd=tree,
        check=True,
        capture_output=True,
        # setuptools copies each file anew, so the wheel's modes are the
        # umask's: 002 and 022 gave two digests (26-10-18).
        umask=0o022,
        env={
            "PATH": "/usr/bin:/bin",
            "SOURCE_DATE_EPOCH": str(epoch),
            "LC_ALL": "C",
            # uv's cache, which holds the build backend the lock pins.
            **{key: os.environ[key] for key in ("HOME", "UV_CACHE_DIR") if key in os.environ},
        },
    )
    wheels = list(out.glob("*.whl"))
    if len(wheels) != 1:
        raise BuildError("the build made no single wheel")
    return wheels[0]


def provides(source: Path, commit: str) -> str:
    """The engine's API level, as a version the interface's package can depend on (6-4)."""

    document = json.loads(_git(source, "show", f"{commit}:src/haprion/compatibility.json"))
    return f"haprion-engine (= {int(document['engine_api'])})"


def build(
    source: Path, output_dir: Path, uv: Path, waf_engine_deb: Path, keyring_deb: Path
) -> Path:
    source = source.resolve(strict=True)
    commit = node_package.source_commit(source)
    output_dir.mkdir(parents=True, exist_ok=True)
    epoch = int(_git(source, "show", "-s", "--format=%ct", commit).decode().strip())
    with tempfile.TemporaryDirectory(prefix="haprion-cli-package-") as directory:
        work = Path(directory)
        wheel = build_wheel(source, commit, epoch, uv, work)
        node_deb, facts = node_package.build_package(source, work / "node")
        #
        # The WAF engine is built apart, from pinned upstream sources
        # (tools/build-coraza-package.py); the release carries it for nodes
        # restored to a new VM. Checked here so a wrong file never ships.
        #
        waf_engine_package.verify_package(waf_engine_deb)
        #
        # The node package depends on the repository key package; a node
        # restored from a release's files gets it from here (B339).
        #
        keyring_package.verify_package(keyring_deb)
        root = work / "root"
        assemble(
            root,
            wheel=wheel,
            node_deb=node_deb,
            waf_engine_deb=waf_engine_deb,
            keyring_deb=keyring_deb,
            installer=_git(source, "show", f"{commit}:tools/install-release.py"),
            sudoers=_git(source, "show", f"{commit}:install/sudoers/haprion"),
            licence=_git(source, "show", f"{commit}:LICENSE"),
            commit=commit,
        )
        return package(
            root,
            {
                "Package": PACKAGE,
                "Version": facts.version,
                "Architecture": "all",
                "Depends": DEPENDS,
                "Recommends": RECOMMENDS,
                "Provides": provides(source, commit),
                "Section": "net",
                "Priority": "optional",
                "Description": "Haprion command line: the engine that manages HAProxy clusters\n"
                " Installs a versioned release under /opt/haprion from the wheel it\n"
                " carries, with the node package that release restores nodes with.",
            },
            output_dir,
            epoch,
        )


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--uv", type=Path, default=shutil.which("uv"), help="the uv to build with")
    parser.add_argument(
        "--waf-engine-package",
        type=Path,
        required=True,
        help="the haprion-coraza-spoa package (tools/build-coraza-package.py) restored nodes get",
    )
    parser.add_argument(
        "--keyring-package",
        type=Path,
        required=True,
        help="the haprion-archive-keyring package (tools/build-keyring-package.py) restored nodes get",
    )
    args = parser.parse_args()
    if args.uv is None:
        parser.error("no uv on PATH; pass --uv")
    try:
        target = build(
            args.source, args.output_dir, args.uv, args.waf_engine_package, args.keyring_package
        )
    except (
        BuildError,
        node_package.PackageError,
        waf_engine_package.PackageError,
        keyring_package.PackageError,
        ValueError,
        OSError,
    ) as exc:
        parser.exit(1, f"package build failed: {exc}\n")
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or b"").decode(errors="replace").strip().splitlines()[-3:]
        parser.exit(1, f"package build failed: {' / '.join(detail) or exc}\n")
    print(json.dumps({"package": str(target), "sha256": sha256(target)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
