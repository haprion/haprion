#!/usr/bin/env python3
"""Install a hash-verified Certmonger bundle without a system Certmonger service."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import tempfile
import zipfile
from pathlib import Path
from typing import Any

MAX_BYTES = 16 * 1024 * 1024
BINARIES = {"bin/certmonger", "bin/getcert", "bin/scep-submit"}
NAME = re.compile(r"[A-Za-z0-9_.+-]+")
SHA256 = re.compile(r"[0-9a-f]{64}")


class InstallError(ValueError):
    pass


def inspect_bundle(path: Path, digest: str) -> tuple[dict[str, Any], dict[str, bytes]]:
    if SHA256.fullmatch(digest) is None or path.stat().st_size > MAX_BYTES:
        raise InstallError("invalid bundle digest or size")
    raw = path.read_bytes()
    if len(raw) > MAX_BYTES or hashlib.sha256(raw).hexdigest() != digest:
        raise InstallError("SCEP bundle hash does not match")
    import io

    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            entries = archive.infolist()
            names = [entry.filename for entry in entries]
            if (
                len(names) != len(set(names))
                or len(names) > 16
                or sum(e.file_size for e in entries) > MAX_BYTES
            ):
                raise InstallError("SCEP bundle has duplicate files or exceeds its bounds")
            for entry in entries:
                mode = entry.external_attr >> 16
                if not stat.S_ISREG(mode) or entry.is_dir():
                    raise InstallError("SCEP bundle files must be regular files")
                name = entry.filename
                ordinary = BINARIES | {
                    "manifest.json",
                    "LICENSE",
                    "BUILD.md",
                    "package/certmonger.deb",
                }
                source_name = name.removeprefix("source/")
                source_path = (
                    name.startswith("source/")
                    and NAME.fullmatch(source_name) is not None
                    and source_name not in {".", ".."}
                )
                if name not in ordinary and not source_path:
                    raise InstallError("SCEP bundle contains an unexpected path")
            files = {e.filename: archive.read(e) for e in entries}
    except (zipfile.BadZipFile, RuntimeError):
        raise InstallError("SCEP bundle is not a readable ZIP archive") from None
    try:
        manifest = json.loads(files.pop("manifest.json"))
        expected = {
            "schema_version",
            "project",
            "version",
            "distribution",
            "distribution_release",
            "architecture",
            "package_sha256",
            "dependencies",
            "files",
        }
        if not isinstance(manifest, dict) or set(manifest) != expected:
            raise InstallError("SCEP manifest has an invalid shape")
        if (
            type(manifest["schema_version"]) is not int
            or manifest["schema_version"] != 1
            or manifest["project"] != "certmonger"
        ):
            raise InstallError("SCEP manifest is unsupported")
        for key in ("version", "distribution", "distribution_release", "architecture"):
            if not isinstance(manifest[key], str) or NAME.fullmatch(manifest[key]) is None:
                raise InstallError("SCEP manifest identity is invalid")
        dependencies = manifest["dependencies"]
        if (
            not isinstance(dependencies, str)
            or not dependencies
            or len(dependencies) > 4096
            or re.fullmatch(r"[a-zA-Z0-9_.+:,|()<>~= \-]+", dependencies) is None
        ):
            raise InstallError("SCEP dependencies are invalid")
        if (
            set(files) != set(manifest["files"])
            or not BINARIES | {"LICENSE", "BUILD.md", "package/certmonger.deb"} <= files.keys()
        ):
            raise InstallError("SCEP manifest file set does not match")
        if len([name for name in files if name.startswith("source/")]) != 3:
            raise InstallError("SCEP bundle must retain the complete distro source")
        for name, data in files.items():
            record = manifest["files"][name]
            if (
                set(record) != {"sha256", "size"}
                or record["size"] != len(data)
                or record["sha256"] != hashlib.sha256(data).hexdigest()
            ):
                raise InstallError("SCEP bundle member hash does not match")
        if (
            hashlib.sha256(files["package/certmonger.deb"]).hexdigest()
            != manifest["package_sha256"]
        ):
            raise InstallError("SCEP source package hash does not match")
        if any(not files[name].startswith(b"\x7fELF") for name in BINARIES):
            raise InstallError("SCEP programs must be ELF binaries")
    except (KeyError, TypeError, UnicodeError, ValueError) as exc:
        if isinstance(exc, InstallError):
            raise
        raise InstallError("SCEP manifest is invalid") from None
    return manifest, files


def protected_target(target: Path) -> None:
    if not target.is_absolute():
        raise InstallError("SCEP target must be absolute")
    for parent in (target, *target.parents):
        if parent.exists() or parent.is_symlink():
            info = parent.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise InstallError("SCEP installation must have protected root-owned ancestors")


def activate(target: Path, final: Path) -> None:
    temporary_link = target / (".current-" + secrets.token_hex(8))
    try:
        temporary_link.symlink_to(final.relative_to(target))
        temporary_link.replace(target / "current")
    finally:
        temporary_link.unlink(missing_ok=True)


def install(path: Path, digest: str, target: Path, *, satisfy: bool = True) -> Path:
    if os.geteuid() != 0:
        raise InstallError("SCEP installation must run as root")
    manifest, files = inspect_bundle(path, digest)
    protected_target(target)
    release_info = {}
    for line in Path("/etc/os-release").read_text().splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            release_info[key] = value.strip('"')
    architecture = subprocess.run(
        ["/usr/bin/dpkg", "--print-architecture"], check=True, capture_output=True, text=True
    ).stdout.strip()  # fixed distribution command
    if (release_info.get("ID"), release_info.get("VERSION_ID"), architecture) != (
        manifest["distribution"],
        manifest["distribution_release"],
        manifest["architecture"],
    ):
        raise InstallError("SCEP bundle does not match this distribution, release and architecture")
    current = target / "current"
    if current.exists() and not current.is_symlink():
        raise InstallError("SCEP current must be a release symlink")
    releases = target / "releases"
    protected_target(releases)
    releases.mkdir(parents=True, exist_ok=True, mode=0o755)
    final = releases / (str(manifest["version"]) + "-" + digest[:12])
    if final.exists() or final.is_symlink():
        protected_target(final)
        for name, data in files.items():
            destination = final / name
            protected_target(destination.parent)
            info = destination.lstat()
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != 0
                or info.st_mode & 0o222
                or destination.read_bytes() != data
            ):
                raise InstallError("existing SCEP release does not match the approved bundle")
        if json.loads((final / "manifest.json").read_bytes()) != manifest:
            raise InstallError("existing SCEP release manifest does not match")
        activate(target, final)
        return final
    staging = Path(tempfile.mkdtemp(prefix=".scep-", dir=releases))
    try:
        for name, data in files.items():
            destination = staging / name
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            destination.write_bytes(data)
            destination.chmod(0o555 if name in BINARIES else 0o444)
        (staging / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        (staging / "manifest.json").chmod(0o444)
        #
        # The haprion-scep package depends on the same relations, so apt has
        # installed them before its postinst runs - where apt cannot be run
        # again, dpkg holding its lock (B383). `ldd` below still proves them.
        #
        if satisfy:
            subprocess.run(  # noqa: S603 - dependency relations in approved bundle
                [
                    "/usr/bin/apt-get",
                    "--assume-yes",
                    "--no-install-recommends",
                    "satisfy",
                    manifest["dependencies"],
                ],
                check=True,
            )  # relations from the explicitly approved, verified bundle
        for name in BINARIES:
            result = subprocess.run(  # noqa: S603 - root-only hash-approved ELF
                ["/usr/bin/ldd", str(staging / name)], check=False, capture_output=True, text=True
            )  # hash-approved ELF under root-only staging
            if result.returncode or "not found" in result.stdout:
                raise InstallError("SCEP runtime library check failed")
        for directory in sorted((p for p in staging.rglob("*") if p.is_dir()), reverse=True):
            directory.chmod(0o555)
        staging.chmod(0o555)
        staging.rename(final)
        activate(target, final)
    finally:
        if staging.exists():
            for directory in [staging, *(p for p in staging.rglob("*") if p.is_dir())]:
                directory.chmod(0o700)
            shutil.rmtree(staging)
    return final


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--target", type=Path, default=Path("/opt/haprion-scep"))
    parser.add_argument(
        "--no-satisfy",
        action="store_true",
        help="the dependencies are installed already (the haprion-scep package's)",
    )
    args = parser.parse_args()
    try:
        print(install(args.bundle, args.sha256, args.target, satisfy=not args.no_satisfy))
    except (InstallError, OSError, subprocess.SubprocessError) as exc:
        parser.exit(1, f"SCEP installation failed: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
