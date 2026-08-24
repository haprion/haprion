#!/usr/bin/env python3
"""Install a verified HAProxy Manager wheel into an immutable release directory."""

from __future__ import annotations

import argparse
import configparser
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile
from email.parser import BytesParser
from pathlib import Path, PurePosixPath

DEFAULT_TARGET = Path("/opt/haproxy-mgmt")
DEFAULT_PYTHON = Path("/usr/bin/python3")
EXPECTED_PROJECT = "haproxy-manager"
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
VERSION_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]*")
ENTRY_POINT_PATTERN = re.compile(
    r"(?P<module>haproxy_mgmt(?:\.[a-z_][a-z0-9_]*)*):(?P<callable>[a-z_][a-z0-9_]*)"
)
SCRIPT_NAME_PATTERN = re.compile(r"haproxy-[a-z0-9-]+")


class InstallError(RuntimeError):
    """A fail-closed installation error."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_safe_absolute_path(path: Path, *, label: str) -> Path:
    if not path.is_absolute():
        raise InstallError(f"{label} must be an absolute path")
    resolved = path.resolve(strict=False)
    if resolved != path:
        raise InstallError(f"{label} may not traverse symlinks")
    return path


def inspect_runtime(python: Path) -> dict[str, str]:
    if not python.is_absolute() or not python.is_file() or not os.access(python, os.X_OK):
        raise InstallError("runtime Python must be an executable absolute file")
    probe = (
        "import importlib.metadata,json,sys;"
        "print(json.dumps({'python':'.'.join(map(str,sys.version_info[:3])),"
        "'pyyaml':importlib.metadata.version('PyYAML')}))"
    )
    try:
        completed = subprocess.run(  # noqa: S603 - validated absolute interpreter, fixed argv
            [str(python), "-I", "-c", probe],
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
        )
        result = json.loads(completed.stdout)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError, KeyError) as exc:
        raise InstallError(f"runtime Python/PyYAML probe failed: {exc}") from exc
    if not isinstance(result, dict) or not all(
        isinstance(result.get(key), str) for key in ("python", "pyyaml")
    ):
        raise InstallError("runtime Python/PyYAML probe returned invalid data")
    python_version = tuple(int(part) for part in result["python"].split("."))
    yaml_major = int(result["pyyaml"].split(".", maxsplit=1)[0])
    if python_version < (3, 12, 0):
        raise InstallError("runtime Python must be version 3.12 or newer")
    if yaml_major != 6:
        raise InstallError("runtime PyYAML must be major version 6")
    return {"python": result["python"], "pyyaml": result["pyyaml"]}


def _safe_member(name: str) -> PurePosixPath:
    member = PurePosixPath(name)
    if not name or member.is_absolute() or ".." in member.parts or "" in member.parts:
        raise InstallError(f"wheel contains an unsafe path: {name!r}")
    return member


def inspect_wheel(
    wheel: Path,
) -> tuple[str, str, dict[str, tuple[str, str]], list[zipfile.ZipInfo]]:
    try:
        archive = zipfile.ZipFile(wheel)
    except (OSError, zipfile.BadZipFile) as exc:
        raise InstallError(f"cannot open wheel: {exc}") from exc
    with archive:
        members = archive.infolist()
        for item in members:
            member = _safe_member(item.filename)
            mode = item.external_attr >> 16
            file_type = stat.S_IFMT(mode)
            if file_type == stat.S_IFLNK:
                raise InstallError(f"wheel contains a symlink: {member}")
            if file_type not in (0, stat.S_IFREG, stat.S_IFDIR):
                raise InstallError(f"wheel contains a special file: {member}")

        metadata_items = [item for item in members if item.filename.endswith(".dist-info/METADATA")]
        entry_items = [
            item for item in members if item.filename.endswith(".dist-info/entry_points.txt")
        ]
        if len(metadata_items) != 1 or len(entry_items) != 1:
            raise InstallError("wheel must contain exactly one METADATA and entry_points.txt")

        metadata = BytesParser().parsebytes(archive.read(metadata_items[0]))
        project = metadata.get("Name", "")
        version = metadata.get("Version", "")
        if project.lower().replace("_", "-") != EXPECTED_PROJECT:
            raise InstallError("wheel project name is not haproxy-manager")
        if not VERSION_PATTERN.fullmatch(version):
            raise InstallError("wheel contains an invalid project version")

        parser = configparser.ConfigParser(interpolation=None)
        try:
            parser.read_string(archive.read(entry_items[0]).decode("utf-8"))
        except (UnicodeDecodeError, configparser.Error) as exc:
            raise InstallError(f"invalid wheel entry points: {exc}") from exc
        if set(parser.sections()) != {"console_scripts"}:
            raise InstallError("wheel may contain only console_scripts entry points")
        scripts: dict[str, tuple[str, str]] = {}
        for name, target in parser.items("console_scripts"):
            match = ENTRY_POINT_PATTERN.fullmatch(target.strip())
            if not SCRIPT_NAME_PATTERN.fullmatch(name) or match is None:
                raise InstallError(f"invalid console entry point: {name}={target}")
            scripts[name] = (match.group("module"), match.group("callable"))
        if not scripts:
            raise InstallError("wheel contains no console entry points")
        return project, version, scripts, members


def _write_launchers(
    bin_dir: Path,
    lib_dir: Path,
    python: Path,
    scripts: dict[str, tuple[str, str]],
) -> None:
    bin_dir.mkdir(mode=0o755)
    for name, (module, callable_name) in scripts.items():
        launcher = bin_dir / name
        launcher.write_text(
            f"#!{python} -I\n"
            "import sys\n"
            f"sys.path.insert(0, {str(lib_dir)!r})\n"
            f"from {module} import {callable_name}\n"
            f"raise SystemExit({callable_name}())\n",
            encoding="utf-8",
        )
        launcher.chmod(0o755)


def _freeze_tree(root: Path, *, owner_root: bool) -> None:
    paths = [root, *root.rglob("*")]
    for path in paths:
        if path.is_symlink():
            raise InstallError(f"installed release unexpectedly contains a symlink: {path}")
        if owner_root:
            os.chown(path, 0, 0, follow_symlinks=False)
        if path.is_dir() or path.parent.name == "bin":
            path.chmod(0o555)
        else:
            path.chmod(0o444)


def _verify_imports(python: Path, lib_dir: Path, modules: set[str]) -> None:
    imports = ";".join(f"__import__({module!r})" for module in sorted(modules))
    code = f"import sys;sys.path.insert(0,{str(lib_dir)!r});{imports}"
    try:
        subprocess.run(  # noqa: S603 - validated absolute interpreter and import names
            [str(python), "-I", "-c", code],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise InstallError(f"installed package import verification failed: {exc}") from exc


def install_release(
    *,
    wheel: Path,
    expected_sha256: str,
    target: Path,
    python: Path,
    require_root: bool = True,
) -> str:
    if require_root and os.geteuid() != 0:
        raise InstallError("installer must run as root")
    if not SHA256_PATTERN.fullmatch(expected_sha256):
        raise InstallError("expected SHA-256 must be 64 lowercase hexadecimal characters")
    wheel = require_safe_absolute_path(wheel, label="wheel path")
    target = require_safe_absolute_path(target, label="installation target")
    if not wheel.is_file() or wheel.is_symlink():
        raise InstallError("wheel must be a regular non-symlink file")
    actual_sha256 = sha256_file(wheel)
    if actual_sha256 != expected_sha256:
        raise InstallError("wheel SHA-256 does not match the expected value")

    runtime = inspect_runtime(python)
    project, version, scripts, _ = inspect_wheel(wheel)
    release_id = f"{version}-{actual_sha256[:12]}"
    releases = target / "releases"
    final_release = releases / release_id

    target.mkdir(mode=0o755, parents=True, exist_ok=True)
    releases.mkdir(mode=0o755, exist_ok=True)
    for directory in (target, releases):
        if directory.is_symlink() or not directory.is_dir():
            raise InstallError(f"installation path is not a real directory: {directory}")
        if require_root:
            os.chown(directory, 0, 0)
        directory.chmod(0o755)

    if final_release.exists():
        try:
            installed = json.loads((final_release / "INSTALLATION.json").read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise InstallError(f"existing release cannot be verified: {exc}") from exc
        if installed.get("wheel_sha256") != actual_sha256:
            raise InstallError("existing release ID has different installation metadata")
    else:
        staging = Path(tempfile.mkdtemp(prefix=f".{release_id}.", dir=releases))
        try:
            lib_dir = staging / "lib"
            with zipfile.ZipFile(wheel) as archive:
                archive.extractall(lib_dir)
            _write_launchers(staging / "bin", final_release / "lib", python, scripts)
            installation = {
                "project": project,
                "version": version,
                "release_id": release_id,
                "wheel_sha256": actual_sha256,
                "python": runtime["python"],
                "pyyaml": runtime["pyyaml"],
                "entry_points": sorted(scripts),
            }
            (staging / "INSTALLATION.json").write_text(
                json.dumps(installation, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            _verify_imports(python, lib_dir, {module for module, _ in scripts.values()})
            _freeze_tree(staging, owner_root=require_root)
            staging.rename(final_release)
        except Exception:
            shutil.rmtree(staging, ignore_errors=True)
            raise

    current = target / "current"
    if current.exists() and not current.is_symlink():
        raise InstallError("current exists but is not a symlink")
    temporary_link = target / f".current.{os.getpid()}"
    try:
        temporary_link.symlink_to(Path("releases") / release_id)
        temporary_link.replace(current)
    finally:
        temporary_link.unlink(missing_ok=True)
    if require_root:
        os.lchown(current, 0, 0)
    return release_id


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Install a hash-verified wheel under /opt/haproxy-mgmt"
    )
    parser.add_argument("--wheel", required=True, type=Path)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--target", type=Path, default=DEFAULT_TARGET)
    parser.add_argument("--python", type=Path, default=DEFAULT_PYTHON)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        release_id = install_release(
            wheel=args.wheel,
            expected_sha256=args.sha256,
            target=args.target,
            python=args.python,
        )
    except InstallError as exc:
        print(f"install-release: ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"Installed HAProxy Manager release: {release_id}")
    print(f"Current: {args.target / 'current'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
