#!/usr/bin/env python3
"""Install a verified Haprion wheel into an immutable release directory."""

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

DEFAULT_TARGET = Path("/opt/haprion")
DEFAULT_PYTHON = Path("/usr/bin/python3")
#
# How many releases stay on disk after a successful activation (B156). Ten is
# about a day of an intensive development day, and enough because a release is
# reproducible from its commit: both this wheel and the UI release are built
# from `git archive <commit>`, so removing an old directory loses nothing Git
# holds. The release just activated and the one it replaced are always kept,
# whatever the number - the rollback path must never be the one pruned.
#
DEFAULT_KEEP = 10
# Beside INSTALLATION.json in the release; `haproxy_mgmt.node_package` finds it there.
NODE_PACKAGE_NAME = "haprion-node.deb"
EXPECTED_PROJECT = "haprion"
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
VERSION_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]*")
ENTRY_POINT_PATTERN = re.compile(
    r"(?P<module>haproxy_mgmt(?:\.[a-z_][a-z0-9_]*)*):(?P<callable>[a-z_][a-z0-9_]*)"
)
SCRIPT_NAME_PATTERN = re.compile(r"haprion-[a-z0-9-]+")


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
        "'pyyaml':importlib.metadata.version('PyYAML'),"
        "'pynacl':importlib.metadata.version('PyNaCl'),"
        "'psycopg':importlib.metadata.version('psycopg')}))"
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
        raise InstallError(f"runtime Python/PyYAML/PyNaCl/psycopg probe failed: {exc}") from exc
    if not isinstance(result, dict) or not all(
        isinstance(result.get(key), str) for key in ("python", "pyyaml", "pynacl", "psycopg")
    ):
        raise InstallError("runtime Python/PyYAML/PyNaCl/psycopg probe returned invalid data")
    python_version = tuple(int(part) for part in result["python"].split("."))
    yaml_major = int(result["pyyaml"].split(".", maxsplit=1)[0])
    if python_version < (3, 12, 0):
        raise InstallError("runtime Python must be version 3.12 or newer")
    if yaml_major != 6:
        raise InstallError("runtime PyYAML must be major version 6")
    #
    # PyNaCl seals DNS provider credentials between the web and the root
    # helper (B146). The distribution's python3-nacl, like its PyYAML: the
    # release runs on the system interpreter and carries no packages of its
    # own. Its absence is named here, before anything is unpacked.
    #
    nacl_major = int(result["pynacl"].split(".", maxsplit=1)[0])
    if nacl_major != 1:
        raise InstallError("runtime PyNaCl must be major version 1")
    psycopg_major = int(result["psycopg"].split(".", maxsplit=1)[0])
    if psycopg_major != 3:
        raise InstallError("runtime psycopg must be major version 3")
    return {
        "python": result["python"],
        "pyyaml": result["pyyaml"],
        "pynacl": result["pynacl"],
        "psycopg": result["psycopg"],
    }


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
            raise InstallError("wheel project name is not haprion")
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


def inspect_engine_api(wheel: Path) -> int:
    """Read the engine's compatibility level without importing untrusted wheel code.

    A wheel without the file is refused: the compatibility check could only
    report it as older than every UI, so it is no release to install.
    """

    member = "haproxy_mgmt/compatibility.json"
    try:
        with zipfile.ZipFile(wheel) as archive:
            if member not in archive.namelist():
                raise InstallError("wheel carries no engine compatibility metadata")
            document = json.loads(archive.read(member))
    except (OSError, zipfile.BadZipFile, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise InstallError(f"invalid engine compatibility metadata: {exc}") from exc
    if (
        not isinstance(document, dict)
        or document.get("schema_version") != 1
        or type(document.get("engine_api")) is not int
        or document["engine_api"] < 1
    ):
        raise InstallError("invalid engine compatibility metadata")
    return int(document["engine_api"])


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


def _verify_node_package(
    python: Path, lib_dir: Path, package: Path, expected: str
) -> dict[str, str]:
    """Verify the node package with the release's own verifier; answer its version and commit.

    The wheel just extracted is the code that will later send this package to a
    restored node, so it is also the code that judges it now - one verifier,
    not a second copy in this installer.
    """

    code = (
        "import json,sys;"
        f"sys.path.insert(0,{str(lib_dir)!r});"
        "from pathlib import Path;"
        "from haproxy_mgmt.node_package import verify_package;"
        "facts=verify_package(Path(sys.argv[1]),sys.argv[2]);"
        "print(json.dumps({'version':facts.version,'commit':facts.commit}))"
    )
    try:
        completed = subprocess.run(  # noqa: S603 - validated interpreter, fixed code
            [str(python), "-I", "-c", code, str(package), expected],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        facts = json.loads(completed.stdout)
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or "").strip().splitlines()[-1:] or ["no detail"]
        raise InstallError(f"node package verification failed: {detail[0]}") from exc
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        raise InstallError(f"node package verification failed: {exc}") from exc
    return {"version": str(facts["version"]), "commit": str(facts["commit"]), "sha256": expected}


def install_release(
    *,
    wheel: Path,
    expected_sha256: str,
    target: Path,
    python: Path,
    require_root: bool = True,
    keep: int = DEFAULT_KEEP,
    node_package: Path | None = None,
    node_package_sha256: str | None = None,
) -> str:
    if require_root and os.geteuid() != 0:
        raise InstallError("installer must run as root")
    if keep < 2:
        raise InstallError("at least two releases must be kept: the new one and its predecessor")
    if not SHA256_PATTERN.fullmatch(expected_sha256):
        raise InstallError("expected SHA-256 must be 64 lowercase hexadecimal characters")
    wheel = require_safe_absolute_path(wheel, label="wheel path")
    target = require_safe_absolute_path(target, label="installation target")
    if not wheel.is_file() or wheel.is_symlink():
        raise InstallError("wheel must be a regular non-symlink file")
    actual_sha256 = sha256_file(wheel)
    if actual_sha256 != expected_sha256:
        raise InstallError("wheel SHA-256 does not match the expected value")
    #
    # The node package built from the same commit (B180, B266). A node restore
    # installs exactly this one, so a CLI rollback takes the package back with
    # it. Optional, so a wheel installed without one stays installable for
    # rollback; a release without one refuses to restore a node and says why.
    #
    if (node_package is None) != (node_package_sha256 is None):
        raise InstallError("a node package needs both its path and its SHA-256")
    if node_package is not None:
        node_package = require_safe_absolute_path(node_package, label="node package path")
        if not node_package.is_file() or node_package.is_symlink():
            raise InstallError("node package must be a regular non-symlink file")
        if not SHA256_PATTERN.fullmatch(node_package_sha256 or ""):
            raise InstallError("node package SHA-256 must be 64 lowercase hexadecimal characters")
        if sha256_file(node_package) != node_package_sha256:
            raise InstallError("node package SHA-256 does not match the expected value")

    runtime = inspect_runtime(python)
    project, version, scripts, _ = inspect_wheel(wheel)
    engine_api = inspect_engine_api(wheel)
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
        carried = (installed.get("node_package") or {}).get("sha256")
        if carried != node_package_sha256:
            raise InstallError(
                "this release is already installed with "
                + (f"node package {carried[:12]}" if carried else "no node package")
                + "; a release is not changed in place"
            )
    else:
        staging = Path(tempfile.mkdtemp(prefix=f".{release_id}.", dir=releases))
        try:
            lib_dir = staging / "lib"
            with zipfile.ZipFile(wheel) as archive:
                archive.extractall(lib_dir)
            _write_launchers(staging / "bin", final_release / "lib", python, scripts)
            package_facts = None
            if node_package is not None and node_package_sha256 is not None:
                package_facts = _verify_node_package(
                    python, lib_dir, node_package, node_package_sha256
                )
                shutil.copyfile(node_package, staging / NODE_PACKAGE_NAME)
            installation = {
                "project": project,
                "version": version,
                "release_id": release_id,
                "wheel_sha256": actual_sha256,
                "python": runtime["python"],
                "pyyaml": runtime["pyyaml"],
                "pynacl": runtime["pynacl"],
                "psycopg": runtime["psycopg"],
                "entry_points": sorted(scripts),
                "engine_api": engine_api,
            }
            if package_facts is not None:
                installation["node_package"] = {"file": NODE_PACKAGE_NAME, **package_facts}
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
    previous_id = Path(os.readlink(current)).name if current.is_symlink() else None
    temporary_link = target / f".current.{os.getpid()}"
    try:
        temporary_link.symlink_to(Path("releases") / release_id)
        temporary_link.replace(current)
    finally:
        temporary_link.unlink(missing_ok=True)
    if require_root:
        os.lchown(current, 0, 0)
    #
    # Only now, after the link moved: a new release has been added, and a
    # failed activation is exactly when nothing may be removed.
    #
    prune_releases(releases, keep=keep, always={release_id, previous_id})
    return release_id


def prune_releases(releases: Path, *, keep: int, always: set[str | None]) -> list[str]:
    """Remove all but the `keep` newest release directories; answer what went.

    Newest by modification time, not by name: a release id ends in a commit
    hash, which sorts alphabetically and says nothing about when it was built.
    Names in `always` stay whatever their age. A directory that cannot be
    removed is left and reported, never fatal - the release is installed.
    """

    candidates = sorted(
        (path for path in releases.iterdir() if path.is_dir() and not path.name.startswith(".")),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    removed: list[str] = []
    for path in candidates[keep:]:
        if path.name in always:
            continue
        try:
            for directory in [path, *(p for p in path.rglob("*") if p.is_dir())]:
                directory.chmod(0o700)
            shutil.rmtree(path)
        except OSError as exc:
            print(f"install-release: WARNING: could not remove {path}: {exc}", file=sys.stderr)
            continue
        removed.append(path.name)
    return removed


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Install a hash-verified wheel under /opt/haprion")
    parser.add_argument("--wheel", required=True, type=Path)
    parser.add_argument("--sha256", required=True)
    parser.add_argument(
        "--node-package",
        type=Path,
        help="the node package built from the same commit (tools/node-package.py build)",
    )
    parser.add_argument("--node-package-sha256")
    parser.add_argument("--target", type=Path, default=DEFAULT_TARGET)
    parser.add_argument("--python", type=Path, default=DEFAULT_PYTHON)
    parser.add_argument(
        "--keep",
        type=int,
        default=DEFAULT_KEEP,
        help=f"releases left on disk after activation (default {DEFAULT_KEEP}; "
        "the new release and its predecessor always stay)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        release_id = install_release(
            wheel=args.wheel,
            expected_sha256=args.sha256,
            target=args.target,
            python=args.python,
            keep=args.keep,
            node_package=args.node_package,
            node_package_sha256=args.node_package_sha256,
        )
    except InstallError as exc:
        print(f"install-release: ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"Installed Haprion release: {release_id}")
    print(f"Current: {args.target / 'current'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
