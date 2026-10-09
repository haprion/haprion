#!/usr/bin/env python3
"""Build the locked certbot environment into an immutable release directory.

    sudo /usr/bin/python3 tools/install-certbot-env.py \\
        --project certbot --uv /path/to/uv

Reads `certbot/pyproject.toml` and `certbot/uv.lock`, lets uv install exactly
that set - `--locked`, so a lock file that no longer matches the project is a
refusal, not a re-resolve - into `<target>/releases/<certbot version>-<lock
hash>/venv`, proves that every plugin in it loads and runs the catalogue's
mocked integration checks through the installed plugins, freezes the tree
root-owned and read-only, and only then points `<target>/current` at it. A release that is
already installed from the same lock is not rebuilt; the link is moved back to
it, which is the rollback.

The environment is one set on purpose. Nothing installs a plugin at runtime:
what the web interface can offer is what this lock resolved, and a plugin that
stops resolving against a newer certbot falls out of the lock, and so out of
the catalogue, at the next bump.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

DEFAULT_TARGET = Path("/opt/haprion-certbot")
DEFAULT_PYTHON = Path("/usr/bin/python3")
PROJECT_NAME = "haproxy-manager-certbot-env"
# The lock names certbot once, as a package; its version is the release's.
CERTBOT_VERSION = re.compile(r'^\[\[package\]\]\nname = "certbot"\nversion = "([^"]+)"', re.M)
SYNC_TIMEOUT = 900
VERIFY_TIMEOUT = 120


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


def require_executable(path: Path, *, label: str) -> Path:
    if not path.is_absolute() or not path.is_file() or not os.access(path, os.X_OK):
        raise InstallError(f"{label} must be an executable absolute file")
    return path


def inspect_project(project: Path) -> tuple[Path, str, str]:
    """The lock file, its hash and the certbot version it pins."""

    pyproject = project / "pyproject.toml"
    lock = project / "uv.lock"
    for path in (pyproject, lock):
        if not path.is_file() or path.is_symlink():
            raise InstallError(f"{path} must be a regular non-symlink file")
    if f'name = "{PROJECT_NAME}"' not in pyproject.read_text(encoding="utf-8"):
        raise InstallError(f"{pyproject} is not the {PROJECT_NAME} project")
    match = CERTBOT_VERSION.search(lock.read_text(encoding="utf-8"))
    if match is None:
        raise InstallError(f"{lock} does not pin certbot")
    return lock, sha256_file(lock), match.group(1)


#
# The proof that the environment is what the lock promised: every entry point
# certbot would discover loads, and every plugin distribution in the venv
# contributes at least one. `certbot plugins` does the same import; this asks
# without needing certbot's writable directories. The report goes to a file
# named on the command line, because a plugin is free to print on import - one
# does - and stdout is therefore not a channel.
#
VERIFY_CODE = """
import importlib.metadata as m, json, sys
loaded, failed, providers = [], [], set()
for ep in m.entry_points(group="certbot.plugins"):
    try:
        ep.load()
        loaded.append(ep.name)
        providers.add(ep.dist.name.lower().replace("_", "-"))
    except Exception as exc:  # noqa: BLE001 - the name of the failure is the report
        failed.append(f"{ep.name}: {type(exc).__name__}: {exc}")
silent = sorted(
    d.metadata["Name"].lower().replace("_", "-") for d in m.distributions()
    if d.metadata["Name"].lower().startswith("certbot-")
    and d.metadata["Name"].lower().replace("_", "-") not in providers
)
with open(sys.argv[1], "w") as out:
    json.dump({"loaded": sorted(loaded), "failed": failed, "silent": silent}, out)
"""


def verify_plugins(venv_python: Path, scratch: Path) -> list[str]:
    report_path = scratch / "plugins.json"
    try:
        subprocess.run(  # noqa: S603 - the release's own interpreter, fixed code
            [str(venv_python), "-I", "-W", "ignore", "-c", VERIFY_CODE, str(report_path)],
            check=True,
            capture_output=True,
            text=True,
            timeout=VERIFY_TIMEOUT,
        )
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except subprocess.CalledProcessError as exc:
        raise InstallError(f"plugin verification could not run: {exc.stderr.strip()}") from exc
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        raise InstallError(f"plugin verification could not run: {exc}") from exc
    finally:
        report_path.unlink(missing_ok=True)
    if report["failed"]:
        raise InstallError("plugins that do not load: " + "; ".join(report["failed"]))
    if report["silent"]:
        raise InstallError(
            "plugin packages that register no plugin: " + ", ".join(report["silent"])
        )
    if not report["loaded"]:
        raise InstallError("no certbot plugins at all were found")
    return list(report["loaded"])


def verify_integrations(venv_python: Path, project: Path, scratch: Path) -> list[str]:
    """Run catalogue-to-plugin checks inside the environment being installed."""

    verifier = project / "verify-integrations.py"
    if not verifier.is_file() or verifier.is_symlink():
        raise InstallError(f"{verifier} must be a regular non-symlink file")
    source_root = project.parent / "src"
    if not source_root.is_dir() or source_root.is_symlink():
        raise InstallError(f"{source_root} must be a real source directory")
    report_path = scratch / "integrations.json"
    try:
        completed = subprocess.run(  # noqa: S603 - locked interpreter and project verifier
            [str(venv_python), "-I", str(verifier), str(source_root), str(report_path)],
            check=False,
            capture_output=True,
            text=True,
            timeout=VERIFY_TIMEOUT,
        )
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        raise InstallError(f"integration verification could not run: {exc}") from exc
    finally:
        report_path.unlink(missing_ok=True)
    if (
        set(report) != {"passed", "failed"}
        or not isinstance(report["passed"], list)
        or not isinstance(report["failed"], list)
    ):
        raise InstallError("integration verification returned an invalid report")
    if completed.returncode or report["failed"]:
        detail = "; ".join(str(item) for item in report["failed"])
        raise InstallError("integration checks failed" + (f": {detail}" if detail else ""))
    if not report["passed"]:
        raise InstallError("integration verification ran no checks")
    return [str(item) for item in report["passed"]]


def _relocate_scripts(venv: Path, final_venv: Path) -> None:
    """The venv is built in a staging directory and renamed into place, and uv
    writes the staging path into every script's interpreter line - as a
    shebang, or as an `exec` header when the path is too long for one.
    Rewriting that path, in the scripts and nowhere else, is what makes the
    rename a move."""

    staging_path = str(venv)
    for script in (venv / "bin").iterdir():
        if script.is_symlink() or not script.is_file():
            continue
        try:
            text = script.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if staging_path in text:
            script.write_text(text.replace(staging_path, str(final_venv)), encoding="utf-8")


def _remove_tree(root: Path) -> None:
    """A tree that freezing left read-only comes off only after being opened."""

    for path in [root, *root.rglob("*")]:
        if path.is_dir() and not path.is_symlink():
            path.chmod(0o755)
    shutil.rmtree(root, ignore_errors=True)


def _freeze_tree(root: Path, *, python: Path, owner_root: bool) -> None:
    """Root-owned and read-only. A venv carries two kinds of symlink - bin/
    links to its interpreter, and lib64 to lib - and exactly those are allowed:
    an interpreter link must lead to the interpreter this release was built
    with or to a sibling in the same bin/, and lib64 must lead to lib."""

    venv = root / "venv"
    interpreter = python.resolve()
    for path in [root, *root.rglob("*")]:
        if path.is_symlink():
            target = Path(os.readlink(path))
            if path.parent == venv / "bin":
                allowed = (target.is_absolute() and path.resolve() == interpreter) or (
                    not target.is_absolute() and "/" not in str(target)
                )
            elif path == venv / "lib64":
                allowed = target == Path("lib")
            else:
                allowed = False
            if not allowed:
                raise InstallError(f"installed release unexpectedly contains a symlink: {path}")
            if owner_root:
                os.lchown(path, 0, 0)
            continue
        if owner_root:
            os.chown(path, 0, 0, follow_symlinks=False)
        if path.is_dir() or path.parent.name == "bin":
            path.chmod(0o555)
        else:
            path.chmod(0o444)


def _sync(uv: Path, project: Path, venv: Path, python: Path) -> None:
    environment = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(venv.parent),
        "UV_PROJECT_ENVIRONMENT": str(venv),
        "UV_PYTHON_DOWNLOADS": "never",
        "UV_NO_PROGRESS": "1",
    }
    command = [
        str(uv),
        "sync",
        "--locked",
        "--no-install-project",
        "--no-cache",
        "--python",
        str(python),
        "--project",
        str(project),
    ]
    try:
        subprocess.run(  # noqa: S603 - validated uv binary, fixed arguments
            command,
            check=True,
            capture_output=True,
            text=True,
            timeout=SYNC_TIMEOUT,
            env=environment,
        )
    except subprocess.CalledProcessError as exc:
        raise InstallError(f"uv sync failed:\n{exc.stderr.strip()}") from exc
    except (OSError, subprocess.SubprocessError) as exc:
        raise InstallError(f"uv sync could not run: {exc}") from exc


def install_environment(
    *,
    project: Path,
    uv: Path,
    target: Path,
    python: Path,
    require_root: bool = True,
) -> str:
    if require_root and os.geteuid() != 0:
        raise InstallError("installer must run as root")
    project = require_safe_absolute_path(project, label="project path")
    target = require_safe_absolute_path(target, label="installation target")
    uv = require_executable(uv, label="uv")
    python = require_executable(python, label="runtime Python")
    lock, lock_sha256, certbot_version = inspect_project(project)
    release_id = f"{certbot_version}-{lock_sha256[:12]}"
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
        if installed.get("lock_sha256") != lock_sha256:
            raise InstallError("existing release ID has different installation metadata")
    else:
        staging = Path(tempfile.mkdtemp(prefix=f".{release_id}.", dir=releases))
        try:
            venv = staging / "venv"
            _sync(uv, project, venv, python)
            plugins = verify_plugins(venv / "bin" / "python", staging)
            integrations = verify_integrations(venv / "bin" / "python", project, staging)
            _relocate_scripts(venv, final_release / "venv")
            installation = {
                "project": PROJECT_NAME,
                "certbot": certbot_version,
                "release_id": release_id,
                "lock_sha256": lock_sha256,
                "python": str(python),
                "uv_sha256": sha256_file(uv),
                "plugins": plugins,
                "integrations": integrations,
            }
            (staging / "INSTALLATION.json").write_text(
                json.dumps(installation, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            shutil.copyfile(lock, staging / "uv.lock")
            _freeze_tree(staging, python=python, owner_root=require_root)
            staging.rename(final_release)
        except Exception:
            _remove_tree(staging)
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
        description="Build the locked certbot environment under /opt/haprion-certbot"
    )
    parser.add_argument("--project", required=True, type=Path, help="directory with uv.lock")
    parser.add_argument("--uv", required=True, type=Path, help="the uv binary to build with")
    parser.add_argument("--target", type=Path, default=DEFAULT_TARGET)
    parser.add_argument("--python", type=Path, default=DEFAULT_PYTHON)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        release_id = install_environment(
            project=args.project.absolute(),
            uv=args.uv.absolute(),
            target=args.target,
            python=args.python,
        )
    except InstallError as exc:
        print(f"install-certbot-env: ERROR: {exc}", file=sys.stderr)
        return 1
    installed = json.loads((args.target / "current" / "INSTALLATION.json").read_text())
    print(f"Installed certbot environment: {release_id}")
    print(f"Plugins: {len(installed['plugins'])}")
    print(f"Current: {args.target / 'current'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
