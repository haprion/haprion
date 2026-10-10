#!/usr/bin/env python3
"""Build and inspect installable artifacts without writing inside the repository."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(*args: str, cwd: Path, env: dict[str, str] | None = None) -> None:
    subprocess.run(  # noqa: S603 - callers construct fixed local build and import commands
        args, check=True, cwd=cwd, env=env
    )


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="haprion-build-") as temporary:
        work = Path(temporary)
        source = work / "source"
        distributions = work / "dist"
        target = work / "site"
        shutil.copytree(
            ROOT,
            source,
            ignore=shutil.ignore_patterns(
                ".git",
                ".ruff_cache",
                ".coverage",
                "AGENTS.md",
                "CLAUDE.md",
                "__pycache__",
                "*.egg-info",
                "build",
                "dist",
            ),
        )
        run(
            sys.executable,
            "-m",
            "build",
            "--outdir",
            str(distributions),
            str(source),
            cwd=source,
        )

        wheels = list(distributions.glob("*.whl"))
        source_archives = list(distributions.glob("*.tar.gz"))
        if len(wheels) != 1 or len(source_archives) != 1:
            raise RuntimeError("build must create exactly one wheel and one source archive")

        with zipfile.ZipFile(wheels[0]) as wheel:
            names = set(wheel.namelist())
        required = {
            "haprion/__init__.py",
            "haprion/config.py",
            "haprion/envelope.py",
            "haprion/cli/cluster_config.py",
        }
        missing = required - names
        if missing:
            raise RuntimeError(f"wheel is missing package files: {', '.join(sorted(missing))}")
        if any("AGENTS.md" in name or "CLAUDE.md" in name for name in names):
            raise RuntimeError("wheel contains an internal agent instruction file")
        if not any(name.endswith(".dist-info/entry_points.txt") for name in names):
            raise RuntimeError("wheel is missing the console-script metadata")

        with tarfile.open(source_archives[0], "r:gz") as source_archive:
            source_names = source_archive.getnames()
        if any(
            Path(name).name in {"AGENTS.md", "CLAUDE.md"} or "/private/" in name
            for name in source_names
        ):
            raise RuntimeError("source archive contains internal-only files")

        run(
            sys.executable,
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--no-deps",
            "--target",
            str(target),
            str(wheels[0]),
            cwd=source,
        )
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(target)
        run(
            sys.executable,
            "-c",
            "import haprion; import haprion.cli.cluster_config",
            cwd=source,
            env=environment,
        )

    print("build smoke: OK (sdist, wheel, isolated wheel import)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
