#!/usr/bin/env python3
"""The gate runs on the versions in toolchain.json, here and on GitHub alike (B494).

Python 3.14 is Ubuntu 26.04's (the installations', and here its own
/usr/bin/python3.14); 3.13 a build that has what the product calls, since
uv's build of Debian's 3.13.5 has neither `os.memfd_create` nor
`os.getrandom` (measured 26-11-07) - the installation test runs Debian's own.
git is the one the distribution the manager and the runner both are ships. Without the pins the two sides drifted apart: the
runner image brought git 2.56 and a newer Python patch while this machine had
the distribution's, and a test that passed here failed only there (26-11-07).
A version that moves is now a refusal that names both, and changing the pin
is a commit.

    check_toolchain.py [--ui-python <path>]

The Python checked is the one running this script (the engine environment's,
first on PATH in the gate); `--ui-python` is the interface environment's and
must be the same version.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
PINS = BASE / "toolchain.json"
GIT_VERSION = re.compile(r"^git version (\d+\.\d+\.\d+)\b")


def load(path: Path = PINS) -> tuple[tuple[str, ...], str]:
    """The pinned Pythons and git, or ValueError naming what is wrong with the file."""

    document = json.loads(path.read_text(encoding="utf-8"))
    pythons = document.get("python")
    git = document.get("git")
    if (
        document.get("schema_version") != 1
        or not isinstance(pythons, list)
        or not pythons
        or not all(
            isinstance(item, str) and re.fullmatch(r"\d+\.\d+\.\d+", item) for item in pythons
        )
        or len({item.rsplit(".", 1)[0] for item in pythons}) != len(pythons)
        or not isinstance(git, str)
        or not re.fullmatch(r"\d+\.\d+\.\d+", git)
    ):
        raise ValueError(
            f"{path.name}: python must list one x.y.z per minor version and git one x.y.z"
        )
    return tuple(pythons), git


def git_version(output: str) -> str | None:
    found = GIT_VERSION.match(output.strip())
    return found.group(1) if found else None


#
# What the product calls that a Python built against old headers lacks: the
# certificate export's sealed files and the standard library's own randomness
# (which then holds /dev/urandom open). A build without them is refused by name.
#
REQUIRED_CALLS = ("memfd_create", "getrandom")


def problems(
    pythons: Sequence[str],
    git: str,
    *,
    running: str,
    ui: str | None,
    found_git: str | None,
    missing: Sequence[str] = (),
) -> list[str]:
    """What differs from the pins, each as one sentence; empty when nothing does."""

    said: list[str] = []
    if missing:
        said.append(
            f"this Python {running} has no os.{', os.'.join(missing)}: another build is needed"
        )
    if running not in pythons:
        said.append(f"Python {running} runs the gate; {PINS.name} pins {', '.join(pythons)}")
    if ui is not None and ui != running:
        said.append(f"the interface environment runs Python {ui}, the engine's {running}")
    if found_git != git:
        said.append(f"git {found_git or 'that cannot be read'} is on PATH; {PINS.name} pins {git}")
    return said


def _python_of(executable: str) -> str:
    done = subprocess.run(  # noqa: S603 - the interface environment's own python
        [executable, "-c", "import platform; print(platform.python_version())"],
        capture_output=True,
        text=True,
        check=True,
    )
    return done.stdout.strip()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="check_toolchain.py")
    parser.add_argument("--ui-python")
    args = parser.parse_args(argv)
    try:
        pythons, git = load()
    except (OSError, ValueError) as exc:
        print(f"toolchain: {exc}", file=sys.stderr)
        return 2
    running = ".".join(str(part) for part in sys.version_info[:3])
    ui = _python_of(args.ui_python) if args.ui_python else None
    try:
        output = subprocess.run(
            ["git", "--version"],  # noqa: S607 - the git the gate's tests run
            capture_output=True,
            text=True,
            check=False,
        ).stdout
    except OSError:
        output = ""
    missing = [name for name in REQUIRED_CALLS if not hasattr(os, name)]
    found = problems(
        pythons, git, running=running, ui=ui, found_git=git_version(output), missing=missing
    )
    if found:
        for sentence in found:
            print(f"toolchain: {sentence}", file=sys.stderr)
        print(
            f"toolchain: the gate runs on the versions in {PINS.name}; install those, "
            "or change the pins in a commit of their own",
            file=sys.stderr,
        )
        return 2
    print(f"toolchain: Python {running}, git {git} ({PINS.name})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
