"""Reproducible Debian packages from a tree, shared by the package builders.

The tree is normalised - directories 0755, every time clamped to one epoch, no
symlinks - and dpkg-deb builds it with root as owner and SOURCE_DATE_EPOCH set,
so the same tree gives the same bytes. Build twice and compare.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path

MAINTAINER = "haprion maintainers <maintainers@example.org>"
FIELD_ORDER = (
    "Package",
    "Version",
    "Architecture",
    "Maintainer",
    "Installed-Size",
    "Depends",
    "Recommends",
    "Suggests",
    "Conflicts",
    "Replaces",
    "Section",
    "Priority",
    "Homepage",
    "Description",
)


def write(root: Path, relative: str, data: bytes, mode: int) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(mode)


def control(fields: dict[str, str], root: Path) -> bytes:
    unknown = set(fields) - set(FIELD_ORDER)
    if unknown:
        raise ValueError(f"unknown control fields: {', '.join(sorted(unknown))}")
    size = sum(p.stat().st_size for p in root.rglob("*") if p.is_file() and "DEBIAN" not in p.parts)
    fields = {**fields, "Maintainer": MAINTAINER, "Installed-Size": str(-(-size // 1024))}
    return "".join(f"{name}: {fields[name]}\n" for name in FIELD_ORDER if name in fields).encode()


def package(root: Path, fields: dict[str, str], output_dir: Path, epoch: int) -> Path:
    """Normalise the tree and let dpkg-deb build it; same tree, same bytes."""
    sums = []
    for path in sorted(p for p in root.rglob("*") if p.is_file() and "DEBIAN" not in p.parts):
        relative = path.relative_to(root).as_posix()
        sums.append(f"{hashlib.md5(path.read_bytes()).hexdigest()}  {relative}\n")  # noqa: S324 - dpkg's md5sums format
    write(root, "DEBIAN/md5sums", "".join(sums).encode(), 0o644)
    write(root, "DEBIAN/control", control(fields, root), 0o644)
    for path in [root, *root.rglob("*")]:
        if path.is_symlink():
            raise ValueError("a package tree must not hold symlinks")
        if path.is_dir():
            path.chmod(0o755)
        os.utime(path, (epoch, epoch))
    name = f"{fields['Package']}_{fields['Version']}_{fields['Architecture']}.deb"
    target = output_dir / name
    if target.exists():
        raise ValueError(f"{target} exists; move it aside first")
    subprocess.run(  # noqa: S603 - fixed builder, generated tree
        [
            "/usr/bin/dpkg-deb",
            "--root-owner-group",
            "-Zxz",
            "-z9",
            "--build",
            str(root),
            str(target),
        ],
        check=True,
        capture_output=True,
        env={"PATH": "/usr/bin:/bin", "SOURCE_DATE_EPOCH": str(epoch), "LC_ALL": "C"},
        timeout=300,
    )
    return target
