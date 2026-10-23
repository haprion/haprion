#!/usr/bin/env python3
"""Build `haprion-archive-keyring`, the key the apt repository is signed with (B325).

    /usr/share/keyrings/haprion-archive-keyring.asc   keys/haprion-archive.asc

An installation's source names this file in `Signed-By`, so apt trusts the
key for this repository and for no other. The key is a primary key, kept
offline, with a signing subkey that CI holds and that expires; a renewed or
replaced subkey reaches every installation as a new version of this package,
signed by the subkey it replaces, before that one expires. The first
installation fetches the same file from the repository's site, and the
package then takes it over.

The version is the key's: it names the day the key file last changed, and
the file's digest is pinned beside it, so a new key without a new version -
which apt would never install - stops the build.
"""

from __future__ import annotations

import argparse
import hashlib
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from haprion.debian_package import package, write  # the path above comes first

PACKAGE = "haprion-archive-keyring"
KEY_FILE = "keys/haprion-archive.asc"
TARGET = "usr/share/keyrings/haprion-archive-keyring.asc"
VERSION = "2026.10.17"
PINNED_SHA256 = "f2b9eb89ed1db258340f82233cfba3658723f78067359d75a243e2d3ddc5fa09"
COPYRIGHT = """\
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: haprion

Files: *
Copyright: haprion maintainers
License: public-domain
 The public key of the haprion apt repository.
"""


class KeyringError(RuntimeError):
    """A keyring package that cannot be built."""


def _git(source: Path, *arguments: str) -> bytes:
    return subprocess.run(  # noqa: S603 - fixed executable and internal git arguments
        ["/usr/bin/git", "-C", str(source), *arguments],
        check=True,
        capture_output=True,
        timeout=30,
    ).stdout


def build(source: Path, output_dir: Path) -> Path:
    source = source.resolve(strict=True)
    commit = _git(source, "rev-parse", "HEAD").decode().strip()
    key = _git(source, "show", f"{commit}:{KEY_FILE}")
    if hashlib.sha256(key).hexdigest() != PINNED_SHA256:
        raise KeyringError(f"{KEY_FILE} changed; give the package a new VERSION and PINNED_SHA256")
    epoch = int(_git(source, "log", "-1", "--format=%ct", commit, "--", KEY_FILE).decode().strip())
    output_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="haprion-keyring-package-") as directory:
        root = Path(directory) / "root"
        write(root, TARGET, key, 0o644)
        write(root, f"usr/share/doc/{PACKAGE}/copyright", COPYRIGHT.encode(), 0o644)
        return package(
            root,
            {
                "Package": PACKAGE,
                "Version": VERSION,
                "Architecture": "all",
                "Section": "misc",
                "Priority": "optional",
                "Description": "Haprion apt repository key\n"
                " The OpenPGP key the haprion apt repository is signed with, for the\n"
                " Signed-By line of the source that names the repository.",
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
    args = parser.parse_args()
    try:
        target = build(args.source, args.output_dir)
    except (KeyringError, OSError, ValueError, subprocess.CalledProcessError) as exc:
        parser.exit(1, f"keyring package build failed: {exc}\n")
    print(f"{hashlib.sha256(target.read_bytes()).hexdigest()}  {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
