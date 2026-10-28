#!/usr/bin/env python3
"""Build the SCEP client package, `haprion-scep`, for one distribution (B381, B383, 26-10-28).

NDES enrolment runs Certmonger's own programs from a bundle
(`tools/build-scep-client.py`): the distribution's certmonger package, its
complete source, and the three programs taken from it. The package carries
that bundle, so a new installation has the client without a hand-built file
(F31), and an update brings a new one.

    /usr/lib/haprion/scep/   the bundle and PAYLOAD, which names it with its digest

The inputs are pinned below by version and SHA-256 for each distribution, as
the WAF engine's are: the archive's newest certmonger would make two builds of
one commit differ, and the published packages are compared byte for byte with
the release's (B325). A pin is taken where apt has checked the archive's signed
index - in a container of the distribution, `apt-get download certmonger` and
`apt-get source --download-only certmonger` - and the build fetches exactly
those files from the archive's pool and refuses any other bytes. When the
archive drops a pinned version, the build fails here and the pin is moved.

`postinst` installs the bundle with step 16 where the client is already
installed (`/opt/haprion-scep/current`), so an update brings the new one; on a
first installation it only says so, and `haprion-setup` runs step 16. The
package depends on what Certmonger's own package depends on, so apt installs the
libraries before step 16 runs; nothing calls apt from inside dpkg.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from haprion import node_package  # the path above comes first
from haprion.debian_package import package, write


def _load(name: str, filename: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    if spec is None or spec.loader is None:
        raise SystemExit(f"build-scep-package: {filename} is not beside it")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ui = _load("build_ui_package", "build-ui-package.py")
client = _load("build_scep_client", "build-scep-client.py")

PACKAGE = "haprion-scep"
LIB = "usr/lib/haprion/scep"
ROOT = "/opt/haprion-scep"
STEP = "/usr/share/haprion-ui/install/platform/16-platform-scep"
MAX_BYTES = 16 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class Pin:
    """One distribution's certmonger: its package and its complete source, by digest."""

    distribution: str
    release: str
    pool: str
    version: str
    deb: str
    dsc: str
    orig: tuple[str, str]
    debian: tuple[str, str]


#
# Taken 26-10-28 in containers of each distribution, from apt's own download
# after it checked the archive's signed index.
#
PINS = {
    "ubuntu26.04": Pin(
        "ubuntu",
        "26.04",
        "https://archive.ubuntu.com/ubuntu/pool/universe/c/certmonger/",
        "0.79.21-1",
        "75180fdc2eef1d94f1dfe63703671ed599fe58b654257fb8a792153481ec842e",
        "19e98e6ed2a0cb1693a4278fe821f9b380b7bc5c7c668a49064485da392d2624",
        (
            "certmonger_0.79.21.orig.tar.gz",
            "4674649d087496bb2868f0b4c5859a62e39fc4e31cec5795a76f41530cdc5196",
        ),
        (
            "certmonger_0.79.21-1.debian.tar.xz",
            "a0dccbebedd79319cf5e1f20a42ac689b0e5b84370c06d8966f359f5705e436d",
        ),
    ),
    "debian13": Pin(
        "debian",
        "13",
        "https://deb.debian.org/debian/pool/main/c/certmonger/",
        "0.79.20-2",
        "73ff5228a97e5f67a8656c4a1406a9926c9c74b4106c477f555cdd7d7fb1165a",
        "e15228ab410391ac188e70a1d0bec80ba3f987ef677ecba86a6a48de6e4569f3",
        (
            "certmonger_0.79.20.orig.tar.gz",
            "23645a5c1b284d73df448dbb97366c1b6e639223fc9465e7834fa5c5fef3f01e",
        ),
        (
            "certmonger_0.79.20-2.debian.tar.xz",
            "483fbb139734b29568fe4a9b64913a103d7115b4cb34cfeb09621c04d7ec8eea",
        ),
    ),
}
#
# The bundle's digest is checked by step 16's installer, which refuses any other
# bytes. A failed install leaves the previous client current and is said; it does
# not fail the package, which the interface depends on.
#
POSTINST = f"""\
#!/bin/sh
set -e
if [ "$1" = configure ]; then
    . /{LIB}/PAYLOAD
    if [ -L {ROOT}/current ] && [ -x {STEP} ]; then
        if ! {STEP} "/{LIB}/$BUNDLE" "$BUNDLE_SHA256" --no-satisfy; then
            echo "haprion-scep: WARNING: the SCEP client $BUNDLE was not installed; the reason is above" >&2
            echo "haprion-scep: the previous client stays current" >&2
            echo "haprion-scep: when the cause is fixed: sudo {STEP} /{LIB}/$BUNDLE $BUNDLE_SHA256 --no-satisfy" >&2
        fi
    else
        echo "haprion-scep: the SCEP client $BUNDLE is in /{LIB}"
        echo "haprion-scep: haprion-setup installs it"
    fi
fi
"""
#
# The releases are the installer's, as certbot's are; purge removes them. The
# NDES profiles and requests under /etc/haprion are the manager's.
#
POSTRM = f"""\
#!/bin/sh
set -e
if [ "$1" = purge ]; then
    rm -rf {ROOT}
fi
"""


def fetch(url: str, digest: str) -> bytes:
    with urllib.request.urlopen(url, timeout=120) as response:  # noqa: S310 - pinned https pool
        data: bytes = response.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ui.BuildError(f"{url} is larger than {MAX_BYTES} bytes")
    if hashlib.sha256(data).hexdigest() != digest:
        raise ui.BuildError(f"{url} is not the pinned file (SHA-256 differs)")
    return data


def inputs(pin: Pin, directory: Path) -> tuple[Path, Path]:
    """The pinned package and source, fetched and checked, under their archive names."""

    deb = directory / f"certmonger_{pin.version}_amd64.deb"
    dsc = directory / f"certmonger_{pin.version}.dsc"
    deb.write_bytes(fetch(pin.pool + deb.name, pin.deb))
    dsc.write_bytes(fetch(pin.pool + dsc.name, pin.dsc))
    for name, digest in (pin.orig, pin.debian):
        (directory / name).write_bytes(fetch(pin.pool + name, digest))
    return deb, dsc


def build(source: Path, output_dir: Path, distribution: str) -> Path:
    target, pin = ui.DISTRIBUTIONS[distribution], PINS[distribution]
    source = source.resolve(strict=True)
    commit = node_package.source_commit(source)
    output_dir.mkdir(parents=True, exist_ok=True)
    epoch = int(ui._git(source, "show", "-s", "--format=%ct", commit).decode().strip())
    version = node_package.version_for(pin.version.split("-", 1)[0], epoch, commit)
    with tempfile.TemporaryDirectory(prefix="haprion-scep-package-") as raw:
        work = Path(raw)
        fetched = work / "in"
        fetched.mkdir()
        deb, dsc = inputs(pin, fetched)
        name = f"certmonger-{pin.version}-{pin.distribution}-{pin.release}-amd64.zip"
        bundle = work / name
        digest, checked = client.build(
            package=deb,
            package_sha256=pin.deb,
            source_description=dsc,
            source_sha256=pin.dsc,
            distribution=pin.distribution,
            distribution_release=pin.release,
            output=bundle,
            query=client.osv_query,
        )
        print(checked, file=sys.stderr)
        depends = client.package_field(deb, "Depends")
        root = work / "root"
        write(root, f"{LIB}/{name}", bundle.read_bytes(), 0o644)
        write(
            root,
            f"{LIB}/PAYLOAD",
            f"BUNDLE={name}\nBUNDLE_SHA256={digest}\n".encode(),
            0o644,
        )
        write(
            root,
            "usr/share/doc/haprion-scep/copyright",
            node_package.COPYRIGHT_HEADER + ui._git(source, "show", f"{commit}:LICENSE"),
            0o644,
        )
        write(
            root,
            "usr/share/doc/haprion-scep/BUILD",
            f"commit: {commit}\ncertmonger: {pin.version} ({pin.distribution} {pin.release})\n"
            f"bundle_sha256: {digest}\n".encode(),
            0o644,
        )
        write(root, "DEBIAN/postinst", POSTINST.encode(), 0o755)
        write(root, "DEBIAN/postrm", POSTRM.encode(), 0o755)
        return package(
            root,
            {
                "Package": PACKAGE,
                "Version": f"{version}{target.suffix}",
                "Architecture": "amd64",
                "Depends": f"python3, {depends}",
                "Section": "net",
                "Priority": "optional",
                "Description": "Haprion's SCEP client for NDES\n"
                f" Certmonger {pin.version}'s programs from the distribution's package, with its\n"
                " complete source, installed under /opt/haprion-scep without a system\n"
                " Certmonger service.",
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
    parser.add_argument("--distribution", choices=sorted(PINS), required=True)
    args = parser.parse_args()
    try:
        built = build(args.source, args.output_dir, args.distribution)
    except (ui.BuildError, node_package.PackageError, ValueError, OSError) as exc:
        parser.exit(1, f"package build failed: {exc}\n")
    except subprocess.CalledProcessError as exc:
        parser.exit(1, f"package build failed: {exc}\n")
    print(json.dumps({"package": str(built), "sha256": ui.sha256(built)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
