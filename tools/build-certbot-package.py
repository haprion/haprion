#!/usr/bin/env python3
"""Build the certbot package, `haprion-certbot`, for one distribution (B322, 26-10-17).

Certbot runs from the locked environment `certbot/uv.lock` names - certbot and
every DNS plugin the interface offers - and a virtual environment is bound to
one Python and to its path, as the interface's is. So it is built the same way
(`build-ui-package.py`): inside a container of the distribution, at its final
path `/opt/haprion-certbot/releases/<certbot version>-<lock hash>`, by the same
`tools/install-certbot-env.py` that builds it on a manager, which proves every
plugin loads and runs the catalogue's checks before it freezes the tree. `uv`
and the network to PyPI are needed here, and nowhere a package is installed.

    /usr/lib/haprion/certbot/   the release archive and PAYLOAD, which names it
                                with its digest

`postinst` unpacks the release after checking the archive's digest. On a
manager whose certbot is already set up (step 14 has installed the renewal
timer), it then runs step 14, which makes the release current only after a
dry-run renewal of every lineage with it, and puts the previous one back when
that fails - the gate a certbot upgrade has always had. A failed gate is said and
does not fail the package: the dry run asks Let's Encrypt's staging server, and
the network or staging being down left `haprion-certbot` unconfigured and, since
the interface depends on it, `haprion-ui` too (review 2026-10-22, 6-7). The
previous release keeps renewing. On a first installation it only unpacks;
`haprion-setup` runs step 14.

The certbot version is the package's upstream version; the commit names the
lock it was built from.
"""

from __future__ import annotations

import argparse
import importlib.util
import io
import json
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from haprion import node_package  # the path above comes first
from haprion.debian_package import package, write

_spec = importlib.util.spec_from_file_location(
    "build_ui_package", Path(__file__).with_name("build-ui-package.py")
)
if _spec is None or _spec.loader is None:
    raise SystemExit("build-certbot-package: build-ui-package.py is not beside it")
ui = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = ui
_spec.loader.exec_module(ui)

PACKAGE = "haprion-certbot"
LIB = "usr/lib/haprion/certbot"
ROOT = "/opt/haprion-certbot"
STEP = "/usr/share/haprion-ui/install/platform/14-platform-certbot"
TIMER = "/etc/systemd/system/haprion-certbot-renew.timer"
SERVICE = "/etc/systemd/system/haprion-certbot-renew.service"
HOOK = "/etc/letsencrypt/renewal-hooks/deploy/50-haprion"
CERTBOT_VERSION = re.compile(r'^\[\[package\]\]\nname = "certbot"\nversion = "([^"]+)"', re.M)
#
# Runs inside the container, as its root. The source is mounted read-only and
# copied, as the interface's build does.
#
BUILD = r"""#!/bin/sh
set -eu
export DEBIAN_FRONTEND=noninteractive UV_CACHE_DIR=/uv-cache
apt-get update -qq >/dev/null
apt-get install -y -qq --no-install-recommends python3 ca-certificates >/dev/null
cp -a /src-ro /src
python3 /src/tools/install-certbot-env.py --project /src/certbot --uv /uv --target /opt/haprion-certbot
R="$(readlink -f /opt/haprion-certbot/current)"
tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner \
    --pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime \
    -cf /out/release.tar -C / "${R#/}"
echo "${R##*/}" > /out/RELEASE_ID
"""
#
# Its digest is checked first: PAYLOAD came in the same package, and a damaged
# archive must stop here. The release is unpacked beside the others and renamed
# into place, so a half-unpacked one is never there to be made current.
#
POSTINST = f"""\
#!/bin/sh
set -e
if [ "$1" = configure ]; then
    . /{LIB}/PAYLOAD
    release="{ROOT}/releases/$RELEASE_ID"
    if [ ! -d "$release" ]; then
        echo "$RELEASE_SHA256  /{LIB}/$RELEASE_ARCHIVE" | sha256sum --check --quiet
        mkdir -p {ROOT}/releases
        # A failed tar under set -e left its directory; dpkg's lock means no
        # live run owns one now (review 26-10-24, 03-09).
        rm -rf {ROOT}/.unpack.*
        unpack="$(mktemp -d {ROOT}/.unpack.XXXXXX)"
        tar -xf "/{LIB}/$RELEASE_ARCHIVE" -C "$unpack"
        mv -T "$unpack{ROOT}/releases/$RELEASE_ID" "$release"
        rm -rf "$unpack"
    fi
    if [ "$(readlink {ROOT}/current || true)" = "releases/$RELEASE_ID" ]; then
        echo "haprion-certbot: release $RELEASE_ID is already current"
    elif [ -f {TIMER} ] && [ -x {STEP} ]; then
        if ! {STEP} -; then
            echo "haprion-certbot: WARNING: release $RELEASE_ID was not made current; the reason is above" >&2
            echo "haprion-certbot: the previous environment keeps renewing" >&2
            echo "haprion-certbot: when the cause is fixed: sudo {STEP} -" >&2
        fi
    else
        echo "haprion-certbot: release $RELEASE_ID is prepared in $release"
        echo "haprion-certbot: haprion-setup makes it current"
    fi
fi
"""
#
# Removed with the environment it renews with: the renewal timer, which would
# fail twice a day without it, and the deploy hook step 14 installed. The
# distribution's certbot.timer, which step 14 masked, is given back, so a
# certbot used for anything else keeps renewing (review 26-10-24, 14-08). The
# timer's and service's files go too: "the timer is there" is how this
# package's postinst and the interface's update tell that step 14 has run, and
# a reinstall found it there, put the hook back and left the renewal off
# (review 26-10-25, 3-02). An upgrade removes nothing.
#
PRERM = f"""\
#!/bin/sh
set -e
if [ "$1" = remove ]; then
    rm -f {HOOK}
    if [ -d /run/systemd/system ]; then
        systemctl disable --now haprion-certbot-renew.timer >/dev/null 2>&1 || true
    fi
    rm -f {TIMER} {SERVICE}
    if [ -d /run/systemd/system ]; then
        systemctl daemon-reload || true
        if [ "$(systemctl is-enabled certbot.timer 2>/dev/null || true)" = masked ]; then
            systemctl unmask certbot.timer
            systemctl enable --now certbot.timer || true
        fi
    fi
fi
"""
#
# The releases are the installer's, as the interface's are; purge removes them.
# /etc/letsencrypt is the operator's and stays.
#
POSTRM = f"""\
#!/bin/sh
set -e
if [ "$1" = purge ]; then
    rm -rf {ROOT}
fi
"""


def depends(python: str) -> str:
    """The distribution's Python, and the CLI: step 14 renews through `haprion-cert-renew`."""

    major, minor = (int(part) for part in python.split("."))
    return f"python3 (>= {major}.{minor}), python3 (<< {major}.{minor + 1}), haprion-cli"


def build_release(
    source: Path, commit: str, epoch: int, image: str, uv: Path, podman: Path, work: Path
) -> tuple[Path, str]:
    tree, out = work / "src", work / "out"
    tree.mkdir()
    out.mkdir()
    with tarfile.open(
        fileobj=io.BytesIO(ui._git(source, "archive", "--format=tar", commit))
    ) as tar:
        tar.extractall(tree, filter="data")
    script = work / "build.sh"
    script.write_text(BUILD)
    script.chmod(0o755)
    cache = ui.uv_cache()
    subprocess.run(  # noqa: S603 - the operator's podman, fixed arguments
        [
            str(podman), "run", "--rm",
            "-e", f"SOURCE_DATE_EPOCH={epoch}",
            "-v", f"{tree}:/src-ro:ro",
            "-v", f"{script}:/build.sh:ro",
            "-v", f"{uv}:/uv:ro",
            "-v", f"{cache}:/uv-cache",
            "-v", f"{out}:/out",
            image, "/build.sh",
        ],
        check=True,
        capture_output=True,
    )  # fmt: skip
    archive, named = out / "release.tar", out / "RELEASE_ID"
    if not archive.is_file() or not named.is_file():
        raise ui.BuildError("the container made no release archive")
    return archive, named.read_text().strip()


def build(source: Path, output_dir: Path, distribution: str, uv: Path, podman: Path) -> Path:
    target = ui.DISTRIBUTIONS[distribution]
    source = source.resolve(strict=True)
    commit = node_package.source_commit(source)
    output_dir.mkdir(parents=True, exist_ok=True)
    epoch = int(ui._git(source, "show", "-s", "--format=%ct", commit).decode().strip())
    found = CERTBOT_VERSION.search(ui._git(source, "show", f"{commit}:certbot/uv.lock").decode())
    if found is None:
        raise ui.BuildError("certbot/uv.lock names no certbot")
    version = node_package.version_for(found.group(1), epoch, commit)
    digest = ui.image_digest(podman, target.image)
    with tempfile.TemporaryDirectory(prefix="haprion-certbot-package-") as directory:
        work = Path(directory)
        archive, release_id = build_release(source, commit, epoch, target.image, uv, podman, work)
        root = work / "root"
        name = f"release-{release_id}.tar"
        write(root, f"{LIB}/{name}", archive.read_bytes(), 0o644)
        write(
            root,
            f"{LIB}/PAYLOAD",
            f"RELEASE_ID={release_id}\nRELEASE_ARCHIVE={name}\n"
            f"RELEASE_SHA256={ui.sha256(archive)}\n".encode(),
            0o644,
        )
        write(
            root,
            "usr/share/doc/haprion-certbot/copyright",
            node_package.COPYRIGHT_HEADER + ui._git(source, "show", f"{commit}:LICENSE"),
            0o644,
        )
        write(
            root,
            "usr/share/doc/haprion-certbot/BUILD",
            f"commit: {commit}\nimage: {target.image}@{digest}\n"
            f"release_sha256: {ui.sha256(archive)}\n".encode(),
            0o644,
        )
        write(root, "DEBIAN/postinst", POSTINST.encode(), 0o755)
        write(root, "DEBIAN/prerm", PRERM.encode(), 0o755)
        write(root, "DEBIAN/postrm", POSTRM.encode(), 0o755)
        return package(
            root,
            {
                "Package": PACKAGE,
                "Version": f"{version}{target.suffix}",
                "Architecture": "amd64",
                "Depends": depends(target.python),
                "Section": "net",
                "Priority": "optional",
                "Description": "Haprion's certbot\n"
                " Certbot and the DNS plugins the web interface offers, as one locked\n"
                " environment for one distribution's Python, under /opt/haprion-certbot.",
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
    parser.add_argument("--distribution", choices=sorted(ui.DISTRIBUTIONS), required=True)
    parser.add_argument("--uv", type=Path, default=shutil.which("uv"))
    parser.add_argument("--podman", type=Path, default=shutil.which("podman"))
    args = parser.parse_args()
    if args.uv is None or args.podman is None:
        parser.error("uv and podman are needed to build")
    try:
        built = build(args.source, args.output_dir, args.distribution, args.uv, args.podman)
    except (ui.BuildError, node_package.PackageError, ValueError, OSError) as exc:
        parser.exit(1, f"package build failed: {exc}\n")
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or b"").decode(errors="replace").strip().splitlines()[-3:]
        parser.exit(1, f"package build failed: {' / '.join(detail) or exc}\n")
    print(json.dumps({"package": str(built), "sha256": ui.sha256(built)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
