#!/usr/bin/env python3
"""Build the web interface package, `haprion-ui`, for one distribution (B266).

The interface runs from a virtual environment, and a virtual environment is
neither relocatable nor portable between Python versions: every console script
names the interpreter by absolute path, and the binary wheels are built for one
Python. So the release is built where it will run - at its final path,
`/opt/haprion-ui/releases/<version>-<commit>`, against the distribution's own
`/usr/bin/python3` - inside a container of that distribution (podman, rootless):

    ubuntu26.04   Python 3.14
    debian13      Python 3.13

The package carries that release as a tar archive with its migration bundle,
and nothing else of the platform's: installing it prepares the release on disk
and says what comes next. The platform's own steps make it current (model C).

The same commit, distribution image and lock give the same bytes, measured
26-10-09: the two local distributions are built as wheels first (the wheel
build is reproducible) and installed from files; uv's own cache key, which
holds the time of installation and which nothing reads at run time, is removed
from each package with its line in RECORD; the archive is sorted, root-owned and
dated at the commit. The image is named by digest in the package's BUILD file,
because a newer image with a newer Python is a different release.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from haproxy_mgmt import node_package  # noqa: E402 - the path above comes first
from haproxy_mgmt.debian_package import package, write  # noqa: E402

PACKAGE = "haprion-ui"
LIB = "usr/lib/haprion/ui"
ROOT = "/opt/haprion-ui"


@dataclass(frozen=True, slots=True)
class Distribution:
    image: str
    suffix: str
    python: str


DISTRIBUTIONS = {
    "ubuntu26.04": Distribution("docker.io/library/ubuntu:26.04", "~ubuntu26.04", "3.14"),
    "debian13": Distribution("docker.io/library/debian:13", "~deb13", "3.13"),
}
#
# Runs inside the container, as its root - which rootless podman maps to the
# operator's own account outside it. The source is mounted read-only and
# copied, because the builds write into the tree.
#
BUILD = r"""#!/bin/sh
set -eu
export DEBIAN_FRONTEND=noninteractive UV_CACHE_DIR=/uv-cache
apt-get update -qq >/dev/null
apt-get install -y -qq --no-install-recommends python3 ca-certificates >/dev/null
R="/opt/haprion-ui/releases/$RELEASE_ID"
mkdir -p "$R" /wheels
cp -a /src-ro /src
cd /src && /uv build -q --wheel --out-dir /wheels .
cd /src/ui && /uv build -q --wheel --out-dir /wheels .
UV_PROJECT_ENVIRONMENT="$R/venv" /uv sync -q --locked --no-dev --no-editable \
    --no-install-project --no-install-package haprion \
    --python /usr/bin/python3 --python-preference only-system
/uv pip install -q --no-cache --python "$R/venv/bin/python" --no-deps /wheels/*.whl
find "$R" -name __pycache__ -prune -exec rm -rf {} +
python3 - "$R/venv" <<'PY'
import sys
from pathlib import Path
for cache in Path(sys.argv[1]).glob("lib/python3*/site-packages/*.dist-info/uv_cache.json"):
    record = cache.parent / "RECORD"
    name = f"{cache.parent.name}/uv_cache.json,"
    lines = record.read_text().splitlines(keepends=True)
    record.write_text("".join(line for line in lines if not line.startswith(name)))
    cache.unlink()
PY
mkdir -p "$R/migration"
cp /src/ui/alembic.ini "$R/migration/alembic.ini"
cd /src/ui && find migrations -type f -not -path '*/__pycache__/*' -exec cp --parents {} "$R/migration/" \;
"$R/venv/bin/python" -B -c 'import haproxy_ui.app, haproxy_mgmt.cluster_status, haproxy_mgmt.inventory'
tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner \
    --pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime \
    -cf /out/release.tar -C / "${R#/}"
"""
POSTINST = f"""\
#!/bin/sh
set -e
if [ "$1" = configure ]; then
    . /{LIB}/PAYLOAD
    release="{ROOT}/releases/$RELEASE_ID"
    if [ ! -d "$release" ]; then
        mkdir -p {ROOT}/releases
        tar -xf "/{LIB}/$RELEASE_ARCHIVE" -C /
    fi
    echo "haprion-ui: release $RELEASE_ID is prepared in $release"
fi
"""


class BuildError(RuntimeError):
    """A fail-closed package build error."""


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _git(source: Path, *arguments: str) -> bytes:
    return subprocess.run(  # noqa: S603 - fixed executable and internal git arguments
        ["/usr/bin/git", "-C", str(source), *arguments], check=True, capture_output=True
    ).stdout


def image_digest(podman: Path, image: str) -> str:
    subprocess.run([str(podman), "pull", "-q", image], check=True, capture_output=True)  # noqa: S603
    digest = subprocess.run(  # noqa: S603 - the operator's podman, fixed arguments
        [str(podman), "image", "inspect", "--format", "{{.Digest}}", image],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if not digest.startswith("sha256:"):
        raise BuildError(f"{image} has no digest")
    return digest


def build_release(
    source: Path,
    commit: str,
    epoch: int,
    release_id: str,
    image: str,
    uv: Path,
    podman: Path,
    work: Path,
) -> Path:
    tree, out = work / "src", work / "out"
    tree.mkdir()
    out.mkdir()
    with tarfile.open(fileobj=io.BytesIO(_git(source, "archive", "--format=tar", commit))) as tar:
        tar.extractall(tree, filter="data")
    script = work / "build.sh"
    script.write_text(BUILD)
    script.chmod(0o755)
    cache = Path(os.environ.get("UV_CACHE_DIR", Path.home() / ".cache/uv"))
    subprocess.run(  # noqa: S603 - the operator's podman, fixed arguments
        [
            str(podman), "run", "--rm",
            "-e", f"RELEASE_ID={release_id}",
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
    archive = out / "release.tar"
    if not archive.is_file():
        raise BuildError("the container made no release archive")
    return archive


def assemble(
    root: Path,
    *,
    archive: Path,
    release_id: str,
    licence: bytes,
    commit: str,
    image: str,
    digest: str,
) -> None:
    name = f"release-{release_id}.tar"
    write(root, f"{LIB}/{name}", archive.read_bytes(), 0o644)
    write(
        root,
        f"{LIB}/PAYLOAD",
        f"RELEASE_ID={release_id}\nRELEASE_ARCHIVE={name}\nRELEASE_SHA256={sha256(archive)}\n".encode(),
        0o644,
    )
    write(
        root, "usr/share/doc/haprion-ui/copyright", node_package.COPYRIGHT_HEADER + licence, 0o644
    )
    write(
        root,
        "usr/share/doc/haprion-ui/BUILD",
        f"commit: {commit}\nimage: {image}@{digest}\nrelease_sha256: {sha256(archive)}\n".encode(),
        0o644,
    )
    write(root, "DEBIAN/postinst", POSTINST.encode(), 0o755)


def depends(python: str) -> str:
    major, minor = (int(part) for part in python.split("."))
    return (
        f"python3 (>= {major}.{minor}), python3 (<< {major}.{minor + 1}), "
        "haprion-cli, nginx, postgresql, sudo, curl"
    )


def build(source: Path, output_dir: Path, distribution: str, uv: Path, podman: Path) -> Path:
    target = DISTRIBUTIONS[distribution]
    source = source.resolve(strict=True)
    commit = node_package.source_commit(source)
    output_dir.mkdir(parents=True, exist_ok=True)
    epoch = int(_git(source, "show", "-s", "--format=%ct", commit).decode().strip())
    project = tomllib.loads(_git(source, "show", f"{commit}:ui/pyproject.toml").decode())
    version = node_package.version_for(str(project["project"]["version"]), epoch, commit)
    upstream = version.split("+", 1)[0]
    release_id = f"{upstream}-{commit[:12]}"
    digest = image_digest(podman, target.image)
    with tempfile.TemporaryDirectory(prefix="haprion-ui-package-") as directory:
        work = Path(directory)
        archive = build_release(source, commit, epoch, release_id, target.image, uv, podman, work)
        root = work / "root"
        assemble(
            root,
            archive=archive,
            release_id=release_id,
            licence=_git(source, "show", f"{commit}:LICENSE"),
            commit=commit,
            image=target.image,
            digest=digest,
        )
        return package(
            root,
            {
                "Package": PACKAGE,
                "Version": f"{version}{target.suffix}",
                "Architecture": "amd64",
                "Depends": depends(target.python),
                "Section": "net",
                "Priority": "optional",
                "Description": "Haprion web interface\n"
                " The release of the web interface for one distribution's Python,\n"
                " prepared under /opt/haprion-ui when the package is installed.",
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
    parser.add_argument("--distribution", choices=sorted(DISTRIBUTIONS), required=True)
    parser.add_argument("--uv", type=Path, default=shutil.which("uv"))
    parser.add_argument("--podman", type=Path, default=shutil.which("podman"))
    args = parser.parse_args()
    if args.uv is None or args.podman is None:
        parser.error("pass --uv and --podman, or put them on PATH")
    try:
        target = build(args.source, args.output_dir, args.distribution, args.uv, args.podman)
    except (BuildError, node_package.PackageError, ValueError, OSError) as exc:
        parser.exit(1, f"package build failed: {exc}\n")
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or b"").decode(errors="replace").strip().splitlines()[-3:]
        parser.exit(1, f"package build failed: {' / '.join(detail) or exc}\n")
    print(json.dumps({"package": str(target), "sha256": sha256(target)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
