"""Build and verify a minimal, commit-bound node installation bundle.

The operator's `tools/install-node-bundle` verifies a bundle with this module
before it sends one to a node, the release installer verifies the bundle a CLI
release carries with it (B180), and a node restore verifies that one again
before it sends it to the restored node. One implementation for all three,
run from a checkout by `tools/node-bundle.py`.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import re
import subprocess
import sys
import tarfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

SCHEMA_VERSION = 1
MAX_BUNDLE_BYTES = 4 * 1024 * 1024
MAX_MEMBER_BYTES = 1024 * 1024
MAX_MANIFEST_BYTES = 64 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}")
COMMIT = re.compile(r"[0-9a-f]{40}")
NODE_SCRIPTS = (
    "haprion-pull-deploy",
    "haprion-cert-pull",
    "haprion-cert-remove",
    "haprion-cert-trigger",
    "haprion-node-status",
    "haprion-health-probe",
    "haprion-keepalived-state",
    "haprion-state-export",
    "haprion-traffic-log-read",
    "haprion-traffic-log-enable",
    "haprion-traffic-log-prune",
    "haprion-server-state",
    "haprion-server-state-trigger",
)
#
# Data rather than programs, so 0644: the shell library the scripts source,
# and the repository key `lib.sh` installs dnsdist with (B249).
#
NOT_EXECUTABLE = ("install/lib.sh", "install/apt-keys/powerdns-dnsdist.asc")
PAYLOAD = (
    "install/04-node-prepare",
    *NOT_EXECUTABLE,
    *(f"install/node/{name}" for name in NODE_SCRIPTS),
)


def payload_mode(relative: str) -> int:
    return 0o644 if relative in NOT_EXECUTABLE else 0o755


class BundleError(RuntimeError):
    """A fail-closed node bundle error."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git(source: Path, *arguments: str) -> str:
    try:
        result = subprocess.run(  # noqa: S603 -- fixed executable and internal git arguments
            ["/usr/bin/git", "-C", str(source), *arguments],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise BundleError(f"cannot inspect source commit: {exc}") from exc
    return result.stdout.strip()


def source_commit(source: Path) -> str:
    commit = _git(source, "rev-parse", "HEAD")
    if COMMIT.fullmatch(commit) is None:
        raise BundleError("source tree did not report a full commit hash")
    if _git(source, "status", "--porcelain"):
        raise BundleError("source tree has uncommitted changes; a release is a commit")
    return commit


def _payload(source: Path, commit: str) -> dict[str, tuple[bytes, int]]:
    result: dict[str, tuple[bytes, int]] = {}
    for relative in PAYLOAD:
        try:
            tree = subprocess.run(  # noqa: S603 -- fixed executable, commit and payload path
                ["/usr/bin/git", "-C", str(source), "ls-tree", commit, "--", relative],
                check=True,
                capture_output=True,
                text=True,
                timeout=30,
            ).stdout.rstrip("\n")
            content = subprocess.run(  # noqa: S603 -- fixed executable, commit and payload path
                ["/usr/bin/git", "-C", str(source), "show", f"{commit}:{relative}"],
                check=True,
                capture_output=True,
                timeout=30,
            ).stdout
        except (OSError, subprocess.SubprocessError) as exc:
            raise BundleError(f"cannot read committed payload file {relative}: {exc}") from exc
        fields = tree.split(maxsplit=3)
        if len(fields) != 4 or fields[1] != "blob" or fields[3] != relative:
            raise BundleError(f"payload path is missing or not a regular file: {relative}")
        git_mode = fields[0]
        expected = payload_mode(relative)
        expected_git_mode = "100755" if expected == 0o755 else "100644"
        if git_mode != expected_git_mode:
            raise BundleError(
                f"payload file {relative} has Git mode {git_mode}, expected {expected_git_mode}"
            )
        result[relative] = (content, expected)
    return result


def build_bundle(source: Path, output: Path) -> tuple[str, str]:
    source = source.resolve(strict=True)
    if output.exists() or output.is_symlink():
        raise BundleError("output already exists")
    release_commit = source_commit(source)
    return write_bundle(output, release_commit, _payload(source, release_commit))


def write_bundle(
    output: Path, release_commit: str, payload: dict[str, tuple[bytes, int]]
) -> tuple[str, str]:
    """Write a reproducible bundle of this payload; answer its root and SHA-256."""

    root = f"haproxy-manager-node-{release_commit[:12]}"
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "commit": release_commit,
        "files": {
            name: {"mode": mode, "sha256": sha256_bytes(data)}
            for name, (data, mode) in sorted(payload.items())
        },
    }
    manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()

    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with (
            output.open("xb") as raw,
            gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed,
            tarfile.open(fileobj=compressed, mode="w") as archive,
        ):
            for name, (data, mode) in [
                ("MANIFEST.json", (manifest_bytes, 0o644)),
                *sorted(payload.items()),
            ]:
                info = tarfile.TarInfo(f"{root}/{name}")
                info.size = len(data)
                info.mode = mode
                info.uid = 0
                info.gid = 0
                info.uname = "root"
                info.gname = "root"
                info.mtime = 0
                archive.addfile(info, io.BytesIO(data))
    except Exception:
        output.unlink(missing_ok=True)
        raise
    return root, sha256_file(output)


def _safe_member(name: str) -> PurePosixPath:
    member = PurePosixPath(name)
    if not name or member.is_absolute() or ".." in member.parts or "" in member.parts:
        raise BundleError(f"bundle contains an unsafe path: {name!r}")
    return member


def verify_bundle(
    bundle: Path, expected_sha256: str | None = None
) -> tuple[str, dict[str, object]]:
    if not bundle.is_file() or bundle.is_symlink():
        raise BundleError("bundle must be a regular non-symlink file")
    if bundle.stat().st_size > MAX_BUNDLE_BYTES:
        raise BundleError("bundle exceeds its size limit")
    actual = sha256_file(bundle)
    if expected_sha256 is not None and (
        SHA256.fullmatch(expected_sha256) is None or actual != expected_sha256
    ):
        raise BundleError("bundle SHA-256 does not match the expected value")
    try:
        archive = tarfile.open(bundle, mode="r:gz")  # noqa: SIM115 -- closed immediately below
    except (OSError, tarfile.TarError) as exc:
        raise BundleError(f"cannot open node bundle: {exc}") from exc
    with archive:
        members = archive.getmembers()
        for item in members:
            _safe_member(item.name)
            if not item.isreg():
                raise BundleError(f"bundle member is not a regular file: {item.name}")
            if item.size > MAX_MEMBER_BYTES:
                raise BundleError(f"bundle member exceeds its size limit: {item.name}")
        roots = {PurePosixPath(item.name).parts[0] for item in members}
        if len(roots) != 1:
            raise BundleError("bundle must contain exactly one release root")
        root = roots.pop()
        manifest_name = f"{root}/MANIFEST.json"
        indexed = {item.name: item for item in members}
        if len(indexed) != len(members):
            raise BundleError("bundle contains a duplicate member name")
        if manifest_name not in indexed:
            raise BundleError("bundle has no MANIFEST.json")
        if indexed[manifest_name].size > MAX_MANIFEST_BYTES:
            raise BundleError("bundle manifest exceeds its size limit")
        try:
            manifest = json.loads(archive.extractfile(indexed[manifest_name]).read())  # type: ignore[union-attr]
        except (AttributeError, UnicodeError, json.JSONDecodeError) as exc:
            raise BundleError(f"bundle manifest is invalid: {exc}") from exc
        if not isinstance(manifest, dict) or set(manifest) != {"schema_version", "commit", "files"}:
            raise BundleError("bundle manifest has unexpected or missing fields")
        commit = manifest["commit"]
        if (
            type(manifest["schema_version"]) is not int
            or manifest["schema_version"] != SCHEMA_VERSION
            or not isinstance(commit, str)
            or COMMIT.fullmatch(commit) is None
        ):
            raise BundleError("bundle manifest version or commit is invalid")
        expected_root = f"haproxy-manager-node-{commit[:12]}"
        if root != expected_root:
            raise BundleError("bundle root does not match its commit")
        files = manifest["files"]
        if not isinstance(files, dict) or set(files) != set(PAYLOAD):
            raise BundleError("bundle manifest does not name the exact node payload")
        if set(indexed) != {manifest_name, *(f"{root}/{name}" for name in PAYLOAD)}:
            raise BundleError("bundle contains an unmanifested or missing member")
        for name in PAYLOAD:
            record = files[name]
            if not isinstance(record, dict) or set(record) != {"mode", "sha256"}:
                raise BundleError(f"invalid manifest record for {name}")
            expected_mode = payload_mode(name)
            if (
                type(record["mode"]) is not int
                or record["mode"] != expected_mode
                or not isinstance(record["sha256"], str)
                or SHA256.fullmatch(record["sha256"]) is None
            ):
                raise BundleError(f"invalid manifest values for {name}")
            member = indexed[f"{root}/{name}"]
            content = archive.extractfile(member)
            if content is None or sha256_bytes(content.read()) != record["sha256"]:
                raise BundleError(f"payload digest mismatch for {name}")
            if member.mode != record["mode"]:
                raise BundleError(f"payload mode mismatch for {name}")
    return root, manifest


#
# Where a CLI release carries its node bundle (B180): beside INSTALLATION.json,
# put there by tools/install-release.py from the same commit as the wheel.
#
RELEASE_BUNDLE = "node-bundle.tar.gz"


@dataclass(frozen=True, slots=True)
class ReleaseBundle:
    path: Path
    root: str
    commit: str
    sha256: str


def release_bundle(release: Path | None = None) -> ReleaseBundle | None:
    """The node bundle the running release carries, verified; None when it carries none.

    The release directory is the one this module was installed into:
    ``<release>/lib/haproxy_mgmt/node_bundle.py``. A checkout, or a release
    installed without ``--node-bundle``, has no INSTALLATION.json record and
    answers None.
    """

    release = release or Path(__file__).resolve().parents[2]
    installation = release / "INSTALLATION.json"
    if not installation.is_file():
        return None
    try:
        document = json.loads(installation.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BundleError(f"cannot read {installation}: {exc}") from exc
    record = document.get("node_bundle") if isinstance(document, dict) else None
    if record is None:
        return None
    if (
        not isinstance(record, dict)
        or record.get("file") != RELEASE_BUNDLE
        or not isinstance(record.get("sha256"), str)
    ):
        raise BundleError(f"{installation} has an unusable node_bundle record")
    path = release / RELEASE_BUNDLE
    root, manifest = verify_bundle(path, record["sha256"])
    return ReleaseBundle(
        path=path, root=root, commit=str(manifest["commit"]), sha256=record["sha256"]
    )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    subparsers = result.add_subparsers(dest="operation", required=True)
    build = subparsers.add_parser("build")
    build.add_argument("--source", type=Path, required=True)
    build.add_argument("--output", type=Path, required=True)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--bundle", type=Path, required=True)
    verify.add_argument("--sha256")
    return result


def main() -> int:
    arguments = parser().parse_args()
    try:
        if arguments.operation == "build":
            root, digest = build_bundle(arguments.source, arguments.output)
            _, manifest = verify_bundle(arguments.output, digest)
            print(f"bundle: {arguments.output}")
            print(f"release: {root}")
            print(f"commit: {manifest['commit']}")
            print(f"sha256: {digest}")
        else:
            root, manifest = verify_bundle(arguments.bundle, arguments.sha256)
            files = manifest["files"]
            file_count = len(files) if isinstance(files, dict) else 0
            print(f"release: {root}")
            print(f"commit: {manifest['commit']}")
            print(f"files: {file_count}")
            print(f"sha256: {sha256_file(arguments.bundle)}")
    except BundleError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
