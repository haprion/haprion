#!/usr/bin/env python3
"""Build a deterministic Certmonger bundle from verified distro package and source.

The bundle freezes Certmonger's own programs; the libraries they load stay the
distribution's and follow its updates. Before the bundle is written, the
package version is looked up in the OSV database under the distribution's
release (the distribution's own security tracker, as OSV carries it), and the
build is refused if any advisory affects it. The lookup is made when the
bundle is built, so rebuild to check again.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

NAME = re.compile(r"[A-Za-z0-9_.+-]+")
DIGEST = re.compile(r"[0-9a-f]{64}")
MAX_BYTES = 16 * 1024 * 1024
PROGRAMS = {
    "bin/certmonger": "./usr/sbin/certmonger",
    "bin/getcert": "./usr/bin/getcert",
    "bin/scep-submit": "./usr/lib/certmonger/scep-submit",
    "LICENSE": "./usr/share/doc/certmonger/copyright",
}
OSV_QUERY = "https://api.osv.dev/v1/query"
ECOSYSTEMS = {"debian": "Debian", "ubuntu": "Ubuntu"}
#
# OSV answers a release it has no data for exactly as a release with no
# advisories: an empty list (measured 26-10-06, Ubuntu:99.04). A package every
# release ships and that always has advisories proves the release is known
# before an empty answer for Certmonger is believed.
#
CONTROL_PACKAGE = "openssl"


def osv_query(body: dict[str, Any]) -> dict[str, Any]:
    request = urllib.request.Request(  # fixed https endpoint
        OSV_QUERY,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310 - fixed https endpoint
        answer = json.loads(response.read(MAX_BYTES))
    if not isinstance(answer, dict):
        raise ValueError("the vulnerability database gave an unreadable answer")
    return answer


def advisories(
    version: str,
    distribution: str,
    distribution_release: str,
    query: Callable[[dict[str, Any]], dict[str, Any]],
) -> str:
    """Refuse a Certmonger version with a known advisory; name the ecosystem asked."""
    if distribution not in ECOSYSTEMS:
        raise ValueError(f"no vulnerability database is known for {distribution}")
    ecosystem = f"{ECOSYSTEMS[distribution]}:{distribution_release}"
    control = query({"package": {"name": CONTROL_PACKAGE, "ecosystem": ecosystem}})
    known = {
        str(affected.get("package", {}).get("ecosystem"))
        for record in control.get("vulns", [])
        for affected in record.get("affected", [])
    }
    if not any(name == ecosystem or name.startswith(ecosystem + ":") for name in known):
        raise ValueError(f"the vulnerability database holds nothing for {ecosystem}")
    found = query({"package": {"name": "certmonger", "ecosystem": ecosystem}, "version": version})
    records = sorted(str(record.get("id")) for record in found.get("vulns", []))
    if records or found.get("next_page_token"):
        raise ValueError(
            f"certmonger {version} has known advisories in {ecosystem}: {', '.join(records)}"
        )
    return f"{ecosystem}: no known advisories for certmonger {version}"


def verified(path: Path, digest: str) -> bytes:
    if DIGEST.fullmatch(digest) is None or path.stat().st_size > MAX_BYTES:
        raise ValueError("invalid source digest or size")
    data = path.read_bytes()
    if len(data) > MAX_BYTES or hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("package or source hash does not match")
    return data


def package_field(package: Path, field: str) -> str:
    return subprocess.run(  # noqa: S603 - fixed metadata reader, no shell
        ["/usr/bin/dpkg-deb", "--field", str(package.resolve()), field],
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    ).stdout.strip()  # fixed package metadata read


def build(
    *,
    package: Path,
    package_sha256: str,
    source_description: Path,
    source_sha256: str,
    distribution: str,
    distribution_release: str,
    output: Path,
    query: Callable[[dict[str, Any]], dict[str, Any]] = osv_query,
) -> tuple[str, str]:
    """The bundle's SHA-256 and the advisory lookup's answer."""
    package_bytes = verified(package, package_sha256)
    source_bytes = verified(source_description, source_sha256)
    with tempfile.TemporaryDirectory(prefix="scep-package-") as directory:
        copied = Path(directory) / "package.deb"
        copied.write_bytes(package_bytes)
        if package_field(copied, "Package") != "certmonger":
            raise ValueError("package must be certmonger")
        version = package_field(copied, "Version")
        architecture = package_field(copied, "Architecture")
        dependencies = package_field(copied, "Depends")
        raw = subprocess.run(  # noqa: S603 - approved package bytes, fixed reader
            ["/usr/bin/dpkg-deb", "--fsys-tarfile", str(copied)],
            check=True,
            capture_output=True,
            timeout=15,
        ).stdout
    for value in (version, architecture, distribution, distribution_release):
        if NAME.fullmatch(value) is None or value in {".", ".."}:
            raise ValueError("invalid bundle identity")
    checked = advisories(version, distribution, distribution_release, query)
    source = source_bytes.decode("utf-8")
    if not re.search(r"^Source: certmonger$", source, re.M) or not re.search(
        r"^Version: " + re.escape(version) + "$", source, re.M
    ):
        raise ValueError("source description must match the package version")
    checks = source.split("Checksums-Sha256:\n", 1)[1].split("Files:", 1)[0]
    rows = re.findall(r"^ ([0-9a-f]{64}) ([0-9]+) ([A-Za-z0-9_.+-]+)$", checks, re.M)
    if len(rows) != 2 or any(name in {".", ".."} for _, _, name in rows):
        raise ValueError("complete quilt source must contain upstream and Debian archives")
    files = {
        "package/certmonger.deb": package_bytes,
        "source/certmonger_" + version + ".dsc": source_bytes,
    }
    for digest, size, name in rows:
        content = verified(source_description.parent / name, digest)
        if len(content) != int(size):
            raise ValueError("source archive size does not match")
        files["source/" + name] = content
    if len(raw) > MAX_BYTES:
        raise ValueError("package expands beyond the bundle limit")
    with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
        for destination, member_name in PROGRAMS.items():
            member = archive.getmember(member_name)
            if not member.isfile() or member.size > 1024 * 1024:
                raise ValueError("package program or license is not a bounded regular file")
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError("package program could not be read")
            files[destination] = stream.read()
    if any(not files[name].startswith(b"\x7fELF") for name in PROGRAMS if name.startswith("bin/")):
        raise ValueError("package programs must be ELF binaries")
    files["BUILD.md"] = (
        "# Retained Certmonger source\n\nUpstream: https://codeberg.org/freeipa/certmonger/\n\n"
        "Build on an isolated host matching the bundle distribution/release. Install the\n"
        "Build-Depends declared in the source description, then run:\n\n"
        f"    dpkg-source -x source/certmonger_{version}.dsc\n"
        f"    cd certmonger-{version.split('-')[0]}\n"
        "    dpkg-buildpackage -b -us -uc\n\n"
        "Bit-for-bit binary rebuilding has not been verified. Runtime libraries are\n"
        "maintained by the distribution. The original package, source and license\n"
        "are retained. Use a transient private-socket instance with autorenewal off;\n"
        "the manager does not install the package's system Certmonger service.\n"
    ).encode()
    manifest = {
        "schema_version": 1,
        "project": "certmonger",
        "version": version,
        "distribution": distribution,
        "distribution_release": distribution_release,
        "architecture": architecture,
        "package_sha256": package_sha256,
        "dependencies": dependencies,
        "files": {
            name: {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
            for name, data in sorted(files.items())
        },
    }
    files["manifest.json"] = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    if sum(len(data) for data in files.values()) > MAX_BYTES:
        raise ValueError("bundle exceeds its size limit")
    with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data in sorted(files.items()):
            entry = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            entry.create_system = 3
            entry.external_attr = (0o100555 if name.startswith("bin/") else 0o100444) << 16
            entry.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(entry, data)
    return hashlib.sha256(output.read_bytes()).hexdigest(), checked


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--package-sha256", required=True)
    parser.add_argument("--source-description", type=Path, required=True)
    parser.add_argument("--source-sha256", required=True)
    parser.add_argument("--distribution", required=True)
    parser.add_argument("--distribution-release", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        digest, checked = build(**vars(args))
        print(checked, file=sys.stderr)
        print(digest)
    except (ValueError, OSError, subprocess.SubprocessError, tarfile.TarError) as exc:
        parser.exit(1, f"SCEP bundle build failed: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
