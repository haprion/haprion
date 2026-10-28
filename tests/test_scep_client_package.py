"""Native package digest, archive bounds, member paths and reproducible builds."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import shutil
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from typing import Any
from unittest import mock

TOOLS = Path(__file__).resolve().parents[1] / "tools"


def tool(name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), TOOLS / (name + ".py"))
    assert spec is not None and spec.loader is not None  # local test tool must exist
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeOsv:
    """OSV as the build asks it: the control package, then Certmonger."""

    def __init__(self, *, known: str = "Ubuntu:26.04:LTS", found: list[str] | None = None) -> None:
        self.known, self.found = known, found or []
        self.asked: list[dict[str, Any]] = []

    def __call__(self, body: dict[str, Any]) -> dict[str, Any]:
        self.asked.append(body)
        package = body["package"]
        if package["name"] == "openssl":
            if not self.known.startswith(package["ecosystem"]):
                return {}
            return {
                "vulns": [{"id": "EXAMPLE-1", "affected": [{"package": {"ecosystem": self.known}}]}]
            }
        return {"vulns": [{"id": record} for record in self.found]}


class Advisories(unittest.TestCase):
    def setUp(self) -> None:
        self.builder = tool("build-scep-client")

    def check(self, osv: FakeOsv, distribution: str = "ubuntu", release: str = "26.04") -> str:
        return str(self.builder.advisories("0.79.21-1", distribution, release, osv))

    def test_a_version_without_advisories_passes_after_the_release_is_proven_known(self) -> None:
        osv = FakeOsv()
        self.assertIn("no known advisories", self.check(osv))
        self.assertEqual(
            osv.asked[1],
            {
                "package": {"name": "certmonger", "ecosystem": "Ubuntu:26.04"},
                "version": "0.79.21-1",
            },
        )

    def test_an_advisory_refuses_the_bundle(self) -> None:
        with self.assertRaisesRegex(ValueError, "UBUNTU-CVE-2099-0001"):
            self.check(FakeOsv(found=["UBUNTU-CVE-2099-0001"]))

    def test_a_release_the_database_does_not_know_is_refused_not_passed(self) -> None:
        # OSV answers an unknown release with an empty list (26-10-06).
        osv = FakeOsv()
        with self.assertRaisesRegex(ValueError, "holds nothing for Ubuntu:99.04"):
            self.check(osv, release="99.04")
        self.assertEqual(len(osv.asked), 1)

    def test_a_distribution_without_a_database_is_refused(self) -> None:
        with self.assertRaisesRegex(ValueError, "no vulnerability database"):
            self.check(FakeOsv(), distribution="example")


class BundleInspection(unittest.TestCase):
    def setUp(self) -> None:
        self.installer = tool("install-scep-client")
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "bundle.zip"
        self.files = {
            "bin/" + name: b"\x7fELFexample" for name in ("certmonger", "getcert", "scep-submit")
        }
        self.files.update(
            {
                "LICENSE": b"example license",
                "BUILD.md": b"example build",
                "package/certmonger.deb": b"example package",
                "source/certmonger.dsc": b"example source",
                "source/certmonger.orig.tar.gz": b"example upstream",
                "source/certmonger.debian.tar.xz": b"example patches",
            }
        )

    def archive(
        self, *, extra: str | None = None, duplicate: bool = False, symlink: bool = False
    ) -> str:
        manifest = {
            "schema_version": 1,
            "project": "certmonger",
            "version": "0.79.21-1",
            "distribution": "ubuntu",
            "distribution_release": "26.04",
            "architecture": "amd64",
            "dependencies": "libc6 (>= 2.38)",
            "package_sha256": hashlib.sha256(self.files["package/certmonger.deb"]).hexdigest(),
            "files": {
                name: {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
                for name, data in self.files.items()
            },
        }
        entries = {**self.files, "manifest.json": json.dumps(manifest).encode()}
        if extra:
            entries[extra] = b"unexpected"
        with zipfile.ZipFile(self.path, "w") as archive:
            for name, data in entries.items():
                info = zipfile.ZipInfo(name)
                info.external_attr = (
                    0o120777 if symlink and name == "bin/getcert" else 0o100444
                ) << 16
                archive.writestr(info, data)
            if duplicate:
                with self.assertWarns(UserWarning):
                    archive.writestr("LICENSE", b"other")
        return hashlib.sha256(self.path.read_bytes()).hexdigest()

    def test_complete_bundle_keeps_all_three_programs_and_source(self) -> None:
        digest = self.archive()
        manifest, files = self.installer.inspect_bundle(self.path, digest)
        self.assertEqual(manifest["version"], "0.79.21-1")
        self.assertEqual(files, self.files)

    def test_digest_member_traversal_duplicates_symlinks_and_extra_fields_are_refused(self) -> None:
        digest = self.archive()
        with self.assertRaises(self.installer.InstallError):
            self.installer.inspect_bundle(self.path, "f" * 64)
        for arguments in (
            {"extra": "../outside"},
            {"extra": "/absolute"},
            {"extra": "source/.."},
            {"duplicate": True},
            {"symlink": True},
            {"extra": "challenge"},
        ):
            with self.subTest(arguments=arguments):
                digest = self.archive(**arguments)
                with self.assertRaises(self.installer.InstallError):
                    self.installer.inspect_bundle(self.path, digest)

    def test_member_tampering_is_refused_even_with_an_updated_outer_digest(self) -> None:
        self.archive()
        with zipfile.ZipFile(self.path) as archive:
            entries = {name: archive.read(name) for name in archive.namelist()}
        entries["bin/getcert"] = b"\x7fELFchanged-example"
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            for name, data in entries.items():
                info = zipfile.ZipInfo(name)
                info.external_attr = 0o100444 << 16
                archive.writestr(info, data)
        self.path.write_bytes(buffer.getvalue())
        with self.assertRaises(self.installer.InstallError):
            self.installer.inspect_bundle(self.path, hashlib.sha256(buffer.getvalue()).hexdigest())

    def installed(self, *, satisfy: bool) -> list[list[str]]:
        """The commands an install ran, with root, the machine and the programs imitated."""

        digest = self.archive()
        ran: list[list[str]] = []

        def run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
            ran.append(command)
            answer = "amd64\n" if command[-1] == "--print-architecture" else ""
            return subprocess.CompletedProcess(command, 0, answer, "")

        read_text = Path.read_text

        def os_release(path: Path, *arguments: Any, **keywords: Any) -> str:
            if str(path) == "/etc/os-release":
                return 'ID=ubuntu\nVERSION_ID="26.04"\n'
            return read_text(path, *arguments, **keywords)

        target = Path(self.temporary.name) / "scep"
        with (
            mock.patch.object(self.installer.os, "geteuid", return_value=0),
            mock.patch.object(self.installer, "protected_target"),
            mock.patch.object(self.installer.subprocess, "run", side_effect=run),
            mock.patch.object(Path, "read_text", os_release),
        ):
            self.installer.install(self.path, digest, target, satisfy=satisfy)
        self.assertTrue((target / "current").is_symlink())
        for directory in [target, *target.rglob("*")]:
            if directory.is_dir() and not directory.is_symlink():
                directory.chmod(0o700)
        return ran

    def test_the_package_s_install_never_runs_apt_and_still_checks_the_libraries(self) -> None:
        """B383: inside haprion-scep's postinst dpkg holds apt's lock; the package's
        own dependencies are the bundle's, so nothing is left to satisfy."""

        ran = self.installed(satisfy=False)
        self.assertFalse([command for command in ran if command[0] == "/usr/bin/apt-get"])
        self.assertEqual(sum(command[0] == "/usr/bin/ldd" for command in ran), 3)

    def test_a_bundle_installed_by_hand_satisfies_its_dependencies_first(self) -> None:
        ran = self.installed(satisfy=True)
        self.assertIn(
            [
                "/usr/bin/apt-get",
                "--assume-yes",
                "--no-install-recommends",
                "satisfy",
                "libc6 (>= 2.38)",
            ],
            ran,
        )


@unittest.skipUnless(shutil.which("dpkg-deb"), "requires distribution package tools")
class ReproducibleBuild(unittest.TestCase):
    def test_two_bundles_from_the_same_verified_package_and_source_are_identical(self) -> None:
        builder, installer = tool("build-scep-client"), tool("install-scep-client")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tree = root / "tree"
            (tree / "DEBIAN").mkdir(parents=True)
            (tree / "DEBIAN/control").write_text(
                "Package: certmonger\nVersion: 0.79.21-1\nArchitecture: amd64\nMaintainer: Example <admin@example.com>\nDescription: test package\nDepends: libc6\n"
            )
            for member in builder.PROGRAMS.values():
                target = tree / member.removeprefix("./")
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(
                    b"\x7fELFexample" if "copyright" not in member else b"example license"
                )
            package = root / "package.deb"
            subprocess.run(
                ["/usr/bin/dpkg-deb", "--build", str(tree), str(package)],
                check=True,
                capture_output=True,
            )  # local fixture package, no execution
            rows = []
            for name in ("certmonger_0.79.21.orig.tar.gz", "certmonger_0.79.21-1.debian.tar.xz"):
                data = b"example source"
                (root / name).write_bytes(data)
                rows.append(f" {hashlib.sha256(data).hexdigest()} {len(data)} {name}")
            source = root / "certmonger_0.79.21-1.dsc"
            source.write_text(
                "Source: certmonger\nVersion: 0.79.21-1\nChecksums-Sha256:\n"
                + "\n".join(rows)
                + "\nFiles:\n"
            )
            arguments = {
                "package": package,
                "package_sha256": hashlib.sha256(package.read_bytes()).hexdigest(),
                "source_description": source,
                "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                "distribution": "ubuntu",
                "distribution_release": "26.04",
            }
            first, second = root / "first.zip", root / "second.zip"
            one, checked = builder.build(**arguments, output=first, query=FakeOsv())
            two, _ = builder.build(**arguments, output=second, query=FakeOsv())
            self.assertEqual(checked, "Ubuntu:26.04: no known advisories for certmonger 0.79.21-1")
            self.assertEqual(one, two)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            installer.inspect_bundle(first, one)
