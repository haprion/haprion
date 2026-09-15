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

TOOLS = Path(__file__).resolve().parents[1] / "tools"


def tool(name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), TOOLS / (name + ".py"))
    assert spec is not None and spec.loader is not None  # noqa: S101 - local test tool must exist
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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
            )  # noqa: S603,S607 - local fixture package, no execution
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
            one = builder.build(**arguments, output=first)
            two = builder.build(**arguments, output=second)
            self.assertEqual(one, two)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            installer.inspect_bundle(first, one)
