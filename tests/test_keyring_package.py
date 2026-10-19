"""The repository key package a CLI release carries for restored nodes (B339)."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from haprion import keyring_package
from haprion.keyring_package import PackageError, release_package, verify_package

BASE = Path(__file__).resolve().parents[1]


def deb(
    directory: Path,
    *,
    name: str = "haprion-archive-keyring",
    version: str = "2026.10.17",
    architecture: str = "all",
    key: bool = True,
) -> Path:
    tree = directory / f"tree-{name}-{version}-{architecture}-{key}"
    (tree / "DEBIAN").mkdir(parents=True)
    (tree / "DEBIAN/control").write_text(
        f"Package: {name}\nVersion: {version}\nArchitecture: {architecture}\n"
        "Maintainer: test <test@example.com>\nDescription: test\n"
    )
    target = tree / (
        "usr/share/keyrings/haprion-archive-keyring.asc" if key else "usr/share/doc/x/README"
    )
    target.parent.mkdir(parents=True)
    target.write_text("key\n")
    output = directory / f"{name}_{version}_{architecture}_{key}.deb"
    subprocess.run(
        ["/usr/bin/dpkg-deb", "--root-owner-group", "--build", str(tree), str(output)],
        check=True,
        capture_output=True,
    )
    return output


class TheVerifier(unittest.TestCase):
    def setUp(self) -> None:
        self.work = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.work)

    def test_the_key_package_is_its_version_and_digest(self) -> None:
        package = deb(self.work)
        version, sha256 = verify_package(package)
        self.assertEqual(version, "2026.10.17")
        self.assertEqual(verify_package(package, sha256), (version, sha256))

    def test_what_is_not_it_is_refused(self) -> None:
        for package, said in (
            (deb(self.work, name="haprion-node"), "not a haprion-archive-keyring all"),
            (deb(self.work, architecture="amd64"), "not a haprion-archive-keyring all"),
            (deb(self.work, version="1.0-1"), "version is not one"),
            (deb(self.work, key=False), "does not carry usr/share/keyrings"),
        ):
            with self.subTest(said), self.assertRaisesRegex(PackageError, said):
                verify_package(package)

    def test_the_version_is_the_one_the_key_package_is_built_with(self) -> None:
        # A format change in the builder without one here would refuse every
        # release's key package at installation.
        text = (BASE / "tools/build-keyring-package.py").read_text()
        (version,) = [
            line.split('"')[1] for line in text.splitlines() if line.startswith("VERSION = ")
        ]
        self.assertRegex(version, keyring_package.VERSION)


class TheRelease(unittest.TestCase):
    def setUp(self) -> None:
        self.release = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.release)

    def test_a_release_carries_it_verified_beside_the_engine(self) -> None:
        package = deb(self.release)
        package.rename(self.release / keyring_package.RELEASE_PACKAGE)
        _, sha256 = verify_package(self.release / keyring_package.RELEASE_PACKAGE)
        (self.release / "INSTALLATION.json").write_text(
            json.dumps(
                {
                    "keyring_package": {"file": keyring_package.RELEASE_PACKAGE, "sha256": sha256},
                    "waf_engine_package": None,
                }
            )
        )
        found = release_package(self.release)
        assert found is not None
        self.assertEqual((found.version, found.sha256), ("2026.10.17", sha256))

    def test_a_release_without_one_answers_none(self) -> None:
        self.assertIsNone(release_package(self.release))
        (self.release / "INSTALLATION.json").write_text(json.dumps({"waf_engine_package": None}))
        self.assertIsNone(release_package(self.release))


if __name__ == "__main__":
    unittest.main()
