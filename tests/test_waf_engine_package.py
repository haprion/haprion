"""The WAF engine package a CLI release carries for restored nodes (B298).

Built here with dpkg-deb, as small as a package can be, so the verifier reads
the same metadata and file list it reads from the real one.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from haprion import waf_engine_package
from haprion.waf_engine_package import PackageError, release_package, verify_package


def deb(
    directory: Path,
    *,
    name: str = "haprion-coraza-spoa",
    version: str = "0.9.0-7",
    architecture: str = "amd64",
    engine: bool = True,
) -> Path:
    tree = directory / f"tree-{name}-{version}-{architecture}-{engine}"
    (tree / "DEBIAN").mkdir(parents=True)
    (tree / "DEBIAN/control").write_text(
        f"Package: {name}\nVersion: {version}\nArchitecture: {architecture}\n"
        "Maintainer: test <test@example.com>\nDescription: test\n"
    )
    target = tree / ("usr/sbin/coraza-spoa" if engine else "usr/share/doc/x/README")
    target.parent.mkdir(parents=True)
    target.write_text("engine\n")
    output = directory / f"{name}_{version}_{architecture}_{engine}.deb"
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

    def test_the_engine_package_is_its_version_and_digest(self) -> None:
        package = deb(self.work)
        version, sha256 = verify_package(package)
        self.assertEqual(version, "0.9.0-7")
        self.assertEqual(verify_package(package, sha256), (version, sha256))

    def test_what_is_not_it_is_refused(self) -> None:
        for package, said in (
            (deb(self.work, name="haprion-node"), "not a haprion-coraza-spoa amd64"),
            (deb(self.work, architecture="all"), "not a haprion-coraza-spoa amd64"),
            (deb(self.work, version="0.9.0"), "version is not one"),
            (deb(self.work, engine=False), "does not carry usr/sbin/coraza-spoa"),
        ):
            with self.subTest(said), self.assertRaisesRegex(PackageError, said):
                verify_package(package)

    def test_a_digest_that_does_not_match_is_refused(self) -> None:
        with self.assertRaisesRegex(PackageError, "does not match"):
            verify_package(deb(self.work), "0" * 64)


class TheRelease(unittest.TestCase):
    def setUp(self) -> None:
        self.release = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.release)

    def record(self, record: object) -> None:
        (self.release / "INSTALLATION.json").write_text(json.dumps({"waf_engine_package": record}))

    def test_a_release_carries_it_verified(self) -> None:
        package = deb(self.release)
        package.rename(self.release / waf_engine_package.RELEASE_PACKAGE)
        _, sha256 = verify_package(self.release / waf_engine_package.RELEASE_PACKAGE)
        self.record({"file": waf_engine_package.RELEASE_PACKAGE, "sha256": sha256})
        found = release_package(self.release)
        self.assertIsNotNone(found)
        assert found is not None
        self.assertEqual((found.version, found.sha256), ("0.9.0-7", sha256))

    def test_a_release_without_one_answers_none(self) -> None:
        self.assertIsNone(release_package(self.release))
        self.record(None)
        self.assertIsNone(release_package(self.release))

    def test_an_unusable_record_is_refused(self) -> None:
        self.record({"file": "elsewhere.deb", "sha256": "0" * 64})
        with self.assertRaisesRegex(PackageError, "unusable waf_engine_package record"):
            release_package(self.release)


if __name__ == "__main__":
    unittest.main()
