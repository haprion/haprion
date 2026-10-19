"""The project's repository on a restored node, and what reaches a new VM (B339)."""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from haprion import (
    haprion_repository,
    keyring_package,
    node_package,
    restore_source,
    waf_engine_package,
)
from tests.restore_fixture import FILES, build

BASE = Path(__file__).resolve().parents[1]


class TheRepository(unittest.TestCase):
    def test_the_source_is_the_one_the_installation_documents(self) -> None:
        manual = (BASE / "docs/install.md").read_text()
        for os_release in (
            {"ID": "debian", "VERSION_ID": "13"},
            {"ID": "ubuntu", "VERSION_ID": "26.04"},
        ):
            with self.subTest(os_release):
                key, source = haprion_repository.repository_files(os_release)
                self.assertEqual(key.path, haprion_repository.KEY_PATH)
                self.assertEqual(source.path, haprion_repository.SOURCE_PATH)
                self.assertIn(source.data.decode(), manual)
                self.assertIn(f"sudo tee {source.path} ", manual)
                self.assertIn(f"-fsSLo {key.path} ", manual)
        self.assertIn(f"`{haprion_repository.FINGERPRINT}`", manual)

    def test_the_shipped_key_is_the_repository_s(self) -> None:
        # Two copies, one tree: a renewed key in one and not the other fails here.
        self.assertEqual(haprion_repository.key(), (BASE / "keys/haprion-archive.asc").read_bytes())

    def test_a_target_without_a_suite_is_refused(self) -> None:
        with self.assertRaises(haprion_repository.RepositoryError):
            haprion_repository.repository_files({"ID": "debian", "VERSION_ID": "12"})


class TheArchive(unittest.TestCase):
    def setUp(self) -> None:
        self.work = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.work)

    def source(self, text: str | None) -> restore_source.RestoreSource:
        files = dict(FILES)
        if text is not None:
            files[haprion_repository.SOURCE_PATH] = (text, 0o644)
        work = Path(tempfile.mkdtemp(dir=self.work))
        return restore_source.read(build(work, files=files))

    def test_a_node_with_the_source_had_the_repository(self) -> None:
        for text in (
            "Types: deb\nURIs: https://haprion.github.io/haprion/\nSuites: deb13\n",
            "deb [signed-by=/x.asc] https://haprion.github.io/haprion deb13 main\n",
        ):
            with self.subTest(text):
                self.assertTrue(haprion_repository.in_archive(self.source(text)))

    def test_a_node_without_it_or_with_it_commented_out_did_not(self) -> None:
        self.assertFalse(haprion_repository.in_archive(self.source(None)))
        commented = "# URIs: https://haprion.github.io/haprion/\n"
        self.assertFalse(haprion_repository.in_archive(self.source(commented)))


class WhatTheNodePackageNeedsReachesANewVm(unittest.TestCase):
    def test_every_project_package_it_depends_on_is_carried(self) -> None:
        # The node package came to depend on the key package in 0.9.0 and a
        # restore to a new VM sent only the node package and the engine: apt
        # refused it (measured 26-10-19). Nothing looked; this does.
        depended = {
            alternative.strip().split()[0]
            for relation in node_package.DEPENDS.split(",")
            for alternative in relation.split("|")
            if alternative.strip().startswith("haprion-")
        }
        carried = {waf_engine_package.PACKAGE, keyring_package.PACKAGE}
        self.assertEqual(depended - carried, set())


if __name__ == "__main__":
    unittest.main()
