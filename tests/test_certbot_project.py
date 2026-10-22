"""Static invariants for the separately locked Certbot environment."""

from __future__ import annotations

import re
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT / "certbot" / "pyproject.toml"
LOCK = ROOT / "certbot" / "uv.lock"
PACKAGE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*")


def requirement_name(requirement: str) -> str:
    """The distribution name a requirement line starts with."""

    found = PACKAGE_NAME.match(requirement)
    assert found, f"not a requirement: {requirement!r}"
    return found.group()


def normalized(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


class CertbotProjectTests(unittest.TestCase):
    def test_every_direct_dependency_is_present_once_in_the_lock(self) -> None:
        project = tomllib.loads(PROJECT.read_text())
        lock = tomllib.loads(LOCK.read_text())
        dependencies = project["project"]["dependencies"]
        direct = [normalized(requirement_name(item)) for item in dependencies]
        locked = [normalized(package["name"]) for package in lock["package"]]

        self.assertEqual(len(direct), len(set(direct)), "duplicate direct dependency")
        for package in direct:
            with self.subTest(package=package):
                self.assertEqual(locked.count(package), 1)

    def test_the_compatible_azure_fork_replaces_the_legacy_distribution(self) -> None:
        project = tomllib.loads(PROJECT.read_text())
        dependencies = project["project"]["dependencies"]

        self.assertIn("certbot-dns-azure-modern==2.8.0", dependencies)
        self.assertFalse(
            any(item.startswith("certbot-dns-azure==") for item in dependencies),
            "the two distributions install the same module and may not coexist",
        )

    def test_the_retired_google_domains_plugin_is_not_offered(self) -> None:
        project = tomllib.loads(PROJECT.read_text())
        dependencies = project["project"]["dependencies"]
        self.assertFalse(
            any(item.startswith("certbot-dns-google-domains") for item in dependencies)
        )

        lock = tomllib.loads(LOCK.read_text())
        locked = {package["name"] for package in lock["package"]}
        self.assertNotIn("certbot-dns-google-domains", locked)
        self.assertNotIn("dataclasses-json", locked)


if __name__ == "__main__":
    unittest.main()


class WhatIsBuiltFromSourceIsBuiltWithTheLock(unittest.TestCase):
    """Review 2026-10-22, 5-7: a source build fetched its backend from PyPI with no hash.

    `install-certbot-env.py` installs the `build` group from wheels first and
    builds the sources against it without isolation, so every package that
    arrives only as source must build with what the group holds. Each one was
    read: its `build-system`, or its absence, names setuptools alone. A new one
    fails here until it has been read the same way and named below.
    """

    BUILT_WITH_SETUPTOOLS = frozenset(
        {
            "certbot-dns-acmedns",
            "certbot-dns-baidu",
            "certbot-dns-ddnss",
            "certbot-dns-dnspod",
            "certbot-dns-easydns",
            "certbot-dns-he-ddns",
            "certbot-dns-namecheap",
            "certbot-regru",
            "pyacmedns",
            "pynamecheap",
            "sh-nic-api",
        }
    )

    def test_every_source_only_package_is_one_the_build_group_builds(self) -> None:
        lock = tomllib.loads(LOCK.read_text())
        source_only = {
            normalized(package["name"])
            for package in lock["package"]
            if package.get("sdist") and not package.get("wheels")
        }
        self.assertEqual(source_only, self.BUILT_WITH_SETUPTOOLS)

    def test_the_build_group_is_setuptools_from_a_hashed_wheel(self) -> None:
        project = tomllib.loads(PROJECT.read_text())
        self.assertEqual(project["dependency-groups"]["build"], ["setuptools"])
        lock = tomllib.loads(LOCK.read_text())
        setuptools = [p for p in lock["package"] if p["name"] == "setuptools"]
        self.assertEqual(len(setuptools), 1)
        self.assertTrue(setuptools[0]["wheels"])
        self.assertTrue(
            all(wheel["hash"].startswith("sha256:") for wheel in setuptools[0]["wheels"])
        )

    def test_the_python_2_logging_package_is_not_built(self) -> None:
        lock = tomllib.loads(LOCK.read_text())
        self.assertNotIn("logging", {package["name"] for package in lock["package"]})
