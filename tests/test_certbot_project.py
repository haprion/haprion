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
