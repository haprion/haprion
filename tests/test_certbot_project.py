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


def normalized(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


class CertbotProjectTests(unittest.TestCase):
    def test_every_direct_dependency_is_present_once_in_the_lock(self) -> None:
        project = tomllib.loads(PROJECT.read_text())
        lock = tomllib.loads(LOCK.read_text())
        dependencies = project["project"]["dependencies"]
        direct = [normalized(PACKAGE_NAME.match(item).group()) for item in dependencies]
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


if __name__ == "__main__":
    unittest.main()
