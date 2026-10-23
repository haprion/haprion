"""The manager's packages against what apt's lists offer, without asking the internet (B357)."""

from __future__ import annotations

import gzip
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from haprion import package_inventory
from haprion.package_inventory import Behind, Reader

STATUS = """\
Package: haprion-cli
Status: install ok installed
Priority: optional
Version: 0.99.0+git20261101120000.0123456789ab
Description: the engine
 a continuation line: Version: 9.9.9

Package: haprion-ui
Status: install ok installed
Version: 0.99.0+git20261101120000.0123456789ab~ubuntu26.04

Package: haprion-certbot
Status: deinstall ok config-files
Version: 5.8.0

Package: haproxy
Status: install ok installed
Version: 3.4.6-1ppa1~resolute
"""

PROJECT = """\
Package: haprion-cli
Version: 0.99.0+git20261101120000.0123456789ab
Architecture: all

Package: haprion-cli
Version: 0.99.1+git20261108120000.89abcdef0123
Architecture: all

Package: haprion-ui
Version: 0.99.0+git20261101120000.0123456789ab~ubuntu26.04

Package: haprion-certbot
Version: 5.9.0
"""

DISTRIBUTION = """\
Package: haproxy
Version: 9.9.9-1

Package: haprion-lookalike-from-elsewhere
Version: 1.0
"""


class Fixture(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.status = self.root / "status"
        self.status.write_text(STATUS)
        self.lists = self.root / "lists"
        self.lists.mkdir()
        (self.lists / "example.org_haprion_dists_resolute_main_binary-amd64_Packages").write_text(
            PROJECT
        )
        with gzip.open(
            self.lists / "archive.example.org_ubuntu_dists_resolute_main_binary-amd64_Packages.gz",
            "wt",
        ) as stream:
            stream.write(DISTRIBUTION)
        (self.lists / "example.org_haprion_dists_resolute_InRelease").write_text("signed\n")


class WhatIsCompared(Fixture):
    def test_only_the_project_s_installed_packages(self) -> None:
        self.assertEqual(
            package_inventory.installed(self.status),
            {
                "haprion-cli": "0.99.0+git20261101120000.0123456789ab",
                "haprion-ui": "0.99.0+git20261101120000.0123456789ab~ubuntu26.04",
            },
        )

    def test_the_newest_each_list_offers_plain_or_compressed(self) -> None:
        offered = package_inventory.available(package_inventory._lists(self.lists))
        self.assertEqual(offered["haprion-cli"], "0.99.1+git20261108120000.89abcdef0123")
        self.assertEqual(offered["haprion-lookalike-from-elsewhere"], "1.0")
        self.assertNotIn("haproxy", offered)

    def test_a_package_behind_is_said_and_a_current_one_or_a_removed_one_is_not(self) -> None:
        self.assertEqual(
            Reader(self.status, self.lists).read(),
            [
                Behind(
                    "haprion-cli",
                    "0.99.0+git20261101120000.0123456789ab",
                    "0.99.1+git20261108120000.89abcdef0123",
                )
            ],
        )

    def test_no_lists_and_no_status_are_nothing_waiting(self) -> None:
        self.assertEqual(Reader(self.status, self.root / "absent").read(), [])
        self.assertEqual(package_inventory.available([self.root / "absent_Packages"]), {})


class ReadAgainOnlyWhenChanged(Fixture):
    def test_unchanged_files_are_not_read_again(self) -> None:
        reader = Reader(self.status, self.lists)
        first = reader.read()
        with mock.patch.object(package_inventory, "installed", side_effect=AssertionError):
            self.assertEqual(reader.read(), first)

    def test_an_apt_update_or_an_upgrade_is_read(self) -> None:
        reader = Reader(self.status, self.lists)
        self.assertEqual(len(reader.read()), 1)

        self.status.write_text(
            STATUS.replace(
                "0.99.0+git20261101120000.0123456789ab\n",
                "0.99.1+git20261108120000.89abcdef0123\n",
                1,
            )
        )
        stamp = self.status.stat().st_mtime_ns + 1_000_000_000
        os.utime(self.status, ns=(stamp, stamp))

        self.assertEqual(reader.read(), [])


if __name__ == "__main__":
    unittest.main()
