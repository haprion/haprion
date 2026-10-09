"""What a node measures about the keepalived address list it was given.

The three functions are extracted from `install/node/haprion-node-status`
verbatim and run against real files in a temporary directory, the way
`test_node_vip_detection` extracts the VIP parsing. The node script is not
importable - it is installed on a node, not packaged - and copying its logic
into the test would test the copy.

Why the node measures three things instead of answering one question: a release
activates HAProxy and the addresses in two steps, and the second one can fail
on its own. The node reports what it can see; the manager decides what it
means. See B57 and `deploy_plan.ReleaseTarget`.
"""

from __future__ import annotations

import hashlib
import re
import tempfile
import unittest
from pathlib import Path
from typing import Any

SCRIPT = Path(__file__).resolve().parents[1] / "install" / "node" / "haprion-node-status"
READING = re.compile(
    r"^def address_list\(path\):.*?(?=^def runtime_info\()", re.DOTALL | re.MULTILINE
)

LIST = "192.0.2.10/24 dev eth0  # vip main\n"
OTHER = "198.51.100.10/24 dev eth0  # vip main\n"

INCLUDING = """\
vrrp_instance alpha {
    interface eth0
    virtual_ipaddress {
        include %s
    }
}
"""


class WhatTheNodeReportsAboutItsAddresses(unittest.TestCase):
    def setUp(self) -> None:
        found = READING.search(SCRIPT.read_text())
        assert found, "the address reading is no longer where the test extracts it from"
        self.source = found.group(0)
        self.root = Path(tempfile.mkdtemp())
        self.published = self.root / "published.conf"
        self.installed = self.root / "installed.conf"
        self.config = self.root / "keepalived.conf"

    def read(self) -> dict[str, Any]:
        namespace: dict[str, Any] = {
            "Path": Path,
            "hashlib": hashlib,
            "MAX_KEEPALIVED_BYTES": 1024 * 1024,
            "KEEPALIVED_CONFIG": self.config,
            "KEEPALIVED_ADDRESSES": self.installed,
            "PUBLISHED_ADDRESSES": self.published,
            "read_config": _read_config,
        }
        exec(self.source, namespace)  # noqa: S102 - the file under test, read from disk
        addresses: dict[str, Any] = namespace["read_addresses"]()
        return addresses

    def summary(self, addresses: dict[str, Any]) -> str:
        namespace: dict[str, Any] = {"Path": Path, "hashlib": hashlib}
        exec(self.source, namespace)  # noqa: S102 - the file under test, read from disk
        return str(namespace["address_summary"](addresses))

    def test_a_node_carrying_the_published_list_reports_both_digests_equal(self) -> None:
        self.published.write_text(LIST)
        self.installed.write_text(LIST)
        self.config.write_text(INCLUDING % self.installed)

        addresses = self.read()

        self.assertEqual(addresses["published_sha256"], addresses["installed_sha256"])
        self.assertTrue(addresses["included"])
        self.assertEqual(self.summary(addresses), "installed and in use")

    def test_the_half_way_node_is_visible_as_two_different_digests(self) -> None:
        """The state a release hash cannot see.

        HAProxy took the new release; the address step failed and put the old
        list back. Nothing about the release says so.
        """

        self.published.write_text(LIST)
        self.installed.write_text(OTHER)
        self.config.write_text(INCLUDING % self.installed)

        addresses = self.read()

        self.assertNotEqual(addresses["published_sha256"], addresses["installed_sha256"])
        self.assertEqual(self.summary(addresses), "installed list differs from the release")

    def test_a_list_the_node_never_installed_is_absent_and_not_unreadable(self) -> None:
        self.published.write_text(LIST)
        self.config.write_text(INCLUDING % self.installed)

        addresses = self.read()

        self.assertIs(addresses["installed"], False)
        self.assertIsNone(addresses["installed_sha256"])
        self.assertEqual(self.summary(addresses), "published, not installed")

    def test_a_release_that_publishes_no_list_is_not_managing_addresses(self) -> None:
        """A cluster whose repository predates the generated list.

        An absent published file means the addresses are not managed from here.
        It must never read as an instruction to empty the node's.
        """

        self.installed.write_text(LIST)
        self.config.write_text(INCLUDING % self.installed)

        addresses = self.read()

        self.assertIs(addresses["published"], False)
        self.assertEqual(self.summary(addresses), "none published by this release")

    def test_a_list_that_is_installed_but_not_included_says_so(self) -> None:
        """The deliberate transitional state, and not an error.

        The include line is added by a person, one node at a time, and the node
        deploy exits 0 without it. The status has to show it because nothing
        else does.
        """

        self.published.write_text(LIST)
        self.installed.write_text(LIST)
        self.config.write_text("vrrp_instance alpha {\n    interface eth0\n}\n")

        addresses = self.read()

        self.assertIs(addresses["included"], False)
        self.assertEqual(self.summary(addresses), "installed, not included in keepalived.conf")

    def test_a_keepalived_config_that_cannot_be_read_leaves_the_include_unknown(self) -> None:
        self.published.write_text(LIST)
        self.installed.write_text(LIST)

        addresses = self.read()

        self.assertIsNone(addresses["included"])
        self.assertEqual(self.summary(addresses), "installed, include unknown")


def _read_config(path: Path) -> str | None:
    """The script's own reader, in the one line this extraction needs of it."""

    try:
        return path.read_text(encoding="utf-8")
    except Exception:
        return None


if __name__ == "__main__":
    unittest.main()
