"""How a node decides whether it currently holds the cluster's address.

The parsing is extracted from `install/node/haprion-node-status` verbatim and
run against real files in a temporary directory, the way
`test_node_keepalived_sync` extracts its shell function. That is deliberate:
the answer this code produces is not cosmetic. A node that cannot name the
address reports its ownership as unknown, and a deploy refuses to run at all
without a known owner - so a parser that quietly stops matching takes the whole
cluster's deployment path with it.

It does not prove that keepalived reads an included file the way this assumes.
That is a fact about a real node, measured on one (2026-09-01).
"""

from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import Any

SCRIPT = Path(__file__).resolve().parents[1] / "install" / "node" / "haprion-node-status"
PARSING = re.compile(r"^INTERFACE = re\.compile.*?(?=^def owns_vip\()", re.DOTALL | re.MULTILINE)

#
# The block as a managed node carries it after the address list became a
# generated file: one include and nothing else.
#
INCLUDING = """\
vrrp_instance alpha {
    state             BACKUP
    interface         eth0        # CHANGE: the interface carrying the VIP
    virtual_ipaddress {
        include /etc/keepalived/addresses.conf
    }
}
"""

#
# What `keepalived_fragment.render` writes, header and all.
#
ADDRESSES = """\
#
# Generated from managed/network.yaml. Do not edit on the node: the next
# deploy overwrites this file.
#
    192.0.2.10/24 dev eth0  # vip main
    192.0.2.15/24 dev eth0  # default source for vip main
"""


class ParsingTheNodeSConfiguration(unittest.TestCase):
    def setUp(self) -> None:
        found = PARSING.search(SCRIPT.read_text())
        assert found, "the parsing is no longer where the test extracts it from"
        self.source = found.group(0)
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)

    def parse(self, config: str, *, addresses: str | None = None) -> tuple[object, object]:
        path = self.root / "keepalived.conf"
        path.write_text(config.replace("/etc/keepalived/", f"{self.root}/"))
        if addresses is not None:
            (self.root / "addresses.conf").write_text(addresses)

        namespace: dict[str, Any] = {"re": re, "Path": Path, "KEEPALIVED_CONFIG": path}
        exec(self.source, namespace)  # noqa: S102 - the file under test, read from disk
        parsed: tuple[object, object] = namespace["parse_keepalived"]()
        return parsed

    def test_an_address_written_in_the_block_is_still_read(self) -> None:
        """The form every node used before the list was generated."""

        interface, vip = self.parse(
            INCLUDING.replace(
                "        include /etc/keepalived/addresses.conf\n",
                "        192.0.2.10\n        192.0.2.15\n",
            )
        )

        self.assertEqual(interface, "eth0")
        self.assertEqual(vip, "192.0.2.10")

    def test_an_address_reached_through_an_include_is_read(self) -> None:
        """The form a managed node carries, and the one this used to miss.

        Reading only the block finds no address at all, which reports the
        ownership as unknown on both nodes and blocks every deploy.
        """

        interface, vip = self.parse(INCLUDING, addresses=ADDRESSES)

        self.assertEqual(interface, "eth0")
        self.assertEqual(vip, "192.0.2.10")

    def test_the_interface_may_carry_the_comment_the_example_puts_there(self) -> None:
        """`install/examples/keepalived.conf.example` writes exactly this line."""

        interface, _ = self.parse(INCLUDING, addresses=ADDRESSES)

        self.assertEqual(interface, "eth0")

    def test_an_include_naming_a_file_that_is_not_there_is_unknown(self) -> None:
        """Not an address invented from somewhere else."""

        _, vip = self.parse(INCLUDING)

        self.assertIsNone(vip)

    def test_a_block_with_nothing_in_it_is_unknown(self) -> None:
        interface, vip = self.parse(
            INCLUDING.replace("        include /etc/keepalived/addresses.conf\n", "")
        )

        self.assertEqual(interface, "eth0")
        self.assertIsNone(vip)


if __name__ == "__main__":
    unittest.main()


class WhoWroteKeepalivedAndWhatTheNodeCarries(unittest.TestCase):
    """B313: the two readings that let the manager judge a node without keepalived."""

    REGION = re.compile(r"^KEEPALIVED_MARK = .*?(?=^def address_list\()", re.DOTALL | re.MULTILINE)

    def setUp(self) -> None:
        found = self.REGION.search(SCRIPT.read_text())
        assert found, "the readings are no longer where the test extracts them from"
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        self.conf = self.root / "keepalived.conf"
        self.answer: tuple[int, str] = (0, "[]")
        namespace: dict[str, Any] = {
            "json": __import__("json"),
            "KEEPALIVED_CONFIG": self.conf,
            "run": lambda *_argv: type(
                "Done", (), {"returncode": self.answer[0], "stdout": self.answer[1]}
            )(),
        }
        exec(found.group(0), namespace)  # noqa: S102 - verbatim functions from the node script
        self.namespace = namespace

    def test_missing_product_and_operator_are_told_apart(self) -> None:
        configured = self.namespace["keepalived_configured"]
        self.assertEqual(configured(), "missing")
        self.conf.write_text(
            "# Written by Haprion - a deploy replaces this file.\nvrrp_instance alpha {}\n"
        )
        self.assertEqual(configured(), "product")
        self.conf.write_text("vrrp_instance alpha {}\n")
        self.assertEqual(configured(), "operator")

    def test_the_mark_is_the_generator_s(self) -> None:
        from haprion import keepalived_conf  # noqa: PLC0415

        self.assertEqual(self.namespace["KEEPALIVED_MARK"], keepalived_conf.MARK)

    def test_every_ipv4_address_is_carried_and_a_failed_read_is_none(self) -> None:
        self.answer = (
            0,
            '[{"ifname": "lo", "addr_info": [{"family": "inet", "local": "127.0.0.1"}]},'
            ' {"ifname": "eth0", "addr_info": [{"family": "inet", "local": "192.0.2.11"},'
            ' {"family": "inet", "local": "192.0.2.10"}]}]',
        )
        self.assertEqual(
            self.namespace["carried_addresses"](), ["127.0.0.1", "192.0.2.10", "192.0.2.11"]
        )
        self.answer = (1, "")
        self.assertIsNone(self.namespace["carried_addresses"]())
