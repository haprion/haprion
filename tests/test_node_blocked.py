"""What a node makes of its dynamic blocking tables (B271).

Extracted from `install/node/haprion-node-status` verbatim and run against
output captured from HAProxy 3.4.6 (26-10-10), the way `test_node_peers` reads
`show peers`. The same functions read two live nodes in
`test_dynamic_block_live`.
"""

from __future__ import annotations

import ipaddress
import re
import unittest
from pathlib import Path
from typing import Any

SCRIPT = Path(__file__).resolve().parents[1] / "install" / "node" / "haprion-node-status"
PARSING = re.compile(r"^BLOCKED_TABLE = .*?(?=^def read_blocked\()", re.DOTALL | re.MULTILINE)

TABLES = """\
# table: mgd-main-http, type: ipv6, size:1048576, used:12
# table: web, type: ipv6, size:1048576, used:3
# table: mgd-shop-dynblock-rate, type: ipv6, size:1048576, used:40
# table: mgd-shop-dynblock, type: ipv6, size:1048576, used:2
# table: mgd-db-dynblock, type: ipv6, size:1048576, used:0

"""
ENTRIES = """\
# table: mgd-shop-dynblock, type: ipv6, size:1048576, used:2
0x7f149cc751c8: key=::ffff:192.0.2.7 use=0 exp=1793254 shard=0 gpc0=0
0x7f149cc751d0: key=2001:db8::7 use=1 exp=59000 shard=1 gpc0=0

"""


def parsing() -> dict[str, Any]:
    found = PARSING.search(SCRIPT.read_text())
    assert found, "the parsing is no longer where the test extracts it from"
    namespace: dict[str, Any] = {"re": re, "ipaddress": ipaddress}
    exec(found.group(0), namespace)  # noqa: S102 - the file under test, read from disk
    return namespace


class ReadingTheBlockedTables(unittest.TestCase):
    def setUp(self) -> None:
        self.parsing = parsing()

    def test_only_the_blocked_tables_count_by_object(self) -> None:
        self.assertEqual(self.parsing["parse_blocked_tables"](TABLES), {"shop": 2, "db": 0})

    def test_an_entry_is_an_address_and_its_time_left(self) -> None:
        self.assertEqual(
            self.parsing["parse_blocked_entries"](ENTRIES),
            [
                {"address": "192.0.2.7", "expires_in_ms": 1793254},
                {"address": "2001:db8::7", "expires_in_ms": 59000},
            ],
        )

    def test_the_listing_stops_at_a_hundred(self) -> None:
        many = "".join(
            f"0x1: key=::ffff:192.0.2.{index % 250} use=0 exp={index} gpc0=0\n"
            for index in range(150)
        )
        self.assertEqual(len(self.parsing["parse_blocked_entries"](many)), 100)

    def test_the_shape_is_the_generator_s_name(self) -> None:
        from haprion.generate import block_tables

        counted, blocked = block_tables("a-b_c")
        text = (
            f"# table: {counted}, type: ipv6, size:1, used:9\n"
            f"# table: {blocked}, type: ipv6, size:1, used:1\n"
        )
        self.assertEqual(self.parsing["parse_blocked_tables"](text), {"a-b_c": 1})


if __name__ == "__main__":
    unittest.main()
