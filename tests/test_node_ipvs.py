"""What a node reports of its IPVS virtual servers (Fas 19b, B256).

The reading is extracted from `install/node/haproxy-node-status` verbatim, as
`test_node_dns_metrics` does: the script is installed on the nodes rather than
imported. The ipvsadm text is built in ipvsadm 1.31's own layout, read from its
source (`print_title`, `print_service_entry`, `print_largenum` with `--exact`):
a service line padded to 33 columns, each receiver as `  -> ` padded to 28,
and every counter right-aligned with at least one space before it.
"""

from __future__ import annotations

import json
import re
import unittest
from collections.abc import Callable
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "install" / "node" / "haproxy-node-status"
READING = re.compile(r"^KEEPALIVED_IPVS = .*?(?=^def ipvs_summary\()", re.DOTALL | re.MULTILINE)


def reading() -> dict[str, Any]:
    found = READING.search(SCRIPT.read_text())
    assert found, "the reading is no longer where the test extracts it from"  # noqa: S101
    namespace: dict[str, Any] = {"re": re, "Path": Path}
    exec(found.group(0), namespace)  # noqa: S102 - the file under test, read from disk
    return namespace


def counter(value: int) -> str:
    """`print_largenum` with FMT_EXACT: width 9, or one more than the digits."""

    digits = len(str(value))
    return f"{value:>{9 if digits <= 8 else digits + 1}}"


def service(protocol: str, endpoint: str, *counters: int) -> str:
    return f"{f'{protocol:<4} {endpoint}':<33}" + "".join(counter(c) for c in counters)


def receiver(endpoint: str, *counters: int) -> str:
    return f"  -> {endpoint:<28}" + "".join(counter(c) for c in counters)


TABLE = "\n".join(
    [
        "IP Virtual Server version 1.2.1 (size=4096)",
        f"{'Prot LocalAddress:Port':<33} {'Conns':>8} {'InPkts':>8} {'OutPkts':>8} "
        f"{'InBytes':>8} {'OutBytes':>8}",
        "  -> RemoteAddress:Port",
        service("UDP", "192.0.2.20:514", 7027, 7027, 0, 1617210, 0),
        receiver("192.0.2.71:514", 3514, 3514, 0, 808780, 0),
        receiver("192.0.2.72:1514", 3513, 3513, 0, 808430, 0),
        service("UDP", "[2001:db8::20]:514", 0, 123456789012, 0, 9876543210123, 0),
        receiver("[2001:db8::71]:514", 0, 123456789012, 0, 9876543210123, 0),
        service("TCP", "192.0.2.20:80", 5, 50, 40, 5000, 4000),
        "FWM  7                                  0        0        0        0        0",
        "",
    ]
)


class ReadingTheKernelsTable(unittest.TestCase):
    def setUp(self) -> None:
        self.parse: Callable[[str], list[dict[str, Any]]] = reading()["parse_ipvs_stats"]

    def test_each_virtual_server_with_its_receivers_and_the_counters_in(self) -> None:
        services = self.parse(TABLE)

        self.assertEqual(
            services[0],
            {
                "protocol": "udp",
                "address": "192.0.2.20",
                "port": 514,
                "packets": 7027,
                "bytes": 1617210,
                "receivers": [
                    {"address": "192.0.2.71", "port": 514, "packets": 3514, "bytes": 808780},
                    {"address": "192.0.2.72", "port": 1514, "packets": 3513, "bytes": 808430},
                ],
            },
        )

    def test_an_ipv6_service_and_counters_past_the_column_width(self) -> None:
        """`--exact` widens a column rather than abbreviating to K, M or G."""

        six = self.parse(TABLE)[1]

        self.assertEqual((six["address"], six["port"]), ("2001:db8::20", 514))
        self.assertEqual((six["packets"], six["bytes"]), (123456789012, 9876543210123))
        self.assertEqual(six["receivers"][0]["address"], "2001:db8::71")

    def test_headers_and_a_firewall_mark_are_passed_over(self) -> None:
        self.assertEqual(
            [(entry["protocol"], entry["port"]) for entry in self.parse(TABLE)],
            [("udp", 514), ("udp", 514), ("tcp", 80)],
        )

    def test_an_empty_table_is_no_services(self) -> None:
        self.assertEqual(self.parse("\n".join(TABLE.splitlines()[:3])), [])

    def test_an_unreadable_service_takes_its_receivers_with_it(self) -> None:
        """Without `--exact` ipvsadm writes 1617K: the line is not read as a count,
        and its receivers are not counted under the service before it."""

        table = TABLE.replace(
            service("UDP", "[2001:db8::20]:514", 0, 123456789012, 0, 9876543210123, 0),
            f"{'UDP  [2001:db8::20]:514':<33}        0   123456M        0   9876G        0",
        )

        services = self.parse(table)

        self.assertEqual([entry["address"] for entry in services], ["192.0.2.20", "192.0.2.20"])
        self.assertEqual(len(services[0]["receivers"]), 2)

    def test_what_it_reads_is_what_the_status_schema_allows(self) -> None:
        schema = json.loads((ROOT / "schemas" / "v1" / "haproxy-status.schema.json").read_text())
        section = schema["$defs"]["node_status"]["properties"]["ipvs"]
        document = {
            "ipvsadm": True,
            "published": True,
            "published_sha256": "0" * 64,
            "installed": True,
            "installed_sha256": "0" * 64,
            "included": True,
            "services": self.parse(TABLE),
        }

        Draft202012Validator(section).validate(document)
        Draft202012Validator(section).validate({**document, "services": None, "ipvsadm": False})


class TheIncludeAtTheTop(unittest.TestCase):
    PATH = "/etc/keepalived/ipvs.conf"

    def setUp(self) -> None:
        self.included: Callable[[str, str], bool] = reading()["top_level_include"]

    def test_outside_every_block_with_a_trailing_comment(self) -> None:
        text = (
            f"vrrp_instance a {{\n  virtual_ipaddress {{\n  }}\n}}\ninclude {self.PATH}  # syslog\n"
        )

        self.assertTrue(self.included(text, self.PATH))

    def test_inside_a_block_or_commented_out_is_not(self) -> None:
        for text in (
            f"vrrp_instance a {{\n    include {self.PATH}\n}}\n",
            f"# include {self.PATH}\n",
            f"!include {self.PATH}\n",
            f"include {self.PATH}.old\n",
            "include /etc/keepalived/addresses.conf\n",
        ):
            with self.subTest(text):
                self.assertFalse(self.included(text, self.PATH))

    def test_a_brace_in_a_comment_does_not_change_the_depth(self) -> None:
        text = f"global_defs {{  # {{ {{\n}}\ninclude {self.PATH}\n"

        self.assertTrue(self.included(text, self.PATH))


if __name__ == "__main__":
    unittest.main()
