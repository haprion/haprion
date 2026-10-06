"""What a node makes of dnsdist's counters (Fas 19a B4, 26-10-06).

The parsing is extracted from `install/node/haproxy-node-status` verbatim and
run against text in dnsdist 2.1.2's own shape, as `test_node_runtime_stat`
does for `show stat`: the script is installed on the nodes rather than
imported. `test_dnsdist_behaviour` runs the same function against a real
dnsdist serving the generated configuration.
"""

from __future__ import annotations

import json
import re
import unittest
from collections.abc import Callable
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from haproxy_mgmt import dnsdist_config

SCRIPT = Path(__file__).resolve().parents[1] / "install" / "node" / "haproxy-node-status"
PARSING = re.compile(r"^DNS_METRICS = .*?(?=^def dns_counters\()", re.DOTALL | re.MULTILINE)


def parse_dns_metrics() -> Callable[[str], dict[str, Any] | None]:
    found = PARSING.search(SCRIPT.read_text())
    assert found, "the parsing is no longer where the test extracts it from"  # noqa: S101
    namespace: dict[str, Any] = {"re": re}
    exec(found.group(0), namespace)  # noqa: S102 - the file under test, read from disk
    parse: Callable[[str], dict[str, Any] | None] = namespace["parse_dns_metrics"]
    return parse


#
# Lines as dnsdist 2.1.2 writes them (measured 26-10-06), with the help and type
# lines and a few series this parser does not read.
#
METRICS = """# HELP dnsdist_uptime Uptime of the dnsdist process in seconds
# TYPE dnsdist_uptime gauge
dnsdist_uptime 21
dnsdist_queries 12
dnsdist_rule_hits{id="web"} 7
dnsdist_rule_hits{id="web/tcp"} 2
dnsdist_rule_hits{id="web/refused"} 1
dnsdist_rule_hits{id="open"} 3
dnsdist_rule_hits{id="open/tcp"} 0
dnsdist_rule_hits{id="a3f1c2d4-e230-4f15-bb39-1f353a1774a8"} 9
dnsdist_server_status{server="web/s1",address="192.0.2.1:53"} 1
dnsdist_server_queries{server="web/s1",address="192.0.2.1:53"} 4
dnsdist_server_responses{server="web/s1",address="192.0.2.1:53"} 4
dnsdist_server_drops{server="web/s1",address="192.0.2.1:53"} 0
dnsdist_server_latency{server="web/s1",address="192.0.2.1:53"} 0.00304495
dnsdist_server_status{server="web/s2",address="192.0.2.2:53"} 0
dnsdist_server_queries{server="web/s2",address="192.0.2.2:53"} 2
dnsdist_server_responses{server="web/s2",address="192.0.2.2:53"} 1
dnsdist_server_latency{server="web/s2",address="192.0.2.2:53"} 1.5
dnsdist_server_status{server="open/s1",address="192.0.2.3:53"} 1
dnsdist_server_queries{server="open/s1",address="192.0.2.3:53"} 3
dnsdist_server_responses{server="open/s1",address="192.0.2.3:53"} 3
dnsdist_server_latency{server="open/s1",address="192.0.2.3:53"} 0
dnsdist_server_queries{server="unnamed",address="192.0.2.9:53"} 5
dnsdist_frontend_queries{frontend="192.0.2.20:53",proto="UDP",thread="0"} 5
"""


class ReadingDnsdistCounters(unittest.TestCase):
    def setUp(self) -> None:
        self.parse = parse_dns_metrics()

    def read(self, text: str = METRICS) -> dict[str, Any]:
        parsed = self.parse(text)
        assert parsed is not None
        return parsed

    def test_each_pool_is_counted_under_its_own_name(self) -> None:
        self.assertEqual(
            self.read()["pools"],
            [
                {"pool": "open", "queries": 3, "tcp_queries": 0, "refused": 0, "answered": 3},
                {"pool": "web", "queries": 7, "tcp_queries": 2, "refused": 1, "answered": 5},
            ],
        )

    def test_a_rule_without_a_name_is_no_pool(self) -> None:
        """dnsdist names it with a UUID, which fits a pool's name pattern."""

        pools = {row["pool"] for row in self.read()["pools"]}
        self.assertNotIn("a3f1c2d4-e230-4f15-bb39-1f353a1774a8", pools)

    def test_each_server_says_its_pool_its_verdict_and_its_counts(self) -> None:
        servers = self.read()["servers"]
        self.assertEqual(
            [(row["pool"], row["server"], row["status"]) for row in servers],
            [("open", "s1", "UP"), ("web", "s1", "UP"), ("web", "s2", "DOWN")],
        )
        web = {row["server"]: row for row in servers if row["pool"] == "web"}
        self.assertEqual((web["s2"]["queries"], web["s2"]["answered"]), (2, 1))
        self.assertNotIn("latency_us", web["s1"])

    def test_a_server_not_named_by_the_generator_is_left_out(self) -> None:
        self.assertNotIn("unnamed", {row["server"] for row in self.read()["servers"]})

    def test_the_uptime_is_dnsdists_own(self) -> None:
        self.assertEqual(self.read()["uptime_sec"], 21)

    def test_text_that_is_not_dnsdists_is_no_reading(self) -> None:
        self.assertIsNone(self.parse("<html>not found</html>\n"))
        self.assertIsNone(self.parse(""))

    def test_what_it_reports_is_what_the_status_contract_describes(self) -> None:
        schema = json.loads(
            (SCRIPT.parents[2] / "schemas" / "v1" / "haproxy-status.schema.json").read_text()
        )
        listener = Draft202012Validator(
            schema["$defs"]["node_status"]["properties"]["dns_listener"]
        )
        for counters in (self.read(), None):
            reported = {"version": "2.1.2-1pdns.trixie", "active": True, "counters": counters}
            self.assertEqual(list(listener.iter_errors(reported)), [])
        self.assertTrue(list(listener.iter_errors({**reported, "counters": {"pools": []}})))

    def test_the_node_asks_the_port_the_generator_serves_on(self) -> None:
        self.assertIn(
            f'DNS_METRICS = "http://127.0.0.1:{dnsdist_config.STATS_PORT}/metrics"',
            SCRIPT.read_text(),
        )


if __name__ == "__main__":
    unittest.main()
