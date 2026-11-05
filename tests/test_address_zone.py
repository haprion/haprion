"""An address with a zone ID is never an address that becomes configuration (B450, X01).

Python 3.13's `ipaddress` takes `fe80::1%` followed by nearly anything, a line
break included; the generator writes the text as it stands. Every place that
validates an address and then writes it refuses the zone through one helper.
"""

from __future__ import annotations

import unittest
from typing import Any

from haprion import address_ranges, cluster_settings
from haprion.config import ConfigError, check_allow_entries, parse_network
from haprion.proxy_model import ModelError, load_proxy
from tests.test_proxy_model import with_lines

ZONED = ("2001:db8::1%x\nglobal", "fe80::1%eth0", "2001:db8::1%a b")
ZONED_NETWORKS = ("2001:db8::1%x\nglobal/128", "fe80::1%eth0/128", "2001:db8::1%a b/128")


class TheHelper(unittest.TestCase):
    def test_a_plain_address_and_network_pass_and_a_zone_does_not(self) -> None:
        self.assertEqual(str(address_ranges.plain_address("192.0.2.1")), "192.0.2.1")
        self.assertEqual(str(address_ranges.plain_address("2001:DB8::1")), "2001:db8::1")
        self.assertEqual(
            str(address_ranges.plain_network("2001:db8::/32", strict=True)), "2001:db8::/32"
        )
        self.assertEqual(
            str(address_ranges.plain_network("192.0.2.1", strict=False)), "192.0.2.1/32"
        )
        for value in (
            *ZONED,
            "192.0.2.1\n",
            " 192.0.2.1",
            "192.0.2.1 # x",
            "\uff11" + "92" + ".0.2.1",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                address_ranges.plain_address(value)
        for value in (*ZONED_NETWORKS, "192.0.2.0/24\n"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                address_ranges.plain_network(value, strict=False)


def _object(extra: str) -> bytes:
    return with_lines(("routes:", extra + "\nroutes:"))


class TheObjectModel(unittest.TestCase):
    def refused(self, document: bytes) -> None:
        with self.assertRaises(ModelError):
            load_proxy("shop", document)

    def test_a_server_host_and_address(self) -> None:
        for value in ZONED:
            with self.subTest(value=value):
                self.refused(with_lines(("host: 192.0.2.10", "host: " + _quoted(value))))
                self.refused(
                    with_lines(
                        (
                            "host: 192.0.2.10",
                            "host: backend.example.com\n        address: " + _quoted(value),
                        )
                    )
                )

    def test_the_three_source_lists(self) -> None:
        for value in (*ZONED, *ZONED_NETWORKS):
            with self.subTest(value=value):
                for field in ("allow_from", "deny_from"):
                    self.refused(with_lines(("routes:", f"{field}: [{_quoted(value)}]\nroutes:")))
                self.refused(
                    with_lines(
                        (
                            "routes:",
                            "access:\n  - action: deny\n    source: ["
                            + _quoted(value)
                            + "]\nroutes:",
                        )
                    )
                )


def _quoted(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace("\n", "\\n") + '"'


class TheSettingsAndNetwork(unittest.TestCase):
    def test_log_target_and_sources(self) -> None:
        for value in ZONED:
            with self.subTest(value=value), self.assertRaises(ConfigError):
                cluster_settings.load_mapping(
                    {"log_targets": {"central": {"address": value, "port": 514}}}
                )
        for value in (*ZONED, *ZONED_NETWORKS):
            with self.subTest(value=value):
                with self.assertRaises(ConfigError):
                    cluster_settings.load_mapping({"metrics": {"port": 9100, "sources": [value]}})
                with self.assertRaises(ConfigError):
                    cluster_settings.load_mapping({"not_logged_from": [value]})

    def test_a_network_group_a_vip_a_source_and_an_allow_entry(self) -> None:
        for value in ZONED_NETWORKS:
            with self.subTest(value=value), self.assertRaises(ConfigError):
                _network({"networks": {"office": [value]}})
            with self.subTest(value=value), self.assertRaises(ValueError):
                check_allow_entries([value])
        for value in ZONED:
            with self.subTest(value=value):
                with self.assertRaises(ConfigError):
                    _network({"vips": {"edge": {"address": value}}})
                with self.assertRaises(ConfigError):
                    _network({"sources": {"out": value}})


def _network(raw: Any) -> Any:
    return parse_network(raw, vip="192.0.2.1", location="network")


if __name__ == "__main__":
    unittest.main()
