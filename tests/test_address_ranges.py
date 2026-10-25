"""Every list that takes address ranges refuses host bits when written, in one text.

Review 26-10-24, 15-06: `192.0.2.1/24` was widened to the network without a word
in an object's `allow_from`, `deny_from`, `exempt` and rule `source` and in a
network group, and refused - in words of its own each time - by the cluster
settings and a receiver's whitelist. Now each refuses it when it is written,
in `address_ranges.HOST_BITS`. What is already stored is read as it was: an
object or group saved before the rule keeps loading.
"""

from __future__ import annotations

import unittest
from collections.abc import Callable
from typing import Any

from haprion import address_ranges, cluster_settings
from haprion.config import ConfigError, check_allow_entries, parse_network
from haprion.proxy_model import load_proxy
from tests.test_proxy_model import with_lines

HOST_BITS = "192.0.2.1/24"


def _object(block: str) -> Callable[[str], Any]:
    def load(entry: str) -> Any:
        return load_proxy("shop", with_lines(("routes:", block.format(entry=entry) + "\nroutes:")))

    return load


def _network(entry: str) -> Any:
    return parse_network(
        {"networks": {"office": [entry]}}, vip="192.0.2.20", location="managed/network.yaml"
    )


#
# Every list a stored document carries, as the write paths read it.
#
WRITTEN: dict[str, Callable[[str], Any]] = {
    "allow_from": _object("allow_from: [{entry}]"),
    "deny_from": _object("deny_from:\n  sources: [{entry}]"),
    "a rule's source": _object("deny_rules:\n  - name: a\n    path: /x\n    source: [{entry}]"),
    "dynamic_block.exempt": _object(
        "dynamic_block:\n  max_errors: 5\n  block_for: 1m\n  exempt: [{entry}]"
    ),
    "a network group": _network,
}
#
# The lists that never took host bits, stored or not.
#
ALWAYS: dict[str, Callable[[str], Any]] = {
    "the cluster settings' sources": lambda entry: cluster_settings.load_document(
        f"metrics: {{port: 8405, sources: [{entry}]}}\n".encode()
    ),
    "a receiver's whitelist": lambda entry: check_allow_entries([entry]),
}


class HostBits(unittest.TestCase):
    def test_every_list_refuses_them_when_written_in_one_text(self) -> None:
        for name, read in {**WRITTEN, **ALWAYS}.items():
            with self.subTest(list=name):
                with (
                    address_ranges.writing(),
                    self.assertRaises((ConfigError, ValueError)) as caught,
                ):
                    read(HOST_BITS)
                self.assertIn(address_ranges.HOST_BITS, str(caught.exception))
                with address_ranges.writing():
                    read("192.0.2.0/24")
                    read("192.0.2.1")

    def test_what_is_stored_is_read_as_it_was(self) -> None:
        for name, read in WRITTEN.items():
            with self.subTest(list=name):
                self.assertIn("192.0.2.0/24", repr(read(HOST_BITS)))

    def test_writing_ends_with_its_block(self) -> None:
        with address_ranges.writing():
            self.assertTrue(address_ranges.refused(HOST_BITS))
        self.assertFalse(address_ranges.refused(HOST_BITS))
        self.assertFalse(address_ranges.refused("192.0.2.0/24"))
        self.assertFalse(address_ranges.refused("office"))


if __name__ == "__main__":
    unittest.main()
