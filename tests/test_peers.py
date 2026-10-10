from __future__ import annotations

import socket
import unittest
from dataclasses import dataclass
from typing import Any

from haprion import peers
from haprion.config import ConfigError, Node


@dataclass
class Nodes:
    nodes: tuple[Node, ...]


def answer(*addresses: str) -> list[tuple[Any, ...]]:
    return [
        (
            socket.AF_INET6 if ":" in address else socket.AF_INET,
            socket.SOCK_STREAM,
            6,
            "",
            (address, 0),
        )
        for address in addresses
    ]


CLUSTER = Nodes((Node("node-a", "node-a.example.com"), Node("node-b", "192.0.2.2")))


class EachNodeHasOneAddress(unittest.TestCase):
    def lookup(self, table: dict[str, list[tuple[Any, ...]]]) -> peers.Lookup:
        def find(host: str, *_: object, **__: object) -> list[tuple[Any, ...]]:
            if host not in table:
                raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
            return table[host]

        return find

    def test_names_and_addresses_in_the_clusters_order(self) -> None:
        lookup = self.lookup(
            {
                "node-a.example.com": answer("192.0.2.1", "192.0.2.1"),
                "192.0.2.2": answer("192.0.2.2"),
            }
        )
        self.assertEqual(
            peers.addresses(CLUSTER, lookup),  # type: ignore[arg-type]
            (("node-a", "192.0.2.1"), ("node-b", "192.0.2.2")),
        )

    def test_a_name_that_does_not_resolve_is_refused_by_node(self) -> None:
        lookup = self.lookup({"192.0.2.2": answer("192.0.2.2")})
        with self.assertRaisesRegex(ConfigError, "node-a.example.com for node node-a"):
            peers.addresses(CLUSTER, lookup)  # type: ignore[arg-type]

    def test_two_addresses_are_not_chosen_between(self) -> None:
        lookup = self.lookup(
            {
                "node-a.example.com": answer("192.0.2.1", "2001:db8::1"),
                "192.0.2.2": answer("192.0.2.2"),
            }
        )
        with self.assertRaisesRegex(ConfigError, "exactly one address"):
            peers.addresses(CLUSTER, lookup)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
