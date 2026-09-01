"""A network edit rebuilds the whole managed layer from committed input."""

from __future__ import annotations

import unittest
from pathlib import Path

from haproxy_mgmt.config import Cluster, Node, UnknownHost
from haproxy_mgmt.managed_publish import managed_files


def cluster() -> Cluster:
    return Cluster(
        cluster_id="alpha",
        display_name="Alpha",
        vip="192.0.2.20",
        address_prefix=None,
        address_interface=None,
        vips={},
        default_vip="main",
        resolvers=None,
        sources={},
        networks={},
        unknown_host=UnknownHost(status=404),
        config_path=Path("/config"),
        publish_path=Path("/published"),
        node_path="node",
        validation_certs=Path("/certs"),
        default_certificate="example.com",
        certificate_ids=(),
        trusted_proxy_cidrs=(),
        nodes=(Node(name="node-a", mgmt_host="node-a.example.com"),),
    )


NETWORK = b"""vips:\n  main:\n    address: 192.0.2.20\n    source: 192.0.2.25\ndefault_vip: main\nnetworks:\n  office:\n  - 198.51.100.0/24\n"""
PROXY = b"""schema: 1\nname: shop\nhostnames: [shop.example.com]\nlisten:\n  protocol: http\nroutes:\n- path: /\n  backend: web\nbackends:\n  web:\n    balance: roundrobin\n    health:\n      type: disabled\n    servers:\n    - host: 198.51.100.10\n      port: 8080\n"""


class ManagedNetworkPublishTests(unittest.TestCase):
    def test_the_network_and_generated_config_are_one_snapshot(self) -> None:
        files = managed_files(
            {
                "managed/network.yaml": NETWORK,
                "managed/proxies/shop.yaml": PROXY,
                "managed/generated/1001-stale.cfg": b"stale\n",
            },
            network_document=NETWORK,
            cluster=cluster(),
        )

        self.assertEqual(files["managed/network.yaml"], NETWORK)
        self.assertEqual(files["managed/proxies/shop.yaml"], PROXY)
        self.assertNotIn("managed/generated/1001-stale.cfg", files)
        self.assertIn("managed/generated/1000-frontends.cfg", files)
        self.assertIn("source 192.0.2.25", files["managed/generated/1001-shop.cfg"].decode())

    def test_the_addresses_the_nodes_must_carry_are_part_of_the_same_snapshot(self) -> None:
        #
        # One publish, one version, both halves of the change. The generated
        # HAProxy configuration binds an address and this file is what puts it
        # on an interface; published separately they can disagree, and a
        # cluster that binds an address no node carries looks correct from
        # every side except the network's.
        #
        files = managed_files(
            {
                "managed/network.yaml": NETWORK,
                "managed/keepalived/addresses.conf": b"    198.51.100.99  # gone\n",
            },
            network_document=NETWORK,
            cluster=cluster(),
        )
        fragment = files["managed/keepalived/addresses.conf"].decode()

        self.assertIn("192.0.2.20", fragment)
        self.assertIn("192.0.2.25", fragment)
        # Derived, never carried over: an address removed from the document is
        # removed from the interface the nodes present.
        self.assertNotIn("198.51.100.99", fragment)

    def test_removing_a_vip_used_by_an_object_is_refused_before_commit(self) -> None:
        proxy = PROXY.replace(b"protocol: http", b"protocol: http\n  vip: retired")
        network = NETWORK.replace(b"  main:\n", b"  other:\n").replace(
            b"default_vip: main", b"default_vip: other"
        )
        with self.assertRaisesRegex(ValueError, "VIP retired"):
            managed_files(
                {"managed/proxies/shop.yaml": proxy}, network_document=network, cluster=cluster()
            )


if __name__ == "__main__":
    unittest.main()
