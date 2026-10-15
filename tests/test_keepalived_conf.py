"""Each node's keepalived.conf (B313), in the shape measured on the lab nodes 26-10-15."""

from __future__ import annotations

import re
import unittest
from dataclasses import replace

from haprion import keepalived_conf
from haprion.config import ConfigError
from haprion.managed_publish import managed_files
from haprion.release_layout import build_node_artifact
from tests.test_managed_publish import NETWORK, cluster

PAIR = (("node-a", "192.0.2.11"), ("node-b", "192.0.2.12"))


def render(node: str = "node-a", nodes: tuple[tuple[str, str], ...] = PAIR, **kw: object) -> str:
    return keepalived_conf.render(
        "alpha",
        router_id=7,
        nodes=nodes,
        node=node,
        interface=kw.get("interface", "eth0"),  # type: ignore[arg-type]
    )


def directive(text: str, name: str) -> list[str]:
    return re.findall(rf"^\s*{name}\b(.*)$", text, re.MULTILINE)


class TheShape(unittest.TestCase):
    def test_every_node_is_backup_without_preemption_and_checks_who_advertises(self) -> None:
        for node, _address in PAIR:
            with self.subTest(node=node):
                text = render(node)
                self.assertTrue(text.startswith(keepalived_conf.MARK + "\n"))
                self.assertEqual(directive(text, "state"), [" BACKUP"])
                self.assertEqual(len(directive(text, "nopreempt")), 1)
                self.assertEqual(len(directive(text, "check_unicast_src")), 1)
                self.assertEqual(directive(text, "virtual_router_id"), [" 7"])
                # No password: eight bytes of clear text, dropped by RFC 5798.
                self.assertNotIn("authentication", text)
                self.assertNotIn("auth_pass", text)

    def test_the_priority_follows_the_cluster_order(self) -> None:
        self.assertEqual(directive(render("node-a"), "priority"), [" 100"])
        self.assertEqual(directive(render("node-b"), "priority"), [" 90"])
        self.assertEqual(keepalived_conf.priority(20), 1)

    def test_each_node_names_itself_as_source_and_the_others_as_peers(self) -> None:
        text = render("node-b")
        self.assertEqual(directive(text, "unicast_src_ip"), [" 192.0.2.12"])
        peers = re.search(r"unicast_peer \{\n(.*?)\n    \}", text, re.DOTALL)
        assert peers
        self.assertEqual(peers.group(1).split(), ["192.0.2.11"])

    def test_a_node_alone_names_loopback_never_an_empty_list_or_itself(self) -> None:
        # Empty fell back to multicast; its own address made it warn every
        # second (measured 26-10-15).
        text = render("node-a", nodes=(("node-a", "192.0.2.11"),))
        peers = re.search(r"unicast_peer \{\n(.*?)\n    \}", text, re.DOTALL)
        assert peers
        self.assertEqual(peers.group(1).split(), ["127.0.0.1"])

    def test_the_address_list_and_the_ipvs_file_are_included_where_keepalived_reads_them(
        self,
    ) -> None:
        text = render()
        self.assertRegex(
            text, r"virtual_ipaddress \{\n\s+include /etc/keepalived/addresses\.conf\n"
        )
        self.assertRegex(text, r"(?m)^include /etc/keepalived/ipvs\.conf$")
        for state in ("MASTER", "BACKUP", "FAULT"):
            self.assertIn(f'"/usr/sbin/haprion-keepalived-state {state}"', text)

    def test_without_an_interface_the_node_fills_in_its_own(self) -> None:
        self.assertEqual(directive(render(interface=None), "interface"), [" @INTERFACE@"])
        self.assertEqual(directive(render(interface="ens18"), "interface"), [" ens18"])

    def test_a_node_outside_the_cluster_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            render("node-z")


class InTheRelease(unittest.TestCase):
    def files(
        self, router_id: int | None, addresses: tuple[tuple[str, str], ...] = PAIR
    ) -> dict[str, bytes]:
        return managed_files(
            {},
            network_document=NETWORK,
            cluster=replace(cluster(), vrrp_router_id=router_id),
            node_addresses=lambda: addresses,
        )

    def test_a_cluster_the_product_created_carries_one_file_per_node(self) -> None:
        files = self.files(9)
        self.assertIn(b"virtual_router_id 9", files["managed/keepalived/node-node-a.conf"])
        self.assertIn(b"priority 90", files["managed/keepalived/node-node-b.conf"])
        artifact = build_node_artifact(
            {**files, "core/haproxy.cfg": b"global\n", "manual/reservations.yaml": b"{}\n"}
        )
        self.assertIn("keepalived/node-node-a.conf", artifact)

    def test_a_cluster_from_before_carries_none(self) -> None:
        files = self.files(None)
        self.assertFalse([path for path in files if "/node-" in path])

    def test_without_the_addresses_nothing_is_written_and_the_publish_says_so(self) -> None:
        with self.assertRaisesRegex(ConfigError, "addresses"):
            managed_files(
                {},
                network_document=NETWORK,
                cluster=replace(cluster(), vrrp_router_id=9),
                node_addresses=None,
            )


if __name__ == "__main__":
    unittest.main()
