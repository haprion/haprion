"""Where a syslog object may sit, and what its IPVS file says (Fas 19b, B256).

The golden case `syslog/` holds the file to the byte; this holds the decisions
around it: which collisions are refused and which are not, the address family,
the file a cluster without a syslog object carries, and that a syslog object
leaves HAProxy's files alone. keepalived itself reads the file on the node
(`keepalived --config-test` before every reload), not here.
"""

from __future__ import annotations

import unittest

from haproxy_mgmt import ipvs_config
from haproxy_mgmt.config import Vip
from haproxy_mgmt.generate import GeneratorError, generate
from haproxy_mgmt.proxy_model import Proxy, load_proxy
from haproxy_mgmt.reservations import Reservations

VIPS = {
    "main": Vip("main", "192.0.2.10", source="192.0.2.20"),
    "v6": Vip("v6", "2001:db8::10"),
}


def logs(
    port: int = 514,
    name: str = "logs",
    *,
    vip: str = "main",
    host: str = "198.51.100.71",
    balance: str = "roundrobin",
    health: str = "{type: udp}",
) -> Proxy:
    return load_proxy(
        name,
        f"""schema: 1
name: {name}
listen: {{protocol: syslog, vip: {vip}, port: {port}}}
backend: {name}-receivers
backends:
  {name}-receivers:
    balance: {balance}
    health: {health}
    servers: [{{host: "{host}", port: 514}}]
""".encode(),
    )


def other(protocol: str, port: int, name: str) -> Proxy:
    return load_proxy(
        name,
        f"""schema: 1
name: {name}
listen: {{protocol: {protocol}, port: {port}}}
backend: {name}-pool
backends:
  {name}-pool:
    balance: roundrobin
    servers: [{{host: 198.51.100.53, port: {port}}}]
""".encode(),
    )


SITE = load_proxy(
    "shop",
    b"""schema: 1
name: shop
hostnames: [shop.example.com]
listen: {protocol: http}
routes: [{path: /, backend: web}]
backends:
  web: {balance: roundrobin, servers: [{host: 198.51.100.10, port: 8080}]}
""",
)


def produced(*proxies: Proxy, **options: object) -> str:
    return generate(list(proxies), vips=VIPS, default_vip="main", **options).ipvs  # type: ignore[arg-type]


def refusal(*proxies: Proxy, **options: object) -> str:
    with unittest.TestCase().assertRaises(GeneratorError) as raised:
        produced(*proxies, **options)
    return str(raised.exception)


class WhereASyslogObjectMaySit(unittest.TestCase):
    def test_a_cluster_without_one_carries_the_file_without_a_virtual_server(self) -> None:
        """The empty file is what removes the previous release's virtual servers."""

        text = produced(SITE)

        self.assertEqual(text, ipvs_config.HEADER)
        self.assertNotIn("virtual_server", text)

    def test_it_gets_no_haproxy_file_of_its_own(self) -> None:
        layer = generate([logs(), SITE], vips=VIPS, default_vip="main")

        self.assertNotIn("1001-logs.cfg", layer.configuration)
        self.assertNotIn("514", layer.configuration["1000-frontends.cfg"])
        self.assertIn("virtual_server 192.0.2.10 514 {", layer.ipvs)

    def test_two_syslog_objects_on_one_address_and_port_are_refused(self) -> None:
        message = refusal(logs(), logs(name="audit"))

        self.assertIn("audit and logs both listen on main port 514/udp", message)

    def test_a_dns_object_on_the_same_port_is_refused(self) -> None:
        """IPVS would take the datagrams before dnsdist's socket saw them."""

        self.assertIn("port 53/udp", refusal(logs(port=53), other("dns", 53, "resolver")))

    def test_a_tcp_object_or_the_http_port_may_share_the_number(self) -> None:
        """UDP and TCP are separate ports: syslog over TCP beside it is the usual case."""

        text = produced(
            logs(port=514), other("tcp", 514, "stream"), logs(port=80, name="web"), SITE
        )

        self.assertIn("virtual_server 192.0.2.10 80 {", text)

    def test_a_reserved_tcp_port_does_not_stop_it(self) -> None:
        reserved = Reservations(tcp_ports=frozenset({514}))

        self.assertIn("514", produced(logs(), reservations=reserved))

    def test_the_same_port_on_another_address_is_its_own(self) -> None:
        text = produced(logs(), logs(name="six", vip="v6", host="2001:db8::71"))

        self.assertIn("virtual_server 2001:db8::10 514 {", text)

    def test_a_receiver_of_the_other_address_family_is_refused(self) -> None:
        """NAT keeps the family; a v4 receiver behind a v6 address would never be reached."""

        self.assertIn("keeps the address family", refusal(logs(vip="v6")))


class WhatTheFileSays(unittest.TestCase):
    def test_each_balancing_name_is_its_scheduler(self) -> None:
        for balance, scheduler in (
            ("roundrobin", "rr"),
            ("source", "mh"),
            ("firstAvailable", "fo"),
        ):
            with self.subTest(balance):
                self.assertIn(f"lvs_sched {scheduler}\n", produced(logs(balance=balance)))

    def test_every_message_is_scheduled_on_its_own_and_nat_keeps_the_sender(self) -> None:
        text = produced(logs())

        self.assertIn("    protocol UDP\n    lvs_method NAT\n", text)
        self.assertIn("    ops\n", text)

    def test_fall_is_keepalived_retry_after_the_first_failure(self) -> None:
        text = produced(logs(health="{type: udp, fall: 4, interval: 1500ms}"))

        self.assertIn("retry 3\n", text)
        self.assertIn("delay_loop 1.5\n", text)
        self.assertIn("connect_timeout 5\n", text)

    def test_a_tcp_check_waits_one_interval_on_its_own_port(self) -> None:
        text = produced(logs(health="{type: tcp, port: 601, interval: 3s}"))

        self.assertIn(
            "TCP_CHECK {\n            connect_port 601\n            connect_timeout 3\n", text
        )

    def test_an_unchecked_pool_has_no_checker_and_no_timing(self) -> None:
        text = produced(logs(health="{type: disabled}"))

        self.assertNotIn("CHECK", text)
        self.assertNotIn("delay_loop", text)
        self.assertIn("real_server 198.51.100.71 514 {\n    }\n", text)

    def test_first_available_is_the_highest_weight_in_the_objects_order(self) -> None:
        """The kernel's `fo` picks by weight; list order alone changes when a receiver returns."""

        proxy = load_proxy(
            "standby",
            b"""schema: 1
name: standby
listen: {protocol: syslog, port: 514}
backend: pair
backends:
  pair:
    balance: firstAvailable
    servers: [{host: 198.51.100.72, port: 514}, {host: 198.51.100.71, port: 514},
              {host: 198.51.100.73, port: 514}]
""",
        )
        text = produced(proxy)

        self.assertIn("real_server 198.51.100.72 514 {\n        weight 3\n", text)
        self.assertIn("real_server 198.51.100.71 514 {\n        weight 2\n", text)
        self.assertIn("real_server 198.51.100.73 514 {\n        weight 1\n", text)
        self.assertNotIn("weight", produced(logs()))

    def test_the_manifest_sees_the_object(self) -> None:
        layer = generate([logs()], vips=VIPS, default_vip="main")

        self.assertEqual(layer.object_parts["logs"]["listener"], "192.0.2.10 514 udp\n")
        self.assertIn("real_server 198.51.100.71 514", layer.object_parts["logs"]["backends"])


if __name__ == "__main__":
    unittest.main()
