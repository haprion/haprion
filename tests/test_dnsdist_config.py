"""Where a dns object may sit, and what the generator refuses around it (B249).

`test_dnsdist_behaviour` runs the file; this holds the decisions around it that
need no dnsdist: which collisions are refused, that a cluster without a dns
object carries no file, and that a dns object leaves HAProxy's files alone.
"""

from __future__ import annotations

import unittest

from haproxy_mgmt import dnsdist_config
from haproxy_mgmt.cluster_settings import ClusterSettings, Metrics
from haproxy_mgmt.config import Vip
from haproxy_mgmt.generate import GeneratorError, generate
from haproxy_mgmt.proxy_model import Proxy, load_proxy
from haproxy_mgmt.reservations import Reservations

VIPS = {"main": Vip("main", "192.0.2.10", source="192.0.2.20")}


def resolver(port: int = 53, name: str = "resolver") -> Proxy:
    return load_proxy(
        name,
        f"""schema: 1
name: {name}
listen: {{protocol: dns, port: {port}}}
backend: dns
allow_from: [192.0.2.0/24]
backends:
  dns:
    balance: roundrobin
    servers: [{{host: 198.51.100.53, port: 53}}]
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


def refusal(*proxies: Proxy, **options: object) -> str:
    with unittest.TestCase().assertRaises(GeneratorError) as raised:
        generate(list(proxies), vips=VIPS, default_vip="main", **options)  # type: ignore[arg-type]
    return str(raised.exception)


class WhereADnsObjectMaySit(unittest.TestCase):
    def test_a_cluster_without_one_carries_no_dnsdist_file(self) -> None:
        self.assertEqual(generate([SITE], vips=VIPS, default_vip="main").dns_files, {})

    def test_it_leaves_haproxys_files_as_they_were(self) -> None:
        alone = generate([SITE], vips=VIPS, default_vip="main")
        beside = generate([SITE, resolver()], vips=VIPS, default_vip="main")

        self.assertEqual(alone.configuration, beside.configuration)
        self.assertEqual(sorted(beside.object_parts), ["resolver", "shop"])

    def test_without_allow_from_nobody_is_refused_but_the_listener_still_routes(self) -> None:
        open_to_all = load_proxy(
            "resolver",
            b"""schema: 1
name: resolver
listen: {protocol: dns, port: 53}
backend: dns
backends:
  dns: {balance: roundrobin, servers: [{host: 198.51.100.53, port: 53}]}
""",
        )
        conf = generate([open_to_all], vips=VIPS, default_vip="main").dns_files[dnsdist_config.FILE]

        self.assertNotIn("NotRule", conf)
        self.assertIn('PoolAction("mgd-resolver-dns")', conf)

    def test_it_leaves_from_its_vips_source_unless_it_names_another(self) -> None:
        conf = generate([resolver()], vips=VIPS, default_vip="main").dns_files[dnsdist_config.FILE]

        self.assertIn('source="192.0.2.20"', conf)

    def test_two_on_one_address_and_port_are_refused(self) -> None:
        message = refusal(resolver(), resolver(name="other"))
        self.assertIn("both listen on main port 53", message)

    def test_a_port_the_cluster_serves_http_on_is_refused(self) -> None:
        self.assertIn("already serves http", refusal(SITE, resolver(port=80)))

    def test_a_reserved_port_is_refused(self) -> None:
        reserved = Reservations(tcp_ports=frozenset({53}))
        self.assertIn("reservations.yaml", refusal(resolver(), reservations=reserved))

    def test_the_metrics_port_is_refused_as_a_listener_and_as_the_statistics_port(self) -> None:
        on_listener = ClusterSettings(metrics=Metrics(port=53, sources=()))
        on_statistics = ClusterSettings(metrics=Metrics(port=dnsdist_config.STATS_PORT, sources=()))

        self.assertIn("metrics port 53", refusal(resolver(), settings=on_listener))
        self.assertIn("statistics", refusal(resolver(), settings=on_statistics))


if __name__ == "__main__":
    unittest.main()
