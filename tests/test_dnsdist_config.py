"""Where a dns object may sit, and what the generator refuses around it (B249).

`test_dnsdist_behaviour` runs the file; this holds the decisions around it that
need no dnsdist: which collisions are refused, that a cluster without a dns
object carries no file, and that a dns object leaves HAProxy's files alone.
"""

from __future__ import annotations

import socket
import unittest
from unittest import mock

from haprion import dnsdist_config
from haprion.cluster_settings import NOTHING, ClusterSettings, Metrics
from haprion.config import Vip
from haprion.generate import GeneratorError, generate
from haprion.proxy_model import Proxy, load_proxy
from haprion.reservations import Reservations

VIPS = {"main": Vip("main", "192.0.2.10", source="192.0.2.20")}


def resolver(port: int = 53, name: str = "resolver") -> Proxy:
    return load_proxy(
        name,
        f"""schema: 1
name: {name}
listen: {{protocol: dns, port: {port}}}
backend: {name}-dns
allow_from: [192.0.2.0/24]
backends:
  {name}-dns:
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
        self.assertIn('PoolAction("dns")', conf)

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


NAMED_DOCUMENT = """schema: 1
name: resolver
listen: {{protocol: dns, port: 53}}
backend: dns
backends:
  dns: {{balance: roundrobin, servers: [{{host: {host}, port: 53{address}}}, {{host: 198.51.100.54, port: 53}}]}}
"""


def named(host: str = "ns1.example.com", address: str | None = "198.51.100.53") -> Proxy:
    saved = f", address: {address}" if address else ""
    return load_proxy("resolver", NAMED_DOCUMENT.format(host=host, address=saved).encode())


class ANamedServerIsWrittenWithItsSavedAddress(unittest.TestCase):
    """B252, B261: the name is looked up when the object is saved; publishing looks nothing up."""

    def conf(self, proxy: Proxy) -> str:
        with mock.patch("socket.getaddrinfo", side_effect=AssertionError("looked up")):
            layer = generate([proxy], vips=VIPS, default_vip="main")
        return layer.dns_files[dnsdist_config.FILE]

    def test_the_saved_address_is_written_with_the_name_beside_it(self) -> None:
        conf = self.conf(named())

        self.assertIn('newServer({address="198.51.100.53:53", name="dns/s1"', conf)
        self.assertRegex(conf, r'name="dns/s1".*\) -- looked up from ns1\.example\.com\n')
        self.assertNotIn("looked up from 198.51.100.54", conf)

    def test_a_name_saved_without_an_address_refuses_the_publish(self) -> None:
        with self.assertRaisesRegex(GeneratorError, "ns1.example.com has no address saved"):
            self.conf(named(address=None))


class SavingLooksTheNamesUp(unittest.TestCase):
    """`with_addresses`: what saving a dns object does (B261)."""

    def test_each_name_gets_the_address_it_has_now(self) -> None:
        asked: list[str] = []

        def resolve(host: str) -> str:
            asked.append(host)
            return "198.51.100.60"

        stale = NAMED_DOCUMENT.format(host="ns1.example.com", address=", address: 198.51.100.53")
        saved = dnsdist_config.with_addresses("resolver", stale, resolve)
        proxy = load_proxy("resolver", saved.encode())

        self.assertEqual(asked, ["ns1.example.com"])
        self.assertEqual(
            [(s.host, s.address) for s in proxy.backends["dns"].servers],
            [("ns1.example.com", "198.51.100.60"), ("198.51.100.54", None)],
        )

    def test_a_name_that_does_not_resolve_refuses_the_save(self) -> None:
        def resolve(host: str) -> str:
            raise dnsdist_config.Unresolved(f"{host} does not resolve on the manager")

        with self.assertRaisesRegex(dnsdist_config.Unresolved, "does not resolve"):
            dnsdist_config.with_addresses(
                "resolver", NAMED_DOCUMENT.format(host="ns1.example.com", address=""), resolve
            )

    def test_an_object_that_is_not_dns_is_not_looked_up(self) -> None:
        document = """schema: 1
name: shop
listen: {protocol: tcp, port: 8080}
backend: web
backends:
  web: {servers: [{host: app.example.com, port: 80}]}
"""
        saved = dnsdist_config.with_addresses("shop", document, lambda _host: "not asked")

        self.assertNotIn("address", saved)


class OnlyADnsNameCarriesAnAddress(unittest.TestCase):
    def test_an_address_beside_an_address_is_refused(self) -> None:
        document = NAMED_DOCUMENT.format(host="198.51.100.55", address=", address: 198.51.100.53")

        with self.assertRaisesRegex(Exception, "belongs beside a name"):
            load_proxy("resolver", document.encode())

    def test_a_saved_address_on_a_tcp_object_is_refused(self) -> None:
        document = """schema: 1
name: shop
listen: {protocol: tcp, port: 8080}
backend: web
backends:
  web: {balance: roundrobin, servers: [{host: app.example.com, port: 80, address: 198.51.100.9}]}
"""
        with self.assertRaisesRegex(Exception, "dns object's servers only"):
            load_proxy("shop", document.encode())


class TheLookup(unittest.TestCase):
    def test_the_lookup_takes_one_address_and_refuses_a_choice(self) -> None:
        def answer(*addresses: str) -> list[tuple[object, ...]]:
            return [(0, 0, 0, "", (address, 0)) for address in addresses]

        cases = (
            (("198.51.100.53", "2001:db8::53"), "198.51.100.53"),
            (("2001:db8::53",), "2001:db8::53"),
        )
        for addresses, expected in cases:
            with (
                self.subTest(addresses),
                mock.patch("socket.getaddrinfo", return_value=answer(*addresses)),
            ):
                self.assertEqual(dnsdist_config.lookup("ns1.example.com"), expected)
        with (
            mock.patch("socket.getaddrinfo", return_value=answer("198.51.100.53", "198.51.100.54")),
            self.assertRaisesRegex(dnsdist_config.Unresolved, "several addresses"),
        ):
            dnsdist_config.lookup("ns1.example.com")
        with (
            mock.patch(
                "socket.getaddrinfo", side_effect=socket.gaierror(-2, "Name or service not known")
            ),
            self.assertRaisesRegex(dnsdist_config.Unresolved, "does not resolve"),
        ):
            dnsdist_config.lookup("ns1.example.com")


class PrometheusReadsDnsdist(unittest.TestCase):
    """B253: with the cluster's exporter, dnsdist's statistics are served to its sources too."""

    def file(self, settings: ClusterSettings = NOTHING) -> str:
        layer = generate([resolver()], vips=VIPS, default_vip="main", settings=settings)
        return layer.dns_files[dnsdist_config.FILE]

    def test_without_the_exporter_only_the_node_reads_them(self) -> None:
        text = self.file()
        self.assertIn(f'webserver("127.0.0.1:{dnsdist_config.STATS_PORT}")', text)
        self.assertIn('acl="127.0.0.1/32"', text)

    def test_with_the_exporter_its_sources_read_them_on_every_address(self) -> None:
        text = self.file(
            ClusterSettings(
                metrics=Metrics(port=8405, sources=("198.51.100.0/24", "203.0.113.7/32"))
            )
        )
        self.assertIn(f'webserver("0.0.0.0:{dnsdist_config.STATS_PORT}")', text)
        self.assertIn('acl="127.0.0.1/32, 198.51.100.0/24, 203.0.113.7/32"', text)
        self.assertIn("apiRequiresAuthentication=true", text)

    def test_an_object_on_the_statistics_port_is_refused_once_they_are_served(self) -> None:
        settings = ClusterSettings(metrics=Metrics(port=8405, sources=("198.51.100.0/24",)))
        tcp = load_proxy(
            "nine",
            f"""schema: 1
name: nine
listen: {{protocol: tcp, port: {dnsdist_config.STATS_PORT}}}
backend: nine-pool
backends:
  nine-pool: {{balance: roundrobin, servers: [{{host: 198.51.100.9, port: 9}}]}}
""".encode(),
        )
        self.assertIn("Prometheus reads", refusal(resolver(), tcp, settings=settings))
        generate([resolver(), tcp], vips=VIPS, default_vip="main")


if __name__ == "__main__":
    unittest.main()
