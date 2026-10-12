"""The cluster's own settings: external log targets and the metrics exporter (Fas 15).

Held here: the document has one parser and one canonical form; a target is an
address and never a name, because a name that does not resolve at a reload
fails the whole configuration; the exporter's port, which it takes on every
address, is refused where anything else already listens; and every managed
publish carries the settings over, so changing an object does not quietly
switch the cluster's logging off.
"""

from __future__ import annotations

import unittest

from haprion.cluster_settings import (
    DEFAULT_DISK_MIB,
    LOCATION,
    NOTHING,
    ClusterSettings,
    LogTarget,
    Metrics,
    dump_document,
    load_document,
)
from haprion.config import ConfigError
from haprion.generate import (
    CLUSTER_FILE,
    HTTP_TRAFFIC_LOG_FORMAT,
    TRAFFIC_LOG_PROFILE,
    GeneratedLayer,
    GeneratorError,
    generate,
)
from haprion.golden import GOLDEN, arguments, objects
from haprion.managed_publish import managed_files
from haprion.reservations import load_reservations
from tests.test_managed_publish import NETWORK, PROXY, cluster

GRAYLOG = b"""
log_targets:
  graylog:
    address: 192.0.2.20
    port: 6514
metrics:
  port: 8405
  sources: [192.0.2.0/24]
"""


class TheDocument(unittest.TestCase):
    def test_no_file_and_an_empty_one_are_nothing(self) -> None:
        self.assertEqual(load_document(None), NOTHING)
        self.assertEqual(load_document(b"{}"), NOTHING)
        self.assertEqual(dump_document(NOTHING), b"{}\n")

    def test_it_reads_with_defaults_and_writes_back_the_same(self) -> None:
        settings = load_document(GRAYLOG)
        self.assertEqual(
            settings,
            ClusterSettings(
                log_targets=(LogTarget("graylog", "192.0.2.20", 6514, DEFAULT_DISK_MIB, False),),
                metrics=Metrics(8405, ("192.0.2.0/24",)),
            ),
        )
        self.assertEqual(load_document(dump_document(settings)), settings)

    def test_a_target_is_an_address_and_never_a_name(self) -> None:
        for address in ("graylog.example.com", "localhost", "192.0.2.300", 7):
            with self.subTest(address=address), self.assertRaisesRegex(ConfigError, "address"):
                load_document(f"log_targets: {{g: {{address: {address}, port: 6514}}}}".encode())
        self.assertEqual(
            load_document(b"log_targets: {g: {address: '2001:db8::30', port: 6514}}")
            .log_targets[0]
            .address,
            "2001:db8::30",
        )

    def test_what_the_document_refuses(self) -> None:
        for document in (
            b"extra: 1",
            b"log_targets: {Graylog: {address: 192.0.2.20, port: 6514}}",
            b"log_targets: {g: {address: 192.0.2.20, port: 0}}",
            b"log_targets: {g: {address: 192.0.2.20, port: 6514, buffer_kib: 32}}",
            b"log_targets: {g: {address: 192.0.2.20, port: 6514, disk_mib: 32}}",
            b"log_targets: {g: {address: 192.0.2.20, port: 6514, disk_mib: 70000}}",
            b"log_targets: {g: {address: 192.0.2.20, port: 6514, disk_mib: '1g'}}",
            b"log_targets: {g: {address: 192.0.2.20, port: 6514, tls: 'yes'}}",
            b"log_targets: {g: {address: 192.0.2.20, port: 6514, colour: red}}",
            b"log_targets: {a: {address: 192.0.2.20, port: 6514}, b: {address: 192.0.2.20, port: 6514}}",
            b"log_targets: {a: {address: 192.0.2.1, port: 1}, b: {address: 192.0.2.2, port: 1},"
            b" c: {address: 192.0.2.3, port: 1}, d: {address: 192.0.2.4, port: 1},"
            b" e: {address: 192.0.2.5, port: 1}}",
            b"metrics: {port: 8405}",
            b"metrics: {port: 8405, sources: []}",
            b"metrics: {port: 8405, sources: [192.0.2.5/24]}",
            b"metrics: {port: 8405, sources: [192.0.2.0/24, 192.0.2.0/24]}",
            b"metrics: [8405]",
            b"\xff",
        ):
            with self.subTest(document=document), self.assertRaises(ConfigError):
                load_document(document)


class TheGeneratedLayer(unittest.TestCase):
    def generate(
        self, case: str, settings: ClusterSettings, reservations: bytes = b"{}"
    ) -> GeneratedLayer:
        options = arguments(GOLDEN / case)
        options["settings"] = settings
        return generate(
            objects(GOLDEN / case), reservations=load_reservations(reservations), **options
        )

    def test_one_line_serves_the_day_file_and_every_receiver(self) -> None:
        #
        # B286, B287: HAProxy writes one record, with its node, to the syslog
        # socket; rsyslog writes it to the day file and forwards it. No ring.
        #
        settings = load_document(GRAYLOG)
        options = arguments(GOLDEN / "minimal")
        options["settings"] = settings
        for traffic_logging in (True, False):
            with self.subTest(traffic_logging=traffic_logging):
                layer = generate(
                    objects(GOLDEN / "minimal"), traffic_logging=traffic_logging, **options
                )
                frontends = layer.configuration["1000-frontends.cfg"]
                self.assertEqual(frontends.count("log-profile "), 1)
                self.assertIn(f"format local profile {TRAFFIC_LOG_PROFILE} local2", frontends)
                self.assertNotIn("log ring@", frontends)
                self.assertNotIn("\nring ", layer.configuration.get(CLUSTER_FILE, ""))
                forward = layer.rsyslog_files["forward.conf"]
                self.assertIn('target="192.0.2.20"', forward)
                self.assertIn('queue.timeoutEnqueue="0"', forward)
                self.assertIn('queue.size="20000"', forward)
                self.assertEqual("    stop\n" in forward, not traffic_logging)
        self.assertIn("%(node)H", HTTP_TRAFFIC_LOG_FORMAT)

    def test_without_receivers_nothing_is_forwarded(self) -> None:
        layer = generate(
            objects(GOLDEN / "minimal"), traffic_logging=True, **arguments(GOLDEN / "minimal")
        )
        self.assertEqual(layer.rsyslog_files, {})
        self.assertIn(
            f"format local profile {TRAFFIC_LOG_PROFILE} local2",
            layer.configuration["1000-frontends.cfg"],
        )

    def test_the_old_memory_buffer_is_read_and_no_longer_written(self) -> None:
        settings = load_document(
            b"log_targets: {g: {address: 192.0.2.20, port: 6514, buffer_kib: 4096}}"
        )
        self.assertEqual(settings.log_targets[0].disk_mib, DEFAULT_DISK_MIB)
        written = dump_document(settings)
        self.assertNotIn(b"buffer_kib", written)
        self.assertIn(b"disk_mib: 1024", written)

    def test_nothing_set_writes_no_cluster_file(self) -> None:
        self.assertNotIn(CLUSTER_FILE, self.generate("minimal", NOTHING).configuration)

    def test_the_metrics_port_is_refused_where_something_else_listens(self) -> None:
        for case, port in (("tcp", 5432), ("https", 443), ("minimal", 80)):
            with (
                self.subTest(case=case, port=port),
                self.assertRaisesRegex(GeneratorError, "metrics port"),
            ):
                self.generate(case, ClusterSettings(metrics=Metrics(port, ("192.0.2.0/24",))))

    def test_the_metrics_port_is_refused_where_the_handwritten_half_reserved_it(self) -> None:
        for reservations in (b"tcp_ports: [8405]", b"tcp_ports: ['192.0.2.99:8405']"):
            with (
                self.subTest(reservations=reservations),
                self.assertRaisesRegex(GeneratorError, "reserved"),
            ):
                self.generate(
                    "minimal",
                    ClusterSettings(metrics=Metrics(8405, ("192.0.2.0/24",))),
                    reservations,
                )


class EveryPublishCarriesTheSettings(unittest.TestCase):
    def test_a_publish_without_a_new_document_keeps_the_base_one(self) -> None:
        base = {
            "managed/proxies/shop.yaml": PROXY,
            "managed/network.yaml": NETWORK,
            LOCATION: GRAYLOG,
        }
        kept = managed_files(base, network_document=NETWORK, cluster=cluster())
        self.assertEqual(kept[LOCATION], GRAYLOG)
        self.assertIn("managed/generated/1000-cluster.cfg", kept)

        emptied = managed_files(
            base,
            network_document=NETWORK,
            cluster=cluster(),
            settings_document=b"{}\n",
        )
        self.assertNotIn("managed/generated/1000-cluster.cfg", emptied)


class SharingIsLookedUpOnlyWhenItIsOn(unittest.TestCase):
    """The nodes' addresses are asked for by a publish that shares, and only then (B270)."""

    def publish(self, settings: bytes) -> tuple[dict[str, bytes], list[str]]:
        asked: list[str] = []

        def nodes() -> tuple[tuple[str, str], ...]:
            asked.append("nodes")
            return (("node-a", "192.0.2.1"), ("node-b", "192.0.2.2"))

        files = managed_files(
            {"managed/proxies/shop.yaml": PROXY, "managed/network.yaml": NETWORK},
            network_document=NETWORK,
            cluster=cluster(),
            settings_document=settings,
            peer_nodes=nodes,
        )
        return files, asked

    def test_a_cluster_that_shares_writes_the_section(self) -> None:
        files, asked = self.publish(b"peers:\n  port: 10000\n")
        self.assertEqual(asked, ["nodes"])
        written = files["managed/generated/1000-cluster.cfg"].decode()
        self.assertIn("peers mgd-peers\n    peer node-a 192.0.2.1:10000\n", written)

    def test_a_cluster_that_does_not_asks_nothing(self) -> None:
        _, asked = self.publish(b"{}\n")
        self.assertEqual(asked, [])

    def test_the_metrics_port_is_not_the_peers_port(self) -> None:
        with self.assertRaisesRegex(ConfigError, "same port for metrics and peers"):
            load_document(
                b"metrics:\n  port: 8405\n  sources: [192.0.2.0/24]\npeers:\n  port: 8405\n"
            )


if __name__ == "__main__":
    unittest.main()
