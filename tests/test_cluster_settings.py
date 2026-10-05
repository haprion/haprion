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

from haproxy_mgmt.cluster_settings import (
    DEFAULT_BUFFER_KIB,
    LOCATION,
    NOTHING,
    ClusterSettings,
    LogTarget,
    Metrics,
    dump_document,
    load_document,
)
from haproxy_mgmt.config import ConfigError
from haproxy_mgmt.generate import (
    CLUSTER_FILE,
    EXTERNAL_LOG_FORMAT,
    EXTERNAL_LOG_PROFILE,
    HTTP_TRAFFIC_LOG_FORMAT,
    TRAFFIC_LOG_PROFILE,
    GeneratedLayer,
    GeneratorError,
    generate,
)
from haproxy_mgmt.golden import GOLDEN, arguments, objects
from haproxy_mgmt.managed_publish import managed_files
from haproxy_mgmt.reservations import load_reservations
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
                log_targets=(LogTarget("graylog", "192.0.2.20", 6514, DEFAULT_BUFFER_KIB, False),),
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

    def test_an_external_record_names_its_node_and_the_local_one_is_unchanged(self) -> None:
        settings = load_document(GRAYLOG)
        options = arguments(GOLDEN / "minimal")
        options["settings"] = settings
        both = generate(objects(GOLDEN / "minimal"), traffic_logging=True, **options)
        alone = generate(
            objects(GOLDEN / "minimal"), traffic_logging=True, **arguments(GOLDEN / "minimal")
        )
        frontends = both.configuration["1000-frontends.cfg"]

        self.assertIn(f"log-profile {TRAFFIC_LOG_PROFILE}\n", frontends)
        self.assertIn(f"log-profile {EXTERNAL_LOG_PROFILE}\n", frontends)
        self.assertIn(f"format local profile {TRAFFIC_LOG_PROFILE} local2", frontends)
        self.assertIn(
            f"log ring@mgd-log-graylog len 2048 format rfc5424 profile {EXTERNAL_LOG_PROFILE}",
            frontends,
        )
        self.assertIn("%(node)H", EXTERNAL_LOG_FORMAT)
        self.assertNotIn("%(node)H", HTTP_TRAFFIC_LOG_FORMAT)
        # Without targets, the local stream is written exactly as before.
        self.assertNotIn(EXTERNAL_LOG_PROFILE, alone.configuration["1000-frontends.cfg"])

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


if __name__ == "__main__":
    unittest.main()
