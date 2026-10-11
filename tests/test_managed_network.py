"""The editable network document has one strict, stable representation."""

from __future__ import annotations

import unittest

from haprion.config import ConfigError
from haprion.managed_network import MAX_NETWORK_BYTES, dump_document, load_document


class NetworkDocumentTests(unittest.TestCase):
    def test_a_document_round_trips_in_canonical_order(self) -> None:
        network = load_document(
            b"""networks:\n  office: [198.51.100.0/24]\nsources:\n  outbound: 192.0.2.35\ndefault_vip: public\nvips:\n  public:\n    source: 192.0.2.25\n    address: 192.0.2.20\n""",
            ownership_vip="192.0.2.20",
            location="managed/network.yaml",
        )

        self.assertEqual(
            dump_document(network),
            b"""vips:\n  public:\n    address: 192.0.2.20\n    source: 192.0.2.25\ndefault_vip: public\nsources:\n  outbound: 192.0.2.35\nnetworks:\n  office:\n  - 198.51.100.0/24\n""",
        )

    def test_invalid_yaml_is_refused_before_it_can_be_published(self) -> None:
        with self.assertRaises(ConfigError) as caught:
            load_document(
                b"vips:\n  broken: [\n",
                ownership_vip="192.0.2.20",
                location="managed/network.yaml",
            )

        self.assertIn("not valid YAML", str(caught.exception))

    def test_a_document_has_a_hard_size_limit(self) -> None:
        with self.assertRaises(ConfigError) as caught:
            load_document(
                b"#" + b"x" * MAX_NETWORK_BYTES,
                ownership_vip="192.0.2.20",
                location="managed/network.yaml",
            )

        self.assertIn("size limit", str(caught.exception))


if __name__ == "__main__":
    unittest.main()


class ATlsPolicySurvivesTheRoundTrip(unittest.TestCase):
    """Parsed and written back, because the publish path does both.

    The interface sends a document, the helper parses it and writes the
    canonical form, and it is that form which is committed. A serializer that
    dropped the field would lose the choice between the button and the bind
    line - silently, and with the page still showing what was asked for.
    """

    def canonical(self, document: str) -> str:
        network = load_document(document.encode(), ownership_vip="public", location="network.yaml")
        return dump_document(network).decode()

    def test_a_named_policy_is_written_back(self) -> None:
        written = self.canonical(
            "vips:\n  public:\n    address: 192.0.2.20\n    tls: modern\ndefault_vip: public\n"
        )

        self.assertIn("tls: modern", written)

    def test_a_vip_that_named_none_gains_no_key(self) -> None:
        written = self.canonical("vips:\n  public:\n    address: 192.0.2.20\ndefault_vip: public\n")

        self.assertNotIn("tls", written)


class Http3IsTheVipsChoice(unittest.TestCase):
    """B280: `http3: true` on a VIP, written back, and refused beside TLS 1.2 only."""

    def load(self, text: str) -> object:
        return load_document(
            text.encode(), ownership_vip="192.0.2.20", location="managed/network.yaml"
        )

    def test_it_is_read_and_written_back_only_where_on(self) -> None:
        network = self.load(
            "vips:\n  web:\n    address: 192.0.2.20\n    http3: true\n"
            "  mail:\n    address: 192.0.2.21\ndefault_vip: web\n"
        )
        written = dump_document(network).decode()  # type: ignore[arg-type]

        self.assertIn("http3: true", written)
        self.assertEqual(written.count("http3"), 1)

    def test_it_needs_tls_1_3(self) -> None:
        with self.assertRaises(ConfigError) as raised:
            self.load(
                "vips:\n  web:\n    address: 192.0.2.20\n    tls: tls12only\n    http3: true\n"
            )
        self.assertIn("TLS 1.3", str(raised.exception))

    def test_it_is_true_or_false(self) -> None:
        with self.assertRaises(ConfigError):
            self.load("vips:\n  web:\n    address: 192.0.2.20\n    http3: yes please\n")
