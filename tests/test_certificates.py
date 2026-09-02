"""Identifying the certificates a cluster references, from the files on disk.

Nothing here uses a real certificate. The fingerprint is a SHA-256 over the
DER bytes and cares about nothing else, so synthetic blocks exercise every
branch - and a repository that is going to be public must not carry certificate
material even in a fixture.
"""

from __future__ import annotations

import hashlib
import tempfile
import unittest
from base64 import b64encode
from pathlib import Path

from haproxy_mgmt.certificates import (
    CertificateError,
    certificate_path,
    leaf_fingerprint,
    read_reference,
    target_for,
)
from haproxy_mgmt.config import Cluster, Node, Vip

LEAF = b"leaf-certificate-der-bytes"
INTERMEDIATE = b"intermediate-certificate-der-bytes"


#
# Assembled, not written out - see the note in haproxy_mgmt.certificates. A
# literal PEM header in a tracked file is what the secret scanner is for.
#
DELIMITER = "-" * 5


def block(label: str, payload: bytes) -> str:
    body = b64encode(payload).decode("ascii")
    return f"{DELIMITER}BEGIN {label}{DELIMITER}\n{body}\n{DELIMITER}END {label}{DELIMITER}\n"


def published_pem(*, key: bool = True, chain: bool = True) -> str:
    """A published PEM in the shape cert-publish writes: key, leaf, chain."""

    parts = []
    if key:
        parts.append(block("PRIVATE KEY", b"private-key-bytes-that-must-never-be-hashed"))
    parts.append(block("CERTIFICATE", LEAF))
    if chain:
        parts.append(block("CERTIFICATE", INTERMEDIATE))
    return "".join(parts)


def cluster(*certificates: str) -> Cluster:
    return Cluster(
        cluster_id="alpha",
        display_name="Alpha",
        vip="192.0.2.10",
        address_prefix=None,
        address_interface=None,
        vips={"main": Vip(name="main", address="192.0.2.10")},
        default_vip="main",
        resolvers=None,
        sources={},
        networks={},
        unknown_host=None,
        abuse_protection=None,
        config_path=Path("/configs/alpha"),
        publish_path=Path("/published/alpha"),
        node_path="alpha",
        validation_certs=Path("/validation"),
        default_certificate=certificates[0],
        certificate_ids=certificates,
        trusted_proxy_cidrs=("192.0.2.0/24",),
        nodes=(Node(name="node-a", mgmt_host="node-a.example.com"),),
    )


class FingerprintTests(unittest.TestCase):
    def test_the_leaf_is_hashed_not_the_file(self) -> None:
        self.assertEqual(
            leaf_fingerprint(published_pem()),
            hashlib.sha256(LEAF).hexdigest(),
        )

    def test_the_private_key_and_the_chain_do_not_change_the_answer(self) -> None:
        #
        # The property that makes the fingerprint comparable with what a node
        # computes: the same served certificate must fingerprint the same
        # regardless of how the file around it was assembled.
        #
        self.assertEqual(
            leaf_fingerprint(published_pem()),
            leaf_fingerprint(published_pem(key=False, chain=False)),
        )

    def test_the_first_certificate_wins_not_the_last(self) -> None:
        self.assertNotEqual(
            leaf_fingerprint(published_pem()),
            hashlib.sha256(INTERMEDIATE).hexdigest(),
        )

    def test_a_file_without_a_certificate_is_refused(self) -> None:
        with self.assertRaises(CertificateError):
            leaf_fingerprint(block("PRIVATE KEY", b"only-a-key"))

    def test_a_corrupt_certificate_block_is_refused(self) -> None:
        pem = (
            f"{DELIMITER}BEGIN CERTIFICATE{DELIMITER}\n"
            "not base64 at all!\n"
            f"{DELIMITER}END CERTIFICATE{DELIMITER}\n"
        )

        with self.assertRaises(CertificateError):
            leaf_fingerprint(pem)


class PathTests(unittest.TestCase):
    def test_the_suffix_is_appended_to_the_id(self) -> None:
        self.assertEqual(
            certificate_path(Path("/certs"), "example-net"),
            Path("/certs/example-net.pem"),
        )

    def test_an_id_written_with_the_suffix_doubles_it(self) -> None:
        #
        # Not a bug being enshrined: this is the documented trap. IDs are
        # written without `.pem`, and one written with it resolves to a file
        # that does not exist, which is the loud failure. Silently accepting
        # both spellings would instead make two IDs mean one certificate.
        #
        self.assertEqual(
            certificate_path(Path("/certs"), "example.pem"),
            Path("/certs/example.pem.pem"),
        )

    def test_an_invalid_id_is_refused(self) -> None:
        for identifier in ("../escape", "/absolute", "UPPER", "", "a/b"):
            with self.subTest(identifier=identifier), self.assertRaises(CertificateError):
                certificate_path(Path("/certs"), identifier)


class ReadTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def write(self, identifier: str, pem: str) -> None:
        (self.root / f"{identifier}.pem").write_text(pem, encoding="ascii")

    def test_a_referenced_certificate_is_read_and_identified(self) -> None:
        self.write("example-net", published_pem())

        reference = read_reference(self.root, "example-net")

        self.assertEqual(reference.id, "example-net")
        self.assertEqual(reference.fingerprint, hashlib.sha256(LEAF).hexdigest())

    def test_a_missing_certificate_says_it_is_referenced_but_absent(self) -> None:
        with self.assertRaises(CertificateError) as raised:
            read_reference(self.root, "example-net")

        self.assertIn("referenced by the cluster", str(raised.exception))

    def test_an_implausibly_large_file_is_refused_unread(self) -> None:
        (self.root / "example-net.pem").write_bytes(b"x" * (1024 * 1024 + 1))

        with self.assertRaises(CertificateError) as raised:
            read_reference(self.root, "example-net")

        self.assertIn("implausibly large", str(raised.exception))

    def test_the_target_covers_every_referenced_certificate_in_order(self) -> None:
        self.write("example-net", published_pem())
        self.write("example-com", block("CERTIFICATE", b"the-other-leaf"))

        target = target_for(cluster("example-net", "example-com"), self.root)

        self.assertEqual([ref.id for ref in target.certificates], ["example-net", "example-com"])

    def test_one_missing_certificate_stops_the_whole_target(self) -> None:
        #
        # Refused before anything is sent, rather than reported after three of
        # four nodes were touched. What is knowable up front is checked up front.
        #
        self.write("example-net", published_pem())

        with self.assertRaises(CertificateError):
            target_for(cluster("example-net", "example-com"), self.root)


if __name__ == "__main__":
    unittest.main()
