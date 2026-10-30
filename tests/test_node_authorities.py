"""The node's report of its CA files, held to the manager's definition (B276).

The two sides compute a CA file's identity separately - the node script is
installed, not imported - and the deploy compares the two. So the node's
function is lifted out of the script and run here beside the manager's, on the
same text: a difference in what is hashed would make every node look behind,
or worse, current.
"""

from __future__ import annotations

import base64
import hashlib
import re
import tempfile
import types
import unittest
from pathlib import Path
from typing import Any

from haprion import certificates as manager
from haprion.certificates import DELIMITER, bundle_fingerprint

SCRIPT = Path(__file__).resolve().parents[1] / "install" / "node" / "haprion-node-status"
READER = re.compile(
    r"^def bundle_fingerprint\(.*?(?=^def certificate_valid)", re.DOTALL | re.MULTILINE
)


READER_ALL = re.compile(
    r"^def leaf_fingerprint\(.*?(?=^def read_validation)", re.DOTALL | re.MULTILINE
)


def block(body: bytes) -> str:
    encoded = base64.b64encode(body).decode()
    return f"{DELIMITER}BEGIN CERTIFICATE{DELIMITER}\n{encoded}\n{DELIMITER}END CERTIFICATE{DELIMITER}\n"


class TheNodeCountsACaFileAsTheManagerDoes(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        (self.root / "ca").mkdir()
        self.pending = self.root / "ca.pending"
        found = READER.search(SCRIPT.read_text())
        assert found, "the reader is no longer where the test extracts it from"
        namespace: dict[str, Any] = {
            "Path": lambda name: self.pending if "pending" in str(name) else Path(name),
            "CERTIFICATE_BLOCK": manager.CERTIFICATE_BLOCK,
            "CERTS_DIR": self.root,
            "MAX_CERTIFICATE_BYTES": manager.MAX_CERTIFICATE_BYTES,
            "base64": base64,
            "hashlib": hashlib,
        }
        exec(found.group(0), namespace)  # noqa: S102 - the file under test, read from disk
        self.fingerprint = namespace["bundle_fingerprint"]
        self.read = namespace["read_authorities"]

    def test_the_same_text_gives_the_same_answer_on_both_sides(self) -> None:
        text = block(b"first root") + "between the blocks\n" + block(b"second root")

        self.assertEqual(self.fingerprint(text), bundle_fingerprint(text))

    def test_a_second_root_behind_the_first_changes_it(self) -> None:
        one = block(b"first root")

        self.assertNotEqual(bundle_fingerprint(one), bundle_fingerprint(one + block(b"another")))

    def test_the_files_are_reported_and_a_pending_one_is_left_out(self) -> None:
        (self.root / "ca" / "corp-root.pem").write_text(block(b"root"))
        (self.root / "ca" / "new-root.pem").write_text(block(b"new"))
        self.pending.write_text("new-root\n")

        self.assertEqual(
            self.read(),
            [{"id": "corp-root", "fingerprint_sha256": bundle_fingerprint(block(b"root"))}],
        )


class TheNodeReportsTheChainOfEachCertificate(unittest.TestCase):
    """E03: the leaf is the same behind another chain; the chain fingerprint is not."""

    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        found = READER_ALL.search(SCRIPT.read_text())
        assert found, "the reader is no longer where the test extracts it from"
        namespace: dict[str, Any] = {
            "Path": lambda name: self.root / "none" if "pending" in str(name) else Path(name),
            "CERTIFICATE_BLOCK": manager.CERTIFICATE_BLOCK,
            "CERTS_DIR": self.root,
            "CERT_PENDING": self.root / "none",
            "MAX_CERTIFICATE_BYTES": manager.MAX_CERTIFICATE_BYTES,
            "base64": base64,
            "hashlib": hashlib,
            "run": lambda *argv: types.SimpleNamespace(returncode=0),
            "Any": Any,
        }
        exec(found.group(0), namespace)  # noqa: S102 - the file under test, read from disk
        self.read = namespace["read_certificates"]

    def test_the_chain_fingerprint_is_the_managers_and_follows_the_intermediates(self) -> None:
        short = block(b"leaf")
        full = short + block(b"intermediate")
        (self.root / "example-net.pem").write_text(short)
        first = self.read()
        (self.root / "example-net.pem").write_text(full)
        second = self.read()

        self.assertEqual(first[0]["fingerprint_sha256"], second[0]["fingerprint_sha256"])
        self.assertEqual(first[0]["chain_sha256"], bundle_fingerprint(short))
        self.assertEqual(second[0]["chain_sha256"], bundle_fingerprint(full))
        self.assertNotEqual(first[0]["chain_sha256"], second[0]["chain_sha256"])


if __name__ == "__main__":
    unittest.main()
