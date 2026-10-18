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
import unittest
from pathlib import Path
from typing import Any

from haprion import certificates as manager
from haprion.certificates import DELIMITER, bundle_fingerprint

SCRIPT = Path(__file__).resolve().parents[1] / "install" / "node" / "haprion-node-status"
READER = re.compile(
    r"^def bundle_fingerprint\(.*?(?=^def certificate_valid)", re.DOTALL | re.MULTILINE
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


if __name__ == "__main__":
    unittest.main()
