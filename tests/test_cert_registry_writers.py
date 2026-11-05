"""Every place that writes a certificate's registry entry builds it through `written_entry` (C07).

The builder keeps what a writer does not own (an NDES profile, the interface
and exportable marks, a key the reader gains later). A writer that assembled
its own dict would drop them. The per-writer tests sit with the writers
(`test_cert_registry`, `test_cert_import`, `test_cert_issue`); this module holds
the guard that finds a writer nobody has tested, and the two paths that copy an
entry instead of building one.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path
from typing import Any

from haprion import cert_registry, cluster_definition

SOURCE = Path(__file__).resolve().parents[1] / "src" / "haprion"

#
# `certificates[<id>] = <value>` anywhere in the engine. The value must be the
# builder's, except where the value is a copy of an entry already on file with
# one key changed; those are tested below.
#
ASSIGNMENT = re.compile(r"^\s*certificates\[[^\]]+\]\s*=\s*(?P<value>.*)$", re.MULTILINE)
COPIES = {
    # The loader building its read-only view of an entry, not writing one.
    ("config.py", "RegisteredCertificate("),
    ("cert_registry.py", '{k: v for k, v in other.items() if k != "interface"}'),
    ("cluster_definition.py", "entry"),
}


class TheWritersOfTheEntry(unittest.TestCase):
    def test_every_assignment_of_an_entry_is_the_builder_or_a_known_copy(self) -> None:
        found: list[tuple[str, str]] = []
        for path in sorted(SOURCE.rglob("*.py")):
            for match in ASSIGNMENT.finditer(path.read_text(encoding="utf-8")):
                found.append((path.name, match["value"].strip()))

        unexpected = [
            (name, value)
            for name, value in found
            if not value.startswith(("cert_registry.written_entry(", "written_entry("))
            and (name, value) not in COPIES
        ]
        self.assertEqual(unexpected, [], "a new writer of the entry: build it with written_entry")
        self.assertGreaterEqual(
            sum(value.endswith("written_entry(") for _, value in found),
            4,
            "set_targets, import, authority, issue",
        )


class TheCopiesKeepWhatTheyDoNotTouch(unittest.TestCase):
    ENTRY: dict[str, Any] = {
        "source": {"kind": "import", "ndes_profile": "corp"},
        "clusters": ["alpha"],
        "exportable": True,
        "future_key": {"kept": 1},
    }

    def test_a_cluster_added_to_an_entry_keeps_the_rest(self) -> None:
        document = {"certificates": {"a": dict(self.ENTRY)}}
        rendered = cluster_definition._registry_with(document, "a", "beta").decode()

        written = _parsed(rendered)["certificates"]["a"]
        self.assertEqual(written["clusters"], ["alpha", "beta"])
        self.assertEqual(
            {k: v for k, v in written.items() if k != "clusters"},
            {k: v for k, v in self.ENTRY.items() if k != "clusters"},
        )

    def test_a_cluster_taken_out_of_every_entry_keeps_the_rest(self) -> None:
        document = {"certificates": {"a": dict(self.ENTRY)}}
        rendered = cluster_definition._registry_without(document, "alpha").decode()

        written = _parsed(rendered)["certificates"]["a"]
        self.assertNotIn("clusters", written)
        self.assertEqual(written["source"], self.ENTRY["source"])
        self.assertEqual(written["future_key"], self.ENTRY["future_key"])

    def test_the_interface_mark_taken_from_an_entry_leaves_the_rest(self) -> None:
        certificates = {
            "old": {**self.ENTRY, "interface": True},
            "new": {"source": {"kind": "import"}, "clusters": []},
        }
        displaced = cert_registry.claim_interface(certificates, "new")

        self.assertEqual(displaced, "old")
        self.assertEqual(certificates["old"], self.ENTRY)
        self.assertTrue(certificates["new"]["interface"])


def _parsed(text: str) -> dict[str, Any]:
    import yaml

    return dict(yaml.safe_load(text))


if __name__ == "__main__":
    unittest.main()
