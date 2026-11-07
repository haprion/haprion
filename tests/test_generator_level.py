"""The generator level is decided whenever what the generator writes changes (B493).

A regeneration asks the nodes for a deploy only when the installed generator
level is above the published version's. A release that changes the output and
forgets the level leaves the nodes on the old files without a word, and one
that raises it for a reordering asks every cluster for a deploy that changes
nothing they do. Neither can be read from the code, so the golden files' digest
is held here beside the level: output that changes fails until somebody has
chosen.
"""

from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

from haprion.generate import GENERATOR_LEVEL
from haprion.object_manifest import BASELINE_LEVEL

BASE = Path(__file__).resolve().parents[1]
GOLDEN = BASE / "tests" / "golden"
RECORD = BASE / "tests" / "generator_level.json"


def golden_digest() -> str:
    """The golden output, every file but the objects it is made from."""

    digest = hashlib.sha256()
    for path in sorted(item for item in GOLDEN.rglob("*") if item.is_file()):
        if path.suffix == ".yaml":
            continue
        content = path.read_bytes()
        digest.update(path.relative_to(GOLDEN).as_posix().encode())
        digest.update(f"\0{len(content)}\0".encode())
        digest.update(content)
    return digest.hexdigest()


class TheGeneratorLevelIsDecided(unittest.TestCase):
    def test_the_golden_output_is_the_one_recorded_with_the_level(self) -> None:
        recorded = json.loads(RECORD.read_text())
        self.assertEqual(
            (recorded["generator_level"], recorded["golden_sha256"]),
            (GENERATOR_LEVEL, golden_digest()),
            "the generated output or the level changed. If the nodes would do something "
            "differently with the new output, raise GENERATOR_LEVEL in src/haprion/generate.py; "
            "if only how the files read changed, leave it. Then record both in "
            f"{RECORD.relative_to(BASE)}: generator_level {GENERATOR_LEVEL}, "
            f"golden_sha256 {golden_digest()}",
        )

    def test_the_level_is_never_below_the_baseline(self) -> None:
        self.assertGreaterEqual(GENERATOR_LEVEL, BASELINE_LEVEL)


if __name__ == "__main__":
    unittest.main()
