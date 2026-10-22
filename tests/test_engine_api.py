"""The engine's API level moves when its contract does (review 2026-10-22, 6-4).

`engine_api` is what the interface's compatibility check and its package
compare, and it is raised by hand. It was not when the receiver helper took
two new actions - `secret`, then `key` - so an interface that asks for them
passed the check against an engine that refuses them. The contract the two
share is `schemas/v1`, and its digest is recorded beside the level it was
taken at: a schema change fails here until the level is decided again.
"""

from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
ENGINE = BASE / "src/haprion/compatibility.json"


def schemas_digest() -> str:
    digest = hashlib.sha256()
    for path in sorted((BASE / "schemas/v1").glob("*.json")):
        digest.update(path.name.encode() + b"\0" + path.read_bytes() + b"\0")
    return digest.hexdigest()


class TheLevelFollowsTheContract(unittest.TestCase):
    def test_the_schemas_are_the_ones_the_level_was_set_for(self) -> None:
        recorded = json.loads(ENGINE.read_text())
        self.assertEqual(
            recorded.get("schemas_sha256"),
            schemas_digest(),
            "schemas/v1 changed: raise engine_api in src/haprion/compatibility.json and the "
            "interface's requirement with it, then record the new schemas_sha256",
        )


if __name__ == "__main__":
    unittest.main()
