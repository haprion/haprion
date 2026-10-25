"""The engine's API level moves when its contract does (review 2026-10-22, 6-4).

`engine_api` is what the interface's compatibility check and its package
compare, and it is raised by hand. It was not when the receiver helper took
two new actions - `secret`, then `key` - so an interface that asks for them
passed the check against an engine that refuses them. The contract the two
share is `schemas/v1`, and its digest is recorded beside the level it was
taken at: a schema change fails here until the level is decided again.

The schemas are the answers. What the helpers take - their operations, the
parameters each takes and the actions an `action` names - changes no schema,
so it has a digest of its own beside it (review 26-10-24, 11-05).
"""

from __future__ import annotations

import hashlib
import importlib
import json
import re
import unittest
from collections.abc import Mapping
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
ENGINE = BASE / "src/haprion/compatibility.json"
#
# The names a helper module states what it takes under.
#
REQUEST_NAME = re.compile(
    r"^(?:[A-Z]+_)*(?:OPERATIONS?|PARAMETERS|ACTIONS|KEYS|OPTIONAL|READINGS)$"
)


def schemas_digest() -> str:
    digest = hashlib.sha256()
    for path in sorted((BASE / "schemas/v1").glob("*.json")):
        digest.update(path.name.encode() + b"\0" + path.read_bytes() + b"\0")
    return digest.hexdigest()


def _plain(value: object) -> object:
    if isinstance(value, str):
        return value
    if isinstance(value, Mapping):
        if all(callable(item) for item in value.values()):
            return sorted(str(key) for key in value)
        return {str(key): _plain(item) for key, item in sorted(value.items())}
    if isinstance(value, set | frozenset | tuple | list) and all(
        isinstance(item, str) for item in value
    ):
        return sorted(value)
    raise TypeError(f"{value!r} is not a name, a list of names or a table of them")


def requests_inventory() -> dict[str, dict[str, object]]:
    """What every module in `haprion.cli` states it takes, as plain JSON."""

    inventory: dict[str, dict[str, object]] = {}
    for path in sorted((BASE / "src/haprion/cli").glob("*.py")):
        module = importlib.import_module(f"haprion.cli.{path.stem}")
        stated = {
            name: _plain(value)
            for name, value in sorted(vars(module).items())
            if REQUEST_NAME.fullmatch(name) and not callable(value)
        }
        if stated:
            inventory[path.stem] = stated
    return inventory


def requests_digest() -> str:
    text = json.dumps(requests_inventory(), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(text.encode()).hexdigest()


class TheLevelFollowsTheContract(unittest.TestCase):
    def test_the_schemas_are_the_ones_the_level_was_set_for(self) -> None:
        recorded = json.loads(ENGINE.read_text())
        self.assertEqual(
            recorded.get("schemas_sha256"),
            schemas_digest(),
            "schemas/v1 changed: raise engine_api in src/haprion/compatibility.json and the "
            "interface's requirement with it, then record the new schemas_sha256",
        )

    def test_what_the_helpers_take_is_what_the_level_was_set_for(self) -> None:
        recorded = json.loads(ENGINE.read_text())
        self.assertEqual(
            recorded.get("requests_sha256"),
            requests_digest(),
            "a helper's operations, parameters or actions changed: raise engine_api in "
            "src/haprion/compatibility.json and the interface's requirement with it, then "
            "record the new requests_sha256",
        )

    def test_a_contract_changed_since_it_was_installed_has_a_higher_level(self) -> None:
        """Review 26-10-25, 1-03: the digests were recorded again and the level stayed.

        Re-recording a digest makes the two checks above pass; the level is
        what the interface and the package dependency read. `installed` is the
        newest level any build of this engine went out with - the release
        list records it, with its digests, when a release is rolled out - so
        a contract that differs from it is a contract no installed engine has,
        and has to be a level none has either.
        """

        recorded = json.loads(ENGINE.read_text())
        installed = recorded["installed"]
        self.assertGreaterEqual(recorded["engine_api"], installed["engine_api"])
        if recorded["engine_api"] == installed["engine_api"]:
            self.assertEqual(
                (installed.get("schemas_sha256"), installed.get("requests_sha256")),
                (schemas_digest(), requests_digest()),
                f"engine_api {installed['engine_api']} went out with another contract: raise "
                "engine_api and the interface's requirement with it",
            )

    def test_the_inventory_holds_what_a_helper_takes(self) -> None:
        inventory = requests_inventory()
        self.assertEqual(inventory["resolve_helper"]["PARAMETERS"], ["any", "names"])
        self.assertEqual(
            inventory["cert_receiver_helper"]["ACTIONS"], ["add", "key", "remove", "secret"]
        )
        self.assertEqual(
            inventory["node_restore_helper"]["KEYS"],
            {
                "node_restore": ["confirm", "run"],
                "node_restore_discard": ["run"],
                "node_restore_prepare": ["archive", "node", "run", "target", "test"],
                "node_restore_preview": ["fingerprint", "run"],
                "node_restore_status": ["run"],
            },
        )


if __name__ == "__main__":
    unittest.main()
