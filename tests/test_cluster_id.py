"""Every reader of a cluster ID holds the engine's pattern (2026-10-22).

There were four: the engine's, the UI's and its database's 32 characters with
an underscore, the node restore's without a hyphen, and a schema's that let a
digit lead. A cluster the engine accepted as `edge-a` could not be restored on
a node. What can import `haprion.config` does; what runs on a node with the
standard library alone keeps a copy, held here.
"""

from __future__ import annotations

import json
import re
import subprocess
import unittest
from pathlib import Path
from typing import Any

from haprion import restore_agent, restore_answers, traffic_collector
from haprion.config import CLUSTER_ID

BASE = Path(__file__).resolve().parents[1]


def _cluster_patterns(node: Any, found: list[tuple[str, str]], where: str = "") -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            if key in ("cluster", "clusters", "cluster_id") and isinstance(value, dict):
                shape = value.get("items", value)
                if isinstance(shape, dict) and "pattern" in shape:
                    found.append((f"{where}/{key}", shape["pattern"]))
            _cluster_patterns(value, found, f"{where}/{key}")
    elif isinstance(node, list):
        for index, value in enumerate(node):
            _cluster_patterns(value, found, f"{where}/{index}")


class OneClusterId(unittest.TestCase):
    def test_the_engine_pattern(self) -> None:
        for good in ("alpha", "edge-a", "a", "a" + "b" * 62):
            self.assertTrue(CLUSTER_ID.fullmatch(good), good)
        for bad in ("", "1alpha", "al_pha", "-alpha", "Alpha", "a" * 64, "alpha\n"):
            self.assertFalse(CLUSTER_ID.fullmatch(bad), bad)

    def test_what_imports_the_engine_uses_its_pattern(self) -> None:
        self.assertIs(vars(traffic_collector)["CLUSTER_ID"], CLUSTER_ID)
        self.assertIs(vars(restore_answers)["CLUSTER_ID"], CLUSTER_ID)

    def test_the_node_restore_agent_copies_it(self) -> None:
        self.assertEqual(restore_agent.CLUSTER_ID.pattern, CLUSTER_ID.pattern)

    def test_the_node_status_reads_node_conf_with_it(self) -> None:
        text = (BASE / "install/node/haprion-node-status").read_text(encoding="utf-8")
        (line,) = re.findall(r"^CLUSTER_LINE = re\.compile\(r'(.*)'\)$", text, re.MULTILINE)
        self.assertEqual(line, f'^CLUSTER="({CLUSTER_ID.pattern[1:-1]})"$')

    def test_the_installation_scripts_check_it(self) -> None:
        for cluster, expected in (("edge-a", 0), ("a" + "b" * 62, 0), ("al_pha", 1), ("1a", 1)):
            with self.subTest(cluster=cluster):
                run = subprocess.run(  # fixed interpreter, script built here
                    [
                        "/bin/bash",
                        "-c",
                        f'source {BASE / "install/lib.sh"}; valid_id "$1"',
                        "-",
                        cluster,
                    ],
                    check=False,
                    capture_output=True,
                )
                self.assertEqual(run.returncode, expected)

    def test_every_schema_names_it(self) -> None:
        found: list[tuple[str, str]] = []
        for schema in sorted((BASE / "schemas/v1").glob("*.json")):
            _cluster_patterns(json.loads(schema.read_text(encoding="utf-8")), found, schema.name)
        listed = json.loads((BASE / "schemas/v1/haprion-cluster-list.schema.json").read_text())
        clusters = listed["$defs"]["list_result"]["properties"]["clusters"]["items"]
        found.append(
            ("haprion-cluster-list.schema.json id", clusters["properties"]["id"]["pattern"])
        )
        self.assertGreaterEqual(len(found), 4)
        self.assertEqual([where for where, pattern in found if pattern != CLUSTER_ID.pattern], [])


if __name__ == "__main__":
    unittest.main()
