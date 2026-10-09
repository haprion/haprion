"""The node reads its cluster from node.conf, so its status rule is the same everywhere."""

from __future__ import annotations

import re
import tempfile
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "install/node/haprion-node-status"
KEYS = ROOT / "install/03-manager-keys"
PREPARE = ROOT / "install/04-node-prepare"
READING = re.compile(r"^def read_cluster\(\):.*?(?=^parser = )", re.DOTALL | re.MULTILINE)
CLUSTER_LINE = re.compile(r"^CLUSTER_LINE = (.*)$", re.MULTILINE)


class ReadClusterTests(unittest.TestCase):
    def setUp(self) -> None:
        source = SCRIPT.read_text()
        found = READING.search(source)
        pattern = CLUSTER_LINE.search(source)
        assert found and pattern, "read_cluster is no longer where the test extracts it from"
        self.source = found.group(0)
        self.pattern = pattern.group(1)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.conf = Path(temporary.name) / "node.conf"

    def read(self) -> Any:
        namespace: dict[str, Any] = {"re": re, "NODE_CONF": self.conf}
        exec(f"CLUSTER_LINE = {self.pattern}", namespace)  # noqa: S102 - the script's own pattern
        exec(self.source, namespace)  # noqa: S102 - verbatim function from the node script
        return namespace["read_cluster"]()

    def test_it_reads_the_cluster_04_node_prepare_wrote(self) -> None:
        self.conf.write_text('# Node configuration\n\nCLUSTER="alpha"\nMANAGER="mgr"\n')

        self.assertEqual(self.read(), "alpha")

    def test_a_missing_file_names_no_cluster(self) -> None:
        self.assertIsNone(self.read())

    def test_an_invalid_or_absent_value_names_no_cluster(self) -> None:
        for text in ('CLUSTER="Alpha"\n', 'CLUSTER="a b"\n', "CLUSTER=alpha\n", 'MANAGER="mgr"\n'):
            with self.subTest(text=text):
                self.conf.write_text(text)
                self.assertIsNone(self.read())


class StatusRuleTests(unittest.TestCase):
    def test_the_forced_command_is_what_sudo_allows_and_names_no_cluster(self) -> None:
        forced = re.search(
            r'command=\\"sudo -n (\S*haprion-node-status[^\\]*)\\"', KEYS.read_text()
        )
        allowed = re.search(
            r"NOPASSWD: \$\{SBIN\}/(haprion-node-status.*)$", PREPARE.read_text(), re.M
        )
        assert forced and allowed

        self.assertEqual(forced.group(1), "/usr/sbin/" + allowed.group(1))
        self.assertNotIn("CLUSTER", allowed.group(1))
        self.assertNotIn("cluster", forced.group(1))


if __name__ == "__main__":
    unittest.main()
