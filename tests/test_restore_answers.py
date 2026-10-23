from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from haprion import accounts, restore_answers, restore_source
from haprion.restore_answers import AnswersError
from tests.restore_fixture import FILES, NODE_CONF, build

BASE = Path(__file__).resolve().parents[1]
LIB = BASE / "install/lib.sh"
PUBLISH_ROOT = Path("/srv/haprion/published")


class Deriving(unittest.TestCase):
    def source(self, node_conf: str = NODE_CONF) -> restore_source.RestoreSource:
        work = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, work)
        files = dict(FILES)
        files["/etc/haprion/node.conf"] = (node_conf, 0o600)
        return restore_source.read(build(work, files=files))

    def answers(self, node_conf: str = NODE_CONF, cluster: str = "alpha") -> str:
        return restore_answers.derive(self.source(node_conf), cluster, PUBLISH_ROOT)

    def rendered(self, answers: str, cluster: str = "alpha") -> str:
        """What 04-node-prepare would install as node.conf from these answers.

        The node's path is looked up the way the script looks it up, through
        `cluster_value`, so the answers' variable name is held to lib.sh's.
        """

        work = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, work)
        (work / "answers.env").write_text(answers, encoding="utf-8")
        script = (
            f"set -euo pipefail; source {LIB}; source {work / 'answers.env'}; "
            f'render_node_conf {cluster} "$(cluster_value NODE_PATH {cluster})" '
            f"{accounts.LOGS_GROUP}"
        )
        completed = subprocess.run(  # fixed interpreter, script built here
            ["/bin/bash", "-c", script], check=True, capture_output=True, text=True
        )
        return completed.stdout


class TheAnswersRenderTheArchivedNodeConfBack(Deriving):
    def test_the_template_gives_back_the_archived_bytes(self) -> None:
        """The contract: 04-node-prepare re-installs node.conf unchanged on a restored node."""

        self.assertEqual(self.rendered(self.answers()), NODE_CONF)

    def test_without_a_certificate_account_too(self) -> None:
        node_conf = NODE_CONF.split("\n\n# Where this node fetches certificates")[0] + "\n"
        self.assertNotIn("CERT_PULL_USER", node_conf)
        self.assertEqual(self.rendered(self.answers(node_conf)), node_conf)

    def test_a_cluster_id_with_a_hyphen_too(self) -> None:
        """lib.sh reads NODE_PATH_edge_a for `edge-a`; until 2026-10-22 such a node was refused."""

        node_conf = NODE_CONF.replace('"alpha', '"edge-a')
        answers = self.answers(node_conf, cluster="edge-a")
        self.assertIn('NODE_PATH_edge_a="node-a"', answers)
        self.assertEqual(self.rendered(answers, cluster="edge-a"), node_conf)

    def test_the_manager_supplies_what_node_conf_does_not_carry(self) -> None:
        answers = self.answers()
        self.assertIn(f'PUBLISH_ROOT="{PUBLISH_ROOT}"', answers)
        self.assertIn('NODE_PATH_alpha="node-a"', answers)
        self.assertIn('OPERATOR_ACCOUNTS="operator"', answers)


class WhatStopsTheDerivation(Deriving):
    def test_another_clusters_node_is_refused(self) -> None:
        with self.assertRaisesRegex(AnswersError, "belongs to alpha, not to beta"):
            self.answers(cluster="beta")

    def test_a_value_that_could_expand_is_refused_not_escaped(self) -> None:
        node_conf = NODE_CONF.replace('MANAGER="mgr.example.com"', 'MANAGER="$(id)"')
        with self.assertRaisesRegex(AnswersError, "MANAGER"):
            self.answers(node_conf)

    def test_a_cluster_id_the_engine_would_not_make_is_refused(self) -> None:
        node_conf = NODE_CONF.replace('"alpha', '"al_pha')
        with self.assertRaisesRegex(AnswersError, "not one the engine accepts"):
            self.answers(node_conf, cluster="al_pha")

    def test_service_accounts_out_of_order_are_refused(self) -> None:
        node_conf = NODE_CONF.replace(
            'BACKUP_ACCOUNTS="_haprion-trigger _haprion-status',
            'BACKUP_ACCOUNTS="_haprion-status _haprion-trigger',
        )
        with self.assertRaisesRegex(AnswersError, "begin with its service accounts"):
            self.answers(node_conf)
