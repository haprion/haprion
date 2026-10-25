"""haprion-node-prepare: step 4 again on a prepared node, from its node.conf (B361).

Pass N, part 03's own point: a node installed from apt and joined in the
interface had no way to run step 4 again when a release changed what it sets
up - the documented way needed the source tree and an answers file.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest import mock

from haprion import accounts, config, node_package, restore_answers, restore_source
from tests.restore_fixture import FILES, NODE_CONF, build

BASE = Path(__file__).resolve().parents[1]
SCRIPT = BASE / "install" / "node" / "haprion-node-prepare"
INSTALL = BASE / "install"
LIB = INSTALL / "lib.sh"


def load() -> ModuleType:
    loader = importlib.machinery.SourceFileLoader("haprion_node_prepare", str(SCRIPT))
    spec = importlib.util.spec_from_loader("haprion_node_prepare", loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


PREPARE = load()


def restored(node_conf: str, cluster: str) -> str:
    """What a node restore derives from an archive carrying this node.conf."""

    work = Path(tempfile.mkdtemp())
    try:
        files = dict(FILES)
        files["/etc/haprion/node.conf"] = (node_conf, 0o600)
        source = restore_source.read(build(work, files=files))
        return restore_answers.derive(source, cluster, Path("/srv/haprion/published"))
    finally:
        shutil.rmtree(work)


def assignments(answers: str) -> list[str]:
    return [line for line in answers.splitlines() if line and not line.startswith("#")]


class TheAnswersAreTheRestoresReading(unittest.TestCase):
    """Two readers of node.conf, one on the manager and one on the node: the same answers."""

    def check(self, node_conf: str, cluster: str) -> None:
        answers, read_cluster = PREPARE.answers(node_conf)
        self.assertEqual(read_cluster, cluster)
        expected = [
            line
            for line in assignments(restored(node_conf, cluster))
            if not line.startswith("PUBLISH_ROOT=")
        ]
        self.assertEqual(assignments(answers), [*expected, "PREPARED_AGAIN=yes"])

    def test_the_fixture(self) -> None:
        self.check(NODE_CONF, "alpha")

    def test_without_a_certificate_account(self) -> None:
        self.check(NODE_CONF.split("\n\n# Where this node fetches certificates")[0] + "\n", "alpha")

    def test_a_cluster_id_with_a_hyphen(self) -> None:
        self.check(NODE_CONF.replace('"alpha', '"edge-a'), "edge-a")

    def test_the_patterns_and_names_are_the_engine_s(self) -> None:
        self.assertEqual(PREPARE.CLUSTER_ID.pattern, config.CLUSTER_ID.pattern)
        for name in ("LINE", "SAFE", "NAME", "NODE_PATH"):
            with self.subTest(name):
                self.assertEqual(
                    getattr(PREPARE, name).pattern, getattr(restore_answers, name).pattern
                )
        self.assertEqual(PREPARE.REQUIRED, restore_answers.REQUIRED)
        self.assertEqual(PREPARE.SERVICE_ACCOUNTS, restore_answers.SERVICE_ACCOUNTS)
        self.assertEqual(PREPARE.LOGS_GROUP, accounts.LOGS_GROUP)
        self.assertEqual(
            PREPARE.PULL_USERS,
            {"CONFIG_PULL_USER": accounts.PULL, "CERT_PULL_USER": accounts.CERT_PULL},
        )


class TheAnswersRenderNodeConfBack(unittest.TestCase):
    def test_step_four_s_template_gives_back_the_same_bytes(self) -> None:
        work = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, work)
        answers, cluster = PREPARE.answers(NODE_CONF)
        (work / "answers.env").write_text(answers, encoding="utf-8")
        script = (
            f"set -euo pipefail; source {LIB}; source {work / 'answers.env'}; "
            f'render_node_conf {cluster} "$(cluster_value NODE_PATH {cluster})" '
            f"{accounts.LOGS_GROUP}"
        )
        rendered = subprocess.run(  # fixed interpreter, script built here
            ["/bin/bash", "-c", script], check=True, capture_output=True, text=True
        ).stdout
        self.assertEqual(rendered, NODE_CONF)


class WhatStopsIt(unittest.TestCase):
    def refused(self, node_conf: str, message: str) -> None:
        with self.assertRaisesRegex(PREPARE.Refused, message):
            PREPARE.answers(node_conf)

    def test_a_value_that_could_expand(self) -> None:
        self.refused(NODE_CONF.replace('MANAGER="mgr.example.com"', 'MANAGER="$(id)"'), "MANAGER")

    def test_a_missing_line(self) -> None:
        self.refused(NODE_CONF.replace('CONFIG_PULL_KEY="', 'X="'), "CONFIG_PULL_KEY")

    def test_other_service_accounts(self) -> None:
        self.refused(
            NODE_CONF.replace("_haprion-trigger _haprion-status", "a b", 1), "service accounts"
        )

    def test_another_cluster_s_path(self) -> None:
        self.refused(
            NODE_CONF.replace('CONFIG_REMOTE_PATH="alpha/', 'CONFIG_REMOTE_PATH="beta/'), "REMOTE"
        )


class TheCommand(unittest.TestCase):
    """main() with a stand-in step 4."""

    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="prepare-"))
        self.addCleanup(shutil.rmtree, self.root, True)
        self.install = self.root / "install"
        self.install.mkdir()
        self.node_conf = self.root / "node.conf"
        self.node_conf.write_text(NODE_CONF)
        self.state = self.root / "lib"
        patches: list[Any] = [
            mock.patch.object(PREPARE, "INSTALL", self.install),
            mock.patch.object(PREPARE, "NODE_CONF", self.node_conf),
            mock.patch.object(PREPARE, "STATE_DIR", self.state),
            mock.patch.object(PREPARE.os, "geteuid", return_value=0),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)

    def step(self, exit_code: int) -> Path:
        seen = self.root / "seen"
        step = self.install / "04-node-prepare"
        step.write_text(f'#!/bin/sh\necho "$1 $2" > {seen}\nexit {exit_code}\n')
        step.chmod(0o755)
        return seen

    def test_it_runs_step_four_with_the_answers_and_the_cluster(self) -> None:
        seen = self.step(0)
        self.assertEqual(PREPARE.main(), 0)
        answers = self.state / "prepare.env"
        self.assertEqual(seen.read_text().split(), [str(answers), "alpha"])
        self.assertEqual(oct(answers.stat().st_mode & 0o777), "0o600")
        self.assertIn("PREPARED_AGAIN=yes", answers.read_text())

    def test_a_stopped_step_is_its_exit_code(self) -> None:
        self.step(1)
        self.assertEqual(PREPARE.main(), 1)

    def test_a_node_never_prepared_is_told_how(self) -> None:
        self.step(0)
        self.node_conf.unlink()
        with mock.patch.object(PREPARE.sys, "stderr") as stderr:
            self.assertEqual(PREPARE.main(), 64)
        self.assertIn(
            "haprion-node-key", "".join(call.args[0] for call in stderr.write.call_args_list)
        )

    def test_only_root(self) -> None:
        with (
            mock.patch.object(PREPARE.os, "geteuid", return_value=1000),
            mock.patch.object(PREPARE.sys, "stderr"),
        ):
            self.assertEqual(PREPARE.main(), 77)


class TheRecordOfTheStep(unittest.TestCase):
    """The postinst's question: is the step this package brings the one that last ran here?"""

    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="prepared-"))
        self.addCleanup(shutil.rmtree, self.root, True)
        self.step = self.root / "install"
        (self.step / "sysusers").mkdir(parents=True)
        (self.step / "04-node-prepare").write_text("step\n")
        (self.step / "sysusers" / "haprion-node.conf").write_text("u x\n")
        self.record = self.root / "state" / "prepared"

    def bash(self, call: str) -> int:
        return subprocess.run(  # fixed interpreter, the package's own files
            [
                "/bin/bash",
                "-c",
                f'. "{LIB}" && . "{INSTALL}/node-installation.sh" && {call} "$1"',
                "record",
                str(self.step),
            ],
            env={**os.environ, "NODE_PREPARED": str(self.record)},
            capture_output=True,
            text=True,
            check=False,
        ).returncode

    def test_no_record_is_a_step_not_run(self) -> None:
        self.assertNotEqual(self.bash("node_prepared_by"), 0)

    def test_the_recorded_step_is_current_until_a_file_changes(self) -> None:
        self.assertEqual(self.bash("record_node_prepared"), 0)
        self.assertEqual(self.bash("node_prepared_by"), 0)
        (self.step / "sysusers" / "haprion-node.conf").write_text("u y\n")
        self.assertNotEqual(self.bash("node_prepared_by"), 0)

    def test_step_four_records_itself_before_either_quiet_ending(self) -> None:
        step = (INSTALL / "04-node-prepare").read_text()
        record = step.index('record_node_prepared "$PWD"')
        self.assertLess(
            record, step.index('if [[ "${JOINED_BY_MANAGER:-}" == yes ]]; then\n    echo')
        )
        self.assertLess(record, step.index('if [[ "${PREPARED_AGAIN:-}" == yes ]]; then\n    echo'))

    def test_the_postinst_says_when_to_run_it_on_a_joined_node(self) -> None:
        script = node_package.POSTINST
        guard = script.index("if [ -f /etc/haprion/node.conf ]; then")
        self.assertLess(guard, script.index(f"node_prepared_by {node_package.INSTALL_DIR}"))
        self.assertIn("run  sudo haprion-node-prepare", script)
        self.assertEqual(
            node_package.CONTENTS["usr/sbin/haprion-node-prepare"],
            ("install/node/haprion-node-prepare", 0o755),
        )


STATUS_SCRIPT = BASE / "install" / "node" / "haprion-node-status"


def status_reader(record: Path, step: Path) -> dict[str, Any]:
    """`step_digest` and `read_preparation`, cut verbatim from the node's status script."""

    text = STATUS_SCRIPT.read_text()
    code = text[text.index("def step_digest(") : text.index("def run(")]
    import hashlib

    namespace: dict[str, Any] = {
        "hashlib": hashlib,
        "Path": Path,
        "Any": Any,
        "NODE_PREPARED": record,
        "NODE_STEP": step,
    }
    exec(compile(code, str(STATUS_SCRIPT), "exec"), namespace)  # noqa: S102 - the script's own code
    return namespace


class TheStatusSaysIt(TheRecordOfTheStep):
    """B363: a node upgraded unattended is read by nobody; its status says it instead."""

    def test_the_node_s_digest_is_the_shell_s(self) -> None:
        (self.step / "sysusers" / "a-b.conf").write_text("x\n")
        (self.step / "a_b").write_text("y\n")
        (self.step / "link").symlink_to(self.step / "a_b")
        self.assertEqual(self.bash("record_node_prepared"), 0)
        reader = status_reader(self.record, self.step)
        self.assertEqual(reader["step_digest"](self.step), self.record.read_text().strip())

    def test_current_after_the_step_and_not_after_a_change(self) -> None:
        reader = status_reader(self.record, self.step)
        self.assertEqual(reader["read_preparation"](), {"current": False})
        self.assertEqual(self.bash("record_node_prepared"), 0)
        self.assertEqual(reader["read_preparation"](), {"current": True})
        (self.step / "04-node-prepare").write_text("step, changed\n")
        self.assertEqual(reader["read_preparation"](), {"current": False})

    def test_an_unreadable_step_is_null(self) -> None:
        self.assertEqual(self.bash("record_node_prepared"), 0)
        reader = status_reader(self.record, self.root / "missing")
        self.assertEqual(reader["read_preparation"](), {"current": False})
        (self.step / "04-node-prepare").chmod(0)
        self.addCleanup((self.step / "04-node-prepare").chmod, 0o644)
        if os.geteuid() != 0:
            self.assertIsNone(status_reader(self.record, self.step)["read_preparation"]())

    def test_the_status_carries_it_and_the_contract_names_it(self) -> None:
        text = STATUS_SCRIPT.read_text()
        self.assertIn('"preparation": read_preparation(),', text)
        schema = (BASE / "schemas/v1/haprion-status.schema.json").read_text()
        self.assertIn('"preparation": {', schema)


if __name__ == "__main__":
    unittest.main()
