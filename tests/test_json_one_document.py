"""`--json` is one document on stdout, also when the helper never answered (review 2026-10-22, 4-2).

The read commands wrote nothing to stdout when sudo refused them or the helper
failed before it wrote its envelope, so `stdout | from_json` read an empty
string; the apply commands already answered. Every command here is asked once
with a helper that says only what sudo says, and must print exactly one
envelope in its contract with the reason in it.
"""

from __future__ import annotations

import ast
import io
import subprocess
import unittest
from collections.abc import Callable
from pathlib import Path
from typing import Any
from unittest import mock

from haprion import exit_codes
from haprion.cli import (
    cert_list,
    cluster,
    cluster_settings,
    history_reset,
    inventory,
    list_backups,
    network,
    node,
    objects,
    probe,
    server_state,
    status,
)
from tests.contract_schema import assert_contract

SUDO_SAYS = "sudo: a password is required"


def silent(*_args: Any, **_kwargs: Any) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(["sudo"], 1, "", f"{SUDO_SAYS}\n")


def _streams(main: Callable[..., int], argv: list[str], **injected: Any) -> tuple[int, str]:
    out = io.StringIO()
    code = main(argv, stream_out=out, stream_err=io.StringIO(), **injected)
    return code, out.getvalue()


class AHelperThatNeverAnswered(unittest.TestCase):
    def assert_one_refusal(self, schema: str, code: int, stdout: str) -> None:
        self.assertEqual(code, exit_codes.UNAVAILABLE)
        self.assertEqual(len(stdout.splitlines()), 1, stdout)
        answer = assert_contract(schema, stdout)
        self.assertEqual(answer["outcome"], "failed")
        self.assertEqual(answer["error"]["code"], "dependency_unavailable")
        self.assertIn(SUDO_SAYS, answer["error"]["message"])

    def test_the_read_commands(self) -> None:
        for name, main, schema in (
            ("status", status.main, "haprion-status"),
            ("inventory", inventory.main, "haprion-inventory"),
            ("network", network.main, "haprion-network"),
            ("objects", objects.main, "haprion-objects"),
            ("cert_list", cert_list.main, "haprion-cert-list"),
            ("list_backups", list_backups.main, "haprion-list-backups"),
            ("cluster_settings", cluster_settings.main, "haprion-cluster-settings"),
        ):
            with self.subTest(name):
                code, stdout = _streams(main, ["-c", "alpha", "--json"], run_helper=silent)
                self.assert_one_refusal(schema, code, stdout)

    def test_the_commands_that_ask_through_sudo_with_a_terminal(self) -> None:
        for module, runner, argv, schema in (
            (
                probe,
                "run_probe_helper",
                ["-c", "alpha", "-t", "198.51.100.10:80", "--json"],
                "haprion-probe",
            ),
            (
                server_state,
                "run_helper",
                ["-c", "alpha", "-o", "shop", "drain", "198.51.100.10:8080", "--json"],
                "haprion-server-state",
            ),
        ):
            with self.subTest(module.__name__):
                out = io.StringIO()
                with (
                    mock.patch.object(module, runner, side_effect=silent),
                    mock.patch("sys.stderr", io.StringIO()),
                ):
                    code = module.main(argv, writer=out)
                self.assert_one_refusal(schema, code, out.getvalue())

    def test_the_node_and_cluster_commands(self) -> None:
        for main, argv, schema in (
            (node.main, ["remove", "-c", "alpha", "node-b", "--json"], "haprion-cluster-node"),
            (cluster.main, ["remove", "-c", "alpha", "--json"], "haprion-cluster-define"),
        ):
            with self.subTest(schema):
                out = io.StringIO()
                code = main(argv, stdout=out, stderr=io.StringIO(), run=silent)
                self.assert_one_refusal(schema, code, out.getvalue())


class AHistoryResetPublishesOnStderr(unittest.TestCase):
    def test_the_publish_s_progress_is_not_on_stdout(self) -> None:
        with mock.patch.object(subprocess, "run") as run:
            run.return_value = subprocess.CompletedProcess([], 0)
            history_reset._publish("alpha")
        self.assertIs(run.call_args.kwargs["stdout"], __import__("sys").stderr)


if __name__ == "__main__":
    unittest.main()


class OneEnvelopeBuilder(unittest.TestCase):
    """Review 2026-10-22, 4-9: `apply_common` and four interface tools built their own.

    Without `haprion.envelope`'s invariants, and with codes the contract does
    not have (`refused`, `unavailable`). A dictionary that has an envelope's
    `ok`, `outcome` and `operation` is built there and nowhere else.
    """

    def test_no_module_writes_an_envelope_by_hand(self) -> None:
        root = Path(__file__).resolve().parents[1]
        built = []
        for source in (root / "src" / "haprion", root / "ui" / "src" / "haprion_ui"):
            for path in sorted(source.rglob("*.py")):
                if path.name == "envelope.py":
                    continue
                for found in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                    if isinstance(found, ast.Dict):
                        keys = {key.value for key in found.keys if isinstance(key, ast.Constant)}
                        if {"ok", "outcome", "operation"} <= keys:
                            built.append(f"{path.relative_to(root)}:{found.lineno}")
        self.assertEqual(built, [], "build it with haprion.envelope")
