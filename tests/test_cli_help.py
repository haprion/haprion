"""`--help` says what each flag is for, and keeps the examples as written (26-11-02)."""

from __future__ import annotations

import io
import subprocess
import sys
import tomllib
import unittest
from collections.abc import Callable
from contextlib import redirect_stdout
from pathlib import Path

from haprion.cli import cert_delete, cert_request, cert_target, cluster


def helptext(main: Callable[..., int], *argv: str) -> str:
    shown = io.StringIO()
    try:
        with redirect_stdout(shown):
            main([*argv, "--help"])
    except SystemExit:
        pass
    return shown.getvalue()


class HelpIsNotThin(unittest.TestCase):
    def test_each_flag_of_cluster_add_and_remove_has_a_line(self) -> None:
        added = helptext(cluster.main, "add")
        for phrase in (
            "the new cluster's ID",
            "the address the cluster serves on",
            "the VIP's prefix",
        ):
            self.assertIn(phrase, added)
        self.assertIn("the cluster to remove", helptext(cluster.main, "remove"))

    def test_cert_delete_and_cert_target_describe_their_arguments(self) -> None:
        self.assertIn("the ID of a certificate to delete", helptext(cert_delete.main))
        text = helptext(cert_target.main)
        for phrase in ("a cluster; may be repeated", "a receiver; may be repeated"):
            self.assertIn(phrase, text)

    def test_the_cert_request_example_keeps_its_own_lines(self) -> None:
        text = helptext(cert_request.main)
        self.assertIn("\n    haprion-cert-request --id shop.example", text)
        self.assertIn("\n        --cluster alpha --receiver lb-01", text)


def operator_commands() -> dict[str, str]:
    """Every command an operator types: the helpers and `-ask` clients read JSON, not argv."""

    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    scripts = tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"]["scripts"]
    return {
        name: target for name, target in scripts.items() if not name.endswith(("-helper", "-ask"))
    }


class HelpIsAnAnswer(unittest.TestCase):
    """`--help` is asked for, not a mistake: exit 0, on stdout (26-11-02).

    26-11-03 seven commands still answered it 64, haprion-node-restore among them, its
    usage on stderr. Every command in pyproject.toml is called, so a new one is too.
    """

    def test_every_operator_command_answers_help_with_exit_0_on_stdout(self) -> None:
        commands = operator_commands()
        self.assertGreater(len(commands), 20)
        for name, target in sorted(commands.items()):
            module, function = target.split(":")
            program = (
                "import sys\n"
                f"from {module} import {function} as main\n"
                f"sys.argv = [{name!r}, '--help']\n"
                "sys.exit(main())\n"
            )
            with self.subTest(command=name):
                done = subprocess.run(
                    [sys.executable, "-c", program],
                    capture_output=True,
                    text=True,
                    stdin=subprocess.DEVNULL,
                    timeout=60,
                    check=False,
                )
                self.assertEqual(done.returncode, 0, done.stderr[-500:])
                self.assertIn("usage", done.stdout.lower())


if __name__ == "__main__":
    unittest.main()
