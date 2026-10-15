"""A node script the manager runs without sudo reads nothing the installation closed.

The other node tests run each script as the test's own user against files the
test owns, so they pass whatever the script's account on a node may read. The
server test read the pool's CA from /etc/haproxy/certs, a directory only root
may enter, and every test passed while every node refused it (review 26-10-12).

Both halves are read from the installation rather than written here: which
scripts the manager's keys run without sudo from `03-manager-keys`, and which
directories are closed to other accounts from `04-node-prepare`.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

INSTALL = Path(__file__).resolve().parents[1] / "install"
# lib.sh's table of the manager's keys: purpose, key, account, forced command (B317).
FORCED = re.compile(r'^    "[A-Z_]+ \S+ \S+ (sudo -n )?/usr/sbin/(haprion-[a-z-]+)', re.MULTILINE)
ASSIGNED = re.compile(r'^([A-Z_]+)="([^"$]+)"$', re.MULTILINE)
ENSURED = re.compile(r"^\s*ensure_dir\s+(\S+)\s+\S+\s+([0-7]{3,4})\s*$", re.MULTILINE)


def run_without_sudo() -> set[str]:
    return {script for sudo, script in FORCED.findall((INSTALL / "lib.sh").read_text()) if not sudo}


def closed_directories() -> set[str]:
    """Directories `04-node-prepare` gives no permission for other accounts."""

    text = (INSTALL / "04-node-prepare").read_text()
    values = dict(ASSIGNED.findall(text))
    closed = set()
    for written, mode in ENSURED.findall(text):
        path = written.strip('"')
        variable = re.fullmatch(r"\$\{?([A-Z_]+)\}?", path)
        if variable:
            path = values.get(variable.group(1), "")
        if path.startswith("/") and mode.endswith("0"):
            closed.add(path)
    return closed


class TheInstallationIsReadAsWritten(unittest.TestCase):
    """The readers still find what they look for, or the test below proves nothing."""

    def test_the_server_test_is_among_the_scripts_run_without_sudo(self) -> None:
        self.assertIn("haprion-health-probe", run_without_sudo())

    def test_the_certificate_directory_is_among_the_closed_ones(self) -> None:
        self.assertIn("/etc/haproxy/certs", closed_directories())
        self.assertIn("/var/lib/haprion", closed_directories())


class AScriptRunWithoutSudo(unittest.TestCase):
    def test_names_no_directory_closed_to_its_account(self) -> None:
        closed = closed_directories()
        for script in sorted(run_without_sudo()):
            text = (INSTALL / "node" / script).read_text()
            for directory in sorted(closed):
                with self.subTest(script=script, directory=directory):
                    self.assertFalse(directory in text, f"{script} reads under {directory}")


if __name__ == "__main__":
    unittest.main()
