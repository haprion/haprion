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
# node-lib.sh's table of the manager's keys: purpose, key, account, forced command (B317).
FORCED = re.compile(r'^    "[A-Z_]+ \S+ (\S+) (sudo -n )?/usr/sbin/(haprion-[a-z-]+)', re.MULTILINE)
ASSIGNED = re.compile(r'^([A-Z_]+)="([^"$]+)"$', re.MULTILINE)
ENSURED = re.compile(r"^\s*ensure_dir\s+(\S+)\s+(\S+)\s+([0-7]{3,4})\s*$", re.MULTILINE)
# `usermod -a -G "$GROUP" "$ACCOUNT"`: an account step 4 puts in a group.
JOINED = re.compile(r'^usermod -a -G "\$([A-Z_]+)" "\$([A-Z_]+)"$', re.MULTILINE)


def run_without_sudo() -> dict[str, str]:
    """Each script a key runs without sudo, and the account variable it runs as."""

    found = FORCED.findall((INSTALL / "node-lib.sh").read_text())
    return {script: account for account, sudo, script in found if not sudo}


def closed_directories() -> dict[str, str]:
    """Directories `04-node-prepare` gives no permission for other accounts, and their group.

    The group is the variable named after the colon (`"${A}:${LOGS_GROUP}"`),
    or empty: a member of that group may still enter (26-10-16, the traffic
    log's reader and /var/log/haprion).
    """

    text = (INSTALL / "04-node-prepare").read_text()
    values = dict(ASSIGNED.findall(text))
    closed = {}
    for written, owner, mode in ENSURED.findall(text):
        path = written.strip('"')
        variable = re.fullmatch(r"\$\{?([A-Z_]+)\}?", path)
        if variable:
            path = values.get(variable.group(1), "")
        if path.startswith("/") and mode.endswith("0"):
            group = re.search(r":\$\{?([A-Z_]+)\}?", owner)
            closed[path] = group.group(1) if group and mode[-2] in "57" else ""
    return closed


def memberships() -> set[tuple[str, str]]:
    """(group variable, account variable) for each account step 4 adds to a group."""

    return set(JOINED.findall((INSTALL / "04-node-prepare").read_text()))


class TheInstallationIsReadAsWritten(unittest.TestCase):
    """The readers still find what they look for, or the test below proves nothing."""

    def test_the_server_test_is_among_the_scripts_run_without_sudo(self) -> None:
        self.assertEqual(run_without_sudo()["haprion-health-probe"], "STATUS_USER")

    def test_the_certificate_directory_is_among_the_closed_ones(self) -> None:
        self.assertEqual(closed_directories()["/etc/haproxy/certs"], "")
        self.assertIn("/var/lib/haprion", closed_directories())

    def test_the_traffic_log_s_directory_is_open_to_its_group(self) -> None:
        self.assertEqual(closed_directories()["/var/log/haprion"], "LOGS_GROUP")
        self.assertIn(("LOGS_GROUP", "LOGREAD_USER"), memberships())


class AScriptRunWithoutSudo(unittest.TestCase):
    def test_names_no_directory_closed_to_its_account(self) -> None:
        closed = closed_directories()
        members = memberships()
        for script, account in sorted(run_without_sudo().items()):
            text = (INSTALL / "node" / script).read_text()
            for directory, group in sorted(closed.items()):
                if (group, account) in members:
                    continue
                with self.subTest(script=script, directory=directory):
                    self.assertFalse(directory in text, f"{script} reads under {directory}")


if __name__ == "__main__":
    unittest.main()
