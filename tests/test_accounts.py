"""The fixed account names (B266) are stated three times; this holds them together.

`haproxy_mgmt.accounts` for the engine, `install/accounts.sh` for the
installation steps, and the sysusers fragments that create the accounts. A name
changed in one and not the others would install an account nobody uses, or a
sudoers rule for an account that does not exist.
"""

from __future__ import annotations

import re
import subprocess
import tempfile
import unittest
from pathlib import Path

from haproxy_mgmt import accounts

INSTALL = Path(__file__).resolve().parents[1] / "install"
MANAGER = INSTALL / "sysusers/haprion.conf"
NODE = INSTALL / "sysusers/haprion-node.conf"

#
# accounts.sh's variable for each name in the module. A name the module has
# and the script does not is a failure, not a skip.
#
SHELL_NAMES = {
    "CONFIG_GROUP": "CONFIG_GROUP",
    "PLATFORM_GROUP": "PLATFORM_GROUP",
    "PULL": "PULL_USER",
    "CERT_PULL": "CERT_PULL_USER",
    "WEB": "WEB_USER",
    "WORKER": "WORKER_USER",
    "POLLER": "POLLER_USER",
    "COLLECTOR": "COLLECTOR_USER",
    "OIDC": "OIDC_USER",
    "DATABASE": "DB_NAME",
    "MIGRATION_ROLE": "DB_MIGRATION_ROLE",
    "TRIGGER": "TRIGGER_USER",
    "STATUS": "STATUS_USER",
    "BACKUP": "BACKUP_USER",
    "LOGREAD": "LOGREAD_USER",
    "LOGS_GROUP": "LOGS_GROUP",
    "WAF_GROUP": "WAF_GROUP",
    "DNS_GROUP": "DNS_GROUP",
    "WEB_UNIT": "WEB_UNIT",
    "WORKER_UNIT": "WORKER_UNIT",
    "POLLER_UNIT": "POLLER_UNIT",
    "WORKER_SUDOERS": "WORKER_SUDOERS",
    "POLLER_SUDOERS": "POLLER_SUDOERS",
}


def module_names() -> dict[str, str]:
    return {
        name: value
        for name, value in vars(accounts).items()
        if name.isupper() and isinstance(value, str)
    }


def shell_names() -> dict[str, str]:
    script = f'source "{INSTALL / "accounts.sh"}"; ' + " ".join(
        f'printf "%s=%s\\n" {variable} "${variable}";' for variable in SHELL_NAMES.values()
    )
    done = subprocess.run(  # noqa: S603 - fixed interpreter, the repository's file
        ["/bin/bash", "-c", script], capture_output=True, text=True, check=True
    )
    return dict(line.split("=", 1) for line in done.stdout.splitlines())


def sysusers(path: Path) -> tuple[set[str], set[str], set[tuple[str, str]]]:
    """Users, groups and memberships a fragment declares."""

    users: set[str] = set()
    groups: set[str] = set()
    members: set[tuple[str, str]] = set()
    for line in path.read_text().splitlines():
        fields = re.findall(r'"[^"]*"|\S+', line)
        if not fields or fields[0].startswith("#"):
            continue
        if fields[0] == "u":
            users.add(fields[1])
        elif fields[0] == "g":
            groups.add(fields[1])
        elif fields[0] == "m":
            members.add((fields[1], fields[2]))
    return users, groups, members


class TheNamesAgree(unittest.TestCase):
    def test_every_module_name_has_a_shell_name_and_they_match(self) -> None:
        names = module_names()
        self.assertEqual(set(names), set(SHELL_NAMES))
        shell = shell_names()
        for name, variable in SHELL_NAMES.items():
            with self.subTest(name=name):
                self.assertEqual(shell[variable], names[name])

    def test_the_manager_fragment_creates_exactly_the_manager_accounts(self) -> None:
        users, groups, members = sysusers(MANAGER)
        self.assertEqual(
            users,
            {
                accounts.PULL,
                accounts.CERT_PULL,
                accounts.WEB,
                accounts.WORKER,
                accounts.POLLER,
                accounts.COLLECTOR,
                accounts.OIDC,
            },
        )
        self.assertEqual(groups, {accounts.CONFIG_GROUP, accounts.PLATFORM_GROUP})
        self.assertEqual(
            members,
            {
                (accounts.WORKER, accounts.CONFIG_GROUP),
                (accounts.WEB, accounts.PLATFORM_GROUP),
                (accounts.WORKER, accounts.PLATFORM_GROUP),
                (accounts.POLLER, accounts.PLATFORM_GROUP),
            },
        )

    def test_the_node_fragment_creates_exactly_the_node_accounts(self) -> None:
        users, groups, members = sysusers(NODE)
        self.assertEqual(
            users, {accounts.TRIGGER, accounts.STATUS, accounts.BACKUP, accounts.LOGREAD}
        )
        self.assertEqual(groups, {accounts.LOGS_GROUP, accounts.WAF_GROUP, accounts.DNS_GROUP})
        self.assertEqual(members, {(accounts.LOGREAD, accounts.LOGS_GROUP)})

    def test_each_identity_reaches_a_node_account(self) -> None:
        node_users = sysusers(NODE)[0]
        for identity, account in accounts.IDENTITY_ACCOUNTS.items():
            with self.subTest(identity=identity):
                self.assertIn(account, node_users)

    def test_service_accounts_carry_the_underscore_and_the_operators_group_does_not(self) -> None:
        for name, value in module_names().items():
            with self.subTest(name=name):
                if name in ("CONFIG_GROUP", "DATABASE") or name.endswith(("_UNIT", "_SUDOERS")):
                    self.assertFalse(value.startswith("_"))
                else:
                    self.assertTrue(value.startswith("_haprion-"), value)


class AnOldAnswersFile(unittest.TestCase):
    def load(self, text: str) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as raw:
            answers = Path(raw) / "answers.env"
            answers.write_text(text)
            return subprocess.run(  # noqa: S603 - fixed interpreter, the repository's library
                ["/bin/bash", "-c", f'source "{INSTALL / "lib.sh"}"; load_answers "{answers}"'],
                capture_output=True,
                text=True,
                check=False,
            )

    def test_one_still_naming_an_account_is_refused_by_name(self) -> None:
        done = self.load('MANAGER_HOST="mgr.example.com"\nWEB_USER=svc-web\n')
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("sets WEB_USER, which is no longer an answer", done.stderr)

    def test_one_without_account_names_loads(self) -> None:
        done = self.load('MANAGER_HOST="mgr.example.com"\n')
        self.assertEqual(done.returncode, 0, done.stderr)


if __name__ == "__main__":
    unittest.main()
