"""A test restore lets its VM fetch for the run alone (B398)."""

from __future__ import annotations

import fcntl
import os
import unittest
from pathlib import Path

from haprion import accounts, change_journal, cluster_lock, restore_fetch
from haprion.config import load_policy
from tests.test_node_enrollment import key
from tests.test_pull_keys import Fixture, Site

RUN = "r261030-0a1b2c3d"
NAME = f"restore-{RUN}"
KEYS = {"config": key(71), "cert": key(72)}
ADDRESS = "192.0.2.29"


class Access(Fixture):
    def setUp(self) -> None:
        super().setUp()
        self.site = Site(self.root)
        policy = load_policy(self.site.policy_file, require_secure=False)
        self.access = restore_fetch.for_policy(
            policy,
            locations=self.site.locations,
            lock_root=self.root / "locks",
            journal=self.site.locations.journal,
            wait=0.0,
        )

    def lines(self, account: str) -> list[str]:
        return [
            line
            for line in self.site.authorized_keys(account).read_text().splitlines()
            if NAME in line
        ]


class TheLinesAreTheNodesOwnFormat(Access):
    def test_each_account_gets_one_line_from_the_test_address_alone(self) -> None:
        self.access.grant(RUN, "alpha", ADDRESS, KEYS)

        [config] = self.lines("_haprion-pull")
        [cert] = self.lines("_haprion-cert-pull")
        self.assertRegex(
            config,
            rf'^from="{ADDRESS}",restrict,expiry-time="\d{{12}}Z",'
            rf'command="/usr/bin/rrsync -ro {self.site.publish_root / "alpha"}" '
            rf"{KEYS['config']} {NAME} config pull$",
        )
        self.assertIn(f"-ro {self.site.certificates / 'alpha'}", cert)
        self.assertTrue(cert.endswith(f"{KEYS['cert']} {NAME} certificate pull"))

    def test_the_nodes_own_lines_and_the_rest_are_untouched(self) -> None:
        before = {
            account: self.site.authorized_keys(account).read_text()
            for account in ("_haprion-pull", "_haprion-cert-pull")
        }

        self.access.grant(RUN, "alpha", ADDRESS, KEYS)
        self.access.revoke(RUN, "alpha")

        for account, text in before.items():
            self.assertEqual(self.site.authorized_keys(account).read_text(), text)

    def test_an_unfinished_node_change_is_left_for_its_own_commands(self) -> None:
        journal = self.site.locations.journal
        change_journal._write_record(
            journal, change_journal.Record("add", "alpha", ())
        )
        accounts_before = {
            account: self.site.authorized_keys(account).read_bytes()
            for account in ("_haprion-pull", "_haprion-cert-pull")
        }
        recorded = journal.read_bytes()

        with self.assertRaisesRegex(restore_fetch.FetchAccessError, "unfinished node change"):
            self.access.grant(RUN, "alpha", ADDRESS, KEYS)
        with self.assertRaisesRegex(restore_fetch.FetchAccessError, "unfinished node change"):
            self.access.revoke(RUN, "alpha")

        self.assertEqual(journal.read_bytes(), recorded)
        for account, content in accounts_before.items():
            self.assertEqual(self.site.authorized_keys(account).read_bytes(), content)

    def test_an_unreadable_change_record_is_a_refusal_not_a_traceback(self) -> None:
        self.site.locations.journal.write_text("not a record")
        with self.assertRaisesRegex(restore_fetch.FetchAccessError, "unreadable"):
            self.access.revoke(RUN, "alpha")

    def test_taking_them_out_twice_is_the_same_as_once(self) -> None:
        self.access.grant(RUN, "alpha", ADDRESS, KEYS)
        self.access.revoke(RUN, "alpha")
        self.access.revoke(RUN, "alpha")

        self.assertEqual(self.lines("_haprion-pull") + self.lines("_haprion-cert-pull"), [])

    def test_granting_again_replaces_and_does_not_duplicate(self) -> None:
        self.access.grant(RUN, "alpha", ADDRESS, KEYS)
        self.access.grant(RUN, "alpha", ADDRESS, KEYS)

        self.assertEqual(len(self.lines("_haprion-pull")), 1)


class ANormalRewriteKeepsThem(Access):
    def test_pull_keys_leaves_a_temporary_line_alone(self) -> None:
        self.access.grant(RUN, "alpha", ADDRESS, KEYS)
        held = (self.lines("_haprion-pull"), self.lines("_haprion-cert-pull"))

        report = self.site.run()

        self.assertEqual((self.lines("_haprion-pull"), self.lines("_haprion-cert-pull")), held)
        self.assertFalse(any(NAME in line for line in report.done + report.left))

    def test_a_node_added_beside_it_neither_loses_nor_doubles_it(self) -> None:
        from haprion.node_enrollment import keys_with

        self.access.grant(RUN, "alpha", ADDRESS, KEYS)
        path = self.site.authorized_keys("_haprion-pull")
        path.write_bytes(
            keys_with(path.read_bytes(), f"{key(50)} node-z config pull", "node-z", "config pull")
        )

        self.assertEqual(len(self.lines("_haprion-pull")), 1)

    def test_the_cluster_file_lock_a_node_change_holds_is_waited_for_then_refused(self) -> None:
        locks = self.root / "locks"
        locks.mkdir(exist_ok=True)
        descriptor = os.open(locks / "cluster-file.lock", os.O_RDWR | os.O_CREAT, 0o600)
        self.addCleanup(os.close, descriptor)
        fcntl.flock(descriptor, fcntl.LOCK_EX)

        with self.assertRaises(restore_fetch.FetchAccessError):
            self.access.grant(RUN, "alpha", ADDRESS, KEYS)
        self.assertEqual(self.lines("_haprion-pull"), [])
        self.assertTrue(issubclass(cluster_lock.LockBusy, Exception))


class WhatTheTargetReportsIsHeldToOneKey(Access):
    def test_only_public_keys_of_a_known_type_pass(self) -> None:
        self.assertEqual(restore_fetch.valid_keys(KEYS), KEYS)
        for bad in (
            {"config": 'command="x" ssh-ed25519 AAAA'},
            {"config": "ssh-ed25519 AAAA\nssh-ed25519 BBBB"},
            {"config": "ssh-ed25519 AAAA comment"},
            {"cert": KEYS["cert"]},
            {"config": KEYS["config"], "other": KEYS["config"]},
            "a string",
        ):
            with self.subTest(bad=bad), self.assertRaises(restore_fetch.FetchAccessError):
                restore_fetch.valid_keys(bad)

    def test_a_run_id_is_the_only_name(self) -> None:
        with self.assertRaises(restore_fetch.FetchAccessError):
            self.access.grant("node-a", "alpha", ADDRESS, KEYS)


class TheHelperMayWriteWhatItGrants(unittest.TestCase):
    """The helper's sandbox is read-only for /home: the pull accounts' keys need a path of their own."""

    def test_both_pull_accounts_ssh_directories_are_read_write_paths(self) -> None:
        unit = (
            Path(__file__).resolve().parents[1]
            / "install/platform/examples/haprion-node-restore-helper@.service.example"
        ).read_text(encoding="utf-8")
        line = next(line for line in unit.splitlines() if line.startswith("ReadWritePaths="))
        paths = [item.removeprefix("-") for item in line.split("=", 1)[1].split()]
        for account in (accounts.PULL, accounts.CERT_PULL):
            self.assertIn(f"/home/{account}/.ssh", paths)
        self.assertIn("ProtectHome=read-only", unit)
