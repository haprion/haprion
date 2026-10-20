"""The weekly restore check measures a restore against the archive, not against live.

Compared with the live database, the check failed every week retention had
something to do between the dump and the check (2026-09-20: job live 59,
restored 63) while the restore itself was perfect. What a restore owes is the
rows the archive holds; how far live has moved since is information.
"""

from __future__ import annotations

import os
import re
import stat
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "install/platform/bin/haprion-backup"

#
# What `pg_restore --data-only --table=<t> --file=-` writes: a header, one COPY
# block, one line per row, and the `\.` terminator. A value with a newline in it
# is escaped by COPY, so it is still one line; a value that is the two characters
# backslash-dot is escaped as `\\.` and must not end the block.
#
FAKE_PG_RESTORE = r"""#!/bin/sh
table=""
for argument in "$@"; do
    case "$argument" in --table=*) table="${argument#--table=}" ;; esac
done
line() { printf '%s\n' "$1"; }
line "--"
line "-- PostgreSQL database dump"
line "SET statement_timeout = 0;"
case "$table" in
    job)
        line 'COPY public.job (id, result) FROM stdin;'
        line '1	r'
        line '2	two\nlines'
        line '3	\\.'
        line '\.'
        ;;
    app_user)
        line 'COPY public.app_user (id) FROM stdin;'
        line '1'
        line '\.'
        ;;
    *)
        line "COPY public.$table (id) FROM stdin;"
        line '\.'
        ;;
esac
line "-- dump complete"
"""


def function(name: str, source: str) -> str:
    match = re.search(rf"^{name}\(\) \{{\n.*?^\}}\n", source, re.MULTILINE | re.DOTALL)
    if match is None:
        raise AssertionError(f"{name} is not defined in {SCRIPT}")
    return match.group(0)


class TheRestoreCheck(unittest.TestCase):
    source: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.source = SCRIPT.read_text()

    def test_the_archive_is_counted_one_row_per_line_between_copy_and_terminator(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fake = Path(directory) / "pg_restore"
            fake.write_text(FAKE_PG_RESTORE)
            fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
            program = (
                "set -Eeuo pipefail\n"
                "TABLES=(app_user app_session audit_event login_attempt job)\n"
                + function("archive_counts", self.source)
                + "archive_counts /nonexistent.dump\n"
            )
            result = subprocess.run(  # noqa: S603 - fixed program, test fixture PATH
                ["/bin/bash", "-c", program],
                capture_output=True,
                text=True,
                check=True,
                env={**os.environ, "PATH": f"{directory}:{os.environ['PATH']}"},
            )

        self.assertEqual(
            result.stdout.splitlines(),
            ["app_user=1", "app_session=0", "audit_event=0", "login_attempt=0", "job=3"],
        )

    def test_the_restore_is_compared_with_the_archive_and_live_is_only_shown(self) -> None:
        verify = function("do_verify_restore", self.source)

        self.assertIn('expected="$(archive_counts "$archive")"', verify)
        self.assertIn('done <<<"$expected"', verify)
        self.assertIn('"$expected_count" == "$restored_count"', verify)
        self.assertNotIn('"$live_count" == "$restored_count"', verify)
        self.assertIn('die "the restore does not match the archive"', verify)


class ANewInstallationIsBackedUpBeforeItHasAnAccount(unittest.TestCase):
    """haprion-setup asks for the first account after its last step, and step
    06 proves the first dump by restoring it: the check refused a restore with
    no account and stopped every new installation (26-10-15, the install
    test). The schema's version row is what an empty restore lacks."""

    def brought_back(self, restored: str) -> subprocess.CompletedProcess[str]:
        source = SCRIPT.read_text()
        program = (
            "set -Eeuo pipefail\n"
            'die() { echo "ERROR: $*" >&2; exit 1; }\n'
            + function("restore_brought_back", source)
            + 'restore_brought_back "$1"\n'
        )
        return subprocess.run(  # noqa: S603 - fixed program
            ["/bin/bash", "-c", program, "bash", restored],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_a_restore_with_the_version_and_no_account_is_proven(self) -> None:
        done = self.brought_back("alembic_version=1\napp_user=0\njob=0")
        self.assertEqual(done.returncode, 0, done.stderr)

    def test_a_restore_without_the_version_brought_nothing_back(self) -> None:
        done = self.brought_back("alembic_version=0\napp_user=0\njob=0")
        self.assertEqual(done.returncode, 1)
        self.assertIn("brought nothing back", done.stderr)

    def test_the_version_is_counted_and_an_account_is_not_required(self) -> None:
        source = SCRIPT.read_text()
        self.assertIn("TABLES=(alembic_version ", source)
        self.assertNotIn("holds no accounts", source)


if __name__ == "__main__":
    unittest.main()


class TheRestoredHashIsALocalAccounts(unittest.TestCase):
    """Review 2026-10-20, R2: an OIDC account has no hash, by the schema's rule.

    The check read the oldest account of any kind, so an installation whose
    oldest account was OIDC failed every restore check of a sound dump.
    """

    def checked(self, answer: str) -> subprocess.CompletedProcess[str]:
        source = SCRIPT.read_text()
        program = (
            "set -Eeuo pipefail\n"
            'log() { echo "$*"; }\n'
            'die() { echo "ERROR: $*" >&2; exit 1; }\n'
            'psql_scratch() { printf "%s\\n" "$*" >&2; printf "%s" "$ANSWER"; }\n'
            + function("restored_hash_intact", source)
            + "restored_hash_intact scratch\n"
        )
        return subprocess.run(  # noqa: S603 - fixed program
            ["/bin/bash", "-c", program],
            capture_output=True,
            text=True,
            check=False,
            env={**os.environ, "ANSWER": answer},
        )

    def test_only_a_local_account_is_read(self) -> None:
        done = self.checked("$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("where source = 'local'", done.stderr)
        self.assertIn("a restored password hash is intact", done.stdout)

    def test_no_local_account_is_not_a_failure(self) -> None:
        done = self.checked("")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("no local account", done.stdout)

    def test_a_local_hash_that_is_not_argon2id_fails(self) -> None:
        done = self.checked("plain")
        self.assertEqual(done.returncode, 1)
        self.assertIn("is not Argon2id", done.stderr)


class OneRunAtATime(unittest.TestCase):
    """Review 2026-10-20, R3: a run by hand beside the timer's shared its files."""

    def locked(self, lock: Path, *, wait: int) -> subprocess.CompletedProcess[str]:
        source = SCRIPT.read_text()
        program = (
            "set -Eeuo pipefail\n"
            'log() { echo "$*"; }\n'
            'die() { echo "ERROR: $*" >&2; exit 1; }\n'
            f"LOCK={lock}\nLOCK_WAIT_SECONDS={wait}\n"
            + function("take_lock", source)
            + "take_lock\necho locked\n"
        )
        return subprocess.run(  # noqa: S603 - fixed program
            ["/bin/bash", "-c", program], capture_output=True, text=True, check=False
        )

    def test_dump_and_verify_take_the_lock_and_list_does_not(self) -> None:
        source = SCRIPT.read_text()
        self.assertIn("dump)           take_lock; do_dump ;;", source)
        self.assertIn("verify-restore) take_lock; do_verify_restore ;;", source)

    def test_a_free_lock_is_taken_at_once(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            done = self.locked(Path(directory) / "lock", wait=1)
        self.assertEqual((done.returncode, done.stdout.strip()), (0, "locked"), done.stderr)

    def test_a_held_lock_is_waited_for_and_then_named(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lock = Path(directory) / "lock"
            holder = subprocess.Popen(  # noqa: S603 - fixed program
                ["/usr/bin/flock", str(lock), "/usr/bin/sleep", "5"]
            )
            self.addCleanup(holder.wait)
            self.addCleanup(holder.kill)
            for _ in range(50):
                if lock.exists():
                    break
                time.sleep(0.05)
            done = self.locked(lock, wait=1)
        self.assertEqual(done.returncode, 1)
        self.assertIn("waiting for it", done.stdout)
        self.assertIn("still holds", done.stderr)
