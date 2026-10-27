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


class ADumpBeforeAMigration(unittest.TestCase):
    """Logic review 26-10-22, F1: a dump of its own before the schema changes."""

    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.dumps = self.root / "dumps"
        bin_ = self.root / "bin"
        bin_.mkdir()
        stubs = {
            "pg_dump": 'for a; do case "$a" in --file=*) echo dump > "${a#--file=}" ;; esac; done\n',
            "pg_restore": "echo '1; 0 0 TABLE public job'\n",
            "chown": "exit 0\n",
            "install": 'shift 7; mkdir -p "$@"\n',
        }
        for name, body in stubs.items():
            (bin_ / name).write_text("#!/bin/sh\n" + body)
            (bin_ / name).chmod(0o755)
        self.path = f"{bin_}:/usr/bin:/bin"

    def dump(self, before: str, after: str) -> subprocess.CompletedProcess[str]:
        source = SCRIPT.read_text()
        kept = re.search(r"^BEFORE_MIGRATION_KEPT=.*$", source, re.MULTILINE)
        if kept is None:
            self.fail("haprion-backup no longer states how many dumps before a migration it keeps")
        program = (
            "set -Eeuo pipefail\n"
            'log() { echo "$*"; }\nwarn() { echo "$*" >&2; }\n'
            'die() { echo "ERROR: $*" >&2; exit 1; }\nstep_log() { :; }\n'
            f"DUMP_DIR={self.dumps}\nDB_NAME=haprion\nDB_ROLE=r\nDISK_WARN_PERCENT=101\n"
            + kept.group(0)
            + "\n"
            + function("write_dump", source)
            + function("do_dump_before_migration", source)
            + f"do_dump_before_migration {before} {after}\n"
        )
        return subprocess.run(  # noqa: S603 - fixed program
            ["/bin/bash", "-c", program],
            capture_output=True,
            text=True,
            check=False,
            env={"PATH": self.path},
            cwd=self.root,
        )

    def test_named_by_both_revisions_apart_from_the_daily_ones_and_three_kept(self) -> None:
        self.dumps.mkdir()
        (self.dumps / "haprion-20261022.dump").write_text("daily")
        for step in range(4):
            done = self.dump(f"00{80 + step}", f"00{81 + step}")
            self.assertEqual(done.returncode, 0, done.stderr)
            time.sleep(1.1)
        kept = sorted(path.name for path in (self.dumps / "before-migration").iterdir())
        self.assertEqual(len(kept), 3)
        self.assertTrue(all(name.startswith("haprion-00") for name in kept))
        self.assertFalse(any(name.startswith("haprion-0080-to-0081-") for name in kept))
        self.assertEqual(
            sorted(path.name for path in self.dumps.glob("*.dump")), ["haprion-20261022.dump"]
        )

    def test_a_revision_that_is_not_one_is_refused(self) -> None:
        done = self.dump("0084", "../x")
        self.assertEqual(done.returncode, 1)
        self.assertIn("takes two schema revisions", done.stderr)


class TheDumpIsReadBackTheWholeWay(unittest.TestCase):
    """B376 (R2 26-10-27, F21): `haprion-backup restore <dump>`, with the machine stubbed.

    By hand it took seven steps and two traps: the web's socket started the web
    again, and `pg_restore --clean` failed on the partitions.
    """

    def restore(
        self, *, active: str, connections: str = "0", restored: bool = True
    ) -> tuple[subprocess.CompletedProcess[str], list[str]]:
        source = SCRIPT.read_text()
        units = re.search(r"^RESTORE_UNITS=\(\n.*?^\)\n", source, re.MULTILINE | re.DOTALL)
        if units is None:
            self.fail("haprion-backup has no RESTORE_UNITS")
        with tempfile.TemporaryDirectory() as raw:
            here = Path(raw)
            dump = here / "haprion-20261027.dump"
            dump.write_text("dump")
            steps = here / "steps"
            steps.mkdir()
            (steps / "03-verify").write_text('#!/bin/sh\necho "03-verify" >> "$CALLS"\n')
            (steps / "03-verify").chmod(0o755)
            config = here / "traffic-collector.json"
            config.write_text("{}")
            collector = here / "collector"
            collector.write_text("#!/bin/sh\n")
            collector.chmod(0o755)
            calls = here / "calls"
            program = (
                "set -Eeuo pipefail\n"
                'log() { :; }; warn() { echo "WARNING: $*" >&2; }; step_log() { :; }\n'
                'die() { echo "ERROR: $*" >&2; exit 1; }\n'
                'record() { echo "$*" >> "$CALLS"; }\n'
                f'systemctl() {{ case "$1" in is-active) [[ " {active} " == *" $3 "* ]] ;;'
                ' show) echo _haprion-collector ;; *) record "systemctl $*" ;; esac; }\n'
                f"psql_scratch() {{ echo {connections}; }}\n"
                f'sudo() {{ record "$* <$(cat)"; {"true" if restored else "false"}; }}\n'
                "pg_restore() { :; }\n"
                'runuser() { record "runuser $*"; }\n'
                'do_after_restore() { record "after-restore"; }\n'
                "DB_NAME=haprion\n"
                + re.search(r"^counted\(\) .*\n", source, re.MULTILINE).group(0)  # type: ignore[union-attr]
                + units.group(0)
                + f'PLATFORM_STEPS="{steps}"\nCOLLECTOR_CONFIG="{config}"\n'
                f'COLLECTOR_COMMAND="{collector}"\n'
                + function("do_restore", source)
                + function("start_units", source)
                + 'do_restore "$1"\n'
            )
            done = subprocess.run(  # noqa: S603 - fixed program
                ["/bin/bash", "-c", program, "bash", str(dump)],
                capture_output=True,
                text=True,
                check=False,
                env={**os.environ, "CALLS": str(calls)},
            )
            said = calls.read_text().splitlines() if calls.exists() else []
        return done, [line.replace(str(here), "<here>") for line in said]

    ACTIVE = "haprion-traffic-collector.timer haprion-web.socket haprion-worker.service"

    def test_it_stops_restores_proves_holds_and_starts_in_that_order(self) -> None:
        done, said = self.restore(active=self.ACTIVE)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(
            said,
            [
                "systemctl stop haprion-traffic-collector.timer",
                "systemctl stop haprion-web.socket",
                "systemctl stop haprion-worker.service",
                "-u postgres pg_restore -d postgres --clean --create --if-exists --exit-on-error"
                " <dump",
                "03-verify",
                "after-restore",
                "systemctl start haprion-worker.service",
                "systemctl start haprion-web.socket",
                "systemctl start haprion-traffic-collector.timer",
                "runuser -u _haprion-collector -- <here>/collector --replay-database"
                " <here>/traffic-collector.json",
            ],
        )

    def test_a_connection_left_restores_nothing_and_starts_what_it_stopped(self) -> None:
        done, said = self.restore(active=self.ACTIVE, connections="1")
        self.assertEqual(done.returncode, 1)
        self.assertIn("1 connection to haprion still open; nothing was restored", done.stderr)
        self.assertFalse(any("pg_restore" in line for line in said))
        self.assertEqual(said[-1], "systemctl start haprion-traffic-collector.timer")

    def test_a_failed_restore_leaves_the_services_stopped(self) -> None:
        done, said = self.restore(active=self.ACTIVE, restored=False)
        self.assertEqual(done.returncode, 1)
        self.assertIn("the services stay stopped", done.stderr)
        self.assertFalse(any(line.startswith("systemctl start") for line in said))
        self.assertNotIn("after-restore", said)

    def test_the_command_is_offered(self) -> None:
        source = SCRIPT.read_text()
        self.assertIn("#     haprion-backup restore <dump>", source)
        self.assertIn('restore)        take_lock; do_restore "$1" ;;', source)


if __name__ == "__main__":
    unittest.main()
