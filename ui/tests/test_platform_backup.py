"""The weekly restore check measures a restore against the archive, not against live.

Compared with the live database, the check failed every week retention had
something to do between the dump and the check (2026-09-20: job live 59,
restored 63) while the restore itself was perfect. What a restore owes is the
rows the archive holds; how far live has moved since is information.
"""

from __future__ import annotations

import os
import re
import signal
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

    HASH = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA"

    def checked(self, answer: str, archived: str | None = None) -> subprocess.CompletedProcess[str]:
        """The restored row is `answer`; the archive holds `archived` (the same, if not given)."""

        archived = answer if archived is None else archived
        source = SCRIPT.read_text()
        copy = (
            "COPY public.app_user (id, username, password_hash, role, source) FROM stdin;\n"
            "2\tolder-oidc\t\\N\tviewer\toidc\n"
            f"7\tadmin\t{archived}\tadmin\tlocal\n"
            "9\toperator\t$argon2id$other\tadmin\tlocal\n"
            "\\.\n"
            if archived
            else "COPY public.app_user (id, username, password_hash, role, source) FROM stdin;\n"
            "\\.\n"
        )
        program = (
            "set -Eeuo pipefail\n"
            'log() { echo "$*"; }\n'
            'die() { echo "ERROR: $*" >&2; exit 1; }\n'
            'psql_scratch() { printf "%s\\n" "$*" >&2; printf "%s" "$ANSWER"; }\n'
            'pg_restore() { printf "%b" "$COPY"; }\n'
            + function("archive_local_hash", source)
            + function("restored_hash_intact", source)
            + "restored_hash_intact scratch archive\n"
        )
        return subprocess.run(  # noqa: S603 - fixed program
            ["/bin/bash", "-c", program],
            capture_output=True,
            text=True,
            check=False,
            env={**os.environ, "ANSWER": answer, "COPY": copy},
        )

    def test_only_a_local_account_is_read(self) -> None:
        done = self.checked(self.HASH)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("where id = 7", done.stderr)
        self.assertIn("matches the archive", done.stdout)

    def test_no_local_account_is_not_a_failure(self) -> None:
        done = self.checked("", "")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("no local account", done.stdout)

    def test_a_hash_cut_short_after_its_prefix_fails(self) -> None:
        done = self.checked("$argon2id$x", self.HASH)
        self.assertEqual(done.returncode, 1)
        self.assertIn("differs from the archive", done.stderr)

    def test_a_hash_that_is_not_the_archives_fails(self) -> None:
        done = self.checked(self.HASH.replace("aGFzaA", "b3RoZXI"), self.HASH)
        self.assertEqual(done.returncode, 1)


class TheUnitsWaitForTheDumpDirectory(unittest.TestCase):
    """`RequiresMountsFor` named a fixed path while DUMP_DIR is a setting."""

    def test_the_services_name_the_dump_directory_and_the_step_fills_it_in(self) -> None:
        examples = SCRIPT.parents[1] / "examples"
        for unit in ("haprion-backup", "haprion-restore-check"):
            text = (examples / f"{unit}.service.example").read_text()
            self.assertIn("RequiresMountsFor=DUMP_DIR\n", text)
        step = (SCRIPT.parents[1] / "06-platform-backup").read_text()
        self.assertIn('sed "s|DUMP_DIR|${DUMP_DIR}|g"', step)


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
            #
            # A group of its own, stopped whole: flock runs sleep as its child,
            # and killing flock alone left sleep running past the module
            # (26-10-29, the gate's check of what a module leaves running).
            #
            holder = subprocess.Popen(  # noqa: S603 - fixed program
                ["/usr/bin/flock", str(lock), "/usr/bin/sleep", "5"], start_new_session=True
            )
            self.addCleanup(holder.wait)
            self.addCleanup(os.killpg, holder.pid, signal.SIGKILL)
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
            + function("keep_newest", source)
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

    def before_restore(self, exists: bool) -> subprocess.CompletedProcess[str]:
        source = SCRIPT.read_text()
        program = (
            "set -Eeuo pipefail\n"
            'log() { echo "$*"; }\nwarn() { echo "$*" >&2; }\n'
            'die() { echo "ERROR: $*" >&2; exit 1; }\nstep_log() { :; }\n'
            f"psql_scratch() {{ echo {1 if exists else 0}; }}\n"
            f"DUMP_DIR={self.dumps}\nDB_NAME=haprion\nDB_ROLE=r\nDISK_WARN_PERCENT=101\n"
            "BEFORE_RESTORE_KEPT=3\n"
            + function("write_dump", source)
            + function("keep_newest", source)
            + function("dump_before_restore", source)
            + "dump_before_restore\n"
        )
        return subprocess.run(  # noqa: S603 - fixed program
            ["/bin/bash", "-c", program],
            capture_output=True,
            text=True,
            check=False,
            env={"PATH": self.path},
            cwd=self.root,
        )

    def test_the_database_a_restore_replaces_is_dumped_and_three_kept(self) -> None:
        self.dumps.mkdir()
        (self.dumps / "haprion-20261022.dump").write_text("daily")
        for _ in range(4):
            done = self.before_restore(True)
            self.assertEqual(done.returncode, 0, done.stderr)
            time.sleep(1.1)
        self.assertEqual(len(list((self.dumps / "before-restore").iterdir())), 3)
        self.assertEqual(
            sorted(path.name for path in self.dumps.glob("*.dump")), ["haprion-20261022.dump"]
        )

    def test_no_database_means_nothing_to_dump(self) -> None:
        self.dumps.mkdir()
        done = self.before_restore(False)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertFalse((self.dumps / "before-restore").exists())

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
        self,
        *,
        active: str,
        connections: str = "0",
        restored: bool = True,
        plan: str | None = "same 0102 new",
        migrated: bool = True,
        proved: bool = True,
        migrate_step: bool = True,
        remembered: Path | None = None,
        dumped: bool = True,
    ) -> tuple[subprocess.CompletedProcess[str], list[str]]:
        """One run; `remembered` is the file the runs before it left, kept across runs."""

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
            (steps / "03-verify").write_text(
                f'#!/bin/sh\necho "03-verify" >> "$CALLS"\nexit {0 if proved else 1}\n'
            )
            (steps / "03-verify").chmod(0o755)
            if migrate_step:
                (steps / "migrate").write_text(
                    f'#!/bin/sh\necho "migrate $*" >> "$CALLS"\nexit {0 if migrated else 1}\n'
                )
                (steps / "migrate").chmod(0o755)
            retention = here / "haprion-retention"
            retention.write_text('#!/bin/sh\necho "retention $*" >> "$CALLS"\n')
            retention.chmod(0o755)
            timer = here / "haprion-retention.timer"
            timer.write_text("")
            refused = "the dump is at schema 0103 and new at 0102: it comes from a newer release"
            config = here / "traffic-collector.json"
            config.write_text("{}")
            collector = here / "collector"
            collector.write_text("#!/bin/sh\n")
            collector.chmod(0o755)
            calls = here / "calls"
            program = (
                "set -Eeuo pipefail\n"
                'log() { echo "$*"; }; warn() { echo "WARNING: $*" >&2; }; step_log() { :; }\n'
                'die() { echo "ERROR: $*" >&2; exit 1; }\n'
                'record() { echo "$*" >> "$CALLS"; }\n'
                f'systemctl() {{ case "$1" in is-active) [[ " {active} " == *" $3 "* ]] ;;'
                ' show) echo _haprion-collector ;; *) record "systemctl $*" ;; esac; }\n'
                f"psql_scratch() {{ echo {connections}; }}\n"
                f'sudo() {{ record "$* <$(cat)"; {"true" if restored else "false"}; }}\n'
                # The dump's alembic_version, as `pg_restore --data-only` writes it.
                'pg_restore() { [[ " $* " != *" --table=alembic_version "* ]]'
                " || printf 'COPY public.alembic_version (version_num) FROM stdin;\\n0101\\n\\\\.\\n'; }\n"
                + (
                    f'schema_plan() {{ record "plan $1"; echo "{plan}"; }}\n'
                    if plan is not None
                    else f'schema_plan() {{ record "plan $1"; echo "{refused}" >&2; return 1; }}\n'
                )
                + 'runuser() { record "runuser $*"; }\n'
                'do_after_restore() { record "after-restore"; }\n'
                f'dump_before_restore() {{ record "dump-before-restore"; {"true" if dumped else "false"}; }}\n'
                "DB_NAME=haprion\nDUMP_DIR=/dumps\n"
                + re.search(r"^counted\(\) .*\n", source, re.MULTILINE).group(0)  # type: ignore[union-attr]
                + units.group(0)
                + f'RESTORE_STOPPED="{remembered or here / "restore-stopped"}"\n'
                + f'PLATFORM_STEPS="{steps}"\nCOLLECTOR_CONFIG="{config}"\n'
                f'RETENTION_COMMAND="{retention}"\nRETENTION_TIMER="{timer}"\n'
                f'COLLECTOR_COMMAND="{collector}"\n'
                + "".join(
                    function(name, source)
                    for name in (
                        "dump_revision",
                        "stopped_before",
                        "remember_stopped",
                        "restore_stopped",
                        "do_restore",
                        "start_units",
                    )
                )
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
                "plan 0101",
                "systemctl stop haprion-traffic-collector.timer",
                "systemctl stop haprion-web.socket",
                "systemctl stop haprion-worker.service",
                "dump-before-restore",
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

    def test_a_dump_that_cannot_be_made_restores_nothing_and_starts_what_it_stopped(self) -> None:
        done, said = self.restore(active=self.ACTIVE, dumped=False)
        self.assertEqual(done.returncode, 1)
        self.assertIn("could not be dumped before it is replaced", done.stderr)
        self.assertFalse(any("pg_restore" in line for line in said))
        self.assertIn("systemctl start haprion-worker.service", said)

    def test_the_last_sentence_says_where_the_replaced_database_is(self) -> None:
        done, _ = self.restore(active=self.ACTIVE)
        self.assertIn("kept in /dumps/before-restore/", done.stdout)

    def test_an_older_dump_is_migrated_before_its_privileges_are_proved(self) -> None:
        """Review 26-10-29, A1: a dump from before 0102 stopped on 03-verify, services down."""

        done, said = self.restore(active=self.ACTIVE, plan="migrate 0102 new")
        self.assertEqual(done.returncode, 0, done.stderr)
        restored = said.index(
            "-u postgres pg_restore -d postgres --clean --create --if-exists --exit-on-error <dump"
        )
        self.assertEqual(
            said[restored + 1 : restored + 5],
            ["migrate --release new", "retention horizon", "03-verify", "after-restore"],
        )
        self.assertIn("the dump is at 0101; migrated to 0102", done.stdout)

    def test_a_dump_the_release_cannot_take_stops_nothing(self) -> None:
        done, said = self.restore(active=self.ACTIVE, plan=None)
        self.assertEqual(done.returncode, 1)
        self.assertIn("the dump is at schema 0103 and new at 0102", done.stderr)
        self.assertIn("nothing was stopped or restored", done.stderr)
        self.assertEqual(said, ["plan 0101"])

    def test_a_failed_migration_leaves_the_services_stopped_and_holds_nothing(self) -> None:
        done, said = self.restore(active=self.ACTIVE, plan="migrate 0102 new", migrated=False)
        self.assertEqual(done.returncode, 1)
        self.assertIn("the migration from 0101 stopped; the services stay stopped", done.stderr)
        self.assertFalse(any(line.startswith("systemctl start") for line in said))
        self.assertNotIn("03-verify", said)
        self.assertNotIn("after-restore", said)

    def test_a_failure_after_the_dump_is_in_says_to_hold_the_jobs_before_anything_starts(
        self,
    ) -> None:
        """Review 26-10-29, B1 and P3-3: started by hand, the restored jobs ran unheld.

        Said wherever the dump's jobs are in the database and nothing has held
        them: after a failed migration as after a failed proof. Not after a
        failed pg_restore, which may have left no database to hold them in.
        """

        hold = "Before starting any of them by hand, hold the restored jobs:"
        behind = "do not start any of them by hand"
        for failure, held, schema_behind in (
            ({"plan": "migrate 0102 new", "migrated": False}, False, True),
            ({"proved": False}, True, False),
            ({"restored": False}, False, False),
        ):
            with self.subTest(**failure):
                done, said = self.restore(active=self.ACTIVE, **failure)
                self.assertEqual(done.returncode, 1)
                self.assertIn("run this again; it starts them once a restore finishes", done.stderr)
                self.assertEqual(f"{hold} sudo haprion-backup after-restore" in done.stderr, held)
                #
                # F3: after a migration that fell the schema is the dump's, behind
                # the code, and holding the jobs does not make a start safe.
                #
                self.assertEqual(behind in done.stderr, schema_behind)
                self.assertNotIn("after-restore", said)

    def test_a_run_after_a_failed_one_starts_what_that_one_stopped(self) -> None:
        """Review 26-10-29, D1: the run again found nothing active and started nothing.

        The web, the worker, the poller and every timer - the daily dump's too -
        stayed down while the command said the restore had finished.
        """

        for failure in (
            {"restored": False},
            {"plan": "migrate 0102 new", "migrated": False},
            {"proved": False},
        ):
            with self.subTest(**failure), tempfile.TemporaryDirectory() as raw:
                remembered = Path(raw) / "restore-stopped"
                first, _ = self.restore(active=self.ACTIVE, remembered=remembered, **failure)
                self.assertEqual(first.returncode, 1)
                self.assertEqual(stat.S_IMODE(remembered.stat().st_mode), 0o600)
                done, said = self.restore(active="", remembered=remembered)
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertFalse(any(line.startswith("systemctl stop") for line in said))
                self.assertEqual(
                    said[said.index("after-restore") :][:4],
                    [
                        "after-restore",
                        "systemctl start haprion-worker.service",
                        "systemctl start haprion-web.socket",
                        "systemctl start haprion-traffic-collector.timer",
                    ],
                )
                self.assertIn("haprion-worker.service stays stopped", done.stdout)
                self.assertFalse(remembered.exists())

    def test_what_the_run_again_finds_running_is_stopped_and_started_with_the_rest(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            remembered = Path(raw) / "restore-stopped"
            self.restore(active=self.ACTIVE, remembered=remembered, restored=False)
            done, said = self.restore(active="haprion-poller.service", remembered=remembered)
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertIn("systemctl stop haprion-poller.service", said)
            self.assertEqual(
                [line for line in said if line.startswith("systemctl start")],
                [
                    "systemctl start haprion-poller.service",
                    "systemctl start haprion-worker.service",
                    "systemctl start haprion-web.socket",
                    "systemctl start haprion-traffic-collector.timer",
                ],
            )

    def test_a_connection_left_on_the_run_again_starts_only_what_that_run_stopped(self) -> None:
        """The database is still the failed restore's: what that one stopped stays down."""

        with tempfile.TemporaryDirectory() as raw:
            remembered = Path(raw) / "restore-stopped"
            self.restore(active=self.ACTIVE, remembered=remembered, restored=False)
            before = remembered.read_text()
            done, said = self.restore(
                active="haprion-poller.service", remembered=remembered, connections="1"
            )
            self.assertEqual(done.returncode, 1)
            self.assertEqual(
                [line for line in said if line.startswith("systemctl start")],
                ["systemctl start haprion-poller.service"],
            )
            self.assertIn("haprion-worker.service", done.stderr)
            self.assertEqual(remembered.read_text(), before)

    def test_after_a_boot_the_run_again_stops_and_starts_what_systemd_started(self) -> None:
        """/run is emptied at boot, and systemd starts the enabled units itself."""

        with tempfile.TemporaryDirectory() as raw:
            remembered = Path(raw) / "restore-stopped"
            self.restore(active=self.ACTIVE, remembered=remembered, restored=False)
            remembered.unlink()
            done, said = self.restore(active=self.ACTIVE, remembered=remembered)
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertEqual(
                [line for line in said if line.startswith("systemctl start")],
                [
                    "systemctl start haprion-worker.service",
                    "systemctl start haprion-web.socket",
                    "systemctl start haprion-traffic-collector.timer",
                ],
            )

    def test_a_name_not_one_of_the_units_is_not_started(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            remembered = Path(raw) / "restore-stopped"
            remembered.write_text("haprion-worker.service\nsshd.service\n")
            done, said = self.restore(active="", remembered=remembered)
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertEqual(
                [line for line in said if line.startswith("systemctl start")],
                ["systemctl start haprion-worker.service"],
            )
            self.assertIn("names sshd.service", done.stderr)

    def test_without_the_migration_step_an_older_dump_stops_nothing(self) -> None:
        done, said = self.restore(active=self.ACTIVE, plan="migrate 0102 new", migrate_step=False)
        self.assertEqual(done.returncode, 1)
        self.assertIn("/migrate is missing", done.stderr)
        self.assertEqual(said, ["plan 0101"])

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

    def test_a_failed_restore_with_nothing_running_says_so_rather_than_none(self) -> None:
        done, _ = self.restore(active="", restored=False)
        self.assertEqual(done.returncode, 1)
        self.assertIn("the restore stopped; no service was running.", done.stderr)
        self.assertNotIn(": none", done.stderr)

    def test_the_command_is_offered(self) -> None:
        source = SCRIPT.read_text()
        self.assertIn("#     haprion-backup restore <dump>", source)
        self.assertIn(
            'restore)        hold_release_lock_for_restore; take_lock; do_restore "$1" ;;', source
        )

    def test_what_a_restore_stopped_is_kept_where_only_root_writes_and_a_boot_empties(
        self,
    ) -> None:
        source = SCRIPT.read_text()
        self.assertIn("\nRESTORE_STOPPED=/run/haprion/restore-stopped\n", source)
        tmpfiles = (ROOT / "install/tmpfiles/haprion.conf").read_text()
        self.assertIn("\nd /run/haprion 0755 root root -\n", tmpfiles)


class TheWeeklyCheckAsksWhatARestoreAsks(unittest.TestCase):
    """Review 26-10-29, B1: `verified` was said of dumps `restore` then stopped on."""

    def takes(self, *, revision: str, plan: str | None) -> subprocess.CompletedProcess[str]:
        source = SCRIPT.read_text()
        rows = f"printf '%s\\n' {revision}; " if revision else ""
        program = (
            "set -Eeuo pipefail\n"
            'log() { echo "$*"; }\n'
            'die() { echo "ERROR: $*" >&2; exit 1; }\n'
            "pg_restore() { echo 'COPY public.alembic_version (version_num) FROM stdin;'; "
            + rows
            + "printf '%s\\n' '\\.'; }\n"
            + (
                f'schema_plan() {{ echo "{plan}"; }}\n'
                if plan is not None
                else 'schema_plan() { echo "past the head" >&2; return 1; }\n'
            )
            + function("dump_revision", source)
            + function("restore_takes", source)
            + "restore_takes /dumps/haprion-20261029.dump\n"
        )
        return subprocess.run(  # noqa: S603 - fixed program
            ["/bin/bash", "-c", program], capture_output=True, text=True, check=False
        )

    def test_an_older_dump_is_verified_as_one_a_restore_migrates(self) -> None:
        done = self.takes(revision="0101", plan="migrate 0102 new")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("schema 0101; a restore migrates it to 0102 (new)", done.stdout)

    def test_a_dump_at_the_head_is_verified_as_it_is(self) -> None:
        done = self.takes(revision="0102", plan="same 0102 new")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("schema 0102, the head of new", done.stdout)

    def test_a_dump_a_restore_refuses_fails_the_check(self) -> None:
        done = self.takes(revision="0103", plan=None)
        self.assertEqual(done.returncode, 1)
        self.assertIn("past the head", done.stderr)
        self.assertIn("haprion-backup restore refuses this dump at schema 0103", done.stderr)

    def test_a_dump_without_a_revision_fails_the_check(self) -> None:
        done = self.takes(revision="", plan="same 0102 new")
        self.assertEqual(done.returncode, 1)
        self.assertIn("holds no schema revision", done.stderr)

    def test_the_weekly_check_asks_it(self) -> None:
        self.assertIn('restore_takes "$archive"', function("do_verify_restore", SCRIPT.read_text()))


class HoldingAfterARestore(unittest.TestCase):
    """Review 26-10-29, C05: `after-restore` held a job a running worker went on with."""

    def after_restore(
        self, *, active: bool, remembered: Path | None = None
    ) -> subprocess.CompletedProcess[str]:
        source = SCRIPT.read_text()
        program = (
            "set -Eeuo pipefail\n"
            f'RESTORE_STOPPED="{remembered or "/nonexistent/restore-stopped"}"\n'
            'log() { echo "$*"; }\n'
            'die() { echo "ERROR: $*" >&2; exit 1; }\n'
            f"systemctl() {{ [[ $1 == is-active ]] && {'true' if active else 'false'}; }}\n"
            "psql_as() { cat >/dev/null; printf '[7]\\n2\\n'; }\n"
            "DB_NAME=haprion\n"
            + function("do_after_restore", source)
            + function("after_restore_by_hand", source)
            + "after_restore_by_hand\n"
        )
        return subprocess.run(  # noqa: S603 - fixed program
            ["/bin/bash", "-c", program], capture_output=True, text=True, check=False
        )

    def test_by_hand_it_lets_go_of_the_refusal_a_failed_restore_left(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            remembered = Path(raw) / "restore-stopped"
            remembered.write_text("haprion-worker.service\n")
            done = self.after_restore(active=False, remembered=remembered)
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertFalse(remembered.exists())

    def test_refused_it_leaves_the_marker_for_the_restore_to_finish(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            remembered = Path(raw) / "restore-stopped"
            remembered.write_text("haprion-worker.service\n")
            done = self.after_restore(active=True, remembered=remembered)
            self.assertEqual(done.returncode, 1)
            self.assertTrue(remembered.exists())

    def test_the_command_runs_the_hand_version(self) -> None:
        self.assertIn("\n    after-restore)  after_restore_by_hand ;;\n", SCRIPT.read_text())

    def test_it_refuses_while_the_worker_runs_and_holds_nothing(self) -> None:
        done = self.after_restore(active=True)
        self.assertEqual(done.returncode, 1)
        self.assertIn("haprion-worker.service is running; stop it first", done.stderr)
        self.assertIn(
            "start it again after: sudo systemctl start haprion-worker.service", done.stderr
        )
        self.assertNotIn("held for an admin", done.stdout)

    def test_with_the_worker_stopped_it_holds_and_ends_the_sessions(self) -> None:
        done = self.after_restore(active=False)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("held for an admin on Jobs: [7]", done.stdout)
        self.assertIn("sessions ended: 2", done.stdout)


if __name__ == "__main__":
    unittest.main()
