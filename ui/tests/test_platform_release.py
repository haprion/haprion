"""The platform release and its schema move as one named delivery."""

from __future__ import annotations

import itertools
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class PreparedReleaseTests(unittest.TestCase):
    installer: str
    migrate: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.installer = (ROOT / "install/platform/install-ui-release").read_text()
        cls.migrate = (ROOT / "install/platform/migrate").read_text()

    def test_prepare_stops_before_the_current_link_moves(self) -> None:
        prepared = self.installer.index('if [[ "$prepare_only" -eq 1 ]]')
        activation = self.installer.index('step "Activating"')
        self.assertLess(prepared, activation)
        self.assertIn("prepared but not active", self.installer[prepared:activation])

    def test_a_release_without_its_migrations_or_their_tool_is_refused(self) -> None:
        for part in (
            "migration/alembic.ini",
            "migration/migrations/env.py",
            "migration/lib/alembic",
        ):
            self.assertIn(part, self.installer)
        self.assertNotIn("UV_BIN", self.installer)
        self.assertNotIn("source_tree", self.installer)

    def test_migrate_runs_the_named_releases_own_tool(self) -> None:
        self.assertIn('release="${UI_ROOT}/releases/${release_id}"', self.migrate)
        self.assertIn('migration_root="${release}/migration"', self.migrate)
        self.assertIn(
            'PYTHONPATH="${migration_root}/lib" exec "${release}/venv/bin/python" -m alembic',
            self.migrate,
        )
        self.assertNotIn("ALEMBIC_BIN", self.migrate)

    def test_release_id_cannot_escape_the_release_root(self) -> None:
        self.assertIn("invalid release id", self.migrate)
        self.assertIn("{0,127}", self.migrate)

    def test_candidate_check_does_not_mistake_old_processes_for_the_candidate(self) -> None:
        wrapper = (ROOT / "install/platform/check-compatibility").read_text()
        self.assertIn('extra_args+=(--ui-release "$release_id" --skip-services)', wrapper)
        self.assertIn("extra_args+=(--upgrade-from-current)", wrapper)

    def test_the_check_has_no_environment_switch(self) -> None:
        wrapper = (ROOT / "install/platform/check-compatibility").read_text()
        self.assertNotIn("ENVIRONMENT", wrapper)
        self.assertNotIn("--environment", wrapper)
        self.assertNotIn("contains no clusters", wrapper)

    def test_enabled_traffic_logs_add_the_collector_inventory_check(self) -> None:
        wrapper = (ROOT / "install/platform/check-compatibility").read_text()

        self.assertIn("config.traffic_logs.enabled", wrapper)
        self.assertIn("--runtime-policy /etc/haprion/runtime-policy.yaml", wrapper)
        self.assertIn("--collector-config /etc/haprion/traffic-collector.json", wrapper)

    def test_the_inventory_check_is_asked_of_the_checked_release(self) -> None:
        # The wrapper runs from a checkout that moves on; the release it checks
        # may predate the flag. The release answers, the checkout never assumes.
        wrapper = (ROOT / "install/platform/check-compatibility").read_text()

        self.assertIn('-m "${checker_module}.compatibility" --help', wrapper)
        self.assertIn("grep -q -- '--collector-config'", wrapper)
        self.assertIn("predates the traffic collector inventory check", wrapper)


class CoordinatedUpdateTests(unittest.TestCase):
    update: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.update = (ROOT / "install/platform/update-platform-release").read_text()

    def test_nothing_moves_before_prerequisites_and_schema_are_proved(self) -> None:
        prepare = self.update.index("install-ui-release --prepare")
        prerequisites = self.update.index("--before-migration")
        migrate = self.update.index('./migrate --release "$release_id"')
        database = self.update.index("./03-verify")
        candidate = self.update.index('check-compatibility --release "$release_id"', database)
        activate = self.update.index('./install-ui-release "$release_id"')
        self.assertLess(prepare, prerequisites)
        self.assertLess(prerequisites, migrate)
        self.assertLess(migrate, database)
        self.assertLess(database, candidate)
        self.assertLess(candidate, activate)

    def test_accounts_and_directories_are_made_again_before_the_units(self) -> None:
        """Review 26-10-24, 14-02: only the first installation's steps made them."""

        refresh = self.update.index('./refresh-platform-files "$release_id" "$kept"')
        for line in (
            "apply_sysusers ../sysusers/haprion.conf",
            "apply_tmpfiles ../tmpfiles/haprion.conf",
            "ensure_worker_directories",
            "ensure_identity_directories",
        ):
            with self.subTest(line=line):
                self.assertLess(self.update.index(f"\n{line}\n"), refresh)
        step = (ROOT / "install/platform/07-platform-services").read_text()
        self.assertIn("\nensure_worker_directories\n", step)
        first = (ROOT / "install/01-manager-prepare").read_text()
        self.assertIn("\napply_sysusers sysusers/haprion.conf\n", first)
        self.assertIn("\napply_tmpfiles tmpfiles/haprion.conf\n", first)

    def test_a_schema_change_is_dumped_after_the_checks_and_before_the_migration(self) -> None:
        """Logic review 26-10-22, F1: the newest dump was up to a day old."""

        prerequisites = self.update.index("--before-migration")
        dump = self.update.index(
            'haprion-backup dump-before-migration "$schema_now" "$schema_next"'
        )
        migrate = self.update.index('./migrate --release "$release_id"\n')
        self.assertLess(prerequisites, dump)
        self.assertLess(dump, migrate)
        self.assertIn('if [[ "$schema_now" != "$schema_next" ]]; then', self.update)

    def test_claims_are_held_before_anything_is_switched_or_restarted(self) -> None:
        """CR-12: the pause and the wait come before `current` moves and the worker restarts.

        What the pause does is proved against a database in
        `test_database_integration`; this holds the order in the scripts.
        """

        installer = (ROOT / "install/platform/install-ui-release").read_text()
        pause = installer.index("pause --wait")
        self.assertLess(pause, installer.index('step "Activating"'))
        self.assertLess(pause, installer.index("systemctl restart"))
        self.assertIn('resume || true" EXIT', installer)
        rollback = (ROOT / "install/platform/bin/haprion-rollback").read_text()
        self.assertLess(rollback.index("pause --wait"), rollback.index('step "Switching"'))
        self.assertNotIn("Checking that no node restore or backup is running", self.update)

    def test_the_rollback_says_the_same_in_either_direction(self) -> None:
        """R2 26-10-27 (F13): *rolled back to* and *Roll forward with* after a step forward."""

        rollback = (ROOT / "install/platform/bin/haprion-rollback").read_text()
        self.assertIn('log "switched to ${target}"', rollback)
        self.assertIn('log "To go back: haprion-rollback --to ${current}"', rollback)
        for said in ("rolled back to", "Roll forward with", "rolling forward to", "rolled forward"):
            self.assertNotIn(said, rollback)

    def test_a_restart_is_not_stopped_by_the_start_limit_a_crashing_release_reached(self) -> None:
        """Review 26-10-29, AA02: the web restarts every 2 s, and five starts in 10 s is the limit.

        A candidate whose web dies at start reaches it; the rollback's restart
        was then refused, the target never answered, and the rollback switched
        back to the candidate. `reset-failed` sets the counter to zero.
        """

        restart = re.compile(r"^( *)systemctl restart (.+?)( \|\| true)?$", re.M)
        for path in (
            "install/platform/bin/haprion-rollback",
            "install/platform/install-ui-release",
        ):
            text = (ROOT / path).read_text()
            found = list(restart.finditer(text))
            self.assertTrue(found, path)
            for match in found:
                with self.subTest(path=path, line=match.group(0).strip()):
                    before = text[: match.start()].rstrip("\n").rsplit("\n", 1)[-1]
                    self.assertEqual(
                        before,
                        f"{match.group(1)}systemctl reset-failed {match.group(2)} 2>/dev/null || true",
                    )

    def test_both_post_switch_failures_restore_the_previous_release(self) -> None:
        self.assertEqual(self.update.count("    restore_previous && die "), 2)
        self.assertIn('"$rollback" --to "$previous_id"', self.update)
        self.assertIn("was restored but the installation is not compatible", self.update)

    def functions(self, *names: str) -> str:
        text = ""
        for name in names:
            start = self.update.index(f"{name}() {{")
            text += self.update[start : self.update.index("\n}\n", start) + 3]
        return text

    def restoring(
        self, script: str, *, rollback: str, settled: str = "no"
    ) -> tuple[subprocess.CompletedProcess[str], Path]:
        """The update's own restore and exit, with a rollback, a check and a file step stubbed.

        Review 26-10-29, A02: the rollback in `restore_previous` refused or
        switched back by itself, the candidate stayed current with the previous
        release's files, and `dpkg --configure -a` then called it current.
        """

        raw = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, raw)
        here = Path(raw)
        for release in ("prev", "cand"):
            (here / "releases" / release).mkdir(parents=True)
        (here / "current").symlink_to(here / "releases/cand")
        (here / "kept").mkdir()
        (here / "kept/manifest").write_text("unit\t/etc/systemd/system/haprion-web.service\t\n")
        (here / "update").write_text("RELEASE=cand\nPREVIOUS=prev\n")
        for name, body in (
            ("refresh-platform-files", 'echo "refresh $*" >> "$LOG"'),
            ("check-compatibility", 'echo check >> "$LOG"'),
            ("rollback", rollback),
        ):
            (here / name).write_text(f"#!/bin/bash\n{body}\n")
            (here / name).chmod(0o755)
        done = subprocess.run(  # noqa: S603 - fixed interpreter, the script's own functions
            [
                "/bin/bash",
                "-c",
                f'UI_ROOT="$1"; current="$1/current"; kept="$1/kept"; marker="$1/update"; '
                f'rollback="$1/rollback"; release_id=cand; previous_id=prev; '
                f"files_settled={settled}; restore_tried=no; proved=no; base=0; found_marker=; "
                'warn() { echo "WARNING: $*" >&2; }; where_it_stands() { echo said; }; '
                + self.functions(
                    "settle_files",
                    "candidate_current",
                    "last_proved_current",
                    "restore_previous",
                    "on_exit",
                )
                + script,
                "-",
                raw,
            ],
            cwd=raw,
            capture_output=True,
            text=True,
            check=False,
            env={"PATH": "/usr/bin:/bin", "LOG": str(here / "log")},
        )
        return done, here

    REFUSED = "exit 75"
    SWITCHED_BACK = (
        'ln -sfn "$PWD/releases/prev" current; ln -sfn "$PWD/releases/cand" current; exit 1'
    )
    RESTORED = 'ln -sfn "$PWD/releases/prev" current'

    def test_a_rollback_that_fails_leaves_the_candidate_with_its_own_files(self) -> None:
        for rollback in (self.REFUSED, self.SWITCHED_BACK):
            with self.subTest(rollback=rollback):
                done, here = self.restoring(
                    'restore_previous; echo "rc=$? settled=$files_settled"', rollback=rollback
                )
                self.assertIn("rc=1 settled=candidate", done.stdout)
                self.assertEqual(
                    (here / "log").read_text().splitlines(),
                    [f"refresh --restore {here}/kept --from 0", f"refresh cand {here}/kept"],
                )
                self.assertIn(
                    "prev could not be restored; cand runs, with its own platform files",
                    done.stderr,
                )
                self.assertNotIn("ERROR", done.stderr)

    def test_a_way_out_whose_rollback_fails_keeps_the_marker_and_says_so(self) -> None:
        """Ctrl-C between the switch and the proof: `restore_previous || warn` hid the failure."""

        for rollback in (self.REFUSED, self.SWITCHED_BACK):
            with self.subTest(rollback=rollback):
                done, here = self.restoring("(exit 130); on_exit", rollback=rollback)
                self.assertEqual(done.returncode, 130)
                self.assertEqual(done.stdout.split(), ["said"])
                self.assertIn("prev could not be restored", done.stderr)
                self.assertNotIn("check", (here / "log").read_text())
                self.assertTrue((here / "update").exists())
                self.assertTrue((here / "kept").exists())

    def test_a_restore_that_worked_ends_the_update_s_state(self) -> None:
        done, here = self.restoring("(exit 1); on_exit", rollback=self.RESTORED)
        self.assertEqual(done.returncode, 1)
        self.assertEqual(
            (here / "log").read_text().splitlines(),
            [f"refresh --restore {here}/kept --from 0", "check"],
        )
        self.assertFalse((here / "update").exists())
        self.assertFalse((here / "kept").exists())

    def test_a_proved_update_ends_its_state(self) -> None:
        done, here = self.restoring("proved=yes; on_exit", rollback=self.REFUSED, settled="yes")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertFalse((here / "update").exists())
        self.assertFalse((here / "kept").exists())
        self.assertFalse((here / "log").exists())

    def test_where_it_stands_says_the_candidate_is_not_proved(self) -> None:
        body = self.functions("where_it_stands")
        self.assertIn('elif [[ "${files_settled:-}" == candidate ]]; then', body)
        self.assertIn("could not be restored, and ${running} is not proved", body)

    def unfinished(
        self, marker: str | None, *, dpkg: bool = False
    ) -> subprocess.CompletedProcess[str]:
        lib = (ROOT / "install/lib.sh").read_text()
        start = lib.index("read_admin_file() {")
        reader = lib[start : lib.index("\n}\n", start) + 3]
        raw = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, raw)
        (Path(raw) / "releases/prev").mkdir(parents=True)
        if marker is not None:
            (Path(raw) / "update").write_text(marker)
        return subprocess.run(  # noqa: S603 - fixed interpreter, the script's own function
            [
                "/bin/bash",
                "-c",
                f'UI_ROOT="$1"; marker="$1/update"; previous_id=cand; '
                f'warn() {{ echo "WARNING: $*" >&2; }}; die() {{ echo "ERROR: $*" >&2; exit 1; }}; '
                f'{reader}{self.functions("unfinished_update")}unfinished_update; echo "$previous_id"',
                "-",
                raw,
            ],
            capture_output=True,
            text=True,
            check=False,
            env={
                "PATH": "/usr/bin:/bin",
                **({"DPKG_MAINTSCRIPT_PACKAGE": "haprion-ui"} if dpkg else {}),
            },
        )

    def test_an_update_run_again_goes_on_from_the_release_last_proved(self) -> None:
        """A02: `previous_id` came from `current`, the unproved candidate itself."""

        done = self.unfinished("RELEASE=cand\nPREVIOUS=prev\n")
        self.assertEqual(done.stdout.strip(), "prev")
        self.assertIn(
            "the update to cand did not complete; this one goes on from prev", done.stderr
        )
        self.assertEqual(self.unfinished(None).stdout.strip(), "cand")
        refused = self.unfinished("RELEASE=cand\nPREVIOUS=gone\n")
        self.assertEqual(refused.returncode, 1)
        self.assertIn("names no release on disk to go back to (gone)", refused.stderr)

    def test_a_marker_with_no_way_back_says_the_way_out(self) -> None:
        """Review 26-10-29, AA04: every apt run stopped on it, and nothing said what to do."""

        for marker in ("RELEASE=cand\nPREVIOUS=gone\n", "not a plain assignment\n"):
            for dpkg, then in (
                (False, "then run the update again"),
                (True, "then: sudo dpkg --configure -a"),
            ):
                with self.subTest(marker=marker, dpkg=dpkg):
                    refused = self.unfinished(marker, dpkg=dpkg)
                    self.assertEqual(refused.returncode, 1)
                    self.assertRegex(
                        refused.stderr,
                        r"If cand is the release to keep, remove \S+/update, " + then,
                    )

    def test_the_copy_and_the_marker_are_on_disk_and_root_s_alone(self) -> None:
        """Review 26-10-29, A03: the copy was in /tmp, a tmpfs a restart empties."""

        self.assertNotIn("mktemp -d", self.update)
        self.assertIn('state="${UI_DATA}/platform-update"\n', self.update)
        self.assertIn('marker="${state}/update"\n', self.update)
        self.assertIn('kept="${state}/kept"\n', self.update)
        self.assertIn('chmod 700 -- "$state" "$kept"\n', self.update)
        written = self.update.index('mv -f -- "${marker}.new" "$marker"')
        self.assertLess(written, self.update.index("trap on_exit EXIT"))
        self.assertLess(
            written, self.update.index('./refresh-platform-files "$release_id" "$kept"\n')
        )
        self.assertLess(self.update.index("\nunfinished_update\n"), written)

    def test_a_way_out_after_the_switch_restores_the_previous_release(self) -> None:
        """Review 26-10-24, 03-02: the files went back, the candidate stayed current."""

        self.assertIn("trap on_exit EXIT", self.update)
        start = self.update.index("on_exit() {")
        body = self.update[start : self.update.index("\n}\n", start) + 3]
        for settled, switched, expected in (
            ("no", "true", ["restore", "settle"]),
            ("yes", "true", ["settle"]),
            # R2 26-10-27 (F8): never switched, nothing to put back.
            ("no", "false", ["settle"]),
        ):
            with self.subTest(settled=settled, switched=switched):
                done = subprocess.run(  # noqa: S603 - fixed interpreter, the script's own function
                    [
                        "/bin/bash",
                        "-c",
                        f"files_settled={settled}; kept=/nonexistent; restore_tried=no; "
                        "proved=no; marker=/nonexistent/update; base=0; found_marker=; "
                        "warn() { :; }; restore_previous() { echo restore; }; "
                        f"candidate_current() {{ {switched}; }}; where_it_stands() {{ echo said; }}; "
                        f"last_proved_current() {{ ! {switched}; }}; "
                        f"settle_files() {{ echo settle; files_settled=yes; }}; {body}on_exit",
                    ],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                self.assertEqual(done.stdout.split(), expected)

    def settle_and_exit(self, restore_status: int) -> tuple[subprocess.CompletedProcess[str], Path]:
        """`settle_files` and `on_exit` as written, after an update that stopped with 3."""

        functions = ""
        for name in ("settle_files() {", "on_exit() {"):
            start = self.update.index(name)
            functions += self.update[start : self.update.index("\n}\n", start) + 3]
        raw = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, raw)
        here = Path(raw)
        (here / "refresh-platform-files").write_text(f"#!/bin/sh\nexit {restore_status}\n")
        (here / "refresh-platform-files").chmod(0o755)
        kept = here / "kept"
        kept.mkdir()
        (kept / "manifest").write_text("unit\t/etc/systemd/system/haprion-web.service\t\n")
        done = subprocess.run(  # noqa: S603 - fixed interpreter, the script's own functions
            [
                "/bin/bash",
                "-c",
                f'files_settled=no; kept="$1"; marker="$1/../update"; restore_tried=no; '
                f'proved=no; base=0; found_marker=; warn() {{ echo "WARNING: $*" >&2; }}; '
                "restore_previous() { settle_files 0; }; candidate_current() { false; }; "
                "last_proved_current() { true; }; "
                f"where_it_stands() {{ echo said; }}; {functions}(exit 3); on_exit",
                "-",
                str(kept),
            ],
            cwd=raw,
            capture_output=True,
            text=True,
            check=False,
        )
        return done, kept

    def test_a_restore_that_failed_keeps_the_copy_and_the_failure(self) -> None:
        """Review 2026-10-28, F02: the warning named the copy, and the trap then deleted it."""

        done, kept = self.settle_and_exit(1)
        self.assertEqual(done.returncode, 3)
        self.assertIn(f"{kept} holds them", done.stderr)
        self.assertTrue((kept / "manifest").exists())
        self.assertEqual(done.stdout.split(), ["said"])

        done, kept = self.settle_and_exit(0)
        self.assertEqual(done.returncode, 3)
        self.assertFalse(kept.exists())

    def test_where_it_stands_names_the_copy_a_restore_left(self) -> None:
        start = self.update.index("where_it_stands() {")
        body = self.update[start : self.update.index("\n}\n", start) + 3]
        self.assertIn('if [[ "${files_settled:-}" == failed ]]; then', body)
        self.assertIn("refresh-platform-files --restore ${kept}", body)
        # AA01: a restore of this run's lines alone names where they begin.
        self.assertIn("--restore ${kept} --from ${settled_from}", body)

    def test_an_activation_that_never_switched_says_so_once(self) -> None:
        """R2 26-10-27 (F8): *was restored* and *no UI rollback is needed* twice."""

        self.assertNotIn('warn "the candidate is not current', self.update)
        activation = self.update[
            self.update.index('if ! ./install-ui-release "$release_id"; then') :
        ]
        activation = activation[: activation.index("\nfi\n")]
        self.assertLess(activation.index("candidate_current"), activation.index("restore_previous"))
        self.assertIn(
            'activation stopped before the switch; $(basename "$(readlink -f "$current")") kept '
            "running",
            activation,
        )

    def where_it_stands(self, *, dpkg: bool) -> str:
        start = self.update.index("where_it_stands() {")
        body = self.update[start : self.update.index("\n}\n", start) + 3]
        with tempfile.TemporaryDirectory() as raw:
            here = Path(raw)
            (here / "releases" / "0.99.1-aaaa").mkdir(parents=True)
            (here / "current").symlink_to(here / "releases" / "0.99.1-aaaa")
            (here / "migrate").write_text("#!/bin/sh\necho '0101 (head)'\n")
            (here / "migrate").chmod(0o755)
            dumps = here / "dumps" / "before-migration"
            dumps.mkdir(parents=True)
            (dumps / "haprion-0100-to-0101-20261026-162200.dump").write_text("")
            done = subprocess.run(  # noqa: S603 - fixed interpreter, the script's own function
                [
                    "/bin/bash",
                    "-c",
                    f'root="$1"; current="$1/current"; release_id=0.99.2-bbbb; schema_now=0100; '
                    f'admin_value() {{ echo "$root/dumps"; }}; {body}where_it_stands',
                    "-",
                    raw,
                ],
                cwd=raw,
                capture_output=True,
                text=True,
                check=True,
                env={
                    "PATH": "/usr/bin:/bin",
                    **({"DPKG_MAINTSCRIPT_PACKAGE": "haprion-ui"} if dpkg else {}),
                },
            )
        return done.stderr.replace(raw, "<root>")

    def test_an_update_that_did_not_complete_says_where_it_stands(self) -> None:
        """R2 26-10-27 (F7): under apt the last lines were a TODO and nothing about what runs."""

        said = self.where_it_stands(dpkg=True)
        self.assertIn("The update to 0.99.2-bbbb did not complete. 0.99.1-aaaa is running.", said)
        self.assertIn(
            "The database moved from schema 0100 to 0101, which 0.99.1-aaaa runs on.", said
        )
        self.assertIn(
            "<root>/dumps/before-migration/haprion-0100-to-0101-20261026-162200.dump", said
        )
        self.assertIn("then: sudo dpkg --configure -a", said)
        self.assertIn("then run the update again", self.where_it_stands(dpkg=False))

    def test_a_failed_nginx_reload_does_not_end_the_update_unproved(self) -> None:
        self.assertIn("if systemctl reload nginx; then", self.update)
        self.assertNotIn("\n    systemctl reload nginx\n", self.update)

    def test_old_releases_are_pruned_only_after_the_update_is_proved(self) -> None:
        """B156: retention runs after the final compatibility check, keeps ten,
        and never the release just
        activated or the one it replaced."""

        final_check = self.update.index("if ! ./check-compatibility; then")
        prune = self.update.index('keep="${RELEASES_KEPT:-10}"')
        self.assertLess(final_check, prune)
        self.assertNotIn("RELEASES_KEPT:-3", self.update)
        self.assertIn(
            '[[ -z "$old_release" || "$old_release" == "$release_id" '
            '|| "$old_release" == "$previous_id" ]] && continue',
            self.update,
        )
        # Said only when there is something to remove (Fas 18, 26-10-13).
        self.assertLess(
            self.update.index("if (( ${#old_releases[@]} > 0 )); then"),
            self.update.index('step "Pruning old releases"'),
        )
        self.assertIn("-printf '%T@ %f\\n'", self.update)

    def test_it_ends_by_saying_where_the_interface_is(self) -> None:
        """Fas 18, 26-10-13: the update ends with the address and the commands."""

        ending = self.update[self.update.index('log "platform update complete"') :]
        self.assertIn("admin_value /etc/haprion/ui-tls.conf SERVER_NAME", ending)
        self.assertIn("The web interface is at https://${server_name:-<this machine>}/", ending)

    def test_it_never_installs_the_independent_cli_or_node_bundle(self) -> None:
        self.assertNotIn("install-release.py", self.update)
        self.assertNotIn("04-node-prepare", self.update)

    def test_it_reads_no_answers_file_so_the_package_can_run_it(self) -> None:
        """B266 D2: postinst knows the release id and nothing else."""

        for script in (
            "update-platform-release",
            "install-ui-release",
            "migrate",
            "check-compatibility",
            "03-verify",
        ):
            with self.subTest(script=script):
                text = (ROOT / "install/platform" / script).read_text()
                self.assertNotIn("load_answers", text)


def script_functions(text: str, *names: str) -> str:
    found = ""
    for name in names:
        start = text.index(f"{name}() {{")
        found += text[start : text.index("\n}\n", start) + 3]
    return found


class UpdatesOverAnUnprovedRelease(unittest.TestCase):
    """Review 26-10-29, AA01: the next release over one that fell unproved.

    B's update failed after its switch and its rollback failed too: B runs,
    unproved, the marker names A, and the copy holds A's platform files. C's
    update went on from A - but a failure before C's switch put A's files
    under B, and took the marker and the copy away, so nothing remembered B
    was never proved and the next update started from B.

    The updates run here are the script's own functions, its start and its
    end, with the real `refresh-platform-files --restore`; the release's
    platform file is one hook file, written as `put` writes it, and the steps
    between are a failure before the switch, one after it, or none.
    """

    def setUp(self) -> None:
        raw = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, raw)
        self.here = Path(raw)
        for release in ("A", "B", "C", "D"):
            (self.here / "releases" / release).mkdir(parents=True)
        (self.here / "current").symlink_to(self.here / "releases/A")
        (self.here / "etc").mkdir()
        self.rule.write_text("A's rule\n")
        platform = self.here / "platform"
        platform.mkdir()
        refresh = (ROOT / "install/platform/refresh-platform-files").read_text()
        shutil.copy(ROOT / "install/platform/refresh-platform-files", platform / "refreshing")
        (self.here / "lib.sh").write_text(
            "need_root() { :; }; step() { :; }; log() { :; }\n"
            'warn() { echo "WARNING: $*" >&2; }; die() { echo "ERROR: $*" >&2; exit 1; }\n'
        )
        for name, body in (
            #
            # The restore is the script's own; installing a release's files
            # is its `put`, with one file for every file the steps installed.
            #
            (
                "refresh-platform-files",
                'if [[ "$1" == --restore ]]; then exec ./refreshing "$@"; fi\n'
                "source ../lib.sh\nchown() { :; }\n"
                + script_functions(refresh, "manifest", "put")
                + 'keep="$2"; touch "$(manifest)"; changed=()\n'
                + 'put hook "$RULE" 644 "$1\'s rule"\n',
            ),
            ("check-compatibility", "exit 0"),
            (
                "rollback",
                'if [[ "$ROLLBACK" == restored ]]; then\n'
                '    ln -sfn "$UI_ROOT/releases/$2" "$UI_ROOT/current.new"\n'
                '    mv -T "$UI_ROOT/current.new" "$UI_ROOT/current"\n'
                "else\n"
                "    exit 75\n"
                "fi",
            ),
        ):
            (platform / name).write_text(f"#!/bin/bash\nset -Eeuo pipefail\n{body}\n")
            (platform / name).chmod(0o755)

    @property
    def rule(self) -> Path:
        return self.here / "etc/rule"

    @property
    def running(self) -> str:
        return (self.here / "current").resolve().name

    @property
    def marker(self) -> str | None:
        path = self.here / "platform-update/update"
        return path.read_text() if path.exists() else None

    @property
    def kept(self) -> list[str]:
        """What the copy would put back, in the order its manifest lists it."""

        manifest = self.here / "platform-update/kept/manifest"
        if not manifest.exists():
            return []
        return [
            Path(line.split("\t")[2]).read_text().strip()
            for line in manifest.read_text().splitlines()
        ]

    def update(self, release: str, *, fails: str, rollback: str = "refused") -> str:
        """`update-platform-release <release>`, failing `before` or `after` its switch, or not."""

        text = (ROOT / "install/platform/update-platform-release").read_text()
        lib = (ROOT / "install/lib.sh").read_text()
        steps = {
            "before": "false\n",
            "after": (
                'ln -sfn "$UI_ROOT/releases/$release_id" "$current.new"; mv -T "$current.new" "$current"\n'
                "if ! false; then\n"
                '    restore_previous && die "activation failed; UI release ${previous_id} was restored"\n'
                '    die "activation failed, and UI release ${previous_id} could not be restored"\n'
                "fi\n"
            ),
            "none": (
                'ln -sfn "$UI_ROOT/releases/$release_id" "$current.new"; mv -T "$current.new" "$current"\n'
                "files_settled=yes\nproved=yes\n"
            ),
        }
        start = text.index("\nstate=")
        state = text[start : text.index("\nunfinished_update\n", start)]
        start = text.index("\nfiles_settled=no\n")
        settling = text[start : text.index("\nschema_now=", start)]
        start = text.index("\nschema_now=")
        ending = text[start : text.index("\ntrap on_exit EXIT\n", start)]
        script = (
            "set -Eeuo pipefail\n"
            'UI_ROOT="$1"; UI_DATA="$1"; current="$1/current"; rollback="$PWD/rollback"\n'
            'previous_id="$(basename "$(readlink -f "$current")")"\n'
            f"release_id={release}\n"
            + script_functions(lib, "read_admin_file")
            + 'warn() { echo "WARNING: $*" >&2; }; die() { echo "ERROR: $*" >&2; exit 1; }\n'
            + state
            + "\nunfinished_update\n"
            + settling
            + ending
            + "\ntrap on_exit EXIT\n"
            + './refresh-platform-files "$release_id" "$kept"\n'
            + steps[fails]
        )
        done = subprocess.run(  # noqa: S603 - fixed interpreter, the script's own lines
            ["/bin/bash", "-c", script, "-", str(self.here)],
            cwd=self.here / "platform",
            capture_output=True,
            text=True,
            check=False,
            env={
                "PATH": "/usr/bin:/bin",
                "UI_ROOT": str(self.here),
                "RULE": str(self.rule),
                "ROLLBACK": rollback,
            },
        )
        self.assertEqual(done.returncode != 0, fails != "none", done.stderr)
        return done.stderr.replace(str(self.here), "<root>")

    def b_falls_unproved(self) -> None:
        self.update("B", fails="after", rollback="refused")
        self.assertEqual(self.running, "B")
        self.assertEqual(self.rule.read_text(), "B's rule\n")
        self.assertEqual(self.marker, "RELEASE=B\nPREVIOUS=A\n")
        self.assertEqual(self.kept, ["A's rule"])

    def test_a_failure_before_the_next_release_s_switch_leaves_what_it_found(self) -> None:
        self.b_falls_unproved()
        said = self.update("C", fails="before")
        self.assertIn("the update to B did not complete; this one goes on from A", said)
        self.assertEqual(self.running, "B")
        self.assertEqual(self.rule.read_text(), "B's rule\n")
        self.assertEqual(self.marker, "RELEASE=B\nPREVIOUS=A\n")
        self.assertEqual(self.kept, ["A's rule"])
        self.assertIn("B is not proved; the next update goes on from A", said)

        # Any number of them, and the one after still goes back to A.
        self.update("C", fails="before")
        self.update("D", fails="before")
        self.assertEqual(self.marker, "RELEASE=B\nPREVIOUS=A\n")
        self.assertEqual(self.kept, ["A's rule"])
        self.update("D", fails="after", rollback="restored")
        self.assertEqual(self.running, "A")
        self.assertEqual(self.rule.read_text(), "A's rule\n")
        self.assertIsNone(self.marker)
        self.assertFalse((self.here / "platform-update/kept").exists())

    def test_a_failure_after_the_next_release_s_switch_goes_back_to_the_release_last_proved(
        self,
    ) -> None:
        self.b_falls_unproved()
        self.update("C", fails="after", rollback="restored")
        self.assertEqual(self.running, "A")
        self.assertEqual(self.rule.read_text(), "A's rule\n")
        self.assertIsNone(self.marker)

    def test_a_rollback_that_fails_again_keeps_the_release_last_proved(self) -> None:
        self.b_falls_unproved()
        self.update("C", fails="after", rollback="refused")
        self.assertEqual(self.running, "C")
        self.assertEqual(self.rule.read_text(), "C's rule\n")
        self.assertEqual(self.marker, "RELEASE=C\nPREVIOUS=A\n")
        self.assertEqual(self.kept, ["A's rule"])

    def test_the_next_release_proved_ends_the_unfinished_update(self) -> None:
        self.b_falls_unproved()
        self.update("C", fails="before")
        self.update("C", fails="none")
        self.assertEqual(self.running, "C")
        self.assertEqual(self.rule.read_text(), "C's rule\n")
        self.assertIsNone(self.marker)
        self.assertFalse((self.here / "platform-update/kept").exists())

    def test_a_release_proved_over_an_unproved_one_needs_no_failure_first(self) -> None:
        self.b_falls_unproved()
        self.update("C", fails="none")
        self.assertEqual(self.running, "C")
        self.assertEqual(self.rule.read_text(), "C's rule\n")
        self.assertIsNone(self.marker)
        self.assertFalse((self.here / "platform-update/kept").exists())

    def test_a_failure_before_the_switch_gives_the_release_last_proved_its_files(self) -> None:
        """The copy a failed restore left, with A running again: all of it goes back."""

        self.update("B", fails="none")
        self.rule.write_text("B's rule, half put back\n")
        (self.here / "platform-update/kept").mkdir(parents=True)
        (self.here / "platform-update/kept/1").write_text("B's rule\n")
        (self.here / "platform-update/kept/manifest").write_text(
            f"hook\t{self.rule}\t{self.here}/platform-update/kept/1\n"
        )
        (self.here / "platform-update/update").write_text("RELEASE=C\nPREVIOUS=B\n")
        self.update("C", fails="before")
        self.assertEqual(self.running, "B")
        self.assertEqual(self.rule.read_text(), "B's rule\n")
        self.assertIsNone(self.marker)

    def test_a_copy_without_its_marker_is_not_taken_for_one(self) -> None:
        """A copy left beside no marker - removed by hand - names no release to go back to."""

        (self.here / "platform-update/kept").mkdir(parents=True)
        (self.here / "platform-update/kept/1").write_text("an older release's rule\n")
        (self.here / "platform-update/kept/manifest").write_text(
            f"hook\t{self.rule}\t{self.here}/platform-update/kept/1\n"
        )
        self.update("B", fails="after", rollback="restored")
        self.assertEqual(self.running, "A")
        self.assertEqual(self.rule.read_text(), "A's rule\n")


if __name__ == "__main__":
    unittest.main()


#
# The CLI's cluster list: the names in $CLUSTER_FILE, one a line, or a refusal.
#
STUB_CLUSTER_CONFIG = """#!/bin/bash
[[ "$1" == --list ]] || exit 2
[[ -z "$CLUSTER_FILE_UNREADABLE" ]] || { echo "cannot read clusters.yaml" >&2; exit 1; }
# shellcheck disable=SC2086 # the list is words on purpose
[[ -z "$CLUSTER_FILE" ]] || printf '%s\\n' $CLUSTER_FILE
"""

#
# A release's Python, standing in for either module. The config read prints
# what the wrapper asks for; `--help` says whether the module knows the
# collector flags; the check itself records its arguments and, like argparse
# in a module that predates them, refuses flags it does not know.
#
STUB_PYTHON = """#!/bin/bash
if [[ "$1" == "-I" && "$2" == "-c" && "$3" == *haprion-worker* ]]; then
    echo "${PACKAGE:-haprion_ui}"
    exit 0
fi
if [[ "$1" == "-" ]]; then
    cat >/dev/null
    # shellcheck disable=SC2086 # the list is words on purpose
    printf '%s\\n' "$TRAFFIC_LOGS" $UI_CLUSTERS
    exit 0
fi
if [[ "$*" == "-m ${PACKAGE:-haprion_ui}.compatibility --help" ]]; then
    echo "usage: compatibility --platform-root ROOT"
    [[ "$MODULE" == new ]] && echo "  --collector-config PATH"
    exit 0
fi
printf '%s\\n' "$0" "$@" > "$RECORD"
if [[ "$MODULE" == old && "$*" == *--collector-config* ]]; then
    echo "compatibility: error: unrecognized arguments: --collector-config" >&2
    exit 2
fi
"""


class TheWrapperRunsAgainstARelease(unittest.TestCase):
    """`check-compatibility` run for real, against a stand-in release.

    The tests above read the wrapper as text, which is how `5e1f942` passed
    them while sending an installed release's module flags it did not know:
    only running it shows what it hands the module. The wrapper is copied
    unchanged; its `../lib.sh` is the real one with the root check alone left
    out, because `$EUID` cannot be faked, and its `accounts.sh` the real one
    with the release root moved into the test's directory.
    """

    def setUp(self) -> None:
        work = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, work)
        (work / "platform").mkdir()
        shutil.copy2(ROOT / "install/platform/check-compatibility", work / "platform")
        self.root = work / "root"
        (work / "lib.sh").write_text((ROOT / "install/lib.sh").read_text() + "need_root() { :; }\n")
        shutil.copy2(ROOT / "install/node-lib.sh", work / "node-lib.sh")
        shutil.copy2(ROOT / "install/defaults.sh", work / "defaults.sh")
        self.payload = work / "PAYLOAD"
        (work / "accounts.sh").write_text(
            (ROOT / "install/accounts.sh")
            .read_text()
            .replace("readonly UI_ROOT=/opt/haprion-ui", f"readonly UI_ROOT={self.root}")
            .replace(
                "readonly UI_PAYLOAD=/usr/lib/haprion/ui/PAYLOAD",
                f"readonly UI_PAYLOAD={self.payload}",
            )
        )
        for release in ("current-release", "candidate"):
            python = self.root / "releases" / release / "venv/bin/python"
            python.parent.mkdir(parents=True)
            python.write_text(STUB_PYTHON)
            python.chmod(0o755)
        (self.root / "current").symlink_to(self.root / "releases/current-release")
        self.record = work / "arguments"
        self.wrapper = work / "platform/check-compatibility"
        self.cluster_config = work / "haprion-cluster-config"
        self.cluster_config.write_text(STUB_CLUSTER_CONFIG)
        self.cluster_config.chmod(0o755)

    def check(
        self,
        *arguments: str,
        module: str,
        traffic: str = "enabled",
        package: str = "haprion_ui",
        ui_clusters: str = "alpha",
        cluster_file: str | None = "alpha",
    ) -> tuple[int, str]:
        environment = {
            **os.environ,
            "PACKAGE": package,
            "MODULE": module,
            "TRAFFIC_LOGS": traffic,
            "RECORD": str(self.record),
            "UI_CLUSTERS": ui_clusters,
            "CLUSTER_CONFIG": str(self.cluster_config),
            "CLUSTER_FILE": cluster_file if cluster_file is not None else "",
            "CLUSTER_FILE_UNREADABLE": "1" if cluster_file is None else "",
        }
        completed = subprocess.run(  # noqa: S603 - the copied wrapper, fixed arguments
            ["/bin/bash", str(self.wrapper), *arguments],
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        return completed.returncode, completed.stderr

    def recorded(self) -> list[str]:
        return self.record.read_text().splitlines()

    def test_a_release_that_predates_the_inventory_check_is_not_handed_its_flags(self) -> None:
        code, errors = self.check(module="old")
        self.assertEqual(code, 0, errors)
        self.assertNotIn("--collector-config", self.recorded())
        self.assertIn("predates the traffic collector inventory check", errors)

    def test_a_release_is_run_under_its_own_package(self) -> None:
        code, errors = self.check(module="new", package="earlier_ui")
        self.assertEqual(code, 0, errors)
        self.assertEqual(self.recorded()[1:3], ["-m", "earlier_ui.compatibility"])

    def test_a_release_that_knows_the_check_is_asked_it(self) -> None:
        code, errors = self.check(module="new")
        self.assertEqual(code, 0, errors)
        arguments = self.recorded()
        self.assertIn("/etc/haprion/traffic-collector.json", arguments)
        self.assertIn("/etc/haprion/runtime-policy.yaml", arguments)
        self.assertEqual(arguments[arguments.index("--clusters") + 1], "alpha")

    def test_without_traffic_logs_nothing_about_them_is_asked(self) -> None:
        code, errors = self.check(module="new", traffic="disabled")
        self.assertEqual(code, 0, errors)
        self.assertNotIn("--collector-config", self.recorded())

    def test_a_named_release_is_asked_through_its_own_python(self) -> None:
        code, errors = self.check("--release", "candidate", "--before-migration", module="new")
        self.assertEqual(code, 0, errors)
        arguments = self.recorded()
        self.assertEqual(arguments[0], str(self.root / "releases/candidate/venv/bin/python"))
        for flag in ("--ui-release", "--skip-services", "--upgrade-from-current"):
            self.assertIn(flag, arguments)
        self.assertNotIn("--environment", arguments)

    def test_the_release_last_proved_is_handed_on_when_it_is_not_the_running_one(self) -> None:
        """Review 26-10-29, AA01: an update over an unproved release goes back past it."""

        (self.root / "releases/proved/venv/bin").mkdir(parents=True)
        before = ("--release", "candidate", "--before-migration")
        code, errors = self.check(*before, "--rollback-to", "proved", module="new")
        self.assertEqual(code, 0, errors)
        arguments = self.recorded()
        self.assertEqual(arguments[arguments.index("--rollback-to") + 1], "proved")
        code, errors = self.check(*before, "--rollback-to", "current-release", module="new")
        self.assertEqual(code, 0, errors)
        self.assertNotIn("--rollback-to", self.recorded())
        for refused in (
            ("--release", "candidate", "--rollback-to", "proved"),
            (*before, "--rollback-to", "../proved"),
            (*before, "--rollback-to"),
        ):
            with self.subTest(refused=refused):
                code, errors = self.check(*refused, module="new")
                self.assertEqual(code, 1)
                self.assertIn("ERROR", errors)

    def test_the_release_the_package_installed_checks_the_current_one(self) -> None:
        """Review 26-10-29, A01: after a rollback the current release is older.

        Its own code ruled out a schema past its head that the rollback had
        just let it run on; the packaged release knows the rule the rollback
        used, and checks the current release's requirements by it.
        """

        self.payload.write_text("RELEASE_ID=candidate\nRELEASE_SHA256=0\n")
        code, errors = self.check(module="new")
        self.assertEqual(code, 0, errors)
        arguments = self.recorded()
        self.assertEqual(arguments[0], str(self.root / "releases/candidate/venv/bin/python"))
        self.assertEqual(arguments[arguments.index("--packaged") + 1], "candidate")
        self.assertNotIn("--ui-release", arguments)
        self.assertNotIn("not on disk", errors)

    def test_without_the_package_s_release_the_checked_one_checks_itself(self) -> None:
        for payload in (None, "RELEASE_ID=gone\n", "RELEASE_ID=../candidate\n"):
            with self.subTest(payload=payload):
                if payload is None:
                    self.payload.unlink(missing_ok=True)
                else:
                    self.payload.write_text(payload)
                code, errors = self.check(module="new")
                self.assertEqual(code, 0, errors)
                arguments = self.recorded()
                self.assertEqual(arguments[0], str(self.root / "current/venv/bin/python"))
                self.assertNotIn("--packaged", arguments)
                self.assertIn("is not on disk", errors)

    def test_a_first_installation_is_checked_without_what_step_07_installs(self) -> None:
        code, errors = self.check("--release", "candidate", "--first-install", module="new")
        self.assertEqual(code, 0, errors)
        arguments = self.recorded()
        for flag in ("--ui-release", "--skip-services", "--first-install"):
            self.assertIn(flag, arguments)
        self.assertNotIn("--upgrade-from-current", arguments)

    def test_a_first_installation_names_its_release(self) -> None:
        code, errors = self.check("--first-install", module="new")
        self.assertNotEqual(code, 0)
        self.assertIn("--first-install requires --release", errors)

    def clusters(self) -> list[str]:
        arguments = self.recorded()
        start = arguments.index("--clusters") + 1
        return list(itertools.takewhile(lambda word: not word.startswith("--"), arguments[start:]))

    def test_the_clusters_checked_are_the_cluster_file_s(self) -> None:
        # Review 2026-10-22, 6-1: the list came from `ui.toml`, so a cluster
        # created in the interface was never asked about.
        code, errors = self.check(module="new", ui_clusters="", cluster_file="alpha beta")
        self.assertEqual(code, 0, errors)
        self.assertEqual(self.clusters(), ["alpha", "beta"])
        self.assertNotIn("ui.toml", errors)

    def test_a_cluster_only_ui_toml_still_lists_is_not_asked_about(self) -> None:
        code, errors = self.check(module="new", ui_clusters="alpha gone", cluster_file="alpha")
        self.assertEqual(code, 0, errors)
        self.assertEqual(self.clusters(), ["alpha"])
        self.assertIn("ui.toml's clusters (alpha gone) differ", errors)

    def test_the_same_clusters_in_another_order_are_not_a_difference(self) -> None:
        code, errors = self.check(module="new", ui_clusters="beta alpha", cluster_file="alpha beta")
        self.assertEqual(code, 0, errors)
        self.assertNotIn("ui.toml", errors)

    def test_no_cluster_yet_is_no_node_to_ask(self) -> None:
        code, errors = self.check(module="new", ui_clusters="", cluster_file="")
        self.assertEqual(code, 0, errors)
        self.assertEqual(self.clusters(), [])

    def test_a_cluster_file_that_cannot_be_read_stops_the_check(self) -> None:
        code, errors = self.check(module="new", cluster_file=None)
        self.assertNotEqual(code, 0)
        self.assertIn("the cluster file could not be read", errors)
        self.assertFalse(self.record.exists())


class TheReleaseSaysWhichPackageItIs(unittest.TestCase):
    """The scripts outside a release ask it for its package (rename 26-10-10)."""

    COPIES = (
        "install/lib.sh",
        "install/platform/bin/haprion-rollback",
        "install/platform/bin/haprion-web",
    )

    @staticmethod
    def function(path: str) -> str:
        text = (ROOT / path).read_text()
        start = text.index("release_module() {")
        return text[start : text.index("\n}\n", start) + 3]

    def test_every_copy_is_the_same(self) -> None:
        first, *others = (self.function(path) for path in self.COPIES)
        for path, text in zip(self.COPIES[1:], others, strict=True):
            with self.subTest(path=path):
                self.assertEqual(text, first)

    def test_it_names_this_releases_package(self) -> None:
        import sys

        script = self.function(self.COPIES[0]) + 'release_module "$1"\n'
        result = subprocess.run(  # noqa: S603 - fixed shell, this checkout's function
            ["/bin/bash", "-c", script, "release_module", sys.executable],
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(result.stdout.strip(), "haprion_ui")

    def test_the_web_unit_names_no_package_and_no_port(self) -> None:
        unit = (ROOT / "install/platform/examples/haprion-web.service.example").read_text()
        self.assertIn("ExecStart=/usr/sbin/haprion-web\n", unit)
        self.assertNotIn("haprion_ui", unit)
        self.assertNotIn("--port", unit)

    def launch(self, environment: dict[str, str]) -> list[str]:
        """`haprion-web` run against a release whose Python and uvicorn say what they were asked."""

        import os
        import tempfile

        root = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, root, True)
        bin_dir = root / "release" / "venv" / "bin"
        bin_dir.mkdir(parents=True)
        (bin_dir / "python").write_text(
            '#!/bin/bash\ncase "$*" in *entry_points*) echo haprion_ui ;; *) echo 8443 ;; esac\n'
        )
        (bin_dir / "uvicorn").write_text('#!/bin/bash\nprintf "%s\\n" "$@"\n')
        for name in ("python", "uvicorn"):
            (bin_dir / name).chmod(0o755)
        script = root / "haprion-web"
        script.write_text(
            (ROOT / "install/platform/bin/haprion-web")
            .read_text()
            .replace("release=/opt/haprion-ui/current", f"release={root / 'release'}")
        )
        done = subprocess.run(  # noqa: S603 - fixed shell, the copied script
            ["/bin/bash", str(script)],
            capture_output=True,
            text=True,
            check=True,
            env={"PATH": os.environ["PATH"], **environment},
        )
        return done.stdout.splitlines()

    def test_the_web_takes_the_socket_systemd_hands_it(self) -> None:
        """5-8: no port any local process could reach past nginx."""

        argv = self.launch({"LISTEN_FDS": "1"})
        self.assertIn("--fd", argv)
        self.assertEqual(argv[argv.index("--fd") + 1], "3")
        self.assertNotIn("--port", argv)
        self.assertIn("--forwarded-allow-ips=*", argv)

    def test_a_unit_put_back_without_its_socket_still_starts_on_its_port(self) -> None:
        """An update that did not finish puts back the unit and site that listened on loopback."""

        argv = self.launch({})
        self.assertEqual(argv[argv.index("--port") + 1], "8443")
        self.assertEqual(argv[argv.index("--host") + 1], "127.0.0.1")
        self.assertIn("--forwarded-allow-ips=127.0.0.1", argv)

    def test_one_socket_path_for_the_unit_nginx_the_steps_and_the_rollback(self) -> None:
        socket = (ROOT / "install/platform/examples/haprion-web.socket.example").read_text()
        self.assertIn("ListenStream=/run/haprion-web.sock\n", socket)
        self.assertIn("SocketGroup=www-data\n", socket)
        self.assertIn("SocketMode=0660\n", socket)
        site = (ROOT / "install/platform/examples/haprion.nginx.example").read_text()
        self.assertIn("proxy_pass http://unix:/run/haprion-web.sock;", site)
        self.assertNotIn("127.0.0.1:8080", site)
        for path in ("install/lib.sh", "install/platform/bin/haprion-rollback"):
            with self.subTest(path=path):
                self.assertIn("WEB_SOCKET=/run/haprion-web.sock\n", (ROOT / path).read_text())
        unit = (ROOT / "install/platform/examples/haprion-web.service.example").read_text()
        self.assertIn("Requires=haprion-web.socket\n", unit)

    def test_nginx_takes_the_site_after_the_activation_and_before_the_proof(self) -> None:
        text = (ROOT / "install/platform/update-platform-release").read_text()
        activated = text.index('./install-ui-release "$release_id"')
        reloaded = text.index("systemctl reload nginx")
        self.assertLess(activated, reloaded)
        self.assertLess(reloaded, text.index('step "Proving the running installation"'))

    def test_the_update_installs_the_platform_files_before_it_checks(self) -> None:
        """Review 2026-10-22, 6-5: the check holds the files to the candidate, so they come first."""

        text = (ROOT / "install/platform/update-platform-release").read_text()
        refresh = text.index('./refresh-platform-files "$release_id" "$kept"')
        self.assertLess(refresh, text.index("./check-compatibility --release"))
        self.assertLess(refresh, text.index('./install-ui-release "$release_id"'))
        self.assertIn(
            "haprion-web.service.example",
            (ROOT / "install/platform/refresh-platform-files").read_text(),
        )

    def test_a_failed_update_puts_the_platform_files_back_before_the_rollback(self) -> None:
        text = (ROOT / "install/platform/update-platform-release").read_text()
        restore = text[text.index("restore_previous() {") :]
        self.assertLess(restore.index("settle_files"), restore.index('"$rollback" --to'))
        exiting = text[text.index("on_exit() {") :]
        self.assertIn("settle_files", exiting[: exiting.index("\n}\n")])
        self.assertIn("trap on_exit EXIT", text)
        self.assertLess(
            text.index(
                "files_settled=yes\n", text.index('step "Proving the running installation"')
            ),
            text.index('step "Pruning old releases"'),
        )


LOCK_FUNCTION = re.compile(r"^hold_release_lock\(\) \{\n.*?^\}\n", re.M | re.S)
LOCKED = (
    "install/platform/update-platform-release",
    "install/platform/install-ui-release",
    "install/platform/bin/haprion-rollback",
    "install/haprion-setup",
)


class OneReleaseChangeAtATime(unittest.TestCase):
    """Review 26-10-29, A10: an update, a rollback and an activation took no lock."""

    def function(self) -> str:
        found = LOCK_FUNCTION.search((ROOT / "install/lib.sh").read_text())
        if found is None:
            self.fail("lib.sh has no hold_release_lock")
        return found.group(0)

    def test_every_copy_is_the_same(self) -> None:
        rollback = LOCK_FUNCTION.search(
            (ROOT / "install/platform/bin/haprion-rollback").read_text()
        )
        self.assertIsNotNone(rollback)
        self.assertEqual(rollback.group(0) if rollback else "", self.function())
        for path in ("install/lib.sh", "install/platform/bin/haprion-rollback"):
            with self.subTest(path=path):
                self.assertIn(
                    "\nRELEASE_LOCK=/run/haprion/ui-release.lock\n", (ROOT / path).read_text()
                )

    def test_the_lock_is_root_s_alone(self) -> None:
        """Review 26-10-29, AA06: any account could open the 0644 file and hold every change off."""

        with tempfile.TemporaryDirectory() as raw:
            lock = Path(raw) / "run/ui-release.lock"
            lock.parent.mkdir()
            lock.write_text("")
            lock.chmod(0o644)
            done = subprocess.run(  # noqa: S603 - fixed interpreter, the script's own function
                [
                    "/bin/bash",
                    "-c",
                    f"RELEASE_LOCK={lock}; umask 022; "
                    'die() { echo "ERROR: $*" >&2; exit 1; }; '
                    + self.function()
                    + "hold_release_lock",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertEqual(lock.stat().st_mode & 0o777, 0o600)

    def test_under_dpkg_the_way_to_run_it_again_is_dpkg_s(self) -> None:
        """Review 26-10-29, a's cosmetics: under apt, "this" is `dpkg --configure -a`."""

        with tempfile.TemporaryDirectory() as raw:
            prelude = (
                f"RELEASE_LOCK={Path(raw) / 'ui-release.lock'}; "
                'die() { echo "ERROR: $*" >&2; exit 1; }; ' + self.function()
            )
            inner = prelude + "hold_release_lock"
            done = subprocess.run(  # noqa: S603 - fixed interpreter, the script's own function
                [
                    "/bin/bash",
                    "-c",
                    prelude
                    + "hold_release_lock; DPKG_MAINTSCRIPT_PACKAGE=haprion-ui "
                    + f"/bin/bash -c {shlex.quote(inner)} 9>&-",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(done.returncode, 1)
            self.assertIn("; when it is done: sudo dpkg --configure -a", done.stderr)

    def test_the_rollback_reads_the_releases_under_the_lock(self) -> None:
        """AA06: `current` read before the lock named the release an update had just replaced."""

        rollback = (ROOT / "install/platform/bin/haprion-rollback").read_text()
        lock = rollback.index("\nhold_release_lock\n")
        self.assertLess(lock, rollback.index("\nread_releases\n"))
        self.assertLess(
            rollback.index("\nread_releases\n"), rollback.index('if [[ -z "$target" ]]')
        )
        self.assertNotIn('\ncurrent="$(basename', rollback[:lock])

    def test_each_command_that_changes_the_release_holds_it(self) -> None:
        for path in LOCKED:
            with self.subTest(path=path):
                self.assertIn("\nhold_release_lock\n", (ROOT / path).read_text())
        installer = (ROOT / "install/platform/install-ui-release").read_text()
        self.assertLess(
            installer.index('if [[ "$prepare_only" -eq 1 ]]'),
            installer.index("\nhold_release_lock\n"),
        )
        self.assertLess(installer.index("\nhold_release_lock\n"), installer.index("pause --wait"))
        rollback = (ROOT / "install/platform/bin/haprion-rollback").read_text()
        self.assertLess(rollback.index("    --list)"), rollback.index("\nhold_release_lock\n"))
        self.assertLess(rollback.index("\nhold_release_lock\n"), rollback.index("pause --wait"))
        update = (ROOT / "install/platform/update-platform-release").read_text()
        self.assertLess(update.index("\nhold_release_lock\n"), update.index("unfinished_update\n"))

    def test_a_second_change_is_refused_and_a_command_the_first_runs_is_not(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            lock = Path(raw) / "run/ui-release.lock"
            prelude = (
                f"RELEASE_LOCK={lock}; "
                'die() { echo "ERROR: $*" >&2; exit 1; }; ' + self.function()
            )
            inner = prelude + "hold_release_lock && echo inherited"
            outer = (
                prelude
                + "hold_release_lock; echo held; "
                + f"/bin/bash -c {shlex.quote(inner)}; "
                + f"/bin/bash -c {shlex.quote(inner)} 9>&-; "
                + 'echo "second=$?"'
            )
            done = subprocess.run(  # noqa: S603 - fixed interpreter, the script's own function
                ["/bin/bash", "-c", outer], capture_output=True, text=True, check=False
            )
            self.assertEqual(done.stdout.split(), ["held", "inherited", "second=1"], done.stderr)
            self.assertRegex(
                done.stderr,
                r"another change of the UI release is running \(pid [0-9]+ or a command it "
                r"started\); run this again when it is done",
            )
            again = subprocess.run(  # noqa: S603 - fixed interpreter, the script's own function
                ["/bin/bash", "-c", prelude + "hold_release_lock && echo free"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(again.stdout.strip(), "free", again.stderr)
