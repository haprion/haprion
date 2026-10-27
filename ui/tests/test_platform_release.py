"""The platform release and its schema move as one named delivery."""

from __future__ import annotations

import itertools
import os
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

        self.assertIn('-m "${module}.compatibility" --help', wrapper)
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

    def test_both_post_switch_failures_restore_the_previous_release(self) -> None:
        self.assertEqual(self.update.count("restore_previous\n"), 2)
        self.assertIn('"$rollback" --to "$previous_id"', self.update)
        self.assertIn("was restored but the installation is not compatible", self.update)

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
                        f"files_settled={settled}; kept=/nonexistent; "
                        "warn() { :; }; restore_previous() { echo restore; }; "
                        f"candidate_current() {{ {switched}; }}; where_it_stands() {{ echo said; }}; "
                        f"settle_files() {{ echo settle; }}; {body}on_exit",
                    ],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                self.assertEqual(done.stdout.split(), expected)

    def test_an_activation_that_never_switched_says_so_once(self) -> None:
        """R2 26-10-27 (F8): *was restored* and *no UI rollback is needed* twice."""

        self.assertNotIn('warn "the candidate is not current', self.update)
        activation = self.update[
            self.update.index('if ! ./install-ui-release "$release_id"; then') :
        ]
        activation = activation[: activation.index("\nfi\n")]
        self.assertLess(activation.index("candidate_current"), activation.index("restore_previous"))
        self.assertIn(
            "activation stopped before the switch; ${previous_id} kept running", activation
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
        (work / "accounts.sh").write_text(
            (ROOT / "install/accounts.sh")
            .read_text()
            .replace("readonly UI_ROOT=/opt/haprion-ui", f"readonly UI_ROOT={self.root}")
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
