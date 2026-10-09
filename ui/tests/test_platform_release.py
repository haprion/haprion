"""The platform release and its schema move as one named delivery."""

from __future__ import annotations

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

    def test_release_contains_the_complete_migration_environment(self) -> None:
        self.assertIn('"${source_tree}/ui/alembic.ini"', self.installer)
        self.assertIn('find "${source_tree}/ui/migrations" -type f', self.installer)
        self.assertIn("migrations match the source tree", self.installer)
        self.assertIn("script.py.mako", self.installer)

    def test_migrate_can_name_one_prepared_release(self) -> None:
        self.assertIn(
            'migration_root="${PLATFORM_ROOT}/releases/${release_id}/migration"', self.migrate
        )
        self.assertIn('exec "$alembic" -c alembic.ini "$@"', self.migrate)

    def test_release_id_cannot_escape_the_release_root(self) -> None:
        self.assertIn("invalid release id", self.migrate)
        self.assertIn("{0,127}", self.migrate)

    def test_candidate_check_does_not_mistake_old_processes_for_the_candidate(self) -> None:
        wrapper = (ROOT / "install/platform/check-compatibility").read_text()
        self.assertIn('extra_args+=(--ui-release "$release_id" --skip-services)', wrapper)
        self.assertIn("extra_args+=(--upgrade-from-current)", wrapper)

    def test_the_development_platform_passes_its_boundary_to_the_check(self) -> None:
        wrapper = (ROOT / "install/platform/check-compatibility").read_text()
        self.assertIn('environment="${ENVIRONMENT:-prod}"', wrapper)
        self.assertIn('extra_args+=(--environment "$environment")', wrapper)
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

        self.assertIn("-m haproxy_ui.compatibility --help", wrapper)
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
        migrate = self.update.index('migrate "$answers" --release')
        database = self.update.index('install/platform/03-verify" "$answers"')
        candidate = self.update.index(
            'check-compatibility "$answers" --release "$release_id"', database
        )
        activate = self.update.index('install-ui-release "$answers" "$source_tree"')
        self.assertLess(prepare, prerequisites)
        self.assertLess(prerequisites, migrate)
        self.assertLess(migrate, database)
        self.assertLess(database, candidate)
        self.assertLess(candidate, activate)

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

    def test_both_post_switch_failures_restore_the_previous_release(self) -> None:
        self.assertEqual(self.update.count("restore_previous\n"), 2)
        self.assertIn('"$rollback" --to "$previous_id"', self.update)
        self.assertIn("was restored but the installation is not compatible", self.update)

    def test_old_releases_are_pruned_only_after_the_update_is_proved(self) -> None:
        """B156: retention runs after the final compatibility check, keeps ten
        (three on a development platform), and never the release just
        activated or the one it replaced."""

        final_check = self.update.index('if ! ./check-compatibility "$answers"; then')
        prune = self.update.index('step "Pruning old releases"')
        self.assertLess(final_check, prune)
        self.assertIn('keep="${RELEASES_KEPT:-10}"', self.update)
        self.assertIn('keep="${RELEASES_KEPT:-3}"', self.update)
        self.assertIn(
            '[[ "$old_release" == "$release_id" || "$old_release" == "$previous_id" ]] && continue',
            self.update,
        )
        self.assertIn("-printf '%T@ %f\\n'", self.update)

    def test_it_never_installs_the_independent_cli_or_node_bundle(self) -> None:
        self.assertNotIn("install-release.py", self.update)
        self.assertNotIn("04-node-prepare", self.update)


if __name__ == "__main__":
    unittest.main()


#
# A release's Python, standing in for either module. The config read prints
# what the wrapper asks for; `--help` says whether the module knows the
# collector flags; the check itself records its arguments and, like argparse
# in a module that predates them, refuses flags it does not know.
#
STUB_PYTHON = """#!/bin/bash
if [[ "$1" == "-" ]]; then
    cat >/dev/null
    printf '%s\\n' "$TRAFFIC_LOGS" alpha
    exit 0
fi
if [[ "$*" == "-m haproxy_ui.compatibility --help" ]]; then
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
    out, because `$EUID` cannot be faked.
    """

    def setUp(self) -> None:
        work = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, work)
        (work / "platform").mkdir()
        shutil.copy2(ROOT / "install/platform/check-compatibility", work / "platform")
        (work / "lib.sh").write_text(f'source "{ROOT / "install/lib.sh"}"\nneed_root() {{ :; }}\n')
        self.root = work / "root"
        for release in ("current-release", "candidate"):
            python = self.root / "releases" / release / "venv/bin/python"
            python.parent.mkdir(parents=True)
            python.write_text(STUB_PYTHON)
            python.chmod(0o755)
        (self.root / "current").symlink_to(self.root / "releases/current-release")
        self.answers = work / "answers.env"
        self.answers.write_text(
            f"PLATFORM_ROOT={self.root}\nDB_NAME=ui\nDB_MIGRATION_ROLE=ui_owner\n"
            "WEB_USER=web\nWORKER_USER=worker\nPOLLER_USER=poller\n"
        )
        self.record = work / "arguments"
        self.wrapper = work / "platform/check-compatibility"

    def check(self, *arguments: str, module: str, traffic: str = "enabled") -> tuple[int, str]:
        environment = {
            **os.environ,
            "MODULE": module,
            "TRAFFIC_LOGS": traffic,
            "RECORD": str(self.record),
        }
        environment.pop("ENVIRONMENT", None)
        completed = subprocess.run(  # noqa: S603 - the copied wrapper, fixed arguments
            ["/bin/bash", str(self.wrapper), str(self.answers), *arguments],
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
        self.assertEqual(arguments[arguments.index("--environment") + 1], "prod")
