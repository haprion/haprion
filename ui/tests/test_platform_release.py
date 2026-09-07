"""The platform release and its schema move as one named delivery."""

from __future__ import annotations

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


class CoordinatedUpdateTests(unittest.TestCase):
    update: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.update = (ROOT / "install/platform/update-platform-release").read_text()

    def test_nothing_moves_before_prerequisites_and_schema_are_proved(self) -> None:
        prepare = self.update.index("install-ui-release --prepare")
        prerequisites = self.update.index("--before-migration")
        migrate = self.update.index('migrate "$answers" --release')
        database = self.update.index('03-verify "$answers"')
        candidate = self.update.index(
            'check-compatibility "$answers" --release "$release_id"', database
        )
        activate = self.update.index('install-ui-release "$answers" "$source_tree"')
        self.assertLess(prepare, prerequisites)
        self.assertLess(prerequisites, migrate)
        self.assertLess(migrate, database)
        self.assertLess(database, candidate)
        self.assertLess(candidate, activate)

    def test_both_post_switch_failures_restore_the_previous_release(self) -> None:
        self.assertEqual(self.update.count("restore_previous\n"), 2)
        self.assertIn('"$rollback" --to "$previous_id"', self.update)
        self.assertIn("was restored but the installation is not compatible", self.update)

    def test_it_never_installs_the_independent_cli_or_node_bundle(self) -> None:
        self.assertNotIn("install-release.py", self.update)
        self.assertNotIn("04-node-prepare", self.update)


if __name__ == "__main__":
    unittest.main()
