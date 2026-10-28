from __future__ import annotations

import argparse
import ast
import contextlib
import io
import json
import re
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from haprion import accounts
from haprion.cli import (
    backup_job_ask,
    backup_job_helper,
    cert_receiver_ask,
    cert_receiver_helper,
    node_ask,
    node_helper,
    node_restore_ask,
    node_restore_helper,
)

from haprion_ui import compatibility

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "ui/src/haprion_ui/compatibility.json"


class TheSudoRulesAfterARollback(unittest.TestCase):
    """Review 26-10-24, 11-06: the sudo rules follow the package, not the release.
    After a rollback on its own, the newer package's rules for a helper the older
    release does not run are said, and are no failure; anything else still is."""

    HELPERS = ("haprion-deploy-helper", "haprion-revert-helper")

    def check(self, *helpers: str, mode: int = 0o440, uid: int = 0) -> tuple[int, str]:
        rules = compatibility.expected_sudo_rules("svc-app", helpers, Path("/opt/haprion"))
        with tempfile.TemporaryDirectory() as raw:
            (Path(raw) / "rules").write_text("\n".join(rules) + "\n")
            report = compatibility.Report()
            status = SimpleNamespace(st_uid=uid, st_mode=0o100000 | mode)
            output = io.StringIO()
            with (
                mock.patch.object(Path, "stat", return_value=status),
                contextlib.redirect_stdout(output),
            ):
                compatibility.check_sudoers(
                    report,
                    root=Path(raw),
                    name="rules",
                    user="svc-app",
                    helpers=self.HELPERS,
                    cli_root=Path("/opt/haprion"),
                    label="worker sudoers",
                )
        return report.failures, output.getvalue()

    def test_the_exact_rules_pass(self) -> None:
        failures, said = self.check(*self.HELPERS)
        self.assertEqual((failures, said.split()[0]), (0, "PASS"))

    def test_a_rule_for_a_helper_this_release_does_not_run_is_a_warning(self) -> None:
        failures, said = self.check(*self.HELPERS, "haprion-newer-helper")
        self.assertEqual((failures, said.split()[0]), (0, "WARN"))
        self.assertIn("haprion-newer-helper", said)

    def test_a_missing_rule_or_a_wrong_mode_or_owner_still_fails(self) -> None:
        for helpers, mode, uid in (
            (self.HELPERS[:1], 0o440, 0),
            ((*self.HELPERS, "haprion-newer-helper"), 0o640, 0),
            ((*self.HELPERS, "haprion-newer-helper"), 0o440, 1000),
        ):
            with self.subTest(helpers=helpers, mode=mode, uid=uid):
                failures, said = self.check(*helpers, mode=mode, uid=uid)
                self.assertEqual((failures, said.split()[0]), (1, "FAIL"))

    def test_an_extra_rule_of_another_form_still_fails(self) -> None:
        rules = compatibility.expected_sudo_rules("svc-app", self.HELPERS, Path("/opt/haprion"))
        for extra in (
            "svc-app ALL=(root) NOPASSWD: ALL",
            "svc-app ALL=(root) NOPASSWD: /opt/haprion/current/bin/haprion-newer-helper *",
            'operator ALL=(root) NOPASSWD: /opt/haprion/current/bin/haprion-newer-helper ""',
            rules[0],
        ):
            with self.subTest(extra=extra):
                self.assertIsNone(
                    compatibility.extra_helper_rules(
                        (*rules, extra), rules, "svc-app", Path("/opt/haprion")
                    )
                )


class CompatibilityMetadataTests(unittest.TestCase):
    def test_the_running_ui_names_every_helper_its_services_need(self) -> None:
        requirements = compatibility.load_requirements(MANIFEST)
        worker = (ROOT / "install/platform/examples/haprion-worker.sudoers.example").read_text()
        poller = (ROOT / "install/platform/examples/haprion-poller.sudoers.example").read_text()

        self.assertEqual(
            compatibility.active_sudo_rules(worker),
            compatibility.expected_sudo_rules(
                accounts.WORKER, requirements.worker_helpers, Path("/opt/haprion")
            ),
        )
        self.assertEqual(
            compatibility.active_sudo_rules(poller),
            compatibility.expected_sudo_rules(
                accounts.POLLER, requirements.poller_helpers, Path("/opt/haprion")
            ),
        )

    def test_the_receiver_helper_is_a_socket_helper_and_the_paths_agree(self) -> None:
        """B163: the manifest, the client and the socket unit name one socket."""

        requirements = compatibility.load_requirements(MANIFEST)
        helper = Path(cert_receiver_helper.HELPER).name
        unit = (
            ROOT / "install/platform/examples/haprion-cert-receiver-helper.socket.example"
        ).read_text()

        self.assertNotIn(helper, requirements.worker_helpers)
        self.assertEqual(requirements.socket_helpers[helper], cert_receiver_ask.SOCKET_PATH)
        self.assertIn(f"ListenStream={cert_receiver_ask.SOCKET_PATH}\n", unit)
        self.assertIn("SocketGroup=WORKER_USER", unit)

    def test_backup_mutations_are_reached_only_through_their_socket(self) -> None:
        requirements = compatibility.load_requirements(MANIFEST)
        helper = Path(backup_job_helper.HELPER).name
        unit = (
            ROOT / "install/platform/examples/haprion-backup-job-helper.socket.example"
        ).read_text()

        self.assertNotIn(helper, requirements.worker_helpers)
        self.assertEqual(requirements.socket_helpers[helper], backup_job_ask.SOCKET_PATH)
        self.assertIn(f"ListenStream={backup_job_ask.SOCKET_PATH}\n", unit)
        self.assertIn("SocketGroup=WORKER_USER", unit)

    def test_node_changes_are_reached_only_through_their_socket(self) -> None:
        """B211: the manifest, the client and the socket unit name one socket."""

        requirements = compatibility.load_requirements(MANIFEST)
        helper = Path(node_helper.HELPER).name
        unit = (ROOT / "install/platform/examples/haprion-node-helper.socket.example").read_text()

        self.assertNotIn(helper, requirements.worker_helpers)
        self.assertEqual(requirements.socket_helpers[helper], node_ask.SOCKET_PATH)
        self.assertIn(f"ListenStream={node_ask.SOCKET_PATH}\n", unit)
        self.assertIn("SocketGroup=WORKER_USER", unit)

    def test_node_restores_are_reached_only_through_their_socket(self) -> None:
        requirements = compatibility.load_requirements(MANIFEST)
        helper = Path(node_restore_helper.HELPER).name
        unit = (
            ROOT / "install/platform/examples/haprion-node-restore-helper.socket.example"
        ).read_text()

        self.assertNotIn(helper, requirements.worker_helpers)
        self.assertEqual(requirements.socket_helpers[helper], node_restore_ask.SOCKET_PATH)
        self.assertIn(f"ListenStream={node_restore_ask.SOCKET_PATH}\n", unit)
        self.assertIn("SocketGroup=WORKER_USER", unit)

    def test_every_socket_a_release_installs_is_checked(self) -> None:
        # Resolve and cert-export were installed with every release and never
        # checked: a dead socket still read COMPATIBLE, and the editor said
        # nothing about names it could not look up (review 26-10-24, 11-04).
        requirements = compatibility.load_requirements(MANIFEST)
        refresh = (ROOT / "install/platform/refresh-platform-files").read_text()
        found = re.search(r"^SOCKETS=\(([^)]*)\)$", refresh, re.MULTILINE)
        if found is None:
            self.fail("refresh-platform-files names no SOCKETS")
        installed = {f"haprion-{name}-helper" for name in found.group(1).split()}

        self.assertEqual(set(requirements.socket_helpers), installed)
        for helper, path in requirements.socket_helpers.items():
            with self.subTest(helper):
                unit = (ROOT / f"install/platform/examples/{helper}.socket.example").read_text()
                self.assertIn(f"ListenStream={path}\n", unit)

    def test_invalid_metadata_is_refused_instead_of_defaulted(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "compatibility.json"
            path.write_text('{"schema_version":1,"requires":{}}')
            with self.assertRaises(compatibility.CompatibilityError):
                compatibility.load_requirements(path)

    def test_database_head_must_be_one_of_the_accepted_revisions(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "compatibility.json"
            document = json.loads(MANIFEST.read_text())
            document["requires"]["database_head"] = "9999"
            path.write_text(json.dumps(document))
            with self.assertRaisesRegex(compatibility.CompatibilityError, "database_head"):
                compatibility.load_requirements(path)

    def test_metadata_without_a_database_head_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "compatibility.json"
            document = json.loads(MANIFEST.read_text())
            document["requires"].pop("database_head")
            document["requires"]["database_revisions"] = ["0020"]
            path.write_text(json.dumps(document))

            with self.assertRaisesRegex(compatibility.CompatibilityError, "database_head"):
                compatibility.load_requirements(path)

    def test_requirements_match_this_deliverys_engine_schema_and_node_installer(self) -> None:
        requirements = compatibility.load_requirements(MANIFEST)
        engine = json.loads((ROOT / "src/haprion/compatibility.json").read_text())
        self.assertEqual(engine["engine_api"], requirements.engine_api)

        migrations = ROOT / "ui/migrations/versions"
        revisions: set[str] = set()
        parents: set[str] = set()
        for path in migrations.glob("[0-9]*.py"):
            text = path.read_text()
            revision = re.search(r'^revision = "([0-9]+)"$', text, re.MULTILINE)
            parent = re.search(r'^down_revision = "([0-9]+)"$', text, re.MULTILINE)
            if revision is None:
                self.fail(f"{path.name} has no revision")
            revisions.add(revision.group(1))
            if parent is not None:
                parents.add(parent.group(1))
        heads = revisions - parents
        self.assertEqual(requirements.database_head, next(iter(heads)))
        self.assertTrue(heads <= set(requirements.database_revisions))

        installer = (ROOT / "install/node-installation.sh").read_text()
        node_api = re.search(r"^NODE_API=([0-9]+)$", installer, re.MULTILINE)
        if node_api is None:
            self.fail("the node installer has no API level")
        self.assertEqual(int(node_api.group(1)), requirements.node_api)


class ADatabaseFromBeforeTheBaseline(unittest.TestCase):
    """B369: 0.99 is installed afresh; a 0.9 database is refused in so many words.

    An `apt upgrade` from 0.9.2 reaches this through update-platform-release's
    `check-compatibility --before-migration`, before anything is migrated.
    """

    def test_a_revision_before_the_baseline_is_refused_and_says_what_to_do(self) -> None:
        requirements = compatibility.load_requirements(MANIFEST)
        said = compatibility.before_baseline(requirements, "0091")
        if said is None:
            self.fail("a database at 0091 was not refused")
        self.assertIn("0091 is from before this release's baseline 0100", said)
        self.assertIn("installed afresh", said)
        self.assertIsNone(compatibility.before_baseline(requirements, "0100"))
        self.assertIsNone(
            compatibility.before_baseline(replace(requirements, database_baseline=None), "0091")
        )

    def test_a_baseline_past_the_head_is_refused(self) -> None:
        head = json.loads(MANIFEST.read_text())["requires"]["database_head"]
        for baseline in (f"{int(head) + 1:04d}", "x1"):
            with self.subTest(baseline=baseline), tempfile.TemporaryDirectory() as raw:
                path = Path(raw) / "compatibility.json"
                document = json.loads(MANIFEST.read_text())
                document["requires"]["database_baseline"] = baseline
                path.write_text(json.dumps(document))
                with self.assertRaisesRegex(compatibility.CompatibilityError, "database_baseline"):
                    compatibility.load_requirements(path)

    def test_the_check_fails_on_it_before_any_transition_is_weighed(self) -> None:
        requirements = compatibility.load_requirements(MANIFEST)
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            bin_dir = root / "cli/releases/r1/bin"
            bin_dir.mkdir(parents=True)
            helpers = (
                requirements.worker_helpers
                + requirements.poller_helpers
                + tuple(requirements.socket_helpers)
            )
            for helper in helpers:
                (bin_dir / helper).write_text("")
                (bin_dir / helper).chmod(0o755)
            (root / "ui/releases/new").mkdir(parents=True)
            with (
                mock.patch("os.geteuid", return_value=0),
                mock.patch.object(compatibility, "ui_requirements", return_value=requirements),
                mock.patch.object(compatibility, "current_release", return_value=bin_dir.parent),
                mock.patch.object(compatibility, "cli_metadata", return_value={}),
                mock.patch.object(compatibility, "engine_api", return_value=999),
                mock.patch.object(
                    compatibility, "installed_entry_points", return_value=set(helpers)
                ),
                mock.patch.object(compatibility, "database_revision", return_value="0091"),
                mock.patch.object(compatibility, "schema_upgrade_failures") as weighed,
                contextlib.redirect_stdout(io.StringIO()) as printed,
            ):
                code = compatibility.main(
                    [
                        "--platform-root", str(root / "ui"),
                        "--cli-root", str(root / "cli"),
                        "--database", "haprion",
                        "--database-role", "migrate",
                        "--clusters",
                        "--sudoers-root", str(root / "sudoers.d"),
                        "--systemd-root", str(root / "systemd"),
                        "--ui-release", "new",
                        "--upgrade-from-current",
                        "--skip-services",
                    ]
                )  # fmt: skip
        self.assertNotEqual(code, 0)
        self.assertIn("FAIL  schema revision", printed.getvalue())
        self.assertIn("from before this release's baseline 0100", printed.getvalue())
        weighed.assert_not_called()


class ReleasePackageTests(unittest.TestCase):
    """A release is read under whatever its distribution calls its package."""

    def release(self, root: Path, package: str) -> Path:
        site = root / "venv/lib/python3.12/site-packages"
        (site / package).mkdir(parents=True)
        (site / package / "compatibility.json").write_text(MANIFEST.read_text())
        info = site / "haprion_ui-0.1.0.dist-info"
        info.mkdir()
        (info / "entry_points.txt").write_text(
            f"[console_scripts]\nhaprion-poller = {package}.poller:_entry\n"
            f"haprion-worker = {package}.worker:_entry\n"
        )
        return root

    def test_the_package_comes_from_the_distribution(self) -> None:
        for package in ("haprion_ui", "earlier_ui"):
            with self.subTest(package=package), tempfile.TemporaryDirectory() as raw:
                release = self.release(Path(raw), package)
                requirements = compatibility.ui_requirements(release)
                self.assertEqual(requirements, compatibility.load_requirements(MANIFEST))

    def test_a_release_without_the_command_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            release = self.release(Path(raw), "haprion_ui")
            info = release / "venv/lib/python3.12/site-packages/haprion_ui-0.1.0.dist-info"
            (info / "entry_points.txt").write_text("[console_scripts]\n")
            with self.assertRaisesRegex(compatibility.CompatibilityError, "haprion-worker"):
                compatibility.ui_requirements(release)


class WorkerSandboxTests(unittest.TestCase):
    """The worker's unit opens what the runtime policy names (review 26-10-10, F4)."""

    POLICY = (
        "schema_version: 1\n"
        "cluster_file: /srv/example/registry/clusters.yaml\n"
        "config_root: /srv/example/config\n"
        "publish_root: /srv/example/published\n"
        "validation_certs_root: /srv/example/validation\n"
        "certificate_registry: /srv/example/registry/certificates.yaml\n"
    )

    def check(self, unit: str) -> compatibility.Report:
        report = compatibility.Report()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "policy.yaml").write_text(self.POLICY)
            (root / "worker.service").write_text(unit)
            compatibility.check_worker_sandbox(
                report,
                unit_file=root / "worker.service",
                policy_file=root / "policy.yaml",
                require_secure=False,
            )
        return report

    def test_a_unit_written_from_the_policy_passes(self) -> None:
        unit = (
            "ReadWritePaths=/run/haprion /srv/example/config /srv/example/published "
            "-/srv/example/validation /srv/example/registry /etc/letsencrypt\n"
        )
        self.assertEqual(self.check(unit).failures, 0)

    def test_a_moved_registry_the_unit_does_not_open_fails(self) -> None:
        unit = (
            "ReadWritePaths=/run/haprion /srv/example/config /srv/example/published "
            "/srv/example/validation /srv/old/registry\n"
        )
        self.assertEqual(self.check(unit).failures, 1)


class FirstInstallTests(unittest.TestCase):
    """--first-install leaves step 07's parts to the later check, and only then."""

    def args(self, root: Path, *extra: str) -> argparse.Namespace:
        return compatibility.parse_args(
            [
                "--platform-root",
                str(root),
                "--cli-root",
                "/opt/haprion",
                "--database",
                "haprion",
                "--database-role",
                "_haprion-migrate",
                "--clusters",
                *extra,
            ]
        )

    def test_before_the_first_activation_it_is_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            args = self.args(Path(raw), "--ui-release", "r1", "--first-install")
            self.assertIsNone(compatibility.first_install_error(args))

    def test_with_a_release_current_it_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "releases/r0").mkdir(parents=True)
            (root / "current").symlink_to(root / "releases/r0")
            error = compatibility.first_install_error(
                self.args(root, "--ui-release", "r1", "--first-install")
            )
        self.assertIn("no active release", error or "")

    def test_it_names_a_release_and_is_no_upgrade(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            for extra in (
                ("--first-install",),
                ("--ui-release", "r1", "--first-install", "--upgrade-from-current"),
            ):
                with self.subTest(extra=extra):
                    self.assertIsNotNone(
                        compatibility.first_install_error(self.args(Path(raw), *extra))
                    )

    def test_without_it_nothing_is_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            self.assertIsNone(compatibility.first_install_error(self.args(Path(raw))))


class PreparedReleaseTests(unittest.TestCase):
    def test_a_named_release_must_be_a_direct_child_of_releases(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            release = root / "releases/0.1.0-example"
            release.mkdir(parents=True)
            self.assertEqual(
                compatibility.named_release(root, "0.1.0-example", "UI"), release.resolve()
            )
            with self.assertRaises(compatibility.CompatibilityError):
                compatibility.named_release(root, "../elsewhere", "UI")

    def test_a_symlink_cannot_make_a_named_release_escape(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            outside = root / "outside"
            outside.mkdir()
            releases = root / "releases"
            releases.mkdir()
            (releases / "candidate").symlink_to(outside)
            with self.assertRaises(compatibility.CompatibilityError):
                compatibility.named_release(root, "candidate", "UI")


class RollbackSchemaCommandTests(unittest.TestCase):
    """`python -m haprion_ui.rollback_schema`, as `haprion-rollback` asks it (26-10-20)."""

    def release(self, root: Path, name: str, head: str, safe_from: str) -> None:
        document = json.loads(MANIFEST.read_text())
        revisions = document["requires"]["database_revisions"]
        # Releases with these numbers came before the baseline and named none.
        document["requires"].pop("database_baseline")
        document["requires"].update(
            database_head=head,
            rollback_safe_from=safe_from,
            database_revisions=revisions[: revisions.index(head) + 1]
            if head in revisions
            else [*revisions, head],
        )
        site = root / "releases" / name / "venv/lib/python3.12/site-packages"
        (site / "haprion_ui").mkdir(parents=True)
        (site / "haprion_ui" / "compatibility.json").write_text(json.dumps(document))
        info = site / "haprion_ui-0.1.0.dist-info"
        info.mkdir()
        (info / "entry_points.txt").write_text(
            "[console_scripts]\nhaprion-worker = haprion_ui.worker:_entry\n"
        )

    def ask(self, root: Path, target: str, revision: str, packaged: str = "new") -> tuple[int, str]:
        from haprion_ui import rollback_schema

        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = rollback_schema.main(
                [
                    "--platform-root",
                    str(root),
                    "--target",
                    target,
                    "--revision",
                    revision,
                    "--packaged",
                    packaged,
                ]
            )
        return code, out.getvalue() + err.getvalue()

    def test_the_carrier_on_disk_decides_and_a_target_below_its_floor_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            self.release(root, "new", "9999", "0072")
            self.release(root, "prod", "0078", "0064")
            self.release(root, "old", "0071", "0064")
            (root / "releases" / "broken").mkdir()
            self.assertEqual(self.ask(root, "prod", "9999")[0], 0)
            code, said = self.ask(root, "old", "9999")
            self.assertEqual(code, 1)
            self.assertIn("safe for a UI from 0072 on", said)
            self.assertEqual(self.ask(root, "broken", "9999")[0], 1)
            self.assertEqual(self.ask(root, "../new", "9999")[0], 1)

    def test_the_installed_release_s_declaration_outweighs_an_older_carrier_s(self) -> None:
        """26-10-28: 0.99.3 declared 0101 unsafe, 0.99.4 corrected it to safe from 0100.

        Both on disk, the rollback to 0.99.2 was refused on 0.99.3's word: the
        first carrier by name decided. The release the package installed knows
        the newest migrations; without it carrying the schema, the newest
        version does - by number, so 0.99.10 is after 0.99.9.
        """

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            self.release(root, "0.99.2-aaaa", "0072", "0064")
            self.release(root, "0.99.3-bbbb", "0078", "0078")
            self.release(root, "0.99.4-cccc", "0078", "0072")
            self.assertEqual(self.ask(root, "0.99.2-aaaa", "0078", "0.99.4-cccc")[0], 0)
            self.assertEqual(self.ask(root, "0.99.2-aaaa", "0078", "0.99.2-aaaa")[0], 0)
            code, said = self.ask(root, "0.99.2-aaaa", "0078", "0.99.3-bbbb")
            self.assertEqual(code, 1)
            self.assertIn("safe for a UI from 0078 on", said)

            self.release(root, "0.99.9-dddd", "0079", "0079")
            self.release(root, "0.99.10-eeee", "0079", "0078")
            self.assertEqual(self.ask(root, "0.99.4-cccc", "0079", "0.99.2-aaaa")[0], 0)


class UpgradeFailureTests(unittest.TestCase):
    def requirements(self, *, head: str, accepts: tuple[str, ...]) -> compatibility.Requirements:
        return compatibility.Requirements(
            engine_api=2,
            node_api=2,
            database_head=head,
            database_revisions=accepts,
            worker_helpers=("worker-helper",),
            poller_helpers=("poller-helper",),
            socket_helpers={},
        )

    def test_a_new_schema_needs_a_bridge_release_before_it_can_be_migrated(self) -> None:
        active = self.requirements(head="0020", accepts=("0020",))
        candidate = self.requirements(head="0021", accepts=("0021",))
        self.assertEqual(
            compatibility.schema_upgrade_failures(active, candidate, "0020"),
            ("running UI does not accept candidate head 0021",),
        )

    def test_migrations_declared_rollback_safe_need_no_bridge(self) -> None:
        """B262: the candidate's migrations say a UI from their base keeps working."""

        running = self.requirements(head="0064", accepts=("0063", "0064"))
        candidate = replace(
            self.requirements(head="0066", accepts=("0064", "0065", "0066")),
            rollback_safe_from="0064",
        )
        self.assertEqual(compatibility.schema_upgrade_failures(running, candidate, "0064"), ())

        older = self.requirements(head="0063", accepts=("0063",))
        self.assertEqual(
            compatibility.schema_upgrade_failures(older, candidate, "0063"),
            ("running UI does not accept candidate head 0066",),
        )
        undeclared = replace(candidate, rollback_safe_from=None)
        self.assertEqual(
            compatibility.schema_upgrade_failures(running, undeclared, "0064"),
            ("running UI does not accept candidate head 0066",),
        )

    def test_a_rollback_runs_on_a_schema_its_carrier_declares_safe_for_it(self) -> None:
        """26-10-20: `haprion-rollback` asks before the web starts on a newer schema."""

        carrier = replace(
            self.requirements(head="0079", accepts=("0072", "0078", "0079")),
            rollback_safe_from="0072",
        )
        at_0078 = self.requirements(head="0078", accepts=("0072", "0078"))
        at_0071 = self.requirements(head="0071", accepts=("0064", "0071"))
        problem = compatibility.rollback_schema_problem
        self.assertIsNone(problem(at_0078, [at_0071, carrier], "0079"))
        self.assertIsNone(problem(at_0078, [], "0078"))
        refused = problem(at_0071, [at_0078, carrier], "0079")
        self.assertEqual(
            refused, "schema 0079 is safe for a UI from 0072 on; the target stands at 0071"
        )

    def test_a_rollback_without_a_carrier_or_onto_an_older_schema_is_refused(self) -> None:
        at_0078 = self.requirements(head="0078", accepts=("0072", "0078"))
        undeclared = self.requirements(head="0079", accepts=("0079",))
        problem = compatibility.rollback_schema_problem
        self.assertIn("no release on this machine", problem(at_0078, [], "0079") or "")
        self.assertIn("no release on this machine", problem(at_0078, [undeclared], "0079") or "")
        self.assertIn("older than every", problem(at_0078, [], "0070") or "")

    def test_a_bridge_release_makes_both_live_migration_and_rollback_safe(self) -> None:
        bridge = self.requirements(head="0020", accepts=("0020", "0021"))
        candidate = self.requirements(head="0021", accepts=("0021",))
        self.assertEqual(compatibility.schema_upgrade_failures(bridge, candidate, "0020"), ())

    def test_an_old_or_unreadable_cli_is_not_silently_current(self) -> None:
        self.assertEqual(compatibility.engine_api({"engine_api": 1}), 1)
        self.assertEqual(compatibility.engine_api({"engine_api": "2"}), 0)

    def test_a_missing_helper_is_visible_before_activation(self) -> None:
        installed = compatibility.installed_entry_points(
            {"entry_points": ["worker-helper", "poller-helper"]}
        )
        self.assertEqual({"new-helper"} - installed, {"new-helper"})


class SudoRuleTests(unittest.TestCase):
    def test_comments_and_spacing_do_not_become_compatibility(self) -> None:
        text = """\
# explanation

svc-app   ALL=(root)   NOPASSWD: /opt/example ""
"""
        self.assertEqual(
            compatibility.active_sudo_rules(text),
            ('svc-app ALL=(root) NOPASSWD: /opt/example ""',),
        )


class NodeCompatibilityTests(unittest.TestCase):
    def test_a_current_bundle_at_the_required_api_is_usable(self) -> None:
        name, api, current = compatibility._node_installation(
            {
                "name": "node-a",
                "status": {"installation": {"node_api": 1, "scripts_current": True, "scripts": {}}},
            }
        )
        self.assertEqual((name, api, current), ("node-a", 1, True))

    def test_an_old_node_is_unknown_not_silently_api_zero(self) -> None:
        self.assertEqual(
            compatibility._node_installation({"name": "node-a", "status": {}}),
            ("node-a", None, False),
        )

    def test_a_changed_script_invalidates_an_otherwise_new_bundle(self) -> None:
        self.assertEqual(
            compatibility._node_installation(
                {
                    "name": "node-a",
                    "status": {
                        "installation": {
                            "node_api": 2,
                            "scripts_current": False,
                            "scripts": {},
                        }
                    },
                }
            ),
            ("node-a", 2, False),
        )


class TrafficCollectorInventoryTests(unittest.TestCase):
    def test_the_collector_must_name_exactly_the_runtime_nodes_and_hosts(self) -> None:
        expected = (
            ("alpha", "node-a", "node-a.example.com"),
            ("alpha", "node-b", "node-b.example.com"),
        )
        actual = (
            ("alpha", "node-a", "replacement.example.com"),
            ("beta", "node-c", "node-c.example.com"),
        )

        self.assertEqual(
            compatibility._inventory_differences(expected, actual),
            (("alpha/node-b",), ("beta/node-c",), ("alpha/node-a",)),
        )

    def test_order_does_not_create_false_inventory_drift(self) -> None:
        expected = (
            ("alpha", "node-a", "node-a.example.com"),
            ("alpha", "node-b", "node-b.example.com"),
        )
        self.assertEqual(
            compatibility._inventory_differences(expected, reversed(expected)),
            ((), (), ()),
        )


class FrozenSchemaTests(unittest.TestCase):
    def test_a_node_behind_the_release_s_node_package_is_said_and_not_failed(self) -> None:
        """B335: the node's own record says current; the release's package says otherwise."""

        def entry(digest: str) -> dict[str, object]:
            return {
                "name": "node-a",
                "status": {
                    "installation": {
                        "node_api": 1,
                        "scripts_current": True,
                        "scripts": {"haprion-node-status": {"installed_sha256": digest}},
                    }
                },
            }

        expected = {"haprion-node-status": "a" * 64}
        self.assertEqual(
            compatibility._scripts_behind(entry("b" * 64), expected), ["haprion-node-status"]
        )
        self.assertEqual(compatibility._scripts_behind(entry("a" * 64), expected), [])
        report = compatibility.Report()
        answer = json.dumps({"result": {"nodes": [entry("b" * 64)]}})
        with (
            mock.patch.object(
                compatibility, "_command", return_value=SimpleNamespace(stdout=answer)
            ),
            contextlib.redirect_stdout(io.StringIO()) as printed,
        ):
            compatibility.check_cluster_nodes(
                report,
                cluster="alpha",
                helper=Path("/x"),
                required_api=1,
                expected_scripts=expected,
            )
        self.assertEqual(report.failures, 0)
        self.assertIn("WARN  node/alpha/node-a", printed.getvalue())
        self.assertIn("not this release's node package: haprion-node-status", printed.getvalue())

    def nodes_checked(self, *entries: dict[str, object]) -> tuple[int, str]:
        report = compatibility.Report()
        answer = json.dumps({"result": {"nodes": list(entries)}})
        with (
            mock.patch.object(
                compatibility, "_command", return_value=SimpleNamespace(stdout=answer)
            ),
            contextlib.redirect_stdout(io.StringIO()) as printed,
        ):
            compatibility.check_cluster_nodes(
                report, cluster="alpha", helper=Path("/x"), required_api=1
            )
        return report.failures, printed.getvalue()

    def test_a_node_that_does_not_answer_is_said_and_not_failed(self) -> None:
        """Review 2026-10-22, 6-2: a dead node stopped the update that was to help restore it."""

        failures, printed = self.nodes_checked(
            {"name": "node-a", "reachable": False, "status": None, "error": {}},
            {
                "name": "node-b",
                "reachable": True,
                "status": {"installation": {"node_api": 1, "scripts_current": True}},
            },
        )
        self.assertEqual(failures, 0)
        self.assertIn("WARN  node/alpha/node-a", printed)
        self.assertIn("did not answer", printed)
        self.assertIn("PASS  node/alpha/node-b", printed)

    def test_a_node_that_answers_without_its_metadata_still_fails(self) -> None:
        failures, printed = self.nodes_checked({"name": "node-a", "reachable": True, "status": {}})
        self.assertEqual(failures, 1)
        self.assertIn("does not report node compatibility metadata", printed)

    def test_node_installation_metadata_is_documented_in_the_status_contract(self) -> None:
        schema = json.loads((ROOT / "schemas/v1/haprion-status.schema.json").read_text())
        installation = schema["$defs"]["node_status"]["properties"]["installation"]
        self.assertEqual(installation["required"], ["node_api", "scripts_current", "scripts"])


if __name__ == "__main__":
    unittest.main()


class TheDeclaredHeadIsTheOneOnDisk(unittest.TestCase):
    """What the release says it needs, against what its migrations would apply.

    These are two files and one fact. `migrate --release` runs the bundle's own
    alembic head, and `check-compatibility` gates on the head declared in
    `compatibility.json`; nothing has held them equal. A release whose
    declaration lags its migrations migrates further than the running UI was
    asked to accept, and one whose declaration runs ahead is refused for a
    revision it does not carry - which is the shape of the bridge incident of
    2026-09-07 (B109) rather than a hypothetical.
    """

    VERSIONS = Path(__file__).resolve().parents[1] / "migrations" / "versions"
    DECLARED = Path(__file__).resolve().parents[1] / "src" / "haprion_ui" / "compatibility.json"

    def revisions(self) -> dict[str, str | None]:
        found: dict[str, str | None] = {}
        for path in self.VERSIONS.glob("[0-9]*.py"):
            text = path.read_text()
            revision = re.search(r'^revision = "([^"]+)"', text, re.MULTILINE)
            down = re.search(r'^down_revision = (?:"([^"]+)"|None)', text, re.MULTILINE)
            if revision is None:
                self.fail(f"{path.name} declares no revision")
            found[revision.group(1)] = down.group(1) if down and down.group(1) else None
        return found

    def head(self) -> str:
        found = self.revisions()
        parents = {down for down in found.values() if down is not None}
        heads = sorted(set(found) - parents)
        self.assertEqual(len(heads), 1, f"expected one head, found {heads}")
        return heads[0]

    #
    # The last migration written before migrations declared their own rollback
    # safety (B262). Every later one says whether a UI from before it keeps
    # working over it, and why.
    #
    UNDECLARED_UNTIL = "0064"

    def declarations(self) -> dict[str, bool]:
        found: dict[str, bool] = {}
        for path in self.VERSIONS.glob("[0-9]*.py"):
            text = path.read_text()
            revision = re.search(r'^revision = "([^"]+)"', text, re.MULTILINE)
            if revision is None or revision.group(1) <= self.UNDECLARED_UNTIL:
                continue
            safe = re.search(r"^ROLLBACK_SAFE = (True|False)$", text, re.MULTILINE)
            because = re.search(
                r'^ROLLBACK_SAFE_BECAUSE = \(?\s*"([^"]+)"', text, re.MULTILINE | re.DOTALL
            )
            with self.subTest(migration=path.name):
                self.assertIsNotNone(safe, "declares no ROLLBACK_SAFE = True or False")
                self.assertIsNotNone(because, "says no ROLLBACK_SAFE_BECAUSE")
            if safe is not None:
                found[revision.group(1)] = safe.group(1) == "True"
        return found

    def floors(self) -> dict[str, str]:
        """The oldest UI head a safe migration is safe for, where it is not every one.

        `ROLLBACK_SAFE_FROM` beside `ROLLBACK_SAFE = True` (0079, 26-10-20): the
        migration takes away what only a UI older than the floor still reads.
        """

        found: dict[str, str] = {}
        for path in self.VERSIONS.glob("[0-9]*.py"):
            text = path.read_text()
            revision = re.search(r'^revision = "([^"]+)"', text, re.MULTILINE)
            floor = re.search(r'^ROLLBACK_SAFE_FROM = "(\d+)"$', text, re.MULTILINE)
            if revision is None or floor is None:
                continue
            with self.subTest(migration=path.name):
                self.assertRegex(text, r"(?m)^ROLLBACK_SAFE = True$", "a floor on an unsafe one")
                self.assertLess(floor.group(1), revision.group(1), "a floor at or past itself")
            found[revision.group(1)] = floor.group(1)
        return found

    def test_every_new_migration_declares_whether_a_rollback_over_it_is_safe(self) -> None:
        self.declarations()

    def test_rollback_safe_from_is_what_the_migrations_declare(self) -> None:
        """Back from the head while each migration says it only adds (B262)."""

        found, declared = self.revisions(), self.declarations()
        safe_from = self.head()
        while declared.get(safe_from) is True and found[safe_from] is not None:
            safe_from = str(found[safe_from])
        # A floor among them raises it: a UI below the floor fails over that one.
        safe_from = max(
            [safe_from]
            + [floor for revision, floor in self.floors().items() if revision > safe_from]
        )

        self.assertEqual(self.declared().get("rollback_safe_from"), safe_from)

    def declared(self) -> dict[str, object]:
        requires: dict[str, object] = json.loads(self.DECLARED.read_text())["requires"]
        return requires

    def test_the_declared_baseline_is_where_the_migrations_begin(self) -> None:
        roots = [revision for revision, down in self.revisions().items() if down is None]
        self.assertEqual(roots, [self.declared()["database_baseline"]])

    def test_the_declaration_names_the_head_the_migrations_reach(self) -> None:
        self.assertEqual(self.declared()["database_head"], self.head())

    def test_the_head_is_among_the_revisions_the_release_accepts(self) -> None:
        """`load_requirements` refuses otherwise; this says it about the real file."""

        revisions = self.declared()["database_revisions"]

        if not isinstance(revisions, list):
            raise AssertionError(f"database_revisions is not a list: {revisions!r}")
        self.assertIn(self.declared()["database_head"], revisions)

    def test_the_revisions_accepted_are_the_chain_from_the_floor_to_the_head(self) -> None:
        found = self.revisions()
        accepted = self.declared()["database_revisions"]
        if not isinstance(accepted, list):
            raise AssertionError(f"database_revisions is not a list: {accepted!r}")
        chain = [self.head()]
        while chain[-1] != accepted[0] and found.get(chain[-1]) is not None:
            chain.append(str(found[chain[-1]]))
        self.assertEqual(accepted, chain[::-1])

    #
    # What a migration's upgrade brings that code can name: a table, a view, a
    # function, a column, or a new name for one of them.
    #
    CODE = Path(__file__).resolve().parents[1] / "src" / "haprion_ui"
    CREATES = re.compile(
        r"\b(?:create table(?: if not exists)?|create (?:or replace )?(?:function|view)"
        r"|add column(?: if not exists)?|rename (?:column \w+ )?to)\s+(\w+)",
        re.IGNORECASE,
    )

    def introduced(self) -> dict[str, str]:
        """Each name a migration's upgrade creates, and the first revision that does.

        Read from every string in the module but its docstring and its
        `downgrade`, because an upgrade often runs a module-level statement.
        """

        found: dict[str, str] = {}
        for path in sorted(self.VERSIONS.glob("[0-9]*.py")):
            tree = ast.parse(path.read_text())
            skipped = {id(node) for node in ast.walk(tree.body[0])}
            for statement in tree.body:
                if isinstance(statement, ast.FunctionDef) and statement.name == "downgrade":
                    skipped |= {id(inner) for inner in ast.walk(statement)}
            revision = path.name.split("_", 1)[0]
            for node in ast.walk(tree):
                if id(node) in skipped or not isinstance(node, ast.Constant):
                    continue
                if isinstance(node.value, str):
                    for name in self.CREATES.findall(node.value):
                        found.setdefault(name.lower(), revision)
        return found

    def test_the_code_names_nothing_newer_than_the_oldest_schema_it_accepts(self) -> None:
        """Review 2026-10-22, 6-3: the release accepted 0028 while it read `held_since` from 0082.

        `/healthz` and `check-compatibility` then called a schema healthy that
        the first job would fail on - a dump from before a migration, read back
        under the newer release, for one. A grant is not a name and is not seen
        here; the floor moves to the newest migration whose grant the code needs.
        """

        accepted = self.declared()["database_revisions"]
        if not isinstance(accepted, list):
            raise AssertionError(f"database_revisions is not a list: {accepted!r}")
        floor = accepted[0]
        newer = {name: revision for name, revision in self.introduced().items() if revision > floor}
        self.assertTrue(self.introduced(), "no migration was read")
        code = "\n".join(path.read_text() for path in sorted(self.CODE.rglob("*.py")))
        named = sorted(
            f"{name} ({revision})"
            for name, revision in newer.items()
            if re.search(rf"\b{name}\b", code, re.IGNORECASE)
        )
        self.assertEqual(named, [], f"the code needs more than the floor {floor} holds")

    def test_every_revision_has_exactly_one_child_or_is_the_head(self) -> None:
        """A fork would make "the head" ambiguous and the release unbuildable."""

        found = self.revisions()
        parents = [down for down in found.values() if down is not None]

        self.assertEqual(len(parents), len(set(parents)), "two migrations share a parent")
