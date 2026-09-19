from __future__ import annotations

import json
import re
import tempfile
import unittest
from pathlib import Path

from haproxy_mgmt.cli import cert_receiver_ask, cert_receiver_helper

from haproxy_ui import compatibility

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "ui/src/haproxy_ui/compatibility.json"


class CompatibilityMetadataTests(unittest.TestCase):
    def test_the_running_ui_names_every_helper_its_services_need(self) -> None:
        requirements = compatibility.load_requirements(MANIFEST)
        worker = (ROOT / "install/platform/examples/haproxy-ui-worker.sudoers.example").read_text()
        poller = (ROOT / "install/platform/examples/haproxy-ui-poller.sudoers.example").read_text()

        self.assertEqual(
            compatibility.active_sudo_rules(worker.replace("WORKER_USER", "svc-app")),
            compatibility.expected_sudo_rules(
                "svc-app", requirements.worker_helpers, Path("/opt/haproxy-mgmt")
            ),
        )
        self.assertEqual(
            compatibility.active_sudo_rules(poller.replace("POLLER_USER", "svc-app")),
            compatibility.expected_sudo_rules(
                "svc-app", requirements.poller_helpers, Path("/opt/haproxy-mgmt")
            ),
        )

    def test_the_receiver_helper_is_a_socket_helper_and_the_paths_agree(self) -> None:
        """B163: the manifest, the client and the socket unit name one socket."""

        requirements = compatibility.load_requirements(MANIFEST)
        helper = Path(cert_receiver_helper.HELPER).name
        unit = (
            ROOT / "install/platform/examples/haproxy-cert-receiver-helper.socket.example"
        ).read_text()

        self.assertNotIn(helper, requirements.worker_helpers)
        self.assertEqual(requirements.socket_helpers, {helper: cert_receiver_ask.SOCKET_PATH})
        self.assertIn(f"ListenStream={cert_receiver_ask.SOCKET_PATH}\n", unit)
        self.assertIn("SocketGroup=WORKER_USER", unit)

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

    def test_a_legacy_single_revision_can_be_read_only_for_the_bridge_check(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "compatibility.json"
            document = json.loads(MANIFEST.read_text())
            document["requires"].pop("database_head")
            document["requires"]["database_revisions"] = ["0020"]
            path.write_text(json.dumps(document))

            with self.assertRaisesRegex(compatibility.CompatibilityError, "database_head"):
                compatibility.load_requirements(path)
            requirements = compatibility.load_requirements(path, allow_legacy_database_head=True)
            self.assertEqual(requirements.database_head, "0020")

    def test_legacy_metadata_with_multiple_revisions_is_ambiguous(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "compatibility.json"
            document = json.loads(MANIFEST.read_text())
            document["requires"].pop("database_head")
            document["requires"]["database_revisions"] = ["0020", "0021"]
            path.write_text(json.dumps(document))

            with self.assertRaisesRegex(compatibility.CompatibilityError, "database_head"):
                compatibility.load_requirements(path, allow_legacy_database_head=True)

    def test_requirements_match_this_deliverys_engine_schema_and_node_installer(self) -> None:
        requirements = compatibility.load_requirements(MANIFEST)
        engine = json.loads((ROOT / "src/haproxy_mgmt/compatibility.json").read_text())
        self.assertGreaterEqual(engine["engine_api"], requirements.engine_api)

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

        installer = (ROOT / "install/04-node-prepare").read_text()
        node_api = re.search(r"^NODE_API=([0-9]+)$", installer, re.MULTILINE)
        if node_api is None:
            self.fail("the node installer has no API level")
        self.assertEqual(int(node_api.group(1)), requirements.node_api)


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

    def test_a_bridge_release_makes_both_live_migration_and_rollback_safe(self) -> None:
        bridge = self.requirements(head="0020", accepts=("0020", "0021"))
        candidate = self.requirements(head="0021", accepts=("0021",))
        self.assertEqual(compatibility.schema_upgrade_failures(bridge, candidate, "0020"), ())

    def test_metadata_free_release_can_bridge_only_without_a_schema_change(self) -> None:
        unchanged = self.requirements(head="0020", accepts=("0020", "0021"))
        migrating = self.requirements(head="0021", accepts=("0021",))

        self.assertEqual(compatibility.schema_upgrade_failures(None, unchanged, "0020"), ())
        self.assertEqual(
            compatibility.schema_upgrade_failures(None, migrating, "0020"),
            ("running UI has no compatibility metadata for a schema change",),
        )

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
    def test_node_installation_metadata_is_documented_in_the_status_contract(self) -> None:
        schema = json.loads((ROOT / "schemas/v1/haproxy-status.schema.json").read_text())
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
    DECLARED = Path(__file__).resolve().parents[1] / "src" / "haproxy_ui" / "compatibility.json"

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

    def declared(self) -> dict[str, object]:
        return json.loads(self.DECLARED.read_text())["requires"]

    def test_the_declaration_names_the_head_the_migrations_reach(self) -> None:
        self.assertEqual(self.declared()["database_head"], self.head())

    def test_the_head_is_among_the_revisions_the_release_accepts(self) -> None:
        """`load_requirements` refuses otherwise; this says it about the real file."""

        self.assertIn(self.declared()["database_head"], self.declared()["database_revisions"])

    def test_every_revision_has_exactly_one_child_or_is_the_head(self) -> None:
        """A fork would make "the head" ambiguous and the release unbuildable."""

        found = self.revisions()
        parents = [down for down in found.values() if down is not None]

        self.assertEqual(len(parents), len(set(parents)), "two migrations share a parent")
