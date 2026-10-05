from __future__ import annotations

import io
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from haproxy_mgmt.cli import state_backup
from haproxy_mgmt.config import Cluster, DeployIdentity
from haproxy_mgmt.state_backup import BackupResult, NodeResult


class StateBackupCommandTests(unittest.TestCase):
    def test_one_cluster_is_selected_inside_the_loaded_configuration(self) -> None:
        seen: list[str] = []
        selected_cluster = object()

        class Policy:
            backup_identity = DeployIdentity("svc-backup", Path("/root/key"))
            backup_root = Path("/srv/backups")

        class Runtime:
            clusters = {"alpha": selected_cluster, "beta": object()}

            @staticmethod
            def cluster(cluster_id: str) -> Any:
                if cluster_id != "alpha":
                    raise AssertionError("unexpected cluster")
                return selected_cluster

        def runner(
            cluster_id: str,
            selected: Cluster,
            identity: DeployIdentity | None,
            root: Path | None,
            retention: int,
        ) -> BackupResult:
            self.assertIs(selected, selected_cluster)
            self.assertEqual(identity, Policy.backup_identity)
            self.assertEqual(root, Policy.backup_root)
            # The count the Backups page set, read from the same file the
            # socket helper reads - not the code's default.
            self.assertEqual(retention, 40)
            seen.append(cluster_id)
            return BackupResult(
                cluster_id,
                "2026-09-21_05-00-00",
                (NodeResult("node-a", "done", "2026-09-21_05-00-00", 4096, None),),
            )

        output = io.StringIO()
        with (
            mock.patch.object(state_backup, "load_policy", return_value=Policy()),
            mock.patch.object(state_backup, "load_runtime_config", return_value=Runtime()),
            mock.patch.object(state_backup, "read_retention", return_value=40),
        ):
            code = state_backup.main(
                ["-c", "alpha"], output_stream=output, require_root=False, runner=runner
            )

        self.assertEqual(code, 0)
        self.assertEqual(seen, ["alpha"])
        self.assertIn("node-a: 2026-09-21_05-00-00.tar.gz", output.getvalue())

    def test_no_cluster_keeps_the_break_glass_all_clusters_command(self) -> None:
        seen: list[str] = []

        class Policy:
            backup_identity = DeployIdentity("svc-backup", Path("/root/key"))
            backup_root = Path("/srv/backups")

        class Runtime:
            clusters = {"alpha": object(), "beta": object()}

        def runner(
            cluster_id: str,
            cluster: Cluster,
            identity: DeployIdentity | None,
            root: Path | None,
            retention: int,
        ) -> BackupResult:
            del cluster, identity, root, retention
            seen.append(cluster_id)
            return BackupResult(cluster_id, "stamp", ())

        with (
            mock.patch.object(state_backup, "load_policy", return_value=Policy()),
            mock.patch.object(state_backup, "load_runtime_config", return_value=Runtime()),
            mock.patch.object(state_backup, "read_retention", return_value=14),
        ):
            code = state_backup.main(
                [], output_stream=io.StringIO(), require_root=False, runner=runner
            )

        self.assertEqual(code, 0)
        self.assertEqual(seen, ["alpha", "beta"])

    def test_a_partial_node_run_is_a_failed_service_run(self) -> None:
        class Policy:
            backup_identity = DeployIdentity("svc-backup", Path("/root/key"))
            backup_root = Path("/srv/backups")

        class Runtime:
            clusters = {"alpha": object()}

            @staticmethod
            def cluster(cluster_id: str) -> Any:
                return Runtime.clusters[cluster_id]

        result = BackupResult(
            "alpha",
            "stamp",
            (
                NodeResult("node-a", "done", "stamp", 4096, None),
                NodeResult("node-b", "failed", None, None, "node_export_failed"),
            ),
        )
        with (
            mock.patch.object(state_backup, "load_policy", return_value=Policy()),
            mock.patch.object(state_backup, "load_runtime_config", return_value=Runtime()),
            mock.patch.object(state_backup, "read_retention", return_value=14),
        ):
            code = state_backup.main(
                ["-c", "alpha"],
                output_stream=io.StringIO(),
                require_root=False,
                runner=lambda *args: result,
            )

        self.assertEqual(code, 1)

    def test_arbitrary_arguments_are_refused(self) -> None:
        errors = io.StringIO()
        code = state_backup.main(["alpha"], error_stream=errors, require_root=False)
        self.assertEqual(code, state_backup.EXIT_USAGE)
        self.assertEqual(errors.getvalue(), state_backup.USAGE)


if __name__ == "__main__":
    unittest.main()
