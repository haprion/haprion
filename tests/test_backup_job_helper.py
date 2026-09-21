from __future__ import annotations

import io
import json
import unittest
from pathlib import Path
from unittest import mock
from uuid import uuid4

from haproxy_mgmt import backup_schedule_write
from haproxy_mgmt.cli import backup_job_helper
from haproxy_mgmt.config import DeployIdentity
from haproxy_mgmt.state_backup import BackupResult, NodeResult


class BackupJobHelperTests(unittest.TestCase):
    class Policy:
        backup_identity = DeployIdentity("svc-backup", Path("/root/key"))
        backup_root = Path("/srv/backups")

    class Runtime:
        @staticmethod
        def cluster(cluster_id: str):
            return type("Cluster", (), {"cluster_id": cluster_id})()

    def execute(self, request: str) -> tuple[dict, int]:
        output, errors = io.StringIO(), io.StringIO()
        with (
            mock.patch.object(backup_job_helper, "load_policy", return_value=self.Policy()),
            mock.patch.object(
                backup_job_helper, "load_runtime_config", return_value=self.Runtime()
            ),
        ):
            code = backup_job_helper.main(
                [],
                input_stream=io.BytesIO(request.encode()),
                output_stream=output,
                error_stream=errors,
                require_root=False,
            )
        return (json.loads(output.getvalue()) if output.getvalue() else {}), code

    def test_backup_run_returns_each_nodes_result(self) -> None:
        request_id = str(uuid4())
        report = BackupResult(
            "alpha",
            "2026-09-21_05-00-00",
            (
                NodeResult("node-a", "done", "2026-09-21_05-00-00", 4096, None),
                NodeResult("node-b", "done", "2026-09-21_05-00-00", 4096, None),
            ),
        )
        with mock.patch.object(backup_job_helper.state_backup, "run", return_value=report):
            document, code = self.execute(backup_job_helper.build_run_request("alpha", request_id))

        self.assertEqual(code, 0)
        self.assertEqual(document["operation"], "backup_run")
        self.assertEqual(document["outcome"], "done")
        self.assertEqual(len(document["result"]["nodes"]), 2)

    def test_schedule_change_uses_only_the_bounded_time_and_switch(self) -> None:
        request_id = str(uuid4())
        result = backup_schedule_write.Result(
            "alpha",
            "04:30",
            True,
            {
                "unit": "haproxy-state-backup@alpha.timer",
                "known": True,
                "enabled": True,
                "active": True,
                "calendar": "*-*-* 04:30:00 UTC",
            },
        )
        with mock.patch.object(
            backup_job_helper.backup_schedule_write, "apply", return_value=result
        ):
            document, code = self.execute(
                backup_job_helper.build_schedule_request(
                    "alpha", request_id, time="04:30", enabled=True
                )
            )

        self.assertEqual(code, 0)
        self.assertEqual(document["operation"], "backup_schedule")
        self.assertEqual(document["result"]["time"], "04:30")

    def test_unknown_fields_and_free_form_calendars_are_refused_before_work(self) -> None:
        document = json.loads(
            backup_job_helper.build_schedule_request(
                "alpha", str(uuid4()), time="04:30", enabled=True
            )
        )
        document["parameters"] = {"time": "daily; reboot", "enabled": True, "unit": "x.timer"}
        output, code = self.execute(json.dumps(document))
        self.assertEqual(code, 65)
        self.assertEqual(output, {})


if __name__ == "__main__":
    unittest.main()
