"""The cluster's settings cross the same boundary as every other write (Fas 15).

Published since B257 by the helper that publishes saved changes, as the part
of a package that carries only settings. Held here: a settings publish is a
version of its own, stored canonically,
generated into `1000-cluster.cfg`; it needs the network description the
generated layer is built around; a target given as a name is refused before
anything is written; a later network publish keeps the settings; the read
helper reports them with the head a change must name; and the terminal
command sets them through the same helper.
"""

from __future__ import annotations

import grp
import io
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from haprion.candidate_validation import ValidationResult
from haprion.cli import changes_publish, cluster_settings_helper
from haprion.cli import cluster_settings as command
from haprion.cluster_settings import LOCATION
from haprion.version_history import count_versions, request_id_of
from tests.contract_schema import assert_contract
from tests.test_changes_publish_network import NetworkPublishFixture
from tests.test_publish_helper import Recorder, git

REQUEST_ID = "66666666-6666-4666-8666-666666666666"
SETTINGS = """log_targets:
  graylog: {address: 192.0.2.20, port: 6514}
metrics: {port: 8405, sources: [192.0.2.0/24]}
"""
CANONICAL = """log_targets:
  graylog:
    address: 192.0.2.20
    port: 6514
    disk_mib: 1024
    tls: false
metrics:
  port: 8405
  sources:
  - 192.0.2.0/24
"""


class SettingsPublishFixture(NetworkPublishFixture):
    def settings_request(self, settings: str = SETTINGS) -> io.BytesIO:
        return io.BytesIO(
            changes_publish.build_request(
                "alpha",
                REQUEST_ID,
                settings=settings,
                expected_head=git(self.repo, "rev-parse", "HEAD"),
                comment="Send the traffic log to graylog",
            ).encode()
        )

    def publish_settings(self, policy_path: Path, request: io.BytesIO) -> tuple[int, Any, str]:
        out, err = io.StringIO(), io.StringIO()
        self.recorder = Recorder()
        code = changes_publish.main(
            [],
            policy_path=policy_path,
            run_root=self.run_root,
            lock_root=self.lock_root,
            input_stream=request,
            output_stream=out,
            error_stream=err,
            require_secure=False,
            require_root=False,
            validator=lambda _candidate, _request_id: ValidationResult(valid=True, diagnostics=""),
            group=grp.getgrgid(os.getgid()).gr_name,
            change_owner=self.recorder,
        )
        return code, json.loads(out.getvalue()), err.getvalue()


class SettingsPublicationTests(SettingsPublishFixture):
    def test_a_publish_is_a_version_stored_canonically_and_generated(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.assertEqual(self.publish_network(policy, self.request())[0], 0)

            code, document, err = self.publish_settings(policy, self.settings_request())

            self.assertEqual((code, err), (0, ""))
            assert_contract("haprion-changes-publish", json.dumps(document))
            self.assertTrue(document["result"]["changed"])
            self.assertEqual((self.repo / LOCATION).read_text(), CANONICAL)
            files = git(self.repo, "ls-files")
            self.assertIn("managed/generated/1000-cluster.cfg", files)
            self.assertIn(
                'target="192.0.2.20"', (self.repo / "managed/rsyslog/forward.conf").read_text()
            )
            head = git(self.repo, "rev-parse", "HEAD")
            self.assertEqual(request_id_of(self.repo, head), REQUEST_ID)
            self.assertIn(
                "Publish changes: Send the traffic log to graylog",
                git(self.repo, "log", "-1", "--format=%s"),
            )

            again, repeated, _err = self.publish_settings(policy, self.settings_request())
            self.assertEqual(again, 0)
            self.assertFalse(repeated["result"]["changed"])

    def test_a_retry_after_the_commit_repairs_the_release_from_that_version(self) -> None:
        """What a requeued job sends: the same request, fenced on the old head."""

        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.assertEqual(self.publish_network(policy, self.request())[0], 0)
            sent = self.settings_request().getvalue()
            self.publish_settings(policy, io.BytesIO(sent))
            head = git(self.repo, "rev-parse", "HEAD")
            versions = count_versions(self.repo)
            shutil.rmtree(self.publish_path / "releases" / head)
            (self.publish_path / "current").unlink()

            code, document, err = self.publish_settings(policy, io.BytesIO(sent))

            self.assertEqual((code, err), (0, ""))
            self.assertFalse(document["result"]["changed"])
            self.assertEqual(document["result"]["hash"], head)
            self.assertEqual(count_versions(self.repo), versions)
            self.assertEqual(os.readlink(self.publish_path / "current"), f"releases/{head}")

    def test_without_a_network_description_nothing_is_published(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            before = git(self.repo, "rev-parse", "HEAD")

            code, document, _err = self.publish_settings(policy, self.settings_request())

            self.assertEqual(code, 75)
            self.assertEqual(document["error"]["code"], "network_missing")
            self.assertEqual(git(self.repo, "rev-parse", "HEAD"), before)

    def test_a_target_named_rather_than_addressed_is_refused_before_a_version(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.publish_network(policy, self.request())
            before = git(self.repo, "rev-parse", "HEAD")

            code, document, _err = self.publish_settings(
                policy,
                self.settings_request("log_targets: {g: {address: logs.example.com, port: 6514}}"),
            )

            self.assertEqual(code, 65)
            self.assertEqual(document["error"]["code"], "settings_invalid")
            self.assertEqual(git(self.repo, "rev-parse", "HEAD"), before)

    def test_a_later_network_publish_keeps_the_settings(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.publish_network(policy, self.request())
            self.publish_settings(policy, self.settings_request())

            code, _document, _err = self.publish_network(
                policy, self.request(network=self.request_network_with_a_source())
            )

            self.assertEqual(code, 0)
            self.assertEqual((self.repo / LOCATION).read_text(), CANONICAL)
            self.assertIn("managed/generated/1000-cluster.cfg", git(self.repo, "ls-files"))

    def request_network_with_a_source(self) -> str:
        from tests.test_changes_publish_network import NETWORK

        return NETWORK.replace("outbound: 192.0.2.35", "outbound: 192.0.2.36")

    def test_the_read_helper_reports_the_settings_and_the_head(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.publish_network(policy, self.request())
            self.publish_settings(policy, self.settings_request())
            out = io.StringIO()

            code = cluster_settings_helper.main(
                [],
                policy_path=policy,
                input_stream=io.BytesIO(
                    json.dumps(
                        {
                            "schema_version": 1,
                            "operation": "cluster_settings",
                            "cluster": "alpha",
                            "request_id": REQUEST_ID,
                            "parameters": {},
                        }
                    ).encode()
                ),
                output_stream=out,
                error_stream=io.StringIO(),
                require_secure=False,
                require_root=False,
            )

            self.assertEqual(code, 0)
            assert_contract("haprion-cluster-settings", out.getvalue())
            result = json.loads(out.getvalue())["result"]
            self.assertEqual(result["head"], git(self.repo, "rev-parse", "HEAD"))
            self.assertTrue(result["stored"])
            self.assertEqual(result["metrics"], {"port": 8405, "sources": ["192.0.2.0/24"]})


class TheTerminalCommand(SettingsPublishFixture):
    def reading(self) -> subprocess.CompletedProcess[str]:
        document = {
            "schema_version": 1,
            "ok": True,
            "outcome": "done",
            "operation": "cluster_settings",
            "cluster": "alpha",
            "request_id": REQUEST_ID,
            "result": {
                "cluster": "alpha",
                "head": "b" * 40,
                "stored": True,
                "log_targets": [
                    {
                        "name": "loki",
                        "address": "2001:db8::30",
                        "port": 6514,
                        "disk_mib": 1024,
                        "tls": True,
                    }
                ],
                "metrics": None,
            },
            "warnings": [],
            "error": None,
        }
        return subprocess.CompletedProcess([], 0, json.dumps(document), "")

    def test_it_shows_what_is_set(self) -> None:
        out = io.StringIO()
        code = command.main(["-c", "alpha"], stream_out=out, run_helper=lambda *_: self.reading())
        self.assertEqual(code, 0)
        self.assertIn("[2001:db8::30]:6514", out.getvalue())
        self.assertIn("1024 MiB", out.getvalue())
        self.assertIn("METRICS\n-------\noff", out.getvalue())

    def test_set_refuses_a_file_that_is_not_utf_8_as_apply_does(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "settings.yaml"
            path.write_bytes(b"log_targets: []\n# \xff\n")
            err = io.StringIO()
            code = command.main(
                ["-c", "alpha", "--set", str(path), "-m", "Send the log"],
                stream_out=io.StringIO(),
                stream_err=err,
                run_helper=lambda *_: self.reading(),
                run_publish=lambda _request: self.fail("published"),
            )

        self.assertEqual(code, 65)
        self.assertIn("not UTF-8", err.getvalue())

    def test_set_publishes_through_the_helper_against_the_head_it_read(self) -> None:
        sent: list[dict[str, object]] = []

        def publish(request: str) -> subprocess.CompletedProcess[str]:
            sent.append(json.loads(request))
            answer = {
                "operation": "changes_publish",
                "result": {"changed": True, "version": 12},
                "error": None,
            }
            return subprocess.CompletedProcess([], 0, json.dumps(answer), "")

        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "settings.yaml"
            path.write_text(SETTINGS)
            out = io.StringIO()
            code = command.main(
                ["-c", "alpha", "--set", str(path), "-m", "Send the log"],
                stream_out=out,
                run_helper=lambda *_: self.reading(),
                run_publish=publish,
            )

        self.assertEqual(code, 0)
        (request,) = sent
        self.assertEqual(request["operation"], "changes_publish")
        self.assertEqual(
            request["parameters"],
            {
                "settings": SETTINGS,
                "expected_head": "b" * 40,
                "comment": "Send the log",
                "allow_certificate_mismatch": False,
            },
        )
        self.assertIn("Published version 12 of alpha.", out.getvalue())
        self.assertIn("haprion-deploy -c alpha", out.getvalue())

    def test_as_root_the_helper_runs_directly_so_the_person_is_recorded(self) -> None:
        # Review 2026-09-29 F2: under `sudo haprion-cluster-settings`, an inner
        # sudo would name root; run directly, the outer SUDO_USER carries over.
        from unittest import mock

        with mock.patch("os.geteuid", return_value=0):
            self.assertEqual(command._through("/opt/helper", "--"), ["/opt/helper"])
        with mock.patch("os.geteuid", return_value=1000):
            self.assertEqual(
                command._through("/opt/helper", "--"), ["/usr/bin/sudo", "--", "/opt/helper"]
            )
