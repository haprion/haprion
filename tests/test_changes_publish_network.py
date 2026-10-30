"""Network publication crosses the same hard boundary as every other write.

The network part of a saved-changes publish (B257).
"""

from __future__ import annotations

import grp
import io
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import Any

from haprion import tls_policy
from haprion.candidate_validation import ValidationResult
from haprion.cli import changes_publish
from haprion.version_history import count_versions, request_id_of
from tests.contract_schema import assert_contract
from tests.test_publish_helper import PublishFixture, Recorder, git

REQUEST_ID = "44444444-4444-4444-8444-444444444444"
NETWORK = """vips:
  main:
    address: 192.0.2.20
    source: 192.0.2.25
default_vip: main
sources:
  outbound: 192.0.2.35
networks:
  office:
  - 198.51.100.0/24
"""


class NetworkPublishFixture(PublishFixture):
    def request(self, **overrides: object) -> io.BytesIO:
        parameters: dict[str, object] = {
            "network": NETWORK,
            "expected_head": git(self.repo, "rev-parse", "HEAD"),
            "comment": "Add the office network",
        }
        parameters.update(overrides)
        return io.BytesIO(
            json.dumps(
                {
                    "schema_version": 1,
                    "operation": "changes_publish",
                    "cluster": "alpha",
                    "request_id": REQUEST_ID,
                    "parameters": parameters,
                }
            ).encode()
        )

    def publish_network(
        self, policy_path: Path, request: io.BytesIO, *, valid: bool = True
    ) -> tuple[int, Any, str]:
        out, err = io.StringIO(), io.StringIO()
        self.recorder = Recorder()

        def validator(_candidate: Path, _request_id: str) -> ValidationResult:
            return ValidationResult(valid=valid, diagnostics="candidate output")

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
            validator=validator,
            group=grp.getgrgid(os.getgid()).gr_name,
            change_owner=self.recorder,
        )
        return code, json.loads(out.getvalue()), err.getvalue()


class NetworkPublicationTests(NetworkPublishFixture):
    def test_only_managed_is_changed_and_the_request_is_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            before_core = (self.repo / "core/haproxy.cfg").read_bytes()

            code, document, err = self.publish_network(policy, self.request())

            self.assertEqual((code, err), (0, ""))
            assert_contract("haprion-changes-publish", json.dumps(document))
            self.assertEqual(document["operation"], "changes_publish")
            self.assertTrue(document["result"]["changed"])
            self.assertEqual((self.repo / "managed/network.yaml").read_text(), NETWORK)
            self.assertEqual((self.repo / "core/haproxy.cfg").read_bytes(), before_core)
            self.assertNotIn("managed/generated/1040-managed.cfg", git(self.repo, "ls-files"))
            self.assertEqual(
                request_id_of(self.repo, git(self.repo, "rev-parse", "HEAD")), REQUEST_ID
            )
            self.assertEqual(git(self.repo, "status", "--porcelain"), "")

    def stale_core(self) -> None:
        core = self.repo / "core/haproxy.cfg"
        core.write_text(
            core.read_text().replace(f"  {tls_policy.DEFAULT_PATH_LINE}\n", ""), encoding="utf-8"
        )
        git(self.repo, "commit", "-qam", "Human edit to core")

    def test_a_stale_core_is_refused_before_a_version_is_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.stale_core()
            before = git(self.repo, "rev-parse", "HEAD")

            code, document, _err = self.publish_network(policy, self.request())

            self.assertEqual(code, 75)
            self.assertEqual(document["error"]["code"], "tls_defaults_stale")
            self.assertEqual(git(self.repo, "rev-parse", "HEAD"), before)

    def test_an_unchanged_retry_is_held_to_the_same_policy(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            first, _document, _err = self.publish_network(policy, self.request())
            self.assertEqual(first, 0)
            self.stale_core()
            releases_before = sorted(self.publish_path.rglob("*"))

            code, document, _err = self.publish_network(policy, self.request())

            self.assertEqual(code, 75)
            self.assertEqual(document["error"]["code"], "tls_defaults_stale")
            self.assertEqual(sorted(self.publish_path.rglob("*")), releases_before)

    def test_a_retry_after_the_commit_repairs_the_release_from_that_version(self) -> None:
        """What a requeued job sends: the same request, fenced on the old head."""

        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            sent = self.request().getvalue()
            self.publish_network(policy, io.BytesIO(sent))
            head = git(self.repo, "rev-parse", "HEAD")
            versions = count_versions(self.repo)
            shutil.rmtree(self.publish_path / "releases" / head)
            (self.publish_path / "current").unlink()

            code, document, err = self.publish_network(policy, io.BytesIO(sent))

            self.assertEqual((code, err), (0, ""))
            self.assertFalse(document["result"]["changed"])
            self.assertEqual(document["result"]["hash"], head)
            self.assertEqual(count_versions(self.repo), versions)
            self.assertEqual(os.readlink(self.publish_path / "current"), f"releases/{head}")

    def test_another_request_after_a_stop_before_the_files_were_written_finds_a_clean_draft(
        self,
    ) -> None:
        """Review 26-10-30, E5: the draft is the version before a helper's, and not a person's."""

        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            old = git(self.repo, "rev-parse", "HEAD")
            self.publish_network(policy, self.request())
            git(self.repo, "read-tree", "--reset", "-u", old)
            self.assertNotEqual(git(self.repo, "status", "--porcelain"), "")
            other = json.loads(self.request().getvalue())
            other["request_id"] = "88888888-8888-4888-8888-888888888888"

            code, document, _err = self.publish_network(
                policy, io.BytesIO(json.dumps(other).encode())
            )

            self.assertEqual(code, 0, document)
            self.assertEqual(git(self.repo, "status", "--porcelain"), "")

    def test_a_dirty_human_worktree_is_blocked_without_touching_it(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            before = git(self.repo, "rev-parse", "HEAD")
            (self.repo / "core/haproxy.cfg").write_bytes(b"human draft\n")

            code, document, err = self.publish_network(policy, self.request())

            self.assertEqual(code, 75)
            self.assertEqual(document["outcome"], "blocked")
            self.assertIn("dirty_worktree", err)
            self.assertEqual(git(self.repo, "rev-parse", "HEAD"), before)
            self.assertEqual((self.repo / "core/haproxy.cfg").read_bytes(), b"human draft\n")

    def test_a_stale_page_cannot_replace_a_newer_network(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            before = git(self.repo, "rev-parse", "HEAD")
            (self.repo / "manual/reservations.yaml").write_text("hostnames: [legacy.example.com]\n")
            git(self.repo, "add", "manual/reservations.yaml")
            git(self.repo, "commit", "-qm", "Human update")

            code, document, err = self.publish_network(policy, self.request(expected_head=before))

            self.assertEqual(code, 75)
            self.assertEqual(document["error"]["code"], "expected_target_changed")
            self.assertIn("expected_target_changed", err)
            self.assertEqual(git(self.repo, "log", "-1", "--format=%s"), "Human update")

    def test_an_invalid_candidate_never_records_a_network_version(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            before = git(self.repo, "rev-parse", "HEAD")

            code, document, _err = self.publish_network(policy, self.request(), valid=False)

            self.assertEqual(code, 65)
            self.assertEqual(document["error"]["code"], "candidate_invalid")
            self.assertEqual(git(self.repo, "rev-parse", "HEAD"), before)
            self.assertFalse((self.repo / "managed/network.yaml").exists())


if __name__ == "__main__":
    unittest.main()
