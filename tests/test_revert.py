"""Reverting, and the two halves wired together.

The cases that carry weight here are the ones about the window the privilege
split opened: the caller shows a version, and something changes before the
helper writes it. Everything the caller looked up is looked up again, and a
different answer means nothing is written.
"""

from __future__ import annotations

import grp
import io
import json
import os
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from haproxy_mgmt.candidate_validation import ValidationResult
from haproxy_mgmt.cli import revert, revert_helper
from haproxy_mgmt.cluster_lock import hold
from haproxy_mgmt.version_history import (
    count_versions,
    request_id_of,
    version_commit,
    version_summary,
)
from tests.contract_schema import assert_contract
from tests.test_publish_helper import HAPROXY_CFG, PublishFixture, Recorder, git

REQUEST_ID = "33333333-3333-4333-8333-333333333333"


class RevertFixture(PublishFixture):
    """The publish fixture's clusters, with a history worth reverting through."""

    def history(self, count: int = 3) -> None:
        """Append versions, each with its own recognisable haproxy.cfg."""

        for step in range(2, count + 1):
            (self.repo / "core/haproxy.cfg").write_bytes(
                HAPROXY_CFG + f"  # version {step}\n".encode()
            )
            git(self.repo, "add", "-A")
            git(self.repo, "commit", "-qm", f"Change {step}")

    def run_caller(
        self,
        policy_path: Path,
        *argv: str,
        valid: bool = True,
        diagnostics: str = "Configuration file is valid\n",
        before_helper: object = None,
    ) -> tuple[int, str]:
        self.requests: list[dict[str, object]] = []

        def validate(candidate_root: Path, request_id: str) -> ValidationResult:
            self.seen_files = {
                str(path.relative_to(candidate_root)): path.read_bytes()
                for path in sorted(candidate_root.rglob("*"))
                if path.is_file()
            }
            return ValidationResult(valid=valid, diagnostics=diagnostics)

        def run_helper(request: bytes) -> tuple[int, str, str]:
            self.requests.append(json.loads(request))
            #
            # The window the split opened: anything that happens here happens
            # after the operator saw the preview and before root writes.
            #
            if callable(before_helper):
                before_helper()
            out, err = io.StringIO(), io.StringIO()
            code = revert_helper.main(
                [],
                policy_path=policy_path,
                run_root=self.run_root,
                lock_root=self.lock_root,
                input_stream=io.BytesIO(request),
                output_stream=out,
                error_stream=err,
                require_secure=False,
                require_root=False,
                validator=validate,
                group=grp.getgrgid(os.getgid()).gr_name,
                change_owner=Recorder(),
            )
            #
            # Kept so a test can hold the privileged half to its own contract.
            # Everything else in this file reads the human text the caller
            # printed afterwards, which is exactly how a helper document that
            # matched no schema at all went unnoticed.
            #
            self.helper_stdout = out.getvalue()
            self.helper_stderr = err.getvalue()
            return code, self.helper_stdout, self.helper_stderr

        writer = io.StringIO()
        code = revert.main(
            list(argv),
            stream_out=writer,
            run_helper=run_helper,
            config_path=lambda _cluster: self.repo,
        )
        return code, writer.getvalue()


class VersionHistoryTests(RevertFixture):
    def test_versions_count_from_the_oldest_commit_forward(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            self.runtime(Path(raw))
            self.history(3)
            self.assertEqual(count_versions(self.repo), 3)
            first = version_commit(self.repo, 1)
            self.assertEqual(
                git(self.repo, "log", "--format=%s", first, "-1"), "Initial example configuration"
            )
            self.assertEqual(version_commit(self.repo, 3), git(self.repo, "rev-parse", "HEAD"))

    def test_a_version_outside_the_history_is_absent_rather_than_wrong(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            self.runtime(Path(raw))
            self.history(3)
            for version in (0, -1, 4, 99):
                self.assertIsNone(version_commit(self.repo, version), version)

    def test_the_summary_carries_what_the_preview_shows(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            self.runtime(Path(raw))
            self.history(3)
            commit = version_commit(self.repo, 2)
            assert commit is not None
            summary = version_summary(self.repo, 2, commit)
            self.assertEqual((summary.version, summary.comment), (2, "Change 2"))
            self.assertRegex(summary.date, r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$")


class RevertTests(RevertFixture):
    def test_a_revert_records_a_new_version_holding_the_old_content(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy_path = self.runtime(Path(raw))
            self.history(3)
            target = version_commit(self.repo, 2)

            code, output = self.run_caller(policy_path, "-c", "alpha", "2")

            self.assertEqual(code, 0)
            self.assertIn("recorded as version 4", output)
            self.assertEqual(count_versions(self.repo), 4)
            #
            # A new version, not a rewritten history: version 3 is still there.
            #
            self.assertEqual(version_commit(self.repo, 3), git(self.repo, "rev-parse", "HEAD~1"))
            self.assertEqual(
                git(self.repo, "rev-parse", "HEAD^{tree}"),
                git(self.repo, "rev-parse", f"{target}^{{tree}}"),
            )
            self.assertEqual(
                git(self.repo, "log", "-1", "--format=%s"), "Revert configuration to version 2"
            )

    def test_the_draft_area_shows_the_reverted_content(self) -> None:
        """A hard reset, unlike publishing: what the configuration IS has changed."""
        with tempfile.TemporaryDirectory() as raw:
            policy_path = self.runtime(Path(raw))
            self.history(3)
            self.run_caller(policy_path, "-c", "alpha", "2")
            self.assertIn(b"# version 2", (self.repo / "core/haproxy.cfg").read_bytes())
            self.assertEqual(git(self.repo, "status", "--porcelain"), "")

    def test_without_a_version_the_previous_one_is_restored(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy_path = self.runtime(Path(raw))
            self.history(3)
            code, output = self.run_caller(policy_path, "-c", "alpha")
            self.assertEqual(code, 0)
            self.assertIn("Version:   2", output)
            self.assertIn(b"# version 2", (self.repo / "core/haproxy.cfg").read_bytes())

    def test_the_restored_content_is_validated_before_it_is_recorded(self) -> None:
        """Published once is not a reason to skip validation: the world moved on."""
        with tempfile.TemporaryDirectory() as raw:
            policy_path = self.runtime(Path(raw))
            self.history(3)
            before = git(self.repo, "rev-parse", "HEAD")
            code, output = self.run_caller(
                policy_path,
                "-c",
                "alpha",
                "2",
                valid=False,
                diagnostics="[ALERT] missing certificate\n",
            )
            self.assertEqual(code, 65)
            self.assertIn("missing certificate", output)
            self.assertIn("No version was created", output)
            self.assertEqual(git(self.repo, "rev-parse", "HEAD"), before)
            self.assertIn(b"# version 3", (self.repo / "core/haproxy.cfg").read_bytes())

    def test_the_current_version_is_reported_rather_than_re_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy_path = self.runtime(Path(raw))
            self.history(3)
            code, output = self.run_caller(policy_path, "-c", "alpha", "3")
            self.assertEqual(code, 0)
            self.assertIn("already current", output)
            self.assertEqual(self.requests, [])
            self.assertEqual(count_versions(self.repo), 3)


class WindowTests(RevertFixture):
    def test_a_version_that_moved_after_the_preview_is_refused(self) -> None:
        """The window the privilege split opened, closed on the far side.

        A commit appended at the tip does not invalidate the preview - version 2
        still names the same commit, and the shell path accepted that too. What
        must be refused is the history being rewritten under the operator, so
        that the number they approved now names different content.
        """

        with tempfile.TemporaryDirectory() as raw:
            policy_path = self.runtime(Path(raw))
            self.history(3)

            def someone_rewrites_history() -> None:
                first = version_commit(self.repo, 1)
                assert first is not None
                git(self.repo, "reset", "--hard", "--quiet", first)
                (self.repo / "core/haproxy.cfg").write_bytes(HAPROXY_CFG + b"  # smuggled\n")
                git(self.repo, "add", "-A")
                git(self.repo, "commit", "-qm", "Smuggled version 2")

            code, output = self.run_caller(
                policy_path, "-c", "alpha", "2", before_helper=someone_rewrites_history
            )
            self.assertEqual(code, 75)
            self.assertIn("no longer points at the same commit", output)
            self.assertEqual(git(self.repo, "log", "-1", "--format=%s"), "Smuggled version 2")
            self.assertNotIn(b"# version 2", (self.repo / "core/haproxy.cfg").read_bytes())

    def test_a_draft_that_became_dirty_after_the_preview_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy_path = self.runtime(Path(raw))
            self.history(3)
            before = git(self.repo, "rev-parse", "HEAD")

            def someone_else_edits() -> None:
                (self.repo / "core/haproxy.cfg").write_bytes(HAPROXY_CFG + b"  # editing\n")

            code, output = self.run_caller(
                policy_path, "-c", "alpha", "2", before_helper=someone_else_edits
            )
            self.assertEqual(code, 75)
            self.assertIn("unsaved changes", output)
            self.assertEqual(git(self.repo, "rev-parse", "HEAD"), before)
            #
            # And the edit survived: a refused revert must not eat it.
            #
            self.assertIn(b"# editing", (self.repo / "core/haproxy.cfg").read_bytes())


class RefusalTests(RevertFixture):
    def test_an_unsaved_draft_is_refused_before_anything_is_sent(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy_path = self.runtime(Path(raw))
            self.history(3)
            (self.repo / "core/haproxy.cfg").write_bytes(HAPROXY_CFG + b"  # unsaved\n")
            code, output = self.run_caller(policy_path, "-c", "alpha", "2")
            self.assertEqual(code, 65)
            self.assertIn("unsaved changes", output)
            self.assertIn("core/haproxy.cfg", output)
            self.assertEqual(self.requests, [])

    def test_a_version_that_does_not_exist_is_named(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy_path = self.runtime(Path(raw))
            self.history(3)
            code, output = self.run_caller(policy_path, "-c", "alpha", "9")
            self.assertEqual(code, 65)
            self.assertIn("does not exist", output)
            self.assertIn("current version is 3", output)

    def test_a_version_that_is_not_a_number_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy_path = self.runtime(Path(raw))
            self.history(3)
            for requested in ("latest", "-1", "07", "2.5"):
                code, output = self.run_caller(policy_path, "-c", "alpha", requested)
                self.assertEqual((code, self.requests), (64, []), requested)
                self.assertIn("plain version number", output)

    def test_a_single_version_history_has_nothing_to_go_back_to(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy_path = self.runtime(Path(raw))
            code, output = self.run_caller(policy_path, "-c", "alpha")
            self.assertEqual(code, 65)
            self.assertIn("no previous version", output)

    def test_a_disconnected_draft_area_is_diagnosed_before_the_helper_runs(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy_path = self.runtime(Path(raw), linked_worktree=True)
            history = self.repo.with_name(f"{self.repo.name}.git")
            history.rename(history.with_name(f"{history.name}.moved"))
            code, output = self.run_caller(policy_path, "-c", "alpha", "1")
            self.assertEqual(code, 68)
            self.assertIn("no longer connected to its saved history", output)
            self.assertEqual(self.requests, [])

    def test_the_usage_contract_is_unchanged(self) -> None:
        #
        # Exit 64 and usage on stdout, both as the shell command did. The code
        # is what a wrapper reads to tell a mistyped call from a failed one.
        #
        for argv in ([], ["-c"], ["alpha"], ["-c", "alpha", "2", "3"]):
            shown = io.StringIO()
            with self.assertRaises(SystemExit) as caught, redirect_stdout(shown):
                revert.main(argv, stream_out=io.StringIO())
            self.assertEqual(caught.exception.code, 64)
            self.assertIn("haproxy-revert -c <cluster>", shown.getvalue())

    def test_the_helper_refuses_argv_and_a_non_root_caller(self) -> None:
        stderr = io.StringIO()
        code = revert_helper.main(
            ["-c", "alpha"],
            input_stream=io.BytesIO(b""),
            output_stream=io.StringIO(),
            error_stream=stderr,
            require_root=False,
        )
        self.assertEqual(code, 64)
        self.assertIn("no command-line arguments", stderr.getvalue())


class ContractTests(RevertFixture):
    """What the privileged half prints, held to `schemas/v1/haproxy-revert`.

    The worker stores whatever this document says happened, and refuses anything
    that is not the common v1 envelope bound to the job it claimed. A helper that
    answers in a shape of its own leaves every revert recorded as `unknown` -
    "this may have taken effect" - which is the least useful thing a job history
    can say about a write.
    """

    def test_a_completed_revert_answers_in_the_frozen_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy_path = self.runtime(Path(raw))
            self.history(3)
            code, _ = self.run_caller(policy_path, "-c", "alpha", "2")
            self.assertEqual(code, 0)

            document = assert_contract("haproxy-revert", self.helper_stdout)
            self.assertEqual(document["operation"], "revert")
            self.assertEqual(document["outcome"], "done")
            self.assertIs(document["ok"], True)
            self.assertEqual(document["request_id"], self.requests[0]["request_id"])
            self.assertEqual(document["cluster"], "alpha")

            result = document["result"]
            self.assertEqual(
                (result["changed"], result["from_version"], result["restored_version"]),
                (True, 3, 2),
            )
            self.assertEqual(result["new_version"], 4)
            self.assertIs(result["deployment_required"], True)
            self.assertEqual(result["next_command"], "haproxy-deploy -c alpha")

    def test_reverting_to_the_content_already_in_place_is_a_no_op(self) -> None:
        """The contract's successful no-op, and what makes a retry safe.

        A second attempt at a revert that already landed finds its own content at
        the tip. Recording another version there would grow the history by one
        every time somebody pressed the button twice, and would tell an operator
        to deploy content the nodes already run.
        """

        with tempfile.TemporaryDirectory() as raw:
            policy_path = self.runtime(Path(raw))
            self.history(3)
            self.run_caller(policy_path, "-c", "alpha", "2")
            self.assertEqual(count_versions(self.repo), 4)

            code, output = self.run_caller(policy_path, "-c", "alpha", "2")
            self.assertEqual(code, 0)
            self.assertEqual(count_versions(self.repo), 4)

            document = assert_contract("haproxy-revert", self.helper_stdout)
            self.assertEqual(document["outcome"], "done")
            result = document["result"]
            self.assertIs(result["changed"], False)
            self.assertIs(result["deployment_required"], False)
            self.assertIsNone(result["next_command"])
            self.assertEqual(result["new_version"], result["from_version"])
            self.assertIn("already holds the content of version 2", output)

    def test_an_interrupted_revert_is_finished_without_a_second_version(self) -> None:
        """Phase 6's repair, on the revert path.

        The crash window is between the reference swap and the install. The
        retry finds the tree already restored, so it records nothing - and
        publishes the release from that same commit rather than reverting again.
        """

        with tempfile.TemporaryDirectory() as raw:
            policy_path = self.runtime(Path(raw))
            self.history(3)
            self.run_caller(policy_path, "-c", "alpha", "2")

            head = git(self.repo, "rev-parse", "HEAD")
            versions = count_versions(self.repo)
            shutil.rmtree(self.publish_path / "releases" / head)
            (self.publish_path / "current").unlink()

            code, _ = self.run_caller(policy_path, "-c", "alpha", "2")

            self.assertEqual(code, 0)
            result = assert_contract("haproxy-revert", self.helper_stdout)["result"]
            self.assertFalse(result["changed"])
            self.assertEqual(count_versions(self.repo), versions)
            self.assertEqual(git(self.repo, "rev-parse", "HEAD"), head)
            self.assertTrue(result["deployment_required"])
            self.assertEqual(os.readlink(self.publish_path / "current"), f"releases/{head}")

    def test_an_invalid_candidate_fails_in_the_envelope_with_its_diagnostics(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy_path = self.runtime(Path(raw))
            self.history(3)
            code, output = self.run_caller(
                policy_path,
                "-c",
                "alpha",
                "2",
                valid=False,
                diagnostics="[ALERT] missing certificate\n",
            )
            self.assertEqual(code, 65)

            document = assert_contract("haproxy-revert", self.helper_stdout)
            self.assertEqual(document["outcome"], "failed")
            self.assertIsNone(document["result"])
            self.assertEqual(document["error"]["code"], "candidate_invalid")
            self.assertIn("missing certificate", document["error"]["details"]["diagnostics"])
            #
            # The caller still shows the diagnostics. They moved from a field of
            # their own into the error's details; what an operator sees did not.
            #
            self.assertIn("missing certificate", output)

    def test_a_dirty_draft_is_a_stable_code_rather_than_only_a_message(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy_path = self.runtime(Path(raw))
            self.history(3)

            def somebody_edits_the_draft() -> None:
                (self.repo / "core/haproxy.cfg").write_bytes(HAPROXY_CFG + b"  # unsaved\n")

            code, _ = self.run_caller(
                policy_path, "-c", "alpha", "2", before_helper=somebody_edits_the_draft
            )
            self.assertEqual(code, 75)
            document = assert_contract("haproxy-revert", self.helper_stdout)
            self.assertEqual(document["error"]["code"], "dirty_worktree")

    def test_a_version_that_moved_is_reported_as_a_changed_target(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy_path = self.runtime(Path(raw))
            self.history(3)

            def someone_rewrites_history() -> None:
                first = version_commit(self.repo, 1)
                assert first is not None
                git(self.repo, "reset", "--hard", "--quiet", first)
                (self.repo / "core/haproxy.cfg").write_bytes(HAPROXY_CFG + b"  # smuggled\n")
                git(self.repo, "add", "-A")
                git(self.repo, "commit", "-qm", "Smuggled version 2")

            code, _ = self.run_caller(
                policy_path, "-c", "alpha", "2", before_helper=someone_rewrites_history
            )
            self.assertEqual(code, 75)
            document = assert_contract("haproxy-revert", self.helper_stdout)
            self.assertEqual(document["error"]["code"], "expected_target_changed")

    def test_a_held_cluster_lock_blocks_the_revert_without_writing(self) -> None:
        """The lock a revert did not use to take at all.

        A revert prepared outside the cluster's lock can be built against a
        repository a deploy is already acting on. The reference swap would still
        refuse a moved branch, but nothing stopped a release from being installed
        underneath a rollout that was reading it.
        """

        with tempfile.TemporaryDirectory() as raw:
            policy_path = self.runtime(Path(raw))
            self.history(3)
            before = git(self.repo, "rev-parse", "HEAD")

            with hold("alpha", operation="deploy", root=self.lock_root):
                code, _ = self.run_caller(policy_path, "-c", "alpha", "2")

            self.assertEqual(code, 75)
            document = assert_contract("haproxy-revert", self.helper_stdout)
            self.assertEqual(document["outcome"], "blocked")
            self.assertEqual(document["error"]["code"], "operation_locked")
            self.assertEqual(git(self.repo, "rev-parse", "HEAD"), before)

    def test_the_version_it_records_is_bound_to_the_request(self) -> None:
        """Half of the evidence a restart needs, written where it survives.

        After a crash the question is whether the revert took effect. The
        version's content cannot answer it - the same tree can be restored twice
        for two different reasons - so the commit carries the request that asked
        for it. The subject is untouched, because that is what an operator reads
        in the version list.
        """

        with tempfile.TemporaryDirectory() as raw:
            policy_path = self.runtime(Path(raw))
            self.history(3)
            self.run_caller(policy_path, "-c", "alpha", "2")

            head = git(self.repo, "rev-parse", "HEAD")
            self.assertEqual(request_id_of(self.repo, head), self.requests[0]["request_id"])
            self.assertEqual(
                git(self.repo, "log", "-1", "--format=%s"), "Revert configuration to version 2"
            )

    def test_a_commit_without_a_trailer_confirms_nothing(self) -> None:
        """None means "this commit cannot confirm a request", not "it did not
        happen". Every version published before the trailer existed answers
        this way, and treating that as proof of anything would be a guess."""

        with tempfile.TemporaryDirectory() as raw:
            self.runtime(Path(raw))
            self.history(3)
            self.assertIsNone(request_id_of(self.repo, git(self.repo, "rev-parse", "HEAD")))


if __name__ == "__main__":
    unittest.main()
