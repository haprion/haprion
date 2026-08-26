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
import tempfile
import unittest
from pathlib import Path

from haproxy_mgmt.candidate_validation import ValidationResult
from haproxy_mgmt.cli import revert, revert_helper
from haproxy_mgmt.version_history import count_versions, version_commit, version_summary
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
                input_stream=io.BytesIO(request),
                output_stream=out,
                error_stream=err,
                require_secure=False,
                require_root=False,
                validator=validate,
                group=grp.getgrgid(os.getgid()).gr_name,
                change_owner=Recorder(),
            )
            return code, out.getvalue(), err.getvalue()

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
            self.assertEqual(code, 65)
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
            self.assertEqual(code, 65)
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
        for argv in ([], ["-c"], ["alpha"], ["-c", "alpha", "2", "3"]):
            with self.assertRaises(SystemExit) as caught:
                revert.main(argv, stream_out=io.StringIO())
            self.assertIn("haproxy-revert -c <cluster>", str(caught.exception))

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


if __name__ == "__main__":
    unittest.main()
