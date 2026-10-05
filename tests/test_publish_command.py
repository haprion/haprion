"""The thin caller, and the two halves wired together.

Most of these cases are about what the caller sends: the right layers, chosen
the way git would choose them, with a starting point it measured itself. The
last class runs the caller straight into the real root helper, because the
interesting failures live in the seam between them rather than in either half.
"""

from __future__ import annotations

import grp
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any

from haproxy_mgmt.candidate_validation import ValidationResult
from haproxy_mgmt.cli import publish, publish_helper
from haproxy_mgmt.reservations import fragment_digest
from tests.test_publish_helper import (
    CORE_CFG,
    GENERATED,
    HAPROXY_CFG,
    PublishFixture,
    Recorder,
    git,
)


class CallerFixture(PublishFixture):
    """The publish helper's fixture, driven through the unprivileged caller."""

    def run_caller(
        self,
        policy_path: Path,
        *argv: str,
        valid: bool = True,
        diagnostics: str = "Configuration file is valid\n",
    ) -> tuple[int, str]:
        self.requests: list[dict[str, Any]] = []

        def validate(candidate_root: Path, request_id: str) -> ValidationResult:
            return ValidationResult(valid=valid, diagnostics=diagnostics)

        def run_helper(request: bytes) -> tuple[int, str, str]:
            self.requests.append(json.loads(request))
            out = io.StringIO()
            err = io.StringIO()
            code = publish_helper.main(
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
            return code, out.getvalue(), err.getvalue()

        writer = io.StringIO()
        code = publish.main(
            list(argv),
            stream_out=writer,
            run_helper=run_helper,
            config_path=lambda _cluster: self.repo,
        )
        return code, writer.getvalue()


class RequestTests(CallerFixture):
    def test_only_core_and_manual_are_sent_with_the_measured_head(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy_path = self.runtime(Path(raw))
            head = git(self.repo, "rev-parse", "HEAD")
            self.edit("core/haproxy.cfg", HAPROXY_CFG + b"  option httplog\n")
            self.run_caller(policy_path, "-c", "alpha", "Added serverxyz")

            parameters = self.requests[0]["parameters"]
            self.assertEqual(
                sorted(parameters["files"]),
                ["core/conf.d/0010-core.cfg", "core/haproxy.cfg", "manual/reservations.yaml"],
            )
            self.assertEqual(parameters["expected_head"], head)
            self.assertEqual(parameters["comment"], "Added serverxyz")
            self.assertEqual(self.requests[0]["operation"], "publish_version")

    def test_gitignored_files_stay_out_of_the_version(self) -> None:
        """The reason .gitignore was added to the cluster repositories at all."""
        with tempfile.TemporaryDirectory() as raw:
            policy_path = self.runtime(Path(raw))
            (self.repo / ".gitignore").write_text("*.swp\n*.orig\n")
            git(self.repo, "add", "-A")
            git(self.repo, "commit", "-qm", "Ignore editor leftovers")
            (self.repo / "core/.haproxy.cfg.swp").write_bytes(b"vim leftovers\n")
            (self.repo / "core/conf.d/0010-core.cfg.orig").write_bytes(CORE_CFG)
            self.edit("core/haproxy.cfg", HAPROXY_CFG + b"  option httplog\n")

            code, _ = self.run_caller(policy_path, "-c", "alpha", "Added serverxyz")
            files = self.requests[0]["parameters"]["files"]
            self.assertEqual(code, 0)
            self.assertNotIn("core/.haproxy.cfg.swp", files)
            self.assertNotIn("core/conf.d/0010-core.cfg.orig", files)

    def test_an_untracked_file_is_published_and_a_deleted_one_disappears(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy_path = self.runtime(Path(raw))
            (self.repo / "core/conf.d/0020-new.cfg").write_bytes(b"frontend new\n  bind :82\n")
            (self.repo / "core/conf.d/0010-core.cfg").unlink()

            code, _ = self.run_caller(policy_path, "-c", "alpha", "Replaced the core frontend")
            self.assertEqual(code, 0)
            listed = git(self.repo, "ls-tree", "-r", "--name-only", "HEAD")
            self.assertIn("core/conf.d/0020-new.cfg", listed)
            self.assertNotIn("core/conf.d/0010-core.cfg", listed)

    def test_changes_in_managed_are_reported_rather_than_dropped(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy_path = self.runtime(Path(raw))
            (self.repo / "managed/generated/1040-managed.cfg").write_bytes(GENERATED + b"  # new\n")
            self.edit("core/haproxy.cfg", HAPROXY_CFG + b"  option httplog\n")

            _, output = self.run_caller(policy_path, "-c", "alpha", "Added serverxyz")
            self.assertIn("managed/generated/1040-managed.cfg", output)
            self.assertIn("NOT part of this version", output)
            self.assertNotIn("managed/", str(self.requests[0]["parameters"]["files"]))


class EndToEndTests(CallerFixture):
    def test_a_publish_reports_the_version_it_created(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy_path = self.runtime(Path(raw))
            self.edit("core/haproxy.cfg", HAPROXY_CFG + b"  option httplog\n")
            code, output = self.run_caller(policy_path, "-c", "alpha", "Added serverxyz")

            self.assertEqual(code, 0)
            self.assertIn("Version:  2", output)
            self.assertIn(git(self.repo, "rev-parse", "HEAD"), output)
            self.assertIn("No node deployment has run", output)
            self.assertEqual(git(self.repo, "status", "--porcelain"), "")

    def test_nothing_to_publish_is_said_plainly(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy_path = self.runtime(Path(raw))
            before = git(self.repo, "rev-parse", "HEAD")
            code, output = self.run_caller(policy_path, "-c", "alpha", "No change at all")
            self.assertEqual(code, 0)
            self.assertIn("No changes to publish", output)
            self.assertEqual(git(self.repo, "rev-parse", "HEAD"), before)

    def test_handwritten_fragments_nobody_has_confirmed_are_pointed_out(self) -> None:
        """B86: two frontends on one address bind it and split the traffic at random."""

        with tempfile.TemporaryDirectory() as raw:
            policy_path = self.runtime(Path(raw))
            self.edit("core/haproxy.cfg", HAPROXY_CFG + b"  option httplog\n")
            code, output = self.run_caller(policy_path, "-c", "alpha", "A change")

            self.assertEqual(code, 0)
            self.assertIn("Not written down at all", output)
            self.assertIn("core/conf.d/0010-core.cfg", output)

    def test_reserving_something_no_longer_silences_the_note(self) -> None:
        """L8: an old promise must not look exactly like a current one."""

        with tempfile.TemporaryDirectory() as raw:
            policy_path = self.runtime(Path(raw))
            self.edit("manual/reservations.yaml", b"tcp_ports: [8443]\n")
            code, output = self.run_caller(policy_path, "-c", "alpha", "A reservation")

            self.assertEqual(code, 0)
            self.assertIn("Not written down at all", output)

    def test_a_confirmed_fragment_is_quiet_until_it_changes(self) -> None:
        """The whole point: the note follows the bytes, not the file's existence."""

        with tempfile.TemporaryDirectory() as raw:
            policy_path = self.runtime(Path(raw))
            promise = (
                b"reviewed:\n  core/conf.d/0010-core.cfg: "
                + fragment_digest(CORE_CFG).encode()
                + b"\n"
            )
            self.edit("manual/reservations.yaml", promise)
            code, output = self.run_caller(policy_path, "-c", "alpha", "Read and confirmed")

            self.assertEqual(code, 0)
            self.assertNotIn("not current with", output)

            self.edit("core/conf.d/0010-core.cfg", CORE_CFG + b"  option httplog\n")
            code, output = self.run_caller(policy_path, "-c", "alpha", "Edited afterwards")

            self.assertEqual(code, 0)
            self.assertIn("Changed since somebody read them", output)
            self.assertIn("core/conf.d/0010-core.cfg", output)

    def test_an_invalid_configuration_reaches_the_operator(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy_path = self.runtime(Path(raw))
            before = git(self.repo, "rev-parse", "HEAD")
            self.edit("core/haproxy.cfg", b"global\n  nonsense\n")
            code, output = self.run_caller(
                policy_path,
                "-c",
                "alpha",
                "Broken on purpose",
                valid=False,
                diagnostics="[ALERT] unknown keyword 'nonsense'\n",
            )
            self.assertEqual(code, 65)
            self.assertIn("unknown keyword 'nonsense'", output)
            self.assertIn("No version was created", output)
            self.assertEqual(git(self.repo, "rev-parse", "HEAD"), before)

    def test_the_linked_worktree_layout_publishes_the_same_way(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy_path = self.runtime(Path(raw), linked_worktree=True)
            self.edit("core/haproxy.cfg", HAPROXY_CFG + b"  option httplog\n")
            code, output = self.run_caller(policy_path, "-c", "alpha", "Added serverxyz")
            self.assertEqual(code, 0)
            self.assertIn("Version:  2", output)


class RefusalTests(CallerFixture):
    def test_a_disconnected_draft_area_is_diagnosed_before_the_helper_runs(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy_path = self.runtime(Path(raw), linked_worktree=True)
            history = self.repo.with_name(f"{self.repo.name}.git")
            history.rename(history.with_name(f"{history.name}.moved"))

            code, output = self.run_caller(policy_path, "-c", "alpha", "Added serverxyz")
            self.assertEqual(code, 68)
            self.assertIn("no longer connected to its saved history", output)
            self.assertEqual(self.requests, [])

    def test_the_usage_contract_is_unchanged(self) -> None:
        for argv in ([], ["-c", "alpha"], ["alpha", "comment"], ["-c", "alpha", "   "]):
            shown = io.StringIO()
            with self.assertRaises(SystemExit) as caught, redirect_stdout(shown):
                publish.main(argv, stream_out=io.StringIO())
            self.assertEqual(caught.exception.code, 64)
            self.assertIn("haproxy-publish -c <cluster>", shown.getvalue())

    def test_a_comment_of_several_words_is_joined(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy_path = self.runtime(Path(raw))
            self.edit("core/haproxy.cfg", HAPROXY_CFG + b"  option httplog\n")
            self.run_caller(policy_path, "-c", "alpha", "Added", "server", "xyz")
            self.assertEqual(self.requests[0]["parameters"]["comment"], "Added server xyz")


if __name__ == "__main__":
    unittest.main()
