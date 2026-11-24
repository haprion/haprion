"""The interface's publish of the files written by hand (B529).

`changes_publish` with `handwritten` publishes the draft area's `core/` and
`manual/` as `haprion-publish` does - read by root, taken only while they are
the files the page showed - and a publish of saved changes says which files
wait while they do.
"""

from __future__ import annotations

import grp
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from haprion import handwritten, repo_health
from haprion.candidate_validation import ValidationResult
from haprion.cli import changes_publish
from tests.contract_schema import assert_contract
from tests.test_changes_publish_objects import REQUEST_ID, ObjectsPublishFixture, proxy
from tests.test_publish_helper import HAPROXY_CFG, Recorder, git

EDITED = HAPROXY_CFG.replace(b"  daemon\n", b"  daemon\n  tune.stick-counters 6\n")


class HandwrittenFixture(ObjectsPublishFixture):
    def hand_request(self, **overrides: object) -> io.BytesIO:
        parameters: dict[str, object] = {
            "handwritten": handwritten.fingerprint(handwritten.read_layers(self.repo)),
            "expected_head": git(self.repo, "rev-parse", "HEAD"),
            "comment": "Handwritten changes: core/haproxy.cfg",
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

    def publish_while(
        self, policy_path: Path, request: io.BytesIO, during: Any = None
    ) -> tuple[int, Any, str]:
        """Publish, running `during` while the candidate is in the sandbox."""

        out, err = io.StringIO(), io.StringIO()

        def validator(_candidate: Path, _request_id: str) -> ValidationResult:
            if during is not None:
                during()
            return ValidationResult(valid=True, diagnostics="candidate output")

        code = changes_publish.main(
            [],
            policy_path=policy_path,
            run_root=self.run_root,
            lock_root=self.lock_root,
            blocklist_definitions=self.blocklist_definitions,
            input_stream=request,
            output_stream=out,
            error_stream=err,
            require_secure=False,
            require_root=False,
            validator=validator,
            group=grp.getgrgid(os.getgid()).gr_name,
            change_owner=Recorder(),
        )
        printed = out.getvalue()
        return code, json.loads(printed) if printed else None, err.getvalue()


class PublishingTheHandwrittenFiles(HandwrittenFixture):
    def test_the_files_become_a_version_as_the_terminal_publishes_them(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.seed()
            before = git(self.repo, "rev-parse", "HEAD")
            managed_before = git(self.repo, "rev-parse", f"{before}:managed")
            (self.repo / "core/haproxy.cfg").write_bytes(EDITED)

            code, document, _err = self.publish_while(policy, self.hand_request())

            self.assertEqual(code, 0, document)
            result = assert_contract("haprion-changes-publish", json.dumps(document))["result"]
            head = git(self.repo, "rev-parse", "HEAD")
            self.assertNotEqual(head, before)
            self.assertEqual(result["hash"], head)
            self.assertTrue(result["changed"])
            self.assertEqual(
                result["handwritten"], [{"path": "core/haproxy.cfg", "kind": "changed"}]
            )
            self.assertEqual(
                git(self.repo, "show", f"{head}:core/haproxy.cfg") + "\n", EDITED.decode()
            )
            #
            # managed/ is the version's own, untouched, as the terminal's publish carries it.
            #
            self.assertEqual(git(self.repo, "rev-parse", f"{head}:managed"), managed_before)
            self.assertEqual(
                git(self.repo, "log", "-1", "--format=%s"), "Handwritten changes: core/haproxy.cfg"
            )
            self.assertEqual(git(self.repo, "status", "--porcelain"), "")

    def test_a_file_written_during_the_publish_is_kept_as_a_change_of_its_own(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.seed()
            (self.repo / "core/haproxy.cfg").write_bytes(EDITED)
            later = EDITED.replace(b"stick-counters 6", b"stick-counters 7")

            code, document, _err = self.publish_while(
                policy,
                self.hand_request(),
                during=lambda: (self.repo / "core/haproxy.cfg").write_bytes(later),
            )

            self.assertEqual(code, 0, document)
            self.assertEqual((self.repo / "core/haproxy.cfg").read_bytes(), later)
            self.assertEqual(
                git(self.repo, "show", "HEAD:core/haproxy.cfg") + "\n", EDITED.decode()
            )
            self.assertEqual(git(self.repo, "status", "--porcelain"), "M core/haproxy.cfg")

    def test_files_changed_after_the_page_was_drawn_are_not_taken(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.seed()
            before = git(self.repo, "rev-parse", "HEAD")
            (self.repo / "core/haproxy.cfg").write_bytes(EDITED)
            request = self.hand_request()
            (self.repo / "core/haproxy.cfg").write_bytes(EDITED + b"# again\n")

            code, document, _err = self.publish_while(policy, request)

            self.assertEqual(code, 75)
            self.assertEqual(document["error"]["code"], "handwritten_changed")
            self.assertEqual(git(self.repo, "rev-parse", "HEAD"), before)

    def test_unsaved_changes_in_managed_still_refuse(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.seed()
            (self.repo / "core/haproxy.cfg").write_bytes(EDITED)
            (self.repo / "managed/network.yaml").write_text("vips: {}\n", encoding="utf-8")

            code, document, _err = self.publish_while(policy, self.hand_request())

            self.assertEqual((code, document["error"]["code"]), (75, "dirty_worktree"))
            self.assertIn("managed/", document["error"]["message"])

    def test_a_link_is_refused_by_name(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.seed()
            (self.repo / "core/haproxy.cfg").write_bytes(EDITED)
            request = self.hand_request()
            (self.repo / "core/alias.cfg").symlink_to("haproxy.cfg")

            code, document, _err = self.publish_while(policy, request)

            self.assertEqual(document["error"]["code"], "handwritten_invalid")
            self.assertIn("core/alias.cfg", document["error"]["message"])
            self.assertNotEqual(code, 0)

    def test_it_carries_nothing_else(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.seed()
            (self.repo / "core/haproxy.cfg").write_bytes(EDITED)
            for extra in (
                {"objects": {"shop": proxy("shop", "shop.example.com")}},
                {"regenerate": True},
                {"check": True},
            ):
                with self.subTest(extra=sorted(extra)):
                    code, document, _err = self.publish_while(policy, self.hand_request(**extra))

                    self.assertEqual(code, 65)
                    self.assertEqual(document["error"]["code"], "bad_input")
                    self.assertIn("alone", document["error"]["message"])

    def test_the_fingerprint_must_be_one(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.seed()

            code, document, _err = self.publish_while(
                policy, self.hand_request(handwritten="not a fingerprint")
            )

            self.assertEqual((code, document["error"]["code"]), (65, "bad_input"))


class ReadingTheStatus(unittest.TestCase):
    """`git status -z`: no name is quoted, and a rename names its new path once (B530, H01)."""

    def test_a_space_or_a_letter_outside_ascii_arrives_as_it_is(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            repo = Path(raw)
            git(repo, "init", "-q", "-b", "main")
            git(repo, "config", "user.email", "operator@example.com")
            git(repo, "config", "user.name", "operator")
            (repo / "core").mkdir()
            (repo / "managed").mkdir()
            (repo / "core/a.cfg").write_text("a\n", encoding="utf-8")
            (repo / "managed/old.yaml").write_text("x: 1\n", encoding="utf-8")
            git(repo, "add", "-A")
            git(repo, "commit", "-qm", "first")
            (repo / "core/blocked ips.map").write_text("192.0.2.1\n", encoding="utf-8")
            (repo / "core/v\u00e4xj\u00f6.map").write_text("x\n", encoding="utf-8")
            git(repo, "mv", "managed/old.yaml", "managed/new name.yaml")

            self.assertEqual(
                sorted(repo_health.unsaved_paths(repo)),
                ["core/blocked ips.map", "core/v\u00e4xj\u00f6.map", "managed/new name.yaml"],
            )
            self.assertEqual(
                repo_health.unsaved_paths(repo, *handwritten.LAYERS), ("managed/new name.yaml",)
            )


class ARenameOnlyOnDisk(unittest.TestCase):
    def test_names_the_new_path_and_skips_the_old_one(self) -> None:
        """B530, N1: ` R` in the work tree's column carries the old name as a field of its own."""

        with tempfile.TemporaryDirectory() as raw:
            repo = Path(raw)
            git(repo, "init", "-q", "-b", "main")
            git(repo, "config", "user.email", "operator@example.com")
            git(repo, "config", "user.name", "operator")
            (repo / "managed").mkdir()
            (repo / "managed/a.yaml").write_text(
                "x: 1\nlonger content so rename is detected\n", encoding="utf-8"
            )
            git(repo, "add", "-A")
            git(repo, "commit", "-qm", "first")
            (repo / "managed/a.yaml").rename(repo / "managed/b.yaml")
            git(repo, "add", "-N", "managed/b.yaml")

            self.assertEqual(repo_health.unsaved_paths(repo), ("managed/b.yaml",))


class AVersionWhoseFilesCannotBeWrittenOut(HandwrittenFixture):
    def test_the_refusal_names_the_file_and_the_same_request_finishes_it(self) -> None:
        """B530, N2: a change on disk to a file the version writes; discarded, the retry finishes."""

        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.seed()
            request = self.request()
            target = self.repo / "managed/proxies/shop.yaml"

            def in_the_way() -> None:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("written by hand\n", encoding="utf-8")

            code, document, _err = self.publish_while(policy, request, during=in_the_way)

            self.assertEqual((code, document["error"]["code"]), (75, "publish_incomplete"))
            self.assertIn("managed/proxies/shop.yaml", document["error"]["message"])
            self.assertIn("run the same request again", document["error"]["message"])
            target.unlink()
            request.seek(0)
            code, document, _err = self.publish_while(policy, request)
            self.assertEqual(code, 0, document)
            self.assertEqual(git(self.repo, "status", "--porcelain"), "")


class APublishStoppedBeforeItMovedTheIndex(HandwrittenFixture):
    def test_the_same_request_points_the_index_at_the_version(self) -> None:
        """B530, H02 b / N4: a new file, and the index left at the version before."""

        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.seed()
            (self.repo / "core/conf.d").mkdir(parents=True, exist_ok=True)
            (self.repo / "core/conf.d/0020-new.cfg").write_text(
                "frontend extra\n  bind 192.0.2.20:82\n", encoding="utf-8"
            )
            request = self.hand_request()
            first, document, _err = self.publish_while(policy, request)
            self.assertEqual(first, 0, document)
            git(self.repo, "reset", "-q", "--mixed", "HEAD~1")
            self.assertIn("?? core/conf.d/0020-new.cfg", git(self.repo, "status", "--porcelain"))
            request.seek(0)

            code, document, _err = self.publish_while(policy, request)

            self.assertEqual(code, 0, document)
            self.assertEqual(git(self.repo, "status", "--porcelain"), "")


class ADraftThatCannotBeRead(HandwrittenFixture):
    """B530, N4: a reading that failed is said as one, on every path."""

    def test_the_publish_answers_handwritten_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.seed()
            (self.repo / "core/haproxy.cfg").write_bytes(EDITED)
            request = self.hand_request()
            broken = handwritten.HandwrittenUnreadable("the draft area cannot be opened")
            with mock.patch.object(handwritten, "read_layers", side_effect=broken):
                code, document, _err = self.publish_while(policy, request)
            with mock.patch.object(handwritten, "read_draft", side_effect=broken):
                saved, said, _err = self.publish_objects(policy, self.request())

            self.assertEqual(document["error"]["code"], "handwritten_unavailable")
            self.assertEqual(said["error"]["code"], "handwritten_unavailable")
            self.assertNotEqual(code, 0)
            self.assertNotEqual(saved, 0)


class WhatOnlyGitSees(HandwrittenFixture):
    """A difference that is no content - a mode, an index - holds no publish back (B530, H02)."""

    def test_a_mode_change_holds_no_publish_back(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.seed()
            os.chmod(self.repo / "core/haproxy.cfg", 0o700)
            # Git sees the change, or the test proves nothing (review 26-11-24, PW10):
            # with core.fileMode=false the mode would pass unseen.
            self.assertIn("mode change", git(self.repo, "diff", "--summary"))

            code, document, _err = self.publish_objects(policy, self.request())

            self.assertEqual(code, 0, document)

    def test_an_index_staged_by_hand_is_pointed_back_at_the_version(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.seed()
            (self.repo / "core/haproxy.cfg").write_bytes(EDITED)
            git(self.repo, "add", "core/haproxy.cfg")
            (self.repo / "core/haproxy.cfg").write_bytes(HAPROXY_CFG)

            code, document, _err = self.publish_objects(policy, self.request())

            self.assertEqual(code, 0, document)
            self.assertEqual(git(self.repo, "status", "--porcelain"), "")

    def test_names_git_would_quote_are_published_from_the_page(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.seed()
            (self.repo / "core/blocked ips.map").write_text("192.0.2.1\n", encoding="utf-8")
            (self.repo / "core/v\u00e4xj\u00f6.map").write_text("x\n", encoding="utf-8")

            refused, said, _err = self.publish_objects(policy, self.request())
            code, document, _err = self.publish_while(policy, self.hand_request())

            self.assertEqual(refused, 75)
            self.assertIn("core/blocked ips.map", said["error"]["message"])
            self.assertIn("Handwritten changes", said["error"]["message"])
            self.assertEqual(code, 0, document)


class APublishOfSavedChangesKeepsAHandEdit(HandwrittenFixture):
    def test_a_file_written_during_the_publish_is_still_there_after_it(self) -> None:
        """The version is written out by what it changed, not by a hard reset (B530, H03)."""

        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.seed()

            code, document, _err = self.publish_while(
                policy,
                self.request(),
                during=lambda: (self.repo / "core/haproxy.cfg").write_bytes(EDITED),
            )

            self.assertEqual(code, 0, document)
            self.assertEqual((self.repo / "core/haproxy.cfg").read_bytes(), EDITED)
            self.assertEqual(git(self.repo, "status", "--porcelain"), "M core/haproxy.cfg")
            self.assertTrue((self.repo / "managed/proxies/shop.yaml").is_file())


class TheSameRequestAgain(HandwrittenFixture):
    def test_it_finishes_the_version_it_recorded_and_leaves_a_newer_edit_waiting(self) -> None:
        """B530, H05: the version's own files, not the draft as it is now."""

        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.seed()
            (self.repo / "core/haproxy.cfg").write_bytes(EDITED)
            request = self.hand_request()
            first, _document, _err = self.publish_while(policy, request)
            recorded = git(self.repo, "rev-parse", "HEAD")
            later = EDITED.replace(b"stick-counters 6", b"stick-counters 7")
            (self.repo / "core/haproxy.cfg").write_bytes(later)
            request.seek(0)

            code, document, _err = self.publish_while(policy, request)

            self.assertEqual((first, code), (0, 0), document)
            self.assertEqual(git(self.repo, "rev-parse", "HEAD"), recorded)
            self.assertEqual((self.repo / "core/haproxy.cfg").read_bytes(), later)
            self.assertEqual(git(self.repo, "status", "--porcelain"), "M core/haproxy.cfg")


class SavedChangesWhileHandwrittenFilesWait(HandwrittenFixture):
    def test_the_refusal_names_the_files_and_where_they_are_published(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.seed()
            (self.repo / "core/haproxy.cfg").write_bytes(EDITED)

            code, document, _err = self.publish_objects(policy, self.request())

            self.assertEqual((code, document["error"]["code"]), (75, "dirty_worktree"))
            message = document["error"]["message"]
            self.assertIn("core/haproxy.cfg", message)
            self.assertIn("Handwritten changes", message)
            self.assertIn('haprion-publish -c alpha "<comment>"', message)


if __name__ == "__main__":
    unittest.main()
