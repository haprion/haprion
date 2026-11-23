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

from haprion import handwritten
from haprion.candidate_validation import ValidationResult
from haprion.cli import changes_publish, managed_helper
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
    def test_the_first_line_keeps_its_path_when_the_answer_was_stripped(self) -> None:
        """`unsaved_changes` strips; " M managed/x" arrived as "M managed/x" (26-11-23)."""

        stripped = " M managed/network.yaml\n?? managed/proxies/new.yaml".strip()

        self.assertEqual(
            managed_helper._paths(stripped),
            ["managed/network.yaml", "managed/proxies/new.yaml"],
        )
        self.assertTrue(managed_helper._only_managed(stripped))
        self.assertTrue(managed_helper._only_handwritten("M core/haproxy.cfg"))
        self.assertEqual(
            managed_helper._paths("R  core/a.cfg -> core/b.cfg"),
            ["core/b.cfg"],
        )


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
