"""The three privileged publishing loops answer the same failure the same way.

`publish_helper`, `managed_helper` and `revert_helper` each wrap the cluster's
lock in their own `try` chain. They drifted: one caught a sandbox preparation
failure and two did not, and the third's candidate limit was caught by none.
A failure the loop does not map reaches the worker as a traceback and no
document, which it stores as `unknown` - "may have acted" - for a refusal that
wrote nothing. One case per failure, run through every loop, keeps them level.
"""

from __future__ import annotations

import json
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any
from unittest import mock

from haprion import exit_codes, tls_policy
from haprion.candidate_validation import Limits
from haprion.helper_protocol import HelperProtocolError
from tests.contract_schema import assert_contract
from tests.test_changes_publish_objects import ObjectsPublishFixture, proxy
from tests.test_publish_helper import HAPROXY_CFG, PublishFixture, git
from tests.test_revert import RevertFixture


def code_of(document: dict[str, Any]) -> Any:
    """The refusal's code, or what went wrong instead of a refusal."""

    error = document.get("error")
    if isinstance(error, dict):
        return error.get("code")
    return document.get("raised") or document.get("no_document") or document.get("outcome")


LOOPS = ("publish", "managed", "revert")
STALE_CFG = HAPROXY_CFG.replace(f"  {tls_policy.DEFAULT_PATH_LINE}\n".encode(), b"")


class LoopTests(RevertFixture, ObjectsPublishFixture):
    """Each loop is driven to the same failure; `answer` is the envelope it wrote."""

    def answer(self, loop: str, policy: Path) -> dict[str, Any]:
        if loop == "publish":
            self.edit("core/conf.d/0010-core.cfg", b"frontend core\n  bind 192.0.2.20:82\n")
            code, stdout, _err = self.run_publish(policy, PublishFixture.request(self))
        elif loop == "managed":
            self.seed()
            code, document, _err = self.publish_objects(policy, ObjectsPublishFixture.request(self))
            stdout = json.dumps(document) if document is not None else ""
        else:
            self.history(3)
            _text, stdout = self.revert_to(policy, 2)
        if not stdout:
            return {"no_document": True}
        document = json.loads(stdout)
        assert isinstance(document, dict)
        return document

    def revert_to(self, policy: Path, version: int) -> tuple[str, str]:
        _code, text = self.run_caller(policy, "-c", "alpha", str(version))
        return text, self.helper_stdout

    def each_loop(self, setup: Callable[[Path], None]) -> dict[str, dict[str, Any]]:
        answers: dict[str, dict[str, Any]] = {}
        for loop in LOOPS:
            with tempfile.TemporaryDirectory() as raw:
                policy = self.runtime(Path(raw))
                setup(Path(raw))
                try:
                    answers[loop] = self.answer(loop, policy)
                except Exception as exc:  # noqa: BLE001 - what a worker would store as `unknown`
                    answers[loop] = {"raised": f"{type(exc).__name__}: {exc}"}
        return answers

    def test_an_unreadable_validation_certificate_is_a_refusal_in_every_loop(self) -> None:
        answers = self.each_loop(lambda raw: (raw / "validation-certs/validation.pem").unlink())

        for loop, document in answers.items():
            with self.subTest(loop):
                self.assertEqual(code_of(document), "dependency_unavailable")

    def test_a_candidate_over_the_limit_is_a_refusal_in_every_loop(self) -> None:
        too_big = HelperProtocolError(
            "candidate contains too many files", exit_code=exit_codes.REFUSED
        )
        with (
            mock.patch("haprion.cli.publish_helper.candidate_from_files", side_effect=too_big),
            mock.patch("haprion.cli.managed_helper.candidate_from_files", side_effect=too_big),
            mock.patch("haprion.cli.revert_helper.candidate_from_files", side_effect=too_big),
        ):
            answers = self.each_loop(lambda raw: None)

        for loop, document in answers.items():
            with self.subTest(loop):
                self.assertEqual(code_of(document), "bad_input")

    def test_a_derived_candidate_over_its_limit_is_a_refusal_in_every_loop(self) -> None:
        """The cap that applies to a candidate the helper derived, reached for real."""

        tiny = Limits(files=1, total_bytes=1024)
        with (
            mock.patch("haprion.cli.publish_helper.DERIVED_LIMITS", tiny),
            mock.patch("haprion.cli.managed_helper.DERIVED_LIMITS", tiny),
            mock.patch("haprion.cli.revert_helper.DERIVED_LIMITS", tiny),
        ):
            answers = self.each_loop(lambda raw: None)

        for loop, document in answers.items():
            with self.subTest(loop):
                self.assertEqual(code_of(document), "bad_input")
                self.assertIn("too many files", document["error"]["message"])

    def test_a_cluster_of_five_hundred_objects_publishes(self) -> None:
        """The JSON ingress caps a request at 512 files; a derived candidate is not a request."""

        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.seed()
            for index in range(520):
                (self.repo / "managed/proxies").mkdir(parents=True, exist_ok=True)
                (self.repo / f"managed/proxies/site-{index}.yaml").write_text(
                    proxy(f"site-{index}", f"site{index}.example.com").replace("web", f"web{index}")
                )
            git(self.repo, "add", "-A")
            git(self.repo, "commit", "-qm", "many objects by hand")

            request = ObjectsPublishFixture.request(
                self, objects={"extra": proxy("extra", "extra.example.com").replace("web", "webx")}
            )
            code, document, _err = self.publish_objects(policy, request)

            self.assertEqual((code, document["outcome"]), (0, "done"))
            released = [path for path in self.publish_path.rglob("*.cfg") if path.is_file()]
            self.assertGreater(len(released), 512)

    def test_a_stale_core_stops_a_publish_and_only_warns_a_revert(self) -> None:
        """Going back to a release that was good must not depend on a file being current."""

        def stale(raw: Path) -> None:
            self.edit("core/haproxy.cfg", STALE_CFG)
            git(self.repo, "commit", "-qam", "A core without the TLS defaults")

        answers = self.each_loop(stale)

        for loop in ("publish", "managed"):
            with self.subTest(loop):
                self.assertEqual(code_of(answers[loop]), "tls_defaults_stale")

        revert = answers["revert"]
        self.assertEqual(revert.get("outcome"), "done")
        self.assertEqual(
            [warning["code"] for warning in revert["warnings"]], ["tls_defaults_stale"]
        )

    def test_a_revert_to_a_release_the_checks_dislike_warns_for_each_problem(self) -> None:
        """Stick counters and the traffic stream follow the same rule as the TLS lines."""

        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.edit(
                "managed/generated/1040-managed.cfg",
                b"frontend managed\n  bind 192.0.2.20:80\n"
                b"  http-request track-sc4 src table mgd-x-dynblock\n"
                b"  log /var/lib/haproxy/dev/haprion-traffic len 2048 format local"
                b" profile mgd-traffic-json local2\n",
            )
            self.edit(
                "core/haproxy.cfg",
                STALE_CFG.replace(b"  daemon\n", b"  daemon\n  chroot /srv/haproxy\n"),
            )
            git(self.repo, "commit", "-qam", "Version 2: three things wrong")
            self.history(3)

            _text, stdout = self.revert_to(policy, 2)

            document = assert_contract("haprion-revert", stdout)
            self.assertEqual(document["outcome"], "done")
            self.assertEqual(
                [warning["code"] for warning in document["warnings"]],
                ["stick_counters_short", "traffic_log_unreachable", "tls_defaults_stale"],
            )
            self.assertTrue(all(len(w["message"]) <= 1024 for w in document["warnings"]))

    def test_the_command_says_the_warnings_the_revert_carried(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.edit("core/haproxy.cfg", STALE_CFG)
            git(self.repo, "commit", "-qam", "A core without the TLS defaults")
            self.history(3)

            text, _stdout = self.revert_to(policy, 2)

            self.assertIn("WARNING: ", text)
            self.assertIn("is back on the content of version 2", text)
