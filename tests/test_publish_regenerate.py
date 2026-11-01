"""`haprion-publish --regenerate` publishes the generated layer made again, as the page's button does."""

from __future__ import annotations

import io
import json
import subprocess
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from haprion import exit_codes
from haprion.cli import publish, publish_regenerate
from haprion.envelope import envelope
from tests.contract_schema import assert_contract

HEAD = "a" * 40
FINGERPRINT = "f" * 64
CHANGED: dict[str, Any] = {
    "outcome": "changed",
    "fingerprint": FINGERPRINT,
    "published_commit": "c" * 40,
    "published_version": 3,
    "installed_version": "9.9.9",
    "managed": True,
    "message": None,
    "causes": [],
    "objects": [{"name": "shop", "change": "changed", "parts": ["routing"]}],
    "files_changed": 2,
    "diff": None,
}
PUBLISHED: dict[str, Any] = envelope(
    operation="changes_publish",
    outcome="done",
    cluster="alpha",
    request_id="11111111-1111-4111-8111-111111111111",
    result={
        "changed": True,
        "version": 7,
        "hash": "b" * 40,
        "published_at": "2026-11-01T10:00:00Z",
        "comment": "Regenerated with the installed version.",
        "deployment_required": True,
        "next_command": "haprion-deploy -c alpha",
        "release": "20261101-100000",
        "already_current": False,
        "objects": [],
        "removed": [],
        "network": False,
        "settings": False,
        "regenerate": True,
    },
)


class Terminal:
    def __init__(self, reading: dict[str, Any] | None = CHANGED, answer: Any = PUBLISHED) -> None:
        self.reading, self.answer, self.sent = reading, answer, []
        self.out, self.err = io.StringIO(), io.StringIO()

    def run(self, request: str) -> subprocess.CompletedProcess[str]:
        self.sent.append(json.loads(request))
        if self.answer is None:
            return subprocess.CompletedProcess([], 1, "", "sudo: a password is required\n")
        failed = self.answer["outcome"] != "done"
        return subprocess.CompletedProcess([], 65 if failed else 0, json.dumps(self.answer), "")

    def __call__(self, *argv: str) -> int:
        with (
            mock.patch.object(publish_regenerate, "is_repo_root", return_value=True),
            mock.patch.object(publish_regenerate, "resolve_head", return_value=("main", HEAD)),
        ):
            return publish_regenerate.main(
                list(argv),
                stream_out=self.out,
                stream_err=self.err,
                config_path=lambda _cluster: Path("/config/alpha"),
                read_regeneration=lambda _cluster: self.reading,
                run_publish=self.run,
            )


class PublishingTheRegeneration(unittest.TestCase):
    def test_the_request_carries_the_flag_and_no_part_fenced_on_the_head_just_read(self) -> None:
        terminal = Terminal()

        code = terminal("-c", "alpha", "--regenerate")

        self.assertEqual(code, 0)
        (request,) = terminal.sent
        self.assertEqual(request["operation"], "changes_publish")
        self.assertEqual(
            request["parameters"],
            {
                "expected_head": HEAD,
                "comment": "Regenerated with the installed version.",
                "allow_certificate_mismatch": False,
                "regenerate": True,
            },
        )
        self.assertIn("Published version 7 of alpha.", terminal.out.getvalue())
        self.assertIn("haprion-deploy -c alpha", terminal.out.getvalue())

    def test_haprion_publish_hands_the_flag_over(self) -> None:
        argv = ["-c", "alpha", "--regenerate", "-m", "After the upgrade"]
        with mock.patch.object(publish_regenerate, "main", return_value=0) as handed:
            code = publish.main(argv, stream_out=io.StringIO(), stream_err=io.StringIO())

        self.assertEqual(code, 0)
        self.assertEqual(handed.call_args.args[0], argv)

    def test_the_certificate_override_is_sent_only_when_asked_for(self) -> None:
        terminal = Terminal()

        terminal("-c", "alpha", "--regenerate", "--allow-certificate-mismatch")

        self.assertIs(terminal.sent[0]["parameters"]["allow_certificate_mismatch"], True)

    def test_check_says_what_would_change_and_publishes_nothing(self) -> None:
        terminal = Terminal()

        code = terminal("-c", "alpha", "--regenerate", "--check")

        self.assertEqual(code, 0)
        self.assertEqual(terminal.sent, [])
        shown = terminal.out.getvalue()
        self.assertIn("A publish would change what runs: 2 files; objects: shop (routing)", shown)
        self.assertIn(f"Fingerprint: {FINGERPRINT}", shown)

    def test_check_with_json_is_the_regeneration_document(self) -> None:
        terminal = Terminal()

        terminal("-c", "alpha", "--regenerate", "--check", "--json")

        document = assert_contract("haprion-regeneration", terminal.out.getvalue())
        self.assertEqual(document["result"]["fingerprint"], FINGERPRINT)

    def test_a_reading_that_is_not_the_one_expected_publishes_nothing(self) -> None:
        terminal = Terminal()

        code = terminal("-c", "alpha", "--regenerate", "--expect", "e" * 64)

        self.assertEqual(code, exit_codes.BLOCKED)
        self.assertEqual(terminal.sent, [])
        self.assertIn("Read it again", terminal.err.getvalue())

    def test_the_reading_that_is_expected_is_published(self) -> None:
        terminal = Terminal()

        code = terminal("-c", "alpha", "--regenerate", "--expect", FINGERPRINT)

        self.assertEqual(code, 0)
        self.assertEqual(len(terminal.sent), 1)

    def test_a_reading_that_cannot_be_had_stops_an_expected_publish(self) -> None:
        terminal = Terminal(reading=None)

        code = terminal("-c", "alpha", "--regenerate", "--expect", FINGERPRINT)

        self.assertEqual(code, exit_codes.UNAVAILABLE)
        self.assertEqual(terminal.sent, [])

    def test_the_helper_s_refusal_is_said_in_its_words(self) -> None:
        terminal = Terminal(
            answer={
                **{k: v for k, v in PUBLISHED.items() if k != "result"},
                "outcome": "failed",
                "result": None,
                "error": {"code": "changes_invalid", "message": "shop: the certificate lacks it"},
            }
        )

        code = terminal("-c", "alpha", "--regenerate")

        self.assertEqual(code, exit_codes.REFUSED)
        self.assertIn("shop: the certificate lacks it", terminal.err.getvalue())

    def test_nothing_to_publish_is_said_and_is_not_a_failure(self) -> None:
        answer = json.loads(json.dumps(PUBLISHED))
        answer["result"]["changed"] = False
        terminal = Terminal(answer=answer)

        code = terminal("-c", "alpha", "--regenerate")

        self.assertEqual(code, 0)
        self.assertIn("nothing was published", terminal.out.getvalue())

    def test_json_is_the_helper_s_document(self) -> None:
        terminal = Terminal()

        code = terminal("-c", "alpha", "--regenerate", "--json")

        self.assertEqual(code, 0)
        document = assert_contract("haprion-changes-publish", terminal.out.getvalue())
        self.assertIs(document["result"]["regenerate"], True)

    def test_json_is_one_document_when_the_helper_never_answered(self) -> None:
        terminal = Terminal(answer=None)

        code = terminal("-c", "alpha", "--regenerate", "--json")

        self.assertEqual(code, exit_codes.UNAVAILABLE)
        self.assertEqual(len(terminal.out.getvalue().splitlines()), 1)
        assert_contract("haprion-changes-publish", terminal.out.getvalue())


if __name__ == "__main__":
    unittest.main()
