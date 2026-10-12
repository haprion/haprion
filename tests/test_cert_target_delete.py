"""``haprion-cert-target`` and ``haprion-cert-delete``: the terminal's clients (Fas 23).

The helpers' decisions are held in their own tests; this holds what the
commands send and what they make of the answer - above all that a
certificate already gone counts as deleted, so the same delete twice is
not a failure the second time.
"""

from __future__ import annotations

import io
import json
import subprocess
import unittest
from pathlib import Path
from typing import Any

from haprion.cli import cert_delete, cert_target

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def answering(document: dict[str, Any], code: int, sent: list[dict[str, Any]]) -> Any:
    def run(argv: list[str], request: str) -> subprocess.CompletedProcess[str]:
        sent.append({"argv": argv, "request": json.loads(request)})
        return subprocess.CompletedProcess(argv, code, json.dumps(document), "")

    return run


def gone(*ids: str, removed: tuple[str, ...] = ()) -> dict[str, Any]:
    document: dict[str, Any] = json.loads(
        (FIXTURES / "haprion-cert-delete/valid/done.json").read_text()
    )
    document["result"]["certificates"] = [
        {"certificate": name, "state": "removed"} for name in removed
    ] + [
        {
            "certificate": name,
            "state": "refused",
            "code": "not_registered",
            "reason": "not in the registry, and nothing of it remains on the manager or the nodes",
        }
        for name in ids
    ]
    return document


class TheTargetCommand(unittest.TestCase):
    def test_it_sends_one_delta_for_the_selection(self) -> None:
        sent: list[dict[str, Any]] = []
        answer = json.loads((FIXTURES / "haprion-cert-target/valid/done.json").read_text())
        out = io.StringIO()

        code = cert_target.main(
            ["add", "shop", "api", "--cluster", "beta", "--receiver", "rx", "--format", "rx=pem"],
            run=answering(answer, 0, sent),
            stream_out=out,
        )

        self.assertEqual(code, 0)
        parameters = sent[0]["request"]["parameters"]
        self.assertEqual(parameters["certificates"], ["shop", "api"])
        self.assertEqual(
            parameters["add"], {"clusters": ["beta"], "receivers": ["rx"], "formats": {"rx": "pem"}}
        )
        self.assertTrue(parameters["deploy"])
        self.assertTrue(sent[0]["argv"][-1].endswith("haprion-cert-target-helper"))

    def test_a_target_is_required(self) -> None:
        err = io.StringIO()

        code = cert_target.main(["remove", "shop"], run=answering({}, 0, []), stream_err=err)

        self.assertEqual(code, 64)
        self.assertIn("--cluster or --receiver", err.getvalue())

    def test_json_is_the_helpers_envelope(self) -> None:
        answer = json.loads((FIXTURES / "haprion-cert-target/valid/partial.json").read_text())
        out = io.StringIO()

        cert_target.main(
            ["remove", "shop", "--cluster", "beta", "--json"],
            run=answering(answer, 0, []),
            stream_out=out,
        )

        self.assertEqual(json.loads(out.getvalue()), answer)


class TheDeleteCommand(unittest.TestCase):
    def test_already_gone_is_done(self) -> None:
        code = cert_delete.main(
            ["shop", "api"],
            run=answering(gone("api", removed=("shop",)), 65, []),
            stream_out=io.StringIO(),
        )

        self.assertEqual(code, 0)

    def test_another_refusal_keeps_the_helpers_code(self) -> None:
        document = gone("api")
        document["result"]["certificates"][0]["code"] = "in_use"

        code = cert_delete.main(["api"], run=answering(document, 65, []), stream_out=io.StringIO())

        self.assertEqual(code, 65)

    def test_no_answer_is_unavailable(self) -> None:
        def silent(argv: list[str], request: str) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(argv, 0, "", "sudo: a password is required\n")

        err = io.StringIO()
        code = cert_delete.main(["api"], run=silent, stream_out=io.StringIO(), stream_err=err)

        self.assertEqual(code, 69)
        self.assertIn("password", err.getvalue())


if __name__ == "__main__":
    unittest.main()
