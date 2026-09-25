"""The worker's side of the receiver socket (B163), tried against a real socket.

Not a mock, for the reason `test_probe_socket` gives: what broke in production
was the transport - a helper run through sudo inside a sandbox that keeps
`/etc` read-only - and a test that stubs the transport is the test that misses
it. So these listen on a real unix socket in a temporary directory.

What has to hold:

- the request goes across whole, and the answer comes back whole and untouched:
  it is the helper's document, and the worker judges it
- the exit status says whether an answer was had, from what the answer says
- nothing listening is an envelope naming the missing unit, never `unknown`
- the client is as argument-free as the helper is
"""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path

from haproxy_mgmt.cli import cert_receiver_ask
from haproxy_mgmt.cli.cert_receiver_helper import build_request
from tests.test_probe_socket import Listener


def run(request: str, **options: object) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = cert_receiver_ask.main(
        [],
        input_stream=io.BytesIO(request.encode("utf-8")),
        output_stream=out,
        error_stream=err,
        timeout=2.0,
        **options,  # type: ignore[arg-type]
    )
    return code, out.getvalue(), err.getvalue()


def answer(outcome: str, **extra: object) -> bytes:
    return (
        json.dumps(
            {
                "schema_version": 1,
                "operation": "cert_receiver",
                "outcome": outcome,
                "cluster": None,
                "request_id": "r-1",
                "result": None,
                "warnings": [],
                "error": None,
            }
            | extra
        )
        + "\n"
    ).encode("utf-8")


class AcrossTheSocket(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = str(Path(self.directory.name) / "cert-receiver.sock")
        self.request = build_request("r-1", receiver="lb-02.example.net", action="remove")

    def test_the_request_arrives_whole_and_the_answer_is_passed_through(self) -> None:
        listener = Listener(self.path, answer("done"))
        self.addCleanup(listener.close)

        code, out, err = run(self.request, socket_path=self.path)

        self.assertEqual(code, 0)
        self.assertEqual(json.loads(listener.received), json.loads(self.request))
        self.assertEqual(out.encode("utf-8"), answer("done"))
        self.assertEqual(err, "")

    def test_a_refusal_is_passed_through_and_the_exit_status_says_so(self) -> None:
        listener = Listener(self.path, answer("failed", error={"code": "unknown_receiver"}))
        self.addCleanup(listener.close)

        code, out, _ = run(self.request, socket_path=self.path)

        self.assertEqual(code, cert_receiver_ask.EXIT_REFUSED)
        self.assertEqual(json.loads(out)["error"], {"code": "unknown_receiver"})

    def test_a_partial_removal_is_an_answer_too(self) -> None:
        listener = Listener(self.path, answer("partial"))
        self.addCleanup(listener.close)

        code, _, _ = run(self.request, socket_path=self.path)

        self.assertEqual(code, 0)

    def test_nothing_listening_is_an_envelope_that_names_the_unit(self) -> None:
        code, out, err = run(self.request, socket_path=self.path)

        self.assertEqual(code, cert_receiver_ask.EXIT_UNAVAILABLE)
        document = json.loads(out)
        self.assertEqual(document["outcome"], "failed")
        self.assertEqual(document["operation"], "cert_receiver")
        self.assertEqual(document["request_id"], "r-1")
        self.assertEqual(document["error"]["code"], "dependency_unavailable")
        self.assertIn("haproxy-cert-receiver-helper.socket", document["error"]["message"])
        self.assertIn("not installed", err)

    def test_a_service_that_never_answers_is_given_up_on_without_a_verdict(self) -> None:
        """Asked and silent is not "failed": the root service may have acted.

        No document, so the worker records the job as `unknown`; the sentence
        goes to stderr, which the job keeps (review 2026-09-25, finding 1).
        """

        listener = Listener(self.path, None)
        self.addCleanup(listener.close)

        code, out, err = run(self.request, socket_path=self.path)

        self.assertEqual(code, cert_receiver_ask.EXIT_SILENT)
        self.assertEqual(out, "")
        self.assertIn("[helper_silent]", err)
        self.assertIn("did not answer in time", err)
        self.assertNotIn("Install", err)


class WhatItRefusesItself(unittest.TestCase):
    def test_no_command_line_arguments(self) -> None:
        err = io.StringIO()
        code = cert_receiver_ask.main(
            ["--socket", "/tmp/x"], input_stream=io.BytesIO(b"{}"), error_stream=err
        )

        self.assertEqual(code, 64)
        self.assertIn("no command-line arguments", err.getvalue())

    def test_a_request_without_a_request_id_cannot_be_answered_for(self) -> None:
        code, out, err = run('{"operation": "cert_receiver"}', socket_path="/nonexistent")

        self.assertEqual(code, 64)
        self.assertEqual(out, "")
        self.assertIn("request_id", err)

    def test_a_request_that_is_not_json_is_refused_before_the_socket(self) -> None:
        code, _, err = run("not json", socket_path="/nonexistent")

        self.assertEqual(code, 64)
        self.assertIn("ERROR", err)
