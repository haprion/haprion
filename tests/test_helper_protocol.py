from __future__ import annotations

import io
import json
import os
import time
import unittest
from collections.abc import Mapping
from typing import Any

from haproxy_mgmt import helper_protocol
from haproxy_mgmt.helper_protocol import (
    HelperProtocolError,
    HelperRequest,
    JsonValue,
    read_helper_request,
    require_no_arguments,
)

REQUEST_ID = "11111111-1111-4111-8111-111111111111"


def request_bytes(**changes: object) -> bytes:
    request: dict[str, object] = {
        "schema_version": 1,
        "operation": "status",
        "cluster": "alpha",
        "request_id": REQUEST_ID,
        "parameters": {},
    }
    request.update(changes)
    return json.dumps(request).encode()


class HelperProtocolTests(unittest.TestCase):
    def read(self, raw: bytes, **kwargs: Any) -> HelperRequest:
        return read_helper_request(io.BytesIO(raw), expected_operation="status", **kwargs)

    def test_valid_exact_request(self) -> None:
        result = self.read(request_bytes())
        self.assertEqual(result.operation, "status")
        self.assertEqual(result.cluster, "alpha")
        self.assertEqual(result.request_id, REQUEST_ID)
        self.assertEqual(result.parameters, {})

    def test_no_argument_boundary(self) -> None:
        require_no_arguments([])
        with self.assertRaisesRegex(HelperProtocolError, "no command-line arguments"):
            require_no_arguments(["--cluster", "alpha"])

    def test_empty_malformed_trailing_and_multiple_documents_are_rejected(self) -> None:
        invalid_documents = (
            b"",
            b"not JSON",
            request_bytes() + b" trailing",
            request_bytes() + b"\n" + request_bytes(),
        )
        for raw in invalid_documents:
            with self.subTest(raw=raw), self.assertRaises(HelperProtocolError):
                self.read(raw)

    def test_oversized_and_invalid_utf8_are_rejected(self) -> None:
        with self.assertRaisesRegex(HelperProtocolError, "size limit"):
            self.read(b"{}" * 5, max_bytes=8)
        with self.assertRaisesRegex(HelperProtocolError, "UTF-8"):
            self.read(b"\xff")

    def test_duplicate_and_unknown_fields_are_rejected(self) -> None:
        duplicate = (
            b'{"schema_version":1,"operation":"status","operation":"status",'
            b'"cluster":"alpha","request_id":"' + REQUEST_ID.encode() + b'","parameters":{}}'
        )
        with self.assertRaisesRegex(HelperProtocolError, "duplicate JSON field"):
            self.read(duplicate)
        with self.assertRaisesRegex(HelperProtocolError, "unknown field"):
            self.read(request_bytes(extra=True))

    def test_non_finite_numbers_are_rejected(self) -> None:
        raw = request_bytes().replace(b'"parameters": {}', b'"parameters": {"value": NaN}')
        with self.assertRaisesRegex(HelperProtocolError, "non-finite"):
            self.read(raw, allowed_parameter_keys=frozenset({"value"}))

    def test_wrong_schema_operation_cluster_and_request_id_are_rejected(self) -> None:
        invalid = (
            (request_bytes(schema_version=True), "schema_version"),
            (request_bytes(operation="deploy"), "operation"),
            (request_bytes(cluster="../alpha"), "cluster"),
            (request_bytes(request_id="not-a-uuid"), "request_id"),
        )
        for raw, message in invalid:
            with (
                self.subTest(message=message),
                self.assertRaisesRegex(HelperProtocolError, message),
            ):
                self.read(raw)

    def test_parameters_are_exact_and_support_operation_validation(self) -> None:
        with self.assertRaisesRegex(HelperProtocolError, "unknown field"):
            self.read(request_bytes(parameters={"path": "/tmp/candidate"}))

        seen: list[object] = []

        def validate(parameters: Mapping[str, JsonValue]) -> None:
            seen.append(parameters["target"])

        result = self.read(
            request_bytes(parameters={"target": "node-a"}),
            allowed_parameter_keys=frozenset({"target"}),
            validate_parameters=validate,
        )
        self.assertEqual(result.parameters, {"target": "node-a"})
        self.assertEqual(seen, ["node-a"])


if __name__ == "__main__":
    unittest.main()


class RequestFraming(unittest.TestCase):
    """The request ends at a line ending, and stdin stays open afterwards.

    Reading to EOF would make closing stdin the only way to finish a request,
    and that closes the one channel that survives sudo. Keeping it open is what
    lets a caller say "I have let go" later - including by dying, where the
    kernel says it and no code has to run.

    The EOF-terminated case is kept working on purpose. It is what a caller that
    has not been rebuilt yet still sends, and it is why the engine can be rolled
    out before the interface rather than in lockstep.
    """

    def read(self, raw: bytes, **kwargs: Any) -> HelperRequest:
        return read_helper_request(io.BytesIO(raw), expected_operation="status", **kwargs)

    def test_a_line_ended_request_is_accepted(self) -> None:
        self.assertEqual(self.read(request_bytes() + b"\n").cluster, "alpha")

    def test_an_eof_ended_request_is_still_accepted(self) -> None:
        self.assertEqual(self.read(request_bytes()).cluster, "alpha")

    def test_what_follows_the_line_is_left_on_the_stream(self) -> None:
        stream = io.BytesIO(request_bytes(lifeline=True) + b"\nthe lifeline")
        read_helper_request(stream, expected_operation="status", lifeline=True)
        self.assertEqual(stream.read(), b"the lifeline")

    def test_a_second_line_is_not_read_as_part_of_the_request(self) -> None:
        stream = io.BytesIO(
            request_bytes(lifeline=True) + b"\n" + request_bytes(lifeline=True) + b"\n"
        )
        first = read_helper_request(stream, expected_operation="status", lifeline=True)
        self.assertEqual(first.cluster, "alpha")
        self.assertTrue(stream.read().startswith(b"{"))

    def test_the_limit_counts_the_request_and_not_its_line_ending(self) -> None:
        exact = b'{"a": 1}'
        with self.assertRaisesRegex(HelperProtocolError, "size limit"):
            self.read(exact + b"x\n", max_bytes=len(exact))
        # The same document, at the limit, fails on its content rather than its
        # size - which is what proves the line ending was not counted.
        with self.assertRaisesRegex(HelperProtocolError, "missing field"):
            self.read(exact + b"\n", max_bytes=len(exact))

    def test_without_a_lifeline_anything_after_the_request_is_refused(self) -> None:
        with self.assertRaisesRegex(HelperProtocolError, "followed by more input"):
            self.read(request_bytes() + b"\n" + request_bytes())

    def test_a_caller_that_says_nothing_gets_the_old_behaviour(self) -> None:
        """The rollout depends on this one.

        A helper that watched stdin without being told would read the immediate
        EOF from a caller that has not been rebuilt as "the caller let go", and
        abort every operation - during exactly the window the rollout order
        creates. An undeclared lifeline must therefore mean no lifeline.
        """

        result = read_helper_request(
            io.BytesIO(request_bytes()), expected_operation="status", lifeline=True
        )
        self.assertFalse(result.lifeline)

    def test_a_helper_without_a_lifeline_refuses_a_request_that_wants_one(self) -> None:
        with self.assertRaisesRegex(HelperProtocolError, "does not support a lifeline"):
            self.read(request_bytes(lifeline=True))

    def test_the_lifeline_field_must_be_a_boolean(self) -> None:
        with self.assertRaisesRegex(HelperProtocolError, "must be true or false"):
            self.read(request_bytes(lifeline="yes"))

    def test_an_empty_line_is_an_empty_request(self) -> None:
        with self.assertRaisesRegex(HelperProtocolError, "empty"):
            self.read(b"\n")


class TheLifeline(unittest.TestCase):
    """Watching the caller's stdin, with real pipes.

    Real file descriptors rather than BytesIO: EOF on a pipe whose write end is
    still open is precisely what a mock gets wrong, and it is the whole point -
    a lifeline that reported "released" while the caller was alive would abort
    every operation instead of none.
    """

    def lifeline(self, read_fd: int) -> helper_protocol.Lifeline:
        stream = os.fdopen(read_fd, "rb", buffering=0)
        self.addCleanup(stream.close)
        line = helper_protocol.Lifeline(stream.fileno())
        line.watch()
        return line

    def settle(self, line: helper_protocol.Lifeline, *, expected: bool) -> None:
        for _ in range(200):
            if line.released == expected:
                return
            time.sleep(0.005)
        self.fail(f"the lifeline never became released={expected}")

    def test_a_held_lifeline_is_not_released(self) -> None:
        read_fd, write_fd = os.pipe()
        self.addCleanup(os.close, write_fd)
        line = self.lifeline(read_fd)
        time.sleep(0.05)
        self.assertFalse(line.released)

    def test_closing_the_write_end_releases_it(self) -> None:
        read_fd, write_fd = os.pipe()
        line = self.lifeline(read_fd)
        os.close(write_fd)
        self.settle(line, expected=True)
        self.assertEqual(line.reason, "the caller closed the lifeline")

    def test_input_on_the_lifeline_releases_it_too(self) -> None:
        read_fd, write_fd = os.pipe()
        self.addCleanup(os.close, write_fd)
        line = self.lifeline(read_fd)
        os.write(write_fd, b"x")
        self.settle(line, expected=True)
        self.assertEqual(line.reason, "unexpected input arrived on the lifeline")

    def test_asking_why_before_it_is_released_is_a_mistake(self) -> None:
        read_fd, write_fd = os.pipe()
        self.addCleanup(os.close, write_fd)
        line = self.lifeline(read_fd)
        with self.assertRaises(RuntimeError):
            _ = line.reason


class TakingTheLifelineOffStandardInput(unittest.TestCase):
    """A child must not inherit the lifeline, and not by anyone remembering.

    Found by measurement on 2026-08-31: with the lifeline left on descriptor 0,
    ssh inherited it and forwarded it to the node, where the remote command
    waited for an end of input that only came when the worker let go. A no-op
    deploy went from 0.58s to 3.42s - the cheap symptom of every child of a
    helper being handed the caller's pipe.

    Run in a forked child, because the whole operation is about descriptor 0 of
    the process it runs in.
    """

    def test_descriptor_zero_becomes_empty_and_the_lifeline_survives(self) -> None:
        read_fd, write_fd = os.pipe()
        report_read, report_write = os.pipe()

        pid = os.fork()
        if pid == 0:  # pragma: no cover - the child never returns to the runner
            code = 1
            try:
                os.dup2(read_fd, 0)
                stream = os.fdopen(0, "rb", buffering=0)
                line = helper_protocol.Lifeline.take(stream)

                # Descriptor 0 is now empty for this process and every child of
                # it: a read returns end of input at once instead of blocking.
                inherited = os.read(0, 1)

                line.watch()
                os.close(write_fd)
                for _ in range(200):
                    if line.released:
                        break
                    time.sleep(0.005)

                os.write(report_write, b"1" if (inherited == b"" and line.released) else b"0")
                code = 0
            finally:
                os._exit(code)

        os.close(report_write)
        os.close(write_fd)
        _, status = os.waitpid(pid, 0)
        answer = os.read(report_read, 1)
        os.close(report_read)
        os.close(read_fd)

        self.assertEqual(os.waitstatus_to_exitcode(status), 0)
        self.assertEqual(answer, b"1", "stdin was not emptied, or the lifeline did not survive")


class TheRequestWithNoCluster(unittest.TestCase):
    """The second request shape, for operations whose scope is not a cluster.

    Kept apart from `read_helper_request` rather than expressed as an optional
    field on it, and these tests are where that separation is measured: the
    cluster reader must still refuse a null, and the clusterless reader must
    still refuse a cluster. Either one accepting both would make the absence
    something a caller could introduce by leaving a field out.
    """

    def request(self, **overrides: object) -> io.BytesIO:
        document = {
            "schema_version": 1,
            "operation": "cert_publish",
            "cluster": None,
            "request_id": "8f1d4d3e-0e3e-4f67-8a0b-5d0a5b6a7c8d",
            "parameters": {"deploy": False},
        }
        document.update(overrides)
        return io.BytesIO(json.dumps(document).encode("utf-8") + b"\n")

    def read(self, stream: io.BytesIO) -> helper_protocol.ClusterlessRequest:
        return helper_protocol.read_clusterless_request(
            stream,
            expected_operation="cert_publish",
            allowed_parameter_keys=frozenset({"deploy", "certificates"}),
        )

    def test_an_explicit_null_cluster_is_accepted(self) -> None:
        request = self.read(self.request())

        self.assertIsNone(request.cluster)
        self.assertEqual(request.operation, "cert_publish")
        self.assertEqual(request.parameters, {"deploy": False})

    def test_a_named_cluster_is_refused(self) -> None:
        with self.assertRaises(helper_protocol.HelperProtocolError) as caught:
            self.read(self.request(cluster="alpha"))

        self.assertIn("acts on no cluster", str(caught.exception))

    def test_the_field_may_not_simply_be_left_out(self) -> None:
        """Stating the absence is a decision; omitting the field is forgetting."""

        document = json.loads(self.request().getvalue())
        del document["cluster"]

        with self.assertRaises(helper_protocol.HelperProtocolError) as caught:
            self.read(io.BytesIO(json.dumps(document).encode("utf-8") + b"\n"))

        self.assertIn("missing field(s): cluster", str(caught.exception))

    def test_a_cluster_helper_still_refuses_a_null(self) -> None:
        with self.assertRaises(helper_protocol.HelperProtocolError):
            helper_protocol.read_helper_request(
                self.request(operation="deploy"),
                expected_operation="deploy",
                allowed_parameter_keys=frozenset({"deploy"}),
            )

    def test_no_lifeline_is_offered(self) -> None:
        """These three have no checkpoint to notice a released caller at."""

        with self.assertRaises(helper_protocol.HelperProtocolError) as caught:
            self.read(self.request(lifeline=True))

        self.assertIn("does not support a lifeline", str(caught.exception))
