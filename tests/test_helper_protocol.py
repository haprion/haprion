from __future__ import annotations

import io
import json
import os
import time
import unittest

from haproxy_mgmt import helper_protocol
from haproxy_mgmt.helper_protocol import (
    HelperProtocolError,
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
    def read(self, raw: bytes, **kwargs: object):
        return read_helper_request(io.BytesIO(raw), expected_operation="status", **kwargs)

    def test_valid_exact_request(self):
        result = self.read(request_bytes())
        self.assertEqual(result.operation, "status")
        self.assertEqual(result.cluster, "alpha")
        self.assertEqual(result.request_id, REQUEST_ID)
        self.assertEqual(result.parameters, {})

    def test_no_argument_boundary(self):
        require_no_arguments([])
        with self.assertRaisesRegex(HelperProtocolError, "no command-line arguments"):
            require_no_arguments(["--cluster", "alpha"])

    def test_empty_malformed_trailing_and_multiple_documents_are_rejected(self):
        invalid_documents = (
            b"",
            b"not JSON",
            request_bytes() + b" trailing",
            request_bytes() + b"\n" + request_bytes(),
        )
        for raw in invalid_documents:
            with self.subTest(raw=raw), self.assertRaises(HelperProtocolError):
                self.read(raw)

    def test_oversized_and_invalid_utf8_are_rejected(self):
        with self.assertRaisesRegex(HelperProtocolError, "size limit"):
            self.read(b"{}" * 5, max_bytes=8)
        with self.assertRaisesRegex(HelperProtocolError, "UTF-8"):
            self.read(b"\xff")

    def test_duplicate_and_unknown_fields_are_rejected(self):
        duplicate = (
            b'{"schema_version":1,"operation":"status","operation":"status",'
            b'"cluster":"alpha","request_id":"' + REQUEST_ID.encode() + b'","parameters":{}}'
        )
        with self.assertRaisesRegex(HelperProtocolError, "duplicate JSON field"):
            self.read(duplicate)
        with self.assertRaisesRegex(HelperProtocolError, "unknown field"):
            self.read(request_bytes(extra=True))

    def test_non_finite_numbers_are_rejected(self):
        raw = request_bytes().replace(b'"parameters": {}', b'"parameters": {"value": NaN}')
        with self.assertRaisesRegex(HelperProtocolError, "non-finite"):
            self.read(raw, allowed_parameter_keys=frozenset({"value"}))

    def test_wrong_schema_operation_cluster_and_request_id_are_rejected(self):
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

    def test_parameters_are_exact_and_support_operation_validation(self):
        with self.assertRaisesRegex(HelperProtocolError, "unknown field"):
            self.read(request_bytes(parameters={"path": "/tmp/candidate"}))

        seen: list[object] = []

        def validate(parameters):
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

    def read(self, raw: bytes, **kwargs: object):
        return read_helper_request(io.BytesIO(raw), expected_operation="status", **kwargs)

    def test_a_line_ended_request_is_accepted(self):
        self.assertEqual(self.read(request_bytes() + b"\n").cluster, "alpha")

    def test_an_eof_ended_request_is_still_accepted(self):
        self.assertEqual(self.read(request_bytes()).cluster, "alpha")

    def test_what_follows_the_line_is_left_on_the_stream(self):
        stream = io.BytesIO(request_bytes(lifeline=True) + b"\nthe lifeline")
        read_helper_request(stream, expected_operation="status", lifeline=True)
        self.assertEqual(stream.read(), b"the lifeline")

    def test_a_second_line_is_not_read_as_part_of_the_request(self):
        stream = io.BytesIO(
            request_bytes(lifeline=True) + b"\n" + request_bytes(lifeline=True) + b"\n"
        )
        first = read_helper_request(stream, expected_operation="status", lifeline=True)
        self.assertEqual(first.cluster, "alpha")
        self.assertTrue(stream.read().startswith(b"{"))

    def test_the_limit_counts_the_request_and_not_its_line_ending(self):
        exact = b'{"a": 1}'
        with self.assertRaisesRegex(HelperProtocolError, "size limit"):
            self.read(exact + b"x\n", max_bytes=len(exact))
        # The same document, at the limit, fails on its content rather than its
        # size - which is what proves the line ending was not counted.
        with self.assertRaisesRegex(HelperProtocolError, "missing field"):
            self.read(exact + b"\n", max_bytes=len(exact))

    def test_without_a_lifeline_anything_after_the_request_is_refused(self):
        with self.assertRaisesRegex(HelperProtocolError, "followed by more input"):
            self.read(request_bytes() + b"\n" + request_bytes())

    def test_a_caller_that_says_nothing_gets_the_old_behaviour(self):
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

    def test_a_helper_without_a_lifeline_refuses_a_request_that_wants_one(self):
        with self.assertRaisesRegex(HelperProtocolError, "does not support a lifeline"):
            self.read(request_bytes(lifeline=True))

    def test_the_lifeline_field_must_be_a_boolean(self):
        with self.assertRaisesRegex(HelperProtocolError, "must be true or false"):
            self.read(request_bytes(lifeline="yes"))

    def test_an_empty_line_is_an_empty_request(self):
        with self.assertRaisesRegex(HelperProtocolError, "empty"):
            self.read(b"\n")


class TheLifeline(unittest.TestCase):
    """Watching the caller's stdin, with real pipes.

    Real file descriptors rather than BytesIO: EOF on a pipe whose write end is
    still open is precisely what a mock gets wrong, and it is the whole point -
    a lifeline that reported "released" while the caller was alive would abort
    every operation instead of none.
    """

    def lifeline(self, read_fd: int):
        stream = os.fdopen(read_fd, "rb", buffering=0)
        self.addCleanup(stream.close)
        line = helper_protocol.Lifeline(stream)
        line.watch()
        return line

    def settle(self, line, *, expected: bool) -> None:
        for _ in range(200):
            if line.released == expected:
                return
            time.sleep(0.005)
        self.fail(f"the lifeline never became released={expected}")

    def test_a_held_lifeline_is_not_released(self):
        read_fd, write_fd = os.pipe()
        self.addCleanup(os.close, write_fd)
        line = self.lifeline(read_fd)
        time.sleep(0.05)
        self.assertFalse(line.released)

    def test_closing_the_write_end_releases_it(self):
        read_fd, write_fd = os.pipe()
        line = self.lifeline(read_fd)
        os.close(write_fd)
        self.settle(line, expected=True)
        self.assertEqual(line.reason, "the caller closed the lifeline")

    def test_input_on_the_lifeline_releases_it_too(self):
        read_fd, write_fd = os.pipe()
        self.addCleanup(os.close, write_fd)
        line = self.lifeline(read_fd)
        os.write(write_fd, b"x")
        self.settle(line, expected=True)
        self.assertEqual(line.reason, "unexpected input arrived on the lifeline")

    def test_asking_why_before_it_is_released_is_a_mistake(self):
        read_fd, write_fd = os.pipe()
        self.addCleanup(os.close, write_fd)
        line = self.lifeline(read_fd)
        with self.assertRaises(RuntimeError):
            _ = line.reason
