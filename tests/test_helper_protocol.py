from __future__ import annotations

import io
import json
import unittest

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
