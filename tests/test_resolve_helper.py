"""`haprion-resolve-helper` and the web's way to it (B253, 2026-10-06).

The web is built to reach nothing past localhost, so a dns server's name in the
editor and the preview is looked up here, with the manager's resolver, the one
the publish uses. These cases hold the helper to its envelope and to the
generator's own answer per name, and the client to telling an unreachable
service apart from a name that does not resolve.
"""

from __future__ import annotations

import io
import json
import unittest
import uuid
from typing import Any
from unittest import mock

from haprion import dnsdist_config, helper_socket, resolve_socket
from haprion.cli import resolve_helper
from tests.contract_schema import assert_contract

ADDRESSES = {"ns1.example.com": "192.0.2.53"}


def fake_lookup(host: str) -> str:
    if host in ADDRESSES:
        return ADDRESSES[host]
    raise dnsdist_config.Unresolved(f"{host} has no address on the manager")


def run(names: object) -> tuple[int, dict[str, Any], str]:
    request = {
        "schema_version": 1,
        "operation": "resolve",
        "cluster": None,
        "request_id": str(uuid.uuid4()),
        "parameters": {"names": names},
    }
    out, err = io.StringIO(), io.StringIO()
    code = resolve_helper.main(
        [],
        input_stream=io.BytesIO(json.dumps(request).encode() + b"\n"),
        output_stream=out,
        error_stream=err,
        lookup=fake_lookup,
    )
    return code, assert_contract("haprion-resolve", out.getvalue()), out.getvalue()


class TheHelper(unittest.TestCase):
    def test_each_name_gets_its_address_or_the_generators_sentence(self) -> None:
        code, document, _raw = run(["ns1.example.com", "gone.example.com"])

        self.assertEqual(code, 0)
        self.assertEqual(
            document["result"]["names"],
            [
                {"name": "ns1.example.com", "address": "192.0.2.53", "problem": None},
                {
                    "name": "gone.example.com",
                    "address": None,
                    "problem": "gone.example.com has no address on the manager",
                },
            ],
        )

    def test_what_is_not_a_host_name_is_refused_before_anything_is_asked(self) -> None:
        for names in (
            [],
            ["192.0.2.1"],
            ["a b"],
            ['x"y'],
            ["n"] * 0,
            [f"n{i}.example.com" for i in range(21)],
            "ns1",
        ):
            with self.subTest(names=names):
                code, document, _raw = run(names)
                self.assertEqual(code, 65)
                self.assertEqual(document["error"]["code"], "bad_input")

    def test_it_takes_no_arguments(self) -> None:
        code = resolve_helper.main(
            ["--x"],
            input_stream=io.BytesIO(b""),
            output_stream=io.StringIO(),
            error_stream=io.StringIO(),
        )
        self.assertNotEqual(code, 0)


class TheClient(unittest.TestCase):
    def ask(self, answer: str) -> Any:
        return mock.patch.object(helper_socket, "ask", return_value=answer)

    def test_an_answer_is_the_address(self) -> None:
        _code, _document, raw = run(["ns1.example.com"])
        with self.ask(raw):
            self.assertEqual(resolve_socket.lookup("ns1.example.com"), "192.0.2.53")

    def test_a_name_without_one_is_the_helpers_sentence(self) -> None:
        _code, _document, raw = run(["gone.example.com"])
        with self.ask(raw), self.assertRaises(dnsdist_config.Unresolved) as raised:
            resolve_socket.lookup("gone.example.com")
        self.assertEqual(str(raised.exception), "gone.example.com has no address on the manager")

    def test_a_service_nobody_answers_is_said_as_the_installation(self) -> None:
        with (
            mock.patch.object(
                helper_socket,
                "ask",
                side_effect=helper_socket.HelperUnavailable("nothing listens on the socket"),
            ),
            self.assertRaises(dnsdist_config.Unresolved) as raised,
        ):
            resolve_socket.lookup("ns1.example.com")
        self.assertIn("could not be looked up here", str(raised.exception))
        self.assertIn("nothing listens", str(raised.exception))

    def test_an_answer_that_is_not_an_address_is_not_written(self) -> None:
        document = {
            "ok": True,
            "result": {"names": [{"name": "ns1.example.com", "address": "x", "problem": None}]},
        }
        with self.ask(json.dumps(document)), self.assertRaises(dnsdist_config.Unresolved):
            resolve_socket.lookup("ns1.example.com")


def run_any(names: list[str]) -> str:
    """Finding 72: a pool member's names, asked whether they give any address."""

    request = {
        "schema_version": 1,
        "operation": "resolve",
        "cluster": None,
        "request_id": str(uuid.uuid4()),
        "parameters": {"names": names, "any": True},
    }
    out = io.StringIO()
    code = resolve_helper.main(
        [],
        input_stream=io.BytesIO(json.dumps(request).encode() + b"\n"),
        output_stream=out,
        error_stream=io.StringIO(),
        first=lambda host: {"app.example.com": "198.51.100.10"}.get(host),
    )
    assert_contract("haprion-resolve", out.getvalue())
    if code != 0:
        raise AssertionError(out.getvalue())
    return out.getvalue()


class APoolMembersName(unittest.TestCase):
    def test_any_address_will_do_and_none_is_the_warning(self) -> None:
        raw = run_any(["app.example.com", "typo.example.com"])
        names = json.loads(raw)["result"]["names"]

        self.assertEqual(
            names[0], {"name": "app.example.com", "address": "198.51.100.10", "problem": None}
        )
        self.assertIsNone(names[1]["address"])
        self.assertIn("is not in DNS as the manager sees it", names[1]["problem"])
        with mock.patch.object(helper_socket, "ask", return_value=raw):
            self.assertEqual(
                resolve_socket.unresolved(["app.example.com", "typo.example.com"]),
                ["typo.example.com"],
            )

    def test_a_service_nobody_answers_says_nothing_about_the_names(self) -> None:
        with mock.patch.object(
            helper_socket, "ask", side_effect=helper_socket.HelperUnavailable("nothing listens")
        ):
            self.assertIsNone(resolve_socket.unresolved(["typo.example.com"]))
        self.assertEqual(resolve_socket.unresolved([]), [])


if __name__ == "__main__":
    unittest.main()
