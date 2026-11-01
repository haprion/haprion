"""`haprion-block-api-helper` and the web's way to it (B416): a block placed in the same call.

The fixture is `test_server_state_command`'s: a real policy, the shipped
cluster file and a repository with the objects committed. `store` blocks; `shop` does not.
"""

from __future__ import annotations

import io
import json
import subprocess
import unittest
from pathlib import Path
from unittest import mock

from haprion import block_api_socket, exit_codes, helper_socket
from haprion.cli import block_api_helper
from haprion.config import DeployIdentity, Node
from tests.test_server_state_command import (
    REQUEST_ID,
    STORE,
    HelperFixture,
    commit,
    unblocked,
)

ACTOR = f"token{':'}fail2ban"
EXEMPTING = STORE.replace(
    b"dynamic_block: {max_requests: 300, block_for: 30m}",
    b"dynamic_block: {max_requests: 300, block_for: 30m, exempt: [192.0.2.0/24]}",
)


class Fixture(HelperFixture):
    def setUp(self) -> None:
        super().setUp()
        self.asked: list[tuple[str, str]] = []
        self.failing: set[str] = set()

    def ask(
        self, node: Node, _identity: DeployIdentity, request: str
    ) -> subprocess.CompletedProcess[str]:
        self.asked.append((node.name, request))
        if node.name in self.failing:
            return unblocked(request, still=tuple(request.split()[2:]))
        return unblocked(request)

    def block(
        self, name: str, addresses: list[str], *, actor: object = ACTOR
    ) -> tuple[int, dict[str, object] | None, str]:
        request = json.dumps(
            {
                "schema_version": 1,
                "operation": "dynamic_block",
                "cluster": "alpha",
                "request_id": REQUEST_ID,
                "parameters": {"object": name, "addresses": addresses, "actor": actor},
            }
        )
        out, err = io.StringIO(), io.StringIO()
        code = block_api_helper.main(
            [],
            policy_path=self.policy,
            input_stream=io.BytesIO(request.encode()),
            output_stream=out,
            error_stream=err,
            require_secure=False,
            require_root=False,
            ask=self.ask,
        )
        document = json.loads(out.getvalue()) if out.getvalue() else None
        if document is not None:
            self.assert_contract(document)
        return code, document, err.getvalue()


class AnAddressIsBlockedOnEveryNode(Fixture):
    def test_every_node_is_asked_once_and_the_actor_is_in_the_journal(self) -> None:
        code, document, said = self.block("store", ["203.0.113.9", "::ffff:203.0.113.9"])

        self.assertEqual(code, 0, document)
        assert document is not None
        self.assertEqual((document["operation"], document["outcome"]), ("dynamic_block", "done"))
        self.assertEqual(
            sorted(self.asked), sorted((node, "block store 203.0.113.9") for node in self.nodes)
        )
        self.assertIn(f"203.0.113.9 for {ACTOR}", said)

    def test_a_node_that_did_not_take_it_makes_the_answer_partial(self) -> None:
        self.failing = {self.nodes[0]}

        code, document, _ = self.block("store", ["203.0.113.9"])

        self.assertEqual(code, exit_codes.PARTIAL, document)
        assert document is not None
        self.assertEqual(document["outcome"], "partial")
        self.assertEqual([w["node"] for w in document["warnings"]], [self.nodes[0]])  # type: ignore[attr-defined]

    def test_no_node_taking_it_is_failed(self) -> None:
        self.failing = set(self.nodes)

        code, document, _ = self.block("store", ["203.0.113.9"])

        self.assertEqual(code, exit_codes.FAILED, document)
        assert document is not None
        self.assertEqual(document["error"]["code"], "node_block_failed")  # type: ignore[index]


class TheObjectIsChecked(Fixture):
    def test_an_object_that_does_not_block_or_is_not_there_asks_no_node(self) -> None:
        for name, code in (("shop", "bad_input"), ("nowhere", "server_not_found")):
            with self.subTest(name):
                status, document, _ = self.block(name, ["203.0.113.9"])
                self.assertNotEqual(status, 0)
                assert document is not None
                self.assertEqual(document["error"]["code"], code)  # type: ignore[index]
        self.assertEqual(self.asked, [])

    def test_an_exempt_address_is_left_out_and_said_while_the_rest_is_blocked(self) -> None:
        commit(self.repo, {"managed/proxies/store.yaml": EXEMPTING})

        code, document, _ = self.block("store", ["192.0.2.7", "203.0.113.9"])

        self.assertEqual(code, exit_codes.PARTIAL, document)
        assert document is not None
        self.assertEqual(document["outcome"], "partial")
        self.assertEqual(
            [(w["code"], w["details"]) for w in document["warnings"]],  # type: ignore[attr-defined]
            [("address_exempt", {"address": "192.0.2.7"})],
        )
        self.assertEqual({request for _node, request in self.asked}, {"block store 203.0.113.9"})

    def test_only_exempt_addresses_asks_no_node_and_names_them(self) -> None:
        commit(self.repo, {"managed/proxies/store.yaml": EXEMPTING})

        code, document, _ = self.block("store", ["192.0.2.7"])

        self.assertEqual(code, exit_codes.REFUSED, document)
        assert document is not None
        self.assertEqual(document["error"]["details"], {"addresses": ["192.0.2.7"]})  # type: ignore[index]
        self.assertEqual(self.asked, [])

    def test_a_request_that_is_not_addresses_or_has_no_fit_actor_asks_no_node(self) -> None:
        for addresses, actor in (
            (["not-an-address"], ACTOR),
            ([], ACTOR),
            (["203.0.113.9"], ""),
            (["203.0.113.9"], "line\nbreak"),
            (["203.0.113.9"], None),
        ):
            with self.subTest(addresses=addresses, actor=actor):
                code, document, _ = self.block("store", addresses, actor=actor)
                self.assertEqual(code, exit_codes.REFUSED, document)
                assert document is not None
                self.assertEqual(document["error"]["code"], "bad_input")  # type: ignore[index]
        self.assertEqual(self.asked, [])

    def test_a_policy_without_a_server_state_identity_is_the_installation(self) -> None:
        self.write_policy(identity=False)

        code, document, _ = self.block("store", ["203.0.113.9"])

        self.assertEqual(code, exit_codes.CONFIG, document)
        assert document is not None
        self.assertEqual(document["error"]["code"], "server_state_unavailable")  # type: ignore[index]

    def test_the_helper_needs_root_and_takes_no_client(self) -> None:
        errors = io.StringIO()
        code = block_api_helper.main(
            [], input_stream=io.BytesIO(b"{}"), output_stream=io.StringIO(), error_stream=errors
        )
        self.assertEqual(code, exit_codes.NOT_ROOT)
        request = json.dumps(
            {
                "schema_version": 1,
                "operation": "dynamic_block",
                "cluster": "alpha",
                "request_id": REQUEST_ID,
                "parameters": {
                    "client": "app-f2b",
                    "object": "store",
                    "addresses": ["203.0.113.9"],
                    "actor": ACTOR,
                },
            }
        )
        code = block_api_helper.main(
            [],
            policy_path=self.policy,
            input_stream=io.BytesIO(request.encode()),
            output_stream=io.StringIO(),
            error_stream=errors,
            require_root=False,
            require_secure=False,
            ask=self.ask,
        )
        self.assertNotEqual(code, 0)
        self.assertEqual(self.asked, [])


class TheWebAsksOverTheSocket(unittest.TestCase):
    def test_the_request_names_the_object_the_addresses_and_who_asked(self) -> None:
        sent: list[dict[str, object]] = []

        def ask(request: dict[str, object], **_: object) -> str:
            sent.append(request)
            return '{"outcome": "done"}'

        with mock.patch.object(helper_socket, "ask", side_effect=ask):
            document = block_api_socket.ask("alpha", "store", ["203.0.113.9"], actor=ACTOR)

        self.assertEqual(document, {"outcome": "done"})
        self.assertEqual(sent[0]["cluster"], "alpha")
        self.assertEqual(sent[0]["operation"], "dynamic_block")
        self.assertEqual(
            sent[0]["parameters"],
            {"object": "store", "addresses": ["203.0.113.9"], "actor": ACTOR},
        )

    def test_a_service_that_is_not_there_and_one_that_answers_nonsense_are_told_apart(self) -> None:
        with self.assertRaises(block_api_socket.HelperUnavailable) as raised:
            block_api_socket.ask(
                "alpha", "store", ["203.0.113.9"], actor="x", path="/nonexistent/block.sock"
            )
        self.assertNotIsInstance(raised.exception, helper_socket.HelperSilent)
        with (
            mock.patch.object(helper_socket, "ask", return_value="not json"),
            self.assertRaises(helper_socket.HelperSilent),
        ):
            block_api_socket.ask("alpha", "store", ["203.0.113.9"], actor="x")


class TheSocketIsThePathTheUnitListensOn(unittest.TestCase):
    def test_path(self) -> None:
        unit = (
            Path(__file__).resolve().parents[1]
            / "install/platform/examples/haprion-block-api-helper.socket.example"
        ).read_text()
        self.assertIn(f"ListenStream={block_api_socket.SOCKET_PATH}\n", unit)


if __name__ == "__main__":
    unittest.main()
