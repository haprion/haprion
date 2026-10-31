"""Blocking an address from outside (B412): the registry, its helpers and the forced command.

The fixture is `test_server_state_command`'s: a real policy, the shipped
cluster file and a repository with the objects committed. `store` blocks;
`shop` does not. The nodes are answered by a function, as there.
"""

from __future__ import annotations

import base64
import io
import json
import subprocess
import unittest

from haprion import block_clients, exit_codes
from haprion.block_clients import BlockClientError
from haprion.cli import block_ask, block_client_helper, block_helper
from haprion.config import DeployIdentity, Node
from tests.test_server_state_command import (
    REQUEST_ID,
    STORE,
    HelperFixture,
    commit,
    unblocked,
)


def made_key(fill: int) -> str:
    """An ed25519 public key's shape around 32 made-up bytes: no key anybody holds."""

    blob = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + bytes([fill]) * 32
    return "ssh-ed25519 " + base64.b64encode(blob).decode()


KEY = made_key(7)
OTHER_KEY = made_key(9)
EXEMPTING = STORE.replace(
    b"dynamic_block: {max_requests: 300, block_for: 30m}",
    b"dynamic_block: {max_requests: 300, block_for: 30m, exempt: [192.0.2.0/24]}",
)


def resolved(name: str) -> tuple[str, ...]:
    return {"app.example.com": ("192.0.2.40",)}.get(name, ())


class TheRegistry(unittest.TestCase):
    def client(self, **fields: object) -> block_clients.Client:
        values: dict[str, object] = {
            "host": "app.example.com",
            "cluster": "alpha",
            "objects": ["store"],
            "key": KEY + " someone@app",
        }
        values.update(fields)
        return block_clients.client("app-f2b", **values)  # type: ignore[arg-type]

    def test_what_is_written_is_what_is_read(self) -> None:
        clients = block_clients.added({}, self.client(), by="admin")

        self.assertEqual(block_clients.parse(block_clients.render(clients)), clients)

    def test_each_client_is_one_locked_line_naming_it(self) -> None:
        keys = block_clients.render_keys({"app-f2b": self.client()}, resolved)

        self.assertIn(
            'from="app.example.com,192.0.2.40",restrict,'
            'command="/opt/haprion/current/bin/haprion-block-ask app-f2b" '
            f"{KEY} app-f2b block-client\n",
            keys,
        )
        self.assertNotIn("someone@app", keys, "the key's own comment is dropped")

    def test_a_host_that_does_not_resolve_writes_nothing(self) -> None:
        with self.assertRaises(BlockClientError) as raised:
            block_clients.render_keys({"x": self.client(host="gone.example.com")}, resolved)
        self.assertEqual(raised.exception.code, "host_unresolvable")

    def test_what_a_client_may_not_be(self) -> None:
        cases: tuple[dict[str, object], ...] = (
            {"host": "not a host"},
            {"key": "ssh-rsa AAAA"},
            {"objects": []},
            {"objects": ["Store"]},
            {"cluster": ""},
        )
        for fields in cases:
            with self.subTest(fields), self.assertRaises(BlockClientError):
                self.client(**fields)
        for identifier in ("App", "1app", "app f2b", "app;id", "a" * 41):
            with self.subTest(identifier), self.assertRaises(BlockClientError):
                block_clients.client_id(identifier)

    def test_a_client_blocks_only_on_its_own_objects_in_its_own_cluster(self) -> None:
        clients = {"app-f2b": self.client()}

        block_clients.may_block(clients, "app-f2b", "alpha", "store")
        for identifier, cluster, name in (
            ("app-f2b", "alpha", "shop"),
            ("app-f2b", "beta", "store"),
            ("other", "alpha", "store"),
        ):
            with self.subTest(identifier=identifier, cluster=cluster, name=name):
                with self.assertRaises(BlockClientError) as raised:
                    block_clients.may_block(clients, identifier, cluster, name)
                self.assertEqual(raised.exception.code, "forbidden")

    def test_a_name_is_added_once(self) -> None:
        clients = block_clients.added({}, self.client(), by="admin")

        with self.assertRaises(BlockClientError) as raised:
            block_clients.added(clients, self.client(key=OTHER_KEY), by="admin")
        self.assertEqual(raised.exception.code, "already_exists")


class Fixture(HelperFixture):
    def setUp(self) -> None:
        super().setUp()
        self.clients_file = self.root / "block-clients" / "clients.yaml"
        self.keys_file = self.root / "block-clients" / ".ssh" / "authorized_keys"

    def change(self, **parameters: object) -> tuple[int, dict[str, object] | None]:
        request = json.dumps(
            {
                "schema_version": 1,
                "operation": "block_client",
                "cluster": "alpha",
                "request_id": REQUEST_ID,
                "parameters": parameters,
            }
        )
        out = io.StringIO()
        code = block_client_helper.main(
            [],
            policy_path=self.policy,
            clients_file=self.clients_file,
            keys_file=self.keys_file,
            input_stream=io.BytesIO(request.encode()),
            output_stream=out,
            error_stream=io.StringIO(),
            require_secure=False,
            require_root=False,
            forward=resolved,
        )
        return code, json.loads(out.getvalue()) if out.getvalue() else None

    def add(self, objects: list[str] | None = None) -> tuple[int, dict[str, object] | None]:
        return self.change(
            action="add",
            client="app-f2b",
            host="app.example.com",
            objects=objects or ["store"],
            key=KEY,
            by="admin",
        )


class AClientIsAddedAndRemoved(Fixture):
    def test_an_added_client_is_in_the_registry_and_the_key_file(self) -> None:
        code, document = self.add()

        self.assertEqual(code, 0, document)
        assert document is not None
        self.assertEqual(document["outcome"], "done")
        result = document["result"]
        assert isinstance(result, dict)
        self.assertNotIn("key", result["client"])
        self.assertEqual(result["client"]["added_by"], "admin")
        self.assertIn("app-f2b", block_clients.read(self.clients_file))
        self.assertIn(
            'command="/opt/haprion/current/bin/haprion-block-ask app-f2b"',
            self.keys_file.read_text(),
        )

    def test_a_removed_client_leaves_both(self) -> None:
        self.add()

        code, document = self.change(action="remove", client="app-f2b")

        self.assertEqual(code, 0, document)
        self.assertEqual(block_clients.read(self.clients_file), {})
        self.assertNotIn(KEY, self.keys_file.read_text())

    def test_an_object_that_does_not_block_or_is_not_there_is_refused(self) -> None:
        for objects in (["shop"], ["store", "nowhere"]):
            with self.subTest(objects):
                code, document = self.add(objects)
                self.assertEqual(code, exit_codes.REFUSED, document)
                self.assertFalse(self.keys_file.exists())

    def test_removing_a_client_that_is_not_there_is_not_found(self) -> None:
        code, _document = self.change(action="remove", client="app-f2b")

        self.assertEqual(code, exit_codes.NOT_FOUND)


class AClientBlocks(Fixture):
    def setUp(self) -> None:
        super().setUp()
        self.add()
        self.asked: list[tuple[str, str]] = []

    def ask(
        self, node: Node, _identity: DeployIdentity, request: str
    ) -> subprocess.CompletedProcess[str]:
        self.asked.append((node.name, request))
        return unblocked(request)

    def block(
        self, client: str, name: str, addresses: list[str]
    ) -> tuple[int, dict[str, object] | None]:
        request = json.dumps(
            {
                "schema_version": 1,
                "operation": "dynamic_block",
                "cluster": "alpha",
                "request_id": REQUEST_ID,
                "parameters": {"client": client, "object": name, "addresses": addresses},
            }
        )
        out = io.StringIO()
        code = block_helper.main(
            [],
            policy_path=self.policy,
            clients_file=self.clients_file,
            input_stream=io.BytesIO(request.encode()),
            output_stream=out,
            error_stream=io.StringIO(),
            require_secure=False,
            require_root=False,
            ask=self.ask,
        )
        document = json.loads(out.getvalue()) if out.getvalue() else None
        if document is not None:
            self.assert_contract(document)
        return code, document

    def test_every_node_is_asked_once_to_place_the_addresses(self) -> None:
        code, document = self.block("app-f2b", "store", ["203.0.113.9", "::ffff:203.0.113.9"])

        self.assertEqual(code, 0, document)
        assert document is not None
        self.assertEqual(document["operation"], "dynamic_block")
        self.assertEqual(
            sorted(self.asked), sorted((node, "block store 203.0.113.9") for node in self.nodes)
        )

    def test_an_object_or_a_client_it_was_not_given_asks_no_node(self) -> None:
        for client, name in (("app-f2b", "shop"), ("other", "store")):
            with self.subTest(client=client, name=name):
                code, document = self.block(client, name, ["203.0.113.9"])
                self.assertEqual(code, exit_codes.REFUSED)
                assert document is not None
                self.assertEqual(document["error"]["code"], "forbidden")  # type: ignore[index]
        self.assertEqual(self.asked, [])

    def test_an_address_the_object_exempts_asks_no_node(self) -> None:
        commit(self.repo, {"managed/proxies/store.yaml": EXEMPTING})

        code, document = self.block("app-f2b", "store", ["192.0.2.7"])

        self.assertEqual(code, exit_codes.REFUSED, document)
        self.assertEqual(self.asked, [])


class TheForcedCommand(Fixture):
    def setUp(self) -> None:
        super().setUp()
        self.add()
        self.sent: list[dict[str, object]] = []

    def forced(self, words: str | None, client: str = "app-f2b") -> tuple[int, str]:
        def helper(request: str) -> subprocess.CompletedProcess[str]:
            self.sent.append(json.loads(request))
            answer: dict[str, object] = {"outcome": "done", "result": {}, "warnings": []}
            return subprocess.CompletedProcess(["sudo"], 0, json.dumps(answer) + "\n", "")

        out = io.StringIO()
        environ = {} if words is None else {"SSH_ORIGINAL_COMMAND": words}
        code = block_ask.main(
            [client], environ=environ, clients_file=self.clients_file, run=helper, output_stream=out
        )
        return code, out.getvalue()

    def test_the_client_and_its_cluster_come_from_the_key_and_the_registry(self) -> None:
        code, said = self.forced("block store 203.0.113.9")

        self.assertEqual((code, said), (0, "done\n"))
        self.assertEqual(len(self.sent), 1)
        self.assertEqual(self.sent[0]["cluster"], "alpha")
        self.assertEqual(
            self.sent[0]["parameters"],
            {"client": "app-f2b", "object": "store", "addresses": ["203.0.113.9"]},
        )

    def test_anything_else_never_reaches_the_helper(self) -> None:
        for words in (None, "", "block", "block store", "unblock store 203.0.113.9", "id"):
            with self.subTest(words):
                code, said = self.forced(words)
                self.assertEqual(code, exit_codes.USAGE)
                self.assertTrue(said.startswith("refused: "))
        code, _said = self.forced("block store 203.0.113.9", client="nobody")
        self.assertEqual(code, exit_codes.USAGE)
        self.assertEqual(self.sent, [])


if __name__ == "__main__":
    unittest.main()
