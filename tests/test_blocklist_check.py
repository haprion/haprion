"""*Test* and *Check address* on Settings -> Blocklists: the engine, the helper and the command (B500)."""

from __future__ import annotations

import io
import json
import os
import socket
import tempfile
import threading
import unittest
from typing import Any

import yaml

from haprion import blocklist_check, blocklist_check_socket, blocklist_store, blocklists, exit_codes
from haprion.blocklist_store import ListState, Stored
from haprion.cli import blocklist_check as command
from haprion.cli import blocklist_check_helper as helper
from tests.test_cert_publish import BASE, Fixture

FETCHED = "2026-11-08T05:00:00+00:00"
#
# What the saved definition holds and what the form typed: made up, never sent anywhere.
#
SAVED = "saved-token"
TYPED = "typed"


def _item(name: str = "community", **fields: Any) -> blocklists.Definition:
    return blocklists.definition(
        name=name, url="https://lists.example.com/raw", every_hours=24, **fields
    )


class ATest(unittest.TestCase):
    """Fetched once, read as the timer reads it, nothing kept."""

    BODY = b"# community\n192.0.2.0/24\n198.51.100.7\nnot an address\n203.0.113.0/24 ; drop\n"

    def fetch(self, item: blocklists.Definition, secret: str) -> bytes:
        self.asked = (item.name, secret)
        return self.BODY

    def test_the_counts_the_form_shows(self) -> None:
        tested = blocklist_check.test(_item(), "", {"alpha": {}}, fetch=self.fetch)

        self.assertEqual((tested.answer, tested.entries, tested.skipped), ("fetched", 3, 1))
        self.assertEqual(tested.clusters, ())
        self.assertEqual(tested.sentence(), "3 addresses · 1 lines skipped")

    def test_an_exception_counts_in_each_cluster_with_its_own_groups(self) -> None:
        item = _item(excepts=("198.51.100.7", "partners"))
        groups = {"alpha": {"partners": ["192.0.2.16/28"]}, "beta": {}}

        tested = blocklist_check.test(item, "", groups, fetch=self.fetch)

        self.assertEqual(
            [(c.cluster, c.excepted, c.unknown_groups) for c in tested.clusters],
            [("alpha", 2, ()), ("beta", 1, ("partners",))],
        )
        self.assertEqual(
            tested.sentence(),
            "3 addresses · 1 lines skipped · excepted 2 on alpha, 1 on beta "
            "(198.51.100.7, partners) · partners is not a group on beta",
        )

    def test_the_same_count_everywhere_is_said_once(self) -> None:
        item = _item(excepts=("198.51.100.7",))

        tested = blocklist_check.test(item, "", {"alpha": {}, "beta": {}}, fetch=self.fetch)

        self.assertEqual(
            tested.sentence(), "3 addresses · 1 lines skipped · 1 excepted (198.51.100.7)"
        )

    def test_a_fetch_that_fails_is_the_answer_not_a_refusal(self) -> None:
        def refused(item: blocklists.Definition, secret: str) -> bytes:
            raise blocklists.BlocklistError("http_status", "lists.example.com answered 401")

        tested = blocklist_check.test(_item(), "", {}, fetch=refused)

        self.assertEqual((tested.answer, tested.entries), ("failed", 0))
        self.assertEqual(tested.sentence(), "Not fetched: lists.example.com answered 401.")

    def test_an_empty_list_is_said_as_the_timer_would_refuse_it(self) -> None:
        tested = blocklist_check.test(_item(), "", {}, fetch=lambda _i, _s: b"# nothing\n")

        self.assertEqual(tested.answer, "failed")
        self.assertIsNotNone(tested.problem)

    def test_the_answer_reads_back_as_it_was_written(self) -> None:
        item = _item(excepts=("partners",))
        tested = blocklist_check.test(item, "", {"alpha": {}}, fetch=self.fetch)

        self.assertEqual(blocklist_check.Tested.from_dict(tested.as_dict()), tested)


class CheckingAnAddress(unittest.TestCase):
    """Looked up in the kept lists, never fetched."""

    def setUp(self) -> None:
        self.kept: dict[str, tuple[blocklists.Network, ...]] = {
            "community": blocklists.parse(b"203.0.113.0/24\n198.51.100.7\n").networks,
            "drop": blocklists.parse(b"192.0.2.0/24\n").networks,
        }
        self.states = {"community": ListState(fetched_at=FETCHED)}
        self.definitions = [
            _item("community", excepts=("partners",)),
            _item("drop"),
            _item("fresh"),
        ]

    def check(self, address: str, groups: blocklist_check.Groups) -> blocklist_check.AddressCheck:
        return blocklist_check.check_address(
            address, self.definitions, self.states, groups, kept=self.kept.get
        )

    def test_a_network_holds_it_and_one_cluster_excepts_it(self) -> None:
        groups = {"alpha": {}, "beta": {"partners": ["203.0.113.0/28"]}}

        found = self.check("203.0.113.7", groups)

        self.assertEqual(
            [(item.name, item.network) for item in found.lists], [("community", "203.0.113.0/24")]
        )
        self.assertEqual(found.lists[0].excepted_on, ("beta",))
        self.assertEqual(found.unfetched, ("fresh",))
        self.assertIn("203.0.113.7 is on community (203.0.113.0/24), fetched ", found.sentence())
        self.assertIn(". It is excepted on beta. fresh has not been fetched yet.", found.sentence())

    def test_an_address_the_list_holds_bare_is_not_repeated(self) -> None:
        found = self.check("198.51.100.7", {"alpha": {}})

        self.assertEqual(found.lists[0].network, "198.51.100.7")
        self.assertIn("198.51.100.7 is on community, fetched", found.sentence())
        self.assertIn("It is not excepted.", found.sentence())

    def test_excepted_in_every_cluster_is_excepted(self) -> None:
        groups = {
            "alpha": {"partners": ["198.51.100.0/24"]},
            "beta": {"partners": ["198.51.100.7"]},
        }

        self.assertTrue(
            self.check("198.51.100.7", groups)
            .sentence()
            .endswith("It is excepted. fresh has not been fetched yet.")
        )

    def test_on_no_list(self) -> None:
        self.definitions = self.definitions[:2]

        self.assertEqual(
            self.check("198.51.100.8", {}).sentence(), "198.51.100.8 is on no blocklist."
        )

    def test_a_mapped_address_is_its_ipv4_address(self) -> None:
        found = self.check("::ffff:198.51.100.7", {})

        self.assertEqual(found.address, "198.51.100.7")
        self.assertEqual([item.name for item in found.lists], ["community"])

    def test_a_network_or_text_is_not_an_address(self) -> None:
        for value in ("192.0.2.0/24", "not an address", " 192.0.2.1", "fe80::1%eth0"):
            with self.subTest(value=value), self.assertRaises(blocklist_check.CheckError) as raised:
                self.check(value, {})
            self.assertEqual(raised.exception.code, "bad_input")

    def test_the_answer_reads_back_as_it_was_written(self) -> None:
        found = self.check("203.0.113.7", {"alpha": {}})

        self.assertEqual(blocklist_check.AddressCheck.from_dict(found.as_dict()), found)


class TheHelperAndTheCommand(Fixture):
    """Against a manager in a scratch directory: the policy, alpha with a group, a saved list."""

    def setUp(self) -> None:
        super().setUp()
        self.policy = self.write_config(self.keeper())
        network = yaml.safe_load((BASE / "examples/network.yaml").read_text())
        network["networks"] = {"partners": ["198.51.100.0/28"]}
        managed = self.root / "config" / "alpha" / "managed"
        managed.mkdir(parents=True)
        (managed / "network.yaml").write_text(yaml.safe_dump(network), encoding="utf-8")
        self.definitions = self.root / "definitions"
        self.definitions.mkdir(mode=0o700)
        self.state = self.root / "state"
        self.state.mkdir()
        blocklist_store.write(
            Stored(
                definition=_item(authorization="bearer", excepts=("partners",)),
                secret=SAVED,
                revision=3,
            ),
            directory=self.definitions,
            require_secure=False,
        )
        blocklist_store.keep(
            "community", blocklists.parse(b"198.51.100.0/24\n").networks, directory=self.state
        )
        blocklist_store.write_state(
            {"community": ListState(fetched_at=FETCHED, entries=1)}, directory=self.state
        )
        self.secrets: list[str] = []

    def fetch(self, item: blocklists.Definition, secret: str) -> bytes:
        self.secrets.append(secret)
        return b"192.0.2.0/24\n198.51.100.0/24\n"

    def ask(self, parameters: dict[str, object]) -> tuple[int, dict[str, Any], str]:
        request = {
            "schema_version": 1,
            "operation": "blocklist_check",
            "cluster": None,
            "request_id": "ffffffff-ffff-4fff-8fff-ffffffffffff",
            "parameters": parameters,
        }
        out, err = io.StringIO(), io.StringIO()
        code = helper.main(
            [],
            input_stream=io.BytesIO(json.dumps(request).encode()),
            output_stream=out,
            error_stream=err,
            policy_path=self.policy,
            definitions=self.definitions,
            state=self.state,
            fetch=self.fetch,
            require_root=False,
            require_secure=False,
        )
        return code, json.loads(out.getvalue()), err.getvalue()

    def form(self, **fields: object) -> dict[str, object]:
        return {
            "name": "community",
            "url": "https://lists.example.com/raw",
            "every_hours": 24,
            "authorization": "bearer",
            "excepts": ["partners"],
            **fields,
        }

    def test_a_test_with_the_saved_token(self) -> None:
        code, document, err = self.ask({"list": self.form(keep_secret=True)})

        self.assertEqual(code, 0, err)
        self.assertEqual(self.secrets, [SAVED])
        result = document["result"]
        self.assertEqual(
            (result["kind"], result["answer"], result["entries"]), ("list", "fetched", 2)
        )
        self.assertEqual(
            result["clusters"], [{"cluster": "alpha", "excepted": 1, "unknown_groups": []}]
        )
        self.assertNotIn(SAVED, err)
        self.assertIn("blocklist_check: list community", err)

    def test_a_test_with_the_typed_token_keeps_nothing(self) -> None:
        before = sorted(p.name for p in self.state.iterdir())

        code, _document, _err = self.ask({"list": self.form(secret=TYPED)})

        self.assertEqual(code, 0)
        self.assertEqual(self.secrets, [TYPED])
        self.assertEqual(sorted(p.name for p in self.state.iterdir()), before)
        self.assertEqual(
            blocklist_store.kept("community", directory=self.state),
            blocklists.parse(b"198.51.100.0/24\n").networks,
        )

    def test_the_saved_token_of_a_list_not_saved_is_refused(self) -> None:
        code, document, _err = self.ask({"list": self.form(name="other", keep_secret=True)})

        self.assertEqual(code, exit_codes.REFUSED)
        self.assertEqual(document["error"]["code"], "no_secret")
        self.assertEqual(self.secrets, [])

    def test_the_saved_token_is_not_sent_to_another_url_or_as_another_user(self) -> None:
        for fields in (
            self.form(url="https://attacker.example.net/raw", keep_secret=True),
            self.form(authorization="basic", username="svc-app", keep_secret=True),
        ):
            with self.subTest(fields=fields):
                code, document, _err = self.ask({"list": fields})
                self.assertEqual(code, exit_codes.REFUSED)
                self.assertEqual(document["error"]["code"], "no_secret")
                self.assertIn("type it to test", document["error"]["message"])
                self.assertNotIn("lists.example.com", document["error"]["message"])
        self.assertEqual(self.secrets, [])

    def test_a_field_the_form_cannot_hold_is_refused_before_anything_is_fetched(self) -> None:
        for fields in (
            self.form(every_hours=2),
            self.form(url="http://lists.example.com/raw"),
            self.form(secret=TYPED, keep_secret=True),
            self.form(path="/etc/shadow"),
        ):
            with self.subTest(fields=fields):
                code, document, _err = self.ask({"list": fields})
                self.assertEqual(code, exit_codes.REFUSED)
                self.assertEqual(document["outcome"], "failed")
        self.assertEqual(self.secrets, [])

    def test_both_questions_at_once_is_refused(self) -> None:
        code, _document, _err = self.ask({"address": "192.0.2.1", "list": self.form()})

        self.assertEqual(code, exit_codes.REFUSED)

    def test_an_address_in_the_kept_list_with_alpha_s_exception(self) -> None:
        code, document, err = self.ask({"address": "198.51.100.5"})

        self.assertEqual(code, 0, err)
        self.assertEqual(
            document["result"]["lists"],
            [
                {
                    "name": "community",
                    "network": "198.51.100.0/24",
                    "fetched_at": FETCHED,
                    "excepted_on": ["alpha"],
                    "clusters": ["alpha"],
                }
            ],
        )
        self.assertEqual(self.secrets, [], "an address check never fetches")

    def run_check(self, *argv: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        code = command.main(
            list(argv),
            stream_out=out,
            stream_err=err,
            policy_path=self.policy,
            definitions=self.definitions,
            state=self.state,
            fetch=self.fetch,
            require_root=False,
            require_secure=False,
        )
        return code, out.getvalue(), err.getvalue()

    def test_the_command_says_what_the_form_says(self) -> None:
        code, out, err = self.run_check("--list", "community")

        self.assertEqual(code, exit_codes.OK, err)
        self.assertEqual(out, "2 addresses · 1 excepted (partners)\n")
        self.assertEqual(self.secrets, [SAVED])

        code, out, _err = self.run_check("198.51.100.20")

        self.assertEqual(code, exit_codes.OK)
        self.assertIn("198.51.100.20 is on community (198.51.100.0/24), fetched ", out)
        self.assertTrue(out.endswith("It is not excepted.\n"))

    def test_a_failed_fetch_is_partial_in_words_and_done_in_json(self) -> None:
        def refused(item: blocklists.Definition, secret: str) -> bytes:
            raise blocklists.BlocklistError("http_status", "lists.example.com answered 401")

        self.fetch = refused  # type: ignore[method-assign]
        code, out, _err = self.run_check("--list", "community")

        self.assertEqual(code, exit_codes.PARTIAL)
        self.assertEqual(out, "Not fetched: lists.example.com answered 401.\n")

        code, out, _err = self.run_check("--list", "community", "--json")

        self.assertEqual(code, exit_codes.OK, "the document says it: the question was answered")
        self.assertEqual(json.loads(out)["result"]["answer"], "failed")

    def test_the_command_names_a_list_that_is_not_saved(self) -> None:
        code, _out, err = self.run_check("--list", "nothing")

        self.assertEqual(code, exit_codes.REFUSED)
        self.assertIn("no blocklist is called nothing", err)

    def test_the_command_needs_root(self) -> None:
        if os.geteuid() == 0:
            self.skipTest("run as root")
        out, err = io.StringIO(), io.StringIO()

        code = command.main(["192.0.2.1"], stream_out=out, stream_err=err)

        self.assertEqual(code, exit_codes.NOT_ROOT)
        self.assertIn("run it with sudo", err.getvalue())


class TheWebsClient(unittest.TestCase):
    """Over a socket, as the web asks the helper."""

    def serve(self, answer: dict[str, object]) -> str:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = os.path.join(directory.name, "check.sock")
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(path)
        server.listen(1)
        self.addCleanup(server.close)
        self.requests: list[dict[str, Any]] = []

        def once() -> None:
            connection, _ = server.accept()
            with connection:
                data = b""
                while chunk := connection.recv(65536):
                    data += chunk
                self.requests.append(json.loads(data))
                connection.sendall(json.dumps(answer).encode() + b"\n")

        thread = threading.Thread(target=once, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        return path

    def done(self, result: dict[str, object]) -> dict[str, object]:
        return {
            "schema_version": 1,
            "operation": "blocklist_check",
            "cluster": None,
            "request_id": "ffffffff-ffff-4fff-8fff-ffffffffffff",
            "warnings": [],
            "ok": True,
            "outcome": "done",
            "result": result,
            "error": None,
        }

    def test_a_test_sends_the_typed_secret_and_reads_the_answer(self) -> None:
        tested = blocklist_check.Tested("community", "fetched", 3, 0, (), (), None)
        path = self.serve(self.done(tested.as_dict()))

        answer = blocklist_check_socket.test(
            name="community",
            url="https://lists.example.com/raw",
            every_hours=24,
            authorization="bearer",
            secret=TYPED,
            path=path,
        )

        self.assertEqual(answer, tested)
        self.assertEqual(self.requests[0]["parameters"]["list"]["secret"], TYPED)

    def test_an_unchanged_secret_is_asked_for_by_name(self) -> None:
        tested = blocklist_check.Tested("community", "fetched", 3, 0, (), (), None)
        path = self.serve(self.done(tested.as_dict()))

        blocklist_check_socket.test(
            name="community",
            url="https://lists.example.com/raw",
            every_hours=24,
            authorization="bearer",
            keep_secret=True,
            path=path,
        )

        fields = self.requests[0]["parameters"]["list"]
        self.assertTrue(fields["keep_secret"])
        self.assertNotIn("secret", fields)

    def test_a_refusal_is_its_sentence(self) -> None:
        path = self.serve(
            {
                **self.done({}),
                "ok": False,
                "outcome": "failed",
                "result": None,
                "error": {
                    "code": "bad_input",
                    "message": "x is not an IPv4 or IPv6 address",
                    "details": {},
                },
            }
        )

        with self.assertRaises(blocklist_check.CheckError) as raised:
            blocklist_check_socket.check_address("x", path=path)

        self.assertEqual(
            (raised.exception.code, str(raised.exception)),
            ("bad_input", "x is not an IPv4 or IPv6 address"),
        )

    def test_an_answer_of_the_wrong_kind_is_incomplete(self) -> None:
        tested = blocklist_check.Tested("community", "fetched", 3, 0, (), (), None)
        path = self.serve(self.done(tested.as_dict()))

        with self.assertRaises(blocklist_check.CheckError) as raised:
            blocklist_check_socket.check_address("192.0.2.1", path=path)

        self.assertEqual(raised.exception.code, "unavailable")

    def test_no_helper_is_unavailable(self) -> None:
        with self.assertRaises(blocklist_check.CheckError) as raised:
            blocklist_check_socket.check_address("192.0.2.1", path="/nonexistent/check.sock")

        self.assertEqual(raised.exception.code, "unavailable")
