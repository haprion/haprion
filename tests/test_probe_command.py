"""The probe command and its privileged half, at the boundary between them.

The helper is where a request from a web form stops being text somebody typed,
so the cases here are mostly refusals: what it will not send to a node, and what
it does when the nodes cannot answer. The node validates the same fields again,
and that is not redundant - this check protects a node from this manager, and
the node's protects it from whoever holds the key.

The last class is a different question: not what the helper decides, but whether
the interface can reach it at all. That is the half that was written on an
assumption once and found to be impossible on the machine, so it is proved here
over a real socket rather than reasoned about.
"""

from __future__ import annotations

import io
import json
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

import yaml

from haproxy_mgmt import dnsdist_config
from haproxy_mgmt.cli import probe, probe_helper
from haproxy_mgmt.config import DeployIdentity, Node
from haproxy_mgmt.probe_socket import ask, build_request

BASE = Path(__file__).resolve().parents[1]


def answer(
    results: list[dict[str, object]], *, source_held: bool | None = None
) -> subprocess.CompletedProcess[str]:
    payload: dict[str, object] = {
        "schema_version": 1,
        "ok": True,
        "node": "node",
        "source": "",
        "error": None,
        "results": results,
    }
    if source_held is not None:
        payload["source_held"] = source_held
    return subprocess.CompletedProcess(
        args=["ssh"], returncode=0, stdout=json.dumps(payload), stderr=""
    )


class HelperFixture(unittest.TestCase):
    """A real policy and a real cluster file, built from the shipped example.

    Rewriting the cluster file here by hand would be a second description of a
    cluster to keep in step with the first, and the fields this helper does not
    read are exactly the ones that would be forgotten.
    """

    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        config_root = self.root / "config"
        publish_root = self.root / "published"
        cert_root = self.root / "certs"
        for directory in (config_root, publish_root, cert_root):
            directory.mkdir(parents=True, exist_ok=True)
        (cert_root / "validation.pem").write_text("dummy PEM\n", encoding="utf-8")
        (config_root / "alpha").mkdir(exist_ok=True)

        clusters = yaml.safe_load((BASE / "examples/clusters.yaml").read_text())
        entry = clusters["clusters"]["alpha"]
        entry["config_path"] = str(config_root / "alpha")
        entry["publish_path"] = str(publish_root / "alpha")
        entry["validation_certs"] = str(cert_root)
        self.clusters = self.root / "clusters.yaml"
        self.clusters.write_text(yaml.safe_dump(clusters), encoding="utf-8")
        self.nodes = [node["name"] for node in entry["nodes"]]

        self.policy = self.root / "runtime-policy.yaml"
        self.write_policy(identity=True)

    def write_policy(self, *, identity: bool) -> None:
        document: dict[str, object] = {
            "schema_version": 1,
            "cluster_file": str(self.clusters),
            "config_root": str(self.root / "config"),
            "publish_root": str(self.root / "published"),
            "validation_certs_root": str(self.root / "certs"),
        }
        if identity:
            document["probe_identity"] = {
                "user": "svc-probe",
                "key": str(self.root / "probe.key"),
            }
        self.policy.write_text(yaml.safe_dump(document), encoding="utf-8")

    def run_helper(
        self, parameters: dict[str, object], *, ask: object = None
    ) -> tuple[int, str, str]:
        request = {
            "schema_version": 1,
            "operation": "probe",
            "cluster": "alpha",
            "request_id": "3f1c2b64-6f3f-4f3a-9c6e-1d2b3c4d5e6f",
            "parameters": parameters,
        }
        out, err = io.StringIO(), io.StringIO()
        code = probe_helper.main(
            [],
            policy_path=self.policy,
            input_stream=io.BytesIO(json.dumps(request).encode()),
            output_stream=out,
            error_stream=err,
            require_secure=False,
            require_root=False,
            ask=ask or (lambda node, identity, body: answer([])),
        )
        return code, out.getvalue(), err.getvalue()

    def target(self, **fields: object) -> dict[str, object]:
        entry: dict[str, object] = {"host": "198.51.100.10", "port": 8080, "type": "tcp"}
        entry.update(fields)
        return entry


class WhatTheHelperRefusesToSend(HelperFixture):
    def refusal(self, parameters: dict[str, object]) -> str:
        code, out, err = self.run_helper(parameters)
        self.assertEqual(code, 65)
        self.assertEqual(out, "")
        return err

    def test_a_probe_with_no_targets(self) -> None:
        self.assertIn("targets", self.refusal({"targets": []}))

    def test_a_host_that_is_not_a_name_or_an_address(self) -> None:
        self.assertIn("host", self.refusal({"targets": [self.target(host="198.51.100.10:8080")]}))

    def test_a_port_that_is_not_a_port(self) -> None:
        self.assertIn("port", self.refusal({"targets": [self.target(port=0)]}))

    def test_a_type_nobody_asked_for(self) -> None:
        self.assertIn(
            "tcp, http, dns or udp", self.refusal({"targets": [self.target(type="smtp")]})
        )

    def test_a_path_that_is_not_a_path(self) -> None:
        self.assertIn(
            "path",
            self.refusal({"targets": [self.target(type="http", path="healthz")]}),
        )

    def test_more_targets_than_a_pool_has(self) -> None:
        many = [self.target(port=port) for port in range(1, 25)]
        self.assertIn("at most", self.refusal({"targets": many}))


class AUdpTarget(HelperFixture):
    """Fas 19b B5: keepalived's check on a syslog pool, whose receivers are addresses."""

    def sent(self, **fields: object) -> dict[str, object]:
        asked: list[dict[str, object]] = []

        def ask(
            node: Node, identity: DeployIdentity, body: bytes
        ) -> subprocess.CompletedProcess[str]:
            asked.append(json.loads(body))
            return answer([])

        code, _out, err = self.run_helper(
            {"targets": [self.target(type="udp", port=514, **fields)], "timeout_ms": 5000},
            ask=ask,
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(asked[0]["timeout_ms"], 5000)
        sent: dict[str, object] = asked[0]["targets"][0]  # type: ignore[index]
        return sent

    def test_an_address_is_asked_as_written(self) -> None:
        for host in ("198.51.100.10", "2001:db8::71"):
            with self.subTest(host=host):
                sent = self.sent(host=host)
                self.assertEqual((sent["host"], sent["type"]), (host, "udp"))

    def test_a_tcp_check_may_name_an_ipv6_receiver(self) -> None:
        """Review 26-10-08 F5."""

        code, _out, err = self.run_helper(
            {"targets": [self.target(type="tcp", port=601, host="2001:db8::71")]}
        )
        self.assertEqual(code, 0, err)

    def test_a_name_or_a_bracketed_address_is_refused(self) -> None:
        for host in ("logs.example.com", "[2001:db8::71]"):
            with self.subTest(host=host):
                code, _out, err = self.run_helper(
                    {"targets": [self.target(type="udp", port=514, host=host)]}
                )
                self.assertEqual(code, 65)
                self.assertIn("udp target's host must be an IP address", err)


class ThePersonsUdpCheck(unittest.TestCase):
    """`haproxy-probe --udp`, the command's half of the form's button (Fas 19b B5)."""

    def sent(self, argv: list[str]) -> tuple[list[dict[str, object]], int]:
        with mock.patch.object(probe, "run_probe_helper") as run:
            run.return_value = subprocess.CompletedProcess([], 0, stdout="", stderr="")
            with mock.patch.object(sys, "stderr", io.StringIO()):
                probe.main(argv, writer=io.StringIO())
        targets: list[dict[str, object]] = run.call_args.args[2]
        return targets, run.call_args.kwargs["timeout_ms"]

    def test_receivers_are_asked_as_udp_with_keepalived_s_wait(self) -> None:
        targets, timeout = self.sent(
            ["-c", "alpha", "-t", "198.51.100.10:514,[2001:db8::71]:514", "--udp"]
        )

        self.assertEqual(
            [(t["host"], t["port"], t["type"]) for t in targets],
            [("198.51.100.10", 514, "udp"), ("2001:db8::71", 514, "udp")],
        )
        self.assertEqual(timeout, 5000)

    def test_http_or_tls_beside_it_is_a_usage_error(self) -> None:
        for extra in (["--http", "/"], ["--tls"], ["--host", "logs.example.com"]):
            with (
                self.subTest(extra=extra),
                self.assertRaises(SystemExit),
                mock.patch.object(sys, "stdout", io.StringIO()),
            ):
                probe._parse(["-c", "alpha", "-t", "198.51.100.10:514", "--udp", *extra])

    def test_verify_and_min_version_are_each_read_once(self) -> None:
        """`--verify` never moved on, and the command never returned (found 26-10-08)."""

        parsed: list[dict[str, object]] = []
        argv = [
            "-c",
            "alpha",
            "-t",
            "198.51.100.10:8443",
            "--tls",
            "--verify",
            "--min-version",
            "TLSv1.3",
            "--json",
        ]
        #
        # In a thread, so a parser that loops again fails this test instead of
        # holding the whole run.
        #
        reader = threading.Thread(target=lambda: parsed.append(probe._parse(argv)), daemon=True)
        reader.start()
        reader.join(5)
        self.assertFalse(reader.is_alive(), "the parser did not return")
        options = parsed[0]

        self.assertEqual(
            (options["verify"], options["min_version"], options["json"]), (True, "TLSv1.3", True)
        )


class ADnsTarget(HelperFixture):
    """B253: a dns check's question is held to the model, and a name is looked up here."""

    def sent(self, **fields: object) -> dict[str, object]:
        asked: list[dict[str, object]] = []

        def ask(
            node: Node, identity: DeployIdentity, body: bytes
        ) -> subprocess.CompletedProcess[str]:
            asked.append(json.loads(body))
            return answer([])

        with mock.patch.object(
            dnsdist_config,
            "lookup",
            side_effect=lambda host: {"ns1.example.com": "192.0.2.53"}[host],
        ):
            code, _out, err = self.run_helper(
                {"targets": [self.target(type="dns", port=53, **fields)]}, ask=ask
            )
        self.assertEqual(code, 0, err)
        sent: dict[str, object] = asked[0]["targets"][0]  # type: ignore[index]
        return sent

    def test_a_named_server_is_asked_at_the_address_the_manager_gives_it(self) -> None:
        sent = self.sent(host="ns1.example.com", query_name="example.com", query_type="SOA")
        self.assertEqual(
            (sent["host"], sent["address"], sent["query_name"], sent["query_type"]),
            ("ns1.example.com", "192.0.2.53", "example.com.", "SOA"),
        )

    def test_dnsdist_s_question_when_none_is_written(self) -> None:
        sent = self.sent()
        self.assertEqual(
            (sent["address"], sent["query_name"], sent["query_type"]),
            ("198.51.100.10", "a.root-servers.net.", "A"),
        )

    def test_a_question_the_model_would_refuse_is_refused(self) -> None:
        for fields in ({"query_name": 'x"y'}, {"query_type": "ANY"}):
            with self.subTest(fields=fields):
                code, out, err = self.run_helper({"targets": [self.target(type="dns", **fields)]})
                self.assertEqual((code, out), (65, ""))
                self.assertIn("query_", err)

    def test_a_name_that_does_not_resolve_says_so(self) -> None:
        with mock.patch.object(
            dnsdist_config,
            "lookup",
            side_effect=dnsdist_config.Unresolved("gone.example.com has no address on the manager"),
        ):
            code, out, err = self.run_helper(
                {"targets": [self.target(type="dns", host="gone.example.com")]}
            )
        self.assertEqual(code, 65)
        self.assertIn("gone.example.com has no address", err)
        #
        # An envelope, so the form says the sentence rather than "nothing at all".
        #
        refusal = json.loads(out)["error"]
        self.assertEqual(refusal["code"], "dns_unresolved")
        self.assertEqual(refusal["message"], "gone.example.com has no address on the manager")


class WhatTheHelperAnswers(HelperFixture):
    def test_every_node_is_asked_and_the_answers_are_carried(self) -> None:
        asked = []

        def ask(
            node: Node, identity: DeployIdentity, body: bytes
        ) -> subprocess.CompletedProcess[str]:
            asked.append((node.name, json.loads(body)))
            return answer(
                [
                    {
                        "host": "198.51.100.10",
                        "port": 8080,
                        "ok": True,
                        "status": None,
                        "error": None,
                        "ms": 2,
                    }
                ]
            )

        code, out, _ = self.run_helper(
            {"targets": [self.target()], "source": "192.0.2.25"}, ask=ask
        )
        self.assertEqual(code, 0)
        envelope = json.loads(out)
        self.assertEqual(envelope["outcome"], "done")
        self.assertEqual([name for name, _ in asked], self.nodes)
        self.assertEqual(asked[0][1]["source"], "192.0.2.25")
        self.assertEqual(len(envelope["result"]["nodes"]), 2)
        self.assertTrue(envelope["result"]["nodes"][0]["results"][0]["ok"])

    def test_a_server_that_is_down_is_a_finding_and_not_a_failed_command(self) -> None:
        """A red job every time somebody checks a broken pool teaches nothing."""

        def ask(
            node: Node, identity: DeployIdentity, body: bytes
        ) -> subprocess.CompletedProcess[str]:
            return answer(
                [
                    {
                        "host": "198.51.100.10",
                        "port": 8080,
                        "ok": False,
                        "status": 503,
                        "error": "answered 503",
                        "ms": 4,
                    }
                ]
            )

        code, out, _ = self.run_helper({"targets": [self.target()]}, ask=ask)
        self.assertEqual(code, 0)
        envelope = json.loads(out)
        self.assertEqual(envelope["outcome"], "done")
        self.assertFalse(envelope["result"]["nodes"][0]["results"][0]["ok"])

    def test_no_node_answering_is_a_failure_of_the_command(self) -> None:
        def ask(
            node: Node, identity: DeployIdentity, body: bytes
        ) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(args=["ssh"], returncode=255, stdout="", stderr="")

        code, out, _ = self.run_helper({"targets": [self.target()]}, ask=ask)
        self.assertEqual(code, 68)
        envelope = json.loads(out)
        self.assertEqual(envelope["outcome"], "failed")
        self.assertEqual(envelope["error"]["code"], "probe_unavailable")

    def test_an_installation_without_an_identity_says_what_is_missing(self) -> None:
        """Named, never guessed: a wrong guess reaches a node as somebody else."""

        self.write_policy(identity=False)
        request = {
            "schema_version": 1,
            "operation": "probe",
            "cluster": "alpha",
            "request_id": "3f1c2b64-6f3f-4f3a-9c6e-1d2b3c4d5e6f",
            "parameters": {"targets": [self.target()]},
        }
        out, err = io.StringIO(), io.StringIO()
        code = probe_helper.main(
            [],
            policy_path=self.policy,
            input_stream=io.BytesIO(json.dumps(request).encode()),
            output_stream=out,
            error_stream=err,
            require_secure=False,
            require_root=False,
        )
        self.assertEqual(code, 78)
        self.assertIn("probe_identity", err.getvalue())
        self.assertEqual(json.loads(out.getvalue())["error"]["code"], "probe_unavailable")


class WhatTheHelperWillNotBeCalledAs(HelperFixture):
    def test_it_refuses_command_line_arguments(self) -> None:
        out, err = io.StringIO(), io.StringIO()
        code = probe_helper.main(
            ["-c", "alpha"],
            policy_path=self.policy,
            input_stream=io.BytesIO(b"{}"),
            output_stream=out,
            error_stream=err,
            require_secure=False,
            require_root=False,
        )
        self.assertNotEqual(code, 0)
        self.assertEqual(out.getvalue(), "")


class ThePersonsWayIn(unittest.TestCase):
    def test_sudo_may_ask_for_the_password(self) -> None:
        """A person has a `%sudo` rule and a terminal, not a NOPASSWD line (B71).

        `sudo -n` refused everybody without a cached sudo, while the
        installation guide said the command goes through the person's own rule.
        """

        with mock.patch.object(subprocess, "run") as run:
            probe.run_probe_helper("alpha", "request", [])
        argv = run.call_args.args[0]
        self.assertEqual(argv, [probe.SUDO, "--", probe.HELPER])
        self.assertNotIn("-n", argv)


if __name__ == "__main__":
    unittest.main()


class HowTheInterfaceReachesIt(HelperFixture):
    """The helper behind a socket, asked by the client the interface uses.

    The web service cannot sudo - its unit forbids gaining privilege at all -
    so the request travels to the privilege instead. Both halves of that are
    exercised here: the client half-closes its write side, and the helper reads
    stdin to end of file and answers on the same connection. Each looked right
    on its own before; what had never been run was the pair.
    """

    def serve_one(self, path: str) -> threading.Thread:
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(path)
        listener.listen(1)
        self.addCleanup(listener.close)

        def answer_one() -> None:
            connection, _ = listener.accept()
            with connection, connection.makefile("rb") as reader:
                writer = io.StringIO()
                probe_helper.main(
                    [],
                    policy_path=self.policy,
                    input_stream=reader,
                    output_stream=writer,
                    error_stream=io.StringIO(),
                    require_secure=False,
                    require_root=False,
                    ask=lambda node, identity, body: answer(
                        [
                            {
                                "host": "198.51.100.10",
                                "port": 8080,
                                "ok": True,
                                "status": None,
                                "error": None,
                                "ms": 3,
                            }
                        ]
                    ),
                )
                connection.sendall(writer.getvalue().encode())

        thread = threading.Thread(target=answer_one, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        return thread

    def test_a_request_written_to_the_socket_comes_back_as_an_envelope(self) -> None:
        path = str(self.root / "probe.sock")
        self.serve_one(path)

        envelope = json.loads(
            ask(
                build_request(
                    "alpha",
                    "3f1c2b64-6f3f-4f3a-9c6e-1d2b3c4d5e6f",
                    [{"host": "198.51.100.10", "port": 8080, "type": "tcp"}],
                    source="192.0.2.25",
                ),
                path=path,
                timeout=10,
            )
        )

        self.assertTrue(envelope["ok"])
        self.assertEqual(envelope["operation"], "probe")
        self.assertEqual(envelope["cluster"], "alpha")
        self.assertEqual(envelope["result"]["source"], "192.0.2.25")
        self.assertEqual(len(envelope["result"]["nodes"]), len(self.nodes))


class WhichNodeCouldAnswerAtAll(HelperFixture):
    """A source address lives on one node, so only that node is asked to bind it.

    The other one would bind it anyway - `ip_nonlocal_bind` allows that - and
    fail the route lookup, producing a red row about a pool that is perfectly
    healthy. The node says it does not hold the address instead, and that has to
    travel all the way out rather than being flattened into a failure here.
    """

    def test_a_node_without_the_address_is_carried_through_as_such(self) -> None:
        held = iter([False, True])

        def ask(
            node: Node, identity: DeployIdentity, body: bytes
        ) -> subprocess.CompletedProcess[str]:
            return answer(
                [
                    {
                        "host": "198.51.100.10",
                        "port": 8080,
                        "ok": True,
                        "status": None,
                        "error": None,
                        "ms": 2,
                    }
                ]
                if (this := next(held))
                else [],
                source_held=this,
            )

        code, out, _ = self.run_helper(
            {"targets": [self.target()], "source": "192.0.2.25"}, ask=ask
        )
        envelope = json.loads(out)

        self.assertEqual(code, 0)
        self.assertTrue(envelope["ok"])
        self.assertEqual(envelope["outcome"], "done")
        self.assertEqual(
            [node["source_held"] for node in envelope["result"]["nodes"]], [False, True]
        )

    def test_an_address_no_node_carries_is_a_probe_that_did_not_run(self) -> None:
        """Nothing was tried anywhere, which is not the same as a pool that failed."""

        code, out, _ = self.run_helper(
            {"targets": [self.target()], "source": "192.0.2.25"},
            ask=lambda node, identity, body: answer([], source_held=False),
        )
        envelope = json.loads(out)

        self.assertEqual(code, 68)
        self.assertFalse(envelope["ok"])
        self.assertEqual(envelope["error"]["code"], "probe_unavailable")
        self.assertIn("192.0.2.25", envelope["error"]["message"])

    def test_a_node_whose_script_predates_the_field_is_still_asked(self) -> None:
        """`null` is a node that said nothing, never a node that said no."""

        code, out, _ = self.run_helper(
            {"targets": [self.target()], "source": "192.0.2.25"},
            ask=lambda node, identity, body: answer(
                [
                    {
                        "host": "198.51.100.10",
                        "port": 8080,
                        "ok": True,
                        "status": None,
                        "error": None,
                        "ms": 2,
                    }
                ]
            ),
        )
        envelope = json.loads(out)

        self.assertTrue(envelope["ok"])
        self.assertEqual(
            [node["source_held"] for node in envelope["result"]["nodes"]], [None, None]
        )


class WhatTheCommandPrints(unittest.TestCase):
    """The human output, where a node with nothing to say once said nothing.

    A bare node name with no rows under it reads as a node that answered about
    an empty pool. It has to say which of the two it is - the same distinction
    the interface makes, because the command line is the authoritative path and
    the two must not describe one probe differently.
    """

    def envelope(self, nodes: list[dict[str, object]], source: str = "192.0.2.25") -> str:
        written = io.StringIO()
        probe._render({"cluster": "alpha", "result": {"source": source, "nodes": nodes}}, written)
        return written.getvalue()

    def test_a_node_that_does_not_hold_the_address_says_so(self) -> None:
        printed = self.envelope(
            [
                {
                    "node": "node-a",
                    "reachable": True,
                    "error": None,
                    "source_held": False,
                    "results": [],
                },
            ]
        )
        self.assertIn("NOT HERE", printed)
        self.assertIn("192.0.2.25", printed)

    def test_a_node_that_probed_lists_what_it_found(self) -> None:
        printed = self.envelope(
            [
                {
                    "node": "node-a",
                    "reachable": True,
                    "error": None,
                    "source_held": True,
                    "results": [
                        {
                            "host": "198.51.100.10",
                            "port": 8080,
                            "ok": True,
                            "status": 200,
                            "error": None,
                            "ms": 2,
                        }
                    ],
                },
            ]
        )
        self.assertIn("OK", printed)
        self.assertNotIn("NOT HERE", printed)

    def test_a_node_that_said_nothing_about_the_field_is_not_labelled(self) -> None:
        printed = self.envelope(
            [{"node": "node-a", "reachable": True, "error": None, "results": []}]
        )
        self.assertNotIn("NOT HERE", printed)
