"""Reading what the nodes said about a probe, defensively.

The answer arrives over SSH from a machine this code does not control, so every
shape it could take has to end somewhere usable. The distinction that matters
throughout: a node that could not answer is a node with no answer, never an
answer that the pool is unreachable. They look the same on a page that does not
separate them and they lead to opposite actions - one sends somebody to the
firewall, the other to the node.
"""

from __future__ import annotations

import json
import subprocess
import time
import unittest
from pathlib import Path

from haproxy_mgmt.config import DeployIdentity, Node
from haproxy_mgmt.health_probe import (
    MAX_TARGETS,
    NodeAnswer,
    Target,
    build_request,
    probe,
    read_answer,
)

NODES = (
    Node(name="node-a", mgmt_host="node-a.example.com"),
    Node(name="node-b", mgmt_host="node-b.example.com"),
)
IDENTITY = DeployIdentity(user="svc-probe", key=Path("/root/.ssh/id_ed25519_probe"))


def completed(stdout: str, code: int = 0) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=["ssh"], returncode=code, stdout=stdout, stderr="")


def answered(**fields: object) -> str:
    payload = {
        "schema_version": 1,
        "ok": True,
        "node": "node-a",
        "source": "",
        "error": None,
        "results": [
            {
                "host": "198.51.100.10",
                "port": 8080,
                "ok": True,
                "status": 200,
                "error": None,
                "ms": 3,
            }
        ],
    }
    payload.update(fields)
    return json.dumps(payload)


class BothNodesAtOnce(unittest.TestCase):
    """Two SSH calls of up to 30 s in a row met the web's and nginx's 60 s
    exactly; asked together, the probe takes as long as the slower node
    (review 2026-09-28)."""

    def test_the_nodes_are_asked_together_and_answer_in_configured_order(self) -> None:
        waits = {"node-a": 0.4, "node-b": 0.1}

        def slow(node: Node, _identity: object, _request: str) -> subprocess.CompletedProcess[str]:
            time.sleep(waits[node.name])
            return completed(answered(node=node.name))

        started = time.monotonic()
        answers = probe(NODES, IDENTITY, [Target(host="198.51.100.10", port=8080)], ask=slow)
        elapsed = time.monotonic() - started

        self.assertEqual([answer.node for answer in answers], ["node-a", "node-b"])
        # In a row it would be 0.5 s; together it is the slower one.
        self.assertLess(elapsed, 0.48)

    def test_a_node_that_times_out_does_not_take_the_other_with_it(self) -> None:
        def one_silent(node: Node, _i: object, _r: str) -> subprocess.CompletedProcess[str]:
            if node.name == "node-a":
                raise subprocess.TimeoutExpired(cmd="ssh", timeout=30)
            return completed(answered(node=node.name))

        answers = probe(NODES, IDENTITY, [Target(host="198.51.100.10", port=8080)], ask=one_silent)
        self.assertEqual(
            [(answer.node, answer.reachable) for answer in answers],
            [("node-a", False), ("node-b", True)],
        )


class TheRequestSentToANode(unittest.TestCase):
    def test_it_carries_the_targets_and_the_source(self) -> None:
        request = json.loads(
            build_request([Target(host="198.51.100.10", port=8080)], source="192.0.2.25")
        )
        self.assertEqual(request["schema_version"], 1)
        self.assertEqual(request["source"], "192.0.2.25")
        self.assertEqual(request["targets"][0]["host"], "198.51.100.10")

    def test_more_targets_than_the_node_would_accept_are_refused_here_first(self) -> None:
        """Bounded on both sides. This bound protects the node from us."""

        many = [Target(host="198.51.100.10", port=port) for port in range(MAX_TARGETS + 1)]
        with self.assertRaises(ValueError):
            build_request(many)

    def test_a_probe_of_nothing_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            build_request([])


class WhatCameBackFromANode(unittest.TestCase):
    def test_an_answer_is_read_as_the_node_wrote_it(self) -> None:
        answer = read_answer("node-a", completed(answered()))
        self.assertTrue(answer.reachable)
        self.assertIsNone(answer.error)
        self.assertEqual(answer.results[0].status, 200)
        self.assertTrue(answer.results[0].ok)

    def test_a_node_that_could_not_be_reached_has_no_answer(self) -> None:
        answer = read_answer("node-a", completed("", code=255))
        self.assertFalse(answer.reachable)
        self.assertEqual(answer.results, ())
        self.assertIsNotNone(answer.error)

    def test_a_refusal_from_the_node_is_the_node_s_own_words(self) -> None:
        refusal = json.dumps({"schema_version": 1, "ok": False, "error": "host is not usable"})
        answer = read_answer("node-a", completed(refusal, code=64))
        self.assertTrue(answer.reachable)
        self.assertEqual(answer.error, "host is not usable")
        self.assertEqual(answer.results, ())

    def test_something_that_is_not_json_is_not_a_verdict(self) -> None:
        answer = read_answer("node-a", completed("nologin\n"))
        self.assertFalse(answer.reachable)
        self.assertEqual(answer.results, ())

    def test_a_row_that_names_no_server_is_dropped_rather_than_shown(self) -> None:
        payload = answered(
            results=[
                {"host": "198.51.100.10", "ok": True},
                {"port": 8080, "ok": True},
                {"host": "198.51.100.11", "port": 8080, "ok": False, "error": "refused"},
            ]
        )
        answer = read_answer("node-a", completed(payload))
        self.assertEqual([entry.host for entry in answer.results], ["198.51.100.11"])

    def test_a_count_that_is_not_a_count_is_dropped(self) -> None:
        payload = answered(
            results=[
                {"host": "198.51.100.10", "port": 8080, "ok": True, "ms": True, "status": "200"}
            ]
        )
        answer = read_answer("node-a", completed(payload)).results[0]
        self.assertIsNone(answer.ms)
        self.assertIsNone(answer.status)


class AskingEveryNode(unittest.TestCase):
    def test_both_nodes_are_asked_even_when_the_first_fails(self) -> None:
        """ "Reachable from one node and not the other" is the useful answer."""

        asked: list[str] = []

        def ask(
            node: Node, identity: DeployIdentity, request: object
        ) -> subprocess.CompletedProcess[str]:
            asked.append(node.name)
            return completed("", code=255) if node.name == "node-a" else completed(answered())

        answers = probe(NODES, IDENTITY, [Target(host="198.51.100.10", port=8080)], ask=ask)
        self.assertEqual(asked, ["node-a", "node-b"])
        self.assertFalse(answers[0].reachable)
        self.assertTrue(answers[1].results[0].ok)

    def test_a_node_that_never_answers_ends_as_a_node_without_an_answer(self) -> None:
        def ask(
            node: Node, identity: DeployIdentity, request: object
        ) -> subprocess.CompletedProcess[str]:
            raise subprocess.TimeoutExpired(cmd="ssh", timeout=30)

        answers = probe(NODES, IDENTITY, [Target(host="198.51.100.10", port=8080)], ask=ask)
        self.assertEqual(len(answers), 2)
        self.assertTrue(all(isinstance(answer, NodeAnswer) for answer in answers))
        self.assertTrue(all(not answer.reachable for answer in answers))


if __name__ == "__main__":
    unittest.main()
