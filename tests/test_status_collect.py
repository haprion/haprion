"""What a cluster reading adds up to, including when a node lies or is silent.

The comparison against the published release is the point of these cases. Every
way of *not* being able to say "in sync" has its own state, because reporting
any of them as agreement is the one mistake that would send someone away from a
cluster that needed a deploy.
"""

from __future__ import annotations

import json
import tempfile
import threading
import time
import unittest
from collections.abc import Callable
from pathlib import Path
from typing import Any
from unittest import mock

from haprion import exit_codes, node_ssh, status_collect
from haprion.config import DeployIdentity, Node
from haprion.deploy_plan import ReleaseTarget, VipState
from haprion.object_manifest import MANIFEST_FILE
from haprion.object_manifest import build as build_manifest
from haprion.object_manifest import render as render_manifest
from haprion.status_collect import (
    NodeResponse,
    StatusReport,
    collect,
    read_manifest,
)

SHOP = {
    "backends": "backend mgd-shop-web\n",
    "routing": "    use_backend mgd-shop-web if host\n",
    "listener": "frontend mgd-main-http\n",
    "certificate": "",
}
INTRANET = {**SHOP, "backends": "backend mgd-intranet-portal\n"}

NODES = (
    Node(name="node-a", mgmt_host="node-a.example.com"),
    Node(name="node-b", mgmt_host="node-b.example.com"),
)
TARGET = ReleaseTarget(version=18, hash="a" * 40)


#
# A node carrying exactly the address list its release publishes. Made up
# digests: nothing here hashes a file, and the comparison only asks whether two
# answers are equal. A case about the release hash says nothing about addresses
# on purpose, so this is the default and the cases that are about the address
# list pass their own.
#
ADDRESSES: dict[str, object] = {
    "published": True,
    "published_sha256": "a1" * 32,
    "installed": True,
    "installed_sha256": "a1" * 32,
    "included": True,
}


def node_status(
    name: str,
    *,
    owner: bool | None,
    release_hash: str | None,
    version: object = "18",
    addresses: object = None,
) -> dict[str, object]:
    release: dict[str, object] | None = None
    if release_hash is not None:
        release = {
            "cluster": "alpha",
            "version": version,
            "hash": release_hash,
            "timestamp": "2026-08-28T07:42:00+02:00",
        }
    return {
        "schema_version": 1,
        "node": name,
        "cluster": "alpha",
        "haproxy": {"active": True},
        "keepalived": {
            "active": True,
            "state": "MASTER" if owner else "BACKUP",
            "addresses": ADDRESSES if addresses is None else addresses,
        },
        "vip": {"address": "192.0.2.10", "interface": "eth0", "owner": owner},
        "ip_nonlocal_bind": True,
        "release": release,
        "config_validation": {"ok": True},
        "stats_ok": True,
        "runtime": {"ok": True},
        "certificates": [],
    }


def answering(**by_name: object) -> Callable[[Node], NodeResponse]:
    def read(node: Node) -> NodeResponse:
        value = by_name[node.name]
        if isinstance(value, NodeResponse):
            return value
        return NodeResponse(exit_code=0, stdout=json.dumps(value))

    return read


class CollectTests(unittest.TestCase):
    def both(
        self, *, hash_a: str | None, hash_b: str | None, version: object = "18"
    ) -> StatusReport:
        return collect(
            NODES,
            answering(
                **{
                    "node-a": node_status(
                        "node-a", owner=True, release_hash=hash_a, version=version
                    ),
                    "node-b": node_status(
                        "node-b", owner=False, release_hash=hash_b, version=version
                    ),
                }
            ),
            target=TARGET,
        )

    # ------------------------------------------------------------ the comparison

    def test_both_nodes_on_the_published_hash_are_converged(self) -> None:
        report = self.both(hash_a=TARGET.hash, hash_b=TARGET.hash)
        self.assertEqual(report.result["summary"]["release_state"], "converged")
        self.assertTrue(all(node["current"] for node in report.result["nodes"]))
        self.assertEqual(report.exit_code, exit_codes.OK)

    def test_one_node_on_another_hash_makes_the_cluster_behind(self) -> None:
        report = self.both(hash_a=TARGET.hash, hash_b="b" * 40)
        self.assertEqual(report.result["summary"]["release_state"], "behind")
        self.assertEqual(
            [node["current"] for node in report.result["nodes"]],
            [True, False],
        )
        #
        # Behind is not degraded: both nodes answered, so the reading itself
        # succeeded and the exit code must not claim otherwise.
        #
        self.assertEqual(report.exit_code, exit_codes.OK)

    def test_a_node_that_reports_no_release_is_not_compared(self) -> None:
        report = self.both(hash_a=TARGET.hash, hash_b=None)
        self.assertIsNone(report.result["nodes"][1]["current"])
        self.assertEqual(report.result["summary"]["release_state"], "incomplete")

    def test_nothing_published_means_unknown_rather_than_behind(self) -> None:
        report = collect(
            NODES,
            answering(
                **{
                    "node-a": node_status("node-a", owner=True, release_hash=TARGET.hash),
                    "node-b": node_status("node-b", owner=False, release_hash=TARGET.hash),
                }
            ),
            target=None,
        )
        self.assertEqual(report.result["summary"]["release_state"], "unknown")
        self.assertIsNone(report.result["summary"]["target"])
        self.assertTrue(all(node["current"] is None for node in report.result["nodes"]))

    def test_the_target_it_compared_against_is_reported(self) -> None:
        summary = self.both(hash_a=TARGET.hash, hash_b=TARGET.hash).result["summary"]
        self.assertEqual(summary["target"], {"version": 18, "hash": TARGET.hash})

    # ------------------------------------------------------------ the normalisation

    def test_a_numeric_string_version_becomes_a_number(self) -> None:
        report = self.both(hash_a=TARGET.hash, hash_b=TARGET.hash, version="18")
        self.assertEqual(report.result["nodes"][0]["status"]["release"]["version"], 18)

    def test_a_version_that_is_not_a_number_is_left_exactly_as_sent(self) -> None:
        report = self.both(hash_a=TARGET.hash, hash_b=TARGET.hash, version="eighteen")
        self.assertEqual(report.result["nodes"][0]["status"]["release"]["version"], "eighteen")

    # ------------------------------------------------------------ unusable answers

    def test_an_unreachable_node_is_partial_and_warns(self) -> None:
        report = collect(
            NODES,
            answering(
                **{
                    "node-a": node_status("node-a", owner=True, release_hash=TARGET.hash),
                    "node-b": NodeResponse(exit_code=255, stdout=""),
                }
            ),
            target=TARGET,
        )
        self.assertEqual(report.exit_code, exit_codes.PARTIAL)
        self.assertEqual(report.result["nodes"][1]["error"]["code"], "ssh_unreachable")
        self.assertEqual([w.code for w in report.warnings], ["ssh_unreachable"])
        self.assertEqual(report.result["summary"]["vip_state"], str(VipState.INCOMPLETE))
        #
        # One node current and one unreadable is not a converged cluster.
        #
        self.assertEqual(report.result["summary"]["release_state"], "incomplete")

    def test_json_that_is_not_a_node_status_is_refused(self) -> None:
        for payload in ("null", "[]", '{"schema_version": 1}'):
            with self.subTest(payload=payload):
                report = collect(
                    NODES,
                    answering(
                        **{
                            "node-a": node_status("node-a", owner=True, release_hash=TARGET.hash),
                            "node-b": NodeResponse(exit_code=0, stdout=payload),
                        }
                    ),
                    target=TARGET,
                )
                self.assertEqual(report.result["nodes"][1]["error"]["code"], "node_status_invalid")
                self.assertFalse(report.result["nodes"][1]["status_ok"])

    def test_output_that_is_not_json_is_refused(self) -> None:
        report = collect(
            NODES,
            answering(
                **{
                    "node-a": node_status("node-a", owner=True, release_hash=TARGET.hash),
                    "node-b": NodeResponse(exit_code=0, stdout="not json"),
                }
            ),
            target=TARGET,
        )
        self.assertEqual(report.result["nodes"][1]["error"]["code"], "node_status_invalid_json")

    def test_no_usable_node_fails_rather_than_degrades(self) -> None:
        report = collect(
            NODES,
            answering(
                **{
                    "node-a": NodeResponse(exit_code=255, stdout=""),
                    "node-b": NodeResponse(exit_code=255, stdout=""),
                }
            ),
            target=TARGET,
        )
        self.assertEqual(report.exit_code, exit_codes.UNAVAILABLE)
        envelope = report.as_envelope("alpha", request_id="11111111-1111-4111-8111-111111111111")
        self.assertEqual(envelope["outcome"], "failed")
        self.assertEqual(envelope["error"]["code"], "status_unavailable")

    # ------------------------------------------------------------ the envelope

    def test_a_complete_reading_is_done_with_no_error(self) -> None:
        envelope = self.both(hash_a=TARGET.hash, hash_b=TARGET.hash).as_envelope(
            "alpha", request_id="11111111-1111-4111-8111-111111111111"
        )
        self.assertEqual(envelope["outcome"], "done")
        self.assertTrue(envelope["ok"])
        self.assertIsNone(envelope["error"])
        self.assertEqual(envelope["warnings"], [])
        self.assertEqual(envelope["operation"], "status")

    def test_a_degraded_reading_is_partial_and_keeps_its_warnings(self) -> None:
        report = collect(
            NODES,
            answering(
                **{
                    "node-a": node_status("node-a", owner=True, release_hash=TARGET.hash),
                    "node-b": NodeResponse(exit_code=255, stdout=""),
                }
            ),
            target=TARGET,
        )
        envelope = report.as_envelope("alpha", request_id="11111111-1111-4111-8111-111111111111")
        self.assertEqual(envelope["outcome"], "partial")
        self.assertFalse(envelope["ok"])
        self.assertIsNone(envelope["error"])
        self.assertEqual(envelope["warnings"][0]["node"], "node-b")


class MoreThanTwoNodes(unittest.TestCase):
    """A cluster of three reads and sums up like a pair (B211)."""

    THREE = (*NODES, Node(name="node-c", mgmt_host="node-c.example.com"))

    def read(self, **answers: object) -> StatusReport:
        return collect(self.THREE, answering(**answers), target=TARGET)

    def test_one_owner_among_three_is_a_single_owner_and_converged(self) -> None:
        report = self.read(
            **{
                name: node_status(name, owner=name == "node-b", release_hash=TARGET.hash)
                for name in ("node-a", "node-b", "node-c")
            }
        )

        summary = report.result["summary"]
        self.assertEqual(summary["configured_nodes"], 3)
        self.assertEqual(summary["vip_state"], str(VipState.SINGLE_OWNER))
        self.assertEqual(summary["vip_owners"], ["node-b"])
        self.assertEqual(summary["release_state"], "converged")

    def test_two_owners_among_three_is_split_brain(self) -> None:
        report = self.read(
            **{
                name: node_status(name, owner=name != "node-b", release_hash=TARGET.hash)
                for name in ("node-a", "node-b", "node-c")
            }
        )

        self.assertEqual(report.result["summary"]["vip_state"], str(VipState.SPLIT_BRAIN))

    def test_two_owners_stay_split_brain_when_the_third_cannot_be_read(self) -> None:
        # Review 2026-10-03, F1: INCOMPLETE used to hide an observed conflict.
        report = self.read(
            **{
                "node-a": node_status("node-a", owner=True, release_hash=TARGET.hash),
                "node-b": node_status("node-b", owner=True, release_hash=TARGET.hash),
                "node-c": NodeResponse(exit_code=255, stdout=""),
            }
        )

        summary = report.result["summary"]
        self.assertEqual(summary["vip_state"], str(VipState.SPLIT_BRAIN))
        self.assertEqual(summary["vip_owners"], ["node-a", "node-b"])

    def test_the_third_node_behind_makes_the_cluster_behind(self) -> None:
        report = self.read(
            **{
                "node-a": node_status("node-a", owner=True, release_hash=TARGET.hash),
                "node-b": node_status("node-b", owner=False, release_hash=TARGET.hash),
                "node-c": node_status("node-c", owner=False, release_hash="b" * 40),
            }
        )

        self.assertEqual(report.result["summary"]["release_state"], "behind")


class TheNodesAreAskedAtOnce(unittest.TestCase):
    """Fas 16 punkt 1: a cluster's read takes as long as its slowest node, not their sum."""

    def test_every_node_is_asked_before_any_answers(self) -> None:
        nodes = MoreThanTwoNodes.THREE
        # Each read waits until all three are being read; one after the other,
        # the first would wait alone and the barrier would break.
        together = threading.Barrier(len(nodes), timeout=5)
        answer = answering(
            **{
                node.name: node_status(
                    node.name, owner=node.name == "node-a", release_hash=TARGET.hash
                )
                for node in nodes
            }
        )

        def read(node: Node) -> NodeResponse:
            together.wait()
            return answer(node)

        report = collect(nodes, read, target=TARGET)

        self.assertEqual(
            [entry["name"] for entry in report.result["nodes"]], ["node-a", "node-b", "node-c"]
        )
        self.assertEqual(report.result["summary"]["release_state"], "converged")


class AStatusReadIsBounded(unittest.TestCase):
    def test_a_node_that_connects_and_never_answers_is_abandoned(self) -> None:
        #
        # Stands in for ssh: connected, then silent. The read has to come back
        # on its own, as an unreachable node, rather than holding the poll.
        #
        with tempfile.TemporaryDirectory() as raw:
            silent = Path(raw) / "ssh"
            silent.write_text("#!/bin/sh\nexec sleep 30\n", encoding="utf-8")
            silent.chmod(0o755)
            identity = DeployIdentity(user="svc-status", key=Path(raw) / "key")
            with (
                mock.patch.object(node_ssh, "SSH", str(silent)),
                mock.patch.object(status_collect, "STATUS_TIMEOUT_SECONDS", 1),
            ):
                started = time.monotonic()
                response = status_collect.ask_node(NODES[0], identity)
                elapsed = time.monotonic() - started
                report = status_collect.collect(NODES[:1], lambda _node: response, target=None)

        self.assertEqual(response.exit_code, exit_codes.TIMED_OUT)
        self.assertLess(elapsed, 10)
        error = report.result["nodes"][0]["error"]
        self.assertEqual(error["code"], "ssh_unreachable")
        self.assertEqual(error["message"], "SSH gave no answer within 1 seconds")

    def test_a_status_command_that_failed_on_the_node_is_not_an_unreachable_node(self) -> None:
        """Review 2026-10-30, E3: only ssh's own exit 255 and a timeout are the connection."""

        failed = NodeResponse(
            exit_code=1,
            stdout="",
            stderr="ERROR: node.conf names no cluster\nrun 04-node-prepare\n",
        )
        report = collect(NODES[:1], lambda _node: failed, target=None)
        entry = report.result["nodes"][0]
        self.assertTrue(entry["reachable"])
        self.assertFalse(entry["status_ok"])
        self.assertEqual(entry["error"]["code"], "node_status_invalid")
        self.assertIn("exit 1", entry["error"]["message"])
        self.assertIn("ERROR: node.conf names no cluster", entry["error"]["message"])
        self.assertIn("run 04-node-prepare", entry["error"]["details"]["stderr"])

    def test_what_a_failed_command_said_is_bounded(self) -> None:
        noisy = NodeResponse(exit_code=2, stdout="", stderr="x" * 100_000)
        entry = collect(NODES[:1], lambda _node: noisy, target=None).result["nodes"][0]
        self.assertLess(len(entry["error"]["details"]["stderr"]), 2100)
        self.assertLess(len(entry["error"]["message"]), 300)

    def test_a_resolver_that_does_not_answer_does_not_stretch_the_read(self) -> None:
        """Review 2026-10-30, E10: the names are asked beside the nodes, in a budget."""

        names = tuple(
            status_collect.PublishedName(pool="p", host=f"dns{n}.example.com", address="192.0.2.1")
            for n in range(3)
        )

        def dead(_host: str) -> str:
            time.sleep(1.5)
            return "192.0.2.1"

        with mock.patch.object(status_collect, "DNS_LOOKUP_BUDGET_SECONDS", 0.2):
            started = time.monotonic()
            report = collect(
                NODES[:1],
                answering(
                    **{"node-a": node_status("node-a", owner=True, release_hash=TARGET.hash)}
                ),
                target=TARGET,
                dns_names=names,
                resolve=dead,
            )
            elapsed = time.monotonic() - started
        self.assertLess(elapsed, 1.0)
        self.assertEqual(list(report.warnings), [])

    def test_a_name_that_moved_is_still_warned_of(self) -> None:
        name = status_collect.PublishedName(pool="p", host="dns.example.com", address="192.0.2.1")
        report = collect(
            NODES[:1],
            answering(**{"node-a": node_status("node-a", owner=True, release_hash=TARGET.hash)}),
            target=TARGET,
            dns_names=(name,),
            resolve=lambda _host: "192.0.2.9",
        )
        self.assertEqual([w.code for w in report.warnings], ["dns_server_moved"])

    def test_a_document_nested_past_the_parser_is_one_node_without_status(self) -> None:
        """Code review 26-10-22, 5-6: `RecursionError` is not a `JSONDecodeError`,
        and one node's answer stopped the read of every node."""

        hostile = status_collect.NodeResponse(exit_code=0, stdout="[" * 200_000)
        report = status_collect.collect(NODES[:1], lambda _node: hostile, target=None)

        error = report.result["nodes"][0]["error"]
        self.assertEqual(error["code"], "node_status_invalid_json")


if __name__ == "__main__":
    unittest.main()


class WhatEachObjectIsDoingOnTheNodes(unittest.TestCase):
    """The per-object answer, read from two releases rather than from history.

    A release carries every object, so "the nodes are behind" says nothing
    about which object somebody changed. These cases hold the difference: an
    untouched object stays current through a deploy it is not part of, and a
    node that could not be compared never turns into agreement.
    """

    PUBLISHED = "a" * 40
    OLD = "b" * 40

    def tree(
        self,
        raw: str,
        *,
        published: dict[str, dict[str, str]],
        releases: dict[str, dict[str, dict[str, str]] | None],
    ) -> Path:
        """A published tree with a release per commit, `current` on one of them."""

        publish = Path(raw) / "alpha"
        for commit, objects in releases.items():
            release = publish / "releases" / commit
            (release / "node").mkdir(parents=True)
            if objects is not None:
                (release / MANIFEST_FILE).write_bytes(render_manifest(build_manifest(objects)))
        (publish / "current").symlink_to(publish / "releases" / self.PUBLISHED)
        return publish

    def states(self, publish: Path, *, hash_a: str | None, hash_b: str | None) -> Any:
        report = collect(
            NODES,
            answering(
                **{
                    "node-a": node_status("node-a", owner=True, release_hash=hash_a),
                    "node-b": node_status("node-b", owner=False, release_hash=hash_b),
                }
            ),
            target=TARGET,
            publish_path=publish,
        )
        return report.result["objects"]

    def test_an_untouched_object_is_current_while_the_cluster_is_behind(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            publish = self.tree(
                raw,
                published={},
                releases={
                    self.PUBLISHED: {"shop": SHOP, "intranet": INTRANET},
                    self.OLD: {"shop": SHOP},
                },
            )
            states = self.states(publish, hash_a=self.OLD, hash_b=self.OLD)
            self.assertEqual(states["shop"]["state"], "current")
            self.assertEqual(states["intranet"]["state"], "absent")

    def test_one_node_behind_decides_the_object(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            changed = {"shop": {**SHOP, "routing": "    use_backend other\n"}}
            publish = self.tree(
                raw,
                published={},
                releases={self.PUBLISHED: {"shop": SHOP}, self.OLD: changed},
            )
            states = self.states(publish, hash_a=self.PUBLISHED, hash_b=self.OLD)
            self.assertEqual(states["shop"], {"state": "changed", "parts": ["routing"]})

    def test_a_node_that_cannot_be_compared_is_not_agreement(self) -> None:
        """Silence read as `current` is the mistake this whole path removes."""

        with tempfile.TemporaryDirectory() as raw:
            publish = self.tree(
                raw,
                published={},
                releases={self.PUBLISHED: {"shop": SHOP}, self.OLD: None},
            )
            states = self.states(publish, hash_a=self.PUBLISHED, hash_b=self.OLD)
            self.assertEqual(states["shop"]["state"], "unknown")

    def test_a_node_that_names_no_release_leaves_the_object_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            publish = self.tree(raw, published={}, releases={self.PUBLISHED: {"shop": SHOP}})
            states = self.states(publish, hash_a=self.PUBLISHED, hash_b=None)
            self.assertEqual(states["shop"]["state"], "unknown")

    def test_a_release_without_a_manifest_answers_nothing_at_all(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            publish = self.tree(raw, published={}, releases={self.PUBLISHED: None})
            self.assertEqual(self.states(publish, hash_a=self.PUBLISHED, hash_b=self.PUBLISHED), {})

    def test_a_node_naming_something_that_is_not_a_release_reads_nothing(self) -> None:
        """The name reaches root as a path. It is held to the shape of a commit."""

        with tempfile.TemporaryDirectory() as raw:
            publish = self.tree(raw, published={}, releases={self.PUBLISHED: {"shop": SHOP}})
            secret = Path(raw) / "elsewhere"
            secret.mkdir()
            (secret / MANIFEST_FILE).write_bytes(render_manifest(build_manifest({"shop": SHOP})))
            states = self.states(publish, hash_a=self.PUBLISHED, hash_b="../../elsewhere")
            self.assertEqual(states["shop"]["state"], "unknown")
            self.assertIsNone(read_manifest(publish, release="../../elsewhere"))


class ANodeWithoutKeepalived(unittest.TestCase):
    """B313: before the product's first deploy, no node has keepalived.conf."""

    VIP = "192.0.2.10"

    def bare(self, name: str, carried: object, configured: object = "missing") -> dict[str, object]:
        status = node_status(name, owner=None, release_hash=None)
        status["keepalived"] = {"active": False, "state": None, "configured": configured}
        status["vip"] = {"address": None, "interface": None, "owner": None, "carried": carried}
        return status

    def state(self, a: dict[str, object], b: dict[str, object], vip: str | None = VIP) -> object:
        report = collect(NODES, answering(**{"node-a": a, "node-b": b}), target=None, vip=vip)
        return report.result["summary"]["vip_state"]

    def test_neither_carrying_the_address_is_no_owner_and_lets_the_first_deploy_through(
        self,
    ) -> None:
        a = self.bare("node-a", ["192.0.2.11"])
        b = self.bare("node-b", ["192.0.2.12"])
        self.assertEqual(self.state(a, b), "no_owner")

    def test_one_carrying_it_by_other_means_owns_it(self) -> None:
        a = self.bare("node-a", ["192.0.2.10", "192.0.2.11"])
        b = self.bare("node-b", ["192.0.2.12"])
        self.assertEqual(self.state(a, b), "single_owner")

    def test_both_carrying_it_is_split_brain(self) -> None:
        a = self.bare("node-a", ["192.0.2.10"])
        b = self.bare("node-b", ["192.0.2.10"])
        self.assertEqual(self.state(a, b), "split_brain")

    def test_a_file_somebody_wrote_and_the_node_could_not_read_stays_unknown(self) -> None:
        for configured in ("operator", None):
            with self.subTest(configured=configured):
                a = self.bare("node-a", ["192.0.2.11"], configured=configured)
                b = self.bare("node-b", ["192.0.2.12"])
                self.assertEqual(self.state(a, b), "unknown")

    def test_without_the_carried_list_or_the_address_nothing_is_decided(self) -> None:
        a = self.bare("node-a", None)
        b = self.bare("node-b", ["192.0.2.12"])
        self.assertEqual(self.state(a, b), "unknown")
        a = self.bare("node-a", ["192.0.2.11"])
        self.assertEqual(self.state(a, b, vip=None), "unknown")
