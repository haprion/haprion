"""Turning the object form into a probe, and reading the answer back.

Everything here is about the mapping. What a check would do lives across half a
dozen fields, and each one changes what a node should try - so the request is
built once, from the form, and these tests are what say it was built right.

The other half is what happens when the probe cannot run at all. A socket
nothing answers on and a pool that is down must not look the same on the page,
so they are kept apart here first.
"""

from __future__ import annotations

import json
import unittest

from haproxy_mgmt.probe_socket import ProbeUnavailable

from haproxy_ui.probe import MAX_TARGETS, run, source_address, targets_from


def form(**fields: object) -> dict[str, object]:
    written: dict[str, object] = {
        "servers": "198.51.100.10:8080\n198.51.100.11:8080",
        "health_type": "http",
        "health_path": "/healthz",
        "health_host": "",
        "health_port": "",
        "backend_tls": "",
        "source": "",
        "vip": "",
    }
    written.update(fields)
    return written


CHOICES = {
    "default_vip": "main",
    "vip_sources": {"main": "192.0.2.25", "spare": "192.0.2.26"},
    "sources": [{"name": "egress", "address": "192.0.2.40"}],
}


def answered(nodes: list[dict[str, object]], error: object = None) -> str:
    payload = {
        "schema_version": 1,
        "ok": error is None,
        "outcome": "done" if error is None else "failed",
        "operation": "probe",
        "cluster": "alpha",
        "request_id": "3f1c2b64-6f3f-4f3a-9c6e-1d2b3c4d5e6f",
        "result": {"source": "192.0.2.25", "nodes": nodes},
        "warnings": [],
        "error": error,
    }
    return json.dumps(payload)


class WhatTheNodesAreAskedToTry(unittest.TestCase):
    def test_one_target_per_server_in_the_pool(self) -> None:
        targets = targets_from(form())
        self.assertEqual([entry["host"] for entry in targets], ["198.51.100.10", "198.51.100.11"])
        self.assertEqual([entry["port"] for entry in targets], [8080, 8080])
        self.assertEqual(targets[0]["type"], "http")
        self.assertEqual(targets[0]["path"], "/healthz")

    def test_a_check_port_replaces_the_traffic_port_the_way_haproxy_does(self) -> None:
        self.assertEqual(
            [entry["port"] for entry in targets_from(form(health_port="9443"))], [9443, 9443]
        )

    def test_a_disabled_check_is_still_worth_trying_as_a_connection(self) -> None:
        """ "Can the node reach this server at all" is the useful answer left."""

        self.assertEqual(targets_from(form(health_type="disabled"))[0]["type"], "tcp")

    def test_the_check_follows_the_pool_onto_tls(self) -> None:
        system = targets_from(form(backend_tls="system"))[0]
        self.assertTrue(system["tls"])
        self.assertTrue(system["verify"])

        unverified = targets_from(form(backend_tls="none"))[0]
        self.assertTrue(unverified["tls"])
        self.assertFalse(unverified["verify"])

    def test_a_line_that_is_not_a_server_is_skipped_rather_than_sent(self) -> None:
        targets = targets_from(form(servers="198.51.100.10:8080\nnot-a-server\n\n"))
        self.assertEqual(len(targets), 1)

    def test_a_pool_larger_than_the_bound_is_cut_rather_than_refused_by_the_node(self) -> None:
        many = "\n".join(f"198.51.100.10:{port}" for port in range(9000, 9000 + MAX_TARGETS + 5))
        self.assertEqual(len(targets_from(form(servers=many))), MAX_TARGETS)


class WhichAddressTheProbeLeavesFrom(unittest.TestCase):
    def test_a_named_source_is_resolved_to_its_address(self) -> None:
        self.assertEqual(source_address(form(source="egress"), CHOICES), "192.0.2.40")

    def test_without_one_the_vip_s_own_source_is_used(self) -> None:
        self.assertEqual(source_address(form(), CHOICES), "192.0.2.25")
        self.assertEqual(source_address(form(vip="spare"), CHOICES), "192.0.2.26")

    def test_a_source_the_cluster_does_not_define_binds_nothing(self) -> None:
        """Refused by the engine at publish; here it simply names no address."""

        self.assertEqual(source_address(form(source="ghost"), CHOICES), "")


class WhatThePageIsToldAfterwards(unittest.TestCase):
    def report(self, answer: str, **fields: object):
        return run("alpha", form(**fields), CHOICES, call=lambda *a, **k: answer)

    def test_a_probe_that_ran_carries_every_node_s_answer(self) -> None:
        report = self.report(
            answered(
                [
                    {
                        "node": "node-a",
                        "reachable": True,
                        "error": None,
                        "results": [
                            {
                                "host": "198.51.100.10",
                                "port": 8080,
                                "ok": True,
                                "status": 200,
                                "error": None,
                                "ms": 3,
                            },
                            {
                                "host": "198.51.100.11",
                                "port": 8080,
                                "ok": False,
                                "status": None,
                                "error": "refused",
                                "ms": 1,
                            },
                        ],
                    },
                    {"node": "node-b", "reachable": False, "error": "unreachable", "results": []},
                ]
            )
        )
        self.assertTrue(report.ran)
        self.assertEqual(report.source, "192.0.2.25")
        self.assertEqual(report.failing, 1)
        self.assertFalse(report.nodes[1].reachable)

    def test_a_service_that_is_not_there_is_not_a_pool_that_failed(self) -> None:
        """The distinction the page depends on: nothing was tried."""

        def refuse(*_args: object, **_fields: object) -> str:
            raise ProbeUnavailable("The probe service is not running here.")

        report = run("alpha", form(), CHOICES, call=refuse)
        self.assertFalse(report.ran)
        self.assertEqual(report.nodes, ())
        self.assertIn("not running", str(report.problem))

    def test_an_answer_of_nothing_at_all_is_reported_as_such(self) -> None:
        report = self.report("")
        self.assertFalse(report.ran)
        self.assertIn("nothing at all", str(report.problem))

    def test_a_refusal_from_the_helper_is_shown_in_its_own_words(self) -> None:
        report = self.report(
            answered(
                [],
                error={"code": "probe_unavailable", "message": "no probe identity is configured"},
            )
        )
        self.assertFalse(report.ran)
        self.assertIn("probe identity", str(report.problem))

    def test_a_pool_with_no_servers_is_said_rather_than_asked_about(self) -> None:
        report = run("alpha", form(servers=""), CHOICES, call=lambda *a, **k: answered([]))
        self.assertFalse(report.ran)
        self.assertIn("no server", str(report.problem))


if __name__ == "__main__":
    unittest.main()
