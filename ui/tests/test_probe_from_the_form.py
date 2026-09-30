"""Turning the object form into a probe, and reading the answer back.

Everything here is about the mapping. What a check would do lives across half a
dozen fields, and each one changes what a node should try - so the request is
built once, from the form, and these tests are what say it was built right.

The other half is what happens when the probe cannot run at all. A socket
nothing answers on and a backend that is down must not look the same on the page,
so they are kept apart here first.
"""

from __future__ import annotations

import json
import unittest

from haproxy_mgmt.check_policy import EffectiveCheck, effective_checks
from haproxy_mgmt.probe_socket import ProbeUnavailable
from haproxy_mgmt.proxy_model import ModelError, load_proxy

from haproxy_ui.preview import build_document
from haproxy_ui.probe import (
    MAX_TARGETS,
    ProbeReport,
    caveats_for,
    run,
    source_address,
    targets_from,
)


def form(**fields: object) -> dict[str, object]:
    """A whole object's form, because the probe now reads a whole object.

    It used to be enough to name the health fields: the request was built from
    them one at a time. It is built from the model now - the same load a
    publish makes - so the form has to be one an object can be read from, and
    a test that skipped the rest was testing a path the page cannot take.
    """

    written: dict[str, object] = {
        "name": "shop",
        "protocol": "http",
        "hostnames": "shop.example.com",
        "balance": "roundrobin",
        "redirect_status": "301",
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


def checks(**fields: object) -> tuple[EffectiveCheck, ...]:
    """The object's effective checks, by the road the page takes to them.

    Form to document to model to policy. Asserting on the checks alone would
    prove nothing about what the button does; this is the whole derivation,
    and it is the one that drifted before.
    """

    written = form(**fields)
    document = build_document(dict(written))
    return effective_checks(load_proxy(str(written["name"]), document.encode()))


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
    def test_one_target_per_server_in_the_backend(self) -> None:
        targets = targets_from(checks())
        self.assertEqual([entry["host"] for entry in targets], ["198.51.100.10", "198.51.100.11"])
        self.assertEqual([entry["port"] for entry in targets], [8080, 8080])
        self.assertEqual(targets[0]["type"], "http")
        self.assertEqual(targets[0]["path"], "/healthz")

    def test_a_check_port_replaces_the_traffic_port_the_way_haproxy_does(self) -> None:
        self.assertEqual(
            [entry["port"] for entry in targets_from(checks(health_port="9443"))], [9443, 9443]
        )

    def test_a_tls_check_is_verified_the_way_the_backend_is(self) -> None:
        """The box says the check speaks TLS; the backend says whose certificate is trusted.

        Named servers, because a verified backend refuses addressed ones - the
        name is what the certificate is checked against. The old derivation
        built a request for that combination anyway, which is a probe of a
        configuration that cannot exist.
        """

        named = "backend-a.example.net:8080\npool-b.example.net:8080"
        system = targets_from(checks(health_type="https", backend_tls="system", servers=named))[0]
        self.assertTrue(system["tls"])
        self.assertTrue(system["verify"])

        unverified = targets_from(checks(health_type="https", backend_tls="none"))[0]
        self.assertTrue(unverified["tls"])
        self.assertFalse(unverified["verify"])

        self.assertFalse(targets_from(checks())[0]["tls"])

    def test_the_type_box_carries_the_protocol_too(self) -> None:
        """`https` is an http check over TLS, which is what the box says."""

        secure = targets_from(checks(health_type="https"))[0]
        self.assertEqual((secure["type"], secure["tls"]), ("http", True))

        named = "backend-a.example.net:8080"
        plain = targets_from(checks(health_type="http", backend_tls="system", servers=named))[0]
        self.assertEqual((plain["type"], plain["tls"]), ("http", False))

    def test_a_tcp_handshake_check_is_a_tcp_target(self) -> None:
        handshake = targets_from(checks(health_type="tcp-tls"))[0]

        self.assertEqual((handshake["type"], handshake["tls"]), ("tcp", True))

    def test_a_line_that_is_not_a_server_is_refused_rather_than_skipped(self) -> None:
        """The model decides this now, and it refuses rather than dropping one.

        Skipping was this module's own leniency, and it meant a probe could
        report a whole backend green while quietly leaving a member out of it. The
        engine reads the same line and says what is wrong with it, which is the
        answer the editor gives everywhere else.
        """

        with self.assertRaises((ValueError, ModelError)):
            checks(servers="198.51.100.10:8080\nnot-a-server\n\n")

    def test_a_backend_larger_than_the_bound_is_cut_rather_than_refused_by_the_node(self) -> None:
        many = "\n".join(f"198.51.100.10:{port}" for port in range(9000, 9000 + MAX_TARGETS + 5))
        self.assertEqual(len(targets_from(checks(servers=many))), MAX_TARGETS)


class WhetherTheVerdictIsTheChecksOwn(unittest.TestCase):
    """The button runs the object's check early, so it must judge as the check judges."""

    def report(self, status: int, **fields: object):
        answer = answered(
            [
                {
                    "node": "node-a",
                    "reachable": True,
                    "error": None,
                    "results": [
                        {
                            "host": "198.51.100.10",
                            "port": 8080,
                            #
                            # As the node sends it: anything from 200 to 399,
                            # which is HAProxy's default and not this object's.
                            #
                            "ok": 200 <= status <= 399,
                            "status": status,
                            "error": None,
                            "ms": 3,
                        }
                    ],
                }
            ]
        )
        return run("alpha", form(**fields), CHOICES, call=lambda *a, **k: answer)

    def test_an_answer_outside_the_objects_range_fails_here_as_it_would_there(self) -> None:
        report = self.report(200, health_expect_status="204")
        self.assertEqual(report.failing, 1)
        self.assertEqual(report.nodes[0].results[0].error, "answered 200, not 204")

    def test_an_answer_inside_it_passes_even_where_the_node_called_it_bad(self) -> None:
        report = self.report(404, health_expect_status="404")
        self.assertEqual(report.failing, 0)
        self.assertIsNone(report.nodes[0].results[0].error)

    def test_a_range_is_read_as_a_range(self) -> None:
        self.assertEqual(self.report(204, health_expect_status="200-299").failing, 0)
        self.assertEqual(self.report(301, health_expect_status="200-299").failing, 1)

    def test_an_unwritten_range_is_haproxys_own(self) -> None:
        self.assertEqual(self.report(302).failing, 0)
        self.assertEqual(self.report(404).failing, 1)

    def test_a_row_with_no_status_keeps_the_reason_it_failed(self) -> None:
        """A handshake that never happened has nothing to judge."""

        answer = answered(
            [
                {
                    "node": "node-a",
                    "reachable": True,
                    "error": None,
                    "results": [
                        {
                            "host": "198.51.100.10",
                            "port": 8080,
                            "ok": False,
                            "status": None,
                            "error": "TLS failed: WRONG_VERSION_NUMBER",
                            "ms": 2,
                        }
                    ],
                }
            ]
        )
        report = run(
            "alpha", form(health_expect_status="204"), CHOICES, call=lambda *a, **k: answer
        )
        self.assertEqual(report.nodes[0].results[0].error, "TLS failed: WRONG_VERSION_NUMBER")

    def test_an_object_without_a_check_has_nothing_to_trigger(self) -> None:
        report = run(
            "alpha",
            form(health_type="disabled"),
            CHOICES,
            call=lambda *a, **k: self.fail("no node should have been asked"),
        )
        self.assertFalse(report.ran)
        self.assertIn("no health check", str(report.problem))


class WhatThisRunCannotReproduce(unittest.TestCase):
    """Said on the page. A green row under an unsaid caveat is the failure to avoid."""

    def test_a_tcp_exchange_is_not_run(self) -> None:
        notes = caveats_for(checks(health_type="tcp", health_send="PING", health_expect="PONG"))
        self.assertTrue(any("send and expect" in note for note in notes))
        self.assertEqual(caveats_for(checks(health_type="tcp")), ())

    def test_an_expected_body_is_not_read(self) -> None:
        notes = caveats_for(checks(health_expect_body="ok"))
        self.assertTrue(any("expected body" in note for note in notes))

    def test_a_tls_check_is_reproduced_whole(self) -> None:
        """The node's handshake is HAProxy's since 2026-09-30: no name in it."""

        self.assertEqual(caveats_for(checks(health_type="https")), ())
        self.assertEqual(caveats_for(checks()), ())


class WhetherTheRunWasTheWholeCheck(unittest.TestCase):
    """The verdict the row carries, not just the sentence under the table.

    A run that could not reproduce every condition proved less than HAProxy
    will ask for, and until this it said so only in prose below three green
    rows saying `UP` - the same word the nodes' own table uses for having run
    the whole thing. The rows are read first, so the distinction has to be in
    them.
    """

    def report(self, **fields: object) -> ProbeReport:
        return ProbeReport(ran=True, source="", nodes=(), caveats=caveats_for(checks(**fields)))

    def test_a_check_this_run_can_reproduce_is_complete(self) -> None:
        self.assertTrue(self.report().complete)

    def test_an_expected_body_makes_the_run_partial(self) -> None:
        self.assertFalse(self.report(health_expect_body="ok").complete)

    def test_a_tcp_exchange_makes_the_run_partial(self) -> None:
        self.assertFalse(
            self.report(health_type="tcp", health_send="PING", health_expect="PONG").complete
        )

    def test_a_tls_check_is_complete(self) -> None:
        """The handshake sends no name, so there is nothing left out of it."""

        self.assertTrue(self.report(health_type="https").complete)

    def test_completeness_is_the_caveats_and_not_a_second_judgement(self) -> None:
        """Two answers to one question is how they end up disagreeing."""

        self.assertEqual(
            ProbeReport(ran=True, source="", nodes=(), caveats=("anything",)).complete, False
        )


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

    def test_a_service_that_is_not_there_is_not_a_backend_that_failed(self) -> None:
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

    def test_a_backend_with_no_servers_is_said_rather_than_asked_about(self) -> None:
        """In the engine's words, which is the point of reading the object.

        A backend with no members is refused wherever it is read, and a second
        sentence written here would be a second rule to keep in step with the
        first. What the reader needs is that this is not a backend that failed.
        """

        report = run("alpha", form(servers=""), CHOICES, call=lambda *a, **k: answered([]))
        self.assertFalse(report.ran)
        self.assertIn("at least one server", str(report.problem))


if __name__ == "__main__":
    unittest.main()


class WhichNodeCouldAnswer(unittest.TestCase):
    """A node that does not hold the source address probed nothing.

    It has to arrive at the page as its own thing. Folded into "failed" it
    becomes a red row about a healthy backend; dropped entirely it becomes a
    cluster that appears to have one node.
    """

    def report(self, nodes: list[dict[str, object]]):
        return run("alpha", form(), CHOICES, call=lambda *a, **k: answered(nodes))

    def test_the_node_that_holds_the_address_is_named(self) -> None:
        """With the other rows gone, one row would read as a one-node cluster."""

        report = self.report(
            [
                {
                    "node": "node-a",
                    "reachable": True,
                    "error": None,
                    "source_held": False,
                    "results": [],
                },
                {
                    "node": "node-b",
                    "reachable": True,
                    "error": None,
                    "source_held": True,
                    "results": [],
                },
            ]
        )
        self.assertEqual(report.held_by, ("node-b",))

    def test_two_nodes_claiming_one_address_are_both_named(self) -> None:
        """A keepalived pair can do this, and the page must not hide it."""

        report = self.report(
            [
                {
                    "node": "node-a",
                    "reachable": True,
                    "error": None,
                    "source_held": True,
                    "results": [],
                },
                {
                    "node": "node-b",
                    "reachable": True,
                    "error": None,
                    "source_held": True,
                    "results": [],
                },
            ]
        )
        self.assertEqual(report.held_by, ("node-a", "node-b"))

    def test_it_is_neither_a_failure_nor_a_node_that_went_missing(self) -> None:
        report = self.report(
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
                {
                    "node": "node-b",
                    "reachable": True,
                    "error": None,
                    "source_held": False,
                    "results": [],
                },
            ]
        )

        self.assertTrue(report.ran)
        self.assertEqual(len(report.nodes), 2)
        self.assertTrue(report.nodes[1].reachable)
        self.assertIsNone(report.nodes[1].error)
        self.assertFalse(report.nodes[1].source_held)

    def test_a_node_that_said_nothing_about_it_is_not_read_as_no(self) -> None:
        report = self.report([{"node": "node-a", "reachable": True, "error": None, "results": []}])
        self.assertIsNone(report.nodes[0].source_held)
