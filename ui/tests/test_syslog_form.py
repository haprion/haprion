"""A syslog object on the form, in the listing and in the nodes' verdict (Fas 19b B4).

The design (§16f.3 punkt 7): *Syslog (UDP)* is a protocol beside the others,
offered once every node's keepalived reads the file its virtual servers are
written to; the port is the tcp object's field, 514 when empty; IPVS's
balancing and keepalived's checks replace HAProxy's in the same lists, and what
IPVS cannot carry is hidden on screen and refused by the engine if it is
written anyway.
"""

from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest import mock

import yaml
from haprion.proxy_model import ModelError, load_proxy

from haprion_ui import health, objects, probe
from haprion_ui.db import ClusterStatus
from haprion_ui.health_rows import health_rows
from haprion_ui.preview import (
    BALANCE_CHOICES,
    CHECK_PROTOCOLS,
    DEFAULTS,
    build_document,
    form_from_document,
)
from tests.test_editor_page import EditorTestCase
from tests.test_probe_from_the_form import answered

GOLDEN = Path(__file__).resolve().parents[2] / "tests" / "golden" / "syslog"


def syslog_form(**fields: Any) -> dict[str, Any]:
    return {
        **DEFAULTS,
        "name": "logs",
        "protocol": "syslog",
        "backend": "receivers",
        "servers": "192.0.2.71:514\n192.0.2.72:514",
        "health_type": "udp",
        **fields,
    }


def built(**fields: Any) -> dict[str, Any]:
    document: dict[str, Any] = yaml.safe_load(build_document(syslog_form(**fields)))
    return document


def read(**fields: Any) -> Any:
    return load_proxy("logs", build_document(syslog_form(**fields)).encode())


class WritingASyslogObject(unittest.TestCase):
    def test_an_empty_port_is_syslog_s_own(self) -> None:
        self.assertEqual(built()["listen"], {"protocol": "syslog", "port": 514})
        self.assertEqual(built(tcp_port="5514")["listen"]["port"], 5514)

    def test_it_is_a_port_and_one_pool_and_the_engine_reads_it(self) -> None:
        document = built(balance="firstAvailable")

        self.assertEqual(document["backend"], "receivers")
        self.assertNotIn("routes", document)
        self.assertNotIn("hostnames", document)
        self.assertEqual(
            read(balance="firstAvailable").backends["receivers"].balance, "firstAvailable"
        )

    def test_a_udp_check_writes_only_what_was_asked(self) -> None:
        self.assertEqual(built()["backends"]["receivers"]["health"], {"type": "udp"})
        self.assertEqual(
            built(health_interval="5s", health_fall="2")["backends"]["receivers"]["health"],
            {"type": "udp", "interval": "5s", "fall": 2},
        )

    def test_a_tcp_check_may_name_its_own_port(self) -> None:
        health = built(health_type="tcp", health_port="601")["backends"]["receivers"]["health"]

        self.assertEqual(health, {"type": "tcp", "port": 601})
        self.assertEqual(
            read(health_type="tcp", health_port="601").backends["receivers"].health.port, 601
        )

    def test_what_the_form_hides_for_it_is_not_sent(self) -> None:
        """Left from another protocol, out of sight: none of it may refuse the object."""

        left = {
            "hostnames": "logs.example.com",
            "allow_from": ("office",),
            "allow_ranges": "198.51.100.0/24",
            "deny_ranges": "203.0.113.0/24",
            "rate_limit": "100",
            "source": "outbound",
            "cookie": "SRV",
            "backend_tls": "system",
            "max_connections": "50",
            "server_timeout": "5m",
            "slow_start": "30s",
            "health_rise": "2",
            "health_send": "PING",
            "health_expect": "PONG",
            "health_fast_interval": "1s",
            "health_down_interval": "5s",
        }
        document = built(**left)

        for key in ("hostnames", "allow_from", "deny_from", "rate_limit", "maintenance"):
            self.assertNotIn(key, document)
        self.assertNotIn("source", document["listen"])
        self.assertEqual(document["backends"]["receivers"], built()["backends"]["receivers"])
        read(**left)

    def test_a_check_port_left_from_a_tcp_check_is_not_written_for_udp(self) -> None:
        self.assertEqual(
            built(health_port="601")["backends"]["receivers"]["health"], {"type": "udp"}
        )
        read(health_port="601")

    def test_hidden_http_rules_are_not_written_for_it(self) -> None:
        document = built(
            rule_index=["0"], rule_name=["admin"], rule_mode=["deny"], rule_path=["/x"]
        )

        self.assertNotIn("deny_rules", document)

    def test_a_backup_receiver_is_refused_in_the_engine_s_words(self) -> None:
        with self.assertRaisesRegex(ModelError, "IPVS has no backup receiver"):
            read(servers="192.0.2.71:514\n192.0.2.72:514 backup")

    def test_a_named_receiver_is_refused_in_the_engine_s_words(self) -> None:
        with self.assertRaisesRegex(ModelError, "must be addresses for IPVS"):
            read(servers="logs1.example.com:514")


class TheListsOfferWhatIpvsHas(unittest.TestCase):
    def test_the_checks_are_udp_tcp_and_none(self) -> None:
        offered = {
            name for name, protocols in CHECK_PROTOCOLS.items() if "syslog" in protocols.split()
        }

        self.assertEqual(offered, {"disabled", "tcp", "udp"})

    def test_the_balancing_is_ipvs_s_three(self) -> None:
        offered = {name for name, protocols in BALANCE_CHOICES if "syslog" in protocols.split()}

        self.assertEqual(offered, {"roundrobin", "source", "firstAvailable"})

    def test_udp_is_nobody_else_s(self) -> None:
        self.assertEqual(CHECK_PROTOCOLS["udp"], "syslog")


class OpeningASyslogObject(unittest.TestCase):
    def test_the_golden_objects_open_as_what_they_are(self) -> None:
        for path, check, port in (
            ("logs.yaml", "udp", ""),
            ("audit.yaml", "tcp", "601"),
            ("relay.yaml", "disabled", ""),
        ):
            with self.subTest(path):
                form = form_from_document((GOLDEN / path).read_text())
                self.assertEqual(
                    (form["protocol"], form["health_type"], form["health_port"]),
                    ("syslog", check, port),
                )

    def test_a_pool_that_names_no_check_opens_and_says_disabled_when_saved(self) -> None:
        form = form_from_document((GOLDEN / "relay.yaml").read_text())

        self.assertEqual(built(**form)["backends"]["relays"]["health"], {"type": "disabled"})

    def test_a_check_survives_the_round_trip(self) -> None:
        written = build_document(syslog_form(health_type="tcp", health_port="601", health_fall="1"))

        self.assertEqual(build_document(form_from_document(written)), written)


def status(*nodes: dict[str, Any], cluster: str = "alpha") -> ClusterStatus:
    return ClusterStatus(
        cluster=cluster,
        observed_at=datetime(2026, 10, 8, tzinfo=UTC),
        outcome="done",
        result={"nodes": list(nodes)},
        warnings=[],
        error=None,
        poll_error=None,
    )


def receiver(server: str | None, state: str, address: str = "192.0.2.71") -> dict[str, Any]:
    up = state == "UP"
    return {
        "address": address,
        "port": 514,
        "server": server,
        "status": state,
        "packets": 10 if up else None,
        "bytes": 1000 if up else None,
    }


def service(pool: str | None, *receivers: dict[str, Any]) -> dict[str, Any]:
    return {
        "protocol": "udp",
        "address": "192.0.2.20",
        "port": 514,
        "packets": 10,
        "bytes": 1000,
        "object": "logs" if pool else None,
        "pool": pool,
        "receivers": list(receivers),
    }


def node(
    name: str, *, included: bool | None = True, services: Any = (), owner: bool = True
) -> dict[str, Any]:
    ipvs = {
        "ipvsadm": True,
        "published": True,
        "published_sha256": None,
        "installed": True,
        "installed_sha256": None,
        "included": included,
        "services": list(services),
    }
    return {"name": name, "status": {"vip": {"owner": owner}, "servers": [], "ipvs": ipvs}}


class SyslogIsOfferedWhereEveryNodeIncludesTheFile(unittest.TestCase):
    def test_every_node_including_it_offers_it(self) -> None:
        rows = [status(node("node-a"), node("node-b"))]

        self.assertTrue(health.syslog_everywhere(rows, cluster="alpha"))

    def test_one_node_without_the_include_or_from_before_the_section_does_not(self) -> None:
        older = {"name": "node-b", "status": {"servers": []}}
        for second in (node("node-b", included=False), node("node-b", included=None), older):
            with self.subTest(second=second):
                self.assertFalse(
                    health.syslog_everywhere([status(node("node-a"), second)], cluster="alpha")
                )

    def test_a_cluster_nobody_has_read_does_not(self) -> None:
        self.assertFalse(health.syslog_everywhere([], cluster="alpha"))
        self.assertFalse(health.syslog_everywhere([status()], cluster="alpha"))

    def test_another_cluster_s_nodes_say_nothing_about_this_one(self) -> None:
        rows = [status(node("node-a"), cluster="beta")]

        self.assertFalse(health.syslog_everywhere(rows, cluster="alpha"))


class KeepalivedsVerdictLightsTheLamp(unittest.TestCase):
    def lamp(self, *nodes: dict[str, Any], checked: bool = True) -> health.ObjectHealth:
        return health.object_healths(
            [status(*nodes)],
            cluster="alpha",
            objects={"logs": (checked, True)},
            owners={"receivers": "logs"},
        )["logs"]

    def test_a_receiver_taken_out_is_amber(self) -> None:
        both = service(
            "receivers", receiver("s1", "UP"), receiver("s2", "DOWN", address="192.0.2.72")
        )

        lamp = self.lamp(node("node-a", services=[both]))

        self.assertEqual((lamp.tone, lamp.label), ("warning", "1/2 up"))

    def test_every_receiver_up_on_both_nodes_is_green(self) -> None:
        up = service("receivers", receiver("s1", "UP"))

        lamp = self.lamp(node("node-a", services=[up]), node("node-b", owner=False, services=[up]))

        self.assertEqual((lamp.tone, lamp.label), ("healthy", "1/1 up"))

    def test_the_lamp_is_the_vip_holder_s_as_every_other_object_s(self) -> None:
        """B5 (26-10-08): the messages pass the holder; the standby is not counted."""

        lamp = self.lamp(
            node("node-a", services=[service("receivers", receiver("s1", "UP"))]),
            node("node-b", owner=False, services=[service("receivers", receiver("s1", "DOWN"))]),
        )

        self.assertEqual((lamp.tone, lamp.label), ("healthy", "1/1 up"))

    def test_the_listing_marks_it_so(self) -> None:
        view = objects.object_view(
            {
                "name": "logs",
                "document": (GOLDEN / "logs.yaml").read_text(),
                "readable": True,
                "protocol": "syslog",
                "source": None,
            }
        )

        self.assertTrue(view is not None and view.sourced)

    def test_an_unchecked_pool_is_unlit_although_it_reads_up(self) -> None:
        lamp = self.lamp(
            node("node-a", services=[service("receivers", receiver("s1", "UP"))]), checked=False
        )

        self.assertEqual(lamp.tone, "unknown")

    def test_a_service_the_file_does_not_name_belongs_to_nobody(self) -> None:
        lamp = self.lamp(node("node-a", services=[service(None, receiver(None, "UP"))]))

        self.assertEqual(lamp.label, "")

    def test_a_table_ipvsadm_could_not_read_is_no_receivers(self) -> None:
        unread = node("node-a")
        unread["status"]["ipvs"]["services"] = None

        self.assertEqual(self.lamp(unread).label, "")

    def test_the_editor_s_table_is_the_vip_holder_s(self) -> None:
        up = service("receivers", receiver("s1", "UP"))
        found = health.backend_health(
            [status(node("node-a", services=[up]), node("node-b", owner=False, services=[up]))],
            cluster="alpha",
            obj="logs",
            backend="receivers",
            held_only=True,
        )

        self.assertEqual([entry.node for entry in found.nodes], ["node-a"])

    def test_the_editor_s_table_lists_them_by_address(self) -> None:
        both = service(
            "receivers", receiver("s1", "UP"), receiver("s2", "DOWN", address="192.0.2.72")
        )
        running = replace(
            status(node("node-a", services=[both])),
            result={
                "nodes": [node("node-a", services=[both])],
                "summary": {"release_state": "converged"},
            },
        )
        written = ["192.0.2.71:514", "192.0.2.72:514"]

        def card(
            deployed: list[str], reading: ClusterStatus = running
        ) -> list[tuple[str, str | None]]:
            found = health.backend_health(
                [reading],
                cluster="alpha",
                obj="logs",
                backend="receivers",
                addresses=written,
                deployed=deployed,
            )
            return [
                (found.address(member.server), member.status) for member in found.nodes[0].members
            ]

        self.assertEqual(card(written), [("192.0.2.71:514", "UP"), ("192.0.2.72:514", "DOWN")])
        #
        # Review 26-10-24, 02-10: a draft that moved s2, or nodes not yet on
        # the published version, put the new address beside the old one's health.
        #
        unnamed = [("", "UP"), ("", "DOWN")]
        self.assertEqual(card(["192.0.2.71:514", "192.0.2.99:514"]), unnamed)
        behind = replace(running, result={**running.result, "summary": {"release_state": "behind"}})
        self.assertEqual(card(written, behind), unnamed)


class AMissingIncludeIsSaidInTheListing(unittest.TestCase):
    """Review 26-10-08 F1: not *deploy to add*, which a deploy cannot fix, but what is missing where."""

    def row(self, unforwarded: tuple[str, ...]) -> str:
        from haprion_ui.views import TEMPLATES

        listed = objects.ListedObject(
            name="logs",
            protocol="syslog",
            hostnames=(),
            ports=(514,),
            backend_count=1,
            redirect_http=False,
            readable=True,
            problem=None,
            serving=False,
        )
        macro = TEMPLATES.env.get_template("_proxy-rows.html").module.proxy_rows  # type: ignore[attr-defined]
        return str(macro("alpha", "admin", (), (), (listed,), (), {}, unforwarded=unforwarded))

    def test_the_node_is_named(self) -> None:
        text = self.row(("node-b",))

        self.assertIn("Include missing · node-b", text)
        self.assertNotIn("deploy to add", text)

    def test_two_are_counted(self) -> None:
        self.assertIn("Include missing · 2 nodes", self.row(("node-a", "node-b")))

    def test_without_one_it_is_what_it_was(self) -> None:
        self.assertIn("Inactive · deploy to add", self.row(()))

    def test_both_ways_the_listing_is_drawn_pass_them(self) -> None:
        """The page and its refresh draw the rows with one macro, each passing the nodes."""

        root = Path(objects.__file__).parent
        self.assertIn(
            "unforwarded.get(cluster.cluster, ())",
            (root / "templates" / "proxies.html").read_text(),
        )
        self.assertIn(
            'listing["unforwarded"].get(view.cluster, ())',
            (root / "pages" / "proxies.py").read_text(),
        )

    def test_the_nodes_are_read_from_the_status(self) -> None:
        unread = node("node-b", included=False)
        unread["status"]["ipvs"]["published_servers"] = 1
        waiting = node("node-a", included=False)
        waiting["status"]["ipvs"]["published_servers"] = 0

        self.assertEqual(
            health.syslog_unforwarded([status(waiting, unread)], cluster="alpha"), ("node-b",)
        )


class TheListingShowsTheObjectsPort(unittest.TestCase):
    def view(self, name: str) -> objects.ObjectView:
        found = objects.object_view(
            {
                "name": name,
                "document": (GOLDEN / f"{name}.yaml").read_text(),
                "readable": True,
                "protocol": "syslog",
            }
        )
        if found is None:
            self.fail("the entry was not read as an object")
        return found

    def test_its_port_and_receivers_are_read_from_its_document(self) -> None:
        view = self.view("audit")

        self.assertEqual(view.ports, (5514,))
        self.assertEqual(view.servers, ("192.0.2.81:514", "192.0.2.82:514", "192.0.2.83:514"))

    def test_the_cell_names_them_as_a_raw_port_s(self) -> None:
        template = (Path(objects.__file__).parent / "templates" / "_proxy-rows.html").read_text()

        self.assertIn("object.protocol in ('tcp', 'dns', 'syslog')", template)


class EveryNodeAnswersForItsReceivers(unittest.TestCase):
    def test_it_leaves_from_no_address_so_no_node_is_left_out(self) -> None:
        choices = {"default_vip": "internal", "vip_sources": {"internal": "192.0.2.25"}}

        self.assertEqual(probe.source_address(syslog_form(), choices), "")
        self.assertEqual(probe.source_address(syslog_form(protocol="tcp"), choices), "192.0.2.25")


class ItsCheckIsTestedFromTheNodes(unittest.TestCase):
    """B5: keepalived's checks, tried from each node's own address before a save."""

    CHOICES = {"default_vip": "main", "vip_sources": {"main": "192.0.2.25"}}

    def asked(self, **fields: Any) -> dict[str, Any]:
        requests: list[dict[str, Any]] = []

        def call(request: dict[str, Any], *_a: object, **_k: object) -> str:
            requests.append(request)
            return answered([])

        probe.run("alpha", syslog_form(**fields), self.CHOICES, call=call)
        parameters: dict[str, Any] = requests[0]["parameters"]
        return parameters

    def test_a_udp_check_asks_each_receiver_and_waits_as_keepalived_does(self) -> None:
        parameters = self.asked()

        self.assertEqual(
            [(t["host"], t["port"], t["type"]) for t in parameters["targets"]],
            [("192.0.2.71", 514, "udp"), ("192.0.2.72", 514, "udp")],
        )
        self.assertEqual(parameters["timeout_ms"], 5000)
        self.assertEqual(parameters["source"], "")

    def test_a_tcp_check_connects_to_its_own_port(self) -> None:
        parameters = self.asked(health_type="tcp", health_port="601")

        self.assertEqual(
            {(t["port"], t["type"], t["tls"]) for t in parameters["targets"]}, {(601, "tcp", False)}
        )
        self.assertEqual(parameters["timeout_ms"], 2000)

    def test_not_refused_is_said_as_that_with_what_it_cannot_tell(self) -> None:
        node = {
            "node": "node-a",
            "reachable": True,
            "error": None,
            "source_held": True,
            "results": [
                {
                    "host": "192.0.2.71",
                    "port": 514,
                    "ok": True,
                    "status": None,
                    "error": None,
                    "ms": 5003,
                },
                {
                    "host": "192.0.2.72",
                    "port": 514,
                    "ok": False,
                    "status": None,
                    "error": "refused: nothing listens on the port",
                    "ms": 2,
                },
            ],
        }
        report = probe.run(
            "alpha", syslog_form(), self.CHOICES, call=lambda *a, **k: answered([node])
        )

        first, second = report.nodes[0].results
        self.assertEqual(first.phrase, "not refused")
        self.assertEqual(second.phrase, "refused: nothing listens on the port")
        self.assertTrue(any("firewall" in caveat for caveat in report.caveats))
        rows = health_rows(None, report)
        self.assertEqual(rows[0].last, "not refused · tested")
        self.assertEqual(rows[1].last, "refused: nothing listens on the port · 2 ms · tested")


class TheEditorOffersSyslog(EditorTestCase):
    def page(self, rows: list[ClusterStatus]) -> str:
        with mock.patch("haprion_ui.db.cluster_statuses", return_value=rows):
            return str(self.editor().get("/proxies/alpha/shop/edit").text)

    def syslog_page(self) -> str:
        client = self.editor()
        with mock.patch("haprion_ui.db.cluster_statuses", return_value=[status(node("node-a"))]):
            return str(
                self.submit(
                    client,
                    "/proxies/alpha/shop/edit",
                    action="check",
                    protocol="syslog",
                    hostnames="",
                    balance="source",
                    health_type="tcp",
                ).text
            )

    def test_only_where_every_node_includes_the_file(self) -> None:
        offered = r'<option value="syslog"[^>]*>Syslog \(UDP\)</option>'
        self.assertRegex(self.page([status(node("node-a"), node("node-b"))]), offered)
        self.assertNotRegex(
            self.page([status(node("node-a"), node("node-b", included=False))]), offered
        )

    def test_until_then_it_is_greyed_out_with_the_reason(self) -> None:
        """Review 26-10-08 F2: there, and saying why, rather than missing."""

        self.assertIn(
            '<option value="syslog" disabled>Syslog (UDP) · include missing on a node</option>',
            self.page([status(node("node-a"), node("node-b", included=False))]),
        )

    def test_the_object_page_says_what_serves_it(self) -> None:
        """Review 26-10-08 F3: not HAProxy's shared frontend."""

        template = (Path(objects.__file__).parent / "templates" / "object.html").read_text()
        self.assertIn("by the kernel's IPVS, with each sender's own address", template)

    def test_its_port_s_example_is_514(self) -> None:
        text = self.syslog_page()

        self.assertNotRegex(text, r'name="tcp_port"[^>]*disabled')
        self.assertIn('placeholder="514"', text)

    def test_the_lists_offer_ipvs_s_choices(self) -> None:
        text = self.syslog_page()

        self.assertRegex(
            text,
            r'<option value="source" data-show-when="protocol:http https tcp syslog"\s*selected',
        )
        self.assertRegex(
            text, r'<option value="leastconn" data-show-when="protocol:http https tcp" hidden'
        )
        self.assertRegex(text, r'<option value="udp" data-show-when="protocol:syslog"\s*>udp')
        self.assertRegex(
            text, r'<option value="tcp-tls" data-show-when="protocol:http https tcp" hidden'
        )

    def test_what_ipvs_cannot_carry_is_hidden(self) -> None:
        text = self.syslog_page()

        for hidden in (
            r'<details class="form-group" data-show-when="protocol:http https tcp dns" hidden>'
            r"\s*<summary>.*?Access",
            r'<details class="form-group" data-show-when="protocol:http https tcp dns" hidden>'
            r"\s*<summary>.*?Connections",
            r'<label data-show-when="protocol:http https tcp dns" hidden>'
            r'<span class="field-title">Checks to rise',
            r'<label data-show-when="health_type:tcp tcp-tls;protocol:http https tcp" hidden>'
            r'<span class="field-title">Send',
            r'<div class="form-grid" data-show-when="health_type:http https tcp tcp-tls;'
            r'protocol:http https tcp" hidden>',
        ):
            with self.subTest(hidden=hidden[:60]):
                self.assertRegex(text, hidden)

    def test_a_test_shows_the_vip_holder_s_rows_only(self) -> None:
        def tried(name: str) -> probe.NodeReport:
            return probe.NodeReport(
                node=name,
                reachable=True,
                error=None,
                source_held=True,
                results=(
                    probe.Reached(
                        host="192.0.2.71",
                        port=514,
                        ok=True,
                        status=None,
                        error=None,
                        ms=5000,
                        udp=True,
                    ),
                ),
            )

        report = probe.ProbeReport(ran=True, source="", nodes=(tried("node-a"), tried("node-b")))
        rows = [status(node("node-a"), node("node-b", owner=False))]
        client = self.editor()
        with (
            mock.patch("haprion_ui.probe.run", return_value=report),
            mock.patch("haprion_ui.db.wake_poller"),
            mock.patch("haprion_ui.db.cluster_statuses", return_value=rows),
        ):
            text = str(
                self.submit(
                    client,
                    "/proxies/alpha/shop/edit",
                    action="recheck",
                    protocol="syslog",
                    hostnames="",
                    servers="192.0.2.71:514",
                    health_type="udp",
                ).text
            )

        self.assertIn("<td>node-a</td>", text)
        self.assertNotIn("<td>node-b</td>", text)

    def test_its_check_can_be_tested(self) -> None:
        self.assertIn(
            'value="recheck" class="secondary-button">Test health check', self.syslog_page()
        )

    def test_a_tcp_check_s_port_stays_on_screen(self) -> None:
        text = self.syslog_page()

        self.assertRegex(
            text,
            r'<details class="form-group" data-show-when="health_type:http https tcp tcp-tls">'
            r"\s*<summary>.*?Check details",
        )


if __name__ == "__main__":
    unittest.main()
