"""A dns object on the form, in the listing and in the nodes' verdict (Fas 19a B5).

The design is the one the rest of the form follows (§16f.2 punkt 7): DNS is a
protocol beside the others, the port is the tcp object's field, dnsdist's
balancing and a dns check replace HAProxy's, and what dnsdist cannot carry is
hidden on screen and refused by the engine if it is written anyway.
"""

from __future__ import annotations

import unittest
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest import mock

import yaml
from haproxy_mgmt import status_collect
from haproxy_mgmt.proxy_model import load_proxy

from haproxy_ui import form_groups, health, objects, views
from haproxy_ui.db import ClusterStatus
from haproxy_ui.preview import DEFAULTS, build_document, form_from_document
from tests.test_editor_page import EditorTestCase

GOLDEN = Path(__file__).resolve().parents[2] / "tests" / "golden" / "dns"


def dns_form(**fields: Any) -> dict[str, Any]:
    return {
        **DEFAULTS,
        "name": "resolver",
        "protocol": "dns",
        "backend": "dns",
        "servers": "192.0.2.53:53\n192.0.2.54:53",
        **fields,
    }


def built(**fields: Any) -> dict[str, Any]:
    document: dict[str, Any] = yaml.safe_load(build_document(dns_form(**fields)))
    return document


class WritingADnsObject(unittest.TestCase):
    def test_an_empty_port_is_dns_s_own(self) -> None:
        self.assertEqual(built()["listen"], {"protocol": "dns", "port": 53})
        self.assertEqual(built(tcp_port="5353")["listen"]["port"], 5353)

    def test_it_is_a_port_and_one_pool_and_the_engine_reads_it(self) -> None:
        document = built(balance="firstAvailable")

        self.assertEqual(document["backend"], "dns")
        self.assertNotIn("routes", document)
        self.assertNotIn("hostnames", document)
        proxy = load_proxy("resolver", build_document(dns_form(balance="firstAvailable")).encode())
        self.assertEqual(proxy.backends["dns"].balance, "firstAvailable")

    def test_a_dns_check_writes_only_what_was_asked(self) -> None:
        self.assertEqual(built(health_type="dns")["backends"]["dns"]["health"], {"type": "dns"})
        self.assertEqual(
            built(
                health_type="dns",
                health_query_name="example.com.",
                health_query_type="SOA",
                health_interval="5s",
            )["backends"]["dns"]["health"],
            {"type": "dns", "interval": "5s", "query_name": "example.com.", "query_type": "SOA"},
        )

    def test_hostnames_left_from_another_protocol_are_not_sent(self) -> None:
        """The field is hidden for dns, so its old text cannot refuse the object (26-10-06)."""

        document = build_document(dns_form(hostnames="ad.example.com", cookie="SRV"))

        self.assertNotIn("hostnames", yaml.safe_load(document))
        load_proxy("resolver", document.encode())

    def test_a_server_may_be_named(self) -> None:
        """B252: looked up when published."""

        document = build_document(dns_form(servers="ns1.example.com:53"))
        proxy = load_proxy("resolver", document.encode())
        self.assertEqual(proxy.backends["dns"].servers[0].host, "ns1.example.com")

    def test_hidden_http_rules_are_not_written_for_it(self) -> None:
        document = built(
            rule_index=["0"], rule_name=["admin"], rule_mode=["deny"], rule_path=["/x"]
        )

        self.assertNotIn("deny_rules", document)

    def test_a_backup_server_is_refused_in_the_engine_s_words(self) -> None:
        document = build_document(dns_form(servers="192.0.2.53:53\n192.0.2.54:53 backup"))
        with self.assertRaisesRegex(Exception, "dnsdist has no backup server"):
            load_proxy("resolver", document.encode())


class OpeningADnsObject(unittest.TestCase):
    def test_the_golden_objects_open_as_what_they_are(self) -> None:
        for path, check in (("resolver.yaml", "dns"), ("iot.yaml", "disabled")):
            with self.subTest(path):
                form = form_from_document((GOLDEN / path).read_text(), networks=("office", "vpn"))
                self.assertEqual((form["protocol"], form["health_type"]), ("dns", check))

    def test_a_question_survives_the_round_trip(self) -> None:
        written = build_document(
            dns_form(health_type="dns", health_query_name="example.com.", health_query_type="A")
        )
        form = form_from_document(written)

        self.assertEqual(
            (form["health_query_name"], form["health_query_type"]), ("example.com.", "A")
        )
        self.assertEqual(build_document(form), written)


class TheClosedGroupsSayWhatDnsHas(unittest.TestCase):
    def test_access_has_no_rate_limit_to_mention(self) -> None:
        groups = form_groups.form_groups(dns_form())

        self.assertEqual(groups["access"].summary, "From everywhere")

    def test_connections_name_only_the_source(self) -> None:
        self.assertEqual(
            form_groups.form_groups(dns_form())["connections"].summary,
            "From the VIP's own address",
        )
        self.assertEqual(
            form_groups.form_groups(dns_form(source="outbound"))["connections"].summary,
            "from outbound",
        )


def status(*nodes: dict[str, Any], cluster: str = "alpha") -> ClusterStatus:
    return ClusterStatus(
        cluster=cluster,
        observed_at=datetime(2026, 10, 6, tzinfo=UTC),
        outcome="done",
        result={"nodes": list(nodes)},
        warnings=[],
        error=None,
        poll_error=None,
    )


def node(
    name: str, *, version: str | None = "2.1.2", servers: Any = None, owner: bool = True
) -> dict[str, Any]:
    listener: dict[str, Any] = {"version": version, "active": servers is not None}
    if servers is not None:
        listener["counters"] = {"uptime_sec": 5, "pools": [], "servers": servers}
    return {
        "name": name,
        "status": {"vip": {"owner": owner}, "servers": [], "dns_listener": listener},
    }


class DnsIsOfferedWhereEveryNodeHasDnsdist(unittest.TestCase):
    def test_every_node_with_dnsdist_offers_it(self) -> None:
        rows = [status(node("node-a"), node("node-b"))]
        self.assertTrue(health.dns_everywhere(rows, cluster="alpha"))

    def test_one_node_without_it_or_from_before_the_field_does_not(self) -> None:
        older = {"name": "node-b", "status": {"servers": []}}
        for second in (node("node-b", version=None), older):
            with self.subTest(second=second):
                self.assertFalse(
                    health.dns_everywhere([status(node("node-a"), second)], cluster="alpha")
                )

    def test_a_cluster_nobody_has_read_does_not(self) -> None:
        self.assertFalse(health.dns_everywhere([], cluster="alpha"))
        self.assertFalse(health.dns_everywhere([status()], cluster="alpha"))


class DnsdistsVerdictLightsTheLamp(unittest.TestCase):
    def test_a_server_down_on_the_holder_is_amber(self) -> None:
        servers = [
            {"pool": "dns", "server": "s1", "status": "UP"},
            {"pool": "dns", "server": "s2", "status": "DOWN"},
        ]
        rows = [status(node("node-a", servers=servers))]

        lamp = health.object_healths(
            rows, cluster="alpha", objects={"resolver": (True, False)}, owners={"dns": "resolver"}
        )["resolver"]

        self.assertEqual((lamp.tone, lamp.label), ("warning", "1/2 up"))

    def test_the_standby_s_verdict_is_left_out_for_a_sourced_object(self) -> None:
        """dnsdist on the standby cannot bind the source address, and says DOWN."""

        rows = [
            status(
                node("node-a", servers=[{"pool": "dns", "server": "s1", "status": "UP"}]),
                node(
                    "node-b",
                    owner=False,
                    servers=[{"pool": "dns", "server": "s1", "status": "DOWN"}],
                ),
            )
        ]

        lamp = health.object_healths(
            rows, cluster="alpha", objects={"resolver": (True, True)}, owners={"dns": "resolver"}
        )["resolver"]

        self.assertEqual(lamp.tone, "healthy")


class TheListingShowsTheObjectsPort(unittest.TestCase):
    def view(self, document: str, protocol: str) -> objects.ObjectView:
        found = objects.object_view(
            {"name": "resolver", "document": document, "readable": True, "protocol": protocol}
        )
        if found is None:
            self.fail("the entry was not read as an object")
        return found

    def test_a_dns_object_s_port_is_read_from_its_document(self) -> None:
        self.assertEqual(self.view((GOLDEN / "iot.yaml").read_text(), "dns").ports, (5353,))

    def test_and_its_servers_as_written(self) -> None:
        self.assertEqual(
            self.view((GOLDEN / "iot.yaml").read_text(), "dns").servers,
            ("192.0.2.61", "192.0.2.62"),
        )

    def test_the_listing_row_carries_them(self) -> None:
        """The row the page draws, not only the view it is made from (26-10-06)."""

        view = self.view((GOLDEN / "iot.yaml").read_text(), "dns")
        (row,) = objects.listed_objects(None, views=[view])

        self.assertEqual((row.ports, row.servers), ((5353,), ("192.0.2.61", "192.0.2.62")))

    def test_the_cell_reads_like_a_site_s_servers_then_port(self) -> None:
        """`domaincontroller1.example.com, domaincontroller2.example.com · 53`, as a site is `shop.example.com · 443`."""

        template = (Path(views.__file__).parent / "templates" / "_proxy-rows.html").read_text()
        self.assertIn(
            "{{ object.servers | join(', ') }} · {% endif %}{{ object.ports | join(', ')", template
        )

    def test_a_tcp_object_s_too(self) -> None:
        document = "schema: 1\nname: db\nlisten: {protocol: tcp, port: 5432}\n"
        self.assertEqual(self.view(document, "tcp").ports, (5432,))

    def test_a_document_that_does_not_read_has_none(self) -> None:
        self.assertEqual(self.view("listen: [", "dns").ports, ())


class AMovedServerIsSaidOnItsObjectsPage(unittest.TestCase):
    """B252: the status names the pool; the page of the object owning it repeats it."""

    def found(self, pool: str) -> list[str]:
        name = status_collect.PublishedName(
            pool=pool, host="ns1.example.com", address="198.51.100.53"
        )
        warning = {
            "code": status_collect.DNS_SERVER_MOVED,
            "message": status_collect.moved_message(name, "now resolves to 198.51.100.9"),
        }
        row = moved(status(node("node-a")), warning)
        return views.moved_dns_servers([row], cluster="alpha", pools=["dns"])

    def test_its_own_pool_is_said(self) -> None:
        self.assertEqual(len(self.found("dns")), 1)
        self.assertIn("ns1.example.com now resolves to 198.51.100.9", self.found("dns")[0])

    def test_another_pool_is_not(self) -> None:
        self.assertEqual(self.found("other"), [])

    def test_the_page_shows_what_it_is_given(self) -> None:
        template = (Path(views.__file__).parent / "templates" / "object.html").read_text()
        self.assertIn("{% for message in dns_moved %}", template)


PUBLISHED = status_collect.PublishedName(
    pool="dns", host="ns1.example.com", address="198.51.100.53"
)


def moved(row: ClusterStatus, warning: dict[str, Any]) -> ClusterStatus:
    return ClusterStatus(
        cluster=row.cluster,
        observed_at=row.observed_at,
        outcome=row.outcome,
        result=row.result,
        warnings=[warning],
        error=None,
        poll_error=None,
    )


class TheEditorOffersDns(EditorTestCase):
    def page(self, rows: list[ClusterStatus]) -> str:
        with mock.patch("haproxy_ui.db.cluster_statuses", return_value=rows):
            return str(self.editor().get("/proxies/alpha/shop/edit").text)

    def test_only_where_every_node_runs_dnsdist(self) -> None:
        offered = r'<option value="dns"[^>]*>DNS</option>'
        self.assertRegex(self.page([status(node("node-a"), node("node-b"))]), offered)
        self.assertNotRegex(
            self.page([status(node("node-a"), node("node-b", version=None))]), offered
        )

    def test_a_dns_object_hides_what_dnsdist_cannot_carry(self) -> None:
        client = self.editor()
        with mock.patch("haproxy_ui.db.cluster_statuses", return_value=[status(node("node-a"))]):
            text = str(
                self.submit(
                    client,
                    "/proxies/alpha/shop/edit",
                    action="check",
                    protocol="dns",
                    hostnames="",
                    balance="chashed",
                    health_type="dns",
                ).text
            )

        self.assertRegex(text, r'<option value="chashed" data-show-when="protocol:dns"\s*selected')
        self.assertRegex(
            text, r'<option value="leastconn" data-show-when="protocol:http https tcp" hidden'
        )
        self.assertRegex(
            text, r'<option value="http" data-show-when="protocol:http https tcp" hidden'
        )
        self.assertRegex(text, r'name="health_query_name"')
        self.assertRegex(text, r"Rate limit")
        self.assertRegex(
            text,
            r'<label data-show-when="protocol:http https tcp" hidden><span class="field-title">Rate limit',
        )
        self.assertNotRegex(text, r'name="tcp_port"[^>]*disabled')
        self.assertIn('placeholder="53"', text)


if __name__ == "__main__":
    unittest.main()
