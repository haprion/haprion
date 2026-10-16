"""Reading a stored object back into the form that produced it.

`build_document` has always been able to turn a form into a document. The
editor needs the other direction, and the risk there is not that it fails - it
is that it succeeds partially, drops what it has no field for, and writes the
remainder back as if it were the whole object. Every test below is about that
one failure.
"""

from __future__ import annotations

import unittest
from typing import Any

import yaml

from haprion_ui.preview import (
    DEFAULTS,
    Unexpressible,
    build_document,
    form_from_document,
)

SHOP = """
schema: 1
name: shop
hostnames: [shop.example.com]
listen:
  protocol: http
routes:
  - path: /
    backend: web
backends:
  web:
    balance: roundrobin
    health:
      type: disabled
    servers:
      - host: 192.0.2.10
        port: 8080
"""


class ReadingAnObjectBackIntoTheForm(unittest.TestCase):
    def test_a_plain_object_opens(self) -> None:
        form = form_from_document(SHOP)

        self.assertEqual(form["name"], "shop")
        self.assertEqual(form["protocol"], "http")
        self.assertEqual(form["hostnames"], "shop.example.com")
        self.assertEqual(form["servers"], "192.0.2.10:8080")

    def test_what_it_reads_produces_the_same_document(self) -> None:
        """The property the editor depends on, stated directly.

        Opening an object and saving it without touching anything must not
        change it. Anything else means the editor edits by being opened.
        """

        self.assertEqual(
            build_document(form_from_document(SHOP)),
            build_document(form_from_document(build_document(form_from_document(SHOP)))),
        )

    def test_every_field_the_form_offers_survives_the_trip(self) -> None:
        filled = dict(
            DEFAULTS,
            name="app",
            hostnames="app.example.com, www.example.com",
            protocol="https",
            vip="dmz",
            source="outbound",
            certificate="wildcard-example-com",
            hsts=True,
            hsts_subdomains=True,
            balance="hdr",
            balance_key="X-Tenant",
            cookie="hap_app",
            servers="198.51.100.10:8080\n198.51.100.11:8080",
            health_type="http",
            health_path="/healthz",
            health_host="app.example.com",
            health_port="9000",
            backend_tls="system",
            max_connections="50",
            server_timeout="5m",
            slow_start="30s",
            allow_from=("office",),
            allow_ranges="203.0.113.0/24",
            maintenance=True,
            maintenance_message="Back at 09:00",
            unavailable_message="No server answered for %URL%",
            request_headers="X-Tenant: acme\n+X-Trace: 1\n-X-Debug",
            response_headers="X-Frame-Options: DENY\n-Server",
            redirect_path="/old",
            redirect_location="https://example.net/new",
            redirect_status="308",
        )
        document = build_document(filled)

        read = form_from_document(document, networks=("office", "vpn"))

        self.assertEqual(build_document(read), document)

    def test_a_group_is_told_apart_from_an_address(self) -> None:
        """Split by what the cluster defines, never by what a name looks like."""

        document = build_document(
            dict(
                DEFAULTS,
                servers="198.51.100.10:8080",
                allow_from=("office",),
                allow_ranges="203.0.113.0/24",
            )
        )

        read = form_from_document(document, networks=("office",))

        self.assertEqual(read["allow_from"], ("office",))
        self.assertEqual(read["allow_ranges"], "203.0.113.0/24")

    def test_a_group_the_cluster_no_longer_defines_becomes_an_address(self) -> None:
        """Not silently dropped.

        A group removed from the network description leaves objects naming it.
        Putting it in the free-text box keeps it in the document, so the person
        sees it and the publish refuses it - rather than the editor quietly
        widening who may reach the site.
        """

        document = build_document(
            dict(DEFAULTS, servers="198.51.100.10:8080", allow_from=("office",))
        )

        read = form_from_document(document, networks=())

        self.assertEqual(read["allow_from"], ())
        self.assertEqual(read["allow_ranges"], "office")

    def test_a_tcp_object_opens(self) -> None:
        document = build_document(
            dict(
                DEFAULTS,
                servers="198.51.100.10:8080",
                protocol="tcp",
                tcp_port="5432",
                hostnames="",
                certificate="",
            )
        )

        read = form_from_document(document)

        self.assertEqual(read["protocol"], "tcp")
        self.assertEqual(read["tcp_port"], "5432")
        self.assertEqual(build_document(read), document)

    def test_key_order_is_not_a_difference(self) -> None:
        """The author's ordering is the author's, and carries no meaning."""

        reordered = """
schema: 1
name: shop
backends:
  web:
    balance: roundrobin
    health:
      type: disabled
    servers:
      - host: 192.0.2.10
        port: 8080
routes:
  - path: /
    backend: web
listen:
  protocol: http
hostnames: [shop.example.com]
"""

        self.assertEqual(form_from_document(reordered)["name"], "shop")

    def test_a_second_backend_is_refused_rather_than_dropped(self) -> None:
        document = SHOP.replace(
            "backends:\n  web:",
            "backends:\n  api:\n    balance: roundrobin\n"
            "    health:\n      type: disabled\n"
            "    servers:\n      - host: 192.0.2.11\n        port: 8080\n  web:",
        )

        #
        # Which path the refusal names is not pinned. The form reads one backend,
        # so the round trip fails at whichever key first disagrees - the backend
        # it did not read, or the route pointing at it. What matters is that it
        # fails rather than opening with one of the two silently gone.
        #
        with self.assertRaises(Unexpressible):
            form_from_document(document)

    def test_a_second_route_is_refused_rather_than_dropped(self) -> None:
        document = SHOP.replace(
            "  - path: /\n    backend: web",
            "  - path: /\n    backend: web\n  - path: /api\n    backend: web",
        )

        with self.assertRaises(Unexpressible):
            form_from_document(document)

    def test_a_document_that_is_not_an_object_is_refused(self) -> None:
        with self.assertRaises(Unexpressible):
            form_from_document("- not a mapping\n")


class WhatTheFormMayOffer(unittest.TestCase):
    """The choices carry addresses, not just names.

    Which address a site is served on is the thing being chosen. A list of
    names asks the reader to remember a mapping that lives on another page,
    and the mapping is what they came here to be sure about.
    """

    def test_a_vip_is_offered_with_its_address(self) -> None:
        from haprion_ui.preview import PREVIEW_CLUSTER, choices

        offered = choices(PREVIEW_CLUSTER)
        vips = offered["vips"]

        if not isinstance(vips, list):
            raise AssertionError(f"vips is not a list: {vips!r}")
        self.assertIn({"name": "dmz", "address": "198.51.100.20"}, vips)
        self.assertEqual(offered["default_vip_address"], "192.0.2.20")

    def test_a_source_is_offered_with_its_address(self) -> None:
        from haprion_ui.preview import PREVIEW_CLUSTER, choices

        self.assertEqual(
            choices(PREVIEW_CLUSTER)["sources"],
            [{"name": "outbound", "address": "192.0.2.35"}],
        )

    def test_an_address_that_has_not_been_read_is_left_empty(self) -> None:
        """Never guessed. The option still names the VIP; the choice is real."""

        from haprion_ui.preview import named_addresses

        self.assertEqual(named_addresses({"main": ""}), [{"name": "main", "address": ""}])

    def test_the_form_opens_without_a_hostname(self) -> None:
        """So the placeholder shows what several names look like."""

        self.assertEqual(DEFAULTS["hostnames"], "")

    def test_the_form_opens_without_a_server(self) -> None:
        """The example address is the placeholder's, never a value saved unread."""

        self.assertEqual(DEFAULTS["servers"], "")


class ASiteMayNameItsOwnTlsPolicy(unittest.TestCase):
    """The field exists because a bind line belongs to an address, not a site.

    Several sites answer on one VIP through SNI and share its bind line, so the
    VIP's policy is the default for all of them. HAProxy will still hold one
    certificate on that frontend to different terms than the next, which is
    what this writes.
    """

    def document(self, **fields: str) -> dict[str, Any]:
        form = dict(DEFAULTS, servers="198.51.100.10:8080")
        form.update({"protocol": "https", "certificate": "shop", **fields})
        document: dict[str, Any] = yaml.safe_load(build_document(form))
        return document

    def test_a_named_policy_reaches_the_frontend(self) -> None:
        self.assertEqual(self.document(listen_tls_policy="modern")["listen"]["tls"], "modern")

    def test_a_site_that_names_none_writes_no_key(self) -> None:
        """Not an empty string: the VIP deciding is the case that needs no words.

        A key written for every object would move every site off its VIP's
        policy the moment somebody opened its page and pressed save.
        """

        self.assertNotIn("tls", self.document()["listen"])
