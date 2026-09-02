"""The generator's input, held to the shape the golden files will assume.

Every refusal below is a message somebody reads while wondering why their site
is not working. They are tested for what they say, not only for the fact that
something was raised: "invalid configuration" is technically a refusal and
practically useless.
"""

from __future__ import annotations

import unittest

from haproxy_mgmt.proxy_model import ModelError, load_proxy

MINIMAL = b"""
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


def with_lines(*replacements: tuple[str, str]) -> bytes:
    text = MINIMAL.decode()
    for old, new in replacements:
        assert old in text, old
        text = text.replace(old, new)
    return text.encode()


class TheSmallestUsableObject(unittest.TestCase):
    def test_it_loads_and_defaults_the_things_that_have_obvious_defaults(self) -> None:
        proxy = load_proxy("shop", MINIMAL)

        self.assertEqual(proxy.hostnames, ("shop.example.com",))
        self.assertEqual(proxy.listen.protocol, "http")
        self.assertFalse(proxy.listen.redirect_http)
        #
        # `match` defaults to prefix because that is what almost every route
        # wants, and an exact route is the deliberate exception.
        #
        self.assertEqual(proxy.routes[0].match, "prefix")
        self.assertIsNone(proxy.routes[0].strip_prefix)

    def test_an_unknown_field_is_refused_rather_than_ignored(self) -> None:
        """A key nobody expected is a typo or a feature this version lacks.

        Ignoring it silently means the writer believes something is configured
        that is not, which surfaces as a proxy that quietly does the wrong
        thing.
        """

        with self.assertRaises(ModelError) as caught:
            load_proxy("shop", with_lines(("  protocol: http", "  protocol: http\n  tls: yes")))

        self.assertIn("unknown field", str(caught.exception))

    def test_the_document_must_agree_with_the_file_it_is_in(self) -> None:
        """Two sources for one identity is how a rename generates the old name."""

        with self.assertRaises(ModelError) as caught:
            load_proxy("shop", with_lines(("name: shop", "name: something-else")))

        self.assertIn("must match the file", str(caught.exception))


class RoutesAndPaths(unittest.TestCase):
    def test_a_route_naming_no_backend_is_refused(self) -> None:
        with self.assertRaises(ModelError) as caught:
            load_proxy("shop", with_lines(("    backend: web", "    backend: gone")))

        self.assertIn("names no backend", str(caught.exception))

    def test_a_backend_no_route_uses_is_refused(self) -> None:
        """Either a leftover edit or a route somebody forgot. Both worth saying."""

        with self.assertRaises(ModelError) as caught:
            load_proxy(
                "shop",
                with_lines(
                    (
                        "      - host: 192.0.2.10\n        port: 8080",
                        "      - host: 192.0.2.10\n        port: 8080\n"
                        "  orphan:\n    balance: roundrobin\n    health:\n      type: disabled\n"
                        "    servers:\n      - host: 192.0.2.30\n        port: 80",
                    )
                ),
            )

        self.assertIn("orphan", str(caught.exception))

    def test_a_trailing_slash_is_the_same_route(self) -> None:
        """`/api` and `/api/` are one rule; what is forwarded is the prefix fields' business."""

        proxy = load_proxy("shop", with_lines(("  - path: /", "  - path: /api/")))

        self.assertEqual(proxy.routes[0].path, "/api")

    def test_specificity_is_counted_in_segments_not_characters(self) -> None:
        """`/a/b` beats `/abcdef`: depth is a stronger statement than length."""

        deep = load_proxy("shop", with_lines(("  - path: /", "  - path: /a/b")))
        long = load_proxy("shop", with_lines(("  - path: /", "  - path: /abcdef")))

        self.assertGreater(deep.routes[0].segments, long.routes[0].segments)

    def test_stripping_a_prefix_the_route_does_not_have_is_refused(self) -> None:
        with self.assertRaises(ModelError) as caught:
            load_proxy(
                "shop",
                with_lines(("  - path: /", "  - path: /api\n    strip_prefix: /other")),
            )

        self.assertIn("prefix of the route's own path", str(caught.exception))


class ListenersAndCertificates(unittest.TestCase):
    def test_https_without_a_certificate_is_refused(self) -> None:
        with self.assertRaises(ModelError) as caught:
            load_proxy("shop", with_lines(("  protocol: http", "  protocol: https")))

        self.assertIn("certificate is required", str(caught.exception))

    def test_a_certificate_on_a_plain_listener_is_refused(self) -> None:
        """Not ignored: it means the writer believes the site is encrypted."""

        with self.assertRaises(ModelError) as caught:
            load_proxy(
                "shop", with_lines(("  protocol: http", "  protocol: http\n  certificate: x"))
            )

        self.assertIn("only meaningful for https", str(caught.exception))

    def test_redirecting_to_https_that_does_not_exist_is_refused(self) -> None:
        """Otherwise it generates a redirect loop instead of an error."""

        with self.assertRaises(ModelError) as caught:
            load_proxy(
                "shop", with_lines(("  protocol: http", "  protocol: http\n  redirect_http: true"))
            )

        self.assertIn("requires protocol: https", str(caught.exception))


class BackendsAndHealth(unittest.TestCase):
    def test_the_same_server_twice_is_refused(self) -> None:
        """A copied line makes a pool look twice as healthy as it is."""

        with self.assertRaises(ModelError) as caught:
            load_proxy(
                "shop",
                with_lines(
                    (
                        "      - host: 192.0.2.10\n        port: 8080",
                        "      - host: 192.0.2.10\n        port: 8080\n"
                        "      - host: 192.0.2.10\n        port: 8080",
                    )
                ),
            )

        self.assertIn("same host and port twice", str(caught.exception))

    def test_a_port_that_is_a_boolean_is_refused(self) -> None:
        """`port: true` is 1 in Python. The same trap the worker's payload has."""

        with self.assertRaises(ModelError) as caught:
            load_proxy("shop", with_lines(("        port: 8080", "        port: true")))

        self.assertIn("port number", str(caught.exception))

    def test_an_http_health_check_needs_a_path(self) -> None:
        with self.assertRaises(ModelError) as caught:
            load_proxy("shop", with_lines(("      type: disabled", "      type: http")))

        self.assertIn("absolute path", str(caught.exception))

    def test_a_path_on_a_tcp_health_check_is_refused(self) -> None:
        with self.assertRaises(ModelError) as caught:
            load_proxy(
                "shop", with_lines(("      type: disabled", "      type: tcp\n      path: /x"))
            )

        self.assertIn("means nothing for a tcp health check", str(caught.exception))


class ThingsThatAreNotAProxyObject(unittest.TestCase):
    def test_a_document_that_is_not_a_mapping_is_refused(self) -> None:
        for document in (b"- a list\n", b"just a string\n", b""):
            with self.subTest(document=document), self.assertRaises(ModelError):
                load_proxy("shop", document)

    def test_invalid_yaml_says_so_rather_than_raising_a_parser_error(self) -> None:
        with self.assertRaises(ModelError) as caught:
            load_proxy("shop", b"schema: 1\n  bad: indentation\n")

        self.assertIn("not valid YAML", str(caught.exception))

    def test_a_document_beyond_the_size_limit_is_refused_before_parsing(self) -> None:
        with self.assertRaises(ModelError) as caught:
            load_proxy("shop", b"# " + b"x" * (256 * 1024))

        self.assertIn("size limit", str(caught.exception))


class TheBalancingAlgorithms(unittest.TestCase):
    """Which algorithms an object may ask for, and which it may not.

    The list is deliberately shorter than HAProxy's. Everything left out takes
    an expression as its argument, and a field somebody writes an expression
    into is the raw configuration syntax this project has decided not to offer.
    """

    def test_every_offered_algorithm_loads(self) -> None:
        for algorithm in (
            "roundrobin",
            "static-rr",
            "leastconn",
            "first",
            "source",
            "uri",
            "random",
        ):
            with self.subTest(algorithm):
                proxy = load_proxy(
                    "shop", with_lines(("balance: roundrobin", f"balance: {algorithm}"))
                )

                self.assertEqual(proxy.backends["web"].balance, algorithm)

    def test_an_algorithm_that_hashes_by_name_must_be_told_the_name(self) -> None:
        with self.assertRaises(ModelError) as raised:
            load_proxy("shop", with_lines(("balance: roundrobin", "balance: url_param")))

        self.assertIn("balance_key is required", str(raised.exception))

    def test_a_header_and_a_parameter_are_validated_as_what_they_are(self) -> None:
        for balance, key in (("hdr", "X-Tenant"), ("url_param", "userid")):
            with self.subTest(balance):
                proxy = load_proxy(
                    "shop",
                    with_lines(
                        ("balance: roundrobin", f"balance: {balance}\n    balance_key: {key}")
                    ),
                )

                self.assertEqual(proxy.backends["web"].balance_key, key)

        with self.assertRaises(ModelError) as raised:
            load_proxy(
                "shop",
                with_lines(("balance: roundrobin", "balance: hdr\n    balance_key: not a header")),
            )

        self.assertIn("header name", str(raised.exception))

    def test_a_key_next_to_an_algorithm_that_ignores_it_is_refused(self) -> None:
        """Silently ignoring it would leave somebody believing the pool is sticky."""

        with self.assertRaises(ModelError) as raised:
            load_proxy(
                "shop",
                with_lines(("balance: roundrobin", "balance: roundrobin\n    balance_key: Host")),
            )

        self.assertIn("means nothing", str(raised.exception))

    def test_a_free_haproxy_expression_is_not_an_option(self) -> None:
        """`hash <expression>` is the escape hatch this project decided not to have."""

        with self.assertRaises(ModelError) as raised:
            load_proxy("shop", with_lines(("balance: roundrobin", "balance: hash")))

        self.assertIn("roundrobin", str(raised.exception))


class TheMonitorVariants(unittest.TestCase):
    """Six monitor types as three independent choices.

    An ADC lists TCP, TCP-ECV, HTTP, HTTP-ECV, HTTPS and HTTPS-ECV as separate
    monitors. Here they are combinations of which protocol the check speaks,
    whether it runs over TLS, and whether it reads the answer - the same
    reasoning that made four path modes two optional fields.
    """

    def health(self, body: str) -> object:
        document = with_lines(("    health:\n      type: disabled", f"    health:\n{body}"))
        return load_proxy("shop", document).backends["web"].health

    def test_a_plain_tcp_check_needs_nothing_but_its_type(self) -> None:
        health = self.health("      type: tcp")

        self.assertEqual(health.interval, "2s")
        self.assertEqual((health.rise, health.fall), (2, 3))

    def test_a_content_check_sends_and_expects_together(self) -> None:
        health = self.health("      type: tcp\n      send: PING\n      expect: PONG")

        self.assertEqual((health.send, health.expect), ("PING", "PONG"))

    def test_sending_without_expecting_proves_nothing_a_connection_did_not(self) -> None:
        with self.assertRaises(ModelError) as raised:
            self.health("      type: tcp\n      send: PING")

        self.assertIn("belong together", str(raised.exception))

    def test_an_http_check_carries_a_host_header_when_asked(self) -> None:
        """Without it a name-based backend answers 404 and a healthy pool reads down."""

        health = self.health("      type: http\n      path: /healthz\n      host: app.example.com")

        self.assertEqual(health.host, "app.example.com")
        self.assertEqual(health.expect_status, "200-399")

    def test_a_disabled_check_cannot_also_be_configured(self) -> None:
        with self.assertRaises(ModelError) as raised:
            self.health("      type: disabled\n      interval: 5s")

        self.assertIn("disabled", str(raised.exception))

    def test_a_probe_value_that_would_break_the_line_is_refused(self) -> None:
        with self.assertRaises(ModelError) as raised:
            self.health('      type: tcp\n      send: "a b"\n      expect: c')

        self.assertIn("without spaces", str(raised.exception))

    def test_a_tls_check_forces_the_backend_to_state_its_verification(self) -> None:
        """HAProxy refuses the alternative, and the safe default is not ours to pick."""

        with self.assertRaises(ModelError) as raised:
            self.health("      type: http\n      tls: true\n      path: /healthz")

        self.assertIn("verified", str(raised.exception))


class WhoMayReachAnObject(unittest.TestCase):
    """`allow_from` takes a group the cluster named, or a range written here.

    The named form is better where it fits, because the addresses then live in
    the cluster configuration and the object means the same thing everywhere it
    is published. A range that belongs to one site and nothing else has no
    business being named cluster-wide, though, and writing it in the object is
    the honest answer rather than a workaround.
    """

    def allow(self, entries: str) -> tuple[str, ...]:
        document = with_lines(("routes:", f"allow_from: [{entries}]\nroutes:"))
        return load_proxy("shop", document).allow_from

    def test_a_group_name_and_a_range_may_sit_in_the_same_list(self) -> None:
        self.assertEqual(self.allow("office, 198.51.100.0/24"), ("office", "198.51.100.0/24"))

    def test_a_single_address_is_a_range_of_one(self) -> None:
        self.assertEqual(self.allow("198.51.100.10"), ("198.51.100.10/32",))

    def test_a_range_meaning_everywhere_is_refused(self) -> None:
        """It reads as a restriction and enforces nothing, which is worse than none."""

        with self.assertRaises(ModelError) as raised:
            self.allow("192.0.2.0/0")

        self.assertIn("entire address family", str(raised.exception))

    def test_something_that_is_neither_says_which_it_is_not(self) -> None:
        with self.assertRaises(ModelError) as raised:
            self.allow("'Office Network'")

        self.assertIn("neither a group name nor an address", str(raised.exception))


class TheHealthCheckMayUseItsOwnPort(unittest.TestCase):
    def test_a_check_port_is_separate_from_the_traffic_port(self) -> None:
        """Plenty of systems answer health on a management port of their own."""

        document = with_lines(
            ("    health:\n      type: disabled", "    health:\n      type: tcp\n      port: 8413")
        )

        self.assertEqual(load_proxy("shop", document).backends["web"].health.port, 8413)

    def test_absent_means_the_server_s_own_port(self) -> None:
        document = with_lines(("    health:\n      type: disabled", "    health:\n      type: tcp"))

        self.assertIsNone(load_proxy("shop", document).backends["web"].health.port)


class TakingASiteOutOfServiceWithoutDeletingIt(unittest.TestCase):
    """`maintenance` keeps the object and stops serving it.

    The alternative people reach for is deleting the object, which loses the
    routes, the pools and the checks, and makes the way back a rewrite from
    memory.
    """

    def maintain(self, body: str) -> bytes:
        return with_lines(("routes:", f"maintenance:\n{body}\nroutes:"))

    def test_the_message_is_what_the_visitor_is_told(self) -> None:
        proxy = load_proxy("shop", self.maintain("  message: Back at 18:00."))

        assert proxy.maintenance is not None
        self.assertEqual(proxy.maintenance.message, "Back at 18:00.")

    def test_an_object_that_says_nothing_is_serving(self) -> None:
        self.assertIsNone(load_proxy("shop", MINIMAL).maintenance)

    def test_maintenance_without_a_message_is_refused(self) -> None:
        """A maintenance mode with nothing to say is the naked 503 on purpose."""

        with self.assertRaises(ModelError) as raised:
            load_proxy("shop", self.maintain("  message: ''"))

        self.assertIn("readable text", str(raised.exception))

    def test_a_quote_is_refused_because_it_would_end_the_line(self) -> None:
        with self.assertRaises(ModelError) as raised:
            load_proxy("shop", self.maintain('  message: Back at 18:00" '))

        self.assertIn("without quotes", str(raised.exception))

    def test_a_dollar_sign_is_refused_because_haproxy_expands_it(self) -> None:
        """Measured on 3.4.4: `$HOME` inside double quotes becomes the node's own path."""

        with self.assertRaises(ModelError) as raised:
            load_proxy("shop", self.maintain("  message: Back at $HOME"))

        self.assertIn("$", str(raised.exception))


class WhatAVisitorIsToldWhenNothingAnswers(unittest.TestCase):
    """`unavailable` is the page the site cannot serve for itself."""

    def unavailable(self, body: str) -> bytes:
        return with_lines(("routes:", f"unavailable:\n{body}\nroutes:"))

    def test_the_message_is_carried(self) -> None:
        proxy = load_proxy("shop", self.unavailable("  message: The shop is not answering."))

        assert proxy.unavailable is not None
        self.assertEqual(proxy.unavailable.message, "The shop is not answering.")

    def test_absent_means_haproxy_s_own_text(self) -> None:
        self.assertIsNone(load_proxy("shop", MINIMAL).unavailable)

    def test_it_is_held_to_the_same_rule_as_the_maintenance_message(self) -> None:
        """Both end up in the same kind of quoted configuration line."""

        with self.assertRaises(ModelError) as raised:
            load_proxy("shop", self.unavailable("  message: Ask $USER"))

        self.assertIn("$", str(raised.exception))

    def test_it_is_separate_from_maintenance(self) -> None:
        """One is deliberate and one is a failure; a site may describe both."""

        document = with_lines(
            (
                "routes:",
                "maintenance:\n  message: Back at 18:00.\n"
                "unavailable:\n  message: The shop is not answering.\nroutes:",
            )
        )
        proxy = load_proxy("shop", document)

        assert proxy.maintenance is not None and proxy.unavailable is not None
        self.assertNotEqual(proxy.maintenance.message, proxy.unavailable.message)


class TheOneThingAMessageMayAskToHaveFilledIn(unittest.TestCase):
    def message(self, text: str) -> bytes:
        return with_lines(("routes:", f"unavailable:\n  message: {text}\nroutes:"))

    def test_the_token_is_carried_through_the_model_unchanged(self) -> None:
        """The model keeps what was written; the generator is where it is filled in."""

        proxy = load_proxy("shop", self.message("The site %URL% is not answering."))

        assert proxy.unavailable is not None
        self.assertEqual(proxy.unavailable.message, "The site %URL% is not answering.")

    def test_a_token_this_version_does_not_fill_in_is_refused(self) -> None:
        """Otherwise it reaches a visitor as the literal word between percent signs."""

        with self.assertRaises(ModelError) as raised:
            load_proxy("shop", self.message("The site %SITE% is not answering."))

        self.assertIn("%SITE%", str(raised.exception))
        self.assertIn("%URL%", str(raised.exception))

    def test_a_lone_percent_sign_is_still_ordinary_text(self) -> None:
        proxy = load_proxy("shop", self.message("100% of the pool is down."))

        assert proxy.unavailable is not None
        self.assertIn("100%", proxy.unavailable.message)


class ProtectingOneServerFromMoreThanItCanServe(unittest.TestCase):
    """`max_connections` bounds a server; `slow_start` bounds how fast it returns."""

    def backend(self, *lines: str) -> bytes:
        added = "".join(f"    {line}\n" for line in lines)
        return with_lines(("  web:\n", f"  web:\n{added}"))

    def checked(self, *lines: str) -> bytes:
        document = self.backend(*lines).decode()
        return document.replace("      type: disabled", "      type: tcp").encode()

    def test_a_connection_limit_is_carried(self) -> None:
        self.assertEqual(
            load_proxy("shop", self.backend("max_connections: 50")).backends["web"].max_connections,
            50,
        )

    def test_absent_means_no_limit(self) -> None:
        self.assertIsNone(load_proxy("shop", MINIMAL).backends["web"].max_connections)

    def test_a_limit_of_nothing_is_refused(self) -> None:
        with self.assertRaises(ModelError) as raised:
            load_proxy("shop", self.backend("max_connections: 0"))

        self.assertIn("per server", str(raised.exception))

    def test_a_ramp_is_carried(self) -> None:
        proxy = load_proxy("shop", self.checked("slow_start: 30s"))

        self.assertEqual(proxy.backends["web"].slow_start, "30s")

    def test_a_ramp_without_a_health_check_is_refused(self) -> None:
        """HAProxy applies it when a failed server returns, which needs checks to see."""

        with self.assertRaises(ModelError) as raised:
            load_proxy("shop", self.backend("slow_start: 30s"))

        self.assertIn("health check", str(raised.exception))

    def test_a_ramp_no_longer_than_the_check_interval_is_refused(self) -> None:
        """The weight moves one step per check, so a shorter ramp is one step."""

        with self.assertRaises(ModelError) as raised:
            load_proxy("shop", self.checked("slow_start: 2s"))

        self.assertIn("check interval", str(raised.exception))


class EditingTheHeadersThatPassThrough(unittest.TestCase):
    """Three questions with answers, not a list of operations."""

    def headers(self, body: str) -> bytes:
        return with_lines(("routes:", f"headers:\n{body}\nroutes:"))

    def test_each_direction_is_read_separately(self) -> None:
        proxy = load_proxy(
            "shop",
            self.headers(
                "  request:\n    set:\n      X-Tenant: acme\n  response:\n    delete: [Server]"
            ),
        )

        self.assertEqual(proxy.headers.request.assign, (("X-Tenant", "acme"),))
        self.assertEqual(proxy.headers.response.remove, ("Server",))

    def test_an_object_that_says_nothing_touches_nothing(self) -> None:
        self.assertFalse(load_proxy("shop", MINIMAL).headers)

    def test_one_header_under_two_actions_is_refused(self) -> None:
        """Which one wins would be decided by whichever order this module writes."""

        with self.assertRaises(ModelError) as raised:
            load_proxy(
                "shop",
                self.headers("  request:\n    set:\n      X-Tenant: acme\n    delete: [x-tenant]"),
            )

        self.assertIn("both", str(raised.exception))

    def test_the_forwarded_headers_belong_to_the_cluster(self) -> None:
        """An object setting one would overwrite a measured fact with a guess."""

        with self.assertRaises(ModelError) as raised:
            load_proxy(
                "shop", self.headers("  request:\n    set:\n      X-Forwarded-For: 203.0.113.1")
            )

        self.assertIn("the connection actually was", str(raised.exception))

    def test_a_value_with_a_single_quote_is_refused(self) -> None:
        """The generator writes values in single quotes, so one would end the line."""

        with self.assertRaises(ModelError) as raised:
            load_proxy("shop", self.headers('  request:\n    set:\n      X-Note: "it\'s here"'))

        self.assertIn("single quote", str(raised.exception))

    def test_a_value_yaml_read_as_a_boolean_says_so(self) -> None:
        with self.assertRaises(ModelError) as raised:
            load_proxy("shop", self.headers("  request:\n    set:\n      X-Trace: yes"))

        self.assertIn("quote it", str(raised.exception))

    def test_a_name_that_is_not_a_header_name_is_refused(self) -> None:
        with self.assertRaises(ModelError) as raised:
            load_proxy("shop", self.headers("  request:\n    delete: ['X Tenant']"))

        self.assertIn("not a header name", str(raised.exception))
