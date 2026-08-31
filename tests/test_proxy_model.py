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
