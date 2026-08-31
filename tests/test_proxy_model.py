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

        self.assertIn("only meaningful for an http health check", str(caught.exception))


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
