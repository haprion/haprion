"""The generator's input, held to the shape the golden files will assume.

Every refusal below is a message somebody reads while wondering why their site
is not working. They are tested for what they say, not only for the fact that
something was raised: "invalid configuration" is technically a refusal and
practically useless.
"""

from __future__ import annotations

import unittest
from typing import Any

from haproxy_mgmt.proxy_model import (
    COMMON_KEYS,
    HTTP_ONLY_KEYS,
    NAME,
    PROXY_KEYS,
    TCP_ONLY_KEYS,
    ModelError,
    RateLimit,
    WafException,
    load_proxy,
    name_refusal,
)

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
            load_proxy("shop", with_lines(("  protocol: http", "  protocol: http\n  sni: yes")))

        self.assertIn("unknown field", str(caught.exception))

    def test_a_tls_policy_on_a_listener_without_tls_is_refused(self) -> None:
        """`tls` was this test's example of an unknown field until it became one.

        It is refused still, and for a better reason: there is no handshake on
        a plain http listener to hold to anything, so a policy there is a
        setting somebody would believe was doing something.
        """

        with self.assertRaises(ModelError) as caught:
            load_proxy("shop", with_lines(("  protocol: http", "  protocol: http\n  tls: modern")))

        self.assertIn("only meaningful for https", str(caught.exception))

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

    def test_the_fast_and_down_intervals_are_absent_unless_written(self) -> None:
        self.assertIsNone(self.health("      type: tcp").fast_interval)

        health = self.health("      type: tcp\n      fast_interval: 1s\n      down_interval: 3s")

        self.assertEqual((health.fast_interval, health.down_interval), ("1s", "3s"))

    def test_a_fast_interval_that_is_not_a_duration_is_refused(self) -> None:
        with self.assertRaises(ModelError) as raised:
            self.health("      type: tcp\n      fast_interval: soon")

        self.assertIn("fast_interval must be a duration", str(raised.exception))

    def test_a_disabled_check_cannot_also_be_configured(self) -> None:
        with self.assertRaises(ModelError) as raised:
            self.health("      type: disabled\n      interval: 5s")

        self.assertIn("disabled", str(raised.exception))

    def test_a_probe_value_that_would_break_the_line_is_refused(self) -> None:
        with self.assertRaises(ModelError) as raised:
            self.health('      type: tcp\n      send: "a b"\n      expect: c')

        self.assertIn("without spaces", str(raised.exception))

    def test_a_tls_check_on_a_plain_pool_is_allowed_and_says_so(self) -> None:
        """A health endpoint on its own TLS port. The generator writes `verify none`.

        Refused until 2026-09-05, because what was generated for it - a TLS
        check against a server line with no TLS words at all - is refused by
        HAProxy. `verify none` alone answers that without making the pool TLS,
        measured `L7OK 200`, so the object may say it.
        """

        health = self.health("      type: http\n      tls: true\n      path: /healthz")

        self.assertIs(health.tls, True)

    def test_saying_nothing_about_tls_is_not_saying_no(self) -> None:
        """The distinction `no-check-ssl` exists for: no opinion, against plaintext."""

        self.assertIsNone(self.health("      type: http\n      path: /healthz").tls)
        self.assertIs(
            self.health("      type: http\n      tls: false\n      path: /healthz").tls, False
        )

    def test_tls_must_still_be_a_boolean(self) -> None:
        with self.assertRaises(ModelError) as raised:
            self.health("      type: http\n      tls: maybe\n      path: /healthz")

        self.assertIn("true or false", str(raised.exception))


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

    def test_a_country_is_two_letters_in_upper_case(self) -> None:
        self.assertEqual(self.allow("country:se, office"), ("country:SE", "office"))
        with self.assertRaises(ModelError) as raised:
            self.allow("country:SWE")
        self.assertIn("two letters", str(raised.exception))

    def test_a_range_meaning_everywhere_is_refused(self) -> None:
        """It reads as a restriction and enforces nothing, which is worse than none."""

        with self.assertRaises(ModelError) as raised:
            self.allow("192.0.2.0/0")

        self.assertIn("entire address family", str(raised.exception))

    def test_something_that_is_neither_says_which_it_is_not(self) -> None:
        with self.assertRaises(ModelError) as raised:
            self.allow("'Office Network'")

        self.assertIn("neither a group name nor an address", str(raised.exception))


class WhoAndWhatAnObjectRefuses(unittest.TestCase):
    """`deny_from`, `deny_rules` and `max_request_body` (Fas 21, B227)."""

    def load(self, block: str) -> Any:
        return load_proxy("shop", with_lines(("routes:", f"{block}\nroutes:")))

    def refused(self, block: str) -> str:
        with self.assertRaises(ModelError) as raised:
            self.load(block)
        return str(raised.exception)

    def test_a_new_refusal_only_looks_until_told_to_deny(self) -> None:
        proxy = self.load("deny_from:\n  sources: [office]\ndeny_rules:\n  - name: a\n    path: /x")
        self.assertEqual(proxy.deny_from.mode, "log")
        self.assertEqual(proxy.deny_rules[0].mode, "log")

    def test_a_rule_reads_every_condition_it_names(self) -> None:
        proxy = self.load(
            "deny_rules:\n  - name: admin\n    mode: deny\n    path: /admin/\n"
            "    match: exact\n    methods: [POST, DELETE]\n"
            "    header: {name: User-Agent, contains: sqlmap}\n    source: [198.51.100.7]"
        )
        rule = proxy.deny_rules[0]
        self.assertEqual(
            (rule.path, rule.path_match, rule.methods, rule.sources),
            ("/admin", "exact", ("DELETE", "POST"), ("198.51.100.7/32",)),
        )
        self.assertEqual(
            (rule.header.name, rule.header.match, rule.header.value),
            ("User-Agent", "contains", "sqlmap"),
        )

    def test_all_but_needs_the_sources_it_excepts(self) -> None:
        self.assertIn(
            "needs the sources",
            self.refused("deny_rules:\n  - name: a\n    path: /x\n    source_negate: true"),
        )
        proxy = self.load(
            "deny_rules:\n  - name: a\n    path: /x\n    source: [office]\n    source_negate: true"
        )
        self.assertTrue(proxy.deny_rules[0].source_negate)

    def test_a_rule_without_a_condition_would_refuse_everything(self) -> None:
        self.assertIn(
            "names no condition", self.refused("deny_rules:\n  - name: all\n    mode: deny")
        )

    def test_the_names_the_generator_writes_are_not_a_rule_s(self) -> None:
        for name in ("deny-from", "body-limit", "body-unbounded"):
            with self.subTest(name):
                self.assertIn(
                    "generator itself", self.refused(f"deny_rules:\n  - name: {name}\n    path: /x")
                )

    def test_two_rules_may_not_share_a_name(self) -> None:
        block = "deny_rules:\n  - name: a\n    path: /x\n  - name: a\n    path: /y"
        self.assertIn("same rule twice", self.refused(block))

    def test_a_header_value_is_text_without_a_single_quote(self) -> None:
        self.assertIn(
            "single quote",
            self.refused('deny_rules:\n  - name: a\n    header: {name: X-A, equals: "it\'s"}'),
        )
        self.assertIn(
            "exactly one",
            self.refused("deny_rules:\n  - name: a\n    header: {name: X-A, equals: a, prefix: b}"),
        )

    def test_a_method_is_one_http_knows(self) -> None:
        self.assertIn(
            "methods must list", self.refused("deny_rules:\n  - name: a\n    methods: [get]")
        )

    def test_refusing_everywhere_is_turning_the_site_off(self) -> None:
        self.assertIn(
            "may not refuse an entire address family",
            self.refused("deny_from:\n  mode: deny\n  sources: [0.0.0.0/0]"),
        )

    def test_a_body_size_reads_in_binary_units_within_bounds(self) -> None:
        self.assertEqual(self.load("max_request_body: 10m").max_request_body, 10 * 1024**2)
        self.assertEqual(self.load("max_request_body: 2048").max_request_body, 2048)
        for wrong in ("512", "0k", "10M", "200g", "yes"):
            with self.subTest(wrong):
                self.assertIn("max_request_body", self.refused(f"max_request_body: {wrong}"))

    def test_a_raw_port_refuses_by_address_only_and_only_for_real(self) -> None:
        tcp = TCP.decode()
        denied = load_proxy(
            "db",
            tcp.replace(
                "backend: pool", "deny_from:\n  mode: deny\n  sources: [office]\nbackend: pool"
            ).encode(),
        )
        self.assertEqual(denied.deny_from.mode, "deny")
        for block in (
            "deny_from:\n  sources: [office]",
            "max_request_body: 1m",
            "deny_rules:\n  - name: a\n    path: /x",
        ):
            with self.subTest(block), self.assertRaises(ModelError):
                load_proxy("db", tcp.replace("backend: pool", f"{block}\nbackend: pool").encode())


class TheWafEngineOnAnObject(unittest.TestCase):
    """`waf` (Fas 21 del B, B232)."""

    def load(self, block: str) -> Any:
        return load_proxy("shop", with_lines(("routes:", f"{block}\nroutes:")))

    def refused(self, block: str) -> str:
        with self.assertRaises(ModelError) as raised:
            self.load(block)
        return str(raised.exception)

    def test_an_object_without_the_key_is_not_seen_by_the_engine(self) -> None:
        self.assertIsNone(load_proxy("shop", MINIMAL).waf)

    def test_a_new_engine_only_looks_lets_through_on_error_and_starts_at_level_one(self) -> None:
        waf = self.load("waf: {}").waf
        self.assertEqual(
            (waf.mode, waf.on_engine_error, waf.paranoia, waf.exceptions),
            ("log", "allow", 1, ()),
        )

    def test_every_field_reads_and_each_exception_keeps_its_scope(self) -> None:
        waf = self.load(
            "waf:\n  mode: block\n  on_engine_error: deny\n  paranoia: 2\n"
            "  exceptions:\n"
            "    - rule: 942100\n      field: ARGS:json.q\n      paths: [/search, /find]\n"
            "      by: admin\n      at: 2026-10-03T09:10:00Z\n"
            "    - rule: 920350\n"
            "    - {rule: 913100, field: 'REQUEST_HEADERS:User-Agent'}\n"
            "    - {rule: 930120, field: REQUEST_FILENAME, paths: [/files/]}"
        ).waf
        self.assertEqual((waf.mode, waf.on_engine_error, waf.paranoia), ("block", "deny", 2))
        self.assertEqual(
            waf.exceptions,
            (
                WafException(
                    942100, "ARGS:json.q", ("/find", "/search"), "admin", "2026-10-03T09:10:00Z"
                ),
                WafException(920350),
                WafException(913100, "REQUEST_HEADERS:User-Agent"),
                WafException(930120, "REQUEST_FILENAME", ("/files/",)),
            ),
        )

    def test_the_old_exclusion_list_says_what_replaced_it(self) -> None:
        self.assertIn("replaced by exceptions", self.refused("waf: {exclude_rules: [920350]}"))

    def test_an_exception_writes_nothing_into_the_engine_it_was_not_meant_to(self) -> None:
        for exception, word in (
            ("{rule: 200002}", "rule"),
            ("{rule: '942100'}", "rule"),
            ("{rule: 949110}", "turn the engine off"),  # the blocking decision itself
            ("{rule: 980170}", "turn the engine off"),
            ("{field: ARGS:q}", "rule"),
            ("{rule: 942100, field: 'ARGS:q;942200'}", "field"),
            ("{rule: 942100, field: 'ARGS:a b'}", "field"),
            ("{rule: 942100, field: 'ARGS:\"x\"'}", "field"),
            ("{rule: 942100, field: 'ARGS:a,ctl:ruleEngine=Off'}", "field"),
            ("{rule: 942100, field: 'TX:score'}", "field"),
            ("{rule: 942100, field: REQUEST_HEADERS}", "field"),  # keyed, without its key
            ("{rule: 942100, paths: [search]}", "paths"),
            ("{rule: 942100, paths: ['/a b']}", "paths"),
            ("{rule: 942100, paths: ['/a\"b']}", "paths"),
            ("{rule: 942100, paths: ['/a%20b']}", "paths"),
            ("{rule: 942100, paths: ['/a//b']}", "paths"),
            ("{rule: 942100, paths: ['/a/../b']}", "paths"),
            ("{rule: 942100, paths: ['/a/.']}", "paths"),
            ("{rule: 942100, paths: [/a, /a]}", "paths"),
            ("{rule: 942100, paths: [" + ", ".join(f"/p{n}" for n in range(21)) + "]}", "paths"),
            ("{rule: 942100, by: " + "a" * 65 + "}", "by"),
            ("{rule: 942100, at: 2026-10-03}", "at"),
            ("{rule: 942100, at: '2026-10-03 09:10:00'}", "at"),
            ("{rule: 942100, at: 2026-10-03T11:10:00+02:00}", "at"),  # UTC only
            ("{rule: 942100, why: x}", "why"),
        ):
            with self.subTest(exception):
                self.assertIn(word, self.refused(f"waf: {{exceptions: [{exception}]}}"))

    def test_the_same_rule_on_the_same_scope_twice_is_refused(self) -> None:
        self.assertIn(
            "twice",
            self.refused(
                "waf: {exceptions: [{rule: 942100, paths: [/a]}, {rule: 942100, paths: [/a]}]}"
            ),
        )
        # The same rule on another scope is another exception.
        self.load("waf: {exceptions: [{rule: 942100, paths: [/a]}, {rule: 942100, field: ARGS:q}]}")

    def test_values_outside_their_range_are_refused_by_name(self) -> None:
        for block, field in (
            ("waf: {mode: deny}", "mode"),
            ("waf: {on_engine_error: block}", "on_engine_error"),
            ("waf: {paranoia: 5}", "paranoia"),
            ("waf: {paranoia: true}", "paranoia"),
            ("waf: {exceptions: {rule: 942100}}", "exceptions"),
            ("waf: {level: 2}", "level"),
        ):
            with self.subTest(block):
                self.assertIn(field, self.refused(block))

    def test_crs_is_a_name_only_the_engine_writes_on_a_record(self) -> None:
        self.assertIn("generator itself", self.refused("deny_rules:\n  - name: crs\n    path: /x"))

    def test_a_raw_port_has_no_request_for_the_engine_to_read(self) -> None:
        self.assertIn("waf", HTTP_ONLY_KEYS)
        tcp = TCP.decode()
        with self.assertRaises(ModelError):
            load_proxy("db", tcp.replace("backend: pool", "waf: {}\nbackend: pool").encode())


class HowMuchOneSourceMayAsk(unittest.TestCase):
    """`rate_limit`: requests for http, new connections for tcp, never both."""

    def http(self, block: str) -> RateLimit | None:
        document = with_lines(("routes:", f"rate_limit:\n{block}\nroutes:"))
        return load_proxy("shop", document).rate_limit

    def tcp(self, block: str) -> RateLimit | None:
        document = TCP.replace(
            b"backend: pool\n", f"rate_limit:\n{block}\nbackend: pool\n".encode()
        )
        return load_proxy("db", document).rate_limit

    def test_there_is_no_limit_unless_one_is_written(self) -> None:
        self.assertIsNone(load_proxy("shop", MINIMAL).rate_limit)

    def test_the_window_is_the_cluster_s_default_when_left_out(self) -> None:
        self.assertEqual(
            self.http("  max_requests: 100"), RateLimit(window="10s", max_requests=100)
        )

    def test_a_tcp_object_counts_connections(self) -> None:
        self.assertEqual(
            self.tcp("  window: 1m\n  max_new_connections: 20"),
            RateLimit(window="1m", max_new_connections=20),
        )

    def test_the_threshold_of_the_other_shape_is_refused_with_the_reason(self) -> None:
        """Ignoring it would publish the object with no limit at all."""

        with self.assertRaises(ModelError) as raised:
            self.tcp("  max_requests: 20")
        self.assertIn("a tcp object has no requests", str(raised.exception))

        with self.assertRaises(ModelError) as raised:
            self.http("  max_new_connections: 20")
        self.assertIn("counts requests, not connections", str(raised.exception))

    def test_a_limit_without_a_threshold_is_refused(self) -> None:
        with self.assertRaises(ModelError) as raised:
            self.http("  window: 10s")

        self.assertIn("max_requests must be a count", str(raised.exception))

    def test_a_threshold_that_is_not_a_positive_count_is_refused(self) -> None:
        for value in ("0", "-1", "true", "'100'", "1000001"):
            with self.subTest(value), self.assertRaises(ModelError):
                self.http(f"  max_requests: {value}")

    def test_a_window_that_is_not_seconds_or_minutes_is_refused(self) -> None:
        for value in ("500ms", "1h", "10", "0s"):
            with self.subTest(value), self.assertRaises(ModelError) as raised:
                self.http(f"  window: {value}\n  max_requests: 5")
            self.assertIn("window must be a duration", str(raised.exception))


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

        self.assertIn("double quotes", str(raised.exception))

    def test_a_dollar_sign_is_carried_rather_than_refused(self) -> None:
        """The expansion is HAProxy's, and the generator escapes it there.

        Measured on 3.4.4: `$HOME` inside double quotes becomes the node's own
        path, and `\\$HOME` is the four characters a visitor should read. The
        model has no reason to take a dollar out of a sentence about money.
        """

        proxy = load_proxy("shop", self.maintain("  message: Back at 18:00, refunds cost $0."))

        assert proxy.maintenance is not None
        self.assertEqual(proxy.maintenance.message, "Back at 18:00, refunds cost $0.")


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
            load_proxy("shop", self.unavailable('  message: Ask " somebody'))

        self.assertIn("double quotes", str(raised.exception))

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

    def test_a_line_break_is_refused_where_it_is_still_a_value(self) -> None:
        """The one injection an HTTP header carries, stopped at the model.

        A CR or an LF inside a value ends the header and starts whatever
        follows it - a second header, or a response body. It has to be refused
        here rather than escaped where the line is written: the generator
        writes a configuration line, and by the time HAProxy reads that line
        the break has already become structure.

        Written as YAML escapes in a double-quoted scalar, so the bytes really
        do reach the model rather than being folded away by the parser.
        """

        for name, written in (("carriage return", "\\r"), ("line feed", "\\n")):
            document = self.headers(
                f'  request:\n    set:\n      X-Note: "a{written}X-Admin: true"'
            )
            with self.subTest(name), self.assertRaises(ModelError) as raised:
                load_proxy("shop", document)

            self.assertIn("line breaks", str(raised.exception))

    def test_a_redirect_target_may_not_carry_a_line_break_either(self) -> None:
        """Same value, same injection, a different field that writes a line."""

        document = with_lines(
            (
                "  - path: /\n    backend: web\n",
                "  - path: /old\n    redirect:\n"
                '      location: "https://example.com/\\r\\nX-Admin: true"\n',
            )
        )

        with self.assertRaises(ModelError) as raised:
            load_proxy("shop", document)

        self.assertIn("location", str(raised.exception))

    def test_a_value_yaml_read_as_a_boolean_says_so(self) -> None:
        with self.assertRaises(ModelError) as raised:
            load_proxy("shop", self.headers("  request:\n    set:\n      X-Trace: yes"))

        self.assertIn("quote it", str(raised.exception))

    def test_a_name_that_is_not_a_header_name_is_refused(self) -> None:
        with self.assertRaises(ModelError) as raised:
            load_proxy("shop", self.headers("  request:\n    delete: ['X Tenant']"))

        self.assertIn("not a header name", str(raised.exception))


class ARouteMayAnswerInsteadOfForwarding(unittest.TestCase):
    """Exactly one of `backend` and `redirect`, never both and never neither."""

    def route(self, body: str) -> bytes:
        return with_lines(
            ("  - path: /\n    backend: web\n", f"  - path: /\n    backend: web\n{body}")
        )

    def test_a_redirect_carries_its_location_and_status(self) -> None:
        proxy = load_proxy(
            "shop",
            self.route(
                "  - path: /old\n    redirect:\n"
                "      location: https://example.net/new\n      status: 308\n"
            ),
        )

        redirect = proxy.routes[1].redirect
        assert redirect is not None
        self.assertEqual((redirect.location, redirect.status), ("https://example.net/new", 308))
        self.assertIsNone(proxy.routes[1].backend)

    def test_permanent_is_the_default(self) -> None:
        proxy = load_proxy(
            "shop",
            self.route("  - path: /old\n    redirect:\n      location: https://example.net/new\n"),
        )

        redirect = proxy.routes[1].redirect
        assert redirect is not None
        self.assertEqual(redirect.status, 301)

    def test_both_at_once_is_refused(self) -> None:
        with self.assertRaises(ModelError) as raised:
            load_proxy(
                "shop",
                self.route(
                    "  - path: /old\n    backend: web\n    redirect:\n"
                    "      location: https://example.net/new\n"
                ),
            )

        self.assertIn("exactly one", str(raised.exception))

    def test_a_rewrite_beside_a_redirect_is_refused(self) -> None:
        """It describes what a pool is handed, and a redirect hands a pool nothing."""

        with self.assertRaises(ModelError) as raised:
            load_proxy(
                "shop",
                self.route(
                    "  - path: /old\n    strip_prefix: /old\n    redirect:\n"
                    "      location: https://example.net/new\n"
                ),
            )

        self.assertIn("rewrites the path", str(raised.exception))

    def test_a_status_that_is_not_a_redirect_is_refused(self) -> None:
        with self.assertRaises(ModelError) as raised:
            load_proxy(
                "shop",
                self.route(
                    "  - path: /old\n    redirect:\n"
                    "      location: https://example.net/new\n      status: 200\n"
                ),
            )

        self.assertIn("308", str(raised.exception))

    def test_a_location_that_is_not_absolute_is_refused(self) -> None:
        with self.assertRaises(ModelError) as raised:
            load_proxy("shop", self.route("  - path: /old\n    redirect:\n      location: /new\n"))

        self.assertIn("absolute", str(raised.exception))


TCP = b"""
schema: 1
name: db
listen:
  protocol: tcp
  port: 5432
backend: pool
backends:
  pool:
    balance: leastconn
    health:
      type: tcp
    servers:
      - host: 198.51.100.10
        port: 5432
"""


class ARawPortIsASmallerObject(unittest.TestCase):
    """A tcp object is an address, a port and one pool. Nothing else fits."""

    def tcp(self, *replacements: tuple[bytes, bytes]) -> bytes:
        document = TCP
        for old, new in replacements:
            assert old in document, old
            document = document.replace(old, new)
        return document

    def test_it_loads_with_no_hostnames_and_no_routes(self) -> None:
        proxy = load_proxy("db", TCP)

        self.assertEqual((proxy.hostnames, proxy.routes), ((), ()))
        self.assertEqual((proxy.listen.port, proxy.backend), (5432, "pool"))

    def test_a_port_is_required(self) -> None:
        with self.assertRaises(ModelError) as raised:
            load_proxy("db", self.tcp((b"  port: 5432\n", b"")))

        self.assertIn("required for tcp", str(raised.exception))

    def test_http_may_not_name_a_port(self) -> None:
        """The cluster owns those, and an object naming one would be ignored."""

        document = MINIMAL.replace(b"  protocol: http", b"  protocol: http\n  port: 8080")

        with self.assertRaises(ModelError) as raised:
            load_proxy("shop", document)

        self.assertIn("only meaningful for tcp", str(raised.exception))

    def test_hostnames_are_refused_rather_than_ignored(self) -> None:
        with self.assertRaises(ModelError) as raised:
            load_proxy("db", self.tcp((b"listen:", b"hostnames: [db.example.com]\nlisten:")))

        self.assertIn("no Host header", str(raised.exception))

    def test_routes_are_refused_rather_than_ignored(self) -> None:
        with self.assertRaises(ModelError) as raised:
            load_proxy(
                "db", self.tcp((b"backend: pool\n", b"routes:\n  - path: /\n    backend: pool\n"))
            )

        self.assertIn("no path", str(raised.exception))

    def test_a_balance_that_hashes_an_http_request_is_refused(self) -> None:
        """HAProxy falls back to roundrobin with a warning and exits 0."""

        with self.assertRaises(ModelError) as raised:
            load_proxy("db", self.tcp((b"balance: leastconn", b"balance: uri")))

        self.assertIn("roundrobin", str(raised.exception))

    def test_session_persistence_is_refused_rather_than_ignored(self) -> None:
        with self.assertRaises(ModelError) as raised:
            load_proxy("db", self.tcp((b"    health:", b"    cookie: SRV\n    health:")))

        self.assertIn("ignores it in tcp mode", str(raised.exception))

    def test_every_http_only_key_is_refused_on_a_raw_port(self) -> None:
        """Driven by the table, so this cannot go stale while the table grows.

        The refusal fires on the key being present at all, so the value here is
        only enough YAML to parse.
        """

        for key in HTTP_ONLY_KEYS:
            body = f"{key}: []\n".encode()
            with self.subTest(key), self.assertRaises(ModelError) as raised:
                load_proxy("db", self.tcp((b"listen:", body + b"listen:")))

            self.assertIn(f"db.{key} means nothing for a tcp object", str(raised.exception))

    def test_every_tcp_only_key_is_refused_on_an_http_object(self) -> None:
        for key in TCP_ONLY_KEYS:
            body = f"{key}: web\n".encode()
            with self.subTest(key), self.assertRaises(ModelError) as raised:
                load_proxy("shop", with_lines(("routes:", body.decode() + "routes:")))

            self.assertIn(
                f"shop.{key} means nothing for an http or https object", str(raised.exception)
            )

    def test_a_key_belongs_to_exactly_one_shape(self) -> None:
        """What makes forgetting loud instead of silent.

        A key in neither group is in no allowlist either, so an object carrying
        it is refused for every shape rather than being ignored in `mode tcp` -
        and a key in both groups would be refused for every shape as well,
        which is why the two sets may not overlap.
        """

        self.assertEqual(PROXY_KEYS, COMMON_KEYS | set(HTTP_ONLY_KEYS) | set(TCP_ONLY_KEYS))
        self.assertEqual(set(HTTP_ONLY_KEYS) & set(TCP_ONLY_KEYS), set())
        self.assertEqual(COMMON_KEYS & (set(HTTP_ONLY_KEYS) | set(TCP_ONLY_KEYS)), set())

    def test_a_key_no_shape_claims_is_refused_for_both(self) -> None:
        for shape, document in (
            ("db", self.tcp((b"listen:", b"invented: 1\nlisten:"))),
            ("shop", MINIMAL + b"invented: 1\n"),
        ):
            with self.subTest(shape), self.assertRaises(ModelError) as raised:
                load_proxy(shape, document)

            self.assertIn("invented", str(raised.exception))

    def test_terminating_tls_is_what_https_is_for(self) -> None:
        """Refused by the listener itself, which already allows it only for https."""

        with self.assertRaises(ModelError) as raised:
            load_proxy("db", self.tcp((b"  port: 5432", b"  port: 5432\n  certificate: example")))

        self.assertIn("only meaningful for https", str(raised.exception))


class WhyANameWasRefused(unittest.TestCase):
    """The refusal names the character, not just the rule.

    A name is usually copied from the hostname it serves, and the two things
    that make one unusable - a dot and a capital - are invisible as mistakes
    until somebody says which one it was.
    """

    def test_the_offending_character_is_quoted_back(self) -> None:
        self.assertEqual(name_refusal("ftp2.example.com"), "'.' is not allowed")
        self.assertEqual(name_refusal("ftp:2"), "':' is not allowed")

    def test_an_underscore_is_a_name_and_not_a_refusal(self) -> None:
        """Let in by B72, and proved against a real HAProxy before it was."""

        self.assertIsNotNone(NAME.match("monitor-server-admin_web"))
        self.assertIsNotNone(NAME.match("admin_web"))
        self.assertIsNone(NAME.match("_leading"))

    def test_capitals_are_one_rule_rather_than_a_list_of_letters(self) -> None:
        self.assertEqual(name_refusal("FTP2"), "capital letters are not allowed")
        self.assertEqual(
            name_refusal("ftp2.EX"), "'.' is not allowed and capital letters are not allowed"
        )

    def test_a_name_of_allowed_characters_is_refused_for_its_shape(self) -> None:
        self.assertEqual(name_refusal("2ftp"), "it must start with a letter")
        self.assertEqual(name_refusal("a" * 41), "it is longer than 40 characters")

    def test_the_model_says_it_where_the_name_is_read(self) -> None:
        with self.assertRaises(ModelError) as raised:
            load_proxy(
                "ftp2.example.com", MINIMAL.replace(b"name: shop", b"name: ftp2.example.com")
            )
        self.assertIn("'.' is not allowed", str(raised.exception))
