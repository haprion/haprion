"""*Test a path* (B496, 7): which route a path takes on a stored object, said one way."""

from __future__ import annotations

import unittest

from haprion.path_test import (
    ADVANCED_NOTE,
    MAINTENANCE_NOTE,
    PathRefused,
    answer,
    checked_target,
)

SHOP = """schema: 1
name: shop
hostnames: [shop.example.com]
listen:
  protocol: https
  certificate: shop-example-com
routes:
  - path: /
    backend: web
  - path: /api
    backend: api
    strip_prefix: /api
  - path: /health
    match: exact
    backend: web
  - path: /legacy
    redirect:
      location: https://example.net/store
      status: 308
backends:
  web:
    balance: roundrobin
    health:
      type: disabled
    servers:
      - host: 192.0.2.10
        port: 8080
  api:
    balance: roundrobin
    health:
      type: disabled
    servers:
      - host: 192.0.2.20
        port: 8080
"""

#
# Only a redirect at the root of the paths it covers: everything else reaches
# no pool, which is a fact about the object the answer has to say.
#
NO_ROOT = """schema: 1
name: docs
hostnames: [docs.example.com]
listen:
  protocol: http
routes:
  - path: /manual
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


class TheAnswerSaysWhereAPathGoes(unittest.TestCase):
    def test_a_stripped_prefix_is_what_the_server_gets_with_the_query_unchanged(self) -> None:
        found = answer("shop", SHOP, "/api/users?limit=10")

        self.assertEqual(found.sentence, "Route /api · pool api · the server gets /users?limit=10")
        self.assertEqual(found.notes, ())

    def test_a_prefix_ends_on_a_segment_boundary(self) -> None:
        self.assertEqual(
            answer("shop", SHOP, "/apix").sentence, "Route / · pool web · the server gets /apix"
        )

    def test_an_exact_route_says_it_is_exact_and_takes_its_trailing_slash(self) -> None:
        for target in ("/health", "/health/"):
            with self.subTest(target=target):
                self.assertEqual(
                    answer("shop", SHOP, target).sentence,
                    f"Route /health (exact) · pool web · the server gets {target}",
                )

    def test_a_redirect_says_where_and_how(self) -> None:
        found = answer("shop", SHOP, "/legacy/old")

        self.assertEqual(found.sentence, "Redirect 308 to https://example.net/store")
        self.assertIsNone(found.sent)

    def test_a_path_no_route_claims_reaches_no_pool(self) -> None:
        self.assertEqual(
            answer("docs", NO_ROOT, "/blog").sentence,
            "No route matches: the request reaches no pool",
        )


class WhatTheObjectCanChange(unittest.TestCase):
    def test_the_maintenance_page_is_noted(self) -> None:
        document = SHOP + "maintenance:\n  message: Back at noon\n"

        self.assertEqual(answer("shop", document, "/").notes, (MAINTENANCE_NOTE,))

    def test_advanced_config_that_rewrites_a_path_is_noted_and_other_text_is_not(self) -> None:
        rewriting = SHOP + "advanced: |\n  http-request set-path /v2%[path]\n"
        quiet = SHOP + "advanced: |\n  timeout server 30s\n"

        self.assertEqual(answer("shop", rewriting, "/").notes, (ADVANCED_NOTE,))
        self.assertEqual(answer("shop", quiet, "/").notes, ())

    def test_an_action_that_answers_or_changes_the_path_is_noted_one_by_one(self) -> None:
        for action in (
            "auth realm x",
            "normalize-uri path-merge-slashes",
            "normalize-uri percent-decode-unreserved",
        ):
            with self.subTest(action=action):
                document = SHOP + f"advanced: |\n  http-request {action}\n"

                self.assertEqual(answer("shop", document, "/abc").notes, (ADVANCED_NOTE,))


class AQuestionThatCannotBeAsked(unittest.TestCase):
    def test_a_path_a_client_would_not_send_is_refused_with_why(self) -> None:
        for target, reason in (
            ("api/users", "starts with /"),
            ("/a b", "no spaces"),
            ("/a\tb", "no spaces"),
            ("/page#top", "follows #"),
            ("/" + "a" * 2048, "at most 2048"),
        ):
            with self.subTest(target=target[:20]), self.assertRaisesRegex(PathRefused, reason):
                checked_target(target)

    def test_only_an_http_proxy_routes_by_path(self) -> None:
        tcp = """schema: 1
name: db
listen:
  protocol: tcp
  port: 5432
backend: db
backends:
  db:
    balance: roundrobin
    health:
      type: disabled
    servers:
      - host: 192.0.2.30
        port: 5432
"""
        with self.assertRaisesRegex(PathRefused, "Only an http or https proxy"):
            answer("db", tcp, "/")

    def test_an_object_that_cannot_be_read_says_so(self) -> None:
        with self.assertRaisesRegex(PathRefused, "shop cannot be read"):
            answer("shop", "schema: 1\nname: shop\n", "/")


if __name__ == "__main__":
    unittest.main()
