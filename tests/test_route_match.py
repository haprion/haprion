"""The routing semantics, frozen.

These tests are the freeze itself. The plan requires the matching and rewriting
rules to be executable before the first golden file is written, because every
golden file encodes them and a later change to any of them rewrites all of
them. Each rule in the plan has a test here with the same words in its name, so
that a failure points at a sentence somebody can go and read.
"""

from __future__ import annotations

import unittest
from collections.abc import Sequence

from haprion.proxy_model import Route, load_proxy
from haprion.route_match import (
    header_name_is_usable,
    header_value_is_usable,
    matches,
    order_routes,
    rewrite,
    select,
    split_target,
)


def prefix(path: str, backend: str = "web", **fields: str | None) -> Route:
    return Route(path=path, match="prefix", backend=backend, **fields)  # type: ignore[arg-type]


def exact(path: str, backend: str = "web") -> Route:
    return Route(path=path, match="exact", backend=backend)


def backend_for(ordered: Sequence[Route], target: str) -> str | None:
    """The backend of the route that wins, which some route must."""

    route = select(ordered, target)
    assert route is not None, f"no route takes {target}"
    return route.backend


class APrefixMatchesOnASegmentBoundary(unittest.TestCase):
    def test_it_matches_the_prefix_itself_and_anything_below_it(self) -> None:
        route = prefix("/api")

        self.assertTrue(matches(route, "/api"))
        self.assertTrue(matches(route, "/api/v1"))
        self.assertTrue(matches(route, "/api/v1/orders"))

    def test_it_does_not_match_a_longer_first_segment(self) -> None:
        """`/apix` is a different site, not a page below `/api`.

        This is the rule that makes routing predictable. A plain string prefix
        would hand `/apixel` to the API backend, and the report would be that
        one page is broken rather than that one route is wrong.
        """

        route = prefix("/api")

        self.assertFalse(matches(route, "/apix"))
        self.assertFalse(matches(route, "/apix/v1"))
        self.assertFalse(matches(route, "/api-gateway"))

    def test_the_root_prefix_matches_everything(self) -> None:
        route = prefix("/")

        self.assertTrue(matches(route, "/"))
        self.assertTrue(matches(route, "/anything"))
        self.assertTrue(matches(route, "/deeply/nested/page"))


class AnExactRouteMatchesOnePathOnly(unittest.TestCase):
    def test_it_matches_its_own_path_and_nothing_below_it(self) -> None:
        route = exact("/health")

        self.assertTrue(matches(route, "/health"))
        self.assertFalse(matches(route, "/health/live"))
        self.assertFalse(matches(route, "/healthz"))


class TheTrailingSlashIsNormalisedWhenMatching(unittest.TestCase):
    def test_a_route_matches_with_and_without_it(self) -> None:
        self.assertTrue(matches(prefix("/api"), "/api/"))
        self.assertTrue(matches(exact("/health"), "/health/"))

    def test_it_is_normalised_on_the_route_as_it_is_read(self) -> None:
        """`/api/` and `/api` cannot be two different routes.

        Normalising in the model rather than at match time means the two spell
        the same route in a diff, and means the generator cannot emit two
        `acl` lines that can never both be reached.
        """

        proxy = load_proxy("shop", MINIMAL.replace(b"path: /api", b"path: /api/"))

        self.assertEqual(proxy.routes[1].path, "/api")

    def test_what_the_client_typed_survives_into_the_rewrite(self) -> None:
        """Matching normalises; forwarding does not.

        The path mode decides what the backend sees, not the shape of the rule
        that matched. A backend that distinguishes `/api/` from `/api` still
        gets to.
        """

        self.assertEqual(rewrite(prefix("/api"), "/api/"), "/api/")
        self.assertEqual(rewrite(prefix("/api"), "/api"), "/api")


class TheQueryStringIsNeverMatchedAndNeverTouched(unittest.TestCase):
    def test_it_is_split_off_before_matching(self) -> None:
        self.assertTrue(matches(prefix("/api"), split_target("/api?x=/other")[0]))
        self.assertFalse(matches(exact("/health"), split_target("/health/live?a=b")[0]))

    def test_a_query_that_looks_like_a_path_cannot_change_the_route(self) -> None:
        ordered = order_routes([prefix("/"), prefix("/api")])

        chosen = select(ordered, "/shop?next=/api/v1")

        self.assertEqual(chosen and chosen.path, "/")

    def test_it_is_carried_across_a_rewrite_unchanged(self) -> None:
        route = prefix("/api", strip_prefix="/api", add_prefix="/v2")

        self.assertEqual(
            rewrite(route, "/api/orders?id=7&sort=a%20b"), "/v2/orders?id=7&sort=a%20b"
        )

    def test_an_empty_query_is_still_the_client_s_query(self) -> None:
        self.assertEqual(rewrite(prefix("/api"), "/api?"), "/api?")
        self.assertEqual(split_target("/api"), ("/api", ""))


class PercentEncodingIsComparedAsItArrived(unittest.TestCase):
    def test_an_encoded_slash_is_not_a_segment_boundary(self) -> None:
        """No decoding before comparison, deliberately.

        If `%2F` were decoded first, whether `/api%2Fv1` matched `/api` would
        depend on the HAProxy version's normalisation, and the routing rule
        would change meaning on an upgrade rather than on an edit.
        """

        self.assertFalse(matches(prefix("/api"), "/api%2Fv1"))

    def test_an_encoded_route_matches_only_the_same_encoding(self) -> None:
        route = prefix("/a%20b")

        self.assertTrue(matches(route, "/a%20b/c"))
        self.assertFalse(matches(route, "/a b/c"))


class LongestPrefixFirstIsDecidedBySegments(unittest.TestCase):
    def test_a_deeper_route_outranks_a_longer_one(self) -> None:
        ordered = order_routes([prefix("/abcdefghijkl"), prefix("/a/b")])

        self.assertEqual([route.path for route in ordered], ["/a/b", "/abcdefghijkl"])

    def test_the_deepest_matching_route_wins_walking_file_order(self) -> None:
        ordered = order_routes(
            [prefix("/", "site"), prefix("/api", "api"), prefix("/api/v1", "v1")]
        )

        self.assertEqual([route.path for route in ordered], ["/api/v1", "/api", "/"])
        self.assertEqual(backend_for(ordered, "/api/v1/orders"), "v1")
        self.assertEqual(backend_for(ordered, "/api/v2/orders"), "api")
        self.assertEqual(backend_for(ordered, "/about"), "site")

    def test_an_exact_route_sorts_before_a_prefix_at_the_same_depth(self) -> None:
        ordered = order_routes([prefix("/health", "site"), exact("/health")])

        self.assertEqual([route.match for route in ordered], ["exact", "prefix"])
        self.assertEqual(backend_for(ordered, "/health"), "web")
        self.assertEqual(backend_for(ordered, "/health/live"), "site")

    def test_the_order_is_total_so_the_same_object_generates_the_same_file(self) -> None:
        routes = [prefix("/b"), prefix("/a"), prefix("/c")]

        self.assertEqual(order_routes(routes), order_routes(list(reversed(routes))))

    def test_nothing_matches_when_the_object_has_no_root_route(self) -> None:
        ordered = order_routes([prefix("/api")])

        self.assertIsNone(select(ordered, "/about"))


class ThePathModesAreTheFourCombinations(unittest.TestCase):
    def test_preserve_sends_the_path_as_it_arrived(self) -> None:
        self.assertEqual(rewrite(prefix("/api"), "/api/orders"), "/api/orders")

    def test_strip_removes_the_prefix_and_leaves_a_path_behind(self) -> None:
        route = prefix("/api", strip_prefix="/api")

        self.assertEqual(rewrite(route, "/api/orders"), "/orders")
        self.assertEqual(rewrite(route, "/api"), "/")
        self.assertEqual(rewrite(route, "/api/"), "/")

    def test_add_puts_the_backend_s_own_prefix_in_front(self) -> None:
        route = prefix("/api", add_prefix="/v2")

        self.assertEqual(rewrite(route, "/api/orders"), "/v2/api/orders")

    def test_strip_and_add_replace_one_prefix_with_another(self) -> None:
        route = prefix("/api", strip_prefix="/api", add_prefix="/v2")

        self.assertEqual(rewrite(route, "/api/orders"), "/v2/orders")
        self.assertEqual(rewrite(route, "/api"), "/v2/")


class AHeaderNameIsATokenAndAValueHasNoLineEnding(unittest.TestCase):
    def test_a_name_outside_the_token_set_is_not_usable(self) -> None:
        self.assertTrue(header_name_is_usable("X-Request-Id"))
        self.assertFalse(header_name_is_usable("X Request Id"))
        self.assertFalse(header_name_is_usable("X-Request-Id:"))
        self.assertFalse(header_name_is_usable(""))

    def test_a_value_carrying_cr_lf_or_nul_is_not_usable(self) -> None:
        """A value with a line ending in it is a second header.

        Checked where a value is accepted rather than where configuration is
        written: a refusal at generation time arrives after the writer was told
        their change was saved, and with no field to point at.
        """

        self.assertTrue(header_value_is_usable("no-store"))
        self.assertFalse(header_value_is_usable("no-store\r\nX-Injected: yes"))
        self.assertFalse(header_value_is_usable("no-store\nX-Injected: yes"))
        self.assertFalse(header_value_is_usable("no\0store"))


MINIMAL = b"""
schema: 1
name: shop
hostnames: [shop.example.com]
listen:
  protocol: http
routes:
  - path: /
    backend: web
  - path: /api
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


if __name__ == "__main__":
    unittest.main()
