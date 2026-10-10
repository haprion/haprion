"""The GUIDs, frozen with their values.

Statistics counters survive a reload by GUID, so a GUID that changes silently
resets a graph somebody is reading. The known values below are therefore part
of the test rather than something it recomputes: a refactor that changes what
is hashed has to change these lines, and changing these lines is the decision
the plan asks somebody to take deliberately.

The character rules checked here were read from the HAProxy 3.4.4 documentation
on this machine, not from memory: at most 127 characters, alphanumerics plus
`.`, `:`, `-` and `_`, unique across all object types.
"""

from __future__ import annotations

import unittest

from haprion.guid import (
    MAX_GUID,
    backend_guid,
    frontend_guid,
    guid_is_usable,
    guid_prefix_is_usable,
    guids_for,
    listener_guid_prefix,
    redirect_name,
    redirect_suffixes,
    server_guid,
)
from haprion.proxy_model import Server, load_proxy

MEMBER = Server(host="198.51.100.10", port=8080)


class TheDerivationIsFrozen(unittest.TestCase):
    """Known values, so that a change to the scheme cannot pass unnoticed.

    A failure here is not necessarily a bug - it may be an intended new
    scheme - but it is always a decision, and the plan prices it: every golden
    file is rewritten, and once `shm-stats-file` is enabled every affected
    object's counters reset once.
    """

    def test_the_frontend_guid_has_not_moved(self) -> None:
        self.assertEqual(frontend_guid("shop"), "fe:shop.cdc15a9b56dd3363")

    def test_the_listener_prefix_has_not_moved(self) -> None:
        self.assertEqual(listener_guid_prefix("shop"), "li:shop.9baa183d66778ccb")

    def test_the_backend_guid_has_not_moved(self) -> None:
        self.assertEqual(backend_guid("shop", "web"), "be:shop.f09df8b8d098ecb1")

    def test_the_server_guid_has_not_moved(self) -> None:
        self.assertEqual(server_guid("shop", "web", MEMBER), "srv:shop.df076618bf1c6c86")


class TheSameObjectKeepsTheSameGuid(unittest.TestCase):
    def test_two_runs_agree(self) -> None:
        self.assertEqual(backend_guid("shop", "web"), backend_guid("shop", "web"))

    def test_a_server_is_identified_by_where_it_points_not_by_its_position(self) -> None:
        """Reordering the pool moves no counters.

        A list of servers is edited by people, and an edit that only changes
        the order is not a change to any server. Identifying members by
        position would reset every counter below the insertion point.
        """

        reordered = TWO_POOLS.replace(
            b"      - host: 198.51.100.10\n        port: 8080\n"
            b"      - host: 198.51.100.11\n        port: 8080\n",
            b"      - host: 198.51.100.11\n        port: 8080\n"
            b"      - host: 198.51.100.10\n        port: 8080\n",
        )
        self.assertNotEqual(reordered, TWO_POOLS)

        self.assertEqual(
            guids_for(load_proxy("shop", reordered)),
            guids_for(load_proxy("shop", TWO_POOLS)),
        )

    def test_changing_the_address_is_a_different_server(self) -> None:
        self.assertNotEqual(
            server_guid("shop", "web", Server(host="198.51.100.10", port=8080)),
            server_guid("shop", "web", Server(host="198.51.100.10", port=8081)),
        )

    def test_renaming_the_object_is_a_different_object(self) -> None:
        self.assertNotEqual(frontend_guid("shop"), frontend_guid("store"))


class NoTwoObjectsShareAGuid(unittest.TestCase):
    def test_the_types_do_not_collide_on_the_same_name(self) -> None:
        """`unique across all object types` is HAProxy's wording, not ours.

        The frontend and the backend of a one-backend object have the same
        name in every other respect, which is exactly the case a scheme that
        hashed only the name would get wrong.
        """

        values = {
            frontend_guid("shop"),
            listener_guid_prefix("shop"),
            backend_guid("shop", "shop"),
            server_guid("shop", "shop", MEMBER),
        }

        self.assertEqual(len(values), 4)

    def test_a_whole_object_produces_one_guid_per_thing_in_it(self) -> None:
        guids = guids_for(load_proxy("shop", TWO_POOLS))

        self.assertEqual(len(set(guids.values())), len(guids))
        self.assertEqual(
            sorted(guids),
            [
                "frontend",
                "listen",
                "server:api:198.51.100.20:9000",
                "server:web:198.51.100.10:8080",
                "server:web:198.51.100.11:8080",
            ],
        )


class HaproxyWouldAcceptWhatWeGenerate(unittest.TestCase):
    def test_every_guid_in_an_object_is_within_the_documented_rules(self) -> None:
        for key, value in guids_for(load_proxy("shop", TWO_POOLS)).items():
            with self.subTest(key):
                self.assertTrue(guid_is_usable(value), value)
                self.assertLessEqual(len(value), MAX_GUID)

    def test_a_bind_prefix_leaves_room_for_the_index_haproxy_appends(self) -> None:
        """`guid-prefix` is a prefix, and HAProxy adds `-0`, `-1` and so on.

        A prefix that only just fits inside 127 characters would generate a
        listener GUID that does not, and the failure would arrive as a refused
        configuration rather than as a message about a name.
        """

        self.assertTrue(guid_prefix_is_usable(listener_guid_prefix("shop")))
        self.assertTrue(guid_prefix_is_usable(listener_guid_prefix("a" * 40)))

    def test_the_longest_name_the_model_allows_still_fits(self) -> None:
        longest = "a" * 40

        self.assertLessEqual(len(server_guid(longest, longest, MEMBER)), MAX_GUID)

    def test_a_value_outside_the_character_set_is_not_usable(self) -> None:
        self.assertFalse(guid_is_usable("shop/web"))
        self.assertFalse(guid_is_usable("shop web"))
        self.assertFalse(guid_is_usable(""))
        self.assertFalse(guid_is_usable("a" * (MAX_GUID + 1)))


def redirects(name: str, routes: str, pools: str = "web") -> object:
    """An object whose routes are given, every pool a single server."""

    pool_lines = "".join(
        f"  {pool}:\n    balance: roundrobin\n    health:\n      type: disabled\n"
        f"    servers:\n      - host: 198.51.100.10\n        port: 8080\n"
        for pool in pools.split()
    )
    #
    # The model refuses a pool no route sends to; each extra pool gets one.
    #
    used = "".join(
        f"  - path: /to-{pool}\n    backend: {pool}\n" for pool in pools.split() if pool != "web"
    )
    text = (
        f"schema: 1\nname: {name}\nhostnames: [{name}.example.com]\nlisten:\n  protocol: http\n"
        f"routes:\n{routes}{used}backends:\n{pool_lines}"
    )
    return load_proxy(name, text.encode())


def route(path: str, location: str, match: str = "") -> str:
    exact = f"    match: {match}\n" if match else ""
    return f"  - path: {path}\n{exact}    redirect:\n      location: {location}\n"


ANCHOR = "  - path: /app\n    backend: web\n"


class ARedirectIsNamedFromItsPath(unittest.TestCase):
    """`mgd-shop-redirect-old-app` rather than `mgd-shop-redirect-eee20480` (2026-10-05)."""

    def test_the_root_is_the_plain_word_and_other_paths_follow_it(self) -> None:
        proxy = redirects(
            "shop",
            route("/", "https://example.net/")
            + route("/Old/App.v2", "https://example.net/new")
            + route("/old", "https://example.net/", "exact")
            + ANCHOR,
        )
        self.assertEqual(
            redirect_suffixes(proxy),  # type: ignore[arg-type]
            {
                ("/", "prefix"): "redirect",
                ("/Old/App.v2", "prefix"): "redirect-old-app-v2",
                ("/old", "exact"): "redirect-old-exact",
            },
        )

    def test_the_target_does_not_name_it(self) -> None:
        one = redirects("shop", route("/old", "https://example.net/a") + ANCHOR)
        two = redirects("shop", route("/old", "https://example.org/b") + ANCHOR)
        self.assertEqual(redirect_suffixes(one), redirect_suffixes(two))  # type: ignore[arg-type]

    def test_names_that_would_meet_fall_back_to_the_digest_and_only_those(self) -> None:
        proxy = redirects(
            "shop",
            route("/a.b", "https://example.net/1")
            + route("/a-b", "https://example.net/2")
            + route("/exact", "https://example.net/3")
            + route("/", "https://example.net/4", "exact")
            + route("/kept", "https://example.net/5")
            + ANCHOR,
            pools="web redirect-pool",
        )
        found = redirect_suffixes(proxy)  # type: ignore[arg-type]
        for path, match, location in (
            ("/a.b", "prefix", "https://example.net/1"),
            ("/a-b", "prefix", "https://example.net/2"),
            ("/exact", "prefix", "https://example.net/3"),
            ("/", "exact", "https://example.net/4"),
        ):
            self.assertEqual(
                found[(path, match)], f"redirect-{redirect_name(path, match, location)}"
            )
        self.assertEqual(found[("/kept", "prefix")], "redirect-kept")

    def test_a_pool_of_the_same_name_keeps_its_name(self) -> None:
        proxy = redirects(
            "shop", route("/pool", "https://example.net/") + ANCHOR, pools="web redirect-pool"
        )
        self.assertEqual(
            redirect_suffixes(proxy)[("/pool", "prefix")],  # type: ignore[arg-type]
            f"redirect-{redirect_name('/pool', 'prefix', 'https://example.net/')}",
        )

    def test_a_long_path_falls_back_to_the_digest(self) -> None:
        path = "/segment" * 8
        proxy = redirects("shop", route(path, "https://example.net/") + ANCHOR)
        self.assertEqual(
            redirect_suffixes(proxy)[(path, "prefix")],  # type: ignore[arg-type]
            f"redirect-{redirect_name(path, 'prefix', 'https://example.net/')}",
        )

    def test_two_objects_that_produce_one_backend_name_are_refused(self) -> None:
        from haprion.generate import (  # noqa: PLC0415
            GeneratorError,
            _refuse_shared_backend_names,
        )

        #
        # A pool is named by itself (B250), so `b`'s pool `a-redirect-x` meets
        # `a`'s redirect for `/x` - and both objects' `web`.
        #
        first = redirects("a", route("/x", "https://example.net/") + ANCHOR)
        second = redirects("b", ANCHOR, pools="web a-redirect-x")
        with self.assertRaisesRegex(GeneratorError, r"a-redirect-x \(a, b\); web \(a, b\)"):
            _refuse_shared_backend_names([first, second])  # type: ignore[list-item]
        _refuse_shared_backend_names([first])  # type: ignore[list-item]


TWO_POOLS = b"""
schema: 1
name: shop
hostnames: [shop.example.com]
listen:
  protocol: http
routes:
  - path: /
    backend: web
  - path: /api
    backend: api
backends:
  web:
    balance: roundrobin
    health:
      type: disabled
    servers:
      - host: 198.51.100.10
        port: 8080
      - host: 198.51.100.11
        port: 8080
  api:
    balance: leastconn
    health:
      type: http
      path: /healthz
    servers:
      - host: 198.51.100.20
        port: 9000
"""


if __name__ == "__main__":
    unittest.main()
