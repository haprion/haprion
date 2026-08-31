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

from haproxy_mgmt.guid import (
    MAX_GUID,
    backend_guid,
    frontend_guid,
    guid_is_usable,
    guid_prefix_is_usable,
    guids_for,
    listener_guid_prefix,
    server_guid,
)
from haproxy_mgmt.proxy_model import Server, load_proxy

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
                "backend:api",
                "backend:web",
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
