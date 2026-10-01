"""The source objects, read from a commit."""

from __future__ import annotations

import unittest
from datetime import UTC, datetime

from haproxy_mgmt.config import Network, Vip
from haproxy_mgmt.generate import source_of, vip_of
from haproxy_mgmt.objects import ObjectsError, objects_result
from haproxy_mgmt.proxy_model import load_proxy

TIME = datetime(2026, 9, 2, 12, 30, tzinfo=UTC)
COMMIT = "a" * 40

SHOP = b"""
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


class ReadingTheStoredObjects(unittest.TestCase):
    def test_an_object_is_returned_as_it_is_written(self) -> None:
        """The document, byte for byte. An editor loads the source, not a rendering."""

        result = objects_result({"managed/proxies/shop.yaml": SHOP}, COMMIT, generated_at=TIME)

        objects = result["objects"]
        assert isinstance(objects, list)
        self.assertEqual(len(objects), 1)
        self.assertEqual(objects[0]["name"], "shop")
        self.assertEqual(objects[0]["document"], SHOP.decode())
        self.assertEqual(objects[0]["protocol"], "http")
        self.assertEqual(objects[0]["hostnames"], ["shop.example.com"])
        self.assertTrue(objects[0]["readable"])

    def test_the_commit_is_returned_so_a_draft_can_record_its_base(self) -> None:
        result = objects_result({}, COMMIT, generated_at=TIME)

        self.assertEqual(result["commit"], COMMIT)
        self.assertEqual(result["generated_at"], "2026-09-02T12:30:00Z")

    def test_a_repository_with_no_commit_lists_nothing(self) -> None:
        """A new cluster, not a broken one - and never a guess from elsewhere."""

        result = objects_result({"managed/proxies/shop.yaml": SHOP}, None, generated_at=TIME)

        self.assertEqual(result["commit"], None)
        self.assertEqual(result["objects"], [])

    def test_an_object_this_version_cannot_read_is_still_listed(self) -> None:
        """It is the one somebody needs to open.

        Dropping it would leave the editor blind to exactly the file that needs
        fixing, and the refusal is the useful part rather than a reason to hide
        the file.
        """

        broken = SHOP.replace(b"protocol: http", b"protocol: gopher")

        result = objects_result({"managed/proxies/shop.yaml": broken}, COMMIT, generated_at=TIME)

        objects = result["objects"]
        assert isinstance(objects, list)
        self.assertFalse(objects[0]["readable"])
        self.assertIn("protocol", str(objects[0]["problem"]))
        self.assertEqual(objects[0]["document"], broken.decode())

    def test_only_the_objects_directory_is_read(self) -> None:
        result = objects_result(
            {
                "managed/proxies/shop.yaml": SHOP,
                "managed/network.yaml": b"vips: {}\n",
                "managed/generated/1000-frontends.cfg": b"frontend x\n",
                "core/haproxy.cfg": b"global\n",
            },
            COMMIT,
            generated_at=TIME,
        )

        objects = result["objects"]
        assert isinstance(objects, list)
        self.assertEqual([entry["name"] for entry in objects], ["shop"])

    def test_the_placeholder_that_keeps_the_directory_is_not_an_object(self) -> None:
        result = objects_result({"managed/proxies/.gitkeep": b""}, COMMIT, generated_at=TIME)

        self.assertEqual(result["objects"], [])

    def test_a_file_shaped_like_no_object_is_refused_not_skipped(self) -> None:
        """The publishing path refuses the same shapes.

        Two readers that disagree about what a proxy object file is would list
        a file here that a publish then rejects.
        """

        for path in (
            "managed/proxies/nested/shop.yaml",
            "managed/proxies/shop.yml",
            "managed/proxies/shop.yaml.bak",
        ):
            with self.subTest(path), self.assertRaises(ObjectsError) as raised:
                objects_result({path: SHOP}, COMMIT, generated_at=TIME)

            self.assertIn(path, str(raised.exception))

    def test_a_document_that_is_not_utf_8_is_refused(self) -> None:
        with self.assertRaises(ObjectsError) as raised:
            objects_result({"managed/proxies/shop.yaml": b"\xff\xfe"}, COMMIT, generated_at=TIME)

        self.assertIn("UTF-8", str(raised.exception))

    def test_a_file_too_large_to_be_an_object_is_refused(self) -> None:
        """Checked before decoding, which is the cost the limit exists to avoid."""

        with self.assertRaises(ObjectsError) as raised:
            objects_result(
                {"managed/proxies/shop.yaml": b"x" * (256 * 1024 + 1)},
                COMMIT,
                generated_at=TIME,
            )

        self.assertIn("larger", str(raised.exception))

    def test_the_objects_come_back_in_a_stable_order(self) -> None:
        """A listing that reorders itself makes every diff look like a change."""

        files = {
            "managed/proxies/shop.yaml": SHOP,
            "managed/proxies/admin.yaml": SHOP.replace(b"name: shop", b"name: admin").replace(
                b"shop.example.com", b"admin.example.com"
            ),
        }

        result = objects_result(files, COMMIT, generated_at=TIME)

        objects = result["objects"]
        assert isinstance(objects, list)
        self.assertEqual([entry["name"] for entry in objects], ["admin", "shop"])


if __name__ == "__main__":
    unittest.main()


class WhatAnEntryCarriesForTheListing(unittest.TestCase):
    """Counted and answered here, so the interface never reads the document.

    One file with two readers is the hardest kind of divergence to find: both
    look correct on their own. The interface shows a backend count and says
    whether an object redirects plain HTTP, and both come from here.
    """

    def entry(self, document: bytes) -> dict[str, object]:
        result = objects_result({"managed/proxies/shop.yaml": document}, COMMIT, generated_at=TIME)
        return result["objects"][0]

    def test_the_backends_are_counted(self) -> None:
        entry = self.entry(SHOP)

        self.assertEqual(entry["backend_count"], 1)

    def test_a_redirect_is_a_property_of_the_object(self) -> None:
        """Not a second object, however many frontends it takes to implement."""

        plain = self.entry(SHOP)
        self.assertIs(plain["redirect_http"], False)

    def test_an_object_that_cannot_be_read_says_nothing_rather_than_zero(self) -> None:
        """A pool with no backends and a file nobody could parse are different."""

        entry = self.entry(b"schema: 1\nname: shop\nthis is not a document\n")

        self.assertFalse(entry["readable"])
        self.assertIsNone(entry["backend_count"])
        self.assertIsNone(entry["redirect_http"])


NETWORK = Network(
    vips={
        "internal": Vip(name="internal", address="192.0.2.20", source="192.0.2.25"),
        "dmz": Vip(name="dmz", address="198.51.100.20", source=None),
    },
    default_vip="internal",
    sources={"outbound": "192.0.2.35"},
    networks={},
)


class WhereAnEntryIsServedFrom(unittest.TestCase):
    """B222: the VIP, source and servers, worked out here by the generator's rule.

    The interface searches and lists by these, and before this it worked them
    out from the document itself - a second reader of the same file, and a
    second copy of the rule that decides which address a site is on.
    """

    def entry(self, listen: str = "", health: str = "disabled") -> dict[str, object]:
        document = SHOP.replace(b"  protocol: http\n", b"  protocol: http\n" + listen.encode())
        document = document.replace(b"type: disabled", f"type: {health}".encode())
        result = objects_result(
            {"managed/proxies/shop.yaml": document}, COMMIT, network=NETWORK, generated_at=TIME
        )
        return result["objects"][0]

    def test_the_default_vip_and_its_own_source(self) -> None:
        entry = self.entry()

        self.assertEqual(
            entry["vip"], {"name": "internal", "address": "192.0.2.20", "default": True}
        )
        self.assertEqual(entry["source"], {"name": None, "address": "192.0.2.25"})

    def test_a_named_vip_and_a_named_source(self) -> None:
        entry = self.entry("  vip: dmz\n  source: outbound\n")

        self.assertEqual(
            entry["vip"], {"name": "dmz", "address": "198.51.100.20", "default": False}
        )
        self.assertEqual(entry["source"], {"name": "outbound", "address": "192.0.2.35"})

    def test_a_vip_without_a_source_leaves_from_no_fixed_address(self) -> None:
        self.assertIsNone(self.entry("  vip: dmz\n")["source"])

    def test_names_the_network_lacks_are_reported_without_an_address(self) -> None:
        self.assertEqual(
            self.entry("  vip: gone\n")["vip"], {"name": "gone", "address": None, "default": False}
        )
        self.assertEqual(
            self.entry("  source: gone\n")["source"], {"name": "gone", "address": None}
        )

    def test_the_rule_is_the_generators(self) -> None:
        for listen in (
            "",
            "  vip: dmz\n",
            "  source: outbound\n",
            "  vip: dmz\n  source: outbound\n",
        ):
            with self.subTest(listen=listen):
                entry = self.entry(listen)
                proxy = load_proxy(
                    "shop",
                    SHOP.replace(b"  protocol: http\n", b"  protocol: http\n" + listen.encode()),
                )
                vip = vip_of(proxy, NETWORK.vips, NETWORK.default_vip)
                source = entry["source"]
                self.assertEqual(entry["vip"]["address"], vip.address)  # type: ignore[index]
                self.assertEqual(
                    source["address"] if isinstance(source, dict) else None,
                    source_of(proxy, vip, NETWORK.sources),
                )

    def test_without_a_network_nothing_is_guessed(self) -> None:
        result = objects_result({"managed/proxies/shop.yaml": SHOP}, COMMIT, generated_at=TIME)

        self.assertIsNone(result["objects"][0]["vip"])
        self.assertIsNone(result["objects"][0]["source"])

    def test_the_servers_and_whether_anything_checks_them(self) -> None:
        self.assertEqual(self.entry()["servers"], ["192.0.2.10:8080"])
        self.assertIs(self.entry()["health_checked"], False)
        self.assertIs(self.entry(health="tcp")["health_checked"], True)

    def test_a_pool_written_by_hand_lists_the_servers_the_text_names(self) -> None:
        document = (
            SHOP.replace(
                b"    balance: roundrobin\n    health:\n      type: disabled\n    servers:\n"
                b"      - host: 192.0.2.10\n        port: 8080\n",
                b"    servers: []\n",
            )
            + b"advanced: |\n  server a 192.0.2.30:8080 check\n"
        )
        result = objects_result(
            {"managed/proxies/shop.yaml": document}, COMMIT, network=NETWORK, generated_at=TIME
        )

        self.assertEqual(result["objects"][0]["servers"], ["192.0.2.30:8080"])
        self.assertIs(result["objects"][0]["health_checked"], False)

    def test_an_unreadable_object_says_nothing(self) -> None:
        result = objects_result(
            {"managed/proxies/shop.yaml": b"schema: 1\nname: shop\n"},
            COMMIT,
            network=NETWORK,
            generated_at=TIME,
        )
        entry = result["objects"][0]

        self.assertEqual(
            (entry["vip"], entry["servers"], entry["health_checked"]), (None, [], None)
        )
