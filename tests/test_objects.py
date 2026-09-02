"""The source objects, read from a commit."""

from __future__ import annotations

import unittest
from datetime import UTC, datetime

from haproxy_mgmt.objects import ObjectsError, objects_result

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
