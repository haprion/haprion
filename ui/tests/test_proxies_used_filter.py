"""The proxy listing narrowed to the objects using one VIP, source or group.

Where the network page's *Used by* count leads (26-10-11). The rule for which
objects count is the network page's own (`network.usage`), so the two pages
never disagree about the number.
"""

from __future__ import annotations

import unittest
from dataclasses import replace

from fastapi.testclient import TestClient

from haprion_ui import proxies
from tests.test_login import LoginTestCase, configuration


class WhatTheAddressAsksFor(unittest.TestCase):
    CLUSTERS = ("alpha", "beta")

    def test_one_kind_on_a_listed_cluster(self) -> None:
        asked = proxies.used_asked({"cluster": "alpha", "vip": "public"}, self.CLUSTERS)

        self.assertEqual(asked, proxies.UsedFilter("alpha", "vip", "public"))

    def test_anything_else_is_the_whole_listing(self) -> None:
        for query in (
            {"vip": "public"},
            {"cluster": "gamma", "vip": "public"},
            {"cluster": "alpha"},
            {"cluster": "alpha", "vip": "public", "group": "office"},
            {"cluster": "alpha", "source": "x" * 256},
        ):
            with self.subTest(query=query):
                self.assertIsNone(proxies.used_asked(query, self.CLUSTERS))

    def test_a_page_link_keeps_the_filter(self) -> None:
        used = proxies.UsedFilter("alpha", "source", "192.0.2.25")

        self.assertEqual(
            proxies.page_link({}, "alpha", 2, used),
            "/proxies?cluster=alpha&source=192.0.2.25&page-alpha=2",
        )


class TheNarrowedListing(LoginTestCase):
    def demo_client(self) -> TestClient:
        client = self.client(replace(configuration(), demo_fixture=True))
        self.sign_in(client)
        return client

    def test_only_the_objects_using_the_vip_on_its_cluster(self) -> None:
        whole = self.demo_client().get("/proxies").text
        page = self.demo_client().get("/proxies?cluster=edge-demo&vip=public").text

        self.assertIn('data-href="/proxies/service-demo/api"', whole)
        self.assertIn('ownership-unmanaged">Manual<', whole)
        self.assertIn("Only objects using VIP <strong>public</strong>", page)
        self.assertIn('<a href="/proxies">All objects</a>', page)
        self.assertIn('data-href="/proxies/edge-demo/public-web"', page)
        self.assertIn('data-href="/proxies/edge-demo/shop"', page)
        self.assertNotIn("service-demo", page, "the other cluster is not drawn")
        self.assertNotIn('ownership-unmanaged">Manual<', page, "nor configuration not owned here")

    def test_a_value_nothing_uses_lists_nothing(self) -> None:
        page = self.demo_client().get("/proxies?cluster=edge-demo&group=nobody").text

        self.assertIn("Only objects using group <strong>nobody</strong>", page)
        self.assertNotIn('data-href="/proxies/edge-demo/', page)

    def test_the_headings_sort_within_the_filter(self) -> None:
        page = self.demo_client().get("/proxies?cluster=edge-demo&vip=public").text

        self.assertIn('href="/proxies?cluster=edge-demo&amp;vip=public&amp;sort=', page)

    def test_the_refresh_returns_the_same_narrowed_rows(self) -> None:
        answer = self.demo_client().get("/proxies/rows?cluster=edge-demo&vip=public").json()

        self.assertEqual(list(answer["clusters"]), ["edge-demo"])
        self.assertIn("/proxies/edge-demo/shop", answer["clusters"]["edge-demo"])
        self.assertNotIn("Manual", answer["clusters"]["edge-demo"])
        self.assertEqual(answer["counts"]["unmanaged"], 0)
        self.assertEqual(answer["counts"]["managed"], 2)


if __name__ == "__main__":
    unittest.main()
