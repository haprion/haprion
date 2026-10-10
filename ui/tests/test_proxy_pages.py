"""The Proxies listing a hundred rows at a time, per cluster, past a hundred (B222)."""

from __future__ import annotations

import unittest
from dataclasses import replace
from typing import Any
from unittest import mock

from haprion_ui import proxies
from tests.test_login import LoginTestCase, configuration
from tests.test_search import entry, objects_reading


class TheAddress(unittest.TestCase):
    def test_each_clusters_page_is_read_and_nonsense_is_ignored(self) -> None:
        asked = proxies.pages_asked(
            {"page-alpha": "3", "page-beta": "0", "page-gamma": "x", "sort": "name"}
        )

        self.assertEqual(asked, {"alpha": 3})

    def test_a_link_moves_one_table_and_leaves_the_others(self) -> None:
        self.assertEqual(
            proxies.page_link({"beta": 2}, "alpha", 3), "/proxies?page-alpha=3&page-beta=2"
        )
        self.assertEqual(proxies.page_link({"alpha": 2}, "alpha", 1), "/proxies")


class TheListing(LoginTestCase):
    def get(self, path: str, count: int) -> Any:
        client = self.client(replace(configuration(), clusters=("alpha",)))
        self.sign_in(client)
        reading = objects_reading(*[entry(f"site{n:03d}") for n in range(count)])
        with mock.patch("haprion_ui.db.cluster_objects", return_value=[reading]):
            return client.get(path)

    def test_a_hundred_rows_have_no_pages(self) -> None:
        page = self.get("/proxies", 100)

        self.assertEqual(page.text.count('class="proxy-link"'), 100)
        self.assertNotIn("proxy-pager", page.text)

    def test_past_a_hundred_the_first_hundred_and_a_way_on(self) -> None:
        page = self.get("/proxies", 250)

        self.assertEqual(page.text.count('class="proxy-link"'), 100)
        self.assertIn(">site099<", page.text)
        self.assertNotIn(">site100<", page.text)
        self.assertIn("1–100 of 250", page.text)
        self.assertIn('href="/proxies?page-alpha=2">Next', page.text)
        self.assertNotIn(">Previous<", page.text)

    def test_the_last_page_and_a_page_past_it(self) -> None:
        for path in ("/proxies?page-alpha=3", "/proxies?page-alpha=99"):
            with self.subTest(path=path):
                page = self.get(path, 250)
                self.assertEqual(page.text.count('class="proxy-link"'), 50)
                self.assertIn("201–250 of 250", page.text)
                self.assertNotIn(">Next<", page.text)

    def test_the_refresh_returns_the_page_on_screen(self) -> None:
        rows = self.get("/proxies/rows?page-alpha=2", 250).json()["clusters"]["alpha"]

        self.assertIn(">site100<", rows)
        self.assertNotIn(">site099<", rows)
        self.assertIn("101–200 of 250", rows)


if __name__ == "__main__":
    unittest.main()
