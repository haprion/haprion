"""The header's search and the listing's VIP / source column (B221, B222).

The rows are built from what the objects helper reports, so nothing here reads
a document; the engine's tests hold the helper to the generator's rule. The
query itself runs against PostgreSQL in `test_database_integration`.
"""

from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any
from unittest import mock

from haprion_ui import addresses, demo, search_index
from haprion_ui.db import ClusterObjects, ClusterStatus
from tests.test_cluster_traffic import measurement
from tests.test_login import LoginTestCase, configuration

OBSERVED = datetime(2026, 10, 1, 9, 0, tzinfo=UTC)

SHOP = """schema: 1
name: shop
hostnames:
- shop.example.com
listen:
  protocol: http
routes:
- path: /
  backend: web
backends:
  web:
    balance: roundrobin
    servers:
    - host: 192.0.2.10
      port: 8080
"""


def entry(
    name: str, *, vip: str = "main", address: str = "198.51.100.20", **fields: Any
) -> dict[str, Any]:
    return {
        "name": name,
        "document": SHOP.replace("name: shop", f"name: {name}"),
        "readable": True,
        "problem": None,
        "protocol": "http",
        "hostnames": [f"{name}.example.com"],
        "vip": {"name": vip, "address": address, "default": vip == "main"},
        "source": {"name": None, "address": "198.51.100.25"},
        "servers": ["192.0.2.10:8080", "192.0.2.11:8080"],
        "health_checked": True,
        **fields,
    }


SHOP_ENTRY = entry("shop")
API_ENTRY = entry(
    "api",
    vip="partner",
    address="198.51.100.30",
    source={"name": "outbound", "address": "203.0.113.5"},
    servers=["203.0.113.10:8443"],
)


def objects_reading(*entries: dict[str, Any]) -> ClusterObjects:
    return ClusterObjects(
        cluster="alpha",
        observed_at=OBSERVED,
        outcome="done",
        result={"commit": "a" * 40, "objects": list(entries)},
        warnings=[],
        error=None,
        poll_error=None,
    )


class TheRowsFromAReading(unittest.TestCase):
    def test_an_objects_values_and_what_each_is(self) -> None:
        rows = search_index.object_entries("alpha", {"objects": [SHOP_ENTRY, API_ENTRY]})
        shop = {(row.label, row.value, row.admin_only) for row in rows if row.title == "shop"}
        api = {(row.label, row.value) for row in rows if row.title == "api"}

        self.assertEqual(
            shop,
            {
                ("", "shop", False),
                ("Host", "shop.example.com", False),
                ("VIP main", "198.51.100.20", False),
                ("Source of VIP main", "198.51.100.25", False),
                ("Backend", "192.0.2.10:8080", True),
                ("Backend", "192.0.2.11:8080", True),
            },
        )
        self.assertIn(("Source outbound", "203.0.113.5"), api)
        self.assertEqual({row.href for row in rows if row.title == "api"}, {"/proxies/alpha/api"})

    def test_a_description_is_found_by_its_words(self) -> None:
        described = dict(SHOP_ENTRY, description="Web shop, ask the web team")
        rows = search_index.object_entries("alpha", {"objects": [described]})

        self.assertIn(
            ("Description", "Web shop, ask the web team"),
            {(row.label, row.value) for row in rows},
        )

    def test_an_older_helper_contributes_names_and_hosts_only(self) -> None:
        older = {
            key: value
            for key, value in SHOP_ENTRY.items()
            if key not in ("vip", "source", "servers")
        }

        rows = search_index.object_entries("alpha", {"objects": [older]})

        self.assertEqual({row.label for row in rows}, {"", "Host"})

    def test_the_network_nodes_and_clusters(self) -> None:
        network = search_index.network_entries(
            "alpha",
            {
                "default_vip": "main",
                "vips": [{"name": "main", "address": "198.51.100.20", "source": "198.51.100.25"}],
                "sources": [{"name": "outbound", "address": "203.0.113.5"}],
            },
        )
        nodes = search_index.node_entries(
            "alpha", {"nodes": [{"name": "lb-01", "mgmt_host": "lb-01.example.net"}]}
        )

        self.assertEqual({row.title for row in network}, {"VIP main (default)", "Source outbound"})
        self.assertEqual(
            {(row.label, row.value) for row in nodes},
            {("", "lb-01"), ("Host", "lb-01.example.net")},
        )
        self.assertEqual([row.title for row in search_index.cluster_entries(["alpha"])], ["alpha"])

    def test_certificates_are_the_ones_the_certificates_page_lists(self) -> None:
        reading = demo.certificate_rows()[0]

        rows = search_index.certificate_entries(reading.cluster, reading.result)

        self.assertTrue(rows)
        self.assertTrue(all(row.href.startswith("/certificates") for row in rows))

    def test_a_source_the_search_does_not_read_gives_nothing(self) -> None:
        self.assertIsNone(search_index.entries_for("list", "alpha", {}))


class SearchingInMemory(unittest.TestCase):
    """The demo fixture, which has no rows in the database."""

    def find(
        self, query: str, *, role: str = "admin", page: int = 1, names: int = 0
    ) -> search_index.Results:
        many = [entry(f"site{n:03d}") for n in range(names)]
        rows = search_index.object_entries("alpha", {"objects": [SHOP_ENTRY, API_ENTRY, *many]})
        return search_index.matching(rows, query, role=role, clusters=["alpha"], page=page)

    def test_an_empty_query_searches_nothing(self) -> None:
        self.assertEqual(self.find("  ").total, 0)

    def test_a_backend_says_what_matched_and_only_an_admin_finds_it(self) -> None:
        hit = self.find("192.0.2.11").groups[0].hits[0]

        self.assertEqual((hit.title, hit.matched), ("shop", "Backend 192.0.2.11:8080"))
        self.assertEqual(self.find("192.0.2.11", role="reader").total, 0)

    def test_a_reader_is_taken_to_the_listing(self) -> None:
        self.assertEqual(self.find("api", role="reader").groups[0].hits[0].href, "/proxies")

    def test_pages_of_a_hundred(self) -> None:
        third = self.find("site", page=3, names=250)

        self.assertEqual((third.total, third.pages, third.first, third.last), (250, 3, 201, 250))
        self.assertEqual(third.groups[0].hits[-1].title, "site249")

    def test_case_does_not_matter(self) -> None:
        self.assertEqual(self.find("SHOP").total, 1)


class TheAddressesFromTheHelper(unittest.TestCase):
    def test_names_labels_and_the_vips_own_source(self) -> None:
        found = addresses.from_entry(SHOP_ENTRY["vip"], SHOP_ENTRY["source"])

        if found is None:
            self.fail("the helper's fields make an address")
        self.assertEqual(
            (found.vip.label, found.vip.shown), ("VIP main (default)", "198.51.100.20")
        )
        self.assertEqual(found.source.label if found.source else None, "Source of VIP main")

    def test_a_vip_the_network_lacks_shows_its_name(self) -> None:
        found = addresses.from_entry({"name": "gone", "address": None, "default": False}, None)

        self.assertEqual(found.vip.shown if found else None, "VIP gone")

    def test_an_older_helper_says_nothing(self) -> None:
        self.assertIsNone(addresses.from_entry(None, None))

    def test_addresses_order_by_number_not_by_text(self) -> None:
        listed = ["192.0.2.10", "name.example", "192.0.2.9", "2001:db8::1"]

        self.assertEqual(
            sorted(listed, key=addresses.order_key),
            ["192.0.2.9", "192.0.2.10", "2001:db8::1", "name.example"],
        )


class ThePages(LoginTestCase):
    def get(self, path: str, *, role: str = "admin", demo_fixture: bool = False) -> Any:
        self.account = replace(self.account, role=role)
        client = self.client(
            replace(configuration(), clusters=("alpha",), demo_fixture=demo_fixture)
        )
        self.sign_in(client)
        self.searched: list[dict[str, Any]] = []

        def search(_connection: Any, query: str, **kwargs: Any) -> search_index.Results:
            self.searched.append({"query": query, **kwargs})
            return search_index.Results(query, (), 0, kwargs.get("page", 1))

        with (
            mock.patch(
                "haprion_ui.db.cluster_objects",
                return_value=[objects_reading(SHOP_ENTRY, API_ENTRY)],
            ),
            mock.patch("haprion_ui.db.cluster_statuses", return_value=[]),
            mock.patch("haprion_ui.db.search", side_effect=search),
            mock.patch("haprion_ui.db.read_draft", return_value=None),
            mock.patch("haprion_ui.db.recent_jobs", return_value=[]),
            mock.patch("haprion_ui.db.read_backend_series", return_value=[]),
            mock.patch("haprion_ui.db.read_backend_aliases", return_value={}),
            mock.patch(
                "haprion_ui.db.read_backend_totals", side_effect=lambda *_a, **_k: measurement()
            ),
        ):
            return client.get(path)

    def test_every_page_carries_the_search_field(self) -> None:
        page = self.get("/proxies")

        self.assertIn('<form class="header-search" method="get" action="/search"', page.text)

    def test_the_search_asks_the_database_with_the_role_and_the_page(self) -> None:
        page = self.get("/search?q=192.0.2.10&page=2", role="reader")

        self.assertEqual(page.status_code, 200)
        self.assertEqual(self.searched[0]["query"], "192.0.2.10")
        self.assertEqual((self.searched[0]["role"], self.searched[0]["page"]), ("reader", 2))
        self.assertIn('name="q" value="192.0.2.10"', page.text)

    def test_a_page_that_is_not_a_number_is_the_first(self) -> None:
        self.get("/search?q=x&page=-3")

        self.assertEqual(self.searched[0]["page"], 1)

    def test_the_demo_fixture_is_searched_in_memory(self) -> None:
        page = self.get("/search?q=192.0.2.10", demo_fixture=True)

        self.assertEqual(self.searched, [])
        self.assertIn("Backend 192.0.2.10:8080", page.text)

    def test_a_query_with_markup_is_shown_as_text(self) -> None:
        page = self.get("/search?q=%3Cscript%3E")

        self.assertNotIn("<script>", page.text.split("</header>", 1)[1].split("<script defer")[0])
        self.assertIn("&lt;script&gt;", page.text)

    def test_the_listing_shows_each_objects_vip_and_source(self) -> None:
        page = self.get("/proxies")

        self.assertIn(">VIP / source</a></th>", page.text)
        self.assertIn(
            'title="VIP main (default) 198.51.100.20 · Source of VIP main 198.51.100.25"', page.text
        )
        self.assertIn(">198.51.100.30 · 203.0.113.5</span>", page.text)

    def test_the_listing_sorts_on_the_address_by_number(self) -> None:
        page = self.get("/proxies?sort=-address")

        self.assertLess(page.text.index(">api<"), page.text.index(">shop<"))

    def test_the_object_page_names_the_vip_the_object_is_on(self) -> None:
        page = self.get("/proxies/alpha/api")

        self.assertIn("Served on the VIP <code>partner</code> · 198.51.100.30", page.text)


class TheLampUsesTheHelpersAnswer(LoginTestCase):
    """Whether an object is checked comes from the helper, not from reading the document."""

    def test_an_object_the_helper_says_is_unchecked_is_grey(self) -> None:
        client = self.client(replace(configuration(), clusters=("alpha",)))
        self.sign_in(client)
        server = {"backend": "mgd-shop-web", "server": "s1", "status": "UP"}
        status = ClusterStatus(
            cluster="alpha",
            observed_at=OBSERVED,
            outcome="done",
            result={"nodes": [{"node": "n1", "status": {"servers": [server]}}]},
            warnings=[],
            error=None,
            poll_error=None,
        )
        unchecked = {**SHOP_ENTRY, "health_checked": False}
        with (
            mock.patch("haprion_ui.db.cluster_objects", return_value=[objects_reading(unchecked)]),
            mock.patch("haprion_ui.db.cluster_statuses", return_value=[status]),
        ):
            page = client.get("/proxies")

        self.assertIn("This object defines no health check", page.text)


if __name__ == "__main__":
    unittest.main()
