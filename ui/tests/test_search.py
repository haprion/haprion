"""The header's search and the listing's VIP / source column (B221)."""

from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any
from unittest import mock

from haproxy_mgmt.config import Vip
from haproxy_mgmt.generate import _source_of
from haproxy_mgmt.proxy_model import load_proxy

from haproxy_ui import addresses, search
from haproxy_ui.db import ClusterNetwork, ClusterObjects, ClusterStatus
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
    - host: 192.0.2.11
      port: 8080
"""

#
# Every combination the rule has: the default VIP or a named one, and no source,
# the VIP's own or a named one.
#
LISTENS = {
    "default": "  protocol: http\n",
    "named-vip": "  protocol: http\n  vip: partner\n",
    "named-source": "  protocol: http\n  source: outbound\n",
    "both": "  protocol: http\n  vip: partner\n  source: outbound\n",
    "bare-vip": "  protocol: http\n  vip: bare\n",
}

NETWORK = {
    "cluster": "alpha",
    "default_vip": "main",
    "vips": [
        {"name": "main", "address": "198.51.100.20", "source": "198.51.100.25"},
        {"name": "partner", "address": "198.51.100.30", "source": "198.51.100.35"},
        {"name": "bare", "address": "198.51.100.40", "source": None},
    ],
    "sources": [{"name": "outbound", "address": "203.0.113.5"}],
    "groups": [],
}


def document(listen: str, name: str = "shop") -> str:
    return SHOP.replace("name: shop", f"name: {name}").replace("  protocol: http\n", listen)


def objects_reading(*documents: tuple[str, str]) -> ClusterObjects:
    return ClusterObjects(
        cluster="alpha",
        observed_at=OBSERVED,
        outcome="done",
        result={
            "commit": "a" * 40,
            "objects": [
                {
                    "name": name,
                    "document": text,
                    "readable": True,
                    "problem": None,
                    "protocol": "http",
                    "hostnames": [f"{name}.example.com"],
                }
                for name, text in documents
            ],
        },
        warnings=[],
        error=None,
        poll_error=None,
    )


def network_reading() -> ClusterNetwork:
    return ClusterNetwork(
        cluster="alpha",
        observed_at=OBSERVED,
        outcome="done",
        result=NETWORK,
        warnings=[],
        error=None,
        poll_error=None,
    )


def status_reading() -> ClusterStatus:
    return ClusterStatus(
        cluster="alpha",
        observed_at=OBSERVED,
        outcome="done",
        result={"nodes": [{"name": "lb-01", "mgmt_host": "lb-01.example.net"}]},
        warnings=[],
        error=None,
        poll_error=None,
    )


class TheAddressRuleIsTheGenerators(unittest.TestCase):
    """The column and the search restate `generate._source_of`; hold them to it."""

    def test_every_combination_gives_the_generators_source(self) -> None:
        sources = {entry["name"]: entry["address"] for entry in NETWORK["sources"]}
        for case, listen in LISTENS.items():
            with self.subTest(case):
                text = document(listen)
                proxy = load_proxy("shop", text.encode())
                name = proxy.listen.vip or "main"
                entry = next(vip for vip in NETWORK["vips"] if vip["name"] == name)
                vip = Vip(name=name, address=entry["address"], source=entry["source"])
                expected = _source_of(proxy, vip, sources)

                found = addresses.resolve("shop", text, NETWORK)

                if found is None:
                    self.fail("a readable object on a known network resolves")
                self.assertEqual(found.vip.address, entry["address"])
                self.assertEqual(found.source.address if found.source else None, expected)
                self.assertEqual(found.vip_is_default, name == "main")

    def test_an_unreadable_document_or_no_network_answers_nothing(self) -> None:
        self.assertIsNone(addresses.resolve("shop", "schema: [", NETWORK))
        self.assertIsNone(addresses.resolve("shop", document(LISTENS["default"]), {}))

    def test_a_vip_the_network_no_longer_has_shows_its_name(self) -> None:
        found = addresses.resolve("shop", document("  protocol: http\n  vip: gone\n"), NETWORK)

        if found is None:
            self.fail("a readable object on a known network resolves")
        self.assertEqual(found.vip.address, "")
        self.assertEqual(found.vip.shown, "VIP gone")

    def test_addresses_order_by_number_not_by_text(self) -> None:
        listed = ["192.0.2.10", "name.example", "192.0.2.9", "2001:db8::1"]

        self.assertEqual(
            sorted(listed, key=addresses.order_key),
            ["192.0.2.9", "192.0.2.10", "2001:db8::1", "name.example"],
        )


class TheSearch(unittest.TestCase):
    def find(self, query: str, role: str = "admin") -> search.Results:
        return search.search(
            query,
            role=role,
            clusters=("alpha",),
            object_rows=[
                objects_reading(
                    ("shop", document(LISTENS["default"])),
                    ("api", document(LISTENS["both"], "api").replace("192.0.2.", "203.0.113.")),
                )
            ],
            network_rows=[network_reading()],
            status_rows=[status_reading()],
            certificates=None,
        )

    def hits(self, results: search.Results, label: str) -> list[search.Hit]:
        return next((list(group.hits) for group in results.groups if group.label == label), [])

    def test_an_empty_query_searches_nothing(self) -> None:
        self.assertEqual(self.find("   ").groups, ())

    def test_a_backend_address_finds_its_object_and_says_what_matched(self) -> None:
        found = self.hits(self.find("192.0.2.11"), "Proxies")

        self.assertEqual([hit.title for hit in found], ["shop"])
        self.assertEqual(found[0].matched, "Backend 192.0.2.11:8080")
        self.assertEqual(found[0].href, "/proxies/alpha/shop")

    def test_a_vip_address_finds_the_objects_on_it_and_the_vip_itself(self) -> None:
        results = self.find("198.51.100.30")

        self.assertEqual([hit.title for hit in self.hits(results, "Proxies")], ["api"])
        self.assertEqual([hit.title for hit in self.hits(results, "Addresses")], ["VIP partner"])

    def test_a_named_source_is_found_by_name_and_by_address(self) -> None:
        for query in ("outbound", "203.0.113.5"):
            with self.subTest(query):
                titles = [hit.title for hit in self.hits(self.find(query), "Addresses")]
                self.assertEqual(titles, ["Source outbound"])

    def test_case_does_not_matter(self) -> None:
        self.assertEqual([hit.title for hit in self.hits(self.find("SHOP"), "Proxies")], ["shop"])

    def test_nodes_are_found_by_name_and_host(self) -> None:
        for query in ("lb-01", "example.net"):
            with self.subTest(query):
                titles = [hit.title for hit in self.hits(self.find(query), "Clusters and nodes")]
                self.assertEqual(titles, ["lb-01"])

    def test_a_reader_cannot_find_a_backend_address(self) -> None:
        """B68: the backend addresses are what keeps the object page admin-only."""

        self.assertEqual(self.hits(self.find("192.0.2.11", role="reader"), "Proxies"), [])

    def test_a_reader_finds_objects_otherwise_and_is_taken_to_the_listing(self) -> None:
        found = self.hits(self.find("shop", role="reader"), "Proxies")

        self.assertEqual([hit.href for hit in found], ["/proxies"])

    def test_a_long_query_is_cut_rather_than_matched_whole(self) -> None:
        self.assertEqual(len(self.find("x" * 500).query), search.MAX_QUERY)


class ThePages(LoginTestCase):
    def get(self, path: str, *, role: str = "admin") -> Any:
        self.account = replace(self.account, role=role)
        client = self.client(replace(configuration(), clusters=("alpha",)))
        self.sign_in(client)
        with (
            mock.patch(
                "haproxy_ui.db.cluster_objects",
                return_value=[
                    objects_reading(
                        ("shop", document(LISTENS["default"])),
                        ("api", document(LISTENS["both"], "api").replace("192.0.2.", "203.0.113.")),
                    )
                ],
            ),
            mock.patch("haproxy_ui.db.cluster_networks", return_value=[network_reading()]),
            mock.patch("haproxy_ui.db.cluster_statuses", return_value=[status_reading()]),
            mock.patch("haproxy_ui.db.read_draft", return_value=None),
            mock.patch("haproxy_ui.db.recent_jobs", return_value=[]),
            mock.patch("haproxy_ui.db.read_backend_samples", return_value=[]),
            mock.patch(
                "haproxy_ui.db.read_backend_totals", side_effect=lambda *_a, **_k: measurement()
            ),
        ):
            return client.get(path)

    def test_every_page_carries_the_search_field(self) -> None:
        page = self.get("/proxies")

        self.assertIn('<form class="header-search" method="get" action="/search"', page.text)

    def test_the_search_page_lists_what_matched(self) -> None:
        page = self.get("/search?q=192.0.2.10")

        self.assertEqual(page.status_code, 200)
        self.assertIn('data-href="/proxies/alpha/shop"', page.text)
        self.assertIn("Backend 192.0.2.10:8080", page.text)
        self.assertIn('name="q" value="192.0.2.10"', page.text)

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
        self.assertIn(">198.51.100.20 · 198.51.100.25</span>", page.text)
        self.assertIn('title="VIP partner 198.51.100.30 · Source outbound 203.0.113.5"', page.text)
        self.assertIn(">198.51.100.30 · 203.0.113.5</span>", page.text)

    def test_the_listing_sorts_on_the_address_by_number(self) -> None:
        page = self.get("/proxies?sort=-address")

        self.assertLess(page.text.index(">api<"), page.text.index(">shop<"))

    def test_the_object_page_names_the_vip_the_object_is_on(self) -> None:
        page = self.get("/proxies/alpha/api")

        self.assertIn("Served on the VIP <code>partner</code> · 198.51.100.30", page.text)


if __name__ == "__main__":
    unittest.main()
