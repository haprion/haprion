"""Protection review: which states count, and how an acceptance holds them (B517, 12; B521)."""

from __future__ import annotations

import unittest
from datetime import UTC, datetime

from haprion.proxy_model import load_proxy

from haprion_ui.db import ReviewAck, ReviewView
from haprion_ui.objects import ObjectView
from haprion_ui.protection_review import gone, review, row_keys, weaknesses
from haprion_ui.proxies import ProxyView

SITE = """schema: 1
name: shop
hostnames: [shop.example.com]
listen:
  protocol: https
  certificate: shop.pem
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

GUARDED = """schema: 1
name: shop
hostnames: [shop.example.com]
listen:
  protocol: https
  certificate: shop.pem
  hsts: {max_age: 31536000}
allow_from: [office]
rate_limit:
  window: 10s
  max_requests: 100
waf:
  mode: block
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

TCP = """schema: 1
name: db
listen:
  protocol: tcp
  port: 5432
backend: pool
backends:
  pool:
    balance: roundrobin
    health:
      type: disabled
    servers:
      - host: 192.0.2.20
        port: 5432
"""

AT = datetime(2026, 11, 20, 9, 0, tzinfo=UTC)


def view(name: str, document: str) -> ObjectView:
    return ObjectView(
        name=name,
        document=document.replace("name: shop", f"name: {name}", 1),
        readable=True,
        problem=None,
        protocol=None,
        hostnames=(),
        line_count=0,
        ports=(),
    )


def manual(name: str) -> ProxyView:
    return ProxyView(
        name=name,
        protocol="http",
        managed=False,
        enabled=True,
        hostnames=(),
        ports=(80,),
        backend_count=1,
    )


class WhatCountsAsWeaker(unittest.TestCase):
    def test_a_bare_site_has_every_mark_its_kind_has(self) -> None:
        proxy = load_proxy("shop", SITE.encode())

        self.assertEqual(
            weaknesses(proxy, waf_offered=True), ("waf-off", "no-rate-limit", "no-hsts")
        )

    def test_waf_off_counts_only_where_the_engine_is_offered(self) -> None:
        """B521."""

        proxy = load_proxy("shop", SITE.encode())

        self.assertEqual(weaknesses(proxy, waf_offered=False), ("no-rate-limit", "no-hsts"))
        logging = load_proxy("shop", SITE.replace("routes:", "waf:\n  mode: log\nroutes:").encode())
        self.assertIn("waf-log", weaknesses(logging, waf_offered=False))

    def test_a_guarded_site_has_none_and_everywhere_is_not_one(self) -> None:
        """B521: where an object is reachable from is shown, not counted."""

        self.assertEqual(weaknesses(load_proxy("shop", GUARDED.encode()), waf_offered=True), ())

    def test_path_limits_leave_no_rate_limit_said(self) -> None:
        """B521: they protect their paths only."""

        limited = SITE.replace(
            "routes:",
            "path_limits:\n  - path: /login\n    max_requests: 5\n    window: 10s\nroutes:",
        )

        self.assertIn(
            "no-rate-limit", weaknesses(load_proxy("shop", limited.encode()), waf_offered=True)
        )

    def test_an_unverified_pool_and_advanced_config_are_marks(self) -> None:
        document = SITE.replace(
            "    servers:\n      - host: 192.0.2.10",
            "    tls:\n      verify: none\n    servers:\n      - host: 192.0.2.10",
        ).replace("routes:", "advanced: |\n  http-request set-header X-A b\nroutes:")

        found = weaknesses(load_proxy("shop", document.encode()), waf_offered=True)

        self.assertIn("backend-tls-unverified", found)
        self.assertEqual(found[-1], "advanced")

    def test_a_raw_port_has_only_what_a_raw_port_has(self) -> None:
        self.assertEqual(
            weaknesses(load_proxy("db", TCP.encode()), waf_offered=True), ("no-rate-limit",)
        )


class AnAcceptanceHoldsTheMarksItSaw(unittest.TestCase):
    def built(self, acks: dict[tuple[str, str], ReviewAck], *, editable: bool = True) -> object:
        return review(
            [("alpha", 0, "healthy")],
            {"alpha": (view("shop", SITE), view("guarded", GUARDED), view("db", TCP))},
            {"alpha": (manual("legacy"),)},
            acks,
            ReviewView(),
            waf_offered=True,
            editable=editable,
        )

    def rows(self, acks: dict[tuple[str, str], ReviewAck]) -> dict[str, object]:
        built = self.built(acks)
        return {row.name: row for row in built.clusters[0].rows}  # type: ignore[attr-defined]

    def test_rows_are_alphabetical_and_counted(self) -> None:
        built = self.built({})
        cluster = built.clusters[0]  # type: ignore[attr-defined]

        self.assertEqual([row.name for row in cluster.rows], ["db", "guarded", "legacy", "shop"])
        self.assertEqual([row.state for row in cluster.rows], ["open", "clean", "open", "open"])
        self.assertEqual(built.count, 3)  # type: ignore[attr-defined]
        self.assertEqual(cluster.detail, "3 to review · 1 with nothing to review")
        self.assertEqual(cluster.rows[2].marks[0].label, "Not assessed · written by hand")
        self.assertEqual(cluster.rows[1].reach, "office")
        self.assertEqual(cluster.rows[3].reach, "Everywhere")

    def test_an_accepted_row_is_accepted_while_it_has_nothing_new(self) -> None:
        ack = ReviewAck(frozenset({"waf-off", "no-rate-limit", "no-hsts"}), "admin", AT)
        shop = self.rows({("alpha", "shop"): ack})["shop"]

        self.assertEqual(shop.state, "accepted")  # type: ignore[attr-defined]
        self.assertEqual(shop.accepted_by, "admin")  # type: ignore[attr-defined]
        self.assertEqual({mark.state for mark in shop.marks}, {""})  # type: ignore[attr-defined]

    def test_a_new_mark_opens_the_row_again_and_is_said(self) -> None:
        ack = ReviewAck(frozenset({"waf-off", "no-rate-limit"}), "admin", AT)
        shop = self.rows({("alpha", "shop"): ack})["shop"]

        self.assertEqual(shop.state, "open")  # type: ignore[attr-defined]
        self.assertEqual(
            [(mark.label, mark.state) for mark in shop.marks],  # type: ignore[attr-defined]
            [("WAF off", "accepted"), ("No rate limit", "accepted"), ("No HSTS", "new")],
        )

    def test_a_mark_links_to_its_field_and_a_reader_to_the_page(self) -> None:
        shop = self.rows({})["shop"]
        reader = {
            row.name: row
            for row in self.built({}, editable=False).clusters[0].rows  # type: ignore[attr-defined]
        }["shop"]

        self.assertEqual(
            shop.marks[1].href,  # type: ignore[attr-defined]
            "/proxies/alpha/shop/edit?open=access&focus=rate_limit",
        )
        self.assertEqual(reader.marks[1].href, "/proxies/alpha/shop")

    def test_the_keys_accepted_are_the_row_s_now(self) -> None:
        built = self.built({})

        self.assertEqual(row_keys(built, "alpha", "db"), ("no-rate-limit",))  # type: ignore[arg-type]
        self.assertIsNone(row_keys(built, "alpha", "nobody"))  # type: ignore[arg-type]
        self.assertEqual(row_keys(built, "alpha", "guarded"), ())  # type: ignore[arg-type]

    def test_a_hidden_cluster_is_not_counted(self) -> None:
        built = review(
            [("alpha", 0, "healthy")],
            {"alpha": (view("shop", SITE),)},
            {},
            {},
            ReviewView(hidden_clusters=frozenset({"alpha"})),
            waf_offered=True,
            editable=True,
        )

        self.assertEqual(built.count, 0)

    def test_an_acceptance_is_forgotten_only_where_the_cluster_was_read(self) -> None:
        acks = {("alpha", "shop"), ("alpha", "removed"), ("beta", "unread")}

        self.assertEqual(gone(acks, {"alpha": {"shop"}}), {("alpha", "removed")})


if __name__ == "__main__":
    unittest.main()
