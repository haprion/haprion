"""Sortable tables: one mechanism for Users, Proxies and Certificates (THEME.md)."""

from __future__ import annotations

import unittest
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

from haproxy_ui import certificates, proxies, sorting

TABLE = sorting.Table(
    columns=(
        sorting.Column("name", lambda row, _: sorting.text(row["name"])),
        sorting.Column("count", lambda row, _: row["count"], descending_first=True),
        sorting.Column("when", lambda row, _: row["when"]),
    ),
    cookie="haproxy_ui_test_sort",
    path="/things",
)
ROWS = [
    {"name": "delta", "count": 1, "when": None},
    {"name": "Alpha", "count": 3, "when": "2026-09-02"},
    {"name": "charlie", "count": 1, "when": "2026-09-01"},
    {"name": "bravo", "count": 3, "when": None},
]


def names(rows: list[Any]) -> list[str]:
    return [row["name"] for row in rows]


class TheTable(unittest.TestCase):
    def test_the_default_is_the_first_column_a_to_z_without_case(self) -> None:
        self.assertEqual(TABLE.default, "name")
        self.assertEqual(names(TABLE.ordered(ROWS, "name")), ["Alpha", "bravo", "charlie", "delta"])
        self.assertEqual(
            names(TABLE.ordered(ROWS, "-name")), ["delta", "charlie", "bravo", "Alpha"]
        )

    def test_ties_keep_the_default_order_in_both_directions(self) -> None:
        self.assertEqual(
            names(TABLE.ordered(ROWS, "count")), ["Alpha", "bravo", "charlie", "delta"]
        )
        self.assertEqual(
            names(TABLE.ordered(ROWS, "-count")), ["charlie", "delta", "Alpha", "bravo"]
        )

    def test_a_missing_value_comes_last_in_both_directions(self) -> None:
        self.assertEqual(names(TABLE.ordered(ROWS, "when")), ["charlie", "Alpha", "bravo", "delta"])
        self.assertEqual(
            names(TABLE.ordered(ROWS, "-when")), ["Alpha", "charlie", "bravo", "delta"]
        )

    def test_a_link_turns_the_chosen_column_and_keeps_the_query(self) -> None:
        links = TABLE.links("count", {"view": "x"})

        self.assertEqual(links["count"].href, "/things?view=x&sort=-count")
        self.assertEqual((links["count"].arrow, links["count"].aria), ("▼", "descending"))
        self.assertEqual(links["name"].href, "/things?view=x&sort=name")
        self.assertEqual((links["name"].arrow, links["name"].aria), ("", ""))
        self.assertEqual(TABLE.links("-count")["count"].arrow, "▲")

    def test_the_request_then_the_cookie_then_the_default(self) -> None:
        def request(query: dict[str, str], cookies: dict[str, str]) -> Any:
            return SimpleNamespace(query_params=query, cookies=cookies)

        self.assertEqual(TABLE.chosen(request({"sort": "-when"}, {})), ("-when", True))
        self.assertEqual(
            TABLE.chosen(request({"sort": "drop"}, {TABLE.cookie: "count"})), ("count", False)
        )
        self.assertEqual(TABLE.chosen(request({}, {TABLE.cookie: "bogus"})), ("name", False))


class TheProxyTable(unittest.TestCase):
    def test_rows_without_a_protocol_or_health_come_last(self) -> None:
        served = SimpleNamespace(protocol="https", hostnames=("b.example.com",))
        plain = SimpleNamespace(protocol="http", hostnames=("a.example.com",))
        rows = [
            ("draft", "draft", SimpleNamespace()),
            ("shop", "written", served),
            ("old", "removed", "old"),
            ("web", "foreign", plain),
        ]
        lamps = {"shop": SimpleNamespace(tone="critical", label="0/2 up")}

        order = [row[0] for row in proxies.TABLE.ordered(rows, "protocol", lamps)]
        self.assertEqual(order, ["web", "shop", "draft", "old"])
        order = [row[0] for row in proxies.TABLE.ordered(rows, "health", lamps)]
        self.assertEqual(order, ["shop", "draft", "old", "web"])
        order = [row[0] for row in proxies.TABLE.ordered(rows, "ownership", lamps)]
        self.assertEqual(order, ["old", "shop", "web", "draft"])


class TheCertificateTable(unittest.TestCase):
    def certificate(self, identifier: str, **fields: Any) -> Any:
        values: dict[str, Any] = {
            "identifier": identifier,
            "sans": (f"{identifier}.example.com",),
            "lifecycle_label": "Imported",
            "targets": (),
            "valid_from": "2026-01-01",
            "expires": "2027-01-01",
            "state_tone": "healthy",
            "state_label": "Published",
        }
        values.update(fields)
        return SimpleNamespace(**values)

    def test_expiry_soonest_first_and_problems_first(self) -> None:
        rows = [
            self.certificate("a", expires="2028-01-01"),
            self.certificate("b", expires="—", state_tone="critical", state_label="Unreadable"),
            self.certificate("c", expires="2026-10-01", state_tone="warning"),
        ]

        order = [row.identifier for row in certificates.TABLE.ordered(rows, "expires")]
        self.assertEqual(order, ["c", "a", "b"])
        order = [row.identifier for row in certificates.TABLE.ordered(rows, "state")]
        self.assertEqual(order, ["b", "c", "a"])

    def test_a_certificate_used_by_nothing_comes_last(self) -> None:
        rows = [
            self.certificate("a"),
            self.certificate("b", targets=(SimpleNamespace(name="beta"),)),
            self.certificate("c", targets=(SimpleNamespace(name="alpha"),)),
        ]

        order = [row.identifier for row in certificates.TABLE.ordered(rows, "usedby")]
        self.assertEqual(order, ["c", "b", "a"])


class TheUserTable(unittest.TestCase):
    def test_the_state_column_puts_problems_first(self) -> None:
        from haproxy_ui import users
        from haproxy_ui.db import AccountRow

        moment = datetime(2026, 9, 27, tzinfo=UTC)
        rows = [
            AccountRow(1, "alice", "admin", False, 0, moment, False),
            AccountRow(2, "bob", "reader", False, 0, None, True),
            AccountRow(3, "carol", "reader", True, 0, None, False),
        ]

        order = [row.username for row in users.TABLE.ordered(rows, "state")]
        self.assertEqual(order, ["carol", "bob", "alice"])


if __name__ == "__main__":
    unittest.main()
