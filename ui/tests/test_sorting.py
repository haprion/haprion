"""Sortable tables: one mechanism for every table a reader sorts (THEME.md)."""

from __future__ import annotations

import unittest
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

from haprion_ui import certificates, proxies, sorting, traffic_log_table

TABLE = sorting.Table(
    columns=(
        sorting.Column("name", lambda row, _: sorting.text(row["name"])),
        sorting.Column("count", lambda row, _: row["count"], descending_first=True),
        sorting.Column("when", lambda row, _: row["when"]),
    ),
    cookie="haprion_ui_test_sort",
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
        from haprion_ui import users
        from haprion_ui.db import AccountRow

        moment = datetime(2026, 9, 27, tzinfo=UTC)
        rows = [
            AccountRow(1, "alice", "admin", False, 0, moment, False),
            AccountRow(2, "bob", "reader", False, 0, None, True),
            AccountRow(3, "carol", "reader", True, 0, None, False),
        ]

        order = [row.username for row in users.TABLE.ordered(rows, "state")]
        self.assertEqual(order, ["carol", "bob", "alice"])


def entry(at: int, **fields: Any) -> SimpleNamespace:
    values: dict[str, Any] = {
        "at": datetime(2026, 9, 28, 12, 0, at, tzinfo=UTC),
        "cluster": "alpha",
        "node": "node-a",
        "client": "192.0.2.5",
        "method": "GET",
        "host": "app.example.com",
        "path": f"/{at}",
        "server": "198.51.100.10:8080",
        "status": 200,
        "bytes": 100,
    }
    values.update(fields)
    return SimpleNamespace(**values)


class TheTrafficLogTable(unittest.TestCase):
    """The traffic log's default runs the other way: newest first."""

    def order(self, rows: list[Any], sort: str) -> list[str]:
        return [row.path for row in traffic_log_table.TABLE.ordered(rows, sort)]

    def test_newest_first_by_default_and_oldest_first_turned(self) -> None:
        rows = [entry(1), entry(3), entry(2)]
        self.assertEqual(self.order(rows, traffic_log_table.TABLE.default), ["/3", "/2", "/1"])
        self.assertEqual(self.order(rows, "-time"), ["/1", "/2", "/3"])
        self.assertEqual(traffic_log_table.TABLE.links("time")["time"].arrow, "▼")

    def test_ties_keep_newest_first_in_both_directions(self) -> None:
        rows = [entry(1, bytes=5), entry(2, bytes=9), entry(3, bytes=5), entry(4, bytes=9)]
        self.assertEqual(self.order(rows, "bytes"), ["/4", "/2", "/3", "/1"])
        self.assertEqual(self.order(rows, "-bytes"), ["/3", "/1", "/4", "/2"])

    def test_errors_first_and_the_largest_first(self) -> None:
        rows = [entry(1, status=200), entry(2, status=503), entry(3, status=404)]
        self.assertEqual(self.order(rows, "status"), ["/2", "/3", "/1"])

    def test_addresses_by_number_and_a_missing_destination_last(self) -> None:
        rows = [
            entry(1, client="192.0.2.10", server=""),
            entry(2, client="192.0.2.9", server="198.51.100.10:8080"),
            entry(3, client="2001:db8::1", server="198.51.100.9:443"),
            entry(4, client="192.0.2.100", server="backend.example.net:80"),
        ]
        self.assertEqual(self.order(rows, "client"), ["/2", "/1", "/4", "/3"])
        self.assertEqual(self.order(rows, "destination"), ["/3", "/2", "/4", "/1"])
        self.assertEqual(self.order(rows, "-destination"), ["/4", "/2", "/3", "/1"])


if __name__ == "__main__":
    unittest.main()
