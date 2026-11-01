"""`GET /clusters/{cluster}/traffic`: the traffic log's rows, as the page reads them (B416)."""

from __future__ import annotations

import base64
import tempfile
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest import mock

import psycopg

from haprion_ui import traffic_logs
from haprion_ui.api.traffic import moment
from haprion_ui.config import TrafficLogs
from haprion_ui.traffic_logs import Entry, Freshness, Reading
from tests.test_api import ApiTestCase
from tests.test_editor_page import OBJECTS
from tests.test_login import configuration

SEEN = datetime(2026, 10, 31, 11, 59, 30, tzinfo=UTC)


def entry(**changes: Any) -> Entry:
    values: dict[str, Any] = {
        "cluster": "alpha",
        "node": "node-a",
        "at": SEEN,
        "request": 7,
        "client": "192.0.2.5",
        "method": "GET",
        "host": "shop.example.com",
        "path": "/search?q=1",
        "frontend": "https",
        "backend": "shop-web",
        "server": "192.0.2.10:8080",
        "status": 200,
        "request_time": 1,
        "queue_time": 0,
        "connect_time": 2,
        "response_time": 30,
        "total_time": 33,
        "bytes": 512,
    }
    values.update(changes)
    values.setdefault("event", bytes([values["request"] % 256]) * 32)
    return Entry(**values)


NODE = Freshness("alpha", "node-a", SEEN, SEEN, "ok", current_complete=True)
EXPECTED_ROW = {
    "time": "2026-10-31T11:59:30+00:00",
    "node": "node-a",
    "request_number": 7,
    "client": "192.0.2.5",
    "method": "GET",
    "host": "shop.example.com",
    "path": "/search?q=1",
    "frontend": "https",
    "backend": "shop-web",
    "server": "192.0.2.10:8080",
    "status": 200,
    "request_time": 1,
    "queue_time": 0,
    "connect_time": 2,
    "response_time": 30,
    "total_time": 33,
    "bytes": 512,
    "rule": "",
    "rule_name": "",
    "rule_action": "",
    "termination": "",
    "ended": "",
}


REAL_READ = traffic_logs.read_database


class TheTrafficRoute(ApiTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.read = mock.Mock(return_value=Reading((entry(),), (NODE,), 0, False))
        for patch in (
            mock.patch("haprion_ui.db.cluster_objects", side_effect=lambda _c, **_kw: [OBJECTS]),
            mock.patch("haprion_ui.traffic_logs.read_database", self.read),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def get(self, query: str = "", cluster: str = "alpha", **token: Any) -> Any:
        config = replace(
            configuration(),
            clusters=("alpha", "beta"),
            traffic_logs=TrafficLogs(
                enabled=True, directory=Path(self.directory.name), max_lines=500
            ),
        )
        secret = self.issue(**token)
        return self.client(config).get(
            f"/api/v1/clusters/{cluster}/traffic{query}",
            headers={"Authorization": f"Bearer {secret}"},
        )

    def test_the_rows_in_the_envelope(self) -> None:
        response = self.get()
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual((body["operation"], body["cluster"]), ("traffic_list", "alpha"))
        asked_from, asked_to = body["result"]["from"], body["result"]["to"]
        self.assertEqual(
            body["result"],
            {
                "enabled": True,
                "from": asked_from,
                "to": asked_to,
                "requests": [EXPECTED_ROW],
                "truncated": False,
                "next": None,
                "limit": 100,
                "nodes": [
                    {
                        "node": "node-a",
                        "last_attempt": "2026-10-31T11:59:30+00:00",
                        "last_success": "2026-10-31T11:59:30+00:00",
                        "outcome": "ok",
                        "catching_up": False,
                    }
                ],
            },
        )
        asked = self.read.call_args
        self.assertEqual(asked.args[1], Path(self.directory.name))
        self.assertEqual(
            {name: asked.kwargs[name] for name in ("limit", "cluster", "status", "substring")},
            {"limit": 101, "cluster": "alpha", "status": "", "substring": ""},
        )
        self.assertIsNone(asked.kwargs["owned"])

    def test_a_rule_and_how_the_session_ended_are_said_in_words(self) -> None:
        self.read.return_value = Reading(
            (entry(rule="admin-post:deny", termination="SH", status=403),), (), 0, False
        )
        [row] = self.get().json()["result"]["requests"]
        self.assertEqual(
            (row["rule"], row["rule_name"], row["rule_action"]),
            ("admin-post:deny", "admin-post", "denied"),
        )
        self.assertEqual(
            (row["termination"], row["ended"]),
            ("SH", "The server ended it while waiting for the server's headers"),
        )
        self.read.return_value = Reading((entry(rule="scanner:log"),), (), 0, False)
        [row] = self.get().json()["result"]["requests"]
        self.assertEqual((row["rule_name"], row["rule_action"]), ("scanner", "logged"))

    def test_a_dynamic_block_names_its_reason_after_the_prefix(self) -> None:
        # B424: new rows carry `dynamic-block/<reason>`, old ones `dynamic-block`.
        self.read.return_value = Reading(
            (entry(rule="dynamic-block/errors:deny"), entry(rule="dynamic-block:deny")),
            (),
            0,
            False,
        )
        rows = self.get().json()["result"]["requests"]
        self.assertEqual(
            [(row["rule_name"], row["rule_action"]) for row in rows],
            [("dynamic-block/errors", "denied"), ("dynamic-block", "denied")],
        )

    def test_the_filters_are_the_pages(self) -> None:
        self.get(
            "?status=5xx&q=api%20AND%20shop&from=2026-10-31T10:00:00Z&to=2026-10-31T11:00:00Z"
            "&waf=hits&object=shop"
        )
        asked = self.read.call_args.kwargs
        self.assertEqual(
            (asked["status"], asked["substring"], asked["waf"]),
            ("5xx", "api AND shop", "hits"),
        )
        self.assertEqual(asked["from_at"], datetime(2026, 10, 31, 10, tzinfo=UTC))
        self.assertEqual(asked["to_at"], datetime(2026, 10, 31, 11, tzinfo=UTC))
        # The object's own backends and hostnames, and the address behind `s1`.
        self.assertEqual(asked["owned"], ((), ("shop.example.com",)))
        self.assertEqual(asked["server_addresses"], {("alpha", "web", "s1"): "192.0.2.10:8080"})

    def test_q_is_given_the_destinations_it_may_search(self) -> None:
        # The route shows each row's destination, so `q` may find it, as the page's does.

        self.get("?q=192.0.2.10")
        asked = self.read.call_args.kwargs
        parameters: list[Any] = []
        statement = traffic_logs._search_sql(
            traffic_logs._Parser(traffic_logs._tokens(asked["substring"])).parse(),
            parameters,
            asked["server_addresses"],
        ).as_string(None)
        self.assertIn("= any(%s::text[])", statement)
        self.assertIn("traffic_log_client_inet(client) = any(%s::inet[])", statement)
        self.assertEqual(parameters[-1], ["alpha web s1"])

    def test_an_object_the_cluster_does_not_have_is_not_found(self) -> None:
        """A mistyped name must not read as "no requests", for ever, in a monitoring script."""

        response = self.get("?object=intranet")
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json()["error"]["code"], "not_found")
        self.read.assert_not_called()
        # The same answer as an object outside the token's scope.
        scoped = self.get("?object=intranet", objects=["shop"])
        self.assertEqual(scoped.json()["error"], response.json()["error"])

    def test_without_from_the_last_hour_is_read_and_the_window_is_said(self) -> None:
        before = datetime.now(UTC)
        result = self.get().json()["result"]
        asked = self.read.call_args.kwargs
        to_at = datetime.fromisoformat(result["to"])
        self.assertGreaterEqual(to_at, before)
        self.assertEqual(datetime.fromisoformat(result["from"]), to_at - timedelta(hours=1))
        self.assertEqual(asked["from_at"], datetime.fromisoformat(result["from"]))
        # The end is open in the query: a row newer than the answer is not cut off.
        self.assertIsNone(asked["to_at"])

    def test_a_window_the_caller_names_is_read_and_echoed_as_given(self) -> None:
        result = self.get("?from=2026-10-01T00:00:00Z&to=2026-10-31T00:00:00%2B02:00").json()[
            "result"
        ]
        self.assertEqual(
            (result["from"], result["to"]),
            ("2026-10-01T00:00:00+00:00", "2026-10-31T00:00:00+02:00"),
        )

    def test_a_missing_from_is_an_hour_before_the_to_given(self) -> None:
        result = self.get("?to=2026-10-31T10:00:00Z").json()["result"]
        self.assertEqual(result["from"], "2026-10-31T09:00:00+00:00")
        self.assertEqual(
            self.read.call_args.kwargs["from_at"], datetime(2026, 10, 31, 9, tzinfo=UTC)
        )

    def test_a_window_wider_than_the_retention_is_read_not_refused(self) -> None:
        self.assertEqual(self.get("?from=2020-01-01T00:00:00Z").status_code, 200)

    def test_a_query_the_database_cancelled_is_a_timeout_not_an_outage(self) -> None:
        self.read.side_effect = psycopg.errors.QueryCanceled("canceling statement")
        response = self.get("?status=5xx")
        self.assertEqual(response.status_code, 503)
        error = response.json()["error"]
        self.assertEqual(error["code"], "query_timeout")
        self.assertIn("narrow", error["message"])
        # Any other database failure keeps its own code.
        self.read.side_effect = psycopg.OperationalError("down")
        self.assertEqual(self.get().json()["error"]["code"], "database_unavailable")

    def test_a_time_is_written_with_its_offset(self) -> None:
        self.assertEqual(moment(datetime(2026, 10, 31, 12)), "2026-10-31T12:00:00+00:00")

    def test_a_time_without_an_offset_is_utc(self) -> None:
        self.get("?from=2026-10-31T10:00:00")
        self.assertEqual(
            self.read.call_args.kwargs["from_at"], datetime(2026, 10, 31, 10, tzinfo=UTC)
        )

    def test_a_result_longer_than_the_limit_is_cut_and_says_so(self) -> None:
        self.read.return_value = Reading(
            tuple(entry(request=number) for number in (3, 2, 1)), (), 0, False
        )
        result = self.get("?limit=2").json()["result"]
        self.assertEqual([row["request_number"] for row in result["requests"]], [3, 2])
        self.assertEqual((result["truncated"], result["limit"]), (True, 2))
        self.assertEqual(self.read.call_args.kwargs["limit"], 3)
        self.read.return_value = Reading(tuple(entry(request=n) for n in (2, 1)), (), 0, False)
        self.assertFalse(self.get("?limit=2").json()["result"]["truncated"])

    def test_an_empty_log_is_an_empty_list(self) -> None:
        self.read.return_value = Reading((), (), 0, False)
        result = self.get().json()["result"]
        self.assertEqual(
            (result["requests"], result["truncated"], result["nodes"]), ([], False, [])
        )

    def test_what_cannot_be_asked_is_a_400_in_the_envelope(self) -> None:
        for query in (
            "?limit=0",
            "?limit=1001",
            "?status=20",
            "?status=abc",
            "?waf=sometimes",
            "?object=Not%20A%20Name",
            "?from=yesterday",
            "?from=2026-10-31T11:00:00Z&to=2026-10-31T10:00:00Z",
            "?q=" + "a" * 201,
        ):
            with self.subTest(query=query):
                response = self.get(query)
                self.assertEqual(response.status_code, 400)
                self.assertEqual(response.json()["error"]["code"], "bad_input")

    def test_a_search_that_cannot_be_read_is_a_400_with_the_reason(self) -> None:
        self.read.return_value = Reading((), (), 0, False, "The search ends with an operator.")
        response = self.get("?q=api%20AND")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"]["message"], "The search ends with an operator.")

    def test_a_cluster_outside_the_token_is_not_found(self) -> None:
        cases: list[tuple[str, dict[str, Any]]] = [("alpha", {"clusters": ["beta"]}), ("gamma", {})]
        for cluster, token in cases:
            with self.subTest(cluster=cluster):
                response = self.get(cluster=cluster, **token)
                self.assertEqual(response.status_code, 404)
                self.assertEqual(response.json()["error"]["code"], "not_found")
        self.read.assert_not_called()

    def test_an_object_outside_a_block_token_is_not_found(self) -> None:
        response = self.get("?object=shop", level="block", objects=["intranet"])
        self.assertEqual(response.status_code, 403)
        response = self.get("?object=shop", objects=["intranet"])
        self.assertEqual(response.status_code, 404)

    def test_a_log_that_is_switched_off_is_said_and_not_read(self) -> None:
        secret = self.issue()
        client = self.client(replace(configuration(), clusters=("alpha", "beta")))
        response = client.get(
            "/api/v1/clusters/alpha/traffic", headers={"Authorization": f"Bearer {secret}"}
        )
        result = response.json()["result"]
        self.assertEqual((result["enabled"], result["requests"], result["nodes"]), (False, [], []))
        self.read.assert_not_called()

    def test_a_cut_list_gives_the_place_to_go_on_from(self) -> None:
        # Review 26-11-01, c-P3-8: three rows share one time, two are asked for.
        rows = tuple(entry(request=number) for number in (3, 2, 1))
        self.read.return_value = Reading(rows, (), 0, False)
        first = self.get("?limit=2").json()["result"]
        self.assertIsNotNone(first["next"])
        self.assertIsNone(self.read.call_args.kwargs["before"])
        self.read.return_value = Reading(rows[2:], (), 0, False)
        second = self.get("?limit=2&before=" + first["next"]).json()["result"]
        self.assertEqual([row["request_number"] for row in second["requests"]], [1])
        self.assertIsNone(second["next"])
        # The place is the last row listed, and the read starts after it.
        self.assertEqual(self.read.call_args.kwargs["before"], (SEEN, 2, "node-a", bytes([2]) * 32))

    def test_a_next_page_stays_in_the_window_the_first_was_cut_from(self) -> None:
        # Without `from` the window is an hour before now; an hour later the next page
        # must still start where the first did, or the oldest rows are dropped.
        rows = tuple(entry(request=number) for number in (3, 2, 1))
        self.read.return_value = Reading(rows, (), 0, False)
        first = self.get("?limit=2").json()["result"]
        first_from = datetime.fromisoformat(first["from"])
        later = datetime.now(UTC) + timedelta(hours=1)
        with mock.patch("haprion_ui.api.traffic._now", return_value=later):
            second = self.get("?limit=2&before=" + first["next"]).json()["result"]
        self.assertEqual(self.read.call_args.kwargs["from_at"], first_from)
        self.assertEqual(second["from"], first["from"])
        # A `from` the caller names still wins.
        self.get("?limit=2&from=2026-10-01T00:00:00Z&before=" + first["next"])
        self.assertEqual(self.read.call_args.kwargs["from_at"], datetime(2026, 10, 1, tzinfo=UTC))

    def test_a_nul_byte_or_a_place_outside_the_table_is_a_400_not_a_500(self) -> None:
        def cursor(text: str) -> str:
            return base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")

        start = "2026-10-31T11:00:00+00:00|2026-10-31T11:59:30+00:00"
        event = "ab" * 32
        for query in (
            "?before=" + cursor(f"{start}|7|node-a\x00|{event}"),
            "?before=" + cursor(f"{start}|7|no de|{event}"),
            # `$` in a regex also matches before a trailing newline (2042f126).
            "?before=" + cursor(f"{start}|7|node-a\n|{event}"),
            "?before=" + cursor(f"{start}|{2**63}|node-a|{event}"),
            "?before=" + cursor(f"{start}|-1|node-a|{event}"),
            "?before=" + cursor(f"{start}|7|node-a|{event[:-1]}"),
            "?before=" + cursor(f"{start}|7|node-a|{'AB' * 32}"),
            "?before=" + cursor(f"{start}|7|node-a"),
            "?before="
            + cursor(f"0001-01-01T00:00:00+00:00|2026-10-31T11:59:30+00:00|7|node-a|{event}"),
            "?q=a%00b",
            "?object=a%00",
            "?status=2%00x",
        ):
            with self.subTest(query=query):
                response = self.get(query)
                self.assertEqual(response.status_code, 400, response.text)
                self.assertEqual(response.json()["error"]["code"], "bad_input")

    def test_a_network_with_a_zone_is_a_400_not_a_500(self) -> None:
        # Review 26-11-01, P3-1: PostgreSQL cannot read it; the search says so before asking.
        self.read.side_effect = REAL_READ
        response = self.get("?q=fe80%3A%3A%25eth0%2F64")
        self.assertEqual(response.status_code, 400, response.text)
        self.assertEqual(response.json()["error"]["code"], "bad_input")

    def test_a_place_that_was_not_given_is_a_400(self) -> None:
        for before in ("x", "bm90LWEtcGxhY2U", "MjAyNi0xMC0zMXx4fG5vZGUtYQ"):
            with self.subTest(before=before):
                response = self.get("?before=" + before)
                self.assertEqual(response.status_code, 400)
                self.assertEqual(response.json()["error"]["code"], "bad_input")

    def test_a_time_the_log_cannot_hold_is_a_400_not_a_500(self) -> None:
        for query in (
            "?to=0001-01-01T00:00:00Z",
            "?from=0001-01-01T00:00:00Z",
            "?from=1969-12-31T23:59:59Z",
            "?to=9999-12-31T23:59:59Z",
            "?from=9999-12-31T23:59:59-01:00",
        ):
            with self.subTest(query=query):
                response = self.get(query)
                self.assertEqual(response.status_code, 400, response.text)
                self.assertEqual(response.json()["error"]["code"], "bad_input")

    def test_a_parameter_the_call_does_not_take_is_refused_by_name(self) -> None:
        response = self.get("?since=2026-10-01T00:00:00Z")
        self.assertEqual(response.status_code, 400)
        error = response.json()["error"]
        self.assertEqual(error["code"], "bad_input")
        self.assertIn("since", error["message"])
        self.read.assert_not_called()
