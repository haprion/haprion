"""`GET /clusters/{cluster}/traffic`: the traffic log's rows, as the page reads them (B416)."""

from __future__ import annotations

import tempfile
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest import mock

import psycopg

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
