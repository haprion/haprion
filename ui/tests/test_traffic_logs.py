from __future__ import annotations

import json
import os
import tempfile
import time
import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import patch

from haprion.proxy_model import load_proxy

from haprion_ui import metrics, traffic_logs
from haprion_ui.config import TrafficLogs
from haprion_ui.db import ClusterObjects
from haprion_ui.traffic_logs import (
    MAX_RECORD_BYTES,
    Freshness,
    Reading,
    configured_server_addresses,
    parse,
    read,
    resolve_server_addresses,
)
from haprion_ui.views import ZONE_COOKIE
from tests.test_login import LoginTestCase, configuration

NOW = datetime(2026, 9, 8, 12, 0, 0, tzinfo=UTC)


class TrafficFreshnessTests(unittest.TestCase):
    def test_a_failure_in_the_same_pass_as_the_last_mirror_success_is_visible(self) -> None:
        freshness = Freshness("alpha", "node-a", NOW, NOW, "database")

        self.assertTrue(freshness.latest_attempt_failed())


PROXY = """schema: 1
name: sample-proxy
hostnames:
- service.example.com
listen:
  protocol: http
routes:
- path: /
  backend: primary-backend
backends:
  primary-backend:
    balance: roundrobin
    servers:
    - host: app-one.example.net
      port: 8080
    - host: app-two.example.net
      port: 8080
    - host: app-three.example.net
      port: 8080
"""


def object_reading() -> ClusterObjects:
    return ClusterObjects(
        cluster="alpha",
        observed_at=NOW,
        outcome="done",
        result={
            "commit": "a" * 40,
            "objects": [
                {
                    "name": "sample-proxy",
                    "document": PROXY,
                    "readable": True,
                    "protocol": "http",
                    "hostnames": ["service.example.com"],
                }
            ],
        },
        warnings=[],
        error=None,
        poll_error=None,
    )


def record(**overrides: object) -> bytes:
    value: dict[str, object] = {
        "schema": 1,
        "at": int(NOW.timestamp()),
        "request": 1,
        "client": "192.0.2.5",
        "method": "GET",
        "host": "app.example.com",
        "path": "/index.html",
        "frontend": "fe-https",
        "backend": "be-app",
        "server": "srv1",
        "status": 200,
        "request_time": 1,
        "queue_time": 0,
        "connect_time": 0,
        "response_time": 2,
        "total_time": 3,
        "bytes": 512,
    }
    value.update(overrides)
    return json.dumps(value).encode("utf-8") + b"\n"


class TrafficLogReadingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def mirror(self, cluster: str, node: str, *records: bytes) -> None:
        (self.root / f"{cluster}--{node}.jsonl").write_bytes(b"".join(records))

    def meta(self, cluster: str, node: str, **overrides: object) -> None:
        value: dict[str, object] = {
            "schema_version": 1,
            "cluster": cluster,
            "node": node,
            "last_attempt": NOW.isoformat(),
            "last_success": NOW.isoformat(),
            "outcome": "ok",
        }
        value.update(overrides)
        (self.root / f"{cluster}--{node}.meta.json").write_text(json.dumps(value))

    def test_records_are_read_and_newest_comes_first(self) -> None:
        self.mirror(
            "alpha",
            "node-a",
            record(at=int(NOW.timestamp()) - 5, path="/old"),
            record(path="/new"),
        )

        reading = read(self.root, ("alpha",))

        self.assertEqual([entry.path for entry in reading.entries], ["/new", "/old"])
        self.assertEqual(reading.malformed, 0)

    def test_generated_server_positions_resolve_to_configured_destinations(self) -> None:
        parsed = load_proxy("sample-proxy", PROXY.encode())
        addresses = configured_server_addresses("alpha", (parsed,))
        reading = Reading(
            entries=(
                parse(
                    record(backend="primary-backend", server="s3"),
                    "alpha",
                    "node-a",
                ),
            ),
            nodes=(),
            malformed=0,
            unavailable=False,
        )

        resolved = resolve_server_addresses(reading, addresses)

        self.assertEqual(resolved.entries[0].server, "app-three.example.net:8080")

    def test_an_unresolved_generated_alias_is_not_presented_as_a_destination(self) -> None:
        reading = Reading(
            entries=(parse(record(server="s2"), "alpha", "node-a"),),
            nodes=(),
            malformed=0,
            unavailable=False,
        )

        resolved = resolve_server_addresses(reading, {})

        self.assertEqual(resolved.entries[0].server, "")

    def test_one_busy_second_is_ordered_by_the_request_counter(self) -> None:
        """The accept time is whole seconds, so it cannot order a busy second."""

        self.mirror(
            "alpha",
            "node-a",
            record(request=7, path="/seventh"),
            record(request=9, path="/ninth"),
            record(request=8, path="/eighth"),
        )

        reading = read(self.root, ("alpha",))

        self.assertEqual(
            [entry.path for entry in reading.entries], ["/ninth", "/eighth", "/seventh"]
        )

    def test_a_node_that_has_never_answered_is_still_listed(self) -> None:
        """The whole point of the strip: silence must not look like calm.

        A node with metadata and no mirror produced no records. Listing only
        the mirrors would drop exactly the node an operator needs to see.
        """

        self.meta("alpha", "node-b", last_success=None, outcome="unreachable")

        reading = read(self.root, ("alpha",))

        self.assertEqual(reading.entries, ())
        self.assertEqual([node.node for node in reading.nodes], ["node-b"])
        self.assertIsNone(reading.nodes[0].last_success)
        self.assertEqual(reading.nodes[0].outcome, "unreachable")
        self.assertIsNone(reading.nodes[0].stale_seconds(now=NOW))

    def test_a_stale_mirror_reports_its_age_rather_than_looking_current(self) -> None:
        self.mirror("alpha", "node-a", record())
        self.meta("alpha", "node-a", last_success=(NOW - timedelta(minutes=42)).isoformat())

        reading = read(self.root, ("alpha",))
        self.assertEqual(reading.nodes[0].stale_seconds(now=NOW), 2520.0)

    def test_successful_contact_still_reports_backlog_and_invalid_counts_are_unknown(self) -> None:
        self.meta("alpha", "node-a", current_complete=False, remaining_bytes=1234, pending_days=2)
        node = read(self.root, ("alpha",)).nodes[0]
        self.assertTrue(node.catching_up())
        self.assertFalse(node.latest_attempt_failed())
        self.assertEqual((node.remaining_bytes, node.pending_days), (1234, 2))
        self.meta(
            "alpha", "node-a", current_complete="false", remaining_bytes=True, pending_days=-1
        )
        node = read(self.root, ("alpha",)).nodes[0]
        self.assertEqual(
            (node.current_complete, node.remaining_bytes, node.pending_days), (None,) * 3
        )

    def test_a_mirror_without_metadata_is_reported_as_unknown(self) -> None:
        self.mirror("alpha", "node-a", record())

        reading = read(self.root, ("alpha",))

        self.assertEqual(reading.nodes[0].outcome, "unknown")
        self.assertIsNone(reading.nodes[0].last_attempt)

    def test_unreadable_metadata_never_stops_the_page(self) -> None:
        self.mirror("alpha", "node-a", record())
        (self.root / "alpha--node-a.meta.json").write_bytes(b"{ not json")

        reading = read(self.root, ("alpha",))

        self.assertEqual(len(reading.entries), 1)
        self.assertEqual(reading.nodes[0].outcome, "unknown")

    def test_a_malformed_record_is_counted_and_the_rest_still_render(self) -> None:
        self.mirror("alpha", "node-a", b"not json at all\n", record(), b'{"schema":2}\n')

        reading = read(self.root, ("alpha",))

        self.assertEqual(len(reading.entries), 1)
        self.assertEqual(reading.malformed, 2)

    def test_an_oversized_record_is_refused_rather_than_rendered(self) -> None:
        with self.assertRaises(ValueError):
            parse(record(path="/" + "a" * MAX_RECORD_BYTES), "alpha", "node-a")

    def test_fields_that_are_not_what_they_claim_are_refused(self) -> None:
        for overrides in (
            {"status": "200"},
            {"status": True},
            {"status": 1000},
            {"at": -1},
            {"bytes": -1},
            {"client": 5},
            {"path": "a" * 9000},
            {"request": -1},
        ):
            with self.subTest(overrides=overrides), self.assertRaises(ValueError):
                parse(record(**overrides), "alpha", "node-a")

    def test_a_record_from_before_the_request_counter_still_parses(self) -> None:
        raw = json.loads(record())
        del raw["request"]

        entry = parse(json.dumps(raw).encode("utf-8"), "alpha", "node-a")

        self.assertEqual(entry.request, 0)

    def test_a_cluster_the_deployment_does_not_name_reads_nothing(self) -> None:
        """The mirror is on disk; whether it may be read is the config's call."""

        self.mirror("beta", "node-c", record())

        self.assertEqual(read(self.root, ("alpha",)), Reading((), (), 0, False))
        self.assertEqual(read(self.root, ("alpha",), cluster="beta"), Reading((), (), 0, False))

    def test_a_file_name_that_is_not_a_node_is_ignored(self) -> None:
        for name in ("alpha--.jsonl", "alpha--../escape.jsonl", "alpha--a b.jsonl"):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(record())

        reading = read(self.root, ("alpha",))

        self.assertEqual(reading.entries, ())
        self.assertEqual(reading.nodes, ())

    def test_a_symlinked_mirror_is_not_followed(self) -> None:
        target = self.root / "elsewhere.jsonl"
        target.write_bytes(record(path="/secret"))
        (self.root / "alpha--node-a.jsonl").symlink_to(target)

        reading = read(self.root, ("alpha",))

        self.assertEqual(reading.entries, ())
        self.assertTrue(reading.unavailable)

    def test_filters_narrow_without_reaching_past_the_configured_clusters(self) -> None:
        self.mirror(
            "alpha",
            "node-a",
            record(status=200, path="/ok"),
            record(status=503, path="/down", backend="be-other"),
        )

        self.assertEqual(len(read(self.root, ("alpha",), status="5xx").entries), 1)
        self.assertEqual(len(read(self.root, ("alpha",), status="503").entries), 1)
        self.assertEqual(len(read(self.root, ("alpha",), status="99").entries), 0)
        self.assertEqual(len(read(self.root, ("alpha",), substring="be-other").entries), 1)
        self.assertEqual(len(read(self.root, ("alpha",), substring="/OK").entries), 1)

    def test_search_combines_terms_with_case_insensitive_boolean_operators(self) -> None:
        self.mirror(
            "alpha",
            "node-a",
            record(path="/api/orders", backend="be-orders"),
            record(path="/api/health", backend="be-orders"),
            record(path="/login", backend="be-login"),
        )

        reading = read(
            self.root,
            ("alpha",),
            substring="be-orders aNd (/orders OR /missing) AND not /health",
        )

        self.assertEqual([entry.path for entry in reading.entries], ["/api/orders"])

    def test_adjacent_search_terms_are_an_implicit_and_and_quotes_keep_a_phrase(self) -> None:
        self.mirror(
            "alpha",
            "node-a",
            record(host="first.example.com", path="/rock and roll"),
            record(host="second.example.com", path="/rock"),
        )

        implicit = read(self.root, ("alpha",), substring="first rock")
        phrase = read(self.root, ("alpha",), substring='"rock and roll"')

        self.assertEqual([entry.host for entry in implicit.entries], ["first.example.com"])
        self.assertEqual([entry.host for entry in phrase.entries], ["first.example.com"])

    def test_an_invalid_search_is_explained_and_never_silently_shows_everything(self) -> None:
        self.mirror("alpha", "node-a", record())

        reading = read(self.root, ("alpha",), substring="api AND")

        self.assertEqual(reading.entries, ())
        self.assertEqual(reading.filter_error, "The search expression ends with an operator.")

    def test_search_uses_the_resolved_destination_and_the_hidden_backend(self) -> None:
        backend = "primary-backend"
        self.mirror("alpha", "node-a", record(backend=backend, server="s3"))
        addresses = {("alpha", backend, "s3"): "app-three.example.net:8080"}

        by_destination = read(
            self.root,
            ("alpha",),
            substring="app-three.example.net:8080",
            server_addresses=addresses,
        )
        by_backend = read(
            self.root,
            ("alpha",),
            substring="primary-backend",
            server_addresses=addresses,
        )

        self.assertEqual(by_destination.entries[0].server, "app-three.example.net:8080")
        self.assertEqual(len(by_backend.entries), 1)

    def test_time_bounds_are_inclusive(self) -> None:
        self.mirror(
            "alpha",
            "node-a",
            record(at=int(NOW.timestamp()) - 60, path="/before"),
            record(path="/inside"),
            record(at=int(NOW.timestamp()) + 60, path="/after"),
        )

        reading = read(self.root, ("alpha",), from_at=NOW, to_at=NOW)

        self.assertEqual([entry.path for entry in reading.entries], ["/inside"])

    def test_the_limit_is_the_deployment_s_and_not_the_file_s(self) -> None:
        self.mirror("alpha", "node-a", *(record(request=n) for n in range(50)))

        self.assertEqual(len(read(self.root, ("alpha",), limit=10).entries), 10)

    def test_the_unfiltered_view_reads_a_bounded_tail(self) -> None:
        self.mirror("alpha", "node-a", record(path="/old"), record(path="/new"))

        with patch("haprion_ui.traffic_logs.MAX_TAIL_BYTES", len(record()) + 1):
            reading = read(self.root, ("alpha",))

        self.assertEqual([entry.path for entry in reading.entries], ["/new"])

    def test_a_filter_searches_the_whole_mirror_and_not_only_the_tail(self) -> None:
        """The question that found this: "ftp, some day last week".

        The unfiltered page shows the newest records and reads the newest
        bytes. A filter is a question about everything the collector kept,
        and a match older than the tail must be found.
        """

        self.mirror(
            "alpha", "node-a", record(path="/ftp-old"), *(record(path="/new") for _ in range(20))
        )

        with patch("haprion_ui.traffic_logs.MAX_TAIL_BYTES", len(record()) * 3):
            unfiltered = read(self.root, ("alpha",))
            searched = read(self.root, ("alpha",), substring="ftp")
            by_status = read(self.root, ("alpha",), status="200")

        self.assertNotIn("/ftp-old", [entry.path for entry in unfiltered.entries])
        self.assertEqual([entry.path for entry in searched.entries], ["/ftp-old"])
        self.assertEqual(len(by_status.entries), 21)

    def test_a_search_stops_at_the_collector_s_size_limit_and_drops_the_cut_line(self) -> None:
        self.mirror(
            "alpha", "node-a", record(path="/one"), record(path="/two"), record(path="/three")
        )

        with patch("haprion_ui.traffic_logs.MAX_SEARCH_BYTES", len(record()) * 2 + 5):
            reading = read(self.root, ("alpha",), substring="/")

        self.assertEqual(sorted(entry.path for entry in reading.entries), ["/one", "/two"])
        self.assertEqual(reading.malformed, 0)

    def test_a_search_keeps_only_the_newest_matches_within_the_limit(self) -> None:
        self.mirror("alpha", "node-a", *(record(request=n) for n in range(30)))

        reading = read(self.root, ("alpha",), substring="/", limit=5)

        self.assertEqual([entry.request for entry in reading.entries], [29, 28, 27, 26, 25])


class TheTrafficLogPage(LoginTestCase):
    """What the page must not get wrong, whatever it looks like.

    Two things carry weight here. Log text is written by whoever made the
    request, so it has to reach the browser as text and never as markup. And
    the page has to say how old each node's mirror is, because a node that
    stopped answering renders an empty table that otherwise reads as calm.
    """

    def setUp(self) -> None:
        super().setUp()
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        # What zone.js would have written; None is a browser that has not yet.
        self.browser_zone: str | None = None

    def test_successful_contact_with_backlog_shows_a_log_warning(self) -> None:
        (self.root / "alpha--node-a.meta.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "last_attempt": NOW.isoformat(),
                    "last_success": NOW.isoformat(),
                    "outcome": "ok",
                    "current_complete": False,
                    "remaining_bytes": 1234,
                    "pending_days": 2,
                }
            )
        )
        page = self.page(now=NOW)
        self.assertIn("collection succeeded; catching up", page)
        self.assertIn("last success 0 s ago", page)
        self.assertIn("1234 bytes remaining", page)
        self.assertIn("2 older day(s) pending", page)

    def test_backlog_keeps_the_age_of_a_previous_success_visible(self) -> None:
        for age, shown in (
            (timedelta(minutes=10), "10 min ago"),
            (timedelta(hours=9), "9.0 h ago"),
        ):
            for complete in (False, True):
                with self.subTest(age=age, current_complete=complete):
                    stamp = (NOW - age).isoformat()
                    (self.root / "alpha--node-a.meta.json").write_text(
                        json.dumps(
                            {
                                "schema_version": 1,
                                "last_attempt": stamp,
                                "last_success": stamp,
                                "outcome": "ok",
                                "current_complete": complete,
                                "remaining_bytes": 0 if complete else 1234,
                                "pending_days": 2,
                            }
                        )
                    )
                    page = self.page(now=NOW)
                    self.assertIn(f"last success {shown}", page)
                    self.assertIn("2 older day(s) pending", page)
                    if not complete:
                        self.assertIn("1234 bytes remaining", page)

    def host_zone(self, name: str) -> None:
        """Run this test as if the machine stood somewhere in particular.

        Without it a runner already on UTC would compare UTC against UTC and
        the assertion would pass while proving nothing.
        """

        previous = os.environ.get("TZ")
        os.environ["TZ"] = name
        time.tzset()

        def restore() -> None:
            if previous is None:
                del os.environ["TZ"]
            else:
                os.environ["TZ"] = previous
            time.tzset()

        self.addCleanup(restore)

    def page(
        self,
        *,
        enabled: bool = True,
        clusters: tuple[str, ...] = ("alpha",),
        objects: tuple[ClusterObjects, ...] = (),
        query: str = "",
        now: datetime | None = None,
        path: str = "/logs",
    ) -> str:
        """The page, optionally rendered as if the machine's clock read `now`.

        The view judges a chosen time against the retention window from its
        own clock. A test that names a date therefore has to name the clock
        too, or it passes for fourteen days and then fails on a calendar it
        never mentioned - which is exactly what happened on 2026-09-22.
        """
        config = replace(
            configuration(),
            clusters=clusters,
            traffic_logs=TrafficLogs(
                enabled=enabled, directory=self.root, max_lines=500, retention_days=14
            ),
        )
        client = self.client(config)
        if self.browser_zone is not None:
            client.cookies.set(ZONE_COOKIE, self.browser_zone)
        self.sign_in(client)

        def file_read(
            _connection: object, directory: Path, named: tuple[str, ...], **kwargs: object
        ) -> Reading:
            return read(directory, named, **kwargs)  # type: ignore[arg-type]

        frozen = now

        class Clock(datetime):
            @classmethod
            def now(cls, tz: Any = None) -> Any:
                return frozen if frozen is not None else datetime.now(tz)

        with (
            patch("haprion_ui.db.cluster_objects", return_value=list(objects)),
            patch("haprion_ui.traffic_logs.read_database", side_effect=file_read),
            patch("haprion_ui.views.datetime", Clock),
        ):
            response = client.get(f"{path}{query}")

        self.assertEqual(response.status_code, 200)
        return str(response.text)

    def healthy_meta(self, node: str = "node-a") -> None:
        now = datetime.now(UTC)
        (self.root / f"alpha--{node}.meta.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "cluster": "alpha",
                    "node": node,
                    "last_attempt": now.isoformat(),
                    "last_success": now.isoformat(),
                    "outcome": "ok",
                }
            )
        )

    def test_the_waf_page_shows_only_rule_hits_with_the_rule(self) -> None:
        """Fas 21: stored once in the traffic log, shown on a page of its own."""

        self.healthy_meta()
        with (self.root / "alpha--node-a.jsonl").open("wb") as mirror:
            mirror.write(record(request=1, path="/plain"))
            mirror.write(record(request=2, path="/admin", status=403, rule="admin-post:deny"))
            mirror.write(record(request=3, path="/scan", rule="scanner:log"))

        with (
            patch("haprion_ui.db.cluster_objects", return_value=[]),
            patch("haprion_ui.db.waf_findings", return_value=[]),
            patch("haprion_ui.db.waf_verdicts", return_value={}),
            patch("haprion_ui.db.waf_request_count", return_value=2),
            patch("haprion_ui.db.waf_counted", return_value={}),
            patch("haprion.crs.installed_catalog", return_value={}),
        ):
            waf = self.page(path="/waf", query="?view=requests")

        # The same three figures as on the other two tabs (mock round 7).
        self.assertIn("Findings <b>0</b>", waf)
        self.assertIn("Requests <b>2</b>", waf)
        self.assertNotIn(">/plain<", waf)
        self.assertIn(">/admin<", waf)
        self.assertIn(">admin-post</span>", waf)
        self.assertIn('status-badge-critical">admin-post', waf)
        self.assertIn('status-badge-warning">scanner', waf)
        self.assertIn('aria-current="page"><svg', waf.split(">WAF logs</a>")[0][-400:])
        self.assertIn('href="/waf?view=requests&amp;sort=', waf)
        self.assertIn('<input type="hidden" name="view" value="requests">', waf)
        self.assertNotIn('name="waf"', waf)

    def test_the_traffic_page_filters_on_rule_hits_and_keeps_the_filter(self) -> None:
        self.healthy_meta()
        with (self.root / "alpha--node-a.jsonl").open("wb") as mirror:
            mirror.write(record(request=1, path="/plain"))
            mirror.write(record(request=2, path="/admin", rule="admin-post:deny"))

        hits = self.page(query="?waf=hits")
        none = self.page(query="?waf=none")
        everything = self.page(query="?waf=nonsense")

        self.assertIn(">/admin<", hits)
        self.assertNotIn(">/plain<", hits)
        self.assertIn(">/plain<", none)
        self.assertNotIn(">/admin<", none)
        self.assertIn(">/plain<", everything)
        self.assertIn(">/admin<", everything)
        #
        # Without the filter a hit is still marked on its own row.
        #
        self.assertIn('status-badge-critical">admin-post</span>', everything)
        self.assertEqual(everything.count("log-rule"), 1)
        self.assertIn('href="/logs?waf=hits&amp;sort=', hits)

    def test_one_object_is_its_backends_and_its_names_before_any(self) -> None:
        self.healthy_meta()
        reading = object_reading()
        entry = dict(reading.result["objects"][0], runtime_backends=["sample"])
        objects = (replace(reading, result=dict(reading.result, objects=[entry])),)
        with (self.root / "alpha--node-a.jsonl").open("wb") as mirror:
            mirror.write(record(request=1, path="/served", backend="sample"))
            mirror.write(
                record(
                    request=2, path="/refused", host="Service.Example.com:443", backend="fe-https"
                )
            )
            mirror.write(record(request=3, path="/other", backend="be-app"))

        page = self.page(objects=objects, query="?cluster=alpha&object=sample-proxy")
        unknown = self.page(objects=objects, query="?cluster=alpha&object=gone")
        unscoped = self.page(objects=objects, query="?object=sample-proxy")

        self.assertIn(">/served<", page)
        self.assertIn(">/refused<", page)
        self.assertNotIn(">/other<", page)
        self.assertIn('<input type="hidden" name="object" value="sample-proxy">', page)
        self.assertIn('Only <strong>sample-proxy</strong> · <a href="/logs?cluster=alpha">', page)
        self.assertIn('href="/logs?cluster=alpha&amp;object=sample-proxy&amp;sort=', page)
        self.assertNotIn(">/served<", unknown, "an object the cluster lacks matches nothing")
        self.assertIn(">/other<", unscoped, "a name without its cluster is no object")

    def test_a_heading_reorders_the_rows_and_keeps_the_filter(self) -> None:
        self.healthy_meta()
        with (self.root / "alpha--node-a.jsonl").open("wb") as mirror:
            mirror.write(record(request=1, path="/small", bytes=10))
            mirror.write(record(request=2, path="/large", bytes=9000))
            mirror.write(record(request=3, path="/middle", bytes=500))

        newest = self.page(query="?status=2xx&sort=time")
        largest = self.page(query="?status=2xx&sort=bytes")

        def order(page: str) -> list[str]:
            paths = ["/small", "/large", "/middle"]
            return sorted(paths, key=lambda path: page.index(f">{path}<"))

        self.assertEqual(order(newest), ["/middle", "/large", "/small"])
        self.assertEqual(order(largest), ["/large", "/middle", "/small"])
        self.assertIn('href="/logs?status=2xx&amp;sort=-bytes"', largest)
        self.assertIn('aria-sort="descending"', largest)

    def test_a_value_cut_to_its_column_is_whole_on_hover(self) -> None:
        client = "2001:db8:85a3::8a2e:370:7334"
        (self.root / "alpha--node-a.jsonl").write_bytes(record(client=client, bytes=1234567890))

        page = self.page()

        self.assertIn(f'<code title="{client}">{client}</code>', page)
        self.assertIn('<td title="1234567890">1234567890</td>', page)

    def test_a_hostile_path_reaches_the_browser_as_text(self) -> None:
        hostile = "/<script>alert(1)</script>"
        (self.root / "alpha--node-a.jsonl").write_bytes(record(path=hostile))

        page = self.page()

        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertIn("&lt;script&gt;", page)

    def test_an_invalid_search_is_shown_as_the_form_s_error(self) -> None:
        # 26-10-03: it was drawn with classes no rule styled, as plain text.
        (self.root / "alpha--node-a.jsonl").write_bytes(record())

        page = self.page(query="?q=api+AND")

        self.assertIn(
            '<p class="preview-notice form-problem" role="alert">'
            '<span class="status-orb status-critical" aria-hidden="true"></span>'
            "<strong>The search expression ends with an operator.</strong></p>",
            page,
        )

    def test_the_page_shows_the_configured_destination_instead_of_s3(self) -> None:
        (self.root / "alpha--node-a.jsonl").write_bytes(
            record(backend="primary-backend", server="s3")
        )

        page = self.page(objects=(object_reading(),))

        self.assertIn("app-three.example.net:8080", page)
        self.assertNotIn(">s3<", page)

    def test_the_normal_page_has_no_live_badge_or_node_status_strip(self) -> None:
        (self.root / "alpha--node-a.jsonl").write_bytes(record())
        self.healthy_meta()

        page = self.page()

        self.assertNotIn("Log warning", page)
        self.assertNotIn(">Live<", page)
        self.assertNotIn("log-freshness", page)

    def test_only_the_short_log_description_is_shown(self) -> None:
        page = self.page()

        self.assertIn("Recent HTTP requests, mirrored from each node.", page)
        self.assertNotIn("Query strings are removed", page)

    def test_each_request_is_one_row_without_backend_or_timers(self) -> None:
        (self.root / "alpha--node-a.jsonl").write_bytes(record())

        page = self.page()

        self.assertNotIn("Backend / server", page)
        self.assertNotIn("Timers (ms)", page)
        self.assertNotIn("be-app", page)
        self.assertNotIn("1/0/0/2/3", page)
        self.assertIn('href="/logs?sort=destination">Destination</a></th>', page)
        self.assertIn('<td class="log-request"', page)

    def test_a_hostile_host_header_reaches_the_browser_as_text(self) -> None:
        (self.root / "alpha--node-a.jsonl").write_bytes(record(host='x"><img src=x onerror=1>'))

        page = self.page()

        self.assertNotIn("<img src=x", page)
        self.assertIn("&lt;img", page)

    def test_a_silent_node_is_named_on_the_page(self) -> None:
        (self.root / "alpha--node-b.meta.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "cluster": "alpha",
                    "node": "node-b",
                    "last_attempt": datetime.now(UTC).isoformat(),
                    "last_success": None,
                    "outcome": "unreachable",
                }
            )
        )

        page = self.page()

        self.assertIn("node-b", page)
        self.assertIn("never reached", page)
        self.assertIn("unreachable", page)

    def test_a_failed_attempt_after_success_is_not_hidden_by_the_success_age(self) -> None:
        now = datetime.now(UTC)
        (self.root / "alpha--node-a.meta.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "cluster": "alpha",
                    "node": "node-a",
                    "last_attempt": now.isoformat(),
                    "last_success": (now - timedelta(minutes=10)).isoformat(),
                    "outcome": "ssh",
                }
            )
        )

        page = self.page()

        # The view reads its own clock, so the seconds since the attempt depend
        # on how slow the runner is; only the outcome and the old success matter.
        self.assertRegex(page, r"last try \d+ s ago — failed \(ssh\)")
        self.assertIn("last success 10 min ago", page)

    def test_a_record_and_time_pickers_use_the_host_s_clock_without_a_zone_label(self) -> None:
        """One clock across the interface, and the page says which one it is.

        The card already prints the host's zone so its times line up against a
        journal; a log page on UTC beside it would be two clocks in one product.
        The machine-readable attribute stays UTC - that is what a later
        per-reader zone would be rendered from.
        """

        self.host_zone("Europe/Stockholm")
        (self.root / "alpha--node-a.jsonl").write_bytes(record())

        page = self.page()

        # The record is stored as 12:00 UTC and read on a host two hours ahead.
        self.assertIn("26-09-08 14:00:00", page)
        self.assertIn('href="/logs?sort=-time">Time <span', page)
        self.assertNotIn("Time (CEST)", page)
        self.assertNotIn("26-09-08 12:00:00", page)
        self.assertIn(f'datetime="{NOW.isoformat()}"', page)
        self.assertIn('name="from" value="" maxlength="14"', page)
        self.assertIn('name="to" value="" maxlength="14"', page)
        self.assertIn('placeholder="yy-mm-dd HH:mm"', page)
        self.assertNotIn('type="datetime-local"', page)
        self.assertLess(page.index("<span>Mon</span>"), page.index("<span>Sun</span>"))
        self.assertIn("logs.js", page)

    def test_a_browser_s_zone_is_read_and_filtered_in(self) -> None:
        """The browser's zone, not the host's, on every time and every filter (B190)."""

        self.host_zone("Europe/Stockholm")
        self.browser_zone = "America/New_York"
        (self.root / "alpha--node-a.jsonl").write_bytes(record())

        page = self.page(
            query="?from=26-09-08%2007:59&to=26-09-08%2008:00", now=NOW + timedelta(hours=1)
        )

        # 12:00 UTC is 08:00 in New York in September, and 14:00 on the host.
        self.assertIn("26-09-08 08:00:00", page)
        self.assertNotIn("26-09-08 14:00:00", page)
        self.assertIn("app.example.com", page)
        self.assertIn(f'datetime="{NOW.isoformat()}"', page)

    def test_a_zone_the_host_does_not_know_reads_the_host_s_clock(self) -> None:
        self.host_zone("Europe/Stockholm")
        self.browser_zone = "Nowhere/Atlantis"
        (self.root / "alpha--node-a.jsonl").write_bytes(record())

        page = self.page()

        self.assertIn("26-09-08 14:00:00", page)

    def test_a_cookie_that_is_not_a_zone_name_reads_the_host_s_clock(self) -> None:
        self.host_zone("Europe/Stockholm")
        self.browser_zone = "../../etc/localtime"
        (self.root / "alpha--node-a.jsonl").write_bytes(record())

        self.assertIn("26-09-08 14:00:00", self.page())

    def test_a_reader_s_zone_ends_with_the_request(self) -> None:
        """A context variable per request: the next reader starts on the host's clock."""

        self.host_zone("Europe/Stockholm")
        self.browser_zone = "America/New_York"
        (self.root / "alpha--node-a.jsonl").write_bytes(record())
        self.assertIn("26-09-08 08:00:00", self.page())

        self.browser_zone = None
        self.assertIn("26-09-08 14:00:00", self.page())
        self.assertEqual(metrics.shown(NOW).utcoffset(), timedelta(hours=2))

    def test_malformed_records_are_silently_discarded_from_the_page(self) -> None:
        (self.root / "alpha--node-a.jsonl").write_bytes(b"not json\n" + record())

        page = self.page()

        self.assertNotIn("Ignored 1 malformed record", page)
        self.assertIn("app.example.com", page)

    def test_local_from_and_to_values_filter_utc_records(self) -> None:
        self.host_zone("Europe/Stockholm")
        (self.root / "alpha--node-a.jsonl").write_bytes(record())

        page = self.page(
            query="?from=26-09-08%2013:59&to=26-09-08%2014:00", now=NOW + timedelta(hours=1)
        )

        self.assertIn("app.example.com", page)
        self.assertIn('value="26-09-08 13:59"', page)

    def test_to_includes_the_complete_selected_minute(self) -> None:
        self.host_zone("Europe/Stockholm")
        stamp = NOW + timedelta(seconds=45)
        (self.root / "alpha--node-a.jsonl").write_bytes(record(at=int(stamp.timestamp())))

        page = self.page(query="?to=26-09-08%2014:00", now=NOW + timedelta(hours=1))

        self.assertIn("app.example.com", page)

    def test_a_reversed_time_range_is_explained_instead_of_showing_all_records(self) -> None:
        (self.root / "alpha--node-a.jsonl").write_bytes(record())

        page = self.page(
            query="?from=26-09-09%2012:00&to=26-09-08%2012:00", now=NOW + timedelta(days=1)
        )

        self.assertIn("From must be earlier than To.", page)
        self.assertNotIn("app.example.com</strong>", page)

    def test_rows_offer_one_selection_checkbox_and_complete_csv_fields(self) -> None:
        long_path = "/" + "part/" * 80
        (self.root / "alpha--node-a.jsonl").write_bytes(record(path=long_path))

        page = self.page()

        self.assertIn("Export selected (.csv)", page)
        self.assertIn("data-log-select-all", page)
        self.assertEqual(page.count("data-log-select aria-label="), 1)
        self.assertIn(f'data-export-path="{long_path}"', page)
        self.assertNotIn("data-export-backend", page)
        self.assertNotIn("data-export-timers", page)

    def test_export_is_in_the_heading_and_filters_support_still_navigation(self) -> None:
        (self.root / "alpha--node-a.jsonl").write_bytes(record())

        page = self.page()

        self.assertLess(page.index("Export selected (.csv)"), page.index("data-log-filters"))
        self.assertIn("data-log-region", page)
        self.assertIn("data-log-clear-filters", page)

    def test_the_page_offers_compact_client_side_pagination(self) -> None:
        (self.root / "alpha--node-a.jsonl").write_bytes(record())

        page = self.page()

        self.assertIn("data-log-page-size", page)
        self.assertIn('<option value="25">25</option>', page)
        self.assertIn('<option value="50" selected>50</option>', page)
        self.assertIn('<option value="100">100</option>', page)
        self.assertIn("data-log-page-previous disabled", page)
        self.assertIn("data-log-page-next disabled", page)

    def test_disabled_says_so_instead_of_showing_an_empty_table(self) -> None:
        (self.root / "alpha--node-a.jsonl").write_bytes(record(path="/hidden"))

        page = self.page(enabled=False)

        self.assertIn("Traffic logging is disabled", page)
        self.assertNotIn("/hidden", page)

    def test_signing_out_is_required(self) -> None:
        config = replace(
            configuration(),
            clusters=("alpha",),
            traffic_logs=TrafficLogs(enabled=True, directory=self.root, max_lines=500),
        )
        response = self.client(config).get("/logs", follow_redirects=False)

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/login")


class ASubdomainOwnsItsLabelsButNotTheNamesItYields(unittest.TestCase):
    """B278: the file-backed filter matches as the database filter does."""

    def test_one_label_under_it_less_the_yielded_names(self) -> None:
        owned = (
            (),
            traffic_logs.owned_hosts(
                ("*.apps.example.com",), ("grafana.apps.example.com", "shop.example.com")
            ),
        )
        self.assertEqual(owned[1], ("*.apps.example.com", "!grafana.apps.example.com"))

        def entry(host: str) -> traffic_logs.Entry:
            return traffic_logs.Entry(
                cluster="alpha",
                node="node-a",
                at=datetime(2026, 10, 11, tzinfo=UTC),
                request=1,
                client="192.0.2.10",
                method="GET",
                host=host,
                path="/",
                frontend="f",
                backend="f",
                server="",
                status=403,
                request_time=0,
                queue_time=0,
                connect_time=0,
                response_time=0,
                total_time=0,
                bytes=0,
            )

        self.assertTrue(traffic_logs.owned_by(entry("Shop.Apps.Example.com:80"), owned))
        self.assertFalse(traffic_logs.owned_by(entry("grafana.apps.example.com"), owned))
        self.assertFalse(traffic_logs.owned_by(entry("a.b.apps.example.com"), owned))
        self.assertFalse(traffic_logs.owned_by(entry("apps.example.com"), owned))
