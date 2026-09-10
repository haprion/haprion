from __future__ import annotations

import json
import os
import tempfile
import time
import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from haproxy_mgmt.proxy_model import load_proxy

from haproxy_ui.config import TrafficLogs
from haproxy_ui.db import ClusterObjects
from haproxy_ui.traffic_logs import (
    MAX_RECORD_BYTES,
    Reading,
    configured_server_addresses,
    parse,
    read,
    resolve_server_addresses,
)
from tests.test_login import LoginTestCase, configuration

NOW = datetime(2026, 9, 8, 12, 0, 0, tzinfo=UTC)

PROXY = """schema: 1
name: sample-proxy
hostnames:
- service.example.com
listen:
  protocol: http
routes:
- path: /
  backend: primary-pool
backends:
  primary-pool:
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
                    record(backend="mgd-sample-proxy-primary-pool", server="s3"),
                    "alpha",
                    "node-a",
                ),
            ),
            nodes=(),
            malformed=0,
            unavailable=False,
            truncated=False,
        )

        resolved = resolve_server_addresses(reading, addresses)

        self.assertEqual(resolved.entries[0].server, "app-three.example.net:8080")

    def test_an_unresolved_generated_alias_is_not_presented_as_a_destination(self) -> None:
        reading = Reading(
            entries=(parse(record(server="s2"), "alpha", "node-a"),),
            nodes=(),
            malformed=0,
            unavailable=False,
            truncated=False,
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

        self.assertEqual(read(self.root, ("alpha",)), Reading((), (), 0, False, False))
        self.assertEqual(
            read(self.root, ("alpha",), cluster="beta"), Reading((), (), 0, False, False)
        )

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
        backend = "mgd-sample-proxy-primary-pool"
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
            substring="sample-proxy-primary",
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

    def test_a_bounded_tail_reports_that_older_records_were_not_searched(self) -> None:
        self.mirror("alpha", "node-a", record(path="/old"), record(path="/new"))

        with patch("haproxy_ui.traffic_logs.MAX_SCAN_BYTES", len(record()) + 1):
            reading = read(self.root, ("alpha",))

        self.assertTrue(reading.truncated)
        self.assertEqual([entry.path for entry in reading.entries], ["/new"])


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
    ) -> str:
        config = replace(
            configuration(),
            clusters=clusters,
            traffic_logs=TrafficLogs(enabled=enabled, directory=self.root, max_lines=500),
        )
        client = self.client(config)
        self.sign_in(client)
        with patch("haproxy_ui.db.cluster_objects", return_value=list(objects)):
            response = client.get(f"/logs{query}")

        self.assertEqual(response.status_code, 200)
        return response.text

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

    def test_a_hostile_path_reaches_the_browser_as_text(self) -> None:
        hostile = "/<script>alert(1)</script>"
        (self.root / "alpha--node-a.jsonl").write_bytes(record(path=hostile))

        page = self.page()

        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertIn("&lt;script&gt;", page)

    def test_the_page_shows_the_configured_destination_instead_of_s3(self) -> None:
        (self.root / "alpha--node-a.jsonl").write_bytes(
            record(backend="mgd-sample-proxy-primary-pool", server="s3")
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
        self.assertIn("<th>Destination</th>", page)
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

        self.assertIn("last try 0 s ago — failed (ssh)", page)
        self.assertIn("last success 10 min ago", page)

    def test_a_truncated_search_window_is_stated_on_the_page(self) -> None:
        (self.root / "alpha--node-a.jsonl").write_bytes(record(path="/old") + record(path="/new"))

        with patch("haproxy_ui.traffic_logs._tail", return_value=(record(path="/new"), True)):
            page = self.page()

        self.assertIn("Filters searched only the newest 16 MiB per node", page)
        self.assertIn("Older records were not searched", page)

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
        self.assertIn("<th>Time</th>", page)
        self.assertNotIn("Time (CEST)", page)
        self.assertNotIn("26-09-08 12:00:00", page)
        self.assertIn(f'datetime="{NOW.isoformat()}"', page)
        self.assertIn('type="datetime-local" name="from"', page)
        self.assertIn('type="datetime-local" name="to"', page)

    def test_malformed_records_are_silently_discarded_from_the_page(self) -> None:
        (self.root / "alpha--node-a.jsonl").write_bytes(b"not json\n" + record())

        page = self.page()

        self.assertNotIn("Ignored 1 malformed record", page)
        self.assertIn("app.example.com", page)

    def test_local_from_and_to_values_filter_utc_records(self) -> None:
        self.host_zone("Europe/Stockholm")
        (self.root / "alpha--node-a.jsonl").write_bytes(record())

        page = self.page(query="?from=2026-09-08T13:59:59&to=2026-09-08T14:00:01")

        self.assertIn("app.example.com", page)
        self.assertIn('value="2026-09-08T13:59:59"', page)

    def test_a_reversed_time_range_is_explained_instead_of_showing_all_records(self) -> None:
        (self.root / "alpha--node-a.jsonl").write_bytes(record())

        page = self.page(query="?from=2026-09-09T12:00:00&to=2026-09-08T12:00:00")

        self.assertIn("From must be earlier than To.", page)
        self.assertNotIn("app.example.com</strong>", page)

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
