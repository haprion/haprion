"""What needs doing, on the dashboard and for a monitor (B274)."""

from __future__ import annotations

import json
import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from unittest import mock

from haprion_ui import attention, auth
from haprion_ui.db import StatusAccess
from tests.test_job_page import job
from tests.test_login import LoginTestCase, configuration

NOW = datetime(2026, 10, 11, 18, 40, 2, tzinfo=UTC)


def cluster(name: str = "alpha", **fields: Any) -> Any:
    values: dict[str, Any] = {
        "cluster": name,
        "configured": True,
        "stale": False,
        "behind": False,
        "age_label": "15 s ago",
        "observed_at": NOW - timedelta(seconds=15),
        "nodes": (),
    }
    values.update(fields)
    return SimpleNamespace(**values)


def node(name: str, tone: str, label: str = "Down", detail: str = "") -> Any:
    return SimpleNamespace(name=name, tone=tone, label=label, detail=detail)


class EachKindComesAndGoes(unittest.TestCase):
    def test_a_failed_job_stands_until_the_same_operation_works(self) -> None:
        failed = job(state="failed", outcome="failed", operation="deploy")
        failed = replace(failed, id=1, created_at=NOW - timedelta(hours=2))
        other = replace(
            job(state="done", outcome="done", operation="cert_deploy"),
            id=2,
            created_at=NOW - timedelta(hours=1),
        )
        fixed = replace(
            job(state="done", outcome="done", operation="deploy"),
            id=3,
            created_at=NOW - timedelta(minutes=5),
        )

        self.assertEqual([item.subject for item in attention.from_jobs([failed, other])], ["job 1"])
        self.assertEqual(attention.from_jobs([failed, other, fixed]), [])

    def test_a_running_job_does_not_settle_anything(self) -> None:
        failed = replace(job(state="failed", outcome="failed"), id=1, created_at=NOW)
        running = replace(job(state="running"), id=2, created_at=NOW + timedelta(minutes=1))

        self.assertEqual(len(attention.from_jobs([failed, running])), 1)

    def test_a_down_node_and_a_stale_reading_are_listed_and_a_drain_is_not(self) -> None:
        items = attention.from_dashboard(
            [
                cluster("alpha", nodes=(node("node-a", "critical"), node("node-b", "healthy"))),
                cluster("beta", stale=True, age_label="9 min ago"),
            ],
            drift_label="Version drift",
        )

        self.assertEqual(
            [(item.kind, item.subject) for item in items],
            [("node", "node-a"), ("reading", "beta")],
        )

    def test_a_node_waiting_for_its_deploy_is_not_listed(self) -> None:
        items = attention.from_dashboard(
            [
                cluster(
                    behind=True,
                    nodes=(
                        node("node-a", "warning", "Version drift"),
                        node("node-b", "warning", "Version drift"),
                    ),
                )
            ],
            drift_label="Version drift",
        )

        self.assertEqual(items, [])

    def test_a_certificate_running_out_is_listed_once(self) -> None:
        row = SimpleNamespace(
            identifier="shop.example.com",
            tone="critical",
            state_tone="healthy",
            expiry_label="4 days left",
            state_label="On all 2 nodes",
            interface=False,
            placeholder=False,
        )
        registry = SimpleNamespace(certificates=(row,), interface=None, served=None)

        items = attention.from_certificates(registry, ())

        self.assertEqual(
            [(item.subject, item.message) for item in items], [("shop.example.com", "4 days left")]
        )

    def test_the_interface_certificate_counts_only_by_its_expiry(self) -> None:
        row = SimpleNamespace(
            identifier="mgr.example.com",
            tone="healthy",
            state_tone="warning",
            expiry_label="in 300 days",
            state_label="No targets",
            interface=True,
            placeholder=False,
        )
        registry = SimpleNamespace(certificates=(), interface=row, served=None)

        self.assertEqual(attention.from_certificates(registry, ()), [])

    def test_the_worst_comes_first_and_the_counts_add_up(self) -> None:
        warning = attention.Item("waf", "warning", "alpha", "shop", "x", NOW, "/waf")
        critical = attention.Item("job", "critical", "alpha", "job 1", "y", NOW, "/jobs")

        built = attention.build_attention(
            [warning, critical], status_age={"alpha": 10}, stale_after_seconds=40, now=NOW
        )

        self.assertEqual([item.kind for item in built.items], ["job", "waf"])
        self.assertEqual(built.counts(), {"critical": 1, "warning": 1})
        self.assertTrue(built.fresh)


class TheLogsComeOnlyWhenSomebodyIsWanted(unittest.TestCase):
    """26-10-12: the log page's warning on the list, less what heals itself."""

    NOW = datetime(2026, 10, 12, 9, 0, tzinfo=UTC)

    def freshness(self, **fields: Any) -> Any:
        from haprion_ui.traffic_logs import Freshness

        base: dict[str, Any] = {
            "cluster": "alpha",
            "node": "node-a",
            "last_attempt": self.NOW,
            "last_success": self.NOW,
            "outcome": "ok",
        }
        return Freshness(**{**base, **fields})

    def messages(self, *nodes: Any) -> list[str]:
        return [item.message for item in attention.from_traffic_logs(nodes, now=self.NOW)]

    def test_a_current_node_and_a_burst_being_caught_up_are_not_listed(self) -> None:
        self.assertEqual(
            self.messages(
                self.freshness(),
                self.freshness(node="node-b", current_complete=False, behind_runs=2),
            ),
            [],
        )

    def test_what_wants_somebody_is_listed(self) -> None:
        old = self.NOW - timedelta(minutes=12)
        self.assertEqual(
            self.messages(
                self.freshness(outcome="unreachable", last_success=old),
                self.freshness(node="node-b", last_attempt=None, last_success=None),
                self.freshness(node="node-c", last_attempt=old, last_success=old),
                self.freshness(node="node-d", current_complete=False, behind_runs=5),
                self.freshness(node="node-e", pending_days=2),
            ),
            [
                "log collection failed (unreachable)",
                "log collection has never reached the node",
                "log collection last succeeded 12 min ago",
                "log collection behind for 5 runs",
                "log collection behind · 2 older day(s) waiting",
            ],
        )

    def test_a_receiver_that_dropped_lines_is_critical(self) -> None:
        row = SimpleNamespace(
            cluster="alpha",
            result={
                "nodes": [
                    {
                        "name": "node-a",
                        "status_ok": True,
                        "status": {
                            "log_forwarding": {
                                "stats_age_sec": 40,
                                "receivers": [
                                    {"name": "graylog", "queued": 12, "dropped_last_hour": 0},
                                    {"name": "loki", "queued": 20000, "dropped_last_hour": 7},
                                ],
                            }
                        },
                    },
                    {"name": "node-b", "status_ok": True, "status": {"log_forwarding": None}},
                ]
            },
        )

        items = attention.from_log_forwarding([row])

        self.assertEqual(
            [(item.severity, item.subject, item.message) for item in items],
            [
                ("critical", "node-a", "traffic log to loki: 7 lines dropped in the last hour"),
                ("warning", "node-a", "traffic log to loki: 20 000 lines queued"),
            ],
        )


class EveryKindHasALabel(unittest.TestCase):
    def test_the_dashboard_names_where_each_kind_goes(self) -> None:
        #
        # The box's link label is a lookup by kind in the template; a kind
        # missing there renders an empty link rather than an error (26-10-12).
        #
        import re
        from pathlib import Path

        template = (Path(attention.__file__).parent / "templates" / "index.html").read_text()
        found = re.search(r"\{\{ \{(.*?)\}\[item\.kind\] \}\}", template)
        if found is None:
            self.fail("the label lookup is no longer where the test reads it")
        labelled = set(re.findall(r"'([a-z]+)': '", found.group(1)))
        self.assertEqual(labelled, set(attention.KINDS))


class TheTwoForms(unittest.TestCase):
    def built(self, ages: dict[str, int | None]) -> attention.Attention:
        item = attention.Item("job", "critical", "alpha", "job 1", "Deploy failed", NOW, "/jobs")
        return attention.build_attention([item], status_age=ages, stale_after_seconds=40, now=NOW)

    def test_the_json_names_what_a_monitor_asks(self) -> None:
        document = json.loads(self.built({"alpha": 10}).as_json())

        self.assertEqual(document["counts"], {"critical": 1, "warning": 0})
        self.assertTrue(document["fresh"])
        self.assertEqual(document["generated_at"], "2026-10-11T18:40:02Z")
        self.assertEqual(document["items"][0]["kind"], "job")

    def test_a_reading_that_stopped_is_not_fresh(self) -> None:
        self.assertFalse(self.built({"alpha": 300}).fresh)
        self.assertFalse(self.built({"alpha": None}).fresh)

    def test_the_metrics_carry_every_kind_and_each_clusters_age(self) -> None:
        text = self.built({"alpha": 10}).as_metrics()

        self.assertIn('haprion_attention_items{kind="job",severity="critical"} 1', text)
        self.assertIn('haprion_attention_items{kind="certificate",severity="warning"} 0', text)
        self.assertIn('haprion_status_age_seconds{cluster="alpha"} 10', text)


class TheAccessList(unittest.TestCase):
    def test_addresses_and_networks_one_per_line(self) -> None:
        self.assertEqual(
            attention.access_list("192.0.2.10\n198.51.100.0/24\n\n192.0.2.10\n"),
            ("192.0.2.10/32", "198.51.100.0/24"),
        )

    def test_a_network_with_host_bits_is_a_typo(self) -> None:
        with self.assertRaises(ValueError):
            attention.access_list("192.0.2.1/24")
        with self.assertRaises(ValueError):
            attention.access_list("monitor.example.com")


class TheEndpoint(LoginTestCase):
    def ask(self, path: str, *, allowed: list[StatusAccess], address: str) -> Any:
        client = self.client()
        with mock.patch("haprion_ui.db.status_access", return_value=allowed):
            return client.get(path, headers={"X-Forwarded-For": address})

    def test_nobody_may_ask_while_the_list_is_empty(self) -> None:
        response = self.ask("/status/attention.json", allowed=[], address="192.0.2.10")

        self.assertEqual(response.status_code, 404)

    def test_an_address_on_the_list_is_answered_without_a_sign_in(self) -> None:
        listed = [StatusAccess("192.0.2.0/24", "admin", NOW)]

        answer = self.ask("/status/attention.json", allowed=listed, address="192.0.2.10")
        metrics = self.ask("/status/metrics", allowed=listed, address="192.0.2.10")
        refused = self.ask("/status/metrics", allowed=listed, address="198.51.100.7")

        self.assertEqual(answer.status_code, 200)
        self.assertEqual(json.loads(answer.text)["counts"], {"critical": 0, "warning": 0})
        self.assertEqual(metrics.status_code, 200)
        self.assertIn("haprion_attention_items", metrics.text)
        self.assertEqual(refused.status_code, 404)


class TheSettingsCard(LoginTestCase):
    def test_saving_replaces_the_list_and_refuses_a_typo(self) -> None:
        client = self.client(replace(configuration(), management_writes=True))
        self.sign_in(client)
        token = auth.csrf_token(client.cookies[auth.SESSION_COOKIE])
        with mock.patch("haprion_ui.db.set_status_access") as stored:
            saved = client.post(
                "/settings/status-access",
                data={"csrf_token": token, "networks": "192.0.2.10\n"},
                follow_redirects=False,
            )
            refused = client.post(
                "/settings/status-access",
                data={"csrf_token": token, "networks": "192.0.2.1/24"},
                follow_redirects=False,
            )

        self.assertEqual(saved.status_code, 303)
        stored.assert_called_once()
        self.assertEqual(stored.call_args.kwargs["networks"], ("192.0.2.10/32",))
        self.assertEqual(refused.status_code, 400)
        self.assertIn("host bits", refused.text)
        # Refused on the edit page, with what was typed (26-10-12).
        self.assertIn("<h1>External monitoring</h1>", refused.text)
        self.assertIn(">192.0.2.1/24</textarea>", refused.text)

    def test_the_card_is_a_row_and_the_list_has_a_page_of_its_own(self) -> None:
        client = self.client(replace(configuration(), management_writes=True))
        self.sign_in(client)
        entry = StatusAccess(
            "192.0.2.10/32", "localadmin", datetime(2026, 10, 11, 19, 46, tzinfo=UTC)
        )
        with mock.patch("haprion_ui.db.status_access", return_value=[entry]):
            card = client.get("/settings").text.split('id="external-monitoring"', 1)[1]
            card = card.split("</section>", 1)[0]
            page = client.get("/settings/status-access").text

        self.assertIn('href="/settings/status-access">Edit</a>', card)
        self.assertIn("<code>192.0.2.10/32</code>", card)
        self.assertNotIn("<textarea", card)
        self.assertIn('<td data-label="Added by">localadmin</td>', page)
        self.assertIn(">192.0.2.10/32\n</textarea>", page)
        self.assertIn('href="/settings#external-monitoring">Cancel</a>', page)


class TheDashboardBox(LoginTestCase):
    def test_it_is_drawn_only_when_something_needs_doing(self) -> None:
        item = attention.Item(
            "job", "critical", "alpha", "job 7", "Deploy failed", NOW, "/jobs#job-7"
        )
        some = attention.build_attention([item], status_age={}, stale_after_seconds=40, now=NOW)
        none = attention.build_attention([], status_age={}, stale_after_seconds=40, now=NOW)
        client = self.client()
        self.sign_in(client)

        with mock.patch("haprion_ui.views._attention", return_value=some):
            drawn = client.get("/").text
        with mock.patch("haprion_ui.views._attention", return_value=none):
            empty = client.get("/").text

        self.assertIn("Needs attention", drawn)
        self.assertIn('<a class="attention-row" href="/jobs#job-7">', drawn)
        self.assertIn("Deploy failed", drawn)
        self.assertNotIn("Needs attention", empty)


if __name__ == "__main__":
    unittest.main()
