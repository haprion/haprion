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
