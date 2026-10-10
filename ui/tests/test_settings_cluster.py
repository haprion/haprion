"""Settings -> Logs & metrics: each cluster's log targets and exporter (Fas 15, B209).

Held here: one card row per listed cluster, saying where the log goes and
whether metrics are on; the cluster's page is admin-only behind writes, like
every page that queues a change; the form becomes the engine's canonical
document, parsed by the engine's own parser before anything is queued, so a
target given as a name is refused on the page and never reaches the worker;
the job carries the signed-in person for *Published by*.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from typing import Any
from unittest import mock

from haprion.cluster_settings import load_document

from haprion_ui import auth, cluster_settings_page, demo
from tests.test_login import configuration
from tests.test_queue_route import KEY, QueueRouteTestCase

NOW = datetime(2026, 9, 29, 12, 0, tzinfo=UTC)


class TheCard(QueueRouteTestCase):
    def test_one_line_per_cluster_in_the_listed_order(self) -> None:
        views = cluster_settings_page.card_views(
            ("service-demo", "edge-demo", "never-read"), demo.settings_rows(NOW)
        )
        self.assertEqual(
            [view.cluster for view in views], ["service-demo", "edge-demo", "never-read"]
        )
        service, edge, never = views
        self.assertEqual(
            (service.logs, service.metrics, service.logs_set, service.metrics_set),
            ("Not sent", "Off", False, False),
        )
        # The cell names the receivers; the addresses are the hover's.
        self.assertEqual((edge.logs, edge.logs_set), ("graylog, loki (TLS)", True))
        self.assertEqual(edge.logs_title, "graylog 192.0.2.60:6514, loki [2001:db8::60]:6514 (TLS)")
        self.assertEqual((edge.metrics, edge.metrics_set), ("Port 8405 · 2 sources", True))
        self.assertEqual(edge.metrics_title, "192.0.2.0/24, 198.51.100.7/32")
        self.assertEqual((never.readable, never.logs), (False, "Not read yet"))


class WhereTheSettingsHaveGotTo(QueueRouteTestCase):
    """Active only when what is shown is what the nodes run (review 2026-09-29 F1)."""

    def job(self, operation: str, cluster: str, state: str = "done") -> Any:
        from tests.test_queue_route import queued  # noqa: PLC0415

        return queued(operation=operation, cluster=cluster, state=state)

    def test_a_settings_publish_since_the_last_deploy_is_waiting_for_one(self) -> None:
        from haprion_ui import network  # noqa: PLC0415

        newest_first = [
            self.job("cluster_settings_publish", "edge-demo"),
            self.job("deploy", "service-demo"),
            self.job("cluster_settings_publish", "service-demo"),
            self.job("network_publish", "edge-demo"),
        ]
        self.assertEqual(
            network.awaiting_deploy(newest_first, part="settings"),
            frozenset({"edge-demo"}),
        )
        # The network page's own question is unchanged.
        self.assertEqual(network.awaiting_deploy(newest_first), frozenset({"edge-demo"}))

    def test_the_row_carries_what_is_owed(self) -> None:
        views = cluster_settings_page.card_views(
            ("edge-demo", "service-demo"),
            demo.settings_rows(NOW),
            waiting={"edge-demo"},
        )
        edge, service = views
        self.assertEqual((edge.waiting, service.waiting), (True, False))

    def test_the_card_says_waiting_and_not_active(self) -> None:
        patch = mock.patch(
            "haprion_ui.db.cluster_settings", return_value=list(demo.settings_rows(NOW))
        )
        patch.start()
        self.addCleanup(patch.stop)
        recent = mock.patch(
            "haprion_ui.db.recent_jobs",
            return_value=[self.job("cluster_settings_publish", "edge-demo")],
        )
        recent.start()
        self.addCleanup(recent.stop)
        self.account = replace(self.account, role="admin")
        client = self.client(
            replace(configuration(), management_writes=True, clusters=("edge-demo", "service-demo"))
        )
        self.sign_in(client)
        card = client.get("/settings").text.split('id="logs-metrics"')[1].split("</section>")[0]
        self.assertIn("Reconfigured · deploy to activate", card)
        self.assertNotIn(">Active<", card)

    def test_a_publish_still_queued_says_so_and_reloads_when_it_ends(self) -> None:
        """Publishing lands here before its job is done; the row said nothing (2026-10-05)."""

        patch = mock.patch(
            "haprion_ui.db.cluster_settings", return_value=list(demo.settings_rows(NOW))
        )
        patch.start()
        self.addCleanup(patch.stop)
        recent = mock.patch(
            "haprion_ui.db.recent_jobs",
            return_value=[self.job("cluster_settings_publish", "edge-demo", state="pending")],
        )
        recent.start()
        self.addCleanup(recent.stop)
        self.account = replace(self.account, role="admin")
        client = self.client(
            replace(configuration(), management_writes=True, clusters=("edge-demo", "service-demo"))
        )
        self.sign_in(client)
        page = client.get("/settings").text
        card = page.split('id="logs-metrics"')[1].split("</section>")[0]
        edge = next(row for row in card.split("<tr")[1:] if "/settings/clusters/edge-demo" in row)
        self.assertIn('data-busy="edge-demo"', edge)
        self.assertIn("Publishing settings", edge)
        self.assertNotIn(">Active<", edge)
        self.assertNotIn("deploy to activate", edge)
        self.assertIn("/static/waiting.js", page)


class SettingsClusterTestCase(QueueRouteTestCase):
    """The settings page with the demo readings, and its form posted."""

    def setUp(self) -> None:
        super().setUp()
        patch = mock.patch(
            "haprion_ui.db.cluster_settings", return_value=list(demo.settings_rows(NOW))
        )
        patch.start()
        self.addCleanup(patch.stop)

    def client_for(self, *, role: str = "admin", writes: bool = True) -> Any:
        self.account = replace(self.account, role=role)
        client = self.client(
            replace(
                configuration(), management_writes=writes, clusters=("edge-demo", "service-demo")
            )
        )
        self.sign_in(client)
        return client

    def save(self, client: Any, **fields: Any) -> Any:
        token = client.cookies[auth.SESSION_COOKIE]
        data: dict[str, Any] = {
            auth.CSRF_FIELD: auth.csrf_token(token),
            "expected_head": "b" * 40,
            "idempotency_key": KEY,
            "target_name": ["graylog", ""],
            "target_address": ["192.0.2.60", ""],
            "target_port": ["6514", ""],
            "target_buffer": ["", ""],
            "target_tls": ["no", "no"],
            **fields,
        }
        return client.post("/settings/clusters/service-demo", data=data, follow_redirects=False)


class ThePage(SettingsClusterTestCase):
    def test_the_page_is_an_admins_behind_writes_for_a_listed_cluster(self) -> None:
        self.assertEqual(self.client_for().get("/settings/clusters/edge-demo").status_code, 200)
        self.assertEqual(self.client_for().get("/settings/clusters/elsewhere").status_code, 404)
        self.assertEqual(
            self.client_for(role="reader").get("/settings/clusters/edge-demo").status_code, 403
        )
        self.assertEqual(
            self.client_for(writes=False).get("/settings/clusters/edge-demo").status_code, 404
        )

    def test_a_save_writes_the_canonical_document_for_the_signed_in_person(self) -> None:
        response = self.save(
            self.client_for(),
            metrics_on="on",
            metrics_port="8405",
            metrics_sources="192.0.2.0/24\n",
        )

        self.assertEqual(response.status_code, 303, response.text)
        self.assertEqual(response.headers["location"], "/settings/clusters/service-demo")
        self.assertEqual(self.queued, [])
        (change,) = self.saved_changes
        settings = load_document(change["document"].encode())
        self.assertEqual(settings.log_targets[0].address, "192.0.2.60")
        self.assertEqual(settings.metrics.port, 8405)  # type: ignore[union-attr]
        self.assertEqual((change["base_hash"], change["updated_by"]), ("b" * 40, "operator"))

    def test_shared_counters_are_saved_with_their_port(self) -> None:
        response = self.save(self.client_for(), peers_on="on", peers_port="10000")

        self.assertEqual(response.status_code, 303, response.text)
        (change,) = self.saved_changes
        settings = load_document(change["document"].encode())
        self.assertEqual(settings.peers.port, 10000)  # type: ignore[union-attr]
        self.assertIn("counters shared on 10000", cluster_settings_page.comment_for(settings))

    def test_shared_counters_need_a_port(self) -> None:
        response = self.save(self.client_for(), peers_on="on", peers_port="")

        self.assertEqual(response.status_code, 400)
        self.assertIn("The port for shared counters must be a number.", response.text)
        self.assertEqual(self.saved_changes, [])

    def test_a_target_named_rather_than_addressed_never_reaches_the_queue(self) -> None:
        response = self.save(self.client_for(), target_address=["logs.example.com", ""])

        self.assertEqual(response.status_code, 400)
        self.assertIn("must be an IP address, not a name", response.text)
        self.assertIn('value="logs.example.com"', response.text)
        self.assertEqual(self.queued, [])

    def test_an_incomplete_row_is_named(self) -> None:
        response = self.save(self.client_for(), target_name=["", ""])
        self.assertEqual(response.status_code, 400)
        self.assertIn("Log target 1 needs a name.", response.text)
        self.assertEqual(self.queued, [])

    def test_a_forged_form_is_refused(self) -> None:
        client = self.client_for()
        response = client.post(
            "/settings/clusters/service-demo",
            data={auth.CSRF_FIELD: "forged", "idempotency_key": KEY},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.queued, [])
