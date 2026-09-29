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

from haproxy_mgmt.cluster_settings import load_document

from haproxy_ui import auth, cluster_settings_page, demo
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
        self.assertEqual((service.logs, service.metrics), ("Not sent", "Off"))
        self.assertEqual(edge.logs, "graylog 192.0.2.60:6514, loki [2001:db8::60]:6514 (TLS)")
        self.assertEqual(edge.metrics, "Port 8405 for 192.0.2.0/24, 198.51.100.7/32")
        self.assertEqual((never.readable, never.logs), (False, "Not read yet"))


class ThePage(QueueRouteTestCase):
    def setUp(self) -> None:
        super().setUp()
        patch = mock.patch(
            "haproxy_ui.db.cluster_settings", return_value=list(demo.settings_rows(NOW))
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

    def test_the_page_is_an_admins_behind_writes_for_a_listed_cluster(self) -> None:
        self.assertEqual(self.client_for().get("/settings/clusters/edge-demo").status_code, 200)
        self.assertEqual(self.client_for().get("/settings/clusters/elsewhere").status_code, 404)
        self.assertEqual(
            self.client_for(role="reader").get("/settings/clusters/edge-demo").status_code, 403
        )
        self.assertEqual(
            self.client_for(writes=False).get("/settings/clusters/edge-demo").status_code, 404
        )

    def test_a_save_queues_the_canonical_document_for_the_signed_in_person(self) -> None:
        response = self.save(
            self.client_for(),
            metrics_on="on",
            metrics_port="8405",
            metrics_sources="192.0.2.0/24\n",
        )

        self.assertEqual(response.status_code, 303, response.text)
        self.assertEqual(response.headers["location"], "/settings#logs-metrics")
        (queued,) = self.queued
        self.assertEqual(
            (queued["operation"], queued["cluster"]), ("cluster_settings_publish", "service-demo")
        )
        payload = queued["payload"]
        settings = load_document(payload["settings"].encode())
        self.assertEqual(settings.log_targets[0].address, "192.0.2.60")
        self.assertEqual(settings.metrics.port, 8405)  # type: ignore[union-attr]
        self.assertEqual(payload["expected_head"], "b" * 40)
        self.assertEqual(payload["comment"], "Logs & metrics: logs to graylog; metrics on 8405")
        self.assertEqual(payload["requested_by"], "operator")

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
