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

from haprion_ui import auth, cluster_settings_page, db, demo
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
        from tests.test_queue_route import queued

        return queued(operation=operation, cluster=cluster, state=state)

    def test_a_settings_publish_since_the_last_deploy_is_waiting_for_one(self) -> None:
        from haprion_ui import network

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

    def test_a_job_that_is_not_the_settings_is_not_shown_on_their_row(self) -> None:
        """Switching node backups off queued `backup_schedule`, and the row said so (26-10-10)."""

        patch = mock.patch(
            "haprion_ui.db.cluster_settings", return_value=list(demo.settings_rows(NOW))
        )
        patch.start()
        self.addCleanup(patch.stop)
        recent = mock.patch(
            "haprion_ui.db.recent_jobs",
            return_value=[self.job("backup_schedule", "edge-demo", state="pending")],
        )
        recent.start()
        self.addCleanup(recent.stop)
        self.account = replace(self.account, role="admin")
        client = self.client(
            replace(configuration(), management_writes=True, clusters=("edge-demo", "service-demo"))
        )
        self.sign_in(client)
        card = client.get("/settings").text.split('id="logs-metrics"')[1].split("</section>")[0]
        edge = next(row for row in card.split("<tr")[1:] if "/settings/clusters/edge-demo" in row)
        self.assertNotIn("data-busy", edge)
        self.assertNotIn("backup schedule", edge)
        self.assertIn(">Active<", edge)


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
            "target_disk": ["", ""],
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

    def test_sources_not_logged_are_saved_and_read_back(self) -> None:
        response = self.save(self.client_for(), not_logged_from="192.0.2.40\n\n198.51.100.0/28\n")

        self.assertEqual(response.status_code, 303, response.text)
        (change,) = self.saved_changes
        settings = load_document(change["document"].encode())
        self.assertEqual(settings.not_logged_from, ("192.0.2.40/32", "198.51.100.0/28"))
        self.assertIn("not from 192.0.2.40/32", cluster_settings_page.comment_for(settings))
        form = cluster_settings_page.form_from_result(
            {"log_targets": [], "not_logged_from": list(settings.not_logged_from)}
        )
        self.assertEqual(form.not_logged_from, "192.0.2.40/32\n198.51.100.0/28")

    def test_a_name_among_the_sources_not_logged_is_refused(self) -> None:
        response = self.save(self.client_for(), not_logged_from="monitor.example.com")

        self.assertEqual(response.status_code, 400)
        self.assertIn(
            "Not logged from: &#39;monitor.example.com&#39; is not an address or a network.",
            response.text,
        )
        self.assertEqual(self.saved_changes, [])

    def test_a_problem_is_named_in_the_forms_words_not_the_files(self) -> None:
        for fields, said in (
            (
                {"metrics_on": "on", "metrics_port": "8405", "metrics_sources": "x"},
                "Allowed sources: ",
            ),
            ({"target_port": ["70000", ""]}, "The port of graylog must be a port"),
            ({"target_disk": ["32", ""]}, "The disk queue of graylog must be"),
        ):
            with self.subTest(fields):
                response = self.save(self.client_for(), **fields)
                self.assertEqual(response.status_code, 400)
                self.assertIn(said, response.text)
                self.assertNotIn("log_targets.", response.text)
                self.assertNotIn("metrics.sources", response.text)

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


class TheDeliveryTable(SettingsClusterTestCase):
    """Where the attention list's forwarding rows lead (26-10-12)."""

    def rows(self, **receiver: Any) -> list[cluster_settings_page.DeliveryRow]:
        waiting = receiver.pop("waiting", None)
        node: dict[str, Any] = {
            "name": "node-a",
            "status_ok": True,
            "status": {
                "log_forwarding": {
                    "stats_age_sec": 20,
                    "receivers": [{"name": "loki", "dropped_last_hour": 0, **receiver}],
                }
            },
        }
        if waiting is not None:
            node["forward_waiting_since"] = {"loki": (NOW - waiting).isoformat()}
        return cluster_settings_page.delivery({"nodes": [node]}, now=NOW)

    def test_each_state_reads_as_the_attention_list_reads_it(self) -> None:
        from datetime import timedelta

        cases: list[tuple[dict[str, Any], str, str]] = [
            ({"queued": 0}, "Delivering", "healthy"),
            ({"queued": 3, "waiting": timedelta(minutes=2)}, "Delivering", "healthy"),
            ({"queued": 3, "waiting": timedelta(minutes=8)}, "Not delivered", "warning"),
            ({"queued": 10_000}, "Behind", "warning"),
            ({"queued": None}, "Unknown", "unknown"),
            (
                {"queued": 0, "dropped_last_hour": 1048},
                "1 048 dropped in the last hour",
                "critical",
            ),
        ]
        for receiver, state, tone in cases:
            with self.subTest(receiver=receiver):
                (row,) = self.rows(**receiver)
                self.assertEqual((row.state, row.tone), (state, tone))

    def test_the_nodes_reason_is_shown_and_never_reads_as_healthy(self) -> None:
        (row,) = self.rows(queued=1, last_error={"reason": "Connection refused", "age_sec": 5})

        self.assertEqual(
            (row.state, row.tone, row.reason), ("Delivering", "warning", "Connection refused")
        )

    def test_a_node_not_read_says_so_beside_one_that_forwards(self) -> None:
        forwarding = {"receivers": [{"name": "loki", "queued": 0, "dropped_last_hour": 0}]}
        rows = cluster_settings_page.delivery(
            {
                "nodes": [
                    {"name": "node-a", "status_ok": False},
                    {"name": "node-b", "status_ok": True, "status": {"log_forwarding": forwarding}},
                ]
            },
            now=NOW,
        )

        self.assertEqual(
            [(row.node, row.state) for row in rows],
            [("node-a", "Not read"), ("node-b", "Delivering")],
        )

    def test_a_cluster_forwarding_nowhere_has_no_table(self) -> None:
        """Not even for a node not read (review 26-10-12 F4)."""

        rows = cluster_settings_page.delivery(
            {
                "nodes": [
                    {"name": "node-a", "status_ok": False},
                    {"name": "node-b", "status_ok": True, "status": {"log_forwarding": None}},
                ]
            },
            now=NOW,
        )

        self.assertEqual(rows, [])

    def test_the_page_shows_the_demo_receiver_that_is_not_reached(self) -> None:
        with mock.patch("haprion_ui.db.cluster_statuses", return_value=list(demo.status_rows())):
            page = self.client_for().get("/settings/clusters/edge-demo").text

        table = page.split('id="delivery"', 1)[1].split("</section>", 1)[0]
        loki = next(row for row in table.split("<tr")[1:] if ">loki<" in row and ">edge-a<" in row)
        self.assertIn("Not delivered since", loki)
        self.assertIn("· Connection timed out", loki)
        self.assertIn("status-warning", loki)


class ADiscardFromTwoTabs(SettingsClusterTestCase):
    """Review 26-10-24, 07-02: the second tab's Discard was a bare 409 line of text."""

    def test_the_second_is_answered_inside_the_interface(self) -> None:
        client = self.client_for()
        client.headers["referer"] = "https://manager.example.com/settings/clusters/service-demo"
        with mock.patch(
            "haprion_ui.db.discard_cluster_change",
            side_effect=db.DraftConflict("the saved settings changed since they were read"),
        ):
            answer = self.save(client, settings_action="discard", saved_revision="2")

        self.assertEqual(answer.status_code, 409)
        self.assertIn("<h1>Not done</h1>", answer.text)
        self.assertIn("the saved settings changed since they were read", answer.text)
        self.assertIn('href="/settings/clusters/service-demo"', answer.text)
