"""Settings -> Nodes: which nodes a cluster has, and adding or removing one (B211).

Held here: the page is an admin's behind writes, for a listed cluster; a pasted
block is read and shown - its host key fingerprint and the host - before
anything is queued; only the node's name typed back queues the job, and the
job carries the block and the host and nothing the page invented; a block made
for another cluster, a third-to-last node, the VIP holder and a wrong name are
refused on the page and never reach the worker.
"""

from __future__ import annotations

import base64
import copy
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any
from unittest import mock

from haproxy_mgmt import node_enrollment
from haproxy_mgmt.node_enrollment import Enrollment

from haproxy_ui import auth, cluster_nodes, demo
from tests.test_login import configuration
from tests.test_queue_route import KEY, QueueRouteTestCase

NOW = datetime(2026, 9, 30, 9, 0, tzinfo=UTC)


def key(seed: int) -> str:
    blob = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + bytes([seed]) * 32
    return f"ssh-ed25519 {base64.b64encode(blob).decode()}"


def block(cluster: str = "edge-demo", name: str = "edge-c") -> str:
    return node_enrollment.render(
        Enrollment(
            cluster=cluster,
            name=name,
            host=f"{name}.example.com",
            host_key=key(1),
            config_pull_key=key(2),
            cert_pull_key=key(3),
        )
    )


def with_third_node() -> list[Any]:
    rows = list(demo.status_rows(NOW))
    edge = rows[0]
    result = copy.deepcopy(edge.result)
    third = copy.deepcopy(result["nodes"][1])
    third["name"], third["mgmt_host"] = "edge-c", "edge-c.example.com"
    result["nodes"].append(third)
    rows[0] = replace(edge, result=result)
    return rows


class NodesPage(QueueRouteTestCase):
    rows: list[Any] | None = None

    def setUp(self) -> None:
        super().setUp()
        patch = mock.patch(
            "haproxy_ui.db.cluster_statuses",
            side_effect=lambda _connection: self.rows or list(demo.status_rows(NOW)),
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

    def post(self, client: Any, path: str, **fields: Any) -> Any:
        token = client.cookies[auth.SESSION_COOKIE]
        data = {auth.CSRF_FIELD: auth.csrf_token(token), "idempotency_key": KEY, **fields}
        return client.post(path, data=data, follow_redirects=False)


class ThePage(NodesPage):
    def test_the_page_is_an_admins_behind_writes_for_a_listed_cluster(self) -> None:
        page = self.client_for().get("/settings/nodes/edge-demo")
        self.assertEqual(page.status_code, 200)
        self.assertIn("edge-a", page.text)
        self.assertEqual(self.client_for().get("/settings/nodes/elsewhere").status_code, 404)
        self.assertEqual(
            self.client_for(role="reader").get("/settings/nodes/edge-demo").status_code, 403
        )
        self.assertEqual(
            self.client_for(writes=False).get("/settings/nodes/edge-demo").status_code, 404
        )

    def test_the_settings_card_lists_each_cluster_s_nodes(self) -> None:
        card = self.client_for().get("/settings").text.split('id="nodes"')[1].split("</section>")[0]
        self.assertIn("edge-a, edge-b", card)
        self.assertIn('href="/settings/nodes/service-demo"', card)


class AddingANode(NodesPage):
    def test_a_block_is_shown_before_anything_is_queued(self) -> None:
        response = self.post(self.client_for(), "/settings/nodes/edge-demo/add", block=block())

        self.assertEqual(response.status_code, 200)
        self.assertIn(node_enrollment.fingerprint(key(1)), response.text)
        self.assertIn('value="edge-c.example.com"', response.text)
        self.assertIn("Type edge-c to add it", response.text)
        self.assertEqual(self.queued, [])

    def test_the_name_typed_back_queues_the_block_and_the_host(self) -> None:
        response = self.post(
            self.client_for(),
            "/settings/nodes/edge-demo/add",
            block=block(),
            host="lb-edge-c.example.com",
            confirm="edge-c",
        )

        self.assertEqual(response.status_code, 303, response.text)
        (queued,) = self.queued
        self.assertEqual((queued["operation"], queued["cluster"]), ("cluster_node", "edge-demo"))
        self.assertEqual(
            queued["payload"],
            {"action": "add", "block": block(), "host": "lb-edge-c.example.com"},
        )

    def test_a_wrong_name_queues_nothing(self) -> None:
        response = self.post(
            self.client_for(), "/settings/nodes/edge-demo/add", block=block(), confirm="edge-x"
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.queued, [])

    def test_a_block_for_another_cluster_is_refused_on_the_page(self) -> None:
        response = self.post(
            self.client_for(), "/settings/nodes/edge-demo/add", block=block("service-demo")
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("made for service-demo", response.text)
        self.assertEqual(self.queued, [])

    def test_something_that_is_not_a_block_is_named(self) -> None:
        response = self.post(self.client_for(), "/settings/nodes/edge-demo/add", block="hello")
        self.assertEqual(response.status_code, 400)
        self.assertIn("not an enrollment block", response.text)


class RemovingANode(NodesPage):
    def test_a_pair_keeps_both_nodes(self) -> None:
        response = self.post(self.client_for(), "/settings/nodes/edge-demo/remove", node="edge-b")
        self.assertEqual(response.status_code, 400)
        self.assertIn("at least 2 nodes", response.text)

    def test_a_third_node_is_asked_for_and_then_removed(self) -> None:
        self.rows = with_third_node()
        client = self.client_for()

        asked = self.post(client, "/settings/nodes/edge-demo/remove", node="edge-c")
        self.assertIn("Type edge-c to remove it", asked.text)
        self.assertEqual(self.queued, [])

        response = self.post(
            client, "/settings/nodes/edge-demo/remove", node="edge-c", confirm="edge-c"
        )
        self.assertEqual(response.status_code, 303, response.text)
        (queued,) = self.queued
        self.assertEqual(queued["payload"], {"action": "remove", "node": "edge-c"})

    def test_the_vip_holder_is_not_offered_and_is_refused(self) -> None:
        self.rows = with_third_node()
        response = self.post(self.client_for(), "/settings/nodes/edge-demo/remove", node="edge-a")
        self.assertEqual(response.status_code, 400)
        self.assertIn("holds the VIP", response.text)

    def test_removable_says_why_not(self) -> None:
        rows = [
            cluster_nodes.NodeRow("a", "a.example.com", owner=True, reachable=True),
            cluster_nodes.NodeRow("b", "b.example.com", owner=False, reachable=True),
            cluster_nodes.NodeRow("c", "c.example.com", owner=False, reachable=False),
        ]
        self.assertIsNone(cluster_nodes.removable(rows, "c"))
        self.assertIn("holds the VIP", cluster_nodes.removable(rows, "a") or "")
        self.assertIn("not a node", cluster_nodes.removable(rows, "z") or "")


class TheListFollowsTheClusterFile(NodesPage):
    """Once the poller has read the cluster file, the pages draw its clusters (B206)."""

    def test_the_poller_s_list_replaces_the_configured_one(self) -> None:
        patch = mock.patch("haproxy_ui.db.cluster_list", return_value=("service-demo",))
        patch.start()
        self.addCleanup(patch.stop)
        client = self.client_for()

        card = client.get("/settings").text.split('id="nodes"')[1].split("</section>")[0]
        self.assertIn('href="/settings/nodes/service-demo"', card)
        self.assertNotIn('href="/settings/nodes/edge-demo"', card)
        self.assertEqual(client.get("/settings/nodes/edge-demo").status_code, 404)


class ClusterPage(NodesPage):
    def setUp(self) -> None:
        super().setUp()
        patch = mock.patch(
            "haproxy_ui.db.cluster_certificates",
            side_effect=lambda _connection: list(demo.certificate_rows(NOW)),
        )
        patch.start()
        self.addCleanup(patch.stop)

    def creation(self, **fields: Any) -> dict[str, Any]:
        form = {
            "cluster": "gamma",
            "display_name": "Gamma",
            "vip": "198.51.100.30",
            "address_prefix": "24",
            "default_certificate": "demo.example.pem",
            "block_1": block("gamma", "gamma-a"),
            "block_2": block("gamma", "gamma-b").replace("\n", ""),
            "host_2": "lb-gamma-b.example.com",
        }
        form.update(fields)
        return form


class CreatingACluster(ClusterPage):
    """Held here: both blocks are read and shown before anything is queued, and the ID
    typed back queues exactly the request `haproxy-cluster add` sends."""

    def test_the_card_offers_it_and_the_page_lists_the_registry(self) -> None:
        client = self.client_for()
        card = client.get("/settings").text.split('id="nodes"')[1].split("</section>")[0]
        self.assertIn('href="/settings/new-cluster"', card)
        page = client.get("/settings/new-cluster")
        self.assertEqual(page.status_code, 200)
        self.assertIn('<option value="internal.demo.example.pem">', page.text)
        self.assertEqual(
            self.client_for(role="reader").get("/settings/new-cluster").status_code, 403
        )

    def test_both_nodes_are_shown_before_anything_is_queued(self) -> None:
        response = self.post(self.client_for(), "/settings/new-cluster", **self.creation())

        self.assertEqual(response.status_code, 200, response.text)
        self.assertIn("gamma-a.example.com", response.text)
        self.assertIn("lb-gamma-b.example.com", response.text)
        self.assertIn(node_enrollment.fingerprint(key(1)), response.text)
        self.assertIn("Type gamma to create it", response.text)
        self.assertEqual(self.queued, [])

    def test_the_id_typed_back_queues_the_request(self) -> None:
        response = self.post(
            self.client_for(), "/settings/new-cluster", **self.creation(confirm="gamma")
        )

        self.assertEqual(response.status_code, 303, response.text)
        self.assertEqual(response.headers["location"], "/jobs")
        (queued,) = self.queued
        self.assertEqual((queued["operation"], queued["cluster"]), ("cluster_define", "gamma"))
        self.assertEqual(
            queued["payload"],
            {
                "action": "add",
                "display_name": "Gamma",
                "vip": "198.51.100.30",
                "node_path": "gamma",
                "default_certificate": "demo.example.pem",
                "blocks": [block("gamma", "gamma-a"), block("gamma", "gamma-b")],
                "hosts": ["gamma-a.example.com", "lb-gamma-b.example.com"],
                "address_prefix": 24,
            },
        )

    def test_what_the_engine_refuses_is_said_on_the_page(self) -> None:
        for fields, message in (
            ({"cluster": "edge-demo"}, "already a cluster edge-demo"),
            ({"default_certificate": "elsewhere.pem"}, "from the registry"),
            ({"block_2": block("service-demo", "gamma-b")}, "was made for &#39;service-demo&#39;"),
            ({"block_2": block("gamma", "gamma-a")}, "must be two nodes"),
            ({"vip": "not-an-address"}, "must be an IP address"),
            ({"address_prefix": "40"}, "does not fit the VIP"),
            ({"block_1": "hello"}, "not an enrollment block"),
        ):
            with self.subTest(fields=fields):
                response = self.post(
                    self.client_for(), "/settings/new-cluster", **self.creation(**fields)
                )
                self.assertEqual(response.status_code, 400)
                self.assertIn(message, response.text)
        self.assertEqual(self.queued, [])

    def test_a_wrong_id_queues_nothing(self) -> None:
        response = self.post(
            self.client_for(), "/settings/new-cluster", **self.creation(confirm="gamm")
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.queued, [])


class RemovingACluster(ClusterPage):
    def test_it_is_asked_for_and_then_queued(self) -> None:
        client = self.client_for()
        self.assertIn(
            "/settings/nodes/service-demo/remove-cluster",
            client.get("/settings/nodes/service-demo").text,
        )

        asked = self.post(client, "/settings/nodes/service-demo/remove-cluster")
        self.assertIn("Type service-demo to remove it", asked.text)
        self.assertIn("keep serving the VIP", asked.text)
        self.assertEqual(self.queued, [])

        response = self.post(
            client, "/settings/nodes/service-demo/remove-cluster", confirm="service-demo"
        )
        self.assertEqual(response.status_code, 303, response.text)
        (queued,) = self.queued
        self.assertEqual(
            (queued["operation"], queued["cluster"], queued["payload"]),
            ("cluster_define", "service-demo", {"action": "remove"}),
        )

    def test_the_last_cluster_is_not_offered_and_is_refused(self) -> None:
        patch = mock.patch("haproxy_ui.db.cluster_list", return_value=("service-demo",))
        patch.start()
        self.addCleanup(patch.stop)
        client = self.client_for()

        self.assertNotIn("remove-cluster", client.get("/settings/nodes/service-demo").text)
        response = self.post(client, "/settings/nodes/service-demo/remove-cluster")
        self.assertEqual(response.status_code, 400)
        self.assertIn("at least one cluster", response.text)


class ARemovedClusterLeavesThePages(NodesPage):
    """Review 2026-09-30 F1: with the list from the cluster file, a removed cluster's cache is not drawn."""

    def test_the_cluster_file_s_list_decides_what_the_dashboard_draws(self) -> None:
        patch = mock.patch("haproxy_ui.db.cluster_list", return_value=("service-demo",))
        patch.start()
        self.addCleanup(patch.stop)

        page = self.client_for().get("/").text

        self.assertIn("service-demo", page)
        self.assertNotIn("edge-demo", page)
        self.assertNotIn("Not configured", page)

    def test_with_the_list_from_ui_toml_the_old_card_stays(self) -> None:
        self.account = replace(self.account, role="admin")
        client = self.client(replace(configuration(), clusters=("service-demo",)))
        self.sign_in(client)

        page = client.get("/").text

        self.assertIn("Not configured", page)
