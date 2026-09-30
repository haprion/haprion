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
