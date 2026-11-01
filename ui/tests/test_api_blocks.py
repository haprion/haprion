"""`GET /api/v1/clusters/{cluster}/objects/{name}/blocks`: the object page's Blocked card as JSON."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest import mock

from haprion_ui.db import ClusterObjects, ClusterStatus
from tests.test_api import ApiTestCase

SHOP = """
schema: 1
name: shop
hostnames: [shop.example.com]
listen:
  protocol: http
routes:
  - path: /
    backend: web
backends:
  web:
    balance: roundrobin
    health:
      type: disabled
    servers:
      - host: 192.0.2.10
        port: 8080
"""

BLOCKING = SHOP + "dynamic_block:\n  max_requests: 100\n  block_for: 2h\n"


def stored(*documents: tuple[str, str]) -> list[ClusterObjects]:
    return [
        ClusterObjects(
            cluster="alpha",
            observed_at=datetime.now(UTC),
            outcome="done",
            result={
                "commit": "a" * 40,
                "objects": [
                    {
                        "name": name,
                        "document": document,
                        "readable": True,
                        "problem": None,
                        "protocol": "http",
                        "hostnames": [f"{name}.example.com"],
                    }
                    for name, document in documents
                ],
            },
            warnings=[],
            error=None,
            poll_error=None,
        )
    ]


def held(count: int, *addresses: tuple[str, int]) -> dict[str, Any]:
    return {
        "count": count,
        "addresses": [{"address": address, "expires_in_ms": left} for address, left in addresses],
    }


def status(observed: datetime, *nodes: tuple[str, dict[str, Any]]) -> list[ClusterStatus]:
    return [
        ClusterStatus(
            cluster="alpha",
            observed_at=observed,
            outcome="done",
            result={"nodes": [{"name": name, "status": {"blocked": held}} for name, held in nodes]},
            warnings=[],
            error=None,
            poll_error=None,
        )
    ]


class TheBlocksOfAnObject(ApiTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.observed = datetime.now(UTC) - timedelta(minutes=1)
        self.objects = stored(("shop", BLOCKING), ("intranet", SHOP))
        self.statuses = status(
            self.observed,
            ("node-a", {"shop": held(2, ("192.0.2.10", 3_600_000), ("192.0.2.7", 1_800_000))}),
            ("node-b", {"shop": held(1, ("192.0.2.7", 2_400_000))}),
        )
        for name, rows in (
            ("cluster_objects", lambda *_a, **_k: self.objects),
            ("cluster_statuses", lambda *_a, **_k: self.statuses),
        ):
            patch = mock.patch(f"haprion_ui.db.{name}", side_effect=rows)
            patch.start()
            self.addCleanup(patch.stop)

    def get(self, secret: str, cluster: str = "alpha", name: str = "shop") -> Any:
        return self.api().get(
            f"/api/v1/clusters/{cluster}/objects/{name}/blocks",
            headers={"Authorization": f"Bearer {secret}"},
        )

    def test_the_card_as_json_with_the_time_left_and_the_nodes_holding_each(self) -> None:
        response = self.get(self.issue())
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual((body["operation"], body["cluster"]), ("object_blocks", "alpha"))
        result = body["result"]
        addresses = result.pop("addresses")
        self.assertEqual(
            result,
            {
                "object": "shop",
                "block_for": "2h",
                "count": 2,
                "truncated": False,
                "observed_at": self.observed.isoformat(),
            },
        )
        self.assertEqual(
            [(row["address"], row["nodes"], row["ending"]) for row in addresses],
            [
                ("192.0.2.7", ["node-a", "node-b"], False),
                ("192.0.2.10", ["node-a"], False),
            ],
        )
        # The longest of the nodes' times, from the reading's moment.
        self.assertEqual(addresses[0]["until"], (self.observed + timedelta(minutes=40)).isoformat())
        self.assertAlmostEqual(addresses[0]["seconds_left"], 39 * 60, delta=5)

    def test_each_address_carries_its_reason_or_null(self) -> None:
        self.statuses = status(
            self.observed,
            (
                "node-a",
                {
                    "shop": {
                        "count": 2,
                        "addresses": [
                            {"address": "192.0.2.7", "expires_in_ms": 1000, "reason": "manual"},
                            {"address": "192.0.2.10", "expires_in_ms": 1000},
                        ],
                    }
                },
            ),
        )
        addresses = self.get(self.issue()).json()["result"]["addresses"]
        self.assertEqual(
            [(row["address"], row["reason"]) for row in addresses],
            [("192.0.2.7", "manual"), ("192.0.2.10", None)],
        )

    def test_an_object_that_blocks_nothing_has_an_empty_list_and_the_default_time(self) -> None:
        body = self.get(self.issue(), name="intranet").json()
        self.assertEqual(
            body["result"],
            {
                "object": "intranet",
                "block_for": "30m",
                "count": 0,
                "addresses": [],
                "truncated": False,
                "observed_at": None,
            },
        )

    def test_a_block_that_ran_out_by_the_reading_is_ending_with_no_time_left(self) -> None:
        self.statuses = status(
            datetime.now(UTC) - timedelta(hours=1),
            ("node-a", {"shop": held(1, ("192.0.2.7", 60_000))}),
        )
        row = self.get(self.issue()).json()["result"]["addresses"][0]
        self.assertEqual((row["ending"], row["seconds_left"]), (True, 0))

    def test_more_held_than_the_nodes_listed_is_said(self) -> None:
        self.statuses = status(
            self.observed, ("node-a", {"shop": held(250, ("192.0.2.7", 600_000))})
        )
        result = self.get(self.issue()).json()["result"]
        self.assertEqual(
            (result["count"], len(result["addresses"]), result["truncated"]), (250, 1, True)
        )

    def test_an_object_or_cluster_that_is_not_there_is_a_404(self) -> None:
        secret = self.issue()
        for cluster, name in (("alpha", "nothing"), ("gamma", "shop")):
            with self.subTest(cluster=cluster, name=name):
                response = self.get(secret, cluster, name)
                self.assertEqual(response.status_code, 404)
                self.assertEqual(response.json()["error"]["code"], "not_found")

    def test_a_token_limited_to_another_cluster_gets_the_same_404(self) -> None:
        response = self.get(self.issue(clusters=["beta"]))
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json()["error"]["code"], "not_found")
        self.assertEqual(self.get(self.issue(clusters=["alpha"])).status_code, 200)
