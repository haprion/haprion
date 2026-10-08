"""What is saved is published from Versions, together, as one version (B257)."""

from __future__ import annotations

import re
import unittest
from dataclasses import replace
from types import SimpleNamespace
from typing import Any
from unittest import mock
from uuid import UUID, uuid4

from haproxy_ui import auth, db
from tests.test_editor_page import COMMIT, OBSERVED, SHOP, EditorTestCase
from tests.test_saved_changes import WIDER, saved

LATER = "b" * 40


def row(object_id: str = "shop", **overrides: Any) -> db.ProxyDraft:
    values: dict[str, Any] = {
        "cluster": "alpha",
        "object_id": object_id,
        "yaml": SHOP.replace("shop", object_id),
        "base_version": 12,
        "base_hash": COMMIT,
        "revision": 3,
        "updated_by": "operator",
        "updated_at": OBSERVED,
        "deleted": False,
        "id": UUID("11111111-1111-4111-8111-111111111111"),
        "stage": "saved",
    }
    values.update(overrides)
    return db.ProxyDraft(**values)


class VersionsPublishesWhatIsSaved(EditorTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.rows: list[db.ProxyDraft] = []
        self.cluster_changes: dict[str, Any] = {}
        self.queued: list[dict[str, Any]] = []
        for target, effect in (
            ("cluster_drafts", lambda _c, _cluster: list(self.rows)),
            ("cluster_changes", lambda _c, _cluster: dict(self.cluster_changes)),
            ("queue_job", self._queue),
        ):
            patch = mock.patch(f"haproxy_ui.db.{target}", side_effect=effect)
            patch.start()
            self.addCleanup(patch.stop)

    def _queue(self, _c: object, **values: Any) -> Any:
        self.queued.append(values)
        return SimpleNamespace(id=9, request_id=uuid4())

    def page(self, client: Any) -> str:
        return str(client.get("/history").text)

    def publish(self, client: Any, **fields: Any) -> Any:
        data = {
            auth.CSRF_FIELD: self.token(client),
            "expected_head": COMMIT,
            "comment": "Move the shop",
        }
        data.update(fields)
        return client.post("/history/alpha/publish", data=data, follow_redirects=False)

    def test_saved_changes_are_listed_and_drafts_are_not(self) -> None:
        self.rows = [row(), row("console", stage="draft")]
        self.cluster_changes = {"network": saved("network", WIDER, cluster="alpha")}

        text = self.page(self.editor())

        self.assertIn("Pending changes", text)
        self.assertIn("<strong>shop</strong>", text)
        self.assertIn("Network description", text)
        self.assertNotIn("<strong>console</strong>", text)
        self.assertIn(">Publish 2 changes</button>", text)

    def test_nothing_saved_draws_no_list(self) -> None:
        self.assertNotIn("Pending changes", self.page(self.editor()))

    def test_one_publish_carries_objects_network_and_settings(self) -> None:
        self.rows = [row(), row("staging", deleted=True, yaml=SHOP, id=uuid4(), revision=1)]
        self.cluster_changes = {
            "network": saved("network", WIDER, cluster="alpha"),
            "settings": saved("settings", "metrics: null\n", cluster="alpha", revision=4),
        }
        client = self.editor()

        answer = self.publish(client)

        self.assertEqual(
            (answer.status_code, answer.headers["location"]), (303, "/history?published=alpha")
        )
        (job,) = self.queued
        self.assertEqual((job["operation"], job["cluster"]), ("changes_publish", "alpha"))
        payload = job["payload"]
        self.assertEqual(sorted(payload["objects"]), ["shop", "staging"])
        self.assertIsNone(payload["objects"]["staging"])
        self.assertEqual(payload["network"], WIDER)
        self.assertEqual(payload["settings"], "metrics: null\n")
        self.assertEqual(payload["comment"], "Move the shop")
        self.assertEqual(payload["expected_head"], COMMIT)
        self.assertEqual(payload["requested_by"], "operator")
        self.assertEqual(len(payload["drafts"]), 2)
        self.assertEqual([entry["revision"] for entry in payload["changes"]], [2, 4])

    def test_a_saved_rename_removes_the_name_it_replaces(self) -> None:
        self.rows = [row("bazaar", replaces="shop")]

        self.publish(self.editor())

        objects = self.queued[0]["payload"]["objects"]
        self.assertEqual(sorted(objects), ["bazaar", "shop"])
        self.assertIsNone(objects["shop"])

    def test_a_renamed_pool_travels_with_the_publish(self) -> None:
        """B250/B253: the card under the new name keeps the old one's history."""

        self.rows = [
            row(
                yaml=SHOP.replace("  web:", "  shop-front:").replace(
                    "backend: web", "backend: shop-front"
                )
            )
        ]

        self.publish(self.editor())

        renames = self.queued[0]["payload"]["backend_renames"]
        self.assertIn("shop-front", renames["introduced"])

    def test_a_row_saved_against_an_older_version_holds_the_package(self) -> None:
        self.rows = [row(base_hash=LATER)]
        client = self.editor()

        text = self.page(client)
        answer = self.publish(client)

        self.assertIn("Saved against an older version", text)
        self.assertIn("shop was saved against an older version", text)
        self.assertNotIn(">Publish 1 change</button>", text)
        self.assertEqual(answer.status_code, 400)
        self.assertEqual(self.queued, [])

    def test_more_objects_than_one_publish_carries_are_refused(self) -> None:
        self.rows = [row(f"site-{index}", id=uuid4()) for index in range(65)]

        answer = self.publish(self.editor())

        self.assertEqual(answer.status_code, 400)
        self.assertIn("65 objects; at most 64", answer.text)

    def test_a_comment_is_needed(self) -> None:
        self.rows = [row()]

        answer = self.publish(self.editor(), comment="  ")

        self.assertEqual(answer.status_code, 400)
        self.assertIn("A comment is needed", answer.text)
        self.assertEqual(self.queued, [])

    def test_a_page_drawn_at_an_older_version_is_read_again(self) -> None:
        self.rows = [row()]

        answer = self.publish(self.editor(), expected_head=LATER)

        self.assertEqual(answer.status_code, 400)
        self.assertIn("A newer version was recorded", answer.text)

    def test_the_same_publish_asked_twice_carries_one_key(self) -> None:
        self.rows = [row()]
        client = self.editor()

        self.publish(client)
        self.publish(client)

        self.assertEqual(self.queued[0]["idempotency_key"], self.queued[1]["idempotency_key"])

    def test_a_busy_cluster_says_so_and_queues_nothing_else(self) -> None:
        self.rows = [row()]

        def busy(_c: object, **_values: Any) -> Any:
            raise db.ClusterBusy("alpha")

        with mock.patch("haproxy_ui.db.queue_job", side_effect=busy):
            answer = self.publish(self.editor())

        self.assertIn("already running a job", answer.text)

    def test_nothing_saved_is_nothing_to_publish(self) -> None:
        answer = self.publish(self.editor())

        self.assertEqual(answer.status_code, 400)
        self.assertIn("Nothing is saved to publish", answer.text)

    def test_a_reader_sees_no_list_and_may_not_publish(self) -> None:
        self.rows = [row()]
        self.account = replace(self.account, role="reader")
        client = self.editor()

        self.assertNotIn("Pending changes", self.page(client))
        self.assertEqual(self.publish(client).status_code, 403)
        self.assertEqual(self.queued, [])


class TheMenuPutsVersionsSecond(EditorTestCase):
    def test_dashboard_then_versions_then_proxies(self) -> None:
        nav = self.editor().get("/").text.split('class="primary-nav"', 1)[1].split("</nav>", 1)[0]

        self.assertEqual(re.findall(r'href="(/[a-z]*)"', nav)[:3], ["/", "/history", "/proxies"])


if __name__ == "__main__":
    unittest.main()
