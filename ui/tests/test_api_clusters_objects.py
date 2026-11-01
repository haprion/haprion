"""The API's cluster and object reads (B416): what the dashboard and the Proxies page show, as JSON."""

from __future__ import annotations

import json
import unittest
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any
from unittest import mock

from haprion_ui import attention, demo, server_card
from haprion_ui.api import objects as api_objects
from haprion_ui.db import ProxyDraft
from haprion_ui.server_card import Cell
from tests.test_api import ApiTestCase

#
# The demo fixture is what the pages are tested against; its names are turned
# into the ones the API's tests use, so the two cannot drift into describing
# different installations.
#
RENAMED = (
    ("edge-demo", "alpha"),
    ("service-demo", "beta"),
    ("edge-a", "node-a"),
    ("edge-b", "node-b"),
    ("service-a", "node-c"),
    ("service-b", "node-d"),
    ("demo.example", "example.com"),
)


def renamed(rows: Any) -> list[Any]:
    out = []
    for row in rows:
        text = json.dumps(row.result)
        for old, new in RENAMED:
            text = text.replace(old, new)
        cluster = dict(RENAMED).get(row.cluster, row.cluster)
        out.append(replace(row, cluster=cluster, result=json.loads(text)))
    return out


class ReadingTestCase(ApiTestCase):
    def setUp(self) -> None:
        super().setUp()
        for name, rows in (
            ("cluster_statuses", demo.status_rows),
            ("cluster_inventories", demo.inventory_rows),
            ("cluster_objects", demo.object_rows),
            ("cluster_histories", demo.history_rows),
            ("cluster_networks", demo.network_rows),
        ):
            patch = mock.patch(
                f"haprion_ui.db.{name}", side_effect=lambda *_a, rows=rows, **_k: renamed(rows())
            )
            patch.start()
            self.addCleanup(patch.stop)

    def get(
        self, path: str, *, scope: list[str] | None = None, level: str = "read", **query: Any
    ) -> Any:
        secret = self.issue(clusters=scope or [], level=level)
        return self.api().get(
            "/api/v1" + path, params=query, headers={"Authorization": f"Bearer {secret}"}
        )

    def result(
        self, path: str, *, scope: list[str] | None = None, level: str = "read", **query: Any
    ) -> Any:
        response = self.get(path, scope=scope, level=level, **query)
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()["result"]

    def assert_not_found(self, path: str, *, scope: list[str] | None = None) -> None:
        response = self.get(path, scope=scope)
        self.assertEqual(response.status_code, 404, path)
        self.assertEqual(response.json()["error"]["code"], "not_found")


class TheClusters(ReadingTestCase):
    def test_a_cluster_is_answered_as_the_dashboard_shows_it(self) -> None:
        result = self.result("/clusters/beta")

        result.pop("observed_at")
        message = result["attention"][0]["message"]
        self.assertEqual(
            result,
            {
                "name": "beta",
                "status": {
                    "label": "Behind",
                    "tone": "warning",
                    "detail": "1 node is not running the published version",
                },
                "fresh": True,
                "published_version": 24,
                "release_state": "behind",
                "vip_holder": "node-c",
                "vip_count": 1,
                "nodes": [
                    {
                        "name": "node-c",
                        "state": "Online",
                        "tone": "healthy",
                        "detail": "Serving and reporting normally",
                        "holds_vip": True,
                        "release_version": 24,
                        "on_published_version": True,
                        "haproxy_version": "3.2",
                        "node_package_version": demo.NODE_PACKAGE,
                    },
                    {
                        "name": "node-d",
                        "state": "Behind",
                        "tone": "warning",
                        "detail": "Node is not on the published version",
                        "holds_vip": False,
                        "release_version": 23,
                        "on_published_version": False,
                        "haproxy_version": "3.2",
                        "node_package_version": demo.OLDER_NODE_PACKAGE,
                    },
                ],
                "attention": [
                    {
                        "kind": "node_package",
                        "severity": "warning",
                        "cluster": "beta",
                        "subject": "node-d",
                        "message": message,
                        "since": None,
                        "variant": "",
                    }
                ],
            },
        )
        self.assertIn("haprion-node 0.99.5", message)

    def test_the_time_of_the_reading_is_iso_8601_with_its_offset(self) -> None:
        rows = renamed(demo.status_rows())
        with mock.patch("haprion_ui.db.cluster_statuses", return_value=rows):
            result = self.result("/clusters/alpha")

        self.assertEqual(result["observed_at"], rows[0].observed_at.astimezone(UTC).isoformat())
        self.assertTrue(result["observed_at"].endswith("+00:00"))

    def test_the_list_has_each_cluster_with_its_own_attention_only(self) -> None:
        clusters = self.result("/clusters")["clusters"]

        self.assertEqual([entry["name"] for entry in clusters], ["alpha", "beta"])
        self.assertEqual(
            [(item["kind"], item["subject"]) for item in clusters[0]["attention"]],
            [("forwarding", "node-a → loki")],
        )
        self.assertEqual([item["subject"] for item in clusters[1]["attention"]], ["node-d"])
        self.assertEqual(clusters[0]["vip_holder"], "node-a")
        self.assertEqual(
            [(node["name"], node["holds_vip"]) for node in clusters[0]["nodes"]],
            [("node-a", True), ("node-b", False)],
        )

    def test_a_reading_older_than_two_polls_is_not_fresh(self) -> None:
        old = renamed(demo.status_rows(datetime(2026, 1, 1, tzinfo=UTC)))
        with mock.patch("haprion_ui.db.cluster_statuses", return_value=old):
            result = self.result("/clusters/alpha")

        self.assertFalse(result["fresh"])
        self.assertEqual(result["observed_at"], old[0].observed_at.astimezone(UTC).isoformat())

    def test_a_cluster_never_read_has_no_nodes_and_no_time(self) -> None:
        with mock.patch("haprion_ui.db.cluster_statuses", return_value=[]):
            result = self.result("/clusters/alpha")

        self.assertEqual(
            (result["fresh"], result["observed_at"], result["nodes"]), (False, None, [])
        )
        self.assertIsNone(result["published_version"])
        self.assertIsNone(result["vip_holder"])

    def test_a_token_limited_to_beta_sees_beta_and_gets_the_same_404_for_the_rest(self) -> None:
        listed = self.result("/clusters", scope=["beta"])
        self.assertEqual([entry["name"] for entry in listed["clusters"]], ["beta"])
        self.assert_not_found("/clusters/alpha", scope=["beta"])
        refused = self.get("/clusters/alpha", scope=["beta"]).json()["error"]
        unknown = self.get("/clusters/gamma").json()["error"]
        self.assertEqual(refused, unknown)

    def test_a_cluster_removed_between_the_two_readings_is_a_404_not_a_500(self) -> None:
        with mock.patch("haprion_ui.api.clusters.cluster_entries", return_value=[]):
            self.assert_not_found("/clusters/alpha")


class TheAttentionList(ReadingTestCase):
    WHEN = datetime(2026, 10, 31, 9, 30, tzinfo=UTC)

    def setUp(self) -> None:
        super().setUp()
        items = (
            attention.Item(
                "certificate",
                "critical",
                None,
                "web",
                "expires in 3 days",
                self.WHEN,
                "/certificates?view=registry",
            ),
            attention.Item("node", "warning", "alpha", "node-a", "behind", None, "/", "Behind"),
            attention.Item("node", "warning", "beta", "node-c", "behind", None, "/"),
        )
        shown = attention.Attention(self.WHEN, items, {}, True)
        patch = mock.patch("haprion_ui.api.clusters.attention_items", return_value=shown)
        patch.start()
        self.addCleanup(patch.stop)

    def test_an_unlimited_token_gets_the_dashboards_list_with_the_installations_rows(self) -> None:
        body = self.get("/attention").json()

        self.assertEqual((body["operation"], body["cluster"]), ("attention_list", None))
        self.assertEqual(
            body["result"]["items"][0],
            {
                "kind": "certificate",
                "severity": "critical",
                "cluster": None,
                "subject": "web",
                "message": "expires in 3 days",
                "since": "2026-10-31T09:30:00+00:00",
                "variant": "",
            },
        )
        self.assertEqual(
            [(i["cluster"], i["subject"], i["variant"]) for i in body["result"]["items"]],
            [(None, "web", ""), ("alpha", "node-a", "Behind"), ("beta", "node-c", "")],
        )

    def test_a_limited_token_gets_its_clusters_rows_and_none_of_the_installations(self) -> None:
        items = self.result("/attention", scope=["beta"])["items"]
        self.assertEqual([(i["cluster"], i["subject"]) for i in items], [("beta", "node-c")])

    def test_it_says_when_the_readings_behind_it_are_old(self) -> None:
        # Review 26-11-01, c-P3-4: a cluster never read gives no row; `fresh` is how a monitor knows.
        shown = attention.Attention(self.WHEN, (), {"alpha": 20, "beta": None}, False)
        with mock.patch("haprion_ui.api.clusters.attention_items", return_value=shown):
            everyone = self.result("/attention")
            alpha = self.result("/attention", scope=["alpha"])
            beta = self.result("/attention", scope=["beta"])
        self.assertEqual(
            (everyone["fresh"], everyone["generated_at"]), (False, "2026-10-31T09:30:00+00:00")
        )
        self.assertTrue(alpha["fresh"])
        self.assertFalse(beta["fresh"])


class TheObjectList(ReadingTestCase):
    def test_the_objects_are_the_proxies_pages_rows(self) -> None:
        result = self.result("/clusters/alpha/objects")

        self.assertEqual(
            {key: result[key] for key in ("total", "offset", "limit", "truncated")},
            {"total": 4, "offset": 0, "limit": 200, "truncated": False},
        )
        self.assertEqual(
            [(o["name"], o["managed"], o["state"]) for o in result["objects"]],
            [
                ("metrics", False, "serving"),
                ("public-web", True, "serving"),
                ("shop", True, "inactive"),
                ("staging", True, "unreadable"),
            ],
        )
        web = result["objects"][1]
        self.assertEqual(
            web,
            {
                "name": "public-web",
                "managed": True,
                "protocol": "https",
                "state": "serving",
                "serving": True,
                "readable": True,
                "problem": None,
                "hostnames": ["app.example.com", "www.example.com"],
                "ports": [443],
                "servers": [],
                "backend_count": None,
                "redirect_http": None,
                "vip": {"name": "public", "address": "192.0.2.20", "is_default": True},
                "source_address": "192.0.2.25",
                "health": {
                    "tone": "healthy",
                    "label": "2/2 up",
                    "detail": web["health"]["detail"],
                    "up": 2,
                    "total": 2,
                },
                "draft": None,
                "publishing": None,
                "publish_refused": None,
            },
        )
        self.assertIn("1 drained or in maintenance", web["health"]["detail"])
        staging = result["objects"][3]
        # The engine's sentence can quote the document, which a reader is not given.
        self.assertFalse(staging["readable"])
        self.assertIsNone(staging["problem"])
        unmanaged = result["objects"][0]
        self.assertEqual((unmanaged["ports"], unmanaged["backend_count"]), ([80], 1))

    def test_the_engines_sentence_on_an_unreadable_object_is_for_write_tokens(self) -> None:
        written = self.result("/clusters/alpha/objects", level="write")["objects"]
        staging = next(o for o in written if o["name"] == "staging")
        self.assertEqual(staging["problem"], "staging.routes is required for an http object")

    def test_a_list_cut_by_its_limit_says_so_and_continues_at_the_offset(self) -> None:
        first = self.result("/clusters/alpha/objects", limit=3)
        self.assertEqual(
            ([o["name"] for o in first["objects"]], first["truncated"], first["total"]),
            (["metrics", "public-web", "shop"], True, 4),
        )
        rest = self.result("/clusters/alpha/objects", limit=3, offset=3)
        self.assertEqual(
            ([o["name"] for o in rest["objects"]], rest["truncated"]), (["staging"], False)
        )

    def test_a_limit_outside_its_bounds_is_refused_as_bad_input(self) -> None:
        queries: list[dict[str, Any]] = [
            {"limit": 0},
            {"limit": api_objects.OBJECT_LIMIT_MAX + 1},
            {"offset": -1},
        ]
        for query in queries:
            with self.subTest(query=query):
                response = self.get("/clusters/alpha/objects", **query)
                self.assertEqual(response.status_code, 400)
                self.assertEqual(response.json()["error"]["code"], "bad_input")

    def test_a_cluster_with_no_object_has_an_empty_list(self) -> None:
        with (
            mock.patch("haprion_ui.db.cluster_objects", return_value=[]),
            mock.patch("haprion_ui.db.cluster_inventories", return_value=[]),
        ):
            result = self.result("/clusters/alpha/objects")

        self.assertEqual((result["objects"], result["total"], result["truncated"]), ([], 0, False))

    def test_work_that_is_not_released_is_listed_with_its_stage(self) -> None:
        when = datetime(2026, 10, 30, 9, 0, tzinfo=UTC)
        drafts = [
            ProxyDraft(
                cluster="alpha",
                object_id=name,
                yaml="schema: 1\n",
                base_version=None,
                base_hash="",
                revision=1,
                updated_by="operator",
                updated_at=when,
                deleted=deleted,
                stage=stage,
            )
            for name, stage, deleted in (("blog", "draft", False), ("shop", "saved", True))
        ]
        with mock.patch("haprion_ui.db.cluster_drafts", return_value=drafts):
            listed = self.result("/clusters/alpha/objects", level="write")["objects"]
            read = self.result("/clusters/alpha/objects")["objects"]
        objects = {o["name"]: o for o in listed}

        # A reader is shown no drafts; a `read` token neither (B416).
        self.assertNotIn("blog", {o["name"] for o in read})
        self.assertEqual({o["draft"] for o in read if o["name"] == "shop"}, {None})

        self.assertEqual(objects["blog"]["state"], "draft")
        self.assertEqual(
            objects["blog"]["draft"],
            {
                "stage": "draft",
                "removal": False,
                "replaces": None,
                "updated_by": "operator",
                "updated_at": when.isoformat(),
            },
        )
        # A stored object keeps what the nodes do with it; the draft is beside it.
        self.assertEqual(objects["shop"]["state"], "inactive")
        self.assertEqual(
            (objects["shop"]["draft"]["stage"], objects["shop"]["draft"]["removal"]),
            ("saved", True),
        )
        self.assertNotIn("schema: 1", json.dumps(objects["blog"]))

    def test_a_token_for_another_cluster_gets_the_answer_for_a_cluster_that_is_not_there(
        self,
    ) -> None:
        self.assert_not_found("/clusters/alpha/objects", scope=["beta"])
        self.assert_not_found("/clusters/gamma/objects")
        self.assertEqual(
            self.get("/clusters/alpha/objects", scope=["beta"]).json()["error"],
            self.get("/clusters/gamma/objects").json()["error"],
        )


class TheObject(ReadingTestCase):
    def test_an_object_has_its_listing_fields_its_document_and_its_servers_states(self) -> None:
        result = self.result("/clusters/alpha/objects/public-web", level="write")

        listed = next(
            o
            for o in self.result("/clusters/alpha/objects", level="write")["objects"]
            if o["name"] == "public-web"
        )
        self.assertEqual({key: result[key] for key in listed}, listed)
        self.assertEqual(
            result["document"], renamed(demo.object_rows())[0].result["objects"][0]["document"]
        )
        self.assertEqual(result["definition"]["listen"]["protocol"], "https")
        self.assertEqual(
            result["publication"],
            {
                "label": "Serving",
                "detail": "v24 is published and the nodes are on it",
                "tone": "healthy",
                "version": "v24",
            },
        )
        self.assertEqual(result["commit"], f"{24:040d}")
        self.assertFalse(result["stale"])
        states = result["server_states"]
        self.assertTrue(states["current"])
        self.assertEqual(
            [(s["pool"], s["address"], s["sessions"]) for s in states["servers"]],
            [
                ("web", "192.0.2.10:8080", 14),
                ("web", "192.0.2.11:8080", 12),
                ("web", "192.0.2.12:8080", 3),
            ],
        )
        self.assertEqual(
            states["servers"][2]["nodes"],
            [
                {
                    "node": node,
                    "state": "drain",
                    "lost": False,
                    "check": "unknown",
                    "label": "DRAIN",
                    "tone": "warning",
                    "detail": "Check: DRAIN",
                }
                for node in ("node-a", "node-b")
            ],
        )
        # The standby node does not check a server that leaves from the VIP's own address.
        self.assertEqual(
            [(n["node"], n["state"], n["label"]) for n in states["servers"][0]["nodes"]],
            [("node-a", "ready", "UP"), ("node-b", "ready", "STANDBY")],
        )

    def test_an_object_that_cannot_be_read_has_its_document_and_no_states(self) -> None:
        result = self.result("/clusters/alpha/objects/staging", level="write")

        self.assertEqual((result["state"], result["readable"]), ("unreadable", False))
        self.assertIn("protocol: https", result["document"])
        self.assertIsNone(result["server_states"])

    def test_a_read_token_is_shown_the_object_but_not_its_document(self) -> None:
        """B416: `read` sees what a reader sees, and the document is an admin's (B68)."""

        result = self.result("/clusters/alpha/objects/public-web")

        self.assertEqual(
            (result["name"], result["document"], result["definition"]), ("public-web", None, None)
        )

    def test_a_read_token_is_not_given_the_backend_addresses_either(self) -> None:
        """The servers' states name every address behind a site, as the document does (B68)."""

        web = self.result("/clusters/alpha/objects/public-web")
        self.assertIsNone(web["server_states"])
        # The lamp is the reader's level and stays.
        self.assertEqual(web["health"]["total"], 2)
        self.assertNotIn("192.0.2.10", json.dumps(web))
        self.assertIsNotNone(
            self.result("/clusters/alpha/objects/public-web", level="write")["server_states"]
        )

    def test_the_engines_sentence_is_given_to_write_tokens_only(self) -> None:
        read = self.result("/clusters/alpha/objects/staging")
        self.assertEqual(
            (read["state"], read["readable"], read["problem"]), ("unreadable", False, None)
        )
        write = self.result("/clusters/alpha/objects/staging", level="write")
        self.assertEqual(write["problem"], "staging.routes is required for an http object")

    def test_a_servers_check_is_a_code_beside_the_pages_word(self) -> None:
        servers = self.result("/clusters/alpha/objects/public-web", level="write")["server_states"][
            "servers"
        ]
        nodes = [(n["label"], n["check"]) for s in servers for n in s["nodes"]]
        self.assertIn(("UP", "up"), nodes)
        self.assertIn(("STANDBY", "standby"), nodes)
        self.assertIn(("DRAIN", "unknown"), nodes)

    def test_a_proxy_the_platform_did_not_write_has_no_document(self) -> None:
        result = self.result("/clusters/alpha/objects/metrics")

        self.assertEqual(
            (result["managed"], result["document"], result["definition"]), (False, None, None)
        )
        self.assertIsNone(result["server_states"])

    def test_an_object_waiting_for_the_nodes_says_so(self) -> None:
        result = self.result("/clusters/alpha/objects/shop", level="write")

        self.assertEqual((result["state"], result["serving"]), ("inactive", False))
        self.assertIsNotNone(result["document"])

    def test_a_name_nobody_has_is_a_404_and_so_is_one_outside_the_token(self) -> None:
        self.assert_not_found("/clusters/alpha/objects/nothing-here")
        self.assert_not_found("/clusters/alpha/objects/public-web", scope=["beta"])
        self.assert_not_found("/clusters/gamma/objects/public-web")

    def test_a_token_limited_to_objects_is_held_to_them(self) -> None:
        secret = self.issue(clusters=["alpha"], objects=["shop"])
        response = self.api().get(
            "/api/v1/clusters/alpha/objects/public-web",
            headers={"Authorization": f"Bearer {secret}"},
        )
        self.assertEqual(response.status_code, 404)

    def test_a_document_is_given_as_json_even_where_yaml_reads_a_date(self) -> None:
        self.assertEqual(
            api_objects._plain({"on": datetime(2026, 10, 31, tzinfo=UTC), "n": [1, None, "a"]}),
            {"on": "2026-10-31T00:00:00+00:00", "n": [1, None, "a"]},
        )

    def test_the_check_code_is_read_from_what_the_node_reported(self) -> None:
        cases = {
            "UP": "up",
            "UP 2/3": "up",
            "DOWN": "down",
            "DOWN 1/3": "down",
            "no check": "no_check",
            "NOLB": "unknown",
            "": "unknown",
        }
        for status, expected in cases.items():
            with self.subTest(status=status):
                member = mock.Mock(status=status, held=False)
                self.assertEqual(server_card.cell(member).check, expected)
        self.assertEqual(server_card.cell(None).check, "unknown")
        self.assertEqual(
            server_card.cell(mock.Mock(status="UP", held=False), standby=True).check, "standby"
        )

    def test_what_a_node_says_of_a_server_is_ready_drain_or_maintenance(self) -> None:
        cases = {
            Cell("UP", "healthy"): ("ready", False),
            Cell("DOWN", "critical"): ("ready", False),
            Cell("STANDBY", "unknown"): ("ready", False),
            Cell("DRAIN", "warning"): ("drain", False),
            Cell("MAINT", "unknown"): ("maintenance", False),
            Cell("DRAIN LOST", "critical"): ("drain", True),
            Cell("MAINT LOST", "critical"): ("maintenance", True),
            Cell("—", "unknown"): ("unknown", False),
        }
        for cell, expected in cases.items():
            with self.subTest(cell=cell.label):
                self.assertEqual(api_objects._state_of(cell), expected)


class TheHistory(ReadingTestCase):
    def test_the_versions_are_the_history_pages_newest_first(self) -> None:
        result = self.result("/clusters/alpha/objects/public-web/history")

        self.assertEqual(
            {key: result[key] for key in ("published_version", "total", "limit", "truncated")},
            {"published_version": 24, "total": 24, "limit": 50, "truncated": False},
        )
        self.assertEqual(
            result["versions"][:2],
            [
                {
                    "version": 24,
                    "saved_by": None,
                    "saved_at": "2026-08-19T09:14:00+00:00",
                    "comment": "Shorten the health check interval",
                    "published": True,
                    "current": True,
                },
                {
                    "version": 23,
                    "saved_by": None,
                    "saved_at": "2026-08-18T09:13:00+00:00",
                    "comment": "Move the metrics frontend off the shared port",
                    "published": False,
                    "current": False,
                },
            ],
        )
        self.assertEqual(len(result["versions"]), 5)

    def test_who_saved_a_version_is_named_where_the_engine_recorded_it(self) -> None:
        rows = renamed(demo.history_rows())
        rows[0].result["versions"][0]["requested_by"] = "operator"
        rows[0].result["versions"][1]["comment"] = ""
        with mock.patch("haprion_ui.db.cluster_histories", return_value=rows):
            versions = self.result("/clusters/alpha/objects/public-web/history")["versions"]

        self.assertEqual(versions[0]["saved_by"], "operator")
        self.assertEqual(versions[1]["comment"], "")

    def test_a_history_cut_by_its_limit_says_so(self) -> None:
        result = self.result("/clusters/alpha/objects/public-web/history", limit=2)

        self.assertEqual(
            ([v["version"] for v in result["versions"]], result["truncated"]), ([24, 23], True)
        )

    def test_a_cluster_whose_versions_were_not_read_has_none(self) -> None:
        with mock.patch("haprion_ui.db.cluster_histories", return_value=[]):
            result = self.result("/clusters/alpha/objects/public-web/history")

        self.assertEqual(
            (result["versions"], result["published_version"], result["total"]), ([], None, 0)
        )

    def test_an_object_outside_the_token_or_not_there_is_a_404(self) -> None:
        self.assert_not_found("/clusters/alpha/objects/public-web/history", scope=["beta"])
        self.assert_not_found("/clusters/alpha/objects/nothing-here/history")


if __name__ == "__main__":
    unittest.main()
