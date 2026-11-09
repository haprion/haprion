"""Drain, maintenance, ready, deploy and the health check's test through the API (B416, release 3).

Each queued payload is held to what the page queues for the same input: the
worker and the root helpers must not be able to tell the two apart.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from typing import Any
from unittest import mock

from haprion_ui import auth, db, demo, editor_flow, job_payloads
from haprion_ui import probe as probe_module
from haprion_ui.db import ProxyDraft
from tests.test_api import ApiTestCase
from tests.test_editor_page import COMMIT, NETWORK, OBJECTS, SETTINGS, SHOP
from tests.test_login import configuration
from tests.test_queue_route import queued

KEY = "00000000-0000-4000-8000-000000000041"
HTTP_CHECK = SHOP.replace("type: disabled", "type: http\n      path: /up")
ACTOR = f"token{':'}monitoring"


class Queueing(ApiTestCase):
    """The base of the routes that queue: a fake queue and audit table, writes on."""

    cluster = "edge-demo"
    name = "public-web"

    def setUp(self) -> None:
        super().setUp()
        self.jobs: list[dict[str, Any]] = []
        self.audited: list[dict[str, Any]] = []

        def queue(_c: object, **fields: Any) -> db.Job:
            self.jobs.append(fields)
            return queued(operation=fields["operation"], cluster=fields["cluster"])

        def audit(_c: object, **fields: Any) -> None:
            self.audited.append(fields)

        for patch in (
            mock.patch("haprion_ui.db.queue_job", side_effect=queue),
            mock.patch("haprion_ui.db.record_audit_event", side_effect=audit),
            mock.patch("haprion_ui.db.recent_jobs", return_value=[]),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def writing(self, *, writes: bool = True) -> Any:
        return self.client(
            replace(
                configuration(),
                demo_fixture=True,
                management_writes=writes,
                clusters=demo.CLUSTERS,
            )
        )

    def post(
        self,
        path: str,
        body: Any = None,
        *,
        level: str = "write",
        scope: list[str] | None = None,
        key: str | None = KEY,
        writes: bool = True,
        objects: list[str] | None = None,
    ) -> Any:
        secret = self.issue(level=level, clusters=scope or [], objects=objects or [])
        headers = {"Authorization": f"Bearer {secret}"}
        if key is not None:
            headers["Idempotency-Key"] = key
        return self.writing(writes=writes).post("/api/v1" + path, json=body, headers=headers)


class TheServerStates(Queueing):
    def path(self, cluster: str | None = None, name: str | None = None) -> str:
        return f"/clusters/{cluster or self.cluster}/objects/{name or self.name}/servers"

    def page_queues(self, **form: Any) -> dict[str, Any]:
        """What the object page queues for the same buttons."""

        client = self.writing()
        self.sign_in(client)
        fields: dict[str, Any] = {
            "idempotency_key": KEY,
            auth.CSRF_FIELD: auth.csrf_token(client.cookies[auth.SESSION_COOKIE]),
            **form,
        }
        client.post(
            f"/proxies/{self.cluster}/{self.name}/servers", data=fields, follow_redirects=False
        )
        (job,) = self.jobs
        self.jobs.clear()
        self.audited.clear()
        return job

    def test_202_and_the_page_s_own_payload(self) -> None:
        listed = ["web/192.0.2.10:8080", "web/192.0.2.12:8080", "web/192.0.2.10:8080"]
        page = self.page_queues(state="maint", server=listed)
        response = self.post(self.path(), {"servers": listed, "state": "maintenance"})
        self.assertEqual(response.status_code, 202, response.text)
        body = response.json()
        self.assertEqual((body["operation"], body["cluster"]), ("object_servers", self.cluster))
        self.assertEqual(body["result"]["follow"], f"/api/v1/jobs/{body['result']['job']['id']}")
        (job,) = self.jobs
        self.assertEqual(
            job["payload"],
            {
                "object": self.name,
                "servers": ["web/192.0.2.10:8080", "web/192.0.2.12:8080"],
                "state": "maint",
            },
        )
        self.assertEqual(
            {k: job[k] for k in ("operation", "cluster", "payload")},
            {k: page[k] for k in ("operation", "cluster", "payload")},
        )
        (event,) = self.audited
        self.assertEqual((event["actor"], event["action"]), (ACTOR, "queue_job"))
        self.assertEqual(
            event["detail"],
            {
                "operation": "server_state",
                "job": mock.ANY,
                "via": "api",
                "object": self.name,
                "state": "maint",
                "servers": ["web/192.0.2.10:8080", "web/192.0.2.12:8080"],
            },
        )

    def test_each_state_is_the_one_the_buttons_send(self) -> None:
        for word, sent in (("drain", "drain"), ("maintenance", "maint"), ("ready", "ready")):
            with self.subTest(state=word):
                self.jobs.clear()
                response = self.post(
                    self.path(), {"servers": ["web/192.0.2.10:8080"], "state": word}
                )
                self.assertEqual(response.status_code, 202)
                self.assertEqual(self.jobs[0]["payload"]["state"], sent)
                self.assertEqual(
                    self.jobs[0]["payload"],
                    job_payloads.server_state(self.name, ["web/192.0.2.10:8080"], sent),
                )

    def test_a_token_limited_to_another_cluster_finds_nothing(self) -> None:
        response = self.post(
            self.path(), {"servers": ["192.0.2.10:8080"], "state": "drain"}, scope=["other"]
        )
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json()["error"]["code"], "not_found")
        self.assertEqual(self.jobs, [])

    def test_a_cluster_the_installation_does_not_list_finds_nothing(self) -> None:
        response = self.post(self.path("gamma"), {"servers": ["192.0.2.10:8080"], "state": "drain"})
        self.assertEqual(response.status_code, 404)
        self.assertEqual(self.jobs, [])

    def test_a_bad_body_is_a_400_and_queues_nothing(self) -> None:
        bodies: list[Any] = [
            None,
            {},
            {"servers": [], "state": "drain"},
            {"servers": [""], "state": "drain"},
            {"servers": ["x" * 301], "state": "drain"},
            {"servers": [f"192.0.2.{n % 250}:{8000 + n}" for n in range(65)], "state": "drain"},
            {"servers": ["192.0.2.10:8080"], "state": "maint"},
            {"servers": ["192.0.2.10:8080"], "state": "disable"},
            {"servers": ["192.0.2.10:8080"], "state": "drain", "extra": 1},
            {"servers": "192.0.2.10:8080", "state": "drain"},
        ]
        for body in bodies:
            with self.subTest(body=str(body)[:60]):
                response = self.post(self.path(), body)
                self.assertEqual(response.status_code, 400, response.text)
                self.assertEqual(response.json()["error"]["code"], "bad_input")
        self.assertEqual(self.jobs, [])

    def test_a_key_is_needed_and_writes_must_be_on(self) -> None:
        body = {"servers": ["192.0.2.10:8080"], "state": "drain"}
        self.assertEqual(self.post(self.path(), body, key=None).status_code, 400)
        off = self.post(self.path(), body, writes=False)
        self.assertEqual(off.status_code, 403)
        self.assertEqual(off.json()["error"]["code"], "writes_off")
        self.assertEqual(self.jobs, [])

    def test_only_a_write_token_reaches_it(self) -> None:
        body = {"servers": ["192.0.2.10:8080"], "state": "drain"}
        for level in ("read", "block"):
            with self.subTest(level=level):
                self.assertEqual(self.post(self.path(), body, level=level).status_code, 403)
        self.assertEqual(self.jobs, [])


class Repeating(Queueing):
    """Review 26-11-01, P3-1: a retry under the same key is the job it queued, on every route."""

    def assertRepeatedIsTheJob(self, path: str, body: Any, *, method: str = "post") -> None:
        send = self.post if method == "post" else self.delete
        first = send(path, body)
        self.assertEqual(first.status_code, 202, first.text)
        (job,) = self.jobs
        self.under_key[KEY] = (queued(id=77), job["request_digest"])
        self.jobs.clear()
        self.audited.clear()
        again = send(path, body)
        self.assertEqual(again.status_code, 202, again.text)
        self.assertEqual(again.json()["result"]["job"]["id"], 77)
        self.assertEqual((self.jobs, self.audited), ([], []))

    def delete(self, path: str, body: Any) -> Any:
        secret = self.issue(level="write")
        headers = {"Authorization": f"Bearer {secret}", "Idempotency-Key": KEY}
        return self.writing().request("DELETE", "/api/v1" + path, json=body, headers=headers)

    def test_server_states(self) -> None:
        self.assertRepeatedIsTheJob(
            f"/clusters/{self.cluster}/objects/{self.name}/servers",
            {"servers": ["web/192.0.2.10:8080"], "state": "drain"},
        )

    def test_deploy(self) -> None:
        self.assertRepeatedIsTheJob(f"/clusters/{self.cluster}/deploy", {"expected_version": 7})

    def test_unblock(self) -> None:
        self.assertRepeatedIsTheJob(
            f"/clusters/{self.cluster}/objects/{self.name}/blocks",
            {"addresses": ["203.0.113.7"]},
            method="delete",
        )


class TheDeploy(Queueing):
    def page_queues(self, **form: Any) -> dict[str, Any]:
        client = self.writing()
        self.sign_in(client)
        fields = {
            "operation": "deploy",
            "cluster": self.cluster,
            "idempotency_key": KEY,
            auth.CSRF_FIELD: auth.csrf_token(client.cookies[auth.SESSION_COOKIE]),
            **form,
        }
        client.post("/operations", data=fields, follow_redirects=False)
        (job,) = self.jobs
        self.jobs.clear()
        self.audited.clear()
        return job

    def test_202_and_the_page_s_own_payload_with_and_without_a_version(self) -> None:
        for body, form in (({"expected_version": 7}, {"expected_version": "7"}), (None, {})):
            with self.subTest(body=body):
                page = self.page_queues(**form)
                response = self.post(f"/clusters/{self.cluster}/deploy", body)
                self.assertEqual(response.status_code, 202, response.text)
                self.assertEqual(response.json()["operation"], "cluster_deploy")
                (job,) = self.jobs
                self.assertEqual(
                    {k: job[k] for k in ("operation", "cluster", "payload")},
                    {k: page[k] for k in ("operation", "cluster", "payload")},
                )
                self.assertEqual(
                    job["payload"],
                    {"allow_vip_unknown": False, **({"expected_version": 7} if body else {})},
                )
                (event,) = self.audited
                self.assertEqual(event["actor"], ACTOR)
                self.jobs.clear()
                self.audited.clear()

    def test_a_token_limited_to_another_cluster_finds_nothing(self) -> None:
        response = self.post(f"/clusters/{self.cluster}/deploy", None, scope=["other"])
        self.assertEqual(response.status_code, 404)
        self.assertEqual(self.jobs, [])

    def test_a_bad_body_a_missing_key_and_writes_off_queue_nothing(self) -> None:
        path = f"/clusters/{self.cluster}/deploy"
        for body in (
            {"expected_version": 0},
            {"expected_version": "x"},
            {"allow_vip_unknown": True},
        ):
            with self.subTest(body=body):
                response = self.post(path, body)
                self.assertEqual(response.status_code, 400)
                self.assertEqual(response.json()["error"]["code"], "bad_input")
        self.assertEqual(self.post(path, None, key=None).status_code, 400)
        off = self.post(path, None, writes=False)
        self.assertEqual((off.status_code, off.json()["error"]["code"]), (403, "writes_off"))
        self.assertEqual(self.jobs, [])

    def test_only_a_write_token_reaches_it(self) -> None:
        for level in ("read", "block"):
            self.assertEqual(
                self.post(f"/clusters/{self.cluster}/deploy", None, level=level).status_code, 403
            )
        self.assertEqual(self.jobs, [])


class HealthCheckCase(Queueing):
    cluster = "alpha"
    name = "shop"

    def setUp(self) -> None:
        super().setUp()
        self.draft: ProxyDraft | None = None
        self.stored = replace(
            OBJECTS,
            result={
                **OBJECTS.result,
                "objects": [{**OBJECTS.result["objects"][0], "document": HTTP_CHECK}],
            },
        )
        for target, side_effect in (
            ("cluster_objects", lambda _c, **_kw: [self.stored]),
            ("cluster_networks", lambda _c, **_kw: [NETWORK]),
            ("cluster_settings", lambda _c, **_kw: [SETTINGS]),
            ("read_draft", self._read_draft),
        ):
            patch = mock.patch(f"haprion_ui.db.{target}", side_effect=side_effect)
            patch.start()
            self.addCleanup(patch.stop)
        self.asked: list[tuple[str, dict[str, Any]]] = []

    def writing(self, *, writes: bool = True) -> Any:
        return self.client(
            replace(configuration(), management_writes=writes, clusters=("alpha", "beta"))
        )

    def _read_draft(
        self, _c: object, cluster: str, object_id: str, stage: str = "draft"
    ) -> ProxyDraft | None:
        del cluster
        if (
            self.draft is not None
            and self.draft.object_id == object_id
            and self.draft.stage == stage
        ):
            return self.draft
        return None

    def a_draft(self, document: str, **changes: Any) -> ProxyDraft:
        return (
            ProxyDraft(
                cluster="alpha",
                object_id="shop",
                yaml=document,
                base_version=1,
                base_hash=COMMIT,
                revision=2,
                updated_by="operator",
                updated_at=datetime(2026, 10, 31, 9, 0, tzinfo=UTC),
                deleted=False,
                stage="draft",
                replaces=None,
            )
            if not changes
            else replace(self.a_draft(document), **changes)
        )

    def report(self) -> probe_module.ProbeReport:
        return probe_module.ProbeReport(
            ran=True,
            source="192.0.2.25",
            nodes=(
                probe_module.NodeReport(
                    node="node-a",
                    reachable=True,
                    error=None,
                    source_held=True,
                    results=(
                        probe_module.Reached(
                            host="192.0.2.10", port=8080, ok=True, status=200, error=None, ms=3
                        ),
                        probe_module.Reached(
                            host="192.0.2.11",
                            port=8080,
                            ok=False,
                            status=503,
                            error="answered 503, not 200",
                            ms=4,
                        ),
                    ),
                ),
                probe_module.NodeReport(
                    node="node-b", reachable=True, error=None, source_held=False, results=()
                ),
            ),
            caveats=("A caveat.",),
            tested_at=datetime(2026, 10, 31, 9, 30, tzinfo=UTC),
        )

    def run_with(self, report: probe_module.ProbeReport, **post: Any) -> Any:
        def run(cluster: str, fields: Any, choices: Any, **_k: Any) -> probe_module.ProbeReport:
            self.asked.append((cluster, dict(fields)))
            return report

        with mock.patch("haprion_ui.probe.run", side_effect=run):
            return self.post("/clusters/alpha/objects/shop/health-check", **post)


class TheHealthCheck(HealthCheckCase):
    def test_the_trial_is_answered_in_the_call_and_nothing_is_queued(self) -> None:
        response = self.run_with(self.report())
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual((body["operation"], body["cluster"]), ("object_health_check", "alpha"))
        self.assertEqual(
            body["result"],
            {
                "object": "shop",
                "document": "published",
                "ran": True,
                "problem": None,
                "source": "192.0.2.25",
                "complete": False,
                "caveats": ["A caveat."],
                "failing": 1,
                "tested_at": "2026-10-31T09:30:00+00:00",
                "held_by": [],
                "nodes": [
                    {
                        "node": "node-a",
                        "reachable": True,
                        "error": None,
                        "source_held": True,
                        "results": [
                            {
                                "host": "192.0.2.10",
                                "port": 8080,
                                "ok": True,
                                "status": 200,
                                "error": None,
                                "ms": 3,
                                "summary": "answered 200",
                                "certificate": None,
                                "verified": None,
                            },
                            {
                                "host": "192.0.2.11",
                                "port": 8080,
                                "ok": False,
                                "status": 503,
                                "error": "answered 503, not 200",
                                "ms": 4,
                                "summary": "answered 503",
                                "certificate": None,
                                "verified": None,
                            },
                        ],
                    },
                    {
                        "node": "node-b",
                        "reachable": True,
                        "error": None,
                        "source_held": False,
                        "results": [],
                    },
                ],
            },
        )
        self.assertEqual((self.jobs, self.audited), ([], []))

    def test_the_nodes_are_asked_what_the_page_asks_them(self) -> None:
        self.run_with(self.report())
        ((cluster, fields),) = self.asked
        self.assertEqual(cluster, "alpha")
        document = self.stored.result["objects"][0]["document"]
        self.assertEqual(fields, editor_flow.form_fields(document, ("office",)))
        self.assertEqual(fields["health_type"], "http")

    def test_a_draft_is_tried_before_the_stored_object(self) -> None:
        self.draft = self.a_draft(SHOP.replace("type: disabled", "type: tcp"))
        response = self.run_with(self.report())
        self.assertEqual(response.json()["result"]["document"], "draft")
        ((_, fields),) = self.asked
        self.assertEqual(fields["health_type"], "tcp")

    def test_a_removed_draft_is_not_what_is_tried(self) -> None:
        self.draft = self.a_draft(SHOP, deleted=True)
        self.assertEqual(self.run_with(self.report()).json()["result"]["document"], "published")

    def test_an_object_with_no_check_says_it_did_not_run(self) -> None:
        self.stored = replace(
            self.stored,
            result={
                **self.stored.result,
                "objects": [{**self.stored.result["objects"][0], "document": SHOP}],
            },
        )
        response = self.post("/clusters/alpha/objects/shop/health-check")
        self.assertEqual(response.status_code, 200, response.text)
        result = response.json()["result"]
        self.assertEqual((result["ran"], result["complete"], result["nodes"]), (False, False, []))
        self.assertIn("no health check", result["problem"])

    def test_an_object_the_editor_cannot_open_says_it_did_not_run(self) -> None:
        self.draft = self.a_draft("schema: 1\nname: shop\nunknown_key: 1\n")
        response = self.post("/clusters/alpha/objects/shop/health-check")
        self.assertEqual(response.status_code, 200, response.text)
        result = response.json()["result"]
        self.assertFalse(result["ran"])
        self.assertIn("cannot be opened", result["problem"])

    def test_a_token_limited_to_another_cluster_or_object_finds_nothing(self) -> None:
        response = self.run_with(self.report(), scope=["beta"])
        self.assertEqual(response.status_code, 404)
        self.assertEqual(self.asked, [])

    def test_an_object_that_does_not_exist_finds_nothing(self) -> None:
        response = self.post("/clusters/alpha/objects/nothing/health-check")
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json()["error"]["code"], "not_found")

    def test_writes_off_and_the_wrong_level(self) -> None:
        off = self.post("/clusters/alpha/objects/shop/health-check", writes=False)
        self.assertEqual((off.status_code, off.json()["error"]["code"]), (403, "writes_off"))
        for level in ("read", "block"):
            response = self.post("/clusters/alpha/objects/shop/health-check", level=level)
            self.assertEqual(response.status_code, 403)
        self.assertEqual(self.asked, [])
