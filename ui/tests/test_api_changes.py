"""The API's object writes (B416, release 3): saved changes, publish and revert, as the pages make them."""

from __future__ import annotations

import json
import re
from dataclasses import replace
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any
from unittest import mock
from uuid import UUID, uuid4

import yaml

from haprion_ui import api_tokens, db, history
from haprion_ui.api import changes
from haprion_ui.db import ClusterHistory, ProxyDraft
from tests.test_api import ApiTestCase
from tests.test_api_writing import IDEMPOTENT, a_job
from tests.test_editor_page import (
    COMMIT,
    NETWORK,
    OBJECTS,
    OBSERVED,
    SHOP,
    EditorTestCase,
    writing_configuration,
)

BASE = "/api/v1/clusters/alpha"
ACTOR = f"token{':'}monitoring"
SECOND = SHOP.replace("shop", "console")
SHOP_CHANGED = SHOP.replace("8080", "9090")
OLDER = "c" * 40
HEAD_COMMIT = "d" * 40
PUBLISHED_COMMIT = "e" * 40


def saved_row(**changes: Any) -> ProxyDraft:
    row = ProxyDraft(
        cluster="alpha",
        object_id="shop",
        yaml=SHOP.replace("8080", "9090"),
        base_version=12,
        base_hash=COMMIT,
        revision=3,
        updated_by="operator",
        updated_at=OBSERVED,
        deleted=False,
        id=UUID("11111111-1111-4111-8111-111111111111"),
        stage="saved",
        base_document=SHOP,
    )
    return replace(row, **changes)


def versions() -> ClusterHistory:
    def entry(number: int, commit: str, **extra: Any) -> dict[str, Any]:
        return {
            "version": number,
            "hash": commit,
            "created_at": "2026-10-30T10:00:00+00:00",
            "comment": f"Update proxies: version {number}",
            "requested_by": "operator",
            **extra,
        }

    return ClusterHistory(
        cluster="alpha",
        observed_at=datetime.now(UTC),
        outcome="done",
        result={
            "published_version": 2,
            "published_hash": PUBLISHED_COMMIT,
            "total_versions": 3,
            "unpublished": 1,
            "truncated": False,
            "versions": [
                entry(3, HEAD_COMMIT, current=True),
                entry(2, PUBLISHED_COMMIT),
                entry(1, OLDER),
            ],
        },
        warnings=[],
        error=None,
        poll_error=None,
    )


class ChangesTestCase(ApiTestCase, EditorTestCase):
    """The editor's fixtures (one published object, a described cluster) behind a token."""

    def setUp(self) -> None:
        super().setUp()
        self.rows: list[ProxyDraft] = []
        self.queued: list[dict[str, Any]] = []
        self.events: list[dict[str, Any]] = []
        self.history = [versions()]
        for target, effect in (
            ("cluster_drafts", lambda _c, _cluster: list(self.rows)),
            ("queue_job", self._queue),
            ("record_audit_event", self._event),
            ("cluster_histories", lambda _c, **_kw: self.history),
            # Read just now, or the editor does not judge an object by the cluster.
            (
                "cluster_networks",
                lambda _c, **_kw: [replace(NETWORK, observed_at=datetime.now(UTC))],
            ),
        ):
            patch = mock.patch(f"haprion_ui.db.{target}", side_effect=effect)
            patch.start()
            self.addCleanup(patch.stop)
        # The manager's lookup service is no part of these.
        for target, answer in (("lookup", "192.0.2.53"), ("unresolved", [])):
            patch = mock.patch(f"haprion.resolve_socket.{target}", return_value=answer)
            patch.start()
            self.addCleanup(patch.stop)

    def _queue(self, _c: object, **values: Any) -> db.Job:
        self.queued.append(values)
        return a_job(operation=values["operation"], cluster=values["cluster"])

    def _event(self, _c: object, **values: Any) -> None:
        self.events.append(values)

    def _read_draft(
        self, _c: object, cluster: str, object_id: str, stage: str = "draft"
    ) -> ProxyDraft | None:
        # The rows the test holds, by object and stage, as the table has them.
        for row in [*self.rows, *([self.draft] if self.draft else [])]:
            if (row.object_id, row.stage) == (object_id, stage):
                return row
        return None

    def writes(self, *, writes: bool = True) -> Any:
        return self.client(
            replace(writing_configuration(), clusters=("alpha", "beta"), management_writes=writes)
        )

    def send(
        self,
        method: str,
        path: str,
        *,
        body: Any = None,
        level: str = "write",
        scope: list[str] | None = None,
        writes: bool = True,
        key: str | None = IDEMPOTENT,
        headers: dict[str, str] | None = None,
        **token: Any,
    ) -> Any:
        secret = self.issue(level=level, clusters=scope or [], **token)
        sent = {"Authorization": f"Bearer {secret}", **(headers or {})}
        if key is not None:
            sent["Idempotency-Key"] = key
        data = body.encode() if isinstance(body, str) else body
        if isinstance(body, dict):
            data = json.dumps(body).encode()
        return self.writes(writes=writes).request(
            method, "/api/v1" + path, content=data, headers=sent
        )

    def refused(self, response: Any, status: int, code: str) -> str:
        self.assertEqual(response.status_code, status, response.text)
        error = response.json()["error"]
        self.assertEqual(error["code"], code)
        return str(error["message"])


class CreatingAnObject(ChangesTestCase):
    def test_a_new_object_is_the_page_s_save_whatever_the_format(self) -> None:
        # What the page stores for the same fields, to the byte.
        client = self.editor()
        page = self.submit(
            client,
            "/proxies/alpha/new",
            name="console",
            action="save",
            hostnames="console.example.com",
            servers="192.0.2.10:8080",
        )
        self.assertEqual(page.status_code, 303, page.text)
        (by_page,) = self.saved
        for sent in (
            yaml.safe_dump(yaml.safe_load(by_page["yaml"]), sort_keys=False),
            json.dumps(yaml.safe_load(by_page["yaml"])),
            by_page["yaml"],
        ):
            self.changes.clear()
            response = self.send("POST", "/clusters/alpha/objects", body=sent)
            with self.subTest(sent=sent[:12]):
                self.assertEqual(response.status_code, 201, response.text)
                (written,) = self.changes
                self.assertEqual(written["yaml"], by_page["yaml"])
                self.assertEqual(
                    {
                        key: written[key]
                        for key in ("object_id", "base_version", "base_hash", "base_document")
                    },
                    {
                        key: by_page[key]
                        for key in ("object_id", "base_version", "base_hash", "base_document")
                    },
                )
                self.assertEqual(
                    (written["updated_by"], written["saved_revision"], written["draft_revision"]),
                    (ACTOR, None, None),
                )

    def test_the_answer_is_the_change_and_says_how_the_object_fits(self) -> None:
        response = self.send("POST", "/clusters/alpha/objects", body=SECOND)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.headers["location"], "/api/v1/clusters/alpha/objects/console")
        body = response.json()
        self.assertEqual(body["operation"], "object_create")
        result = body["result"]
        self.assertEqual(result["check"]["fits"], True)
        self.assertEqual(
            {key: value for key, value in result.items() if key != "check"},
            {
                "object": "console",
                "stage": "saved",
                "removal": False,
                "changed": True,
                "revision": 1,
                "updated_by": ACTOR,
                "updated_at": OBSERVED.isoformat(),
            },
        )
        (event,) = self.events
        self.assertEqual((event["actor"], event["action"]), (ACTOR, "save_change"))
        self.assertEqual(
            event["detail"], {"object": "console", "revision": 1, "via": "api", "stage": "saved"}
        )

    def test_an_object_the_cluster_does_not_fit_is_saved_and_says_why(self) -> None:
        unknown_vip = SECOND.replace("protocol: http", "protocol: http\n  vip: nowhere")
        response = self.send("POST", "/clusters/alpha/objects", body=unknown_vip)
        self.assertEqual(response.status_code, 201, response.text)
        check = response.json()["result"]["check"]
        self.assertEqual(check["fits"], False)
        self.assertIn("nowhere", check["problem"])
        self.assertEqual(len(self.changes), 1)

    def test_a_document_that_is_no_object_is_a_400_and_nothing_is_saved(self) -> None:
        bad = {
            "not a mapping": "- a\n- list\n",
            "empty": "",
            "no name": SECOND.replace("name: console\n", ""),
            "a name that is no name": SECOND.replace("name: console", "name: Console!"),
            "a number for a name": SECOND.replace("name: console", "name: 7"),
            "not utf-8": b"\xff\xfe",
            "an object the engine refuses": SECOND.replace("schema: 1", "schema: 2"),
            "broken json": '{"name": "console",',
        }
        for label, sent in bad.items():
            with self.subTest(label):
                response = self.send("POST", "/clusters/alpha/objects", body=sent)
                self.refused(response, 400, "bad_input")
        self.assertEqual((self.changes, self.events), ([], []))

    def test_a_body_over_what_an_object_may_be_is_413(self) -> None:
        with mock.patch.object(changes, "MAX_DOCUMENT", 100):
            response = self.send("POST", "/clusters/alpha/objects", body=SECOND)
        self.refused(response, 413, "too_large")

    def test_a_name_that_is_taken_is_a_409(self) -> None:
        self.refused(self.send("POST", "/clusters/alpha/objects", body=SHOP), 409, "conflict")
        self.rows = [saved_row(object_id="console", yaml=SECOND.replace("8080", "9091"))]
        self.refused(self.send("POST", "/clusters/alpha/objects", body=SECOND), 409, "conflict")
        self.draft = saved_row(object_id="console", yaml=SECOND, stage="draft")
        self.rows = []
        self.refused(self.send("POST", "/clusters/alpha/objects", body=SECOND), 409, "conflict")
        self.assertEqual(self.changes, [])

    def test_a_save_that_lost_a_race_is_a_409(self) -> None:
        self.conflict = True
        self.refused(self.send("POST", "/clusters/alpha/objects", body=SECOND), 409, "conflict")
        self.assertEqual(self.events, [])

    def test_a_token_outside_the_cluster_or_the_object_gets_the_404_of_no_such_thing(self) -> None:
        refused = self.send("POST", "/clusters/alpha/objects", body=SECOND, scope=["beta"])
        self.refused(refused, 404, "not_found")
        self.assertEqual(
            refused.json()["error"],
            self.send("POST", "/clusters/gamma/objects", body=SECOND).json()["error"],
        )
        self.refused(
            self.send("POST", "/clusters/alpha/objects", body=SECOND, objects=["shop"]),
            404,
            "not_found",
        )
        self.assertEqual(self.changes, [])

    def test_with_writes_off_nothing_is_saved(self) -> None:
        response = self.send("POST", "/clusters/alpha/objects", body=SECOND, writes=False)
        self.refused(response, 403, "writes_off")
        self.assertEqual(self.changes, [])

    def test_a_token_below_write_is_refused(self) -> None:
        for level in ("read", "block"):
            response = self.send("POST", "/clusters/alpha/objects", body=SECOND, level=level)
            self.refused(response, 403, "forbidden")
        self.assertEqual(self.changes, [])


class ReplacingAnObject(ChangesTestCase):
    def test_a_published_object_is_changed_as_a_saved_change_over_it(self) -> None:
        document = SHOP.replace("8080", "9090")
        response = self.send("PUT", "/clusters/alpha/objects/shop", body=document)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["operation"], "object_replace")
        (written,) = self.changes
        self.assertEqual(written["yaml"], document)
        self.assertEqual(
            (written["base_document"], written["saved_revision"], written["updated_by"]),
            (SHOP, None, ACTOR),
        )
        self.assertEqual(response.json()["result"]["revision"], 1)

    def test_the_page_stores_the_same_for_the_same_input(self) -> None:
        client = self.editor()
        page = self.submit(
            client, "/proxies/alpha/shop/edit", action="save", servers="192.0.2.10:9090"
        )
        self.assertEqual(page.status_code, 303, page.text)
        by_page = self.changes.pop()
        self.events.clear()
        self.send("PUT", "/clusters/alpha/objects/shop", body=SHOP.replace("8080", "9090"))
        (by_api,) = self.changes
        for key in ("yaml", "base_version", "base_hash", "base_document", "replaces"):
            self.assertEqual(by_api[key], by_page[key], key)

    def test_a_saved_change_is_replaced_at_its_revision_and_keeps_what_it_replaces(self) -> None:
        self.rows = [saved_row(replaces="storefront")]
        response = self.send(
            "PUT", "/clusters/alpha/objects/shop", body=SHOP.replace("8080", "9091")
        )
        self.assertEqual(response.status_code, 200)
        (written,) = self.changes
        self.assertEqual((written["saved_revision"], written["replaces"]), (3, "storefront"))
        self.assertEqual(response.json()["result"]["revision"], 4)

    def test_if_match_must_name_the_revision_that_is_saved(self) -> None:
        self.rows = [saved_row()]
        document = SHOP.replace("8080", "9091")
        for held in ('"2"', "4", "W/1"):
            with self.subTest(held=held):
                response = self.send(
                    "PUT",
                    "/clusters/alpha/objects/shop",
                    body=document,
                    headers={"If-Match": held},
                )
                self.refused(response, 409, "conflict")
        self.assertEqual(self.changes, [])
        for held in ("3", '"3"'):
            with self.subTest(held=held):
                response = self.send(
                    "PUT",
                    "/clusters/alpha/objects/shop",
                    body=document,
                    headers={"If-Match": held},
                )
                self.assertEqual(response.status_code, 200)
        self.refused(
            self.send(
                "PUT",
                "/clusters/alpha/objects/shop",
                body=document,
                headers={"If-Match": "latest"},
            ),
            400,
            "bad_input",
        )

    def test_if_match_against_an_object_with_nothing_saved_is_a_409(self) -> None:
        response = self.send(
            "PUT",
            "/clusters/alpha/objects/shop",
            body=SHOP.replace("8080", "9091"),
            headers={"If-Match": "3"},
        )
        self.refused(response, 409, "conflict")

    def test_saying_what_is_already_there_writes_nothing(self) -> None:
        response = self.send("PUT", "/clusters/alpha/objects/shop", body=SHOP)
        self.assertEqual(response.status_code, 200)
        result = response.json()["result"]
        self.assertEqual((result["changed"], result["revision"]), (False, None))
        self.rows = [saved_row()]
        response = self.send(
            "PUT", "/clusters/alpha/objects/shop", body=SHOP.replace("8080", "9090")
        )
        result = response.json()["result"]
        self.assertEqual((result["changed"], result["revision"]), (False, 3))
        self.assertEqual((self.changes, self.events), ([], []))

    def test_a_draft_nobody_finished_is_not_written_over(self) -> None:
        self.draft = saved_row(stage="draft")
        response = self.send(
            "PUT", "/clusters/alpha/objects/shop", body=SHOP.replace("8080", "9091")
        )
        self.assertIn("draft", self.refused(response, 409, "conflict"))
        self.assertEqual(self.changes, [])

    def test_an_object_that_is_nowhere_is_a_404(self) -> None:
        self.refused(
            self.send("PUT", "/clusters/alpha/objects/console", body=SECOND), 404, "not_found"
        )
        self.refused(
            self.send("PUT", "/clusters/alpha/objects/Console!", body=SECOND), 404, "not_found"
        )

    def test_a_pending_new_object_can_be_replaced(self) -> None:
        self.rows = [saved_row(object_id="console", yaml=SECOND)]
        response = self.send(
            "PUT", "/clusters/alpha/objects/console", body=SECOND.replace("8080", "9091")
        )
        self.assertEqual(response.status_code, 200, response.text)

    def test_a_document_for_another_name_or_no_object_is_a_400(self) -> None:
        for label, sent in {
            "another name": SECOND,
            "a list": "- a\n",
            "not utf-8": b"\xff",
        }.items():
            with self.subTest(label):
                self.refused(
                    self.send("PUT", "/clusters/alpha/objects/shop", body=sent), 400, "bad_input"
                )
        self.assertEqual(self.changes, [])

    def test_scope_and_switches(self) -> None:
        document = SHOP.replace("8080", "9091")
        self.refused(
            self.send("PUT", "/clusters/alpha/objects/shop", body=document, scope=["beta"]),
            404,
            "not_found",
        )
        self.refused(
            self.send("PUT", "/clusters/alpha/objects/shop", body=document, objects=["other"]),
            404,
            "not_found",
        )
        self.refused(
            self.send("PUT", "/clusters/alpha/objects/shop", body=document, writes=False),
            403,
            "writes_off",
        )
        self.refused(
            self.send("PUT", "/clusters/alpha/objects/shop", body=document, level="read"),
            403,
            "forbidden",
        )
        self.assertEqual(self.changes, [])

    def test_a_save_that_lost_a_race_is_a_409(self) -> None:
        self.conflict = True
        self.refused(
            self.send("PUT", "/clusters/alpha/objects/shop", body=SHOP.replace("8080", "9091")),
            409,
            "conflict",
        )


class RemovingAnObject(ChangesTestCase):
    def test_a_published_object_is_saved_for_removal_as_the_page_does(self) -> None:
        client = self.editor()
        csrf = self.token(client)
        page = client.post(
            "/proxies/alpha/shop/remove", data={"csrf_token": csrf}, follow_redirects=False
        )
        self.assertEqual(page.status_code, 303)
        by_page = self.changes.pop()
        self.events.clear()
        response = self.send("DELETE", "/clusters/alpha/objects/shop", key=None)
        self.assertEqual(response.status_code, 200, response.text)
        (by_api,) = self.changes
        self.assertEqual({**by_api, "updated_by": ""}, {**by_page, "updated_by": ""})
        self.assertEqual(by_api["updated_by"], ACTOR)
        self.assertEqual(response.json()["operation"], "object_remove")
        result = response.json()["result"]
        self.assertEqual(
            (result["object"], result["removal"], result["changed"], result["check"]),
            ("shop", True, True, None),
        )
        (event,) = self.events
        self.assertEqual(event["detail"]["removed"], True)

    def test_a_removal_over_a_draft_nobody_finished_is_a_409_and_writes_nothing(self) -> None:
        """Review 26-11-01, a-P2-3: the page's own *Remove* is unchanged, the API's is held like a replace."""

        self.rows = [saved_row(updated_by=ACTOR)]
        self.draft = saved_row(stage="draft", revision=5)
        response = self.send("DELETE", "/clusters/alpha/objects/shop")
        self.refused(response, 409, "conflict")
        self.assertIn("draft", response.json()["error"]["message"])
        self.assertEqual((self.changes, self.events), ([], []))

    def test_a_change_somebody_else_saved_is_taken_only_when_if_match_names_it(self) -> None:
        self.rows = [saved_row()]
        refused = self.send("DELETE", "/clusters/alpha/objects/shop")
        self.refused(refused, 409, "conflict")
        self.assertIn("operator", refused.json()["error"]["message"])
        self.refused(
            self.send("DELETE", "/clusters/alpha/objects/shop", headers={"If-Match": "2"}),
            409,
            "conflict",
        )
        self.assertEqual(self.changes, [])
        taken = self.send("DELETE", "/clusters/alpha/objects/shop", headers={"If-Match": "3"})
        self.assertEqual(taken.status_code, 200, taken.text)
        (written,) = self.changes
        self.assertEqual((written["saved_revision"], written["draft_revision"]), (3, None))

    def test_a_change_the_token_saved_itself_is_taken_without_if_match(self) -> None:
        self.rows = [saved_row(updated_by=ACTOR)]
        self.assertEqual(self.send("DELETE", "/clusters/alpha/objects/shop").status_code, 200)

    def test_an_object_that_is_not_published_is_a_404(self) -> None:
        self.refused(self.send("DELETE", "/clusters/alpha/objects/console"), 404, "not_found")

    def test_scope_and_switches(self) -> None:
        self.refused(
            self.send("DELETE", "/clusters/alpha/objects/shop", scope=["beta"]), 404, "not_found"
        )
        self.refused(
            self.send("DELETE", "/clusters/alpha/objects/shop", objects=["other"]),
            404,
            "not_found",
        )
        self.refused(
            self.send("DELETE", "/clusters/alpha/objects/shop", writes=False), 403, "writes_off"
        )
        self.refused(
            self.send("DELETE", "/clusters/alpha/objects/shop", level="block"), 403, "forbidden"
        )
        self.assertEqual(self.changes, [])

    def test_a_removal_that_lost_a_race_is_a_409(self) -> None:
        self.conflict = True
        self.refused(self.send("DELETE", "/clusters/alpha/objects/shop"), 409, "conflict")


class Publishing(ChangesTestCase):
    def page_publish(self, client: Any) -> None:
        text = client.get("/history").text
        package = re.search(r'name="package" value="([0-9a-f]{64})"', text)
        key = re.search(r'name="idempotency_key" value="([0-9a-f-]{36})"', text)
        if package is None or key is None:
            self.fail("the Versions page draws no publish form")
        answer = client.post(
            "/history/alpha/publish",
            data={
                "csrf_token": self.token(client),
                "expected_head": COMMIT,
                "comment": "Move the shop",
                "package": package.group(1),
                "idempotency_key": key.group(1),
                "then": "deploy",
            },
            follow_redirects=False,
        )
        self.assertEqual(answer.status_code, 303, answer.text)

    def test_the_job_is_the_one_the_page_queues_for_the_same_saved_changes(self) -> None:
        self.rows = [
            saved_row(),
            saved_row(object_id="console", yaml=SECOND, id=uuid4(), base_document=""),
        ]
        self.page_publish(self.editor())
        by_page = self.queued.pop()
        self.events.clear()
        response = self.send("POST", "/clusters/alpha/publish", body={"comment": "Move the shop"})
        self.assertEqual(response.status_code, 202, response.text)
        (by_api,) = self.queued
        self.assertEqual(by_api["operation"], "changes_publish")
        self.assertEqual(by_api["idempotency_key"], UUID(IDEMPOTENT))
        self.assertEqual(
            {**by_api["payload"], "requested_by": ""}, {**by_page["payload"], "requested_by": ""}
        )
        self.assertEqual(by_api["payload"]["requested_by"], ACTOR)
        self.assertIs(by_api["payload"]["deploy"], True)
        self.assertEqual(response.headers["location"], "/api/v1/jobs/41")
        self.assertEqual(response.json()["operation"], "cluster_publish")
        (event,) = self.events
        self.assertEqual(event["actor"], ACTOR)
        self.assertEqual(event["detail"]["changes"], ["shop", "console"])

    def test_without_a_body_it_deploys_with_a_comment_of_its_own(self) -> None:
        self.rows = [saved_row()]
        response = self.send("POST", "/clusters/alpha/publish")
        self.assertEqual(response.status_code, 202, response.text)
        payload = self.queued[0]["payload"]
        self.assertEqual((payload["comment"], payload["deploy"]), (changes.DEFAULT_COMMENT, True))

    def test_deploy_false_is_the_versions_page_s_publish(self) -> None:
        self.rows = [saved_row()]
        self.send("POST", "/clusters/alpha/publish", body={"deploy": False, "comment": " Hi "})
        payload = self.queued[0]["payload"]
        self.assertNotIn("deploy", payload)
        self.assertEqual(payload["comment"], "Hi")

    def test_a_long_token_name_does_not_break_the_version_s_trailer(self) -> None:
        self.rows = [saved_row()]
        self.send("POST", "/clusters/alpha/publish", name="a" * 64)
        self.assertEqual(len(self.queued[0]["payload"]["requested_by"]), 64)

    def test_nothing_saved_is_a_409_of_its_own(self) -> None:
        self.refused(self.send("POST", "/clusters/alpha/publish"), 409, "nothing_to_publish")
        self.assertEqual(self.queued, [])

    def test_changes_saved_against_an_older_version_are_not_published(self) -> None:
        self.rows = [saved_row(base_hash="b" * 40, base_document=None)]
        message = self.refused(self.send("POST", "/clusters/alpha/publish"), 409, "conflict")
        self.assertIn("older version", message)
        self.assertEqual(self.queued, [])

    def test_a_bad_body_is_a_400(self) -> None:
        self.rows = [saved_row()]
        for body in (
            {"comment": "x" * 4097},
            {"comment": "a b"},
            {"deploy": "perhaps"},
            {"extra": 1},
            "not json",
        ):
            with self.subTest(body=str(body)[:20]):
                response = self.send(
                    "POST",
                    "/clusters/alpha/publish",
                    body=body,
                    headers={"Content-Type": "application/json"},
                )
                self.refused(response, 400, "bad_input")
        self.assertEqual(self.queued, [])

    def test_a_publish_needs_its_key(self) -> None:
        self.rows = [saved_row()]
        message = self.refused(
            self.send("POST", "/clusters/alpha/publish", key=None), 400, "bad_input"
        )
        self.assertIn("Idempotency-Key", message)

    def test_scope_and_switches(self) -> None:
        self.rows = [saved_row()]
        self.refused(self.send("POST", "/clusters/alpha/publish", scope=["beta"]), 404, "not_found")
        self.refused(self.send("POST", "/clusters/gamma/publish"), 404, "not_found")
        self.refused(self.send("POST", "/clusters/alpha/publish", writes=False), 403, "writes_off")
        self.refused(self.send("POST", "/clusters/alpha/publish", level="read"), 403, "forbidden")
        self.assertEqual(self.queued, [])

    def test_a_busy_cluster_is_a_409(self) -> None:
        self.rows = [saved_row()]
        with mock.patch(
            "haprion_ui.db.queue_job", side_effect=db.ClusterBusy("alpha", active=a_job())
        ):
            self.refused(self.send("POST", "/clusters/alpha/publish"), 409, "cluster_busy")


class Reverting(ChangesTestCase):
    def test_the_job_is_the_one_the_versions_page_queues(self) -> None:
        client = self.editor()
        page = client.post(
            "/operations",
            data={
                "csrf_token": self.token(client),
                "operation": "revert",
                "cluster": "alpha",
                "version": "1",
                "expected_commit": OLDER,
                "expected_head": HEAD_COMMIT,
                "idempotency_key": str(uuid4()),
            },
            follow_redirects=False,
        )
        self.assertEqual(page.status_code, 303, page.text)
        by_page = self.queued.pop()
        self.events.clear()
        response = self.send("POST", "/clusters/alpha/revert", body={"version": 1})
        self.assertEqual(response.status_code, 202, response.text)
        (by_api,) = self.queued
        self.assertEqual(by_api["operation"], "revert")
        self.assertEqual(
            {**by_api["payload"], "requested_by": ""}, {**by_page["payload"], "requested_by": ""}
        )
        self.assertEqual(
            by_api["payload"],
            history.revert_payload(
                version=1, expected_commit=OLDER, requested_by=ACTOR, expected_head=HEAD_COMMIT
            ),
        )
        self.assertEqual(response.json()["operation"], "cluster_revert")
        (event,) = self.events
        self.assertEqual((event["actor"], event["detail"]["version"]), (ACTOR, 1))

    def test_a_version_that_is_not_in_the_history_is_a_404(self) -> None:
        self.refused(
            self.send("POST", "/clusters/alpha/revert", body={"version": 9}), 404, "not_found"
        )
        self.history = []
        self.refused(
            self.send("POST", "/clusters/alpha/revert", body={"version": 1}), 404, "not_found"
        )

    def test_the_published_version_is_a_409(self) -> None:
        self.refused(
            self.send("POST", "/clusters/alpha/revert", body={"version": 2}), 409, "conflict"
        )
        self.assertEqual(self.queued, [])

    def test_a_bad_body_is_a_400(self) -> None:
        for body in (
            {},
            {"version": 0},
            {"version": "one"},
            {"version": True},
            {"version": 1, "x": 1},
        ):
            with self.subTest(body=body):
                self.refused(
                    self.send("POST", "/clusters/alpha/revert", body=body), 400, "bad_input"
                )
        self.assertEqual(self.queued, [])

    def test_scope_and_switches(self) -> None:
        sent = {"version": 1}
        self.refused(
            self.send("POST", "/clusters/alpha/revert", body=sent, scope=["beta"]),
            404,
            "not_found",
        )
        self.refused(self.send("POST", "/clusters/gamma/revert", body=sent), 404, "not_found")
        self.refused(
            self.send("POST", "/clusters/alpha/revert", body=sent, writes=False),
            403,
            "writes_off",
        )
        self.refused(
            self.send("POST", "/clusters/alpha/revert", body=sent, level="block"),
            403,
            "forbidden",
        )
        self.refused(
            self.send("POST", "/clusters/alpha/revert", body=sent, key=None), 400, "bad_input"
        )
        self.assertEqual(self.queued, [])


class TheTokensItNeedsDoNotAppearInTheAnswers(ChangesTestCase):
    def test_no_answer_holds_the_secret(self) -> None:
        secret = self.issue(level="write")
        response = self.writes().post(
            "/api/v1/clusters/alpha/objects",
            content=SECOND.encode(),
            headers={"Authorization": f"Bearer {secret}"},
        )
        self.assertNotIn(secret, response.text)
        self.assertNotIn(api_tokens.secret_hash(secret).hex(), response.text)


class RepeatingACall(ChangesTestCase):
    """Review 26-11-01, a-P2-1: a retry with the same key is the job it queued, whatever the state is now."""

    def remember(self) -> None:
        self.under_key[IDEMPOTENT] = (a_job(), self.queued[-1]["request_digest"])
        self.queued.clear()
        self.events.clear()

    def test_a_publish_repeated_after_it_ran_is_answered_with_its_job(self) -> None:
        self.rows = [saved_row()]
        self.assertEqual(
            self.send("POST", "/clusters/alpha/publish", body={"comment": "Move"}).status_code, 202
        )
        self.remember()
        self.rows = []
        again = self.send("POST", "/clusters/alpha/publish", body={"comment": "Move"})
        self.assertEqual(again.status_code, 202, again.text)
        self.assertEqual(again.json()["result"]["job"]["id"], 41)
        self.assertEqual((self.queued, self.events), ([], []))

    def test_a_revert_repeated_after_the_head_moved_is_answered_with_its_job(self) -> None:
        self.assertEqual(
            self.send("POST", "/clusters/alpha/revert", body={"version": 1}).status_code, 202
        )
        self.remember()
        moved = versions()
        moved.result["versions"][0]["hash"] = "f" * 40
        self.history = [moved]
        again = self.send("POST", "/clusters/alpha/revert", body={"version": 1})
        self.assertEqual(again.status_code, 202, again.text)
        self.assertEqual(self.queued, [])

    def test_the_same_key_with_another_body_is_refused_after_the_job_ran(self) -> None:
        self.rows = [saved_row()]
        self.send("POST", "/clusters/alpha/publish", body={"comment": "Move"})
        self.remember()
        self.rows = []
        other = self.send("POST", "/clusters/alpha/publish", body={"comment": "Something else"})
        self.refused(other, 409, "idempotency_conflict")

    def test_a_call_without_a_valid_token_with_a_large_body_is_a_401_not_a_413(self) -> None:
        """Review 26-11-01, b-P3-8: the token is judged before the body is read."""

        client = self.writes()
        big = b"x" * (changes.MAX_DOCUMENT + 10)
        for path in (
            "/clusters/alpha/revert",
            "/clusters/alpha/publish",
            "/clusters/alpha/objects",
        ):
            with self.subTest(path=path):
                response = client.post(
                    "/api/v1" + path,
                    content=big,
                    headers={"Authorization": "Bearer nonsense", "Idempotency-Key": IDEMPOTENT},
                )
                self.assertEqual(response.status_code, 401, path)


class HonouringTheSwitches(ChangesTestCase):
    """Review 26-11-01, a-P3-3: what the page does not offer while a switch is off, the API does not write."""

    ADVANCED = SHOP + "advanced: |\n  retries 5\n"
    WAF = SHOP + "waf:\n  mode: log\n"

    def off(self, *names: str) -> None:
        self.switches = {name: mock.Mock(enabled=False) for name in names}

    def test_advanced_text_cannot_be_added_or_changed_while_its_switch_is_off(self) -> None:
        self.off("advanced_config")
        self.refused(
            self.send("PUT", "/clusters/alpha/objects/shop", body=self.ADVANCED), 400, "bad_input"
        )
        self.refused(
            self.send(
                "POST", "/clusters/alpha/objects", body=self.ADVANCED.replace("shop", "console")
            ),
            400,
            "bad_input",
        )
        self.assertEqual(self.changes, [])

    def test_advanced_text_is_written_while_its_switch_is_on(self) -> None:
        response = self.send("PUT", "/clusters/alpha/objects/shop", body=self.ADVANCED)
        self.assertEqual(response.status_code, 200, response.text)

    def test_advanced_text_already_there_may_stay_while_its_switch_is_off(self) -> None:
        self.off("advanced_config")
        self.rows = [saved_row(yaml=self.ADVANCED)]
        response = self.send(
            "PUT", "/clusters/alpha/objects/shop", body=self.ADVANCED.replace("8080", "9091")
        )
        self.assertEqual(response.status_code, 200, response.text)

    def test_the_engine_cannot_be_started_while_its_switch_is_off(self) -> None:
        self.off("waf_engine")
        self.refused(
            self.send("PUT", "/clusters/alpha/objects/shop", body=self.WAF), 400, "bad_input"
        )
        self.assertEqual(self.changes, [])

    def test_the_engine_cannot_be_started_where_it_is_not_installed(self) -> None:
        # The switch is on; the fixture's manager lists no engine.
        message = self.refused(
            self.send("PUT", "/clusters/alpha/objects/shop", body=self.WAF), 400, "bad_input"
        )
        self.assertIn("The WAF engine is not installed on", message)
        self.refused(
            self.send("POST", "/clusters/alpha/objects", body=self.WAF.replace("shop", "console")),
            400,
            "bad_input",
        )
        self.assertEqual(self.changes, [])

    def test_the_engine_is_started_where_it_is_installed(self) -> None:
        installed = replace(
            OBJECTS, result=dict(OBJECTS.result, waf={"engine": "0.9.0-2", "crs": "4.25.1"})
        )
        status = SimpleNamespace(
            cluster="alpha",
            observed_at=OBJECTS.observed_at,
            outcome="done",
            result={
                "nodes": [{"name": "node-a", "status": {"waf_engine": {"version": "0.9.0-2"}}}]
            },
            warnings=[],
            error=None,
            poll_error=None,
        )
        with (
            mock.patch("haprion_ui.db.cluster_objects", return_value=[installed]),
            mock.patch("haprion_ui.db.cluster_statuses", return_value=[status]),
        ):
            response = self.send("PUT", "/clusters/alpha/objects/shop", body=self.WAF)
        self.assertEqual(response.status_code, 200, response.text)

    def test_an_object_already_using_the_engine_may_be_changed_or_turned_off(self) -> None:
        self.off("waf_engine")
        self.rows = [saved_row(yaml=self.WAF)]
        self.assertEqual(
            self.send("PUT", "/clusters/alpha/objects/shop", body=SHOP).status_code, 200
        )


class RetriesAndRevisions(ChangesTestCase):
    def test_creating_the_same_object_again_is_a_no_change(self) -> None:
        """Review 26-11-01, a-P3-6: a retry after a lost answer is harmless."""

        first = self.send("POST", "/clusters/alpha/objects", body=SECOND)
        self.assertEqual(first.status_code, 201, first.text)
        (written,) = self.changes
        self.changes.clear()
        self.events.clear()
        self.rows = [saved_row(object_id="console", yaml=written["yaml"], updated_by=ACTOR)]
        again = self.send("POST", "/clusters/alpha/objects", body=SECOND, key=str(uuid4()))
        self.assertEqual(again.status_code, 201, again.text)
        result = again.json()["result"]
        self.assertEqual((result["changed"], result["revision"]), (False, 3))
        self.assertEqual((self.changes, self.events), ([], []))

    def test_if_match_zero_says_nothing_is_saved_yet(self) -> None:
        """Review 26-11-01, a-P3-7."""

        document = SHOP.replace("8080", "9091")
        self.rows = [saved_row()]
        self.refused(
            self.send(
                "PUT", "/clusters/alpha/objects/shop", body=document, headers={"If-Match": "0"}
            ),
            409,
            "conflict",
        )
        self.rows = []
        ok = self.send(
            "PUT", "/clusters/alpha/objects/shop", body=document, headers={"If-Match": "0"}
        )
        self.assertEqual(ok.status_code, 200, ok.text)

    def test_a_token_revoked_during_a_direct_write_saves_nothing(self) -> None:
        """Review 26-11-01, a-P3-4: judged again in the write's own transaction."""

        secret = self.issue(level="write")
        (digest,) = self.tokens
        live = self.tokens[digest]
        revoked = replace(live, revoked_at=datetime.now(UTC), revoked_by="admin")
        reads = iter([live, revoked])
        with (
            mock.patch(
                "haprion_ui.db.api_token_by_hash", side_effect=lambda _c, _d, **_k: next(reads)
            ),
            self.assertLogs("haprion_ui.api", "WARNING"),
        ):
            response = self.writes().put(
                "/api/v1/clusters/alpha/objects/shop",
                content=SHOP.replace("8080", "9091"),
                headers={"Authorization": f"Bearer {secret}"},
            )
        self.assertEqual(response.status_code, 401)
        self.assertEqual((self.changes, self.events), ([], []))
