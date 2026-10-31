"""How the API asks for a change (B416): one job, a key, the token judged again, `202`."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from typing import Any
from unittest import mock
from uuid import UUID, uuid4

from fastapi import Depends, Request
from fastapi.responses import JSONResponse
from starlette.routing import Mount

from haprion_ui import api, db
from haprion_ui.api import writing
from haprion_ui.api.caller import Caller, needs
from tests.test_api import NOW, ApiTestCase
from tests.test_login import configuration

IDEMPOTENT = "00000000-0000-4000-8000-000000000041"


def a_job(**changes: Any) -> db.Job:
    job = db.Job(
        id=41,
        request_id=UUID("11111111-2222-4333-8444-555555555555"),
        operation="server_state",
        cluster="alpha",
        payload={},
        state="pending",
        created_at=NOW,
        started_at=None,
        finished_at=None,
        exit_code=None,
        outcome=None,
        result=None,
        stderr_excerpt=None,
        idempotency_key=UUID(IDEMPOTENT),
        attempts=0,
    )
    return replace(job, **changes)


class QueueingAChange(ApiTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.queued: list[dict[str, Any]] = []
        self.events: list[dict[str, Any]] = []
        for patch in (
            mock.patch("haprion_ui.operations.prepare"),
            mock.patch("haprion_ui.db.queue_job", side_effect=self._queue),
            mock.patch("haprion_ui.db.record_audit_event", side_effect=self._event),
        ):
            patch.start()
            self.addCleanup(patch.stop)
        self.refusal: BaseException | None = None

    def _queue(self, _c: object, **values: Any) -> db.Job:
        if self.refusal is not None:
            raise self.refusal
        self.queued.append(values)
        return a_job(operation=values["operation"], cluster=values["cluster"])

    def _event(self, _c: object, **values: Any) -> None:
        self.events.append(values)

    def writing_client(self, *, writes: bool = True) -> Any:
        client = self.client(
            replace(configuration(), clusters=("alpha", "beta"), management_writes=writes)
        )
        app: Any = client.app
        mounted: Any = next(r for r in app.routes if isinstance(r, Mount) and r.path == api.PREFIX)

        def change(request: Request, caller: Caller = Depends(needs("write"))) -> JSONResponse:  # noqa: B008
            return writing.queue(
                request,
                caller,
                operation="server_state",
                cluster="alpha",
                payload={"object": "shop"},
                detail={"object": "shop"},
            )

        mounted.app.add_api_route("/test-change", change, methods=["POST"], name="test_change")
        return client

    def post(self, client: Any, secret: str, *, key: str | None = IDEMPOTENT) -> Any:
        headers = {"Authorization": f"Bearer {secret}"}
        if key is not None:
            headers[writing.IDEMPOTENCY_HEADER] = key
        return client.post("/api/v1/test-change", headers=headers)

    def test_a_change_is_one_job_answered_202_with_where_to_follow_it(self) -> None:
        client = self.writing_client()
        response = self.post(client, self.issue(level="write"))
        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.headers["location"], "/api/v1/jobs/41")
        body = response.json()
        self.assertEqual((body["ok"], body["outcome"]), (True, "done"))
        self.assertEqual(
            body["result"],
            {
                "job": {
                    "id": 41,
                    "request_id": "11111111-2222-4333-8444-555555555555",
                    "operation": "server_state",
                    "state": "pending",
                },
                "follow": "/api/v1/jobs/41",
            },
        )
        (queued,) = self.queued
        self.assertEqual(
            (queued["operation"], queued["cluster"], queued["idempotency_key"]),
            ("server_state", "alpha", UUID(IDEMPOTENT)),
        )
        (event,) = self.events
        # The actor is the token's name behind `token:` (`Caller.actor`).
        self.assertEqual((event["actor"], event["action"]), (f"token{':'}monitoring", "queue_job"))
        self.assertEqual(
            event["detail"],
            {"operation": "server_state", "job": 41, "via": "api", "object": "shop"},
        )

    def test_a_change_without_a_key_is_refused_before_anything(self) -> None:
        client = self.writing_client()
        for key in (None, "", "not-a-uuid"):
            with self.subTest(key=key):
                response = self.post(client, self.issue(level="write"), key=key)
                self.assertEqual(response.status_code, 400)
                self.assertIn(writing.IDEMPOTENCY_HEADER, response.json()["error"]["message"])
        self.assertEqual((self.queued, self.events), ([], []))

    def test_with_writes_off_nothing_is_queued(self) -> None:
        client = self.writing_client(writes=False)
        response = self.post(client, self.issue(level="write"))
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["error"]["code"], "writes_off")
        self.assertEqual(self.queued, [])

    def test_a_busy_cluster_and_a_key_used_for_something_else_are_409s(self) -> None:
        client = self.writing_client()
        secret = self.issue(level="write")
        for refusal, code in (
            (db.ClusterBusy("alpha", active=a_job()), "cluster_busy"),
            (db.RequestConflict(), "idempotency_conflict"),
        ):
            with self.subTest(code=code):
                self.refusal = refusal
                response = self.post(client, secret, key=str(uuid4()))
                self.assertEqual(response.status_code, 409)
                self.assertEqual(response.json()["error"]["code"], code)
        self.assertEqual(self.events, [])

    def test_a_token_revoked_since_the_request_arrived_queues_nothing(self) -> None:
        """Review 26-10-31, a-P3-5: judged again in the transaction that queues."""

        client = self.writing_client()
        secret = self.issue(level="write")
        (digest,) = self.tokens
        live = self.tokens[digest]
        revoked = replace(live, revoked_at=datetime.now(UTC), revoked_by="admin")
        reads = iter([live, revoked])
        with (
            mock.patch("haprion_ui.db.api_token_by_hash", side_effect=lambda _c, _d: next(reads)),
            self.assertLogs("haprion_ui.api", "WARNING") as logged,
        ):
            response = self.post(client, secret)
            del logged
        self.assertEqual(response.status_code, 401)
        self.assertEqual((self.queued, self.events), ([], []))

    def test_read_and_block_tokens_do_not_reach_a_change(self) -> None:
        client = self.writing_client()
        for level in ("read", "block"):
            with self.subTest(level=level):
                self.assertEqual(self.post(client, self.issue(level=level)).status_code, 403)
        self.assertEqual(self.queued, [])
