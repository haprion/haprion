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
            if (again := writing.replayed(request, caller)) is not None:
                return again
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
            mock.patch(
                "haprion_ui.db.api_token_by_hash", side_effect=lambda _c, _d, **_k: next(reads)
            ),
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

    def test_a_retry_is_the_job_already_queued_and_writes_no_second_history_row(self) -> None:
        """Review 26-11-01, a-P2-1 and a-P3-5: the key is held to the call, and a retry queues nothing."""

        client = self.writing_client()
        secret = self.issue(level="write")
        self.assertEqual(self.post(client, secret).status_code, 202)
        (queued,) = self.queued
        self.assertEqual(len(queued["request_digest"]), 32)
        self.under_key[IDEMPOTENT] = (a_job(id=41), queued["request_digest"])
        again = self.post(client, secret)
        self.assertEqual(again.status_code, 202, again.text)
        self.assertEqual(again.json()["result"]["job"]["id"], 41)
        self.assertEqual(again.headers["location"], "/api/v1/jobs/41")
        self.assertEqual((len(self.queued), len(self.events)), (1, 1))

    def test_a_key_used_for_another_call_is_a_409_that_does_not_say_to_do_it_again(self) -> None:
        client = self.writing_client()
        secret = self.issue(level="write")
        self.under_key[IDEMPOTENT] = (a_job(id=41), b"\0" * 32)
        response = self.post(client, secret)
        self.assertEqual(
            (response.status_code, response.json()["error"]["code"]), (409, "idempotency_conflict")
        )
        message = response.json()["error"]["message"]
        self.assertIn("another change", message)
        self.assertNotIn("new one", message)
        self.assertEqual((self.queued, self.events), ([], []))

    def test_another_token_s_key_is_not_answered_with_its_job(self) -> None:
        client = self.writing_client()
        self.assertEqual(self.post(client, self.issue(level="write")).status_code, 202)
        self.under_key[IDEMPOTENT] = (a_job(id=41), self.queued[0]["request_digest"])
        other = self.issue(level="write", name="other-token", id=8)
        response = self.post(client, other)
        self.assertEqual(
            (response.status_code, response.json()["error"]["code"]), (409, "idempotency_conflict")
        )

    def test_two_retries_racing_are_both_answered_with_the_one_job(self) -> None:
        """Review 26-11-01, P3-2: the queue's conflict is judged by the call's digest, not the payload."""

        client = self.writing_client()
        secret = self.issue(level="write")
        self.assertEqual(self.post(client, secret).status_code, 202)
        digest = self.queued[0]["request_digest"]
        self.queued.clear()
        self.events.clear()
        self.refusal = db.RequestConflict()
        for found, status in (
            ((a_job(id=41), True), 202),
            ((a_job(id=41), False), 409),
            (None, 409),
        ):
            with (
                self.subTest(found=found),
                mock.patch("haprion_ui.db.job_for_call", side_effect=[None, found]) as looked,
            ):
                response = self.post(client, secret)
                self.assertEqual(response.status_code, status, response.text)
                self.assertEqual(looked.call_args.kwargs["request_digest"], digest)
                if status == 202:
                    self.assertEqual(response.json()["result"]["job"]["id"], 41)
                else:
                    self.assertEqual(response.json()["error"]["code"], "idempotency_conflict")
        self.assertEqual(self.events, [])

    def test_a_replay_with_writes_off_is_still_refused(self) -> None:
        client = self.writing_client(writes=False)
        self.under_key[IDEMPOTENT] = (a_job(id=41), b"\0" * 32)
        self.assertEqual(self.post(client, self.issue(level="write")).status_code, 403)

    def test_a_key_the_queue_had_already_seen_writes_no_second_history_row(self) -> None:
        client = self.writing_client()
        secret = self.issue(level="write")
        with mock.patch("haprion_ui.db.queue_job", return_value=a_job(fresh=False)):
            response = self.post(client, secret)
        self.assertEqual(response.status_code, 202)
        self.assertEqual(self.events, [])

    def test_a_busy_cluster_held_for_a_person_says_so_and_promises_nothing(self) -> None:
        """Review 26-11-01, a-P3-1."""

        client = self.writing_client()
        secret = self.issue(level="write")
        self.refusal = db.ClusterBusy("alpha", active=a_job(held_since=datetime.now(UTC)))
        held = self.post(client, secret, key=str(uuid4()))
        self.assertEqual(held.json()["error"]["code"], "cluster_busy")
        self.assertIn("Run or Discard", held.json()["error"]["message"])
        self.assertNotIn("retry-after", held.headers)
        self.refusal = db.ClusterBusy("alpha", active=a_job(created_at=datetime.now(UTC)))
        busy = self.post(client, secret, key=str(uuid4()))
        self.assertIn("try again", busy.json()["error"]["message"])
        self.assertEqual(busy.headers["retry-after"], "5")

    def test_a_token_revoked_during_the_write_is_judged_with_its_row_held(self) -> None:
        """Review 26-11-01, a-P3-4: the row is read `for share`, so a revocation waits or is seen."""

        client = self.writing_client()
        secret = self.issue(level="write")
        seen: list[bool] = []
        original = self._token

        def watching(connection: object, token_hash: bytes, *, lock: bool = False) -> Any:
            seen.append(lock)
            return original(connection, token_hash, lock=lock)

        with mock.patch("haprion_ui.db.api_token_by_hash", side_effect=watching):
            self.assertEqual(self.post(client, secret).status_code, 202)
        self.assertEqual(seen, [False, True])
