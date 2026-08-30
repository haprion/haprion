"""Asking for an operation over HTTP, and the four ways that is refused.

The route is the control, not the template. A page that does not draw a button
is a courtesy to the person using it; what stops a reader, a stale form or a
disabled installation is here.
"""

from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any
from unittest import mock
from uuid import UUID, uuid4

from haproxy_ui import auth, db, operations
from tests.test_login import LoginTestCase, configuration

KEY = str(uuid4())


def queued(**overrides: Any) -> db.Job:
    fields: dict[str, Any] = {
        "id": 7,
        "request_id": uuid4(),
        "operation": "deploy",
        "cluster": "alpha",
        "payload": {"allow_vip_unknown": False},
        "state": "pending",
        "created_at": datetime.now(UTC),
        "started_at": None,
        "finished_at": None,
        "exit_code": None,
        "outcome": None,
        "result": None,
        "stderr_excerpt": None,
        "idempotency_key": UUID(KEY),
    }
    return db.Job(**{**fields, **overrides})


class QueueRouteTestCase(LoginTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.queued: list[dict[str, Any]] = []

        def queue(_c: object, **fields: Any) -> db.Job:
            self.queued.append(fields)
            return queued()

        self.queue_job = mock.patch("haproxy_ui.db.queue_job", side_effect=queue)
        self.queue_job.start()
        self.addCleanup(self.queue_job.stop)

    def writing_client(self, *, role: str = "admin") -> Any:
        self.account = replace(self.account, role=role)
        client = self.client(replace(configuration(), management_writes=True))
        self.sign_in(client)
        return client

    def post(self, client: Any, **fields: str) -> Any:
        token = auth.csrf_token(client.cookies[auth.SESSION_COOKIE])
        form = {
            "operation": "deploy",
            "cluster": "alpha",
            "idempotency_key": KEY,
            auth.CSRF_FIELD: token,
        }
        form.update(fields)
        return client.post("/operations", data=form, follow_redirects=False)


class AskingForAnOperation(QueueRouteTestCase):
    def test_a_queued_job_redirects_rather_than_rendering(self) -> None:
        #
        # A refresh of a rendered page would ask again. The key would catch it,
        # but not relying on the key is cheaper than explaining why it held.
        #
        response = self.post(self.writing_client())

        self.assertEqual(response.status_code, 303)
        self.assertEqual(len(self.queued), 1)

    def test_the_form_key_is_what_reaches_the_database(self) -> None:
        self.post(self.writing_client())

        self.assertEqual(self.queued[0]["idempotency_key"], UUID(KEY))

    def test_queueing_is_recorded_in_the_audit(self) -> None:
        self.post(self.writing_client())

        self.assertIn("queue_job", self.audit)


class RefusedBeforeAnythingIsWritten(QueueRouteTestCase):
    def test_the_route_does_not_exist_when_writes_are_disabled(self) -> None:
        #
        # Turning management writes off is the documented rollback for the write
        # path, so the route has to be dead rather than merely unlinked - and 404
        # rather than 403, because "forbidden" would say an endpoint is there to
        # be enabled.
        #
        client = self.client(configuration())
        self.sign_in(client)
        response = self.post(client)

        self.assertEqual(response.status_code, 404)
        self.assertEqual(self.queued, [])

    def test_a_reader_is_refused_by_the_route_and_not_only_by_the_page(self) -> None:
        response = self.post(self.writing_client(role="reader"))

        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.queued, [])

    def test_a_post_without_a_csrf_token_queues_nothing(self) -> None:
        client = self.writing_client()
        response = client.post(
            "/operations",
            data={"operation": "deploy", "cluster": "alpha", "idempotency_key": KEY},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.queued, [])

    def test_signing_out_is_not_a_way_to_queue_anonymously(self) -> None:
        client = self.client(replace(configuration(), management_writes=True))
        response = client.post(
            "/operations",
            data={"operation": "deploy", "cluster": "alpha", "idempotency_key": KEY},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/login")
        self.assertEqual(self.queued, [])

    def test_an_unknown_operation_never_becomes_a_row(self) -> None:
        response = self.post(self.writing_client(), operation="publish")

        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.queued, [])

    def test_a_missing_request_key_is_refused(self) -> None:
        #
        # Making one up here would be the same as having none: every submission
        # would be a new attempt, and the second click a second operation.
        #
        response = self.post(self.writing_client(), idempotency_key="")

        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.queued, [])

    def test_a_revert_without_a_version_is_refused_before_the_insert(self) -> None:
        response = self.post(
            self.writing_client(), operation="revert", expected_commit="a" * 40, version=""
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.queued, [])

    def test_a_payload_refusal_does_not_echo_request_detail(self) -> None:
        with mock.patch(
            "haproxy_ui.operations.prepare",
            side_effect=operations.BadPayload("request-derived detail"),
        ):
            response = self.post(self.writing_client())

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.text, "Invalid operation parameters")
        self.assertEqual(self.queued, [])


class ConflictsAreToldApart(QueueRouteTestCase):
    def test_a_busy_cluster_answers_409(self) -> None:
        self.queue_job.stop()
        with mock.patch("haproxy_ui.db.queue_job", side_effect=db.ClusterBusy("alpha")):
            response = self.post(self.writing_client())
        self.queue_job.start()

        self.assertEqual(response.status_code, 409)

    def test_a_key_that_asked_for_something_else_answers_409(self) -> None:
        self.queue_job.stop()
        with mock.patch("haproxy_ui.db.queue_job", side_effect=db.RequestConflict(KEY)):
            response = self.post(self.writing_client())
        self.queue_job.start()

        self.assertEqual(response.status_code, 409)


if __name__ == "__main__":
    unittest.main()
