"""Asking for an operation over HTTP, and the four ways that is refused.

The route is the control, not the template. A page that does not draw a button
is a courtesy to the person using it; what stops a reader, a stale form or a
disabled installation is here.
"""

from __future__ import annotations

import json
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
        "attempts": 0,
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

    def post(self, client: Any, **fields: Any) -> Any:
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
        self.assertEqual(response.headers["location"], "/jobs")
        self.assertEqual(len(self.queued), 1)

    def test_a_deploy_is_queued_with_the_version_on_the_page(self) -> None:
        self.post(self.writing_client(), expected_version="12")

        self.assertEqual(
            self.queued[0]["payload"], {"allow_vip_unknown": False, "expected_version": 12}
        )

    def test_a_version_that_is_not_a_number_is_refused_before_the_queue(self) -> None:
        response = self.post(self.writing_client(), expected_version="12abc")

        self.assertNotEqual(response.status_code, 303)
        self.assertEqual(self.queued, [])

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

    def network_form(self, **overrides: Any) -> dict[str, Any]:
        """One filled-in network editor, spare rows and all.

        The spare rows are in the fixture deliberately. They are what the
        browser actually sends, and a route tested only against tidy input
        would not have caught them becoming empty VIPs.
        """

        form: dict[str, Any] = {
            "operation": "network_publish",
            "cluster": "alpha",
            "expected_head": "a" * 40,
            "comment": "Test",
            "vip_name": ["public", ""],
            "vip_address": ["192.0.2.20", ""],
            "vip_source": ["192.0.2.25", ""],
            "default_vip_row": "0",
            "source_name": ["egress", ""],
            "source_address": ["192.0.2.35", ""],
            "group_name": ["partners", ""],
            "group_members": ["198.51.100.0/24\n203.0.113.10", ""],
        }
        form.update(overrides)
        return form

    def test_a_network_publish_needs_the_default_vip_confirmation(self) -> None:
        response = self.post(self.writing_client(), **self.network_form())

        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.queued, [])

    def test_a_confirmed_network_publish_queues_the_document_its_rows_describe(self) -> None:
        response = self.post(
            self.writing_client(), **self.network_form(default_vip_confirmation="on")
        )

        self.assertEqual(response.status_code, 303)
        payload = self.queued[0]["payload"]
        self.assertEqual(payload["expected_head"], "a" * 40)
        self.assertEqual(payload["comment"], "Test")
        self.assertEqual(
            json.loads(payload["network"]),
            {
                "vips": {"public": {"address": "192.0.2.20", "source": "192.0.2.25"}},
                "default_vip": "public",
                "sources": {"egress": "192.0.2.35"},
                "networks": {"partners": ["198.51.100.0/24", "203.0.113.10"]},
            },
        )

    def test_a_hand_written_document_cannot_reach_the_helper_through_this_route(self) -> None:
        #
        # The field the first version of this form posted. A browser that still
        # sends it - a stale page, or somebody curling the route - must not be
        # able to put a document of its own choosing on the other side of the
        # privilege boundary.
        #
        response = self.post(
            self.writing_client(),
            **self.network_form(default_vip_confirmation="on", network="vips: {}\n"),
        )

        self.assertEqual(response.status_code, 303)
        self.assertNotIn("vips: {}", self.queued[0]["payload"]["network"])

    def test_a_half_filled_row_is_refused_without_naming_what_was_typed(self) -> None:
        response = self.post(
            self.writing_client(),
            **self.network_form(
                default_vip_confirmation="on",
                vip_name=["public", "secret-name"],
                vip_address=["192.0.2.20", ""],
                vip_source=["192.0.2.25", ""],
            ),
        )

        self.assertEqual(response.status_code, 400)
        # Rendered in the interface's own chrome now, so the assertion is that
        # the message is on the page and what was typed is not.
        self.assertIn("VIP row 2 needs an address.", response.text)
        self.assertNotIn("secret-name", response.text)
        self.assertEqual(self.queued, [])

    def test_a_refused_form_is_answered_in_the_interface_rather_than_as_bare_text(self) -> None:
        #
        # The message was right and the page around it was missing: a person
        # mid-edit got a white page with one sentence and no way back that did
        # not read as "start over".
        #
        response = self.post(
            self.writing_client(),
            **self.network_form(
                default_vip_confirmation="on", vip_name=["", ""], vip_address=["", ""]
            ),
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("A cluster needs at least one VIP.", response.text)
        self.assertIn('href="/network"', response.text)
        self.assertIn("Nothing was written", response.text)

    def test_a_default_pointing_at_a_row_that_lost_its_name_is_refused(self) -> None:
        #
        # Clearing a name is how a row is removed, and the radio does not move
        # when it happens. Falling back to the first VIP would move every object
        # that did not name one - silently, under a confirmation that was ticked
        # for a different change.
        #
        response = self.post(
            self.writing_client(),
            **self.network_form(
                default_vip_confirmation="on",
                vip_name=["", "partner"],
                vip_address=["", "192.0.2.21"],
                vip_source=["", ""],
                default_vip_row="0",
            ),
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("Choose which VIP is the default.", response.text)
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
