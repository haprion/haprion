from __future__ import annotations

import unittest
from dataclasses import replace
from types import SimpleNamespace
from unittest import mock
from uuid import uuid4

from haproxy_ui import auth
from tests.test_login import LoginTestCase, configuration


class OperationControlsTests(LoginTestCase):
    def test_an_admin_sees_one_keyed_form_for_each_safe_initial_operation(self) -> None:
        client = self.client(replace(configuration(), management_writes=True, clusters=("alpha",)))
        self.sign_in(client)

        page = client.get("/")

        self.assertEqual(page.status_code, 200)
        self.assertEqual(page.text.count('action="/operations"'), 2)
        self.assertIn('name="operation" value="deploy"', page.text)
        self.assertIn('name="operation" value="cert_deploy"', page.text)
        self.assertEqual(page.text.count('name="idempotency_key" value="'), 2)

    def test_the_controls_are_absent_when_writes_are_off_or_the_role_is_reader(self) -> None:
        client = self.client(replace(configuration(), clusters=("alpha",)))
        self.sign_in(client)
        self.assertNotIn('action="/operations"', client.get("/").text)

        self.account = replace(self.account, role="reader")
        reader = self.client(replace(configuration(), management_writes=True, clusters=("alpha",)))
        self.sign_in(reader)
        self.assertNotIn('action="/operations"', reader.get("/").text)


if __name__ == "__main__":
    unittest.main()


class WhereAnOperationSendsYou(LoginTestCase):
    """Back to the page it was asked for on, when the form says which.

    Being moved to the jobs page was the same failure the publish badge had:
    the page somebody acted on could not show that the action was running, so
    the interface moved them to one that could. The dashboard says it now, so
    it can keep them.
    """

    def queue(self, **fields: str):
        client = self.client(replace(configuration(), management_writes=True))
        self.sign_in(client)
        data = {
            "operation": "deploy",
            "cluster": "alpha",
            "idempotency_key": str(uuid4()),
            auth.CSRF_FIELD: auth.csrf_token(client.cookies[auth.SESSION_COOKIE]),
        }
        data.update(fields)
        with mock.patch("haproxy_ui.db.queue_job", side_effect=self._queued):
            return client.post("/operations", data=data, follow_redirects=False)

    def _queued(self, _c: object, **values: object):
        return SimpleNamespace(id=1, request_id=uuid4())

    def test_a_named_page_is_where_it_returns(self) -> None:
        answer = self.queue(return_to="dashboard")

        self.assertEqual(answer.status_code, 303)
        self.assertEqual(answer.headers["location"], "/")

    def test_a_form_that_says_nothing_still_lands_somewhere_useful(self) -> None:
        answer = self.queue()

        self.assertEqual(answer.headers["location"], "/jobs")

    def test_a_page_nobody_offered_is_not_a_destination(self) -> None:
        """The value arrives in a form, so it may not be trusted as a path."""

        answer = self.queue(return_to="https://example.com/")

        self.assertEqual(answer.headers["location"], "/jobs")
