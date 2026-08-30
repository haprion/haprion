from __future__ import annotations

import unittest
from datetime import UTC, datetime, timedelta
from unittest import mock
from uuid import uuid4

from haproxy_ui import db, jobs
from tests.test_login import LoginTestCase


def job(*, state: str, outcome: str | None = None) -> db.Job:
    now = datetime.now(UTC)
    return db.Job(
        id=19,
        request_id=uuid4(),
        operation="deploy",
        cluster="alpha",
        payload={},
        state=state,
        created_at=now - timedelta(minutes=3),
        started_at=None if state == "pending" else now - timedelta(minutes=2),
        finished_at=None if state in {"pending", "running"} else now - timedelta(minutes=1),
        exit_code=0 if state == "done" else None,
        outcome=outcome,
        result=None,
        stderr_excerpt="must not be rendered",
        idempotency_key=uuid4(),
        attempts=1,
    )


class JobOverviewTests(unittest.TestCase):
    def test_every_terminal_state_has_an_honest_label_and_counter(self) -> None:
        rows = [
            job(state="pending"),
            job(state="running"),
            job(state="done", outcome="done"),
            job(state="partial", outcome="partial"),
            job(state="blocked", outcome="blocked"),
            job(state="failed", outcome="failed"),
            job(state="unknown", outcome="unknown"),
        ]

        overview = jobs.build_job_overview(rows, now=datetime.now(UTC))

        self.assertEqual(overview.active_count, 2)
        self.assertEqual(overview.completed_count, 1)
        self.assertEqual(overview.attention_count, 4)
        self.assertEqual(
            [entry.state_label for entry in overview.jobs],
            [
                "Queued",
                "Running",
                "Completed",
                "Completed with gaps",
                "Blocked",
                "Failed",
                "Outcome unknown",
            ],
        )


class JobPageTests(LoginTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.recent_jobs = mock.patch(
            "haproxy_ui.db.recent_jobs", return_value=[job(state="blocked", outcome="blocked")]
        )
        self.recent_jobs.start()
        self.addCleanup(self.recent_jobs.stop)

    def test_the_job_page_is_authenticated_and_hides_raw_diagnostics(self) -> None:
        client = self.client()
        self.sign_in(client)

        page = client.get("/jobs")

        self.assertEqual(page.status_code, 200)
        self.assertIn('href="/jobs" aria-current="page"', page.text)
        self.assertIn("Blocked", page.text)
        self.assertIn("Deploy configuration", page.text)
        self.assertNotIn("must not be rendered", page.text)

    def test_the_attention_states_are_rendered_and_told_apart(self) -> None:
        """`partial`, `blocked` and `unknown` are three different answers.

        Flattening them into one "failed" would lose the distinction the whole
        outcome vocabulary exists for: what may be retried, what needs a person,
        and what nobody yet knows the effect of.
        """

        rows = [
            job(state="partial", outcome="partial"),
            job(state="blocked", outcome="blocked"),
            job(state="unknown", outcome="unknown"),
        ]
        client = self.client()
        self.sign_in(client)

        with mock.patch("haproxy_ui.db.recent_jobs", return_value=rows):
            page = client.get("/jobs")

        self.assertEqual(page.status_code, 200)
        for label in ("Completed with gaps", "Blocked", "Outcome unknown"):
            self.assertIn(label, page.text)
        self.assertNotIn("must not be rendered", page.text)

    def test_the_job_page_requires_a_session(self) -> None:
        page = self.client().get("/jobs", follow_redirects=False)

        self.assertEqual(page.status_code, 303)
        self.assertEqual(page.headers["location"], "/login")


if __name__ == "__main__":
    unittest.main()
