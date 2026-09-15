"""The State cell follows the deletion job; the page refreshes while it does."""

from __future__ import annotations

import unittest
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest import mock

from haproxy_ui import auth, certificate_activity
from tests.test_certificate_delete import DeleteRouteTestCase
from tests.test_queue_route import queued

NOW = datetime(2026, 9, 15, 14, 0, tzinfo=UTC)


def delete_job(state: str, *ids: str, result: dict[str, Any] | None = None, age: int = 0) -> Any:
    return queued(
        operation="cert_delete",
        cluster=None,
        state=state,
        payload={"certificates": list(ids)},
        result=result,
        finished_at=None if state in {"pending", "running"} else NOW - timedelta(minutes=age),
    )


def verdict(identifier: str, state: str, reason: str = "") -> dict[str, Any]:
    row: dict[str, Any] = {"certificate": identifier, "state": state}
    if reason:
        row["reason"] = reason
    return {"certificates": [row]}


class DeletionStates(unittest.TestCase):
    def states(self, *jobs: Any) -> dict[str, certificate_activity.DeletionState]:
        return certificate_activity.deletion_states(jobs, now=NOW)

    def test_a_running_job_says_deleting_and_asks_for_a_refresh(self) -> None:
        state = self.states(delete_job("running", "old.example.com"))["old.example.com"]
        self.assertEqual((state.label, state.tone, state.active), ("Deleting", "info", True))

    def test_a_finished_job_reports_per_certificate_and_only_for_an_hour(self) -> None:
        done = delete_job(
            "done",
            "old.example.com",
            "shop.example.com",
            result={
                "certificates": [
                    {"certificate": "old.example.com", "state": "removed"},
                    {
                        "certificate": "shop.example.com",
                        "state": "refused",
                        "reason": "named by the committed object(s) alpha/shop",
                    },
                ]
            },
        )
        states = self.states(done)
        self.assertEqual(states["old.example.com"].label, "Deleted")
        self.assertTrue(states["old.example.com"].active)
        self.assertEqual(states["shop.example.com"].label, "Delete refused")
        self.assertIn("alpha/shop", states["shop.example.com"].detail)
        self.assertFalse(states["shop.example.com"].active)
        stale = delete_job("done", "x", result=verdict("x", "removed"), age=61)
        self.assertEqual(self.states(stale), {})

    def test_partial_and_failed_jobs_keep_their_reason(self) -> None:
        partial = delete_job(
            "partial", "a", result=verdict("a", "incomplete", "some layers were kept")
        )
        failed = delete_job(
            "failed", "b", result={"error": {"code": "locked", "message": "another job holds it"}}
        )
        states = self.states(partial, failed)
        self.assertEqual(states["a"].label, "Delete incomplete")
        self.assertEqual(states["a"].tone, "warning")
        self.assertEqual(states["b"].detail, "another job holds it")

    def test_the_newest_job_naming_a_certificate_wins(self) -> None:
        newest = delete_job("running", "a")
        older = delete_job("done", "a", result=verdict("a", "removed"))
        self.assertEqual(self.states(newest, older)["a"].label, "Deleting")
        self.assertEqual(self.states(queued(operation="deploy")), {})


class TheListingFollowsTheJob(DeleteRouteTestCase):
    def test_a_deleting_row_shows_the_badge_and_the_page_refreshes(self) -> None:
        with mock.patch(
            "haproxy_ui.db.recent_jobs", return_value=[delete_job("running", "old.example.com")]
        ):
            page = self.writing_client().get("/certificates").text
        self.assertIn('<meta http-equiv="refresh" content="3">', page)
        self.assertIn('status-badge-info">Deleting<', page)
        self.assertNotIn('status-badge-info">Deleted<', page)

    def test_an_idle_listing_does_not_refresh(self) -> None:
        page = self.writing_client().get("/certificates").text
        self.assertNotIn('http-equiv="refresh"', page)
        self.assertIn("Certificate registry", page)

    def test_the_confirmation_returns_to_the_registry_listing(self) -> None:
        client = self.writing_client()
        token = auth.csrf_token(client.cookies[auth.SESSION_COOKIE])
        response = client.post(
            "/certificates/delete/confirm",
            data={
                "certificate": ["old.example.com"],
                "idempotency_key": "ffffffff-ffff-4fff-8fff-ffffffffffff",
                auth.CSRF_FIELD: token,
            },
            follow_redirects=False,
        )
        self.assertEqual(response.headers["location"], "/certificates?view=registry")


if __name__ == "__main__":
    unittest.main()
