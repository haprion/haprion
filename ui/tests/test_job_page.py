from __future__ import annotations

import unittest
from datetime import UTC, datetime, timedelta
from unittest import mock
from uuid import uuid4

from haproxy_ui import db, jobs
from tests.test_login import LoginTestCase


def job(
    *,
    state: str,
    outcome: str | None = None,
    result: dict | None = None,
    operation: str = "deploy",
) -> db.Job:
    now = datetime.now(UTC)
    return db.Job(
        id=19,
        request_id=uuid4(),
        operation=operation,
        cluster="alpha",
        payload={},
        state=state,
        created_at=now - timedelta(minutes=3),
        started_at=None if state == "pending" else now - timedelta(minutes=2),
        finished_at=None if state in {"pending", "running"} else now - timedelta(minutes=1),
        exit_code=0 if state == "done" else None,
        outcome=outcome,
        result=result,
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

    def test_a_revert_that_still_needs_a_deploy_says_so_on_the_page(self) -> None:
        """The projection being right is not the same as the page showing it."""

        rows = [job(state="done", outcome="done", operation="revert", result=revert_result())]
        behind = [
            db.ClusterStatus(
                cluster="alpha",
                observed_at=datetime.now(UTC),
                outcome="done",
                result={"summary": {"release_state": "behind"}},
                warnings=[],
                error=None,
                poll_error=None,
            )
        ]
        client = self.client()
        self.sign_in(client)

        with (
            mock.patch("haproxy_ui.db.recent_jobs", return_value=rows),
            mock.patch("haproxy_ui.db.cluster_statuses", return_value=behind),
        ):
            page = client.get("/jobs")

        self.assertEqual(page.status_code, 200)
        self.assertIn("Published, not deployed", page.text)
        self.assertIn("haproxy-deploy -c alpha", page.text)
        #
        # Still says Completed, and should: the job did finish. The two
        # statements together are the honest answer, which is why the row is
        # added rather than the state relabelled.
        #
        self.assertIn("Completed", page.text)

    def test_the_job_page_requires_a_session(self) -> None:
        page = self.client().get("/jobs", follow_redirects=False)

        self.assertEqual(page.status_code, 303)
        self.assertEqual(page.headers["location"], "/login")


if __name__ == "__main__":
    unittest.main()


def revert_result(**changes: object) -> dict:
    body: dict = {
        "changed": True,
        "new_version": 26,
        "from_version": 25,
        "deployment_required": True,
        "next_command": "haproxy-deploy -c alpha",
    }
    body.update(changes)
    return {"ok": True, "outcome": "done", "result": body}


class WhatAFinishedJobStillOwes(unittest.TestCase):
    """A job that reads `Completed` and has left the nodes on the old version.

    A revert publishes; it does not roll out. The state column is honest about
    the job and silent about the cluster, which is the one combination where a
    reader can walk away believing the wrong thing. The helper has always
    answered this in its result - it was simply never projected to the screen.
    """

    def view(self, *, awaiting: frozenset[str] = frozenset({"alpha"}), **kwargs: object):
        overview = jobs.build_job_overview([job(**kwargs)], awaiting=awaiting)  # type: ignore[arg-type]
        return overview.jobs[0]

    def test_a_revert_that_still_needs_a_deploy_says_so(self) -> None:
        view = self.view(state="done", outcome="done", operation="revert", result=revert_result())

        self.assertIsNotNone(view.follow_up)
        self.assertIn("Published, not deployed", view.follow_up or "")
        self.assertIn("alpha", view.follow_up or "")
        self.assertEqual(view.next_command, "haproxy-deploy -c alpha")

    def test_a_cluster_that_has_caught_up_is_not_captioned(self) -> None:
        """The rule that was missing, and the reason the line was wrong.

        A job's result records what was owed when it ran. Job 15 published and
        job 16 deployed it an hour later; captioning job 15 with "the nodes
        still run the previous version" was a claim about the present built from
        a record of the past. If the cluster is on its target now, nothing is
        owed and nothing is said.
        """

        view = self.view(
            state="done",
            outcome="done",
            operation="revert",
            result=revert_result(),
            awaiting=frozenset(),
        )

        self.assertIsNone(view.follow_up)
        self.assertIsNone(view.next_command)

    def test_only_the_newest_job_that_left_work_is_captioned(self) -> None:
        """Two reverts, one cluster, one thing outstanding.

        Repeating the same sentence down the page would read as several
        outstanding deploys when there is one.
        """

        rows = [
            job(state="done", outcome="done", operation="revert", result=revert_result()),
            job(state="done", outcome="done", operation="revert", result=revert_result()),
        ]
        overview = jobs.build_job_overview(rows, awaiting=frozenset({"alpha"}))

        self.assertIsNotNone(overview.jobs[0].follow_up)
        self.assertIsNone(overview.jobs[1].follow_up)

    def test_a_deploy_that_finished_owes_nothing(self) -> None:
        view = self.view(state="done", outcome="done", result={"ok": True, "result": {}})

        self.assertIsNone(view.follow_up)
        self.assertIsNone(view.next_command)

    def test_a_result_that_answers_something_else_owes_nothing(self) -> None:
        """Read defensively: the document comes from a helper and is stored as it arrived.

        `deployment_required` is checked for being true rather than for being
        truthy, so a string, a number or a missing key all mean the same thing
        here - nothing is owed, and nothing is invented.
        """

        for value in ("yes", 1, None, {}, "true"):
            with self.subTest(value=value):
                view = self.view(
                    state="done",
                    outcome="done",
                    result=revert_result(deployment_required=value),
                )
                self.assertIsNone(view.follow_up)

    def test_a_missing_or_malformed_result_owes_nothing(self) -> None:
        for result in (None, {}, {"result": None}, {"result": "published"}):
            with self.subTest(result=result):
                self.assertIsNone(self.view(state="done", outcome="done", result=result).follow_up)

    def test_the_sentence_survives_a_result_without_a_command(self) -> None:
        """The sentence is the point; the command is the convenience."""

        view = self.view(state="done", outcome="done", result=revert_result(next_command=None))

        self.assertIsNotNone(view.follow_up)
        self.assertIn("Published, not deployed", view.follow_up or "")
        self.assertIsNone(view.next_command)


class WhichClustersAreBehind(unittest.TestCase):
    """Reading the poller's cached answer, defensively.

    A reading that is missing, malformed or `unknown` is not evidence that a
    cluster is behind. Captioning a job on that basis would tell an operator to
    deploy because the interface could not read a status.
    """

    def status(self, cluster: str, result: object) -> db.ClusterStatus:
        return db.ClusterStatus(
            cluster=cluster,
            observed_at=datetime.now(UTC),
            outcome="done",
            result=result,  # type: ignore[arg-type]
            warnings=[],
            error=None,
            poll_error=None,
        )

    def test_a_cluster_off_its_target_is_awaiting(self) -> None:
        rows = [self.status("alpha", {"summary": {"release_state": "behind"}})]
        self.assertEqual(jobs.awaiting_deployment(rows), frozenset({"alpha"}))

    def test_a_converged_cluster_is_not(self) -> None:
        rows = [self.status("alpha", {"summary": {"release_state": "converged"}})]
        self.assertEqual(jobs.awaiting_deployment(rows), frozenset())

    def test_a_reading_that_says_nothing_useful_is_not_evidence(self) -> None:
        for result in ({}, {"summary": None}, {"summary": {}}, "unreadable", None):
            with self.subTest(result=result):
                self.assertEqual(
                    jobs.awaiting_deployment([self.status("alpha", result)]), frozenset()
                )
