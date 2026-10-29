from __future__ import annotations

import json
import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest import mock
from uuid import uuid4

from haprion import exit_codes

from haprion_ui import attention, db, jobs
from tests.test_dashboard import reading as status_reading
from tests.test_login import LoginTestCase, configuration

FIXTURES = Path(__file__).parents[2] / "fixtures"


def job(
    *,
    state: str,
    outcome: str | None = None,
    result: dict[str, Any] | None = None,
    operation: str = "deploy",
    cluster: str | None = "alpha",
    exit_code: int | None = None,
) -> db.Job:
    now = datetime.now(UTC)
    return db.Job(
        id=19,
        request_id=uuid4(),
        operation=operation,
        cluster=cluster,
        payload={},
        state=state,
        created_at=now - timedelta(minutes=3),
        started_at=None if state == "pending" else now - timedelta(minutes=2),
        finished_at=None if state in {"pending", "running"} else now - timedelta(minutes=1),
        exit_code=(0 if state == "done" else None) if exit_code is None else exit_code,
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
        #
        # Zero, not four. The rows arrive newest first, every one of them is the
        # same cluster, and the newest finished row is `done` - so the four bad
        # outcomes below it were all replaced by a later run. They are history,
        # and history is not work.
        #
        self.assertEqual(overview.attention_count, 0)
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
            "haprion_ui.db.recent_jobs", return_value=[job(state="blocked", outcome="blocked")]
        )
        self.recent_jobs.start()
        self.addCleanup(self.recent_jobs.stop)

    def test_the_job_page_is_authenticated(self) -> None:
        client = self.client()
        self.sign_in(client)

        page = client.get("/jobs")

        self.assertEqual(page.status_code, 200)
        self.assertIn('href="/jobs" aria-current="page"', page.text)
        self.assertIn("Blocked", page.text)
        self.assertIn("Deploy configuration", page.text)

    def follow_up_page(self, **config_overrides: object) -> Any:
        """The page showing a cluster that is published but not deployed."""

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
        client = self.client(replace(configuration(), **config_overrides))  # type: ignore[arg-type]
        self.sign_in(client)
        with (
            mock.patch("haprion_ui.db.recent_jobs", return_value=rows),
            mock.patch("haprion_ui.db.cluster_statuses", return_value=behind),
        ):
            return client.get("/jobs")

    def test_the_follow_up_is_a_sentence_and_nothing_to_press(self) -> None:
        #
        # Jobs is the history (2026-10-06). The deploy is on the dashboard and
        # Versions, where the cluster's state is; an admin is not sent to a
        # terminal either.
        #
        page = self.follow_up_page(management_writes=True)

        self.assertIn("Published, not deployed", page.text)
        self.assertNotIn('action="/operations"', page.text)
        self.assertNotIn("haprion-deploy -c", page.text)

    def test_where_nobody_may_press_it_the_command_is_still_named(self) -> None:
        #
        # Writes are off, so there is no button to offer. Hiding the command as
        # well would leave the caption saying something has to happen without
        # saying what.
        #
        page = self.follow_up_page()

        self.assertNotIn('name="operation" value="deploy"', page.text)
        self.assertIn("haprion-deploy -c alpha", page.text)

    def test_a_finished_page_does_not_reload_itself(self) -> None:
        #
        # Nothing on it can change, and a page that reloaded anyway would close
        # the diagnostics somebody opened to read why a job failed - the moment
        # this page matters most.
        #
        client = self.client()
        self.sign_in(client)

        page = client.get("/jobs")

        self.assertNotIn('http-equiv="refresh"', page.text)

    def test_a_page_with_work_on_it_reloads_until_the_work_is_over(self) -> None:
        with mock.patch("haprion_ui.db.recent_jobs", return_value=[job(state="running")]):
            client = self.client()
            self.sign_in(client)
            page = client.get("/jobs")

        #
        # The reload itself and no badge announcing it: a page that visibly
        # updates has already said so, and a standing label about a mechanism
        # is one more thing to read on the page read most often.
        #
        self.assertIn(
            '<meta name="haproxy-live" content="5"><noscript><meta http-equiv="refresh" content="5"></noscript>',
            page.text,
        )
        self.assertNotIn("Refreshing every 5 s", page.text)

    def test_a_reader_is_never_shown_the_operation_diagnostics(self) -> None:
        """The line the frozen contract actually draws.

        `CONTRACT.md` withholds raw stderr from a reader role - and only from a
        reader role. Hiding it from an admin as well was a habit rather than a
        decision, and the person paying for that habit was the one who had to
        open an SSH session at every failure. See B44.

        Asserted on the rendered page rather than on the projection, because a
        template is where such a rule is most easily lost.
        """

        self.account = replace(self.account, role="reader")
        client = self.client()
        self.sign_in(client)

        page = client.get("/jobs")

        self.assertEqual(page.status_code, 200)
        self.assertIn("Blocked", page.text)
        self.assertNotIn("must not be rendered", page.text)
        self.assertNotIn("Diagnostics", page.text)

    def test_an_admin_is_shown_the_code_and_the_diagnostics(self) -> None:
        """What a failure has to answer: which failure, and what did it say."""

        client = self.client()
        self.sign_in(client)

        page = client.get("/jobs")

        self.assertEqual(page.status_code, 200)
        self.assertIn("must not be rendered", page.text)
        self.assertIn("Diagnostics", page.text)

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

        with mock.patch("haprion_ui.db.recent_jobs", return_value=rows):
            page = client.get("/jobs")

        self.assertEqual(page.status_code, 200)
        for label in ("Completed with gaps", "Blocked", "Outcome unknown"):
            self.assertIn(label, page.text)

    def test_the_number_is_shown_only_for_a_job_that_did_not_go(self) -> None:
        """What finds the job in the worker's journal, where that is worth doing."""

        rows = [
            replace(job(state="done", outcome="done"), id=41),
            replace(job(state="unknown", outcome="unknown"), id=42),
        ]
        client = self.client()
        self.sign_in(client)
        with mock.patch("haprion_ui.db.recent_jobs", return_value=rows):
            page = client.get("/jobs").text

        self.assertNotIn("<th>Job</th>", page)
        self.assertIn("<span>Job 42</span>", page)
        self.assertNotIn("<span>Job 41", page)
        # Still findable by the links other pages hold.
        self.assertIn('id="job-41"', page)

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
            mock.patch("haprion_ui.db.recent_jobs", return_value=rows),
            mock.patch("haprion_ui.db.cluster_statuses", return_value=behind),
        ):
            page = client.get("/jobs")

        self.assertEqual(page.status_code, 200)
        self.assertIn("Published, not deployed", page.text)
        self.assertIn("haprion-deploy -c alpha", page.text)
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


def revert_result(**changes: object) -> dict[str, Any]:
    body: dict[str, object] = {
        "changed": True,
        "new_version": 26,
        "from_version": 25,
        "deployment_required": True,
        "next_command": "haprion-deploy -c alpha",
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

    def view(
        self, *, awaiting: frozenset[str] = frozenset({"alpha"}), **kwargs: object
    ) -> jobs.JobView:
        overview = jobs.build_job_overview([job(**kwargs)], awaiting=awaiting)  # type: ignore[arg-type]
        return overview.jobs[0]

    def test_a_revert_that_still_needs_a_deploy_says_so(self) -> None:
        view = self.view(state="done", outcome="done", operation="revert", result=revert_result())

        self.assertIsNotNone(view.follow_up)
        self.assertIn("Published, not deployed", view.follow_up or "")
        self.assertIn("alpha", view.follow_up or "")
        self.assertEqual(view.next_command, "haprion-deploy -c alpha")

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

        values: tuple[object, ...] = ("yes", 1, None, {}, "true")
        for value in values:
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

    def test_an_unread_node_alone_is_no_deploy_owed(self) -> None:
        """Review 26-10-24, 02-07: incomplete and unknown kept 'Published, not deployed'."""

        unread = {"release_state": "incomplete"}
        for result, expected in (
            ({"summary": {"release_state": "unknown"}}, frozenset()),
            ({"summary": unread, "nodes": [{"current": True}, {"current": None}]}, frozenset()),
            ({"summary": unread, "nodes": [{"current": False}, {"current": None}]}, {"alpha"}),
        ):
            with self.subTest(result=result):
                self.assertEqual(jobs.awaiting_deployment([self.status("alpha", result)]), expected)

    def test_a_reading_that_says_nothing_useful_is_not_evidence(self) -> None:
        results: tuple[object, ...] = ({}, {"summary": None}, {"summary": {}}, "unreadable", None)
        for result in results:
            with self.subTest(result=result):
                self.assertEqual(
                    jobs.awaiting_deployment([self.status("alpha", result)]), frozenset()
                )


class WhatStillNeedsReview(unittest.TestCase):
    """The counter has to be able to reach zero, or it teaches people to ignore it.

    Counting every bad outcome ever recorded produces a number that only grows
    and that no action can clear. Asked "what needs review?", a reader wants the
    clusters where the last thing that happened did not work.
    """

    def test_a_cluster_whose_latest_job_succeeded_is_not_counted(self) -> None:
        rows = [
            job(state="done", outcome="done"),
            job(state="failed", outcome="failed"),
            job(state="unknown", outcome="unknown"),
        ]

        self.assertEqual(jobs.build_job_overview(rows).attention_count, 0)

    def test_a_cluster_whose_latest_job_failed_is_counted_once(self) -> None:
        rows = [
            job(state="failed", outcome="failed"),
            job(state="failed", outcome="failed"),
        ]

        self.assertEqual(jobs.build_job_overview(rows).attention_count, 1)

    def test_each_cluster_is_counted_on_its_own(self) -> None:
        rows = [
            job(state="failed", outcome="failed", cluster="alpha"),
            job(state="done", outcome="done", cluster="beta"),
            job(state="unknown", outcome="unknown", cluster="beta"),
        ]

        self.assertEqual(jobs.build_job_overview(rows).attention_count, 1)

    def test_a_job_still_running_does_not_hide_the_outcome_under_it(self) -> None:
        """A running job is not yet an answer, so the last answer still stands."""

        rows = [
            job(state="running"),
            job(state="failed", outcome="failed"),
        ]

        self.assertEqual(jobs.build_job_overview(rows).attention_count, 1)


class WhatTheExitNumberMeans(unittest.TestCase):
    """The column shows a number from a command the reader never ran.

    Keeping it is right - a maintainer reading a bad job wants the precise code
    - but a bare number in an interface whose whole point is not having to read
    exit codes is only half an answer.
    """

    def meaning(self, code: int | None) -> str:
        rows = [job(state="failed", outcome="failed", exit_code=code)]
        return jobs.build_job_overview(rows).jobs[0].exit_meaning

    def test_every_code_the_engine_returns_is_named_in_the_engine_s_words(self) -> None:
        """Review 2026-10-22, 4-1: 68 meant "no usable status" here, whatever the command said."""

        for code, expected in exit_codes.MEANINGS.items():
            with self.subTest(code=code):
                self.assertEqual(self.meaning(code), expected)
        self.assertEqual(self.meaning(exit_codes.BLOCKED), exit_codes.MEANINGS[75])

    def test_a_signal_is_reported_as_a_signal(self) -> None:
        """Negative codes are what a killed helper leaves behind - -15 and -6 both happened."""

        self.assertEqual(self.meaning(-15), "Stopped by signal 15.")
        self.assertEqual(self.meaning(-6), "Stopped by signal 6.")

    def test_an_unrecorded_or_unfamiliar_code_still_says_something(self) -> None:
        self.assertEqual(self.meaning(None), "The job recorded no exit code.")
        self.assertEqual(self.meaning(42), "The command exited with 42.")


class TheErrorCodeReachesThePage(LoginTestCase):
    """The one part of a failure a person can act on months later.

    The helper blames a stable, environment-independent code; the worker keeps
    it in the audit trail for exactly that reason. Until 2026-08-31 it reached
    no page at all, so a locked cluster, a moved target and a refused validation
    were all shown as `failed / exit 65` and told apart by nobody.
    """

    def page(self, rows: list[db.Job]) -> str:
        client = self.client()
        self.sign_in(client)
        with mock.patch("haprion_ui.db.recent_jobs", return_value=rows):
            return str(client.get("/jobs").text)

    def test_a_blocked_job_names_the_code_the_helper_blamed(self) -> None:
        envelope = {"error": {"code": "cluster_not_converged", "message": "not converged"}}

        body = self.page([job(state="blocked", outcome="blocked", result=envelope)])

        self.assertIn("cluster_not_converged", body)
        #
        # The code for everyone; the helper's prose beside it for an admin
        # only, as the diagnostics are (2026-09-21). The message varies with
        # the environment and is not part of the frozen vocabulary; the code
        # is, and it is what a reader gets.
        #
        self.assertIn("— not converged", body)
        self.account = replace(self.account, role="reader")
        self.assertNotIn(
            "not converged", self.page([job(state="blocked", outcome="blocked", result=envelope)])
        )

    def test_a_job_that_worked_carries_no_failure_row(self) -> None:
        body = self.page([job(state="done", outcome="done")])

        self.assertNotIn("Reason:", body)
        self.assertNotIn("Diagnostics", body)

    def test_a_partial_deploy_names_its_reason_and_a_warned_deploy_its_warning(self) -> None:
        """Review 26-10-24, 02-03: a partial showed no reason, a warned deploy read clean."""

        reason = {"warnings": [{"code": "target_not_reached", "message": "node-b is behind"}]}
        body = self.page([job(state="partial", outcome="partial", result=reason)])
        self.assertIn("Reason:</span> <code>target_not_reached</code>", body)
        self.assertIn("— node-b is behind", body)

        warned = {"warnings": [{"code": "vip_not_owned", "message": "no node owns the VIP"}]}
        body = self.page([job(state="done", outcome="done", result=warned)])
        self.assertIn("Warning:</span> <code>vip_not_owned</code>", body)
        self.account = replace(self.account, role="reader")
        body = self.page([job(state="done", outcome="done", result=warned)])
        self.assertIn("vip_not_owned", body)
        self.assertNotIn("no node owns the VIP", body)
        #
        # Another helper's warnings on success are not a row under it.
        #
        quiet = job(state="done", outcome="done", result=warned, operation="cert_issue")
        self.assertNotIn("vip_not_owned", self.page([replace(quiet, cluster=None)]))

    def test_a_partial_run_across_the_nodes_is_not_called_failed(self) -> None:
        partial = job(state="partial", outcome="partial", result={"warnings": []})
        self.assertEqual(jobs.failure_label(partial), "Deploy reached only some nodes")
        self.assertEqual(
            jobs.last_failure([partial])["alpha"].label, "Deploy reached only some nodes"
        )
        self.assertEqual(
            attention.from_jobs([partial])[0].message, "Deploy reached only some nodes"
        )

    def test_an_unknown_outcome_is_not_called_failed(self) -> None:
        """R2 26-10-27 (F19): *Backup failed* for a backup that had been taken."""

        unknown = job(state="unknown", outcome="unknown", operation="backup_run")
        self.assertEqual(jobs.failure_label(unknown), "Backup: outcome unknown")
        self.assertEqual(attention.from_jobs([unknown])[0].message, "Backup: outcome unknown")
        self.assertEqual(
            jobs.failure_label(job(state="failed", outcome="failed", operation="backup_run")),
            "Backup failed",
        )

    def test_a_result_that_is_not_the_expected_shape_is_survived(self) -> None:
        """The document is a privileged helper's, stored as it arrived."""

        shapes: tuple[dict[str, Any] | None, ...] = (
            {"error": "a string"},
            {"error": {"code": 7}},
            {"error": {}},
            {},
            None,
        )
        for broken in shapes:
            with self.subTest(result=broken):
                body = self.page([job(state="failed", outcome="failed", result=broken)])

                self.assertIn("Failed", body)
                self.assertNotIn("Reason:", body)


def certificate_refusal(
    nodes: list[dict[str, object]] | None = None,
    *,
    next_command: str | None = "haprion-cert-deploy -c alpha",
) -> dict[str, Any]:
    """What `haprion-deploy` answers when its preflight finds a node behind."""

    details: dict[str, object] = {
        "nodes": [{"node": "node-b", "missing": ["example-net"], "stale": []}]
        if nodes is None
        else nodes
    }
    if next_command is not None:
        details["next_command"] = next_command
    return {
        "outcome": "blocked",
        "error": {
            "code": "certificates_not_deployed",
            "message": "referenced certificates are not on every node",
            "details": details,
        },
    }


def blocked_deploy(job_id: int = 19, **changes: object) -> db.Job:
    return replace(
        job(state="blocked", outcome="blocked", exit_code=65, result=certificate_refusal()),
        id=job_id,
        **changes,  # type: ignore[arg-type]
    )


def block_of(row: db.Job) -> jobs.CertificateBlock:
    block = jobs.certificate_block(row)
    if block is None:
        raise AssertionError("expected a certificate block")
    return block


class ADeployBlockedOnCertificates(unittest.TestCase):
    """§6.4's preflight, read back: the one refusal a button can fix.

    The engine blocks a configuration deploy when a readable node lacks a
    certificate the release references, and names `cert-deploy`. The standing
    "deploy certificates" button went away with C5; this is where the offer
    lives now - on the job that was refused, and on the cluster's card, for
    as long as that refusal is the newest thing known about the cluster.
    """

    def test_the_refusal_is_read_into_a_block_naming_nodes_and_certificates(self) -> None:
        block = block_of(blocked_deploy())

        self.assertEqual(block.cluster, "alpha")
        self.assertEqual(block.job_id, 19)
        self.assertEqual(block.gaps, (jobs.NodeGap("node-b", ("example-net",), ()),))
        self.assertEqual(block.next_command, "haprion-cert-deploy -c alpha")
        self.assertEqual(block.headline, "Deploy blocked: node-b is missing example-net")
        self.assertEqual(
            block.sentence,
            "Deploy blocked: node-b is missing example-net. "
            "Deploy the certificates first, then deploy the configuration again.",
        )

    def test_several_nodes_are_described_each_on_their_own(self) -> None:
        #
        # Not merged into one list of nodes and one of certificates: that
        # would say node-b carries an older example-com, which the engine did
        # not say.
        #
        refusal = certificate_refusal(
            [
                {"node": "node-a", "missing": ["example-net"], "stale": ["example-com"]},
                {"node": "node-b", "missing": ["example-net"], "stale": []},
            ]
        )
        block = block_of(job(state="blocked", outcome="blocked", result=refusal))

        self.assertEqual(
            block.headline,
            "Deploy blocked: node-a is missing example-net and carries an older example-com; "
            "node-b is missing example-net",
        )

    def test_a_node_behind_only_on_a_ca_file_is_named_with_it(self) -> None:
        #
        # Review 2026-10-18, L1: the engine names CA files apart from
        # certificates. A gap with only those is still a gap, not a node to drop.
        #
        refusal = certificate_refusal(
            [
                {
                    "node": "node-b",
                    "missing": [],
                    "stale": [],
                    "missing_authorities": [],
                    "stale_authorities": ["corp-root"],
                }
            ]
        )
        block = block_of(job(state="blocked", outcome="blocked", result=refusal))

        self.assertEqual(block.headline, "Deploy blocked: node-b carries an older CA corp-root")

    def test_any_other_ending_is_not_a_block(self) -> None:
        other_code = {"error": {"code": "deploy_blocked", "message": "split brain"}}
        for row in (
            job(state="blocked", outcome="blocked", result=other_code),
            job(state="failed", outcome="failed", result=certificate_refusal()),
            job(
                state="blocked",
                outcome="blocked",
                operation="cert_deploy",
                result=certificate_refusal(),
            ),
            job(state="blocked", outcome="blocked", cluster=None, result=certificate_refusal()),
            job(state="done", outcome="done"),
        ):
            with self.subTest(job=(row.operation, row.state, row.cluster, row.result)):
                self.assertIsNone(jobs.certificate_block(row))

    def test_publish_and_deploy_blocked_on_certificates_is_a_block_too(self) -> None:
        """B257: the job ends as its deploy ended, and offers the same fix."""

        both = blocked_deploy(
            operation="changes_publish",
            payload={"objects": {"shop": "x"}, "deploy": True},
            result={**certificate_refusal(), "publish": {"outcome": "done"}},
        )
        alone = replace(both, payload={"objects": {"shop": "x"}})

        self.assertEqual(block_of(both).cluster, "alpha")
        self.assertIsNone(jobs.certificate_block(alone))

    def test_malformed_details_cost_the_sentence_not_the_offer(self) -> None:
        #
        # The code alone is the engine's verdict; the details are what it
        # said about it. A helper that wrote the code and garbled the details
        # still refused the deploy, so the button is still the right offer.
        #
        for details in (None, "text", {"nodes": "text"}, {"nodes": [7, {"node": 3}]}, {}):
            with self.subTest(details=details):
                refusal = certificate_refusal()
                refusal["error"]["details"] = details
                block = block_of(job(state="blocked", outcome="blocked", result=refusal))

                self.assertEqual(block.gaps, ())
                self.assertEqual(block.next_command, "haprion-cert-deploy -c alpha")
                self.assertIn("a node does not carry every certificate", block.headline)

    def test_only_the_newest_finished_job_carries_the_block(self) -> None:
        #
        # Rows arrive newest first. The block on job 20 stands while it is the
        # last word on alpha; a certificate deploy that finished after it is
        # the last word instead, and a block that is history is not offered.
        #
        older, newer = blocked_deploy(19), blocked_deploy(20)
        cleared = replace(job(state="done", outcome="done", operation="cert_deploy"), id=21)
        running = replace(job(state="running"), id=22)

        self.assertEqual(set(jobs.certificate_blocks([newer, older])), {"alpha"})
        self.assertEqual(jobs.certificate_blocks([newer, older])["alpha"].job_id, 20)
        self.assertEqual(jobs.certificate_blocks([cleared, newer, older]), {})
        #
        # A job in flight decides nothing yet: what is known about alpha is
        # still that the last finished attempt was refused.
        #
        self.assertEqual(jobs.certificate_blocks([running, newer, older])["alpha"].job_id, 20)

    def test_the_block_is_captioned_on_its_job(self) -> None:
        overview = jobs.build_job_overview([blocked_deploy(20), blocked_deploy(19)])

        newest, older = overview.jobs
        self.assertEqual(newest.next_command, "haprion-cert-deploy -c alpha")
        self.assertIn("Deploy blocked: node-b is missing example-net", newest.follow_up or "")
        self.assertEqual(newest.error_code, "certificates_not_deployed")
        self.assertIsNone(older.follow_up)

    def test_a_finished_certificate_deploy_owes_the_configuration_deploy(self) -> None:
        #
        # The plan's order is cert-deploy "followed by a new deploy", and
        # nothing chains the second on. So once the certificates are there and
        # the cluster is still behind, the second step is named on the job
        # that finished the first.
        #
        rows = [replace(job(state="done", outcome="done", operation="cert_deploy"), id=21)]

        captioned = jobs.build_job_overview(rows, awaiting=frozenset({"alpha"})).jobs[0]
        self.assertEqual(captioned.next_command, "haprion-deploy -c alpha")
        self.assertIn("Certificates deployed, configuration not", captioned.follow_up or "")

        converged = jobs.build_job_overview(rows).jobs[0]
        self.assertIsNone(converged.follow_up)


class TheBlockReachesThePages(LoginTestCase):
    def page(self, path: str, rows: list[db.Job], *, writes: bool = True) -> str:
        client = self.client(
            replace(configuration(), management_writes=writes, clusters=("alpha",))
        )
        self.sign_in(client)
        with (
            mock.patch("haprion_ui.db.recent_jobs", return_value=rows),
            # A release is published: without one there is no deploy to offer (finding 60).
            mock.patch(
                "haprion_ui.db.cluster_statuses",
                return_value=[status_reading("done-single-owner.json")],
            ),
        ):
            return str(client.get(path).text)

    def test_the_jobs_page_names_the_block_on_the_refused_job_without_a_button(self) -> None:
        body = self.page("/jobs", [blocked_deploy()])

        self.assertIn("Deploy blocked: node-b is missing example-net.", body)
        self.assertNotIn('action="/operations"', body)
        self.assertIn("certificates_not_deployed", body)
        self.assertNotIn("haprion-cert-deploy -c", body)

    def test_where_nobody_may_press_it_the_command_is_named(self) -> None:
        body = self.page("/jobs", [blocked_deploy()], writes=False)

        self.assertNotIn('name="operation" value="cert_deploy"', body)
        self.assertIn("haprion-cert-deploy -c alpha", body)

    def test_the_dashboard_offers_it_on_the_cluster_card_while_the_block_stands(self) -> None:
        body = self.page("/", [blocked_deploy()])

        self.assertIn("Deploy blocked: node-b is missing example-net", body)
        self.assertIn('name="operation" value="cert_deploy"', body)
        self.assertIn('name="operation" value="deploy"', body)
        self.assertEqual(body.count('action="/operations"'), 2)

    def test_the_dashboard_stops_offering_it_once_a_newer_job_has_finished(self) -> None:
        cleared = replace(job(state="done", outcome="done", operation="cert_deploy"), id=21)

        body = self.page("/", [cleared, blocked_deploy()])

        self.assertNotIn("Deploy blocked", body)
        self.assertNotIn('name="operation" value="cert_deploy"', body)
        self.assertEqual(body.count('action="/operations"'), 1)


class AFailedCertificateIssue(LoginTestCase):
    """certbot's own words reach the page that reports the job.

    The contract fixture is the source: `certbot_failed` carries the captured
    output under `error.details.diagnostics`, and the message says only what
    the exit was. The interface reads that key already - it is the one
    `candidate_invalid` uses for the compiler's answer - so a failed challenge
    arrives as the sentence the operator needs and not as an exit status.
    """

    def failed_issue(self) -> db.Job:
        document = json.loads(
            (FIXTURES / "haprion-cert-issue" / "valid" / "certbot-failed.json").read_text()
        )
        return job(
            state="failed",
            outcome="failed",
            operation="cert_issue",
            cluster=None,
            exit_code=1,
            result=document,
        )

    def test_an_admin_reads_certbot_s_reason_not_only_the_exit(self) -> None:
        with mock.patch("haprion_ui.db.recent_jobs", return_value=[self.failed_issue()]):
            client = self.client()
            self.sign_in(client)
            page = client.get("/jobs").text

        self.assertIn("certbot_failed", page)
        self.assertIn("Invalid request headers", page)
        self.assertIn("valid Cloudflare API credentials", page)

    def test_the_envelope_s_sentence_stands_beside_the_code(self) -> None:
        """A refusal written as an envelope prints nothing on stderr (2026-09-21, job 910)."""

        refused = job(
            state="failed",
            outcome="failed",
            operation="cert_import",
            cluster=None,
            exit_code=1,
            result={
                "schema_version": 1,
                "ok": False,
                "outcome": "failed",
                "operation": "cert_import",
                "cluster": None,
                "request_id": "ffffffff-ffff-4fff-8fff-ffffffffffff",
                "result": None,
                "warnings": [],
                "error": {
                    "code": "publish_failed",
                    "message": "not published: the certificate expires 2026-09-24, less than 7 days away",
                    "details": {},
                },
            },
        )
        with mock.patch("haprion_ui.db.recent_jobs", return_value=[refused]):
            client = self.client()
            self.sign_in(client)
            page = client.get("/jobs").text
        self.assertIn("<code>publish_failed</code>", page)
        self.assertIn("— not published: the certificate expires 2026-09-24", page)

    def test_a_reader_gets_the_code_and_not_the_output(self) -> None:
        self.account = replace(self.account, role="reader")
        with mock.patch("haprion_ui.db.recent_jobs", return_value=[self.failed_issue()]):
            client = self.client()
            self.sign_in(client)
            page = client.get("/jobs").text

        self.assertIn("certbot_failed", page)
        self.assertNotIn("Cloudflare", page)


class AHeldJob(LoginTestCase):
    """0082, review 2026-10-20 R1: queued before the manager started, it waits for Run or Discard."""

    def setUp(self) -> None:
        super().setUp()
        held = replace(job(state="pending"), held_since=datetime.now(UTC))
        patch = mock.patch("haprion_ui.db.recent_jobs", return_value=[held])
        patch.start()
        self.addCleanup(patch.stop)

    def admin(self, *, writes: bool = True) -> Any:
        client = self.client(replace(configuration(), management_writes=writes))
        self.assertEqual(self.sign_in(client).status_code, 303)
        return client

    def test_it_is_held_and_an_admin_is_offered_run_and_discard(self) -> None:
        page = self.admin().get("/jobs").text
        self.assertIn(">Held</span>", page)
        self.assertIn("Queued before the manager last started.", page)
        self.assertIn('action="/jobs/19/held"', page)
        self.assertIn('name="decision" value="run">Run</button>', page)
        self.assertIn('name="decision" value="discard">Discard</button>', page)
        self.assertNotIn('action="/jobs/19/held"', self.admin(writes=False).get("/jobs").text)

    def test_a_running_one_is_held_too_and_offered_the_same_answers(self) -> None:
        """Review 2026-10-28, F01: its helper's answer waits with it for Run or Discard."""

        running = replace(job(state="running"), held_since=datetime.now(UTC))
        with mock.patch("haprion_ui.db.recent_jobs", return_value=[running]):
            page = self.admin().get("/jobs").text
        self.assertIn(">Held</span>", page)
        self.assertIn(
            "Running when the manager last started. It may have finished before a restore;"
            " Discard keeps what it did and runs nothing more.",
            page,
        )
        self.assertIn('name="decision" value="discard">Discard</button>', page)

    def test_the_answer_is_recorded_and_anything_else_refused(self) -> None:
        client = self.admin()
        page = client.get("/jobs").text
        token = page.split('name="csrf_token" value="', 1)[1].split('"', 1)[0]
        with mock.patch("haprion_ui.db.decide_held_job", return_value=True) as decide:
            answered = client.post(
                "/jobs/19/held",
                data={"csrf_token": token, "decision": "discard"},
                follow_redirects=False,
            )
            refused = client.post(
                "/jobs/19/held",
                data={"csrf_token": token, "decision": "delete"},
                follow_redirects=False,
            )
        self.assertEqual((answered.status_code, answered.headers["location"]), (303, "/jobs"))
        self.assertEqual(refused.status_code, 400)
        decide.assert_called_once()
        self.assertEqual(decide.call_args.kwargs["decision"], "discard")
        self.assertIn("held_job_decided", self.audit)

    def test_an_answer_not_taken_is_said(self) -> None:
        """Review 26-10-29 (b): back on Jobs with nothing said when the job had moved on."""

        client = self.admin()
        page = client.get("/jobs").text
        token = page.split('name="csrf_token" value="', 1)[1].split('"', 1)[0]
        with mock.patch("haprion_ui.db.decide_held_job", return_value=False):
            answered = client.post(
                "/jobs/19/held",
                data={"csrf_token": token, "decision": "run"},
                follow_redirects=False,
            )
        self.assertEqual(answered.headers["location"], "/jobs?not_held=19")
        self.assertNotIn("held_job_decided", self.audit)
        notice = "Job 19 no longer waits for Run or Discard; nothing was changed."
        self.assertIn(notice, client.get("/jobs?not_held=19").text)
        self.assertNotIn("no longer waits", client.get("/jobs?not_held=x").text)
        self.assertNotIn("no longer waits", client.get("/jobs").text)
