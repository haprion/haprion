"""The State cell follows the deletion job; the page refreshes while it does."""

from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from unittest import mock

from haprion_ui import audit, auth, certificate_activity, certificate_renew, certificates, jobs
from haprion_ui.certificates import CertificateOverview
from tests.test_certificate_delete import DeleteRouteTestCase
from tests.test_certificates import node, overview, registered, registry_of, status, with_registry
from tests.test_certificates import reading as certificate_reading
from tests.test_login import configuration
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
        return certificate_activity.deletion_states(jobs, now=NOW, writes=True)

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
                        "reason": "named by the committed object alpha/shop",
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
        # A success gives way to the listing after the follow-up window; a
        # refusal is kept for the hour.
        stale = delete_job("done", "x", result=verdict("x", "removed"), age=2)
        self.assertEqual(self.states(stale), {})
        refused = delete_job("done", "x", result=verdict("x", "refused", "in use"), age=59)
        self.assertEqual(self.states(refused)["x"].label, "Delete refused")

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


class TheNewestJobHasTheLastWord(unittest.TestCase):
    """Seen 2026-09-19: a Publish to… that went through, and the row still said
    Enrollment failed about a job forty minutes older."""

    def test_the_stored_envelope_is_read_under_result(self) -> None:
        # The worker stores the whole envelope; the rows are under `result`.
        published = queued(
            operation="cert_target",
            cluster=None,
            state="done",
            payload={"certificates": ["hq.example"], "action": "add"},
            result={
                "outcome": "done",
                "result": {
                    "certificates": [
                        {"certificate": "hq.example", "state": "changed", "added": ["lb-01"]}
                    ]
                },
                "error": None,
            },
            finished_at=NOW - timedelta(minutes=1),
        )
        states = certificate_activity.deletion_states([published], now=NOW, writes=True)
        self.assertEqual(states["hq.example"].label, "Published to lb-01")

    def test_a_newer_finished_job_ends_an_older_failure_s_hour(self) -> None:
        failed = queued(
            operation="cert_scep",
            cluster=None,
            state="failed",
            payload={"id": "hq.example", "profile": "certserver1", "domains": ["hq.example"]},
            result={"error": {"code": "x", "message": "not allowlisted"}},
            finished_at=NOW - timedelta(minutes=40),
        )
        # Newer, done, and past the follow-up window: nothing to draw of its own.
        quiet = queued(
            operation="cert_target",
            cluster=None,
            state="done",
            payload={"certificates": ["hq.example"], "action": "add"},
            result={
                "outcome": "done",
                "result": {"certificates": [{"certificate": "hq.example", "state": "unchanged"}]},
                "error": None,
            },
            finished_at=NOW - timedelta(minutes=2),
        )
        states = certificate_activity.deletion_states([quiet, failed], now=NOW, writes=True)
        self.assertNotIn("hq.example", states)


class EnrollmentStates(unittest.TestCase):
    def test_a_running_enrollment_and_a_fresh_failure_are_overlays(self) -> None:
        running = queued(
            operation="cert_scep",
            cluster=None,
            state="running",
            payload={
                "id": "web.example.com",
                "profile": "certserver1",
                "domains": ["web.example.com"],
            },
        )
        failed = queued(
            operation="cert_scep",
            cluster=None,
            state="failed",
            payload={"id": "old.example.com", "resume": True},
            result={"error": {"code": "scep_failed", "message": "Certmonger stopped: CA_REJECTED"}},
            finished_at=NOW - timedelta(minutes=5),
        )
        pending = queued(
            operation="cert_scep",
            cluster=None,
            state="partial",
            payload={"id": "wait.example.com", "resume": True},
            finished_at=NOW,
        )
        states = certificate_activity.deletion_states(
            [running, failed, pending], now=NOW, writes=True
        )
        self.assertEqual(states["web.example.com"].label, "Enrolling")
        self.assertTrue(states["web.example.com"].active)
        self.assertEqual(states["old.example.com"].label, "Enrollment failed")
        self.assertIn("CA_REJECTED", states["old.example.com"].detail)
        # A pending request is the listing helper's fact, not the job's.
        self.assertNotIn("wait.example.com", states)


def issue_job(state: str, domain: str = "new.example.com", **extra: Any) -> Any:
    return queued(
        operation="cert_issue",
        cluster=None,
        state=state,
        payload={"domain": domain, "method": "dns-01", "clusters": ["alpha"], "receivers": ["pve"]},
        finished_at=None if state in {"pending", "running"} else NOW - timedelta(minutes=5),
        **extra,
    )


class RequestStates(unittest.TestCase):
    """A request is a row before the registry has one (2026-09-15).

    The page after pressing "Request the certificate" used to be the jobs
    page; now it is the listing, so the listing has to say what is going on
    about a name that has no material yet.
    """

    def states(self, *jobs: Any) -> dict[str, certificate_activity.DeletionState]:
        return certificate_activity.deletion_states(jobs, now=NOW, writes=True)

    def test_a_running_request_is_a_placeholder_drawn_from_the_payload(self) -> None:
        state = self.states(issue_job("running", "*.example.com"))["example.com"]
        self.assertEqual((state.label, state.tone, state.active), ("Requesting", "info", True))
        self.assertFalse(state.placeholder_only)
        asked = state.placeholder
        if asked is None:
            self.fail("a running request must carry a placeholder row")
        self.assertEqual(asked.source_label, "Certbot")
        self.assertTrue(asked.wildcard)
        self.assertEqual(asked.sans, ("*.example.com", "example.com"))
        self.assertEqual((asked.clusters, asked.receivers), (("alpha",), ("pve",)))

    def test_a_failed_request_carries_certbot_s_words_for_an_hour(self) -> None:
        failed = issue_job(
            "failed",
            result={"error": {"code": "certbot_failed", "message": "DNS problem: NXDOMAIN"}},
        )
        state = self.states(failed)["new.example.com"]
        self.assertEqual(
            (state.label, state.tone, state.active), ("Request failed", "critical", False)
        )
        self.assertEqual(state.detail, "DNS problem: NXDOMAIN")
        stale = queued(
            operation="cert_issue",
            cluster=None,
            state="failed",
            payload={"domain": "new.example.com"},
            finished_at=NOW - timedelta(minutes=61),
        )
        self.assertEqual(self.states(stale), {})

    def test_a_finished_request_only_fills_the_gap_until_the_poll(self) -> None:
        state = self.states(issue_job("done"))["new.example.com"]
        self.assertEqual(state.label, "Issued")
        self.assertTrue(state.active)
        self.assertTrue(state.placeholder_only)

    def test_a_payload_without_a_usable_domain_is_no_row(self) -> None:
        bad = queued(operation="cert_issue", cluster=None, state="running", payload={"domain": "*"})
        self.assertEqual(self.states(bad), {})

    def test_an_enrollment_carries_a_placeholder_too(self) -> None:
        running = queued(
            operation="cert_scep",
            cluster=None,
            state="running",
            payload={
                "id": "web.example.com",
                "profile": "certserver1",
                "domains": ["web.example.com"],
                "clusters": ["alpha"],
            },
        )
        asked = self.states(running)["web.example.com"].placeholder
        if asked is None:
            self.fail("a running enrollment must carry a placeholder row")
        self.assertEqual(
            (asked.source_label, asked.lifecycle, asked.wildcard), ("NDES", "import", False)
        )
        self.assertEqual(asked.clusters, ("alpha",))


class TheListingFollowsTheJob(DeleteRouteTestCase):
    def test_a_requested_certificate_is_a_row_before_the_registry_lists_it(self) -> None:
        with mock.patch(
            "haprion_ui.db.recent_jobs", return_value=[issue_job("running", "*.brand.example")]
        ):
            page = self.writing_client().get("/certificates?open=brand.example").text
        self.assertIn('data-certificates-region data-refresh="true"', page)
        self.assertNotIn('http-equiv="refresh"', page)
        self.assertIn(
            'status-badge-info"><span class="badge-spinner" aria-hidden="true"></span>Requesting<',
            page,
        )
        self.assertIn('<strong class="certificate-name">brand.example</strong>', page)
        self.assertIn("*.brand.example, brand.example", page)
        # No box to tick and no expiry badge: there is nothing yet.
        self.assertNotIn('value="brand.example" data-delete-pick', page)
        self.assertIn("The CA is being asked for the certificate", page)
        self.assertIn('<td data-label="Expires">—</td>', page)
        # First in the table: the newest thing on the page.
        self.assertLess(
            page.index('<strong class="certificate-name">brand.example</strong>'),
            page.index('<strong class="certificate-name">example.com</strong>'),
        )

    def test_a_listed_certificate_keeps_its_own_state_once_the_request_is_done(self) -> None:
        listed = with_registry(certificate_reading(), registered("new.example.com", kind="acme"))
        with (
            mock.patch("haprion_ui.db.recent_jobs", return_value=[issue_job("done")]),
            mock.patch("haprion_ui.db.cluster_certificates", return_value=[listed]),
        ):
            page = self.writing_client().get("/certificates").text
        self.assertNotIn('">Issued<', page)
        self.assertEqual(page.count('<strong class="certificate-name">new.example.com</strong>'), 1)

    def test_a_deleting_row_shows_the_badge_and_the_page_refreshes(self) -> None:
        with mock.patch(
            "haprion_ui.db.recent_jobs", return_value=[delete_job("running", "old.example.com")]
        ):
            page = self.writing_client().get("/certificates").text
        self.assertIn('data-certificates-region data-refresh="true"', page)
        self.assertNotIn('http-equiv="refresh"', page)
        self.assertIn(
            'status-badge-info"><span class="badge-spinner" aria-hidden="true"></span>Deleting<',
            page,
        )
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


class ResumingAnEnrollment(DeleteRouteTestCase):
    def test_a_pending_row_offers_the_button_and_the_post_queues_a_resume(self) -> None:
        pending = registered("wait.example.com", kind="import", clusters=("alpha",), readable=False)
        pending["request_state"] = "pending"
        pending["validation_error"] = "no material at its source yet"
        pending["source"]["ndes_profile"] = "certserver1"
        with mock.patch(
            "haprion_ui.db.cluster_certificates",
            return_value=[with_registry(certificate_reading(), pending)],
        ):
            client = self.writing_client()
            page = client.get("/certificates?view=registry&open=wait.example.com").text
            self.assertIn('status-badge-info">Request pending<', page)
            self.assertIn('action="/certificates/wait.example.com/resume"', page)
            self.assertIn(">Resume enrollment<", page)
            self.assertIn('status-badge-info">Request pending<', page)

            token = auth.csrf_token(client.cookies[auth.SESSION_COOKIE])
            response = client.post(
                "/certificates/wait.example.com/resume",
                data={
                    "idempotency_key": "ffffffff-ffff-4fff-8fff-ffffffffffff",
                    auth.CSRF_FIELD: token,
                },
                follow_redirects=False,
            )
        self.assertEqual(response.status_code, 303)
        self.assertEqual(
            response.headers["location"], "/certificates?view=registry&open=wait.example.com"
        )
        (job,) = self.queued
        self.assertEqual(job["operation"], "cert_scep")
        self.assertEqual(job["payload"], {"id": "wait.example.com", "resume": True})

    def test_the_resume_has_the_form_s_gates(self) -> None:
        reader = self.writing_client(role="reader")
        token = auth.csrf_token(reader.cookies[auth.SESSION_COOKIE])
        response = reader.post(
            "/certificates/x.example/resume",
            data={
                "idempotency_key": "ffffffff-ffff-4fff-8fff-ffffffffffff",
                auth.CSRF_FIELD: token,
            },
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.queued, [])


class AbandoningARequest(DeleteRouteTestCase):
    """B388: a request the CA holds is given up from the list, as `--abandon` does it."""

    def setUp(self) -> None:
        super().setUp()
        self.audited: list[dict[str, Any]] = []
        patch = mock.patch(
            "haprion_ui.db.record_audit_event",
            side_effect=lambda _c, **fields: self.audited.append(fields),
        )
        patch.start()
        self.addCleanup(patch.stop)

    def pending_reading(self) -> Any:
        pending = registered("wait.example.com", kind="import", clusters=("alpha",), readable=False)
        pending["request_state"] = "pending"
        pending["validation_error"] = "no material at its source yet"
        pending["source"]["ndes_profile"] = "certserver1"
        return with_registry(certificate_reading(), pending)

    def test_the_bar_offers_it_on_a_pending_row_and_the_confirmation_queues_it(self) -> None:
        with mock.patch(
            "haprion_ui.db.cluster_certificates", return_value=[self.pending_reading()]
        ):
            client = self.writing_client()
            page = client.get("/certificates?view=registry").text
            self.assertIn('formaction="/certificates/abandon" data-pending-submit disabled>', page)
            self.assertIn(
                'value="wait.example.com" form="certificate-selection" data-delete-pick data-pending',
                page,
            )
            token = auth.csrf_token(client.cookies[auth.SESSION_COOKIE])
            review = client.post(
                "/certificates/abandon",
                data={"certificate": "wait.example.com", auth.CSRF_FIELD: token},
            )
            self.assertEqual(review.status_code, 200)
            self.assertIn("Abandon request", review.text)
            self.assertIn('action="/certificates/abandon/confirm"', review.text)
            self.assertEqual(self.queued, [])
            response = client.post(
                "/certificates/abandon/confirm",
                data={
                    "certificate": "wait.example.com",
                    "idempotency_key": "ffffffff-ffff-4fff-8fff-ffffffffffff",
                    auth.CSRF_FIELD: token,
                },
                follow_redirects=False,
            )
        self.assertEqual(response.status_code, 303)
        (job,) = self.queued
        self.assertEqual(job["operation"], "cert_scep")
        self.assertEqual(job["payload"], {"id": "wait.example.com", "action": "abandon"})
        event = next(e for e in self.audited if e["action"] == "queue_job")
        self.assertEqual(
            audit.ACTIVITY_PHRASES["queue_job"](event["detail"]),
            "Queued the abandon of the NDES request for wait.example.com (job 7)",
        )

    def failed_reading(self, *, waiting: bool) -> Any:
        failed = registered("wait.example.com", fingerprint="a" * 64, kind="import")
        failed["source"]["ndes_profile"] = "certserver1"
        failed["renewal"] = {
            "attempted_at": "2026-10-29T05:00:00Z",
            "outcome": "failed",
            "message": "the NDES server's CA changed since the request waiting at the CA was "
            "made, and it resumes only as it was made. Give it up with Abandon request under "
            "Certificates, or haprion-cert-scep --id wait.example.com --abandon",
        }
        if waiting:
            failed["request_state"] = "pending"
        return with_registry(certificate_reading(), failed)

    def test_a_renewal_whose_resume_was_refused_can_be_abandoned(self) -> None:
        """Review 2026-10-29 again, BB01: the sentence sent the reader to a grey button."""

        for waiting in (True, False):
            with (
                self.subTest(waiting=waiting),
                mock.patch(
                    "haprion_ui.db.cluster_certificates",
                    return_value=[self.failed_reading(waiting=waiting)],
                ),
            ):
                self.queued.clear()
                client = self.writing_client()
                page = client.get("/certificates?view=registry&open=wait.example.com").text
                self.assertIn(">Renewal failed<", page)
                self.assertEqual(
                    'value="wait.example.com" form="certificate-selection" data-delete-pick '
                    "data-pending" in page,
                    waiting,
                )
                # Review 2026-10-29, round 2, BBB02: the failure may be passing.
                self.assertEqual(">Resume enrollment<" in page, waiting)
                token = auth.csrf_token(client.cookies[auth.SESSION_COOKIE])
                response = client.post(
                    "/certificates/abandon/confirm",
                    data={
                        "certificate": "wait.example.com",
                        "idempotency_key": "ffffffff-ffff-4fff-8fff-ffffffffffff",
                        auth.CSRF_FIELD: token,
                    },
                    follow_redirects=False,
                )
                if waiting:
                    self.assertEqual(response.status_code, 303)
                    (job,) = self.queued
                    self.assertEqual(
                        job["payload"], {"id": "wait.example.com", "action": "abandon"}
                    )
                else:
                    self.assertIn("has no request waiting at the CA", response.text)
                    self.assertEqual(self.queued, [])

    def test_a_failed_renewal_keeps_its_moment_and_its_resume_under_the_sentence(self) -> None:
        """Review 2026-10-29, round 3: "(tried 26-10-" / "29 06:00:00)" at 1280."""

        with mock.patch(
            "haprion_ui.db.cluster_certificates", return_value=[self.failed_reading(waiting=True)]
        ):
            page = self.writing_client().get("/certificates?view=registry&open=wait.example.com")
        self.assertRegex(
            page.text, r'\(tried <span class="moment">\d\d-\d\d-\d\d \d\d:\d\d:\d\d</span>\)'
        )
        self.assertIn(
            'action="/certificates/wait.example.com/resume" class="inline-form '
            'certificate-state-action"',
            page.text,
        )

    def test_every_state_of_an_ndes_row_has_one_rule(self) -> None:
        """Review 2026-10-29, round 2, BBB02 and BBB06: the label and the buttons asked apart.

        One table: what the listing says about a row, and what the row then
        shows - its label, *Resume enrollment*, the box that wakes
        *Abandon request…* - and what *Renew…* does with it. A request the CA
        holds is one fact whatever the label is, and a row's wish to renew
        while it waits is answered the same way each time.
        """

        failure = {
            "attempted_at": "2026-10-29T05:00:00Z",
            "outcome": "failed",
            "message": "Certmonger enrollment timed out: CA_UNREACHABLE",
        }
        waiting = "has a request the CA is still holding; resume it from its row, or give it up"

        def row(*, ndes: bool = True, request: bool = False, renewal: Any = None) -> Any:
            entry = registered("wait.example.com", fingerprint="a" * 64, kind="import")
            if ndes:
                entry["source"]["ndes_profile"] = "certserver1"
            if request:
                entry["request_state"] = "pending"
            if renewal is not None:
                entry["renewal"] = renewal
            return entry

        first = registered("wait.example.com", kind="import", readable=False)
        first.update(request_state="pending", validation_error="no material at its source yet")
        first["source"]["ndes_profile"] = "certserver1"
        renewed = {**failure, "outcome": "renewed", "message": ""}
        # state: entry, label (None: the copies' own), resume and abandon, renew
        table: tuple[tuple[Any, ...], ...] = (
            ("first enrollment waits", first, "Request pending", True, waiting),
            ("renewal waits", row(request=True), "Renewal pending", True, waiting),
            (
                "renewal failed, its request kept",
                row(request=True, renewal=failure),
                "Renewal failed",
                True,
                waiting,
            ),
            ("renewal failed, nothing kept", row(renewal=failure), "Renewal failed", False, "ndes"),
            ("renewed by the pass", row(renewal=renewed), None, False, "ndes"),
            ("renewed elsewhere, or abandoned", row(), None, False, "ndes"),
            (
                "a file imported over it, the request kept",
                row(ndes=False, request=True),
                "Renewal pending",
                True,
                "upload",
            ),
            ("a file imported over it", row(ndes=False), None, False, "upload"),
        )
        #
        # A job running on a waiting row (review 2026-10-29, round 3, B3-01):
        # the row says the job's word, and *Resume enrollment* is not drawn
        # beside the spinner - pressed again it would only meet the queue's
        # refusal of a second certificate job.
        #
        running = (
            ("a resume running", {"id": "wait.example.com", "resume": True}, "Enrolling"),
            (
                "an abandon running",
                {"id": "wait.example.com", "action": "abandon"},
                "Abandoning",
            ),
        )
        busy = "has a job running; wait for its row to settle"
        table += tuple(
            (state, row(request=True), label, False, busy, payload)
            for state, payload, label in running
        )
        pending_labels = {"Request pending", "Renewal pending", "Renewal failed"}
        for state, entry, label, waits, renew, *job in table:
            reading = with_registry(certificate_reading(), entry)
            jobs = [
                queued(operation="cert_scep", cluster=None, state="running", payload=payload)
                for payload in job
            ]
            with (
                self.subTest(state),
                mock.patch("haprion_ui.db.cluster_certificates", return_value=[reading]),
                mock.patch("haprion_ui.db.recent_jobs", return_value=jobs),
            ):
                view = registry_of(
                    certificates.with_deletion_states(
                        overview(reading), certificate_activity.deletion_states(jobs, writes=True)
                    )
                ).certificates[0]
                if label is None:
                    self.assertNotIn(view.state_label, pending_labels)
                else:
                    self.assertEqual(view.state_label, label)
                self.assertEqual(view.request_pending, waits or bool(job))
                page = (
                    self.writing_client()
                    .get("/certificates?view=registry&open=wait.example.com")
                    .text
                )
                self.assertEqual(">Resume enrollment<" in page, waits)
                self.assertEqual(
                    'form="certificate-selection" data-delete-pick data-pending' in page,
                    view.request_pending,
                )
                registry = {view.identifier: view}
                if job:
                    with self.assertRaises(certificate_renew.SelectionProblem) as refused:
                        certificate_renew.waiting_selection([view.identifier], registry)
                    self.assertIn(busy, str(refused.exception))
                elif waits:
                    self.assertIs(
                        certificate_renew.waiting_selection([view.identifier], registry), view
                    )
                else:
                    with self.assertRaises(certificate_renew.SelectionProblem):
                        certificate_renew.waiting_selection([view.identifier], registry)
                if renew in {"ndes", "upload"}:
                    self.assertEqual(
                        certificate_renew.selection([view.identifier], registry).way, renew
                    )
                else:
                    with self.assertRaises(certificate_renew.SelectionProblem) as refused:
                        certificate_renew.selection([view.identifier], registry)
                    self.assertIn(renew, str(refused.exception))

    def test_a_row_without_a_waiting_request_is_refused(self) -> None:
        client = self.writing_client()
        token = auth.csrf_token(client.cookies[auth.SESSION_COOKIE])
        response = client.post(
            "/certificates/abandon/confirm",
            data={
                "certificate": "old.example.com",
                "idempotency_key": "ffffffff-ffff-4fff-8fff-ffffffffffff",
                auth.CSRF_FIELD: token,
            },
        )
        self.assertIn("has no request waiting at the CA", response.text)
        self.assertEqual(self.queued, [])

    def test_it_has_the_form_s_gates(self) -> None:
        reader = self.writing_client(role="reader")
        token = auth.csrf_token(reader.cookies[auth.SESSION_COOKIE])
        for path in ("/certificates/abandon", "/certificates/abandon/confirm"):
            with self.subTest(path=path):
                response = reader.post(
                    path,
                    data={
                        "certificate": "wait.example.com",
                        "idempotency_key": "ffffffff-ffff-4fff-8fff-ffffffffffff",
                        auth.CSRF_FIELD: token,
                    },
                )
                self.assertEqual(response.status_code, 403)
        writer = self.writing_client()
        response = writer.post(
            "/certificates/abandon/confirm",
            data={
                "certificate": "wait.example.com",
                "idempotency_key": "ffffffff-ffff-4fff-8fff-ffffffffffff",
                auth.CSRF_FIELD: "x",
            },
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.queued, [])


class PublishingAnUnpublishedCertificate(DeleteRouteTestCase):
    def unpublished_reading(self) -> Any:
        entry = registered(
            "waiting.example.com",
            clusters=(),
            receivers=({"id": "lb-01"},),
        )
        return with_registry(certificate_reading(), entry, receivers=("lb-01",))

    def test_the_open_row_offers_publish_now_and_the_post_queues_the_existing_operation(
        self,
    ) -> None:
        with mock.patch(
            "haprion_ui.db.cluster_certificates", return_value=[self.unpublished_reading()]
        ):
            client = self.writing_client()
            page = client.get("/certificates?view=registry&open=waiting.example.com").text
            self.assertIn('status-badge-warning">Not published<', page)
            self.assertIn('action="/certificates/waiting.example.com/publish"', page)
            self.assertIn(">Publish now<", page)

            token = auth.csrf_token(client.cookies[auth.SESSION_COOKIE])
            response = client.post(
                "/certificates/waiting.example.com/publish",
                data={
                    "idempotency_key": "ffffffff-ffff-4fff-8fff-ffffffffffff",
                    auth.CSRF_FIELD: token,
                },
                follow_redirects=False,
            )

        self.assertEqual(response.status_code, 303)
        self.assertEqual(
            response.headers["location"], "/certificates?view=registry&open=waiting.example.com"
        )
        (job,) = self.queued
        self.assertEqual(job["operation"], "cert_publish")
        self.assertIsNone(job["cluster"])
        self.assertEqual(job["payload"], {"certificates": ["waiting.example.com"], "deploy": True})

    def test_publish_now_is_offered_for_a_receiver_copy_missing_behind_a_cluster(self) -> None:
        entry = registered(
            "example.com",
            fingerprint="a" * 64,
            receivers=({"id": "lb-01", "published_at": None, "current": False},),
        )
        with mock.patch(
            "haprion_ui.db.cluster_certificates",
            return_value=[with_registry(certificate_reading(), entry, receivers=("lb-01",))],
        ):
            client = self.writing_client()
            page = client.get("/certificates?view=registry&open=example.com").text
            self.assertIn('action="/certificates/example.com/publish"', page)
            self.assertIn(">Publish now<", page)
            self.assertNotIn("(older version)", page)

            token = auth.csrf_token(client.cookies[auth.SESSION_COOKIE])
            response = client.post(
                "/certificates/example.com/publish",
                data={
                    "idempotency_key": "ffffffff-ffff-4fff-8fff-ffffffffffff",
                    auth.CSRF_FIELD: token,
                },
                follow_redirects=False,
            )
        self.assertEqual(response.status_code, 303)
        (job,) = self.queued
        self.assertEqual(job["payload"], {"certificates": ["example.com"], "deploy": True})

    def test_publish_now_is_not_drawn_for_an_already_published_row(self) -> None:
        client = self.writing_client()
        page = client.get("/certificates?view=registry&open=example.com").text
        self.assertNotIn(">Publish now<", page)

        token = auth.csrf_token(client.cookies[auth.SESSION_COOKIE])
        response = client.post(
            "/certificates/example.com/publish",
            data={
                "idempotency_key": "ffffffff-ffff-4fff-8fff-ffffffffffff",
                auth.CSRF_FIELD: token,
            },
        )
        self.assertEqual(response.status_code, 409)
        self.assertEqual(self.queued, [])

    def test_publish_now_has_the_certificate_form_gates(self) -> None:
        reader = self.writing_client(role="reader")
        token = auth.csrf_token(reader.cookies[auth.SESSION_COOKIE])
        response = reader.post(
            "/certificates/waiting.example.com/publish",
            data={
                "idempotency_key": "ffffffff-ffff-4fff-8fff-ffffffffffff",
                auth.CSRF_FIELD: token,
            },
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.queued, [])

        read_only = self.writing_client(writes=False)
        token = auth.csrf_token(read_only.cookies[auth.SESSION_COOKIE])
        response = read_only.post(
            "/certificates/waiting.example.com/publish",
            data={
                "idempotency_key": "ffffffff-ffff-4fff-8fff-ffffffffffff",
                auth.CSRF_FIELD: token,
            },
        )
        self.assertEqual(response.status_code, 404)
        self.assertEqual(self.queued, [])


class PublishStates(unittest.TestCase):
    def test_a_running_publish_replaces_the_state_and_asks_for_a_refresh(self) -> None:
        state = certificate_activity.deletion_states(
            [
                queued(
                    operation="cert_publish",
                    cluster=None,
                    state="running",
                    payload={"certificates": ["waiting.example.com"], "deploy": True},
                )
            ],
            now=NOW,
            writes=True,
        )["waiting.example.com"]
        self.assertEqual((state.label, state.tone, state.active), ("Publishing", "info", True))


class AFinishedPublishGivesWayToTheRegistry(unittest.TestCase):
    """Publish now: the overlay lasts until the poller has measured, not a fixed 90 s."""

    def state(self) -> certificate_activity.DeletionState:
        job = queued(
            operation="cert_publish",
            cluster=None,
            state="done",
            payload={"certificates": ["example.com"], "deploy": True},
            result={"result": {"certificates": [{"id": "example.com", "status": "published"}]}},
            finished_at=NOW - timedelta(seconds=5),
        )
        return certificate_activity.deletion_states([job], now=NOW, writes=True)["example.com"]

    def test_published_stays_while_the_reading_still_lacks_a_copy(self) -> None:
        stale = overview(
            with_registry(
                certificate_reading(),
                registered(receivers=({"id": "lb-01", "published_at": None},)),
                receivers=("lb-01",),
            )
        )
        updated = certificates.with_deletion_states(stale, {"example.com": self.state()})
        self.assertEqual(registry_of(updated).certificates[0].state_label, "Publishing")

    def test_published_gives_way_as_soon_as_every_copy_is_current(self) -> None:
        #
        # The worker wakes the poller when the job finishes (`notify
        # cluster_changed`), so "as soon as" is seconds; the overlay used to
        # stand its whole 90 s regardless.
        #
        current = overview(
            with_registry(
                certificate_reading(),
                registered(
                    fingerprint="a" * 64,
                    receivers=(
                        {"id": "lb-01", "published_at": "2026-08-29T10:00:00Z", "current": True},
                    ),
                ),
                receivers=("lb-01",),
            ),
            status=(status(node(("example.com", "a" * 64)), node(("example.com", "a" * 64))),),
        )
        updated = certificates.with_deletion_states(current, {"example.com": self.state()})
        self.assertEqual(registry_of(updated).certificates[0].state_label, "On nodes & published")


class AJustFinishedEnrollmentIsNotUnreadable(unittest.TestCase):
    """The poller read the registry mid-job: the entry was there, the material not yet.

    The row read "Unreadable" in red until the next reading, a few seconds
    later (prod 26-10-28 07:52:59, F32). A request that has just finished
    fills that gap as it fills the one before the registry lists it.
    """

    def unreadable(self) -> CertificateOverview:
        return overview(
            with_registry(
                certificate_reading(), registered("web.example.com", kind="import", readable=False)
            )
        )

    def test_a_finished_enrollment_says_enrolled_until_the_material_is_read(self) -> None:
        job = queued(
            operation="cert_scep",
            cluster=None,
            state="done",
            payload={"id": "web.example.com", "profile": "ca", "domains": ["web.example.com"]},
            finished_at=NOW - timedelta(seconds=2),
        )
        states = certificate_activity.deletion_states([job], now=NOW, writes=True)

        updated = certificates.with_deletion_states(self.unreadable(), states)

        row = registry_of(updated).certificates[0]
        self.assertEqual((row.state_label, row.state_tone), ("Enrolled", "info"))

    def test_a_finished_request_does_the_same(self) -> None:
        states = certificate_activity.deletion_states(
            [issue_job("done", "web.example.com")], now=NOW, writes=True
        )

        updated = certificates.with_deletion_states(self.unreadable(), states)

        self.assertEqual(registry_of(updated).certificates[0].state_label, "Issued")

    def test_once_the_material_is_read_the_row_is_the_registry_s(self) -> None:
        job = queued(
            operation="cert_scep",
            cluster=None,
            state="done",
            payload={"id": "web.example.com", "profile": "ca", "domains": ["web.example.com"]},
            finished_at=NOW - timedelta(seconds=2),
        )
        read = overview(with_registry(certificate_reading(), registered("web.example.com")))

        updated = certificates.with_deletion_states(
            read, certificate_activity.deletion_states([job], now=NOW, writes=True)
        )

        self.assertNotEqual(registry_of(updated).certificates[0].state_label, "Enrolled")


class AFinishedTargetChangeGivesWayToTheRegistry(unittest.TestCase):
    def state(self) -> certificate_activity.DeletionState:
        job = queued(
            operation="cert_target",
            cluster=None,
            state="done",
            payload={
                "certificates": ["example.com"],
                "action": "remove",
                "clusters": ["beta"],
            },
            result={
                "result": {
                    "certificates": [
                        {
                            "certificate": "example.com",
                            "state": "changed",
                            "added": [],
                            "abandoned": ["beta"],
                        }
                    ]
                }
            },
            finished_at=NOW - timedelta(seconds=5),
        )
        return certificate_activity.deletion_states([job], now=NOW, writes=True)["example.com"]

    def test_removed_from_disappears_as_soon_as_the_registry_has_caught_up(self) -> None:
        current = overview(with_registry(certificate_reading(), registered(clusters=("alpha",))))
        updated = certificates.with_deletion_states(current, {"example.com": self.state()})

        self.assertNotEqual(
            registry_of(updated).certificates[0].state_label,
            "Removed from beta",
        )

    def test_removed_from_stays_while_the_registry_still_has_the_target(self) -> None:
        stale = overview(
            with_registry(certificate_reading(), registered(clusters=("alpha", "beta")))
        )
        updated = certificates.with_deletion_states(stale, {"example.com": self.state()})

        self.assertEqual(registry_of(updated).certificates[0].state_label, "Removed from beta")


CSR_TEXT = "-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----\n"


def csr_pending_row(identifier: str = "csr.example.net") -> dict[str, Any]:
    row = registered(identifier, kind="import", clusters=("alpha",), readable=False)
    row["sans"] = []
    row["validation_error"] = "no material at its source yet"
    row["request_state"] = "pending"
    row["request"] = {
        "kind": "csr",
        "domains": [identifier, "*." + identifier],
        "key_type": "ec-p256",
        "requested_at": "2026-09-21T10:30:00+00:00",
        "csr_pem": CSR_TEXT,
    }
    return row


class SigningRequestStates(unittest.TestCase):
    """A `cert_request` job (C9b): a placeholder until the listing shows the request."""

    def test_running_done_and_failed(self) -> None:
        def job(state: str, **extra: Any) -> Any:
            return queued(
                operation="cert_request",
                cluster=None,
                state=state,
                payload={
                    "id": "csr.example.net",
                    "domains": ["csr.example.net", "*.csr.example.net"],
                    "key_type": "ec-p256",
                    "clusters": ["alpha"],
                    "receivers": [],
                },
                finished_at=None if state == "running" else NOW - timedelta(minutes=5),
                **extra,
            )

        running = certificate_activity.deletion_states([job("running")], now=NOW, writes=True)
        state = running["csr.example.net"]
        self.assertEqual((state.label, state.active), ("Making request", True))
        self.assertIsNotNone(state.placeholder)
        placeholder = state.placeholder
        self.assertEqual(
            placeholder.sans if placeholder else (), ("csr.example.net", "*.csr.example.net")
        )
        self.assertTrue(placeholder.wildcard if placeholder else False)

        done = certificate_activity.deletion_states([job("done")], now=NOW, writes=True)
        self.assertEqual(done["csr.example.net"].label, "Request made")
        self.assertTrue(done["csr.example.net"].placeholder_only)

        failed = certificate_activity.deletion_states(
            [job("failed", result={"error": {"code": "already_exists", "message": "taken"}})],
            now=NOW,
            writes=True,
        )
        self.assertEqual(failed["csr.example.net"].label, "Request failed")
        self.assertIn("taken", failed["csr.example.net"].detail)

    def test_the_listing_row_carries_the_request(self) -> None:
        view = overview(with_registry(certificate_reading(), csr_pending_row()))
        row = registry_of(view).certificates[0]
        self.assertEqual((row.state_label, row.state_tone), ("Awaiting signature", "info"))
        self.assertTrue(row.csr_pending)
        self.assertEqual(row.csr_pem, CSR_TEXT)
        self.assertEqual(row.sans, ("csr.example.net", "*.csr.example.net"))
        self.assertTrue(row.wildcard)
        self.assertEqual(row.source_kind, "import")
        self.assertFalse(row.placeholder)


class ADownloadableSigningRequest(DeleteRouteTestCase):
    def test_the_row_offers_the_download_and_the_upload_and_the_route_serves_it(self) -> None:
        with mock.patch(
            "haprion_ui.db.cluster_certificates",
            return_value=[with_registry(certificate_reading(), csr_pending_row())],
        ):
            client = self.writing_client()
            page = client.get("/certificates?view=registry&open=csr.example.net").text
            self.assertIn('status-badge-info">Awaiting signature<', page)
            self.assertIn(
                'href="/certificates/csr.example.net/csr" download="csr.example.net.csr"', page
            )
            self.assertIn(">Download CSR<", page)
            self.assertNotIn(">Resume enrollment<", page)
            #
            # The row's text says the certificate is uploaded here, so the row
            # carries the upload too (review 26-10-24, 12-05).
            #
            self.assertIn(
                '<input type="hidden" name="certificate" value="csr.example.net">'
                '<button type="submit" class="secondary-button">Upload certificate…</button>',
                page,
            )
            self.assertIn("csr.example.net, *.csr.example.net", page)
            #
            # The signed certificate goes through Renew… (C9c), worded for
            # what the row waits for.
            #
            token = auth.csrf_token(client.cookies[auth.SESSION_COOKIE])
            renew = client.post(
                "/certificates/renew",
                data={"certificate": ["csr.example.net"], auth.CSRF_FIELD: token},
            ).text
            self.assertIn("<h1>Install the signed certificate for csr.example.net</h1>", renew)
            self.assertIn('action="/certificates/csr.example.net/upload"', renew)
            self.assertIn("signed for the downloaded request", renew)

            response = client.get("/certificates/csr.example.net/csr")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.text, CSR_TEXT)
            self.assertEqual(response.headers["content-type"], "application/pkcs10")
            self.assertEqual(
                response.headers["content-disposition"],
                'attachment; filename="csr.example.net.csr"',
            )
            #
            # A reader may download it: the request is public, and the row
            # is on a page a reader can see.
            #
            reader = self.writing_client(role="reader", writes=False)
            self.assertEqual(reader.get("/certificates/csr.example.net/csr").status_code, 200)
            self.assertEqual(reader.get("/certificates/example.com/csr").status_code, 404)
            self.assertEqual(reader.get("/certificates/Nope/csr").status_code, 404)

    def test_the_route_needs_a_session(self) -> None:
        client = self.client(configuration())
        response = client.get("/certificates/csr.example.net/csr", follow_redirects=False)
        self.assertEqual(response.status_code, 303)


class EveryOverlaySaysAJobThatEndedBadly(unittest.TestCase):
    """Review 2026-10-22, 1B-5: each overlay asked only for `failed`.

    A refused or unanswered certificate deploy read "Done on alpha; waiting for
    the nodes to be read again", and a refused or unanswered request vanished
    from the page as if it had never been asked.
    """

    ENDINGS = ("failed", "blocked", "unknown")

    def ended(self, operation: str, state: str, payload: dict[str, Any], **fields: Any) -> Any:
        return queued(
            operation=operation,
            cluster=fields.pop("cluster", None),
            state=state,
            outcome=state,
            payload=payload,
            result=None
            if state == "unknown"
            else {"outcome": state, "error": {"code": "refused", "message": "the CA said no"}},
            finished_at=NOW - timedelta(minutes=5),
            **fields,
        )

    def test_every_certificate_job_says_so_on_its_row(self) -> None:
        named = {"certificates": ["web.example.com"]}
        asks: dict[str, tuple[str, dict[str, Any]]] = {
            "enrollment": ("cert_scep", {"id": "web.example.com", "domains": ["web.example.com"]}),
            "import": ("cert_import", {"id": "web.example.com"}),
            "request": ("cert_request", {"id": "web.example.com", "domains": ["web.example.com"]}),
            "issue": ("cert_issue", {"domain": "web.example.com", "method": "dns-01"}),
            "renewal": ("cert_issue", {"domain": "web.example.com", "renew": True}),
            "delete": ("cert_delete", named),
            "publish": ("cert_publish", named),
            "target change": ("cert_target", {**named, "action": "add", "clusters": ["alpha"]}),
        }
        for name, (operation, payload) in asks.items():
            for state in self.ENDINGS:
                with self.subTest(name, state=state):
                    job = self.ended(operation, state, payload)

                    shown = certificate_activity.deletion_states([job], now=NOW, writes=True)

                    self.assertIn("web.example.com", shown)
                    self.assertFalse(shown["web.example.com"].active)
                    self.assertNotEqual(shown["web.example.com"].tone, "info")

    def test_a_deploy_that_did_not_finish_is_not_done(self) -> None:
        row = SimpleNamespace(identifier="web.example.com", older_copy_clusters=("alpha",))
        for state in (*self.ENDINGS, "partial"):
            with self.subTest(state):
                job = self.ended("cert_deploy", state, {}, cluster="alpha")

                shown = certificate_activity.deploy_states([row], [job], now=NOW, writes=True)

                self.assertNotIn("Done", shown["web.example.com"].detail)
                self.assertFalse(shown["web.example.com"].active)

    def test_a_refused_job_names_the_helper_s_reason(self) -> None:
        job = self.ended("cert_import", "blocked", {"id": "web.example.com"})

        shown = certificate_activity.deletion_states([job], now=NOW, writes=True)["web.example.com"]

        self.assertEqual((shown.label, shown.detail), ("Import refused", "the CA said no"))

    def test_an_enrollment_waiting_for_the_ca_is_still_not_the_job_s_to_say(self) -> None:
        job = self.ended("cert_scep", "partial", {"id": "web.example.com"})

        self.assertEqual(certificate_activity.deletion_states([job], now=NOW, writes=True), {})


class AJobThatDoesNotFinishByItself(unittest.TestCase):
    """Review 26-10-29 (rig): a held job, or one no worker holds, is not drawn as working.

    Every overlay said its verb with a spinner, and the listing refreshed
    itself, for as long as nobody answered the job on Events → Jobs.
    """

    def stuck(self, row: Any, held: bool) -> Any:
        if held:
            return replace(row, state="pending", held_since=NOW)
        return replace(
            row,
            state="running",
            lease_lapsed_since=NOW - jobs.NO_WORKER_AFTER - timedelta(minutes=1),
        )

    def cases(self) -> list[tuple[str, Any, str]]:
        names = {"certificates": ["web.example.com"]}
        scep = {"id": "web.example.com", "domains": ["web.example.com"]}
        return [
            (
                "enrollment",
                queued(operation="cert_scep", cluster=None, payload=scep),
                "web.example.com",
            ),
            (
                "abandon",
                queued(operation="cert_scep", cluster=None, payload={**scep, "action": "abandon"}),
                "web.example.com",
            ),
            (
                "import",
                queued(operation="cert_import", cluster=None, payload=scep),
                "web.example.com",
            ),
            (
                "request",
                queued(operation="cert_request", cluster=None, payload=scep),
                "web.example.com",
            ),
            ("issue", issue_job("pending"), "new.example.com"),
            (
                "renewal",
                replace(
                    issue_job("pending"), payload={**issue_job("pending").payload, "renew": True}
                ),
                "new.example.com",
            ),
            (
                "publish",
                queued(operation="cert_publish", cluster=None, payload=names),
                "web.example.com",
            ),
            (
                "target",
                queued(operation="cert_target", cluster=None, payload={**names, "action": "add"}),
                "web.example.com",
            ),
            (
                "delete",
                queued(operation="cert_delete", cluster=None, payload=names),
                "web.example.com",
            ),
        ]

    def test_each_overlay_says_held_or_no_worker_in_its_tone_and_stops_refreshing(self) -> None:
        for name, row, identifier in self.cases():
            for held, label, tone in (
                (True, jobs.HELD, "warning"),
                (False, jobs.NO_WORKER, "critical"),
            ):
                with self.subTest(name, held=held):
                    asked = certificate_activity.deletion_states(
                        [self.stuck(row, held)], now=NOW, writes=True
                    )[identifier]
                    working = certificate_activity.deletion_states([row], now=NOW, writes=True)[
                        identifier
                    ]
                    self.assertEqual((asked.label, asked.tone, asked.active), (label, tone, False))
                    self.assertEqual(asked.placeholder, working.placeholder)

    def test_a_deploy_from_the_row_says_so_too(self) -> None:
        row = SimpleNamespace(identifier="web.example.com", older_copy_clusters=("alpha",))
        deploy = queued(operation="cert_deploy", cluster="alpha", state="running")
        for held, label, tone in (
            (True, jobs.HELD, "warning"),
            (False, jobs.NO_WORKER, "critical"),
        ):
            with self.subTest(held=held):
                asked = certificate_activity.deploy_states(
                    [row], [self.stuck(deploy, held)], now=NOW, writes=True
                )["web.example.com"]
                self.assertEqual((asked.label, asked.tone, asked.active), (label, tone, False))


class TheListingDoesNotWaitForAJobThatDoesNotFinish(DeleteRouteTestCase):
    def test_a_held_deletion_neither_spins_nor_refreshes_the_page(self) -> None:
        """Review 26-10-29 (rig): *Deleting* spun and the page refreshed until answered."""

        row = replace(delete_job("pending", "old.example.com"), held_since=datetime.now(UTC))
        with mock.patch("haprion_ui.db.recent_jobs", return_value=[row]):
            page = self.writing_client().get("/certificates").text
        self.assertNotIn('data-refresh="true"', page)
        self.assertIn('<span class="status-badge status-badge-warning">Held</span>', page)
        self.assertNotIn(">Deleting<", page)

    def test_with_writes_off_a_job_that_stands_still_is_not_called_workerless(self) -> None:
        """Review 26-10-30 (F2): the listing followed the rule only with writes on."""

        row = replace(
            delete_job("running", "old.example.com"),
            lease_lapsed_since=datetime.now(UTC) - jobs.NO_WORKER_AFTER - timedelta(minutes=1),
        )
        for writes, said in ((True, True), (False, False)):
            with self.subTest(writes=writes):
                with mock.patch("haprion_ui.db.recent_jobs", return_value=[row]):
                    page = self.writing_client(writes=writes).get("/certificates").text
                self.assertEqual("No worker" in page, said)
