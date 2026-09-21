"""The State cell follows the deletion job; the page refreshes while it does."""

from __future__ import annotations

import unittest
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest import mock

from haproxy_ui import auth, certificate_activity, certificates
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
        states = certificate_activity.deletion_states([published], now=NOW)
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
        states = certificate_activity.deletion_states([quiet, failed], now=NOW)
        self.assertNotIn("hq.example", states)


class EnrollmentStates(unittest.TestCase):
    def test_a_running_enrollment_and_a_fresh_failure_are_overlays(self) -> None:
        running = queued(
            operation="cert_scep",
            cluster=None,
            state="running",
            payload={"id": "web.example.com", "profile": "certserver1", "domains": ["web.example.com"]},
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
        states = certificate_activity.deletion_states([running, failed, pending], now=NOW)
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
        return certificate_activity.deletion_states(jobs, now=NOW)

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
            "haproxy_ui.db.recent_jobs", return_value=[issue_job("running", "*.brand.example")]
        ):
            page = self.writing_client().get("/certificates?open=brand.example").text
        self.assertIn('data-certificates-region data-refresh="true"', page)
        self.assertNotIn('http-equiv="refresh"', page)
        self.assertIn(
            'status-badge-info"><span class="badge-spinner" aria-hidden="true"></span>Requesting<',
            page,
        )
        self.assertIn("<strong>brand.example</strong>", page)
        self.assertIn("*.brand.example, brand.example", page)
        # No box to tick and no expiry badge: there is nothing yet.
        self.assertNotIn('value="brand.example" data-delete-pick', page)
        self.assertIn("The CA is being asked for the certificate", page)
        self.assertIn('<td data-label="Expires">—</td>', page)
        # First in the table: the newest thing on the page.
        self.assertLess(
            page.index("<strong>brand.example</strong>"), page.index("<strong>example.com</strong>")
        )

    def test_a_listed_certificate_keeps_its_own_state_once_the_request_is_done(self) -> None:
        listed = with_registry(certificate_reading(), registered("new.example.com", kind="acme"))
        with (
            mock.patch("haproxy_ui.db.recent_jobs", return_value=[issue_job("done")]),
            mock.patch("haproxy_ui.db.cluster_certificates", return_value=[listed]),
        ):
            page = self.writing_client().get("/certificates").text
        self.assertNotIn('">Issued<', page)
        self.assertEqual(page.count("<strong>new.example.com</strong>"), 1)

    def test_a_deleting_row_shows_the_badge_and_the_page_refreshes(self) -> None:
        with mock.patch(
            "haproxy_ui.db.recent_jobs", return_value=[delete_job("running", "old.example.com")]
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
            "haproxy_ui.db.cluster_certificates",
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
            "haproxy_ui.db.cluster_certificates", return_value=[self.unpublished_reading()]
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
            "haproxy_ui.db.cluster_certificates",
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
        return certificate_activity.deletion_states([job], now=NOW)["example.com"]

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
        return certificate_activity.deletion_states([job], now=NOW)["example.com"]

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

        running = certificate_activity.deletion_states([job("running")], now=NOW)
        state = running["csr.example.net"]
        self.assertEqual((state.label, state.active), ("Making request", True))
        self.assertIsNotNone(state.placeholder)
        placeholder = state.placeholder
        self.assertEqual(
            placeholder.sans if placeholder else (), ("csr.example.net", "*.csr.example.net")
        )
        self.assertTrue(placeholder.wildcard if placeholder else False)

        done = certificate_activity.deletion_states([job("done")], now=NOW)
        self.assertEqual(done["csr.example.net"].label, "Request made")
        self.assertTrue(done["csr.example.net"].placeholder_only)

        failed = certificate_activity.deletion_states(
            [job("failed", result={"error": {"code": "already_exists", "message": "taken"}})],
            now=NOW,
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
            "haproxy_ui.db.cluster_certificates",
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
