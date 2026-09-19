"""Publish to… and Remove from…: the two buttons, the question, the job.

The interface's half of the 2026-09-15 target change: the same boxes as the
deletion, two more buttons that post them to a page asking which targets,
and one `cert_target` job carrying the selection and one delta. The engine's
guards are tested with the engine; the draft refusal is this side's.
"""

from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest import mock
from uuid import uuid4

from haproxy_ui import auth, certificate_activity, certificate_retarget, db
from tests.test_certificate_delete import SHOP_DRAFT, DeleteRouteTestCase
from tests.test_certificates import reading as certificate_reading
from tests.test_certificates import registered, with_registry
from tests.test_login import configuration
from tests.test_queue_route import queued

NOW = datetime(2026, 9, 15, 20, 0, tzinfo=UTC)


class RetargetRouteTestCase(DeleteRouteTestCase):
    """Two clusters and a receiver, so there is somewhere to publish to."""

    def setUp(self) -> None:
        super().setUp()
        patch = mock.patch(
            "haproxy_ui.db.cluster_certificates",
            return_value=[
                with_registry(
                    certificate_reading(),
                    registered(fingerprint="a" * 64),
                    registered("old.example.com", fingerprint="b" * 64, clusters=("alpha", "beta")),
                    registered(
                        "imported.example",
                        kind="import",
                        fingerprint="d" * 64,
                        receivers=({"id": "lb-01"},),
                    ),
                    receivers=("lb-01",),
                )
            ],
        )
        patch.start()
        self.addCleanup(patch.stop)

    def writing_client(self, *, role: str = "admin", writes: bool = True) -> Any:
        self.account = replace(self.account, role=role)
        client = self.client(
            replace(configuration(), management_writes=writes, clusters=("alpha", "beta"))
        )
        self.sign_in(client)
        return client

    def review(self, client: Any, action: str, *ids: str) -> Any:  # type: ignore[override]
        token = auth.csrf_token(client.cookies[auth.SESSION_COOKIE])
        return client.post(
            f"/certificates/targets/{action}",
            data={"certificate": list(ids), auth.CSRF_FIELD: token},
        )

    def confirm(  # type: ignore[override]
        self,
        client: Any,
        action: str,
        *ids: str,
        clusters: tuple[str, ...] = (),
        receivers: tuple[str, ...] = (),
        formats: tuple[str, ...] = (),
    ) -> Any:
        token = auth.csrf_token(client.cookies[auth.SESSION_COOKIE])
        return client.post(
            f"/certificates/targets/{action}/confirm",
            data={
                "certificate": list(ids),
                "cluster": list(clusters),
                "receiver": list(receivers),
                "format": list(formats),
                "idempotency_key": str(uuid4()),
                auth.CSRF_FIELD: token,
            },
            follow_redirects=False,
        )


class TheRegistryViewOffersTheButtons(RetargetRouteTestCase):
    def test_three_buttons_share_the_boxes_and_all_start_grey(self) -> None:
        page = self.writing_client().get("/certificates?view=registry").text
        self.assertIn(
            'formaction="/certificates/targets/add" data-delete-submit disabled>Publish to…', page
        )
        self.assertIn(
            'formaction="/certificates/targets/remove" data-delete-submit disabled>Remove from…',
            page,
        )
        self.assertIn("data-delete-submit disabled>Delete selected", page)


class TheQuestion(RetargetRouteTestCase):
    def test_publish_offers_what_some_chosen_certificate_is_not_on_yet(self) -> None:
        page = self.review(self.writing_client(), "add", "example.com", "old.example.com").text
        self.assertIn("<h1>Publish to</h1>", page)
        self.assertIn('name="cluster" value="beta"', page)
        self.assertIn("1 of 2 already there", page)
        self.assertIn('name="receiver" value="lb-01"', page)
        # Every chosen certificate is on alpha already: shown ticked and locked, not offered.
        self.assertNotIn('name="cluster" value="alpha"', page)
        self.assertIn(
            '<label class="check target-row target-held" title="Already published to every '
            'selected certificate">',
            page,
        )
        self.assertIn('<input type="checkbox" checked disabled> <span>alpha</span>', page)
        self.assertIn('<span class="target-effect optional">already published</span>', page)
        self.assertIn("reload HAProxy", page)

    def test_remove_offers_only_what_some_chosen_certificate_is_on(self) -> None:
        page = self.review(self.writing_client(), "remove", "example.com", "imported.example").text
        self.assertIn("<h1>Remove from</h1>", page)
        self.assertIn('name="cluster" value="alpha"', page)
        self.assertIn("1 of 2 are on it", page)
        self.assertIn('name="receiver" value="lb-01"', page)
        self.assertNotIn('name="cluster" value="beta"', page)
        self.assertIn("No reload", page)

    def test_a_draft_is_noted_on_the_row_for_a_remove_only(self) -> None:
        self.drafts = [SHOP_DRAFT]
        page = self.review(self.writing_client(), "remove", "old.example.com").text
        self.assertIn("A draft names it: alpha/shop", page)
        page = self.review(self.writing_client(), "add", "old.example.com").text
        self.assertNotIn("A draft names it", page)

    def test_an_unknown_action_id_or_empty_selection_is_said(self) -> None:
        client = self.writing_client()
        self.assertEqual(self.review(client, "replace", "example.com").status_code, 404)
        self.assertIn(
            "Not in the registry: nobody.example", self.review(client, "add", "nobody.example").text
        )
        self.assertIn("Nothing is selected", self.review(client, "add").text)

    def test_the_gates_are_the_deletion_page_s(self) -> None:
        self.assertEqual(
            self.review(self.writing_client(role="reader"), "add", "example.com").status_code, 403
        )
        self.assertEqual(
            self.review(self.writing_client(writes=False), "add", "example.com").status_code, 404
        )


class Confirming(RetargetRouteTestCase):
    def test_queues_one_clusterless_job_with_the_ids_and_the_delta(self) -> None:
        response = self.confirm(
            self.writing_client(),
            "add",
            "example.com",
            "old.example.com",
            clusters=("beta",),
            receivers=("lb-01",),
        )
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/certificates?view=registry")
        (job,) = self.queued
        self.assertEqual(job["operation"], "cert_target")
        self.assertIsNone(job["cluster"])
        self.assertEqual(
            job["payload"],
            {
                "certificates": ["example.com", "old.example.com"],
                "action": "add",
                "clusters": ["beta"],
                "receivers": ["lb-01"],
            },
        )
        self.assertIn("queue_job", self.audit)

    def test_an_added_receiver_carries_its_format_and_a_removal_never_does(self) -> None:
        response = self.confirm(
            self.writing_client(),
            "add",
            "example.com",
            receivers=("lb-01",),
            formats=("lb-01=pkcs12",),
        )
        self.assertEqual(response.status_code, 303, response.text)
        (job,) = self.queued
        self.assertEqual(job["payload"]["formats"], {"lb-01": "pkcs12"})
        self.queued.clear()

        response = self.confirm(
            self.writing_client(),
            "remove",
            "imported.example",
            receivers=("lb-01",),
            formats=("lb-01=pkcs12",),
        )
        self.assertEqual(response.status_code, 303, response.text)
        (job,) = self.queued
        self.assertNotIn("formats", job["payload"])

    def test_the_question_offers_the_format_beside_an_added_receiver_only(self) -> None:
        page = self.review(self.writing_client(), "add", "example.com").text
        self.assertIn('aria-label="Format for lb-01"', page)
        page = self.review(self.writing_client(), "remove", "imported.example").text
        self.assertNotIn('aria-label="Format for', page)

    def test_a_target_not_offered_is_dropped_and_an_empty_choice_asks_again(self) -> None:
        # alpha is on every chosen certificate, so an add to it is not offered.
        response = self.confirm(self.writing_client(), "add", "example.com", clusters=("alpha",))
        self.assertEqual(response.status_code, 200)
        self.assertIn("Choose at least one target", response.text)
        self.assertEqual(self.queued, [])

    def test_a_draft_in_the_dropped_cluster_refuses_the_remove(self) -> None:
        self.drafts = [SHOP_DRAFT]
        response = self.confirm(
            self.writing_client(), "remove", "old.example.com", clusters=("alpha",)
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(
            "a draft still names a certificate: old.example.com by alpha/shop", response.text
        )
        self.assertEqual(self.queued, [])
        # The other cluster is not held by it.
        response = self.confirm(
            self.writing_client(), "remove", "old.example.com", clusters=("beta",)
        )
        self.assertEqual(response.status_code, 303)
        self.assertEqual(self.queued[0]["payload"]["clusters"], ["beta"])

    def test_a_busy_certificate_slot_is_said_on_the_page(self) -> None:
        with mock.patch("haproxy_ui.db.queue_job", side_effect=db.CertificateBusy()):
            response = self.confirm(
                self.writing_client(), "remove", "old.example.com", clusters=("beta",)
            )
        self.assertEqual(response.status_code, 200)
        self.assertIn("already running", response.text)


class TheStateCellFollowsTheJob(unittest.TestCase):
    def job(self, state: str, action: str = "add", result: Any = None, age: int = 0) -> Any:
        return queued(
            operation="cert_target",
            cluster=None,
            state=state,
            payload={
                "certificates": ["a.example", "b.example"],
                "action": action,
                "clusters": ["beta"],
            },
            result=result,
            finished_at=None if state in {"pending", "running"} else NOW - timedelta(seconds=age),
        )

    def states(self, *jobs: Any) -> dict[str, certificate_activity.DeletionState]:
        return certificate_activity.deletion_states(jobs, now=NOW)

    def test_running_and_each_verdict(self) -> None:
        running = self.states(self.job("running"))
        self.assertEqual(
            (running["a.example"].label, running["a.example"].active), ("Publishing", True)
        )
        self.assertEqual(
            self.states(self.job("running", "remove"))["a.example"].label, "Removing from targets"
        )

        done = self.states(
            self.job(
                "partial",
                result={
                    "certificates": [
                        {
                            "certificate": "a.example",
                            "state": "changed",
                            "added": ["beta"],
                            "abandoned": [],
                        },
                        {
                            "certificate": "b.example",
                            "state": "refused",
                            "added": [],
                            "abandoned": [],
                            "code": "cluster_default",
                            "reason": "the default certificate of beta; choose another first",
                        },
                    ]
                },
            )
        )
        self.assertEqual(done["a.example"].label, "Published to beta")
        self.assertTrue(done["a.example"].active)
        self.assertEqual(done["b.example"].label, "Target change refused")
        self.assertIn("default certificate of beta", done["b.example"].detail)
        self.assertFalse(done["b.example"].active)

    def test_a_changed_row_stops_refreshing_after_the_poller_has_had_its_turn(self) -> None:
        result = {
            "certificates": [
                {"certificate": "a.example", "state": "changed", "added": [], "abandoned": ["beta"]}
            ]
        }
        later = self.states(self.job("done", "remove", result=result, age=120))["a.example"]
        self.assertEqual(later.label, "Removed from beta")
        self.assertFalse(later.active)
        self.assertNotIn(
            "a.example", self.states(self.job("done", "remove", result=result, age=3700))
        )


class TheSelectionModel(unittest.TestCase):
    def test_the_payload_keeps_only_offered_and_well_formed_targets(self) -> None:
        picked = certificate_retarget.Selection(
            "add",
            (certificate_retarget.Row("a.example", "Certbot", ("alpha",), ()),),
            (
                certificate_retarget.Choice("beta", "cluster", 0),
                certificate_retarget.Choice("lb-01", "receiver", 0),
            ),
        )
        body = certificate_retarget.payload(picked, ("beta", "gamma", "../x", "beta"), ("lb-01",))
        self.assertEqual(body["clusters"], ["beta"])
        self.assertEqual(body["receivers"], ["lb-01"])
        self.assertNotIn("formats", body)
        body = certificate_retarget.payload(
            picked, (), ("lb-01",), ("lb-01=pkcs12", "lb-02=pkcs12")
        )
        self.assertEqual(body["formats"], {"lb-01": "pkcs12"})
        with self.assertRaises(certificate_retarget.SelectionProblem):
            certificate_retarget.payload(picked, (), ("lb-01",), ("lb-01=der",))
        with self.assertRaises(certificate_retarget.SelectionProblem):
            certificate_retarget.payload(picked, ("gamma",), ())
