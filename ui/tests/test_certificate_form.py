"""The certificate form: what it accepts, what it refuses, and what it queues.

Two halves. The module turns a submission into a `cert_issue` payload or a
sentence, and it is tested on its own because the sentences are the product:
each one is what a person reads instead of a failed job on another page. The
route is tested as HTTP because it is the control - a page that does not draw
the button is a courtesy, and what stops a reader or a stale form is here.
"""

from __future__ import annotations

import unittest
from dataclasses import replace
from typing import Any
from unittest import mock
from uuid import UUID, uuid4

from haproxy_ui import auth, certificate_form, db
from tests.test_certificates import reading as certificate_reading
from tests.test_certificates import registered, with_registry
from tests.test_login import LoginTestCase, configuration
from tests.test_queue_route import queued

CHOICES = certificate_form.IssueChoices(
    clusters=("alpha", "beta"), receivers=("lb-01.example.net",)
)


def form(**overrides: Any) -> certificate_form.IssueForm:
    fields: dict[str, Any] = {
        "domain": "app.example.com",
        "method": "dns-01",
        "clusters": ("alpha",),
        "receivers": (),
    }
    return certificate_form.IssueForm(**{**fields, **overrides})


def problem_of(submission: certificate_form.IssueForm) -> str:
    try:
        certificate_form.payload_from_form(submission, CHOICES)
    except certificate_form.FormProblem as problem:
        return str(problem)
    raise AssertionError("the form accepted a submission it should have refused")


class WhatTheFormAccepts(unittest.TestCase):
    def test_a_name_a_method_and_a_cluster_become_the_engine_payload(self) -> None:
        payload = certificate_form.payload_from_form(form(), CHOICES)

        self.assertEqual(
            payload,
            {
                "domain": "app.example.com",
                "method": "dns-01",
                "clusters": ["alpha"],
                "receivers": [],
            },
        )

    def test_the_name_is_trimmed_lowercased_and_stripped_of_its_dot(self) -> None:
        #
        # The name becomes a lineage, a file and a registry key, and none of
        # them wants "App.Example.COM." - but a person pasting one should not
        # be sent back for it.
        #
        payload = certificate_form.payload_from_form(form(domain="  App.Example.COM. "), CHOICES)

        self.assertEqual(payload["domain"], "app.example.com")

    def test_a_wildcard_over_dns_is_accepted(self) -> None:
        payload = certificate_form.payload_from_form(form(domain="*.example.com"), CHOICES)

        self.assertEqual(payload["domain"], "*.example.com")

    def test_receivers_alone_are_a_target(self) -> None:
        payload = certificate_form.payload_from_form(
            form(clusters=(), receivers=("lb-01.example.net",)), CHOICES
        )

        self.assertEqual(payload["clusters"], [])
        self.assertEqual(payload["receivers"], ["lb-01.example.net"])

    def test_a_target_ticked_twice_is_one_target(self) -> None:
        payload = certificate_form.payload_from_form(form(clusters=("alpha", "alpha")), CHOICES)

        self.assertEqual(payload["clusters"], ["alpha"])


class WhatTheFormRefuses(unittest.TestCase):
    def test_an_empty_name(self) -> None:
        self.assertIn("domain name is required", problem_of(form(domain="")))

    def test_a_name_the_engine_would_not_issue_for(self) -> None:
        #
        # The engine's rule, not a second one: the same call the helper makes.
        # A name with a space, an underscore or one label fails there, and so
        # fails here, without naming what was typed.
        #
        for bad in ("not a name", "under_score.example.com", "localhost", "*.*.example.com"):
            with self.subTest(bad=bad):
                sentence = problem_of(form(domain=bad))
                self.assertIn("not a domain name", sentence)
                self.assertNotIn(bad, sentence)

    def test_a_wildcard_over_http(self) -> None:
        #
        # The one rule a reader can act on before pressing the button, said
        # here rather than by a failed job on another page.
        #
        self.assertIn(
            "wildcard certificate needs DNS-01",
            problem_of(form(domain="*.example.com", method="http-01")),
        )

    def test_an_unknown_method(self) -> None:
        self.assertIn("Choose a challenge method", problem_of(form(method="tls-alpn-01")))

    def test_no_target_at_all(self) -> None:
        self.assertIn("at least one target", problem_of(form(clusters=(), receivers=())))

    def test_a_cluster_that_was_not_offered(self) -> None:
        self.assertIn("not a cluster this manager has", problem_of(form(clusters=("gamma",))))

    def test_a_receiver_that_was_not_offered_is_sent_to_the_manager(self) -> None:
        #
        # A receiver is a directory, an account and a key; a name typed into
        # a form is none of those. The sentence says where one is made.
        #
        sentence = problem_of(form(receivers=("server724.example.net",)))

        self.assertIn("not registered", sentence)
        self.assertIn("on the manager", sentence)
        self.assertNotIn("server724", sentence)


KEY = str(uuid4())


class CertificateFormRouteTestCase(LoginTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.queued: list[dict[str, Any]] = []

        def queue(_c: object, **fields: Any) -> db.Job:
            self.queued.append(fields)
            return queued(operation="cert_issue", cluster=None)

        for patch in (
            mock.patch("haproxy_ui.db.queue_job", side_effect=queue),
            mock.patch(
                "haproxy_ui.db.cluster_certificates",
                return_value=[
                    with_registry(
                        certificate_reading(),
                        registered(fingerprint="a" * 64),
                        receivers=("lb-01.example.net",),
                    )
                ],
            ),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def writing_client(self, *, role: str = "admin") -> Any:
        self.account = replace(self.account, role=role)
        client = self.client(
            replace(configuration(), management_writes=True, clusters=("alpha", "beta"))
        )
        self.sign_in(client)
        return client

    def post(self, client: Any, **fields: Any) -> Any:
        token = auth.csrf_token(client.cookies[auth.SESSION_COOKIE])
        data: dict[str, Any] = {
            "domain": "app.example.com",
            "method": "dns-01",
            "cluster": ["alpha"],
            "idempotency_key": KEY,
            auth.CSRF_FIELD: token,
        }
        data.update(fields)
        return client.post("/certificates/new", data=data, follow_redirects=False)


class TheFormPage(CertificateFormRouteTestCase):
    def test_it_offers_the_clusters_and_the_registered_receivers_as_boxes(self) -> None:
        page = self.writing_client().get("/certificates/new").text

        self.assertIn('name="cluster" value="alpha"', page)
        self.assertIn('name="cluster" value="beta"', page)
        self.assertIn('name="receiver" value="lb-01.example.net"', page)
        #
        # No free-text receiver: one is registered on the manager, and the
        # page says so where the boxes are.
        #
        self.assertNotIn('name="receiver" type="text"', page)
        self.assertIn("registered on the manager, not here", page)
        self.assertIn("Request the certificate", page)

    def test_the_listing_links_to_it_for_an_admin_only(self) -> None:
        self.assertIn('href="/certificates/new"', self.writing_client().get("/certificates").text)
        self.assertNotIn(
            'href="/certificates/new"',
            self.writing_client(role="reader").get("/certificates").text,
        )

    def test_it_is_not_there_when_writes_are_off_and_refused_to_a_reader(self) -> None:
        client = self.client(configuration())
        self.sign_in(client)
        self.assertEqual(client.get("/certificates/new").status_code, 404)
        self.assertEqual(
            self.writing_client(role="reader").get("/certificates/new").status_code, 403
        )

    def test_a_running_certificate_job_is_said_and_the_button_held(self) -> None:
        with mock.patch(
            "haproxy_ui.db.recent_jobs",
            return_value=[queued(operation="cert_issue", cluster=None, state="running")],
        ):
            page = self.writing_client().get("/certificates/new").text

        self.assertIn("Issuing certificate is in progress", page)
        self.assertIn("disabled>Request the certificate", page)


class SendingTheForm(CertificateFormRouteTestCase):
    def test_a_good_submission_queues_one_cert_issue_job_with_no_cluster(self) -> None:
        response = self.post(self.writing_client())

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/jobs")
        self.assertEqual(len(self.queued), 1)
        job = self.queued[0]
        self.assertEqual(job["operation"], "cert_issue")
        self.assertIsNone(job["cluster"])
        self.assertEqual(job["idempotency_key"], UUID(KEY))
        self.assertEqual(
            job["payload"],
            {
                "domain": "app.example.com",
                "method": "dns-01",
                "clusters": ["alpha"],
                "receivers": [],
            },
        )
        self.assertIn("queue_job", self.audit)

    def test_a_refused_submission_is_the_form_again_with_the_typed_values(self) -> None:
        response = self.post(
            self.writing_client(), domain="*.example.com", method="http-01", cluster=["beta"]
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("wildcard certificate needs DNS-01", response.text)
        self.assertIn('value="*.example.com"', response.text)
        self.assertIn('value="http-01" checked', response.text)
        self.assertIn('value="beta" checked', response.text)
        self.assertEqual(self.queued, [])

    def test_a_receiver_typed_rather_than_ticked_queues_nothing(self) -> None:
        response = self.post(self.writing_client(), receiver=["server724.example.net"])

        self.assertEqual(response.status_code, 200)
        self.assertIn("not registered", response.text)
        self.assertEqual(self.queued, [])

    def test_a_busy_certificate_slot_is_a_sentence_on_the_form(self) -> None:
        with mock.patch("haproxy_ui.db.queue_job", side_effect=db.CertificateBusy()):
            response = self.post(self.writing_client())

        self.assertEqual(response.status_code, 200)
        self.assertIn("already running", response.text)

    def test_the_four_refusals_come_before_the_form_is_read(self) -> None:
        client = self.client(configuration())
        self.sign_in(client)
        self.assertEqual(self.post(client).status_code, 404)
        self.assertEqual(self.post(self.writing_client(role="reader")).status_code, 403)
        self.assertEqual(
            self.post(self.writing_client(), **{auth.CSRF_FIELD: "stale"}).status_code, 403
        )
        self.assertEqual(self.post(self.writing_client(), idempotency_key="x").status_code, 400)
        self.assertEqual(self.queued, [])


if __name__ == "__main__":
    unittest.main()
