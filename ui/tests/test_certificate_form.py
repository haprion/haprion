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
from datetime import UTC, datetime
from pathlib import Path
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

    def test_a_receiver_s_format_travels_beside_the_receivers(self) -> None:
        """B159: PKCS#12 is stated per receiver; PEM is the default and is not carried."""

        payload = certificate_form.payload_from_form(
            form(
                clusters=(),
                receivers=("lb-01.example.net",),
                formats=("lb-01.example.net=pkcs12",),
            ),
            CHOICES,
        )
        self.assertEqual(payload["formats"], {"lb-01.example.net": "pkcs12"})

        payload = certificate_form.payload_from_form(
            form(clusters=(), receivers=("lb-01.example.net",), formats=("lb-01.example.net=pem",)),
            CHOICES,
        )
        self.assertNotIn("formats", payload)

    def test_a_format_for_an_unticked_receiver_is_dropped_and_a_bad_one_refused(self) -> None:
        # Every receiver's select is submitted; only the ticked ones count.
        payload = certificate_form.payload_from_form(
            form(formats=("lb-01.example.net=pkcs12",)), CHOICES
        )
        self.assertNotIn("formats", payload)
        self.assertIn(
            "PEM or PKCS#12",
            problem_of(
                form(
                    clusters=(),
                    receivers=("lb-01.example.net",),
                    formats=("lb-01.example.net=der",),
                )
            ),
        )

    def test_a_target_ticked_twice_is_one_target(self) -> None:
        payload = certificate_form.payload_from_form(form(clusters=("alpha", "alpha")), CHOICES)

        self.assertEqual(payload["clusters"], ["alpha"])

    def test_an_in_effect_profile_becomes_the_only_dns_credential_reference(self) -> None:
        choices = replace(CHOICES, dns_profiles=("cf-main",), profiles_required=True)
        payload = certificate_form.payload_from_form(form(dns_profile="cf-main"), choices)

        self.assertEqual(payload["dns_profile"], "cf-main")


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

    def test_dns_needs_a_profile_that_is_in_effect_once_profiles_are_enabled(self) -> None:
        choices = replace(CHOICES, dns_profiles=("cf-main",), profiles_required=True)
        for submission in (form(), form(dns_profile="old-profile")):
            with (
                self.subTest(profile=submission.dns_profile),
                self.assertRaises(certificate_form.FormProblem),
            ):
                certificate_form.payload_from_form(submission, choices)

    def test_http_refuses_a_dns_profile(self) -> None:
        with self.assertRaisesRegex(certificate_form.FormProblem, "belongs to DNS-01"):
            certificate_form.payload_from_form(
                form(method="http-01", dns_profile="cf-main"), CHOICES
            )


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
        self.assertIn("Receiver setup is described in the installation guide", page)
        # The format select beside the box, PEM selected until chosen otherwise.
        self.assertIn(
            '<select name="format" class="receiver-format" aria-label="Format for lb-01.example.net">'
            '<option value="lb-01.example.net=pem" selected>PEM pair</option>'
            '<option value="lb-01.example.net=pkcs12">PKCS#12 + password</option></select>',
            page,
        )
        self.assertIn("0 selected", page)
        self.assertNotIn("data-receiver-search", page)
        self.assertIn("Request the certificate", page)

    def test_a_large_receiver_registry_gets_the_searchable_bounded_picker(self) -> None:
        receivers = tuple(f"receiver-{number:02}.example.net" for number in range(28))
        reading = [
            with_registry(
                certificate_reading(), registered(fingerprint="a" * 64), receivers=receivers
            )
        ]
        with mock.patch("haproxy_ui.db.cluster_certificates", return_value=reading):
            page = self.writing_client().get("/certificates/new").text

        self.assertEqual(page.count(" data-receiver-option>"), 28)
        self.assertIn("data-receiver-search hidden", page)
        self.assertIn("receiver-options-many", page)

    def test_validation_guidance_sits_at_the_top_and_the_form_has_no_cluster_accent(self) -> None:
        page = self.writing_client().get("/certificates/new").text

        self.assertIn('class="challenge-warning certificate-guidance"', page)
        self.assertIn(
            "Certificate validation requires some knowledge of the chosen CA.",
            page,
        )
        self.assertIn("the domain must already point here", page)
        #
        # Three lines: the general sentence, the two Let's Encrypt challenges,
        # the NDES one - the reader picks the line for the CA they chose.
        #
        self.assertIn("the chosen CA.<br>DNS-01:", page)
        self.assertIn("point here.<br>NDES:", page)
        self.assertNotIn("Provide DNS access", page)
        self.assertIn("Let's Encrypt; DNS record, wildcards", page)
        self.assertIn("Let's Encrypt; webroot, single names", page)
        self.assertNotIn("Asks the ACME account", page)
        self.assertNotIn("cluster-accent-", page)

    def test_the_profile_field_is_greyed_under_http_01_and_the_page_wires_it(self) -> None:
        client = self.writing_client()
        page = client.get("/certificates/new").text
        self.assertIn("certificate-form.js", page)
        self.assertIn('<div class="field profile-field" data-profile-field>', page)
        self.assertIn(
            '<select name="dns_profile" class="dns-only" aria-labelledby="profile-field-title">',
            page,
        )
        #
        # One field for the reader: the NDES select is there for the server
        # but hidden until its CA is chosen, and only one hint shows.
        #
        self.assertIn(
            '<select name="ndes_profile" class="ndes-only" aria-labelledby="profile-field-title" disabled hidden>',
            page,
        )
        self.assertIn('<small data-profile-hint="dns-01">Required for DNS-01.', page)
        self.assertIn(
            '<small data-profile-hint="http-01" hidden>Not used with HTTP-01.</small>', page
        )
        self.assertEqual(page.count("Provider profile</span>"), 1)

        #
        # A refused HTTP-01 form is redrawn with the choice kept, so the
        # server draws the field the way the script would have: disabled.
        #
        page = self.post(client, domain="*.example.com", method="http-01").text
        self.assertIn(
            '<select name="dns_profile" class="dns-only" aria-labelledby="profile-field-title" disabled>',
            page,
        )
        self.assertIn('<small data-profile-hint="http-01">Not used with HTTP-01.</small>', page)
        self.assertIn('<small data-profile-hint="dns-01" hidden>', page)

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

    def test_only_an_in_effect_dns_profile_is_offered(self) -> None:
        now = datetime.now(UTC)
        profile = db.DnsProfile(
            "cf-main",
            "Cloudflare",
            "cloudflare",
            1,
            "0123456789abcdef",
            2,
            now,
            "admin",
            now,
            "admin",
        )
        config = replace(
            configuration(),
            management_writes=True,
            clusters=("alpha", "beta"),
            dns_profiles_public_key=Path("/example/public.key"),
        )
        ndes = replace(profile, id="certserver1", name="certserver1", provider_id="ndes", revision=1)
        applied = queued(
            operation="dns_profile_apply",
            cluster=None,
            state="done",
            payload={"profile": "cf-main", "revision": 2},
        )
        with (
            mock.patch("haproxy_ui.db.dns_profiles", return_value=[profile]),
            mock.patch("haproxy_ui.db.ndes_profiles", return_value=[ndes]),
            mock.patch("haproxy_ui.db.recent_jobs", return_value=[applied]),
        ):
            client = self.client(config)
            self.sign_in(client)
            page = client.get("/certificates/new").text

        self.assertIn('name="dns_profile"', page)
        self.assertIn('value="cf-main"', page)
        # The NDES profile is saved but not applied: the third choice says why it is off.
        self.assertIn('value="ndes" disabled', page)
        self.assertIn("Microsoft AD CS; no profile in effect", page)

        enrolled = replace(
            applied,
            id=9,
            operation="ndes_profile_apply",
            payload={"profile": "certserver1", "revision": 1},
        )
        with (
            mock.patch("haproxy_ui.db.dns_profiles", return_value=[profile]),
            mock.patch("haproxy_ui.db.ndes_profiles", return_value=[ndes]),
            mock.patch("haproxy_ui.db.recent_jobs", return_value=[enrolled, applied]),
        ):
            client = self.client(config)
            self.sign_in(client)
            page = client.get("/certificates/new").text
        self.assertNotIn('value="ndes" disabled', page)
        self.assertIn('<option value="certserver1"', page)


class SendingTheFormOverNdes(CertificateFormRouteTestCase):
    def ndes_client(self, *, in_effect: bool = True) -> Any:
        now = datetime.now(UTC)
        profile = db.DnsProfile(
            "certserver1", "certserver1", "ndes", 1, "0123456789abcdef", 1, now, "admin", now, "admin"
        )
        jobs = (
            [
                queued(
                    operation="ndes_profile_apply",
                    cluster=None,
                    state="done",
                    payload={"profile": "certserver1", "revision": 1},
                )
            ]
            if in_effect
            else []
        )
        for patch in (
            mock.patch("haproxy_ui.db.dns_profiles", return_value=[]),
            mock.patch("haproxy_ui.db.ndes_profiles", return_value=[profile]),
            mock.patch("haproxy_ui.db.recent_jobs", return_value=jobs),
        ):
            patch.start()
            self.addCleanup(patch.stop)
        self.account = replace(self.account, role="admin")
        client = self.client(
            replace(
                configuration(),
                management_writes=True,
                clusters=("alpha", "beta"),
                dns_profiles_public_key=Path("/example/public.key"),
            )
        )
        self.sign_in(client)
        return client

    def test_a_pkcs12_receiver_is_in_the_job_and_kept_on_a_redrawn_form(self) -> None:
        response = self.post(
            self.ndes_client(),
            method="ndes",
            ndes_profile="certserver1",
            cluster=[],
            receiver=["lb-01.example.net"],
            format=["lb-01.example.net=pkcs12"],
        )
        self.assertEqual(response.status_code, 303, response.text)
        (job,) = self.queued
        self.assertEqual(job["payload"]["formats"], {"lb-01.example.net": "pkcs12"})

        page = self.post(
            self.ndes_client(),
            domain="",
            method="ndes",
            ndes_profile="certserver1",
            receiver=["lb-01.example.net"],
            format=["lb-01.example.net=pkcs12"],
        ).text
        self.assertIn('<option value="lb-01.example.net=pkcs12" selected>', page)

    def test_a_wildcard_over_ndes_becomes_one_cert_scep_job(self) -> None:
        response = self.post(
            self.ndes_client(), domain="*.example.com", method="ndes", ndes_profile="certserver1"
        )
        self.assertEqual(response.status_code, 303, response.text)
        self.assertEqual(response.headers["location"], "/certificates?view=registry")
        (job,) = self.queued
        self.assertEqual(job["operation"], "cert_scep")
        self.assertIsNone(job["cluster"])
        self.assertEqual(
            job["payload"],
            {
                "id": "example.com",
                "profile": "certserver1",
                "domains": ["example.com", "*.example.com"],
                "clusters": ["alpha"],
                "receivers": [],
            },
        )

    def test_the_first_profile_is_preselected_and_a_typed_choice_is_kept(self) -> None:
        """One profile per CA is the ordinary installation; picking it is a click for nothing."""

        page = self.ndes_client().get("/certificates/new").text
        self.assertIn('<option value="certserver1" selected>certserver1</option>', page)
        self.assertNotIn("Choose a profile", page)
        page = self.post(self.ndes_client(), method="ndes", ndes_profile="certserver1", cluster=[]).text
        self.assertIn('<option value="certserver1" selected>certserver1</option>', page)

    def test_a_refused_ndes_form_is_redrawn_with_the_ndes_select_shown(self) -> None:
        page = self.post(self.ndes_client(), method="ndes").text
        self.assertIn(
            '<select name="dns_profile" class="dns-only" aria-labelledby="profile-field-title" disabled hidden>',
            page,
        )
        self.assertIn(
            '<select name="ndes_profile" class="ndes-only" aria-labelledby="profile-field-title">',
            page,
        )
        self.assertIn('<small data-profile-hint="ndes">Required for Microsoft AD CS.', page)
        self.assertIn('<small data-profile-hint="dns-01" hidden>', page)

    def test_ndes_needs_a_profile_in_effect_and_refuses_a_dns_profile(self) -> None:
        page = self.post(self.ndes_client(), method="ndes").text
        self.assertIn("Choose an NDES provider profile that is in effect", page)
        page = self.post(self.ndes_client(in_effect=False), method="ndes", ndes_profile="certserver1").text
        self.assertIn("enrollment over NDES is unavailable", page)
        page = self.post(self.ndes_client(), method="dns-01", ndes_profile="certserver1").text
        self.assertIn("belongs to NDES enrollment only", page)
        self.assertEqual(self.queued, [])


class SendingTheForm(CertificateFormRouteTestCase):
    def test_a_good_submission_queues_one_cert_issue_job_with_no_cluster(self) -> None:
        response = self.post(self.writing_client())

        self.assertEqual(response.status_code, 303)
        # To the listing, opened on the row that is now "Requesting" - not to
        # the jobs page, which is where a person looks when something failed.
        self.assertEqual(response.headers["location"], "/certificates?view=registry")
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
