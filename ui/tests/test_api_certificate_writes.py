"""Issue, renew, retarget and delete a certificate through the API (B416, release 3).

Each route queues the job the Certificates page queues, with the payload the
page's own builder makes for the same input: that is asserted by calling the
builder, not by copying what it returns.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any
from unittest import mock
from uuid import uuid4

from haprion_ui import certificate_form, certificate_renew, certificate_retarget, db
from haprion_ui.certificates import RegistryCertificateView
from tests.test_api import ApiTestCase
from tests.test_certificate_delete import SHOP_DRAFT
from tests.test_certificate_renew import ndes_row, rows
from tests.test_certificates import reading as certificate_reading
from tests.test_certificates import registered, with_registry
from tests.test_login import configuration
from tests.test_queue_route import queued

KEY = "00000000-0000-4000-8000-000000000041"

CHOICES = certificate_form.IssueChoices(
    clusters=("alpha", "beta"),
    receivers=("lb-01",),
    ndes_profiles=("certserver1",),
    registered=("example.com", "old.example.com", "imported.example", "ndes.example.net"),
)


def entries() -> tuple[dict[str, Any], ...]:
    return (
        registered(fingerprint="a" * 64),
        registered("old.example.com", fingerprint="b" * 64, clusters=("alpha", "beta")),
        registered("imported.example", kind="import", fingerprint="d" * 64),
        ndes_row(),
        registered("beta.example.net", fingerprint="f" * 64, clusters=("beta",)),
        registered(
            "recv.example.net",
            fingerprint="c" * 64,
            receivers=({"id": "lb-01", "published_at": None, "current": None},),
        ),
    )


class CertificateWriteCase(ApiTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.queued: list[dict[str, Any]] = []
        self.events: list[dict[str, Any]] = []
        self.drafts: list[db.ProxyDraft] = []
        self.refusal: BaseException | None = None

        def queue(_c: object, **values: Any) -> db.Job:
            if self.refusal is not None:
                raise self.refusal
            self.queued.append(values)
            return queued(operation=values["operation"], cluster=None)

        for patch in (
            mock.patch("haprion_ui.db.queue_job", side_effect=queue),
            mock.patch(
                "haprion_ui.db.record_audit_event",
                side_effect=lambda _c, **values: self.events.append(values),
            ),
            mock.patch("haprion_ui.db.live_drafts", side_effect=lambda _c, _l: list(self.drafts)),
            mock.patch(
                "haprion_ui.db.cluster_certificates",
                side_effect=lambda *_a, **_k: [
                    with_registry(certificate_reading(), *entries(), receivers=("lb-01",))
                ],
            ),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def send(
        self,
        method: str,
        path: str,
        secret: str,
        body: dict[str, Any] | None = None,
        *,
        key: str | None = KEY,
        writes: bool = True,
    ) -> Any:
        client = self.client(
            replace(configuration(), clusters=("alpha", "beta"), management_writes=writes)
        )
        headers = {"Authorization": f"Bearer {secret}"}
        if key is not None:
            headers["Idempotency-Key"] = key
        return client.request(method, "/api/v1" + path, headers=headers, json=body)

    def write(self, **scope: Any) -> str:
        return self.issue(level="write", **scope)

    def assertRefused(self, response: Any, status: int, code: str) -> None:
        self.assertEqual((response.status_code, response.json()["error"]["code"]), (status, code))
        self.assertEqual(self.queued, [])

    def assertQueued(self, response: Any, operation: str) -> dict[str, Any]:
        self.assertEqual(response.status_code, 202, response.text)
        body = response.json()
        self.assertEqual((body["ok"], body["outcome"]), (True, "done"))
        self.assertEqual(body["result"]["follow"], "/api/v1/jobs/7")
        self.assertEqual(body["result"]["job"]["id"], 7)
        (job,) = self.queued
        self.assertEqual((job["operation"], job["cluster"]), (operation, None))
        self.assertEqual(str(job["idempotency_key"]), KEY)
        (event,) = self.events
        self.assertEqual(
            (event["actor"], event["action"], event["cluster"]),
            (f"token{':'}monitoring", "queue_job", None),
        )
        self.assertEqual(event["detail"]["via"], "api")
        self.assertEqual(event["detail"]["operation"], operation)
        payload: dict[str, Any] = job["payload"]
        return payload

    def registry(self) -> dict[str, RegistryCertificateView]:
        return rows(*entries())


class IssuingACertificate(CertificateWriteCase):
    def setUp(self) -> None:
        super().setUp()
        patch = mock.patch("haprion_ui.api.certificates.certificate_choices", return_value=CHOICES)
        patch.start()
        self.addCleanup(patch.stop)

    def issue_one(self, secret: str, **body: Any) -> Any:
        return self.send(
            "POST",
            "/certificates",
            secret,
            {"domain": "new.example.net", "method": "dns-01", "clusters": ["alpha"], **body},
        )

    def test_a_dns_certificate_is_the_job_the_form_queues(self) -> None:
        response = self.issue_one(
            self.write(),
            clusters=["alpha", "beta"],
            receivers=["lb-01"],
            formats={"lb-01": "pkcs12"},
            dns_profile="",
        )
        payload = self.assertQueued(response, "cert_issue")
        form = certificate_form.IssueForm(
            domain="new.example.net",
            method="dns-01",
            dns_profile="",
            clusters=("alpha", "beta"),
            receivers=("lb-01",),
            formats=("lb-01=pkcs12",),
        )
        self.assertEqual(payload, certificate_form.payload_from_form(form, CHOICES))
        self.assertEqual(
            payload,
            {
                "domain": "new.example.net",
                "method": "dns-01",
                "clusters": ["alpha", "beta"],
                "receivers": ["lb-01"],
                "formats": {"lb-01": "pkcs12"},
            },
        )
        self.assertEqual(self.events[0]["detail"]["certificate"], "new.example.net")

    def test_an_ndes_certificate_is_the_enrollment_the_form_queues(self) -> None:
        response = self.issue_one(self.write(), method="ndes", ndes_profile="certserver1")
        payload = self.assertQueued(response, "cert_scep")
        form = certificate_form.IssueForm(
            domain="new.example.net",
            method="ndes",
            ndes_profile="certserver1",
            clusters=("alpha",),
            receivers=(),
        )
        self.assertEqual(payload, certificate_form.payload_from_form(form, CHOICES))
        self.assertEqual(payload["profile"], "certserver1")

    def test_a_name_in_the_registry_is_a_conflict_and_a_signing_request_is_left_to_the_page(
        self,
    ) -> None:
        secret = self.write()
        self.assertRefused(self.issue_one(secret, domain="Example.com"), 409, "already_exists")
        self.assertRefused(self.issue_one(secret, method="csr"), 400, "bad_input")

    def test_what_the_form_refuses_is_a_400_in_its_words(self) -> None:
        secret = self.write()
        for body, words in (
            ({"clusters": []}, "at least one target"),
            ({"clusters": ["gamma"]}, "not a cluster this manager has"),
            ({"method": "carrier-pigeon"}, "challenge method"),
            ({"domain": "not a name"}, "not a domain name"),
            ({"receivers": ["lb-99"]}, "not registered"),
            ({"method": "ndes", "ndes_profile": "other"}, "NDES profile"),
        ):
            with self.subTest(body=body):
                response = self.issue_one(secret, **body)
                self.assertRefused(response, 400, "bad_input")
                self.assertIn(words, response.json()["error"]["message"])

    def test_a_body_that_is_not_the_form_s_is_a_400(self) -> None:
        secret = self.write()
        for body in (
            {"method": "dns-01", "clusters": ["alpha"]},
            {"domain": "new.example.net", "method": "dns-01", "interface": True},
            {"domain": "new.example.net", "method": "dns-01", "clusters": "alpha"},
            {"domain": "new.example.net", "method": "dns-01", "formats": ["lb-01=pem"]},
        ):
            with self.subTest(body=body):
                self.assertRefused(
                    self.send("POST", "/certificates", secret, body), 400, "bad_input"
                )

    def test_a_token_limited_to_clusters_issues_to_them_and_to_no_receiver(self) -> None:
        secret = self.write(clusters=["alpha"])
        self.assertRefused(self.issue_one(secret, clusters=["beta"]), 404, "not_found")
        self.assertRefused(self.issue_one(secret, clusters=["alpha", "beta"]), 404, "not_found")
        self.assertRefused(self.issue_one(secret, receivers=["lb-01"]), 403, "forbidden")
        self.assertRefused(self.issue_one(secret, receivers=["lb-99"]), 403, "forbidden")
        self.assertRefused(self.issue_one(secret, exportable=True, clusters=[]), 403, "forbidden")
        self.assertRefused(self.issue_one(secret, clusters=[]), 400, "bad_input")
        self.assertQueued(self.issue_one(secret), "cert_issue")

    def test_an_exportable_certificate_is_the_forms_and_needs_the_receivers_feature(self) -> None:
        secret = self.write()
        response = self.issue_one(secret, clusters=[], exportable=True)
        payload = self.assertQueued(response, "cert_issue")
        self.assertTrue(payload["exportable"])
        self.assertEqual(payload["clusters"], [])
        self.queued.clear()
        self.events.clear()
        self.switches = {"cert_receivers": mock.Mock(enabled=False)}
        self.assertRefused(self.issue_one(secret, clusters=[], exportable=True), 400, "bad_input")

    def test_a_change_needs_writes_on_a_key_and_the_write_level(self) -> None:
        self.assertRefused(
            self.send(
                "POST",
                "/certificates",
                self.write(),
                {"domain": "new.example.net", "method": "dns-01", "clusters": ["alpha"]},
                writes=False,
            ),
            403,
            "writes_off",
        )
        self.assertRefused(
            self.send(
                "POST",
                "/certificates",
                self.write(),
                {"domain": "new.example.net", "method": "dns-01", "clusters": ["alpha"]},
                key=None,
            ),
            400,
            "bad_input",
        )
        for level in ("read", "block"):
            with self.subTest(level=level):
                self.assertRefused(
                    self.send("POST", "/certificates", self.issue(level=level), {}),
                    403,
                    "forbidden",
                )

    def test_a_busy_certificate_queue_is_a_409_to_retry(self) -> None:
        self.refusal = db.CertificateBusy()
        response = self.issue_one(self.write())
        self.assertRefused(response, 409, "certificate_busy")
        self.assertEqual(response.headers["retry-after"], "5")
        self.refusal = db.RequestConflict()
        self.assertRefused(self.issue_one(self.write()), 409, "idempotency_conflict")
        self.assertEqual(self.events, [])


class IssuingWithTheRealReading(CertificateWriteCase):
    def test_the_clusters_and_receivers_on_offer_are_the_ones_the_page_reads(self) -> None:
        secret = self.write()
        body = {
            "domain": "new.example.net",
            "method": "dns-01",
            "clusters": ["alpha"],
            "receivers": ["lb-01"],
        }
        payload = self.assertQueued(self.send("POST", "/certificates", secret, body), "cert_issue")
        self.assertEqual(payload["receivers"], ["lb-01"])
        self.queued.clear()
        self.events.clear()
        self.assertRefused(
            self.send("POST", "/certificates", secret, {**body, "clusters": ["gamma"]}),
            400,
            "bad_input",
        )
        # No NDES profile is in effect on an installation that has none.
        refused = self.send("POST", "/certificates", secret, {**body, "method": "ndes"})
        self.assertRefused(refused, 400, "bad_input")
        self.assertIn("NDES", refused.json()["error"]["message"])


class RenewingACertificate(CertificateWriteCase):
    def renew(self, secret: str, certificate: str, **options: Any) -> Any:
        return self.send("POST", f"/certificates/{certificate}/renew", secret, **options)

    def test_a_certbot_certificate_is_renewed_as_the_page_renews_it(self) -> None:
        payload = self.assertQueued(self.renew(self.write(), "example.com"), "cert_issue")
        operation, expected = certificate_renew.payload(
            certificate_renew.selection(["example.com"], self.registry())
        )
        self.assertEqual((operation, payload), ("cert_issue", expected))
        self.assertEqual(payload, {"domain": "example.com", "renew": True})
        self.assertEqual(self.events[0]["detail"]["certificate"], "example.com")
        self.assertTrue(self.events[0]["detail"]["renew"])

    def test_an_ndes_certificate_is_enrolled_again(self) -> None:
        payload = self.assertQueued(self.renew(self.write(), "ndes.example.net"), "cert_scep")
        _, expected = certificate_renew.payload(
            certificate_renew.selection(["ndes.example.net"], self.registry())
        )
        self.assertEqual(payload, expected)

    def test_a_certificate_renewed_with_a_file_is_a_conflict_that_says_so(self) -> None:
        response = self.renew(self.write(), "imported.example")
        self.assertRefused(response, 409, "cannot_renew")
        self.assertIn("with a file", response.json()["error"]["message"])

    def test_a_certificate_that_is_not_there_is_a_404(self) -> None:
        for name in ("nobody.example", "Not A Name"):
            with self.subTest(name=name):
                self.assertRefused(self.renew(self.write(), name), 404, "not_found")

    def test_a_token_limited_to_clusters_renews_what_is_deployed_there_alone(self) -> None:
        secret = self.write(clusters=["alpha"])
        # On beta as well, on a receiver, and only on beta: not the token's to touch.
        for name in ("old.example.com", "recv.example.net", "beta.example.net"):
            with self.subTest(name=name):
                self.assertRefused(self.renew(secret, name), 404, "not_found")
        self.assertQueued(self.renew(secret, "example.com"), "cert_issue")

    def test_writes_off_a_missing_key_and_the_level(self) -> None:
        self.assertRefused(self.renew(self.write(), "example.com", writes=False), 403, "writes_off")
        self.assertRefused(self.renew(self.write(), "example.com", key=None), 400, "bad_input")
        self.assertRefused(self.renew(self.issue(level="read"), "example.com"), 403, "forbidden")

    def test_a_busy_certificate_queue_is_a_409(self) -> None:
        self.refusal = db.CertificateBusy()
        self.assertRefused(self.renew(self.write(), "example.com"), 409, "certificate_busy")


class RetargetingACertificate(CertificateWriteCase):
    def retarget(self, secret: str, certificate: str, body: dict[str, Any], **options: Any) -> Any:
        return self.send("PUT", f"/certificates/{certificate}/targets", secret, body, **options)

    def expected(self, action: str, certificate: str, **chosen: Any) -> dict[str, Any]:
        registry = self.registry()
        picked = certificate_retarget.selection(
            action, [certificate], registry, ("alpha", "beta"), ("lb-01",), self.drafts
        )
        return certificate_retarget.payload(
            picked,
            chosen.get("clusters", ()),
            chosen.get("receivers", ()),
            chosen.get("formats", ()),
        )

    def test_publishing_to_more_places_is_the_job_the_page_queues(self) -> None:
        response = self.retarget(
            self.write(),
            "example.com",
            {
                "action": "add",
                "clusters": ["beta"],
                "receivers": ["lb-01"],
                "formats": {"lb-01": "pkcs12"},
            },
        )
        payload = self.assertQueued(response, "cert_target")
        self.assertEqual(
            payload,
            self.expected(
                "add",
                "example.com",
                clusters=("beta",),
                receivers=("lb-01",),
                formats=("lb-01=pkcs12",),
            ),
        )
        self.assertEqual(
            payload,
            {
                "certificates": ["example.com"],
                "action": "add",
                "clusters": ["beta"],
                "receivers": ["lb-01"],
                "formats": {"lb-01": "pkcs12"},
            },
        )
        self.assertEqual(self.events[0]["detail"]["certificate"], "example.com")

    def test_taking_it_from_a_place_is_the_removal_the_page_queues(self) -> None:
        response = self.retarget(
            self.write(), "old.example.com", {"action": "remove", "clusters": ["beta"]}
        )
        payload = self.assertQueued(response, "cert_target")
        self.assertEqual(payload, self.expected("remove", "old.example.com", clusters=("beta",)))

    def test_a_place_that_already_has_it_is_left_out_and_all_of_them_is_nothing_to_do(self) -> None:
        secret = self.write()
        response = self.retarget(
            secret, "example.com", {"action": "add", "clusters": ["alpha", "beta"]}
        )
        self.assertEqual(self.assertQueued(response, "cert_target")["clusters"], ["beta"])
        self.queued.clear()
        self.events.clear()
        for body in (
            {"action": "add", "clusters": ["alpha"]},
            {"action": "remove", "clusters": ["beta"]},
        ):
            with self.subTest(body=body):
                self.assertRefused(self.retarget(secret, "example.com", body), 409, "no_change")

    def test_a_removal_is_refused_while_a_draft_in_that_cluster_names_the_certificate(self) -> None:
        self.drafts = [SHOP_DRAFT]
        secret = self.write()
        response = self.retarget(
            secret, "old.example.com", {"action": "remove", "clusters": ["alpha"]}
        )
        self.assertRefused(response, 409, "in_use")
        self.assertIn("alpha/shop", response.json()["error"]["message"])
        # Where no draft names it, it goes.
        self.assertQueued(
            self.retarget(secret, "old.example.com", {"action": "remove", "clusters": ["beta"]}),
            "cert_target",
        )

    def test_what_the_page_refuses_is_a_400(self) -> None:
        secret = self.write()
        for body in (
            {"action": "add"},
            {"action": "add", "clusters": ["gamma"]},
            {"action": "add", "receivers": ["lb-99"]},
            {"action": "remove", "clusters": ["beta"], "formats": {"lb-01": "pem"}},
            {"action": "add", "receivers": ["lb-01"], "formats": {"lb-01": "der"}},
            {"action": "replace", "clusters": ["beta"]},
            {"clusters": ["beta"]},
        ):
            with self.subTest(body=body):
                self.assertRefused(self.retarget(secret, "example.com", body), 400, "bad_input")

    def test_a_token_limited_to_clusters_keeps_to_its_clusters_and_its_certificates(self) -> None:
        secret = self.write(clusters=["alpha", "beta"])
        # Receivers are no cluster's: one answer, whether or not the receiver exists.
        for receiver in ("lb-01", "lb-99"):
            self.assertRefused(
                self.retarget(secret, "example.com", {"action": "add", "receivers": [receiver]}),
                403,
                "forbidden",
            )
        self.assertQueued(
            self.retarget(secret, "example.com", {"action": "add", "clusters": ["beta"]}),
            "cert_target",
        )
        self.queued.clear()
        self.events.clear()
        narrow = self.write(clusters=["alpha"])
        self.assertRefused(
            self.retarget(narrow, "example.com", {"action": "add", "clusters": ["beta"]}),
            404,
            "not_found",
        )
        # Deployed to a cluster outside the scope too: not the token's to change.
        self.assertRefused(
            self.retarget(narrow, "old.example.com", {"action": "remove", "clusters": ["alpha"]}),
            404,
            "not_found",
        )
        self.assertRefused(
            self.retarget(narrow, "recv.example.net", {"action": "remove", "clusters": ["alpha"]}),
            404,
            "not_found",
        )

    def test_writes_off_a_missing_key_a_missing_certificate_and_the_level(self) -> None:
        body = {"action": "add", "clusters": ["beta"]}
        self.assertRefused(
            self.retarget(self.write(), "example.com", body, writes=False), 403, "writes_off"
        )
        self.assertRefused(
            self.retarget(self.write(), "example.com", body, key=None), 400, "bad_input"
        )
        self.assertRefused(self.retarget(self.write(), "nobody.example", body), 404, "not_found")
        self.assertRefused(
            self.retarget(self.issue(level="block"), "example.com", body), 403, "forbidden"
        )


class DeletingACertificate(CertificateWriteCase):
    def delete(self, secret: str, certificate: str, **options: Any) -> Any:
        return self.send("DELETE", f"/certificates/{certificate}", secret, **options)

    def test_a_certificate_is_deleted_by_the_job_the_page_queues(self) -> None:
        payload = self.assertQueued(self.delete(self.write(), "example.com"), "cert_delete")
        self.assertEqual(payload, {"certificates": ["example.com"]})
        self.assertEqual(self.events[0]["detail"]["certificate"], "example.com")

    def test_a_draft_that_names_it_refuses_the_deletion_as_it_does_on_the_page(self) -> None:
        self.drafts = [SHOP_DRAFT]
        response = self.delete(self.write(), "old.example.com")
        self.assertRefused(response, 409, "in_use")
        self.assertIn("alpha/shop", response.json()["error"]["message"])
        self.assertQueued(self.delete(self.write(), "example.com"), "cert_delete")

    def test_a_limited_token_is_not_told_of_drafts_in_other_clusters(self) -> None:
        self.drafts = [replace(SHOP_DRAFT, cluster="gamma"), SHOP_DRAFT]
        response = self.delete(self.write(clusters=["alpha", "beta"]), "old.example.com")
        self.assertRefused(response, 409, "in_use")
        message = response.json()["error"]["message"]
        self.assertIn("alpha/shop", message)
        self.assertNotIn("gamma", message)
        self.drafts = [replace(SHOP_DRAFT, cluster="gamma")]
        hidden = self.delete(self.write(clusters=["alpha", "beta"]), "old.example.com")
        self.assertRefused(hidden, 409, "in_use")
        self.assertNotIn("gamma", hidden.json()["error"]["message"])

    def test_a_token_limited_to_clusters_deletes_what_is_deployed_there_alone(self) -> None:
        secret = self.write(clusters=["alpha"])
        for name in ("old.example.com", "recv.example.net", "beta.example.net", "nobody.example"):
            with self.subTest(name=name):
                self.assertRefused(self.delete(secret, name), 404, "not_found")
        self.assertQueued(self.delete(secret, "example.com"), "cert_delete")

    def test_writes_off_a_missing_key_and_the_level(self) -> None:
        self.assertRefused(
            self.delete(self.write(), "example.com", writes=False), 403, "writes_off"
        )
        self.assertRefused(self.delete(self.write(), "example.com", key=None), 400, "bad_input")
        self.assertRefused(self.delete(self.issue(level="read"), "example.com"), 403, "forbidden")

    def test_the_same_key_for_another_certificate_is_the_queue_s_409(self) -> None:
        self.refusal = db.RequestConflict()
        self.assertRefused(self.delete(self.write(), "example.com"), 409, "idempotency_conflict")
        self.assertNotEqual(KEY, str(uuid4()))


class RepeatingACall(CertificateWriteCase):
    """Review 26-11-01, a-P2-1: a retry with the same key is the job it queued, whatever the registry says now."""

    def setUp(self) -> None:
        super().setUp()
        patch = mock.patch("haprion_ui.api.certificates.certificate_choices", return_value=CHOICES)
        patch.start()
        self.addCleanup(patch.stop)

    def remember(self) -> None:
        """What the database holds after the first call: the job under the key, with the call's digest."""

        self.under_key[KEY] = (
            queued(operation="cert_issue", cluster=None),
            self.queued[-1]["request_digest"],
        )
        self.queued.clear()
        self.events.clear()

    def assertAnsweredWithTheJob(self, response: Any) -> None:
        self.assertEqual(response.status_code, 202, response.text)
        self.assertEqual(response.json()["result"]["job"]["id"], 7)
        self.assertEqual((self.queued, self.events), ([], []))

    def changed_registry(self, *, without: str) -> Any:
        registry = self.registry()
        del registry[without]
        return mock.patch("haprion_ui.api.certificates.registry_views", return_value=registry)

    def test_a_renewal_repeated_while_it_runs_is_answered_with_its_job(self) -> None:
        secret = self.write()
        self.send("POST", "/certificates/example.com/renew", secret)
        self.remember()
        registry = self.registry()
        registry["example.com"] = replace(registry["example.com"], state_active=True)
        with mock.patch("haprion_ui.api.certificates.registry_views", return_value=registry):
            self.assertAnsweredWithTheJob(
                self.send("POST", "/certificates/example.com/renew", secret)
            )

    def test_an_issue_repeated_once_the_name_is_registered_is_answered_with_its_job(self) -> None:
        secret = self.write()
        body = {"domain": "new.example.net", "method": "dns-01", "clusters": ["alpha"]}
        self.send("POST", "/certificates", secret, body)
        self.remember()
        taken = replace(CHOICES, registered=(*CHOICES.registered, "new.example.net"))
        with mock.patch("haprion_ui.api.certificates.certificate_choices", return_value=taken):
            self.assertAnsweredWithTheJob(self.send("POST", "/certificates", secret, body))

    def test_a_deletion_repeated_once_the_certificate_is_gone_is_answered_with_its_job(
        self,
    ) -> None:
        secret = self.write()
        self.send("DELETE", "/certificates/example.com", secret)
        self.remember()
        with self.changed_registry(without="example.com"):
            self.assertAnsweredWithTheJob(self.send("DELETE", "/certificates/example.com", secret))

    def test_a_retarget_repeated_once_the_places_are_as_asked_is_answered_with_its_job(
        self,
    ) -> None:
        secret = self.write()
        body = {"action": "add", "clusters": ["beta"], "formats": {}}
        first = self.send("PUT", "/certificates/example.com/targets", secret, body)
        self.assertEqual(first.status_code, 202, first.text)
        self.remember()
        with self.changed_registry(without="example.com"):
            self.assertAnsweredWithTheJob(
                self.send("PUT", "/certificates/example.com/targets", secret, body)
            )

    def test_the_same_key_for_another_certificate_is_refused_not_answered_with_the_first_job(
        self,
    ) -> None:
        secret = self.write()
        self.send("DELETE", "/certificates/example.com", secret)
        self.remember()
        other = self.send("DELETE", "/certificates/old.example.com", secret)
        self.assertEqual(
            (other.status_code, other.json()["error"]["code"]), (409, "idempotency_conflict")
        )
        self.assertNotIn("new one", other.json()["error"]["message"])

    def test_writes_off_is_the_first_refusal_of_every_certificate_route(self) -> None:
        """Review 26-11-01, a-P3-8: before the registry is read, whatever it would say."""

        secret = self.write()
        for method, path, body in (
            (
                "POST",
                "/certificates",
                {"domain": "example.com", "method": "dns-01", "clusters": ["alpha"]},
            ),
            ("POST", "/certificates/missing.example.org/renew", None),
            (
                "PUT",
                "/certificates/missing.example.org/targets",
                {"action": "add", "clusters": ["beta"]},
            ),
            ("DELETE", "/certificates/missing.example.org", None),
            (
                "POST",
                "/certificates",
                {"domain": "example.com", "method": "dns-01", "clusters": ["gamma"]},
            ),
        ):
            with self.subTest(path=path):
                response = self.send(method, path, secret, body, writes=False, key=None)
                self.assertRefused(response, 403, "writes_off")
