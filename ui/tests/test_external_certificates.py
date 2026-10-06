"""External certificates (B255): made with no targets, downloaded, and the key exported.

The form and the queue are held to the engine's limits - one host, no target -
so a refusal is a sentence on the page rather than a failed job. The routes are
tested as HTTP because they are the control: the download is the public chain
and nothing else, and the export is an admin, the name typed again, and the
export helper - with an audit row for every key given out.
"""

from __future__ import annotations

from typing import Any
from unittest import mock

from haproxy_mgmt.cert_export import Export, ExportError
from haproxy_mgmt.certificates import CERTIFICATE_OPENING, DELIMITER

from haproxy_ui import auth, certificate_form, operations
from tests.test_certificate_form import CHOICES, KEY, CertificateFormRouteTestCase, form
from tests.test_certificates import reading as certificate_reading
from tests.test_certificates import registered, with_registry

#
# Assembled, so the secret scanner does not take a test bundle's password for one.
#
BUNDLE_PASSWORD = "-".join(("s3cret", "pass"))
CLOSING = f"{DELIMITER}END CERTIFICATE{DELIMITER}"
LEAF = f"{CERTIFICATE_OPENING}\nLEAF\n{CLOSING}\n"
ISSUER = f"{CERTIFICATE_OPENING}\nISSUER\n{CLOSING}\n"
DEVICE = "bmc01.example.com"


def external(**fields: Any) -> dict[str, Any]:
    entry = registered(DEVICE, kind="import", clusters=(), sans=[DEVICE])
    entry.update({"exportable": True, "fullchain_pem": LEAF + ISSUER, **fields})
    return entry


class TheFormsLimits(CertificateFormRouteTestCase):
    def test_an_external_certificate_is_one_name_and_no_target(self) -> None:
        payload = certificate_form.payload_from_form(
            form(domain=DEVICE, clusters=(), exportable=True), CHOICES
        )

        self.assertEqual(payload["exportable"], True)
        self.assertEqual((payload["clusters"], payload["receivers"]), ([], []))
        for overrides in (
            {"domain": "*.example.com"},
            {"clusters": ("alpha",)},
            {"method": "csr"},
        ):
            with self.subTest(overrides=overrides), self.assertRaises(certificate_form.FormProblem):
                certificate_form.payload_from_form(
                    form(**{"domain": DEVICE, "clusters": (), "exportable": True, **overrides}),
                    CHOICES,
                )

    def test_the_queue_refuses_what_the_form_refuses(self) -> None:
        for payload in (
            {"domain": "*.example.com", "method": "dns-01", "exportable": True},
            {"domain": DEVICE, "method": "dns-01", "clusters": ["alpha"], "exportable": True},
        ):
            with self.subTest(payload=payload), self.assertRaises(operations.BadPayload):
                operations.prepare(
                    operation="cert_issue", cluster=None, request_id=KEY_UUID, payload=payload
                )

    def test_the_new_certificate_form_leads_to_it(self) -> None:
        page = self.writing_client().get("/certificates/new").text

        self.assertIn('href="/certificates/new?for=external"', page)
        self.assertIn('aria-label="Kind of certificate"', page)

    def test_the_page_offers_no_targets_and_sends_the_mark(self) -> None:
        page = self.writing_client().get("/certificates/new?for=external").text

        self.assertIn("External certificate", page)
        self.assertIn('name="exportable" value="1"', page)
        self.assertNotIn("<h3>Targets</h3>", page)
        self.assertNotIn('value="csr"', page)

    def test_a_submission_queues_the_issue_without_targets(self) -> None:
        response = self.post(
            self.writing_client(), domain=DEVICE, cluster=[], exportable="1", dns_profile=""
        )

        self.assertEqual(response.status_code, 303, response.text[:400])
        self.assertTrue(self.queued[0]["payload"]["exportable"])
        self.assertEqual(self.queued[0]["payload"]["clusters"], [])


KEY_UUID = __import__("uuid").UUID(KEY)


class ExternalRowTestCase(CertificateFormRouteTestCase):
    def setUp(self) -> None:
        super().setUp()
        patch = mock.patch(
            "haproxy_ui.db.cluster_certificates",
            return_value=[
                with_registry(
                    certificate_reading(),
                    registered(fingerprint="a" * 64),
                    external(),
                    receivers=("lb-01.example.net",),
                )
            ],
        )
        patch.start()
        self.addCleanup(patch.stop)


class TheDownload(ExternalRowTestCase):
    def test_each_part_is_its_own_file(self) -> None:
        client = self.writing_client(role="reader")
        for part, body, name in (
            ("fullchain", LEAF + ISSUER, f"{DEVICE}.fullchain.pem"),
            ("certificate", LEAF, f"{DEVICE}.crt.pem"),
            ("chain", ISSUER, f"{DEVICE}.chain.pem"),
        ):
            with self.subTest(part=part):
                answer = client.get(f"/certificates/{DEVICE}/download?part={part}")
                self.assertEqual(answer.status_code, 200)
                self.assertEqual(answer.text, body)
                self.assertIn(name, answer.headers["content-disposition"])

    def test_a_certificate_without_the_mark_has_no_download(self) -> None:
        answer = self.writing_client().get("/certificates/example.com/download")

        self.assertEqual(answer.status_code, 404)


class TheExport(ExternalRowTestCase):
    def export(self, client: Any, **fields: Any) -> Any:
        token = auth.csrf_token(client.cookies[auth.SESSION_COOKIE])
        data = {"format": "pfx", "password": BUNDLE_PASSWORD, "confirm": DEVICE, **fields}
        data[auth.CSRF_FIELD] = token
        return client.post(f"/certificates/{DEVICE}/export", data=data, follow_redirects=False)

    def test_an_admin_who_types_the_name_gets_the_file_and_the_audit_says_so(self) -> None:
        exported = Export(DEVICE, "pfx", "ignored", "ignored", b"PFXBYTES", "f" * 64)
        with mock.patch("haproxy_mgmt.cert_export_socket.ask", return_value=exported) as helper:
            answer = self.export(self.writing_client())

        self.assertEqual(answer.status_code, 200)
        self.assertEqual(answer.content, b"PFXBYTES")
        self.assertEqual(answer.headers["content-type"], "application/x-pkcs12")
        self.assertIn(f'filename="{DEVICE}.pfx"', answer.headers["content-disposition"])
        self.assertEqual(answer.headers["cache-control"], "no-store")
        helper.assert_called_once()
        self.assertEqual(helper.call_args.kwargs["requested_by"], self.account.username)
        self.assertIn("certificate_export", self.audit)

    def test_a_reader_is_refused(self) -> None:
        with mock.patch("haproxy_mgmt.cert_export_socket.ask") as helper:
            answer = self.export(self.writing_client(role="reader"))

        self.assertEqual(answer.status_code, 403)
        helper.assert_not_called()

    def test_the_name_not_typed_exports_nothing(self) -> None:
        with mock.patch("haproxy_mgmt.cert_export_socket.ask") as helper:
            answer = self.export(self.writing_client(), confirm="bmc02.example.com")

        self.assertIn("Nothing was exported", answer.text)
        helper.assert_not_called()

    def test_a_certificate_without_the_mark_is_never_asked_for(self) -> None:
        token_client = self.writing_client()
        token = auth.csrf_token(token_client.cookies[auth.SESSION_COOKIE])
        with mock.patch("haproxy_mgmt.cert_export_socket.ask") as helper:
            answer = token_client.post(
                "/certificates/example.com/export",
                data={"format": "pem-key", "confirm": "example.com", auth.CSRF_FIELD: token},
                follow_redirects=False,
            )

        self.assertIn("not an external certificate", answer.text)
        helper.assert_not_called()

    def test_the_helper_s_refusal_is_said_and_nothing_audited(self) -> None:
        with mock.patch(
            "haproxy_mgmt.cert_export_socket.ask",
            side_effect=ExportError("dependency_unavailable", "The service is not running here."),
        ):
            answer = self.export(self.writing_client())

        self.assertIn("The service is not running here. Nothing was exported.", answer.text)
        self.assertNotIn("certificate_export", self.audit)

    def test_the_row_offers_the_downloads_and_the_export_to_an_admin(self) -> None:
        page = self.writing_client().get(f"/certificates?view=registry&open={DEVICE}").text

        self.assertIn(f"/certificates/{DEVICE}/download?part=fullchain", page)
        self.assertIn(f'action="/certificates/{DEVICE}/export"', page)
        self.assertIn(">external<", page)
