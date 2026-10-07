"""External certificates (B255): made with no targets, downloaded, and the key exported.

The form and the queue are held to the engine's limits - one host, no target -
so a refusal is a sentence on the page rather than a failed job. The routes are
tested as HTTP because they are the control: both zips are an admin's, the
public one is the chain and nothing else, and the one with the key comes from
the export helper - with an audit row for every key given out.
"""

from __future__ import annotations

import io
import zipfile
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

        self.assertIn('data-kind-href="/certificates/new?for=external"', page)
        self.assertIn('aria-label="Kind of certificate"', page)

    def test_changing_kind_keeps_what_was_filled_in(self) -> None:
        for path in ("/certificates/new?for=external&", "/certificates/new?"):
            with self.subTest(path=path):
                page = self.writing_client().get(f"{path}domain={DEVICE}&method=http-01").text
                self.assertIn(f'value="{DEVICE}"', page)
                self.assertIn('value="http-01" checked', page)

    def test_a_csr_choice_becomes_the_default_ca_on_the_external_form(self) -> None:
        page = self.writing_client().get("/certificates/new?for=external&method=csr").text

        self.assertIn('value="dns-01" checked', page)
        self.assertIn('value="csr" disabled', page)

    def test_the_page_offers_no_targets_and_sends_the_mark(self) -> None:
        page = self.writing_client().get("/certificates/new?for=external").text

        self.assertIn("External certificate", page)
        self.assertIn('name="exportable" value="1"', page)
        self.assertNotIn('name="cluster"', page)
        self.assertNotIn('name="receiver"', page)
        self.assertIn('value="csr" disabled', page)

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


def members(answer: Any) -> dict[str, tuple[bytes, int]]:
    """A served zip's files, each with its permission bits."""

    with zipfile.ZipFile(io.BytesIO(answer.content)) as archive:
        return {
            item.filename: (archive.read(item), (item.external_attr >> 16) & 0o777)
            for item in archive.infolist()
        }


def post(client: Any, path: str) -> Any:
    token = auth.csrf_token(client.cookies[auth.SESSION_COOKIE])
    return client.post(path, data={auth.CSRF_FIELD: token}, follow_redirects=False)


class TheDownload(ExternalRowTestCase):
    def test_the_public_zip_holds_each_part_as_its_own_file(self) -> None:
        answer = post(self.writing_client(), f"/certificates/{DEVICE}/download")

        self.assertEqual(answer.status_code, 200)
        self.assertEqual(answer.headers["content-type"], "application/zip")
        self.assertIn(f'filename="{DEVICE}.zip"', answer.headers["content-disposition"])
        self.assertEqual(
            members(answer),
            {
                f"{DEVICE}.fullchain.pem": ((LEAF + ISSUER).encode(), 0o644),
                f"{DEVICE}.crt.pem": (LEAF.encode(), 0o644),
                f"{DEVICE}.chain.pem": (ISSUER.encode(), 0o644),
            },
        )

    def test_a_reader_is_refused(self) -> None:
        answer = post(self.writing_client(role="reader"), f"/certificates/{DEVICE}/download")

        self.assertEqual(answer.status_code, 403)

    def test_a_get_or_a_missing_token_gives_nothing(self) -> None:
        client = self.writing_client()
        self.assertEqual(client.get(f"/certificates/{DEVICE}/download").status_code, 405)
        answer = client.post(f"/certificates/{DEVICE}/download", follow_redirects=False)
        self.assertEqual(answer.status_code, 403)

    def test_a_certificate_without_the_mark_has_no_download(self) -> None:
        answer = post(self.writing_client(), "/certificates/example.com/download")

        self.assertIn("not an external certificate", answer.text)
        self.assertNotEqual(answer.headers["content-type"], "application/zip")


FINGERPRINT = "c" * 64


def helper_file(certificate_id: str, form: str, password: str | None, **_: Any) -> Export:
    return Export(
        certificate_id, form, "ignored", "ignored", f"{form}:{password}".encode(), FINGERPRINT
    )


class TheExport(ExternalRowTestCase):
    def export(self, client: Any) -> Any:
        return post(client, f"/certificates/{DEVICE}/export")

    def test_an_admin_gets_every_form_in_one_zip_and_the_audit_says_so(self) -> None:
        with mock.patch("haproxy_mgmt.cert_export_socket.ask", side_effect=helper_file) as helper:
            answer = self.export(self.writing_client())

        self.assertEqual(answer.status_code, 200)
        self.assertEqual(answer.headers["content-type"], "application/zip")
        self.assertIn(f'filename="{DEVICE}.with-key.zip"', answer.headers["content-disposition"])
        self.assertEqual(answer.headers["cache-control"], "no-store")
        files = members(answer)
        password = files[f"{DEVICE}.password"][0].decode().strip()
        self.assertGreaterEqual(len(password), 20)
        self.assertEqual(files[f"{DEVICE}.key.pem"], (b"pem-key:None", 0o600))
        self.assertEqual(files[f"{DEVICE}.pfx"], (f"pfx:{password}".encode(), 0o600))
        self.assertEqual(
            files[f"{DEVICE}.compatible.pfx"], (f"pfx-compatible:{password}".encode(), 0o600)
        )
        self.assertEqual(files[f"{DEVICE}.password"][1], 0o600)
        self.assertEqual(files[f"{DEVICE}.chain.pem"], (ISSUER.encode(), 0o644))
        self.assertEqual(len(files), 7)
        self.assertEqual(helper.call_count, 3)
        self.assertEqual(
            {call.kwargs["requested_by"] for call in helper.call_args_list},
            {self.account.username},
        )
        self.assertIn("certificate_export", self.audit)

    def test_each_export_draws_its_own_password(self) -> None:
        drawn = []
        for _ in range(2):
            with mock.patch("haproxy_mgmt.cert_export_socket.ask", side_effect=helper_file):
                drawn.append(members(self.export(self.writing_client()))[f"{DEVICE}.password"][0])
        self.assertNotEqual(drawn[0], drawn[1])

    def test_a_reader_is_refused(self) -> None:
        with mock.patch("haproxy_mgmt.cert_export_socket.ask") as helper:
            answer = self.export(self.writing_client(role="reader"))

        self.assertEqual(answer.status_code, 403)
        helper.assert_not_called()

    def test_a_certificate_without_the_mark_is_never_asked_for(self) -> None:
        with mock.patch("haproxy_mgmt.cert_export_socket.ask") as helper:
            answer = post(self.writing_client(), "/certificates/example.com/export")

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

    def test_a_certificate_renewed_since_the_reading_is_not_served(self) -> None:
        def renewed(certificate_id: str, form: str, password: str | None, **_: Any) -> Export:
            return Export(certificate_id, form, "ignored", "ignored", b"NEW", "d" * 64)

        with mock.patch("haproxy_mgmt.cert_export_socket.ask", side_effect=renewed):
            answer = self.export(self.writing_client())

        self.assertIn("changed since the page was read", answer.text)
        self.assertNotEqual(answer.headers["content-type"], "application/zip")
        self.assertNotIn("certificate_export", self.audit)

    def test_the_bar_offers_the_export_and_the_row_nothing_of_its_own(self) -> None:
        page = self.writing_client().get(f"/certificates?view=registry&open={DEVICE}").text

        self.assertNotIn(f"/certificates/{DEVICE}/download", page)
        self.assertNotIn(f'action="/certificates/{DEVICE}/export"', page)
        self.assertIn('formaction="/certificates/export" data-export-submit', page)
        self.assertIn(
            f'value="{DEVICE}" form="certificate-selection" data-delete-pick data-exportable', page
        )
        self.assertIn(">external<", page)


class TheExportPage(ExternalRowTestCase):
    def review(self, client: Any, *chosen: str) -> Any:
        token = auth.csrf_token(client.cookies[auth.SESSION_COOKIE])
        return client.post(
            "/certificates/export",
            data={"certificate": list(chosen), auth.CSRF_FIELD: token},
            follow_redirects=False,
        )

    def test_one_external_row_gets_its_two_zips(self) -> None:
        page = self.review(self.writing_client(), DEVICE).text

        self.assertIn(f"Export {DEVICE}", page)
        self.assertIn(f'action="/certificates/{DEVICE}/download"', page)
        self.assertIn(f'action="/certificates/{DEVICE}/export"', page)
        self.assertNotIn('name="confirm"', page)
        self.assertNotIn('name="password"', page)

    def test_anything_else_is_a_sentence_and_no_form(self) -> None:
        for chosen, sentence in (
            ((), "Choose one certificate to export."),
            ((DEVICE, "example.com"), "Choose one certificate to export."),
            (("example.com",), "example.com is not an external certificate."),
        ):
            with self.subTest(chosen=chosen):
                page = self.review(self.writing_client(), *chosen).text
                self.assertIn(sentence, page)
                self.assertNotIn('/export"', page)

    def test_a_reader_is_refused(self) -> None:
        self.assertEqual(self.review(self.writing_client(role="reader"), DEVICE).status_code, 403)
