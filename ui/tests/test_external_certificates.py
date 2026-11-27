"""External certificates (B255): made with no targets, downloaded, and the key exported.

The form and the queue are held to the engine's limits - one host, no target -
so a refusal is a sentence on the page rather than a failed job. The routes are
tested as HTTP because they are the control: both zips are an admin's, the
public one is the chain and nothing else, and the one with the key comes from
the export helper - with an audit row for every key given out.
"""

from __future__ import annotations

import io
import unittest
import zipfile
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest import mock

from haprion.cert_export import Export, ExportError
from haprion.certificates import CERTIFICATE_OPENING, DELIMITER

from haprion_ui import attention, auth, certificate_activity, certificate_form, operations
from haprion_ui.certificates import build_certificate_overview, with_deletion_states
from haprion_ui.db import TakenOut
from tests.registry_fixture import manager_of
from tests.test_certificate_form import CHOICES, KEY, CertificateFormRouteTestCase, form
from tests.test_certificates import (
    NOW,
    STALE_AFTER,
    registered,
    registry_of,
    with_registry,
)
from tests.test_certificates import reading as certificate_reading
from tests.test_queue_route import queued

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

        self.assertIn("<h1>New certificate</h1>", page)
        self.assertNotIn("bmc01", page)
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
            "haprion_ui.db.cluster_certificates",
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

    def test_the_download_is_recorded_as_a_version_taken_out(self) -> None:
        post(self.writing_client(), f"/certificates/{DEVICE}/download")

        self.assertIn("certificate_download", self.audit)

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


class TheVersionTakenOut(unittest.TestCase):
    """26-10-18: the row says whether the version the manager holds was taken out since."""

    def registry(self, taken_out: dict[str, TakenOut] | None) -> Any:
        reading = with_registry(certificate_reading(), external())
        view = build_certificate_overview(
            ("alpha",),
            (reading,),
            now=NOW,
            stale_after=STALE_AFTER,
            manager=manager_of((reading,)),
            taken_out=taken_out,
        )
        return registry_of(view)

    def row(self, taken_out: dict[str, TakenOut] | None) -> Any:
        return self.registry(taken_out).certificates[0]

    def taken(self, fingerprint: str) -> dict[str, TakenOut]:
        return {DEVICE: TakenOut("admin", datetime(2026, 10, 1, 9, 0, tzinfo=UTC), fingerprint)}

    def test_unread_it_says_what_it_always_said(self) -> None:
        row = self.row(None)

        self.assertEqual((row.state_label, row.state_tone), ("Installed by hand", "healthy"))

    def test_nothing_recorded_is_said_and_not_raised(self) -> None:
        row = self.row({})

        self.assertEqual(
            (row.state_label, row.state_detail, row.state_tone),
            ("Installed by hand", "No download recorded", "info"),
        )

    def test_the_version_downloaded_is_the_one_held(self) -> None:
        row = self.row(self.taken(self.row(None).fingerprint))

        self.assertEqual((row.state_label, row.state_tone), ("Installed by hand", "healthy"))
        self.assertIn("Downloaded by admin", row.state_detail)
        self.assertNotIn("installed by admin", row.state_detail)

    def test_a_renewal_since_the_download_is_raised(self) -> None:
        row = self.row(self.taken("0" * 64))

        self.assertEqual(
            (row.state_label, row.state_tone), ("New version not downloaded", "warning")
        )
        self.assertIn("Renewed since admin downloaded it", row.state_detail)
        items = attention.from_certificates(self.registry(self.taken("0" * 64)), ())
        self.assertEqual([(item.subject, item.severity) for item in items], [(DEVICE, "warning")])


FINGERPRINT = "c" * 64


def helper_file(certificate_id: str, form: str, password: str | None, **_: Any) -> Export:
    return Export(
        certificate_id, form, "ignored", "ignored", f"{form}:{password}".encode(), FINGERPRINT
    )


PINNED, CURRENT = "ab" * 32, "a" * 64


def with_bmc(status: str, **state: Any) -> dict[str, Any]:
    return external(
        fingerprint_sha256=CURRENT,
        bmc={
            "address": DEVICE,
            "port": 443,
            "fingerprint_sha256": PINNED,
            "username": "admin",
            "status": status,
            "checked_at": "2026-11-26T03:15:00Z",
            "answered_at": "2026-11-26T03:15:00Z",
            "served_sha256": CURRENT,
            "attempt": None,
            **state,
        },
    )


class TheBmcRow(unittest.TestCase):
    """B536: the row reads the BMC timer's word, and only what the BMC answered is a fault."""

    def registry(self, entry: dict[str, Any]) -> Any:
        reading = with_registry(certificate_reading(), entry)
        view = build_certificate_overview(
            ("alpha",),
            (reading,),
            now=NOW,
            stale_after=STALE_AFTER,
            manager=manager_of((reading,)),
            taken_out={},
        )
        return registry_of(view)

    def row(self, entry: dict[str, Any]) -> Any:
        return self.registry(entry).certificates[0]

    def test_each_word_of_the_timer_is_a_state_of_the_row(self) -> None:
        failed = {
            "fingerprint_sha256": CURRENT,
            "at": "2026-11-26T03:10:00Z",
            "by": "timer",
            "outcome": "failed",
            "code": "refused",
            "message": "bmc01.example.com refused the certificate: SSL certificate validation failed.",
            "seconds": None,
            "firmware": None,
        }
        for entry, label, tone in (
            (with_bmc("installed"), "Installed", "healthy"),
            (with_bmc("waiting", served_sha256=PINNED), "Waiting for the BMC", "info"),
            (
                with_bmc("waiting", answered_at=None, served_sha256=None),
                "Waiting for the BMC",
                "info",
            ),
            (
                with_bmc("failed", served_sha256=PINNED, attempt=failed),
                "Install failed",
                "critical",
            ),
            (with_bmc("untrusted", served_sha256="cd" * 32), "Untrusted BMC", "critical"),
            (with_bmc("unknown", checked_at=None, answered_at=None), "Not checked yet", "info"),
        ):
            with self.subTest(label=label, status=entry["bmc"]["status"]):
                row = self.row(entry)
                self.assertEqual((row.state_label, row.state_tone), (label, tone))
                self.assertEqual(row.bmc.address, DEVICE)
        self.assertIn(
            "SSL certificate validation failed.",
            self.row(with_bmc("failed", served_sha256=PINNED, attempt=failed)).state_detail,
        )

    def test_a_bmc_that_is_off_is_no_attention_however_long(self) -> None:
        for answered in ("2026-11-20T18:40:00Z", "2026-10-01T08:00:00Z", None):
            with self.subTest(answered=answered):
                entry = with_bmc("waiting", answered_at=answered, served_sha256=PINNED)
                self.assertEqual(attention.from_certificates(self.registry(entry), ()), [])
                entry = with_bmc("installed", answered_at=answered or "2026-11-20T18:40:00Z")
                self.assertEqual(attention.from_certificates(self.registry(entry), ()), [])

    def test_only_what_the_bmc_answered_is_attention(self) -> None:
        for status in ("failed", "untrusted"):
            with self.subTest(status=status):
                (item,) = attention.from_certificates(
                    self.registry(with_bmc(status, served_sha256=PINNED)), ()
                )
                self.assertEqual((item.subject, item.severity), (DEVICE, "critical"))

    def test_the_attention_row_leads_to_the_bmc_and_installs_where_that_can_help(self) -> None:
        """Sketch 26-11-26, 4: the BMC's page, and *Install now* on the row itself."""

        (failed,) = attention.from_certificates(
            self.registry(with_bmc("failed", served_sha256=PINNED)), ()
        )
        self.assertEqual((failed.link, failed.page), (f"/certificates/{DEVICE}/bmc", "BMC"))
        self.assertEqual(failed.install, f"/certificates/{DEVICE}/bmc/install")
        self.assertTrue(failed.message.startswith("Install failed: "))
        #
        # An admin's page with writes on: a reader is not sent to a refusal.
        #
        self.assertFalse(failed.reader_opens)
        (untrusted,) = attention.from_certificates(
            self.registry(with_bmc("untrusted", served_sha256="cd" * 32)), ()
        )
        self.assertEqual((untrusted.link, untrusted.install), (f"/certificates/{DEVICE}/bmc", ""))

    def test_one_installed_by_hand_reads_as_it_always_did(self) -> None:
        row = self.row(external())
        self.assertIsNone(row.bmc)
        self.assertEqual(row.state_label, "Installed by hand")


def install_job(state: str, *, seconds: int = 5, result: dict[str, Any] | None = None) -> Any:
    return queued(
        operation="bmc_install",
        cluster=None,
        state=state,
        payload={"id": DEVICE, "by": "install_now"},
        result=result,
        finished_at=None if state in {"pending", "running"} else NOW - timedelta(seconds=seconds),
    )


class TheInstallJobOnTheRow(unittest.TestCase):
    """*Install now*: the row says it is installing, and gives way once the listing has caught up."""

    def drawn(self, entry: dict[str, Any], job: Any) -> Any:
        reading = with_registry(certificate_reading(), entry)
        view = build_certificate_overview(
            ("alpha",),
            (reading,),
            now=NOW,
            stale_after=STALE_AFTER,
            manager=manager_of((reading,)),
            taken_out={},
        )
        states = certificate_activity.deletion_states([job], now=NOW, writes=True)
        return registry_of(with_deletion_states(view, states)).certificates[0]

    def test_a_running_install_is_said_with_a_spinner(self) -> None:
        row = self.drawn(with_bmc("waiting", served_sha256=PINNED), install_job("running"))
        self.assertEqual(
            (row.state_label, row.state_tone, row.state_active), ("Installing", "info", True)
        )

    def test_a_done_install_stays_until_the_listing_shows_it_served(self) -> None:
        before = self.drawn(with_bmc("waiting", served_sha256=PINNED), install_job("done"))
        self.assertEqual((before.state_label, before.state_active), ("Installed", True))

        after = self.drawn(with_bmc("installed"), install_job("done"))
        self.assertEqual(
            (after.state_label, after.state_detail, after.state_active),
            ("Installed", "The BMC serves this certificate", False),
        )

    def test_an_install_behind_another_is_refused_in_its_own_words(self) -> None:
        said = "another install on a BMC is running; ask again when it has ended"
        row = self.drawn(
            with_bmc("waiting", served_sha256=PINNED),
            install_job("blocked", result={"error": {"code": "bmc_busy", "message": said}}),
        )
        self.assertEqual(
            (row.state_label, row.state_detail, row.state_tone),
            ("Install refused", said, "warning"),
        )

    def test_a_failed_install_is_said_for_an_hour_and_then_left_to_the_row(self) -> None:
        said = "bmc01.example.com refused the certificate: SSL certificate validation failed."
        failed = {"error": {"code": "bmc_refused", "message": said}}
        row = self.drawn(
            with_bmc("waiting", served_sha256=PINNED), install_job("failed", result=failed)
        )
        self.assertEqual((row.state_label, row.state_detail), ("Install failed", said))

        later = self.drawn(
            with_bmc("waiting", served_sha256=PINNED),
            install_job("failed", seconds=2 * 3600, result=failed),
        )
        self.assertEqual(later.state_label, "Waiting for the BMC")


class TheBmcOnThePage(CertificateFormRouteTestCase):
    def test_used_by_names_the_bmc_and_the_detail_what_it_served_when_it_last_answered(
        self,
    ) -> None:
        entry = with_bmc(
            "installed",
            checked_at="2026-11-26T09:00:00Z",
            answered_at="2026-11-21T18:40:00Z",
        )
        with mock.patch(
            "haprion_ui.db.cluster_certificates",
            return_value=[with_registry(certificate_reading(), entry)],
        ):
            client = self.writing_client()
            page = client.get(f"/certificates?view=registry&open={DEVICE}").text
        #
        # The mark before the address, so a long address shortened in the cell
        # never takes it away (review 26-11-27, BX07).
        #
        self.assertIn(f'<span class="target-kind">BMC</span> {DEVICE}</span>', page)
        self.assertIn("Installed on", page)
        self.assertIn("serves this certificate · last answered", page)
        self.assertNotIn('<span class="target-kind">external</span>', page)


class TheExport(ExternalRowTestCase):
    def export(self, client: Any) -> Any:
        return post(client, f"/certificates/{DEVICE}/export")

    def test_an_admin_gets_every_form_in_one_zip_and_the_audit_says_so(self) -> None:
        with mock.patch("haprion.cert_export_socket.ask", side_effect=helper_file) as helper:
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
            with mock.patch("haprion.cert_export_socket.ask", side_effect=helper_file):
                drawn.append(members(self.export(self.writing_client()))[f"{DEVICE}.password"][0])
        self.assertNotEqual(drawn[0], drawn[1])

    def test_a_reader_is_refused(self) -> None:
        with mock.patch("haprion.cert_export_socket.ask") as helper:
            answer = self.export(self.writing_client(role="reader"))

        self.assertEqual(answer.status_code, 403)
        helper.assert_not_called()

    def test_a_certificate_without_the_mark_is_never_asked_for(self) -> None:
        with mock.patch("haprion.cert_export_socket.ask") as helper:
            answer = post(self.writing_client(), "/certificates/example.com/export")

        self.assertIn("not an external certificate", answer.text)
        helper.assert_not_called()

    def test_the_helper_s_refusal_is_said_and_nothing_audited(self) -> None:
        with mock.patch(
            "haprion.cert_export_socket.ask",
            side_effect=ExportError("dependency_unavailable", "The service is not running here."),
        ):
            answer = self.export(self.writing_client())

        self.assertIn("The service is not running here. Nothing was exported.", answer.text)
        self.assertNotIn("certificate_export", self.audit)

    def test_a_certificate_renewed_since_the_reading_is_not_served(self) -> None:
        def renewed(certificate_id: str, form: str, password: str | None, **_: Any) -> Export:
            return Export(certificate_id, form, "ignored", "ignored", b"NEW", "d" * 64)

        with mock.patch("haprion.cert_export_socket.ask", side_effect=renewed):
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


class TheDeletion(ExternalRowTestCase):
    def test_an_external_certificate_is_not_told_of_targets_or_nodes(self) -> None:
        client = self.writing_client()
        token = auth.csrf_token(client.cookies[auth.SESSION_COOKIE])
        with mock.patch("haprion_ui.db.live_drafts", return_value=[]):
            page = client.post(
                "/certificates/delete", data={"certificate": [DEVICE], auth.CSRF_FIELD: token}
            ).text

        self.assertIn(
            "Removed from the registry. Its certificate and key are removed from the manager.",
            page,
        )
        self.assertNotIn("every target above", page)
        self.assertNotIn("drop its copy", page)


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
