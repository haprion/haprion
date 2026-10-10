"""*Renew…* (C9c): one row, renewed the way its source is made.

The module decides the way from the row and builds the job for the two
sources that have one; the routes are tested as HTTP because the button is
the control, and what it queues is what the helper will be asked to do.
"""

from __future__ import annotations

import unittest
from typing import Any
from unittest import mock

from haprion_ui import auth, certificate_renew
from haprion_ui.certificates import RegistryCertificateView
from tests.test_certificate_activity import csr_pending_row
from tests.test_certificate_delete import DeleteRouteTestCase
from tests.test_certificates import overview, registered, registry_of, with_registry
from tests.test_certificates import reading as certificate_reading


def rows(*entries: dict[str, object]) -> dict[str, RegistryCertificateView]:
    view = overview(with_registry(certificate_reading(), *entries))
    return {row.identifier: row for row in registry_of(view).certificates}


def ndes_row(
    identifier: str = "ndes.example.net",
    *,
    readable: bool = True,
    receivers: tuple[dict[str, object], ...] = (),
) -> dict[str, Any]:
    entry: dict[str, Any] = registered(
        identifier,
        kind="import",
        fingerprint="e" * 64,
        readable=readable,
        receivers=receivers,
    )
    entry["source"]["ndes_profile"] = "certserver1"
    entry["common_name"] = identifier
    entry["sans"] = [identifier, "*." + identifier]
    return entry


class TheWay(unittest.TestCase):
    def test_each_source_has_its_way(self) -> None:
        registry = rows(
            registered(fingerprint="a" * 64),
            registered("imported.example", kind="import", fingerprint="d" * 64),
            ndes_row(),
            csr_pending_row(),
        )
        for identifier, way in (
            ("example.com", "certbot"),
            ("imported.example", "upload"),
            ("ndes.example.net", "ndes"),
            ("csr.example.net", "signed"),
        ):
            with self.subTest(identifier=identifier):
                renewal = certificate_renew.selection([identifier], registry)
                self.assertEqual(renewal.way, way)
        self.assertEqual(
            certificate_renew.selection(["csr.example.net"], registry).title,
            "Install the signed certificate for csr.example.net",
        )

    def test_what_is_refused(self) -> None:
        pending = ndes_row("wait.example.net", readable=False)
        pending["request_state"] = "pending"
        pending["validation_error"] = "no material at its source yet"
        registry = rows(registered(fingerprint="a" * 64), ndes_row(), pending)
        for chosen, words in (
            ([], "Select one"),
            (["example.com", "ndes.example.net"], "one certificate at a time"),
            (["nobody.example"], "not in the registry"),
            (["wait.example.net"], "still holding"),
        ):
            with (
                self.subTest(chosen=chosen),
                self.assertRaises(certificate_renew.SelectionProblem) as caught,
            ):
                certificate_renew.selection(chosen, registry)
            self.assertIn(words, str(caught.exception))

    def test_the_jobs_the_two_sources_queue(self) -> None:
        registry = rows(
            registered(fingerprint="a" * 64),
            ndes_row(
                receivers=({"id": "lb-01.example.net", "published_at": None, "current": None},)
            ),
            registered("imported.example", kind="import", fingerprint="d" * 64),
        )
        self.assertEqual(
            certificate_renew.payload(certificate_renew.selection(["example.com"], registry)),
            ("cert_issue", {"domain": "example.com", "renew": True}),
        )
        self.assertEqual(
            certificate_renew.payload(certificate_renew.selection(["ndes.example.net"], registry)),
            (
                "cert_scep",
                {
                    "id": "ndes.example.net",
                    "profile": "certserver1",
                    "domains": ["ndes.example.net", "*.ndes.example.net"],
                    "clusters": ["alpha"],
                    "receivers": ["lb-01.example.net"],
                },
            ),
        )
        with self.assertRaises(certificate_renew.SelectionProblem):
            certificate_renew.payload(certificate_renew.selection(["imported.example"], registry))


class TheRoutes(DeleteRouteTestCase):
    def renew(self, client: Any, *ids: str, confirm: bool = False) -> Any:
        token = auth.csrf_token(client.cookies[auth.SESSION_COOKIE])
        data = {"certificate": list(ids), auth.CSRF_FIELD: token}
        if confirm:
            data["idempotency_key"] = "ffffffff-ffff-4fff-8fff-ffffffffffff"
        return client.post(
            "/certificates/renew/confirm" if confirm else "/certificates/renew",
            data=data,
            follow_redirects=False,
        )

    def test_a_certbot_row_is_renewed_by_one_cert_issue_job(self) -> None:
        client = self.writing_client()
        page = self.renew(client, "example.com").text
        self.assertIn("<h1>Renew example.com</h1>", page)
        self.assertIn("five identical certificates", page)
        self.assertIn(">Renew now<", page)

        response = self.renew(client, "example.com", confirm=True)
        self.assertEqual(response.status_code, 303, response.text)
        self.assertEqual(response.headers["location"], "/certificates?view=registry")
        (job,) = self.queued
        self.assertEqual(job["operation"], "cert_issue")
        self.assertIsNone(job["cluster"])
        self.assertEqual(job["payload"], {"domain": "example.com", "renew": True})
        self.assertIn("queue_job", self.audit)

    def test_an_ndes_row_is_enrolled_again(self) -> None:
        with mock.patch(
            "haprion_ui.db.cluster_certificates",
            return_value=[with_registry(certificate_reading(), ndes_row())],
        ):
            client = self.writing_client()
            page = self.renew(client, "ndes.example.net").text
            self.assertIn("same NDES profile", page)
            response = self.renew(client, "ndes.example.net", confirm=True)
        self.assertEqual(response.status_code, 303, response.text)
        (job,) = self.queued
        self.assertEqual(job["operation"], "cert_scep")
        self.assertEqual(job["payload"]["profile"], "certserver1")
        self.assertEqual(job["payload"]["domains"], ["ndes.example.net", "*.ndes.example.net"])

    def test_two_rows_are_refused_and_nothing_queued(self) -> None:
        client = self.writing_client()
        page = self.renew(client, "example.com", "old.example.com").text
        self.assertIn("one certificate at a time", page)
        self.assertNotIn(">Renew now<", page)
        response = self.renew(client, "example.com", "old.example.com", confirm=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.queued, [])

    def test_the_gate_holds(self) -> None:
        self.assertEqual(
            self.renew(self.writing_client(role="reader"), "example.com").status_code, 403
        )
        self.assertEqual(
            self.renew(self.writing_client(writes=False), "example.com").status_code, 404
        )


if __name__ == "__main__":
    unittest.main()
