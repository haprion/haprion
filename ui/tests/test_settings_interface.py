"""Settings and the interface's own certificate (Fas 13, B188).

Held here: the certificate forms in their interface mode take no targets,
refuse a name that does not serve the interface, and give NDES, a CSR and
an import an ID that is not the domain; the queue accepts `interface` only
without targets; the registry's marked entry and the served pair leave the
certificate list for the settings page; the page shows what nginx serves
and the ways to replace it; a renewal and an upload of the interface's
certificate keep the mark and come back to Settings.
"""

from __future__ import annotations

import json
import unittest
from dataclasses import replace
from datetime import timedelta
from typing import Any
from unittest import mock
from uuid import uuid4

from haprion_ui import auth, certificate_form, certificate_renew, certificates, operations
from tests.test_certificate_form import CertificateFormRouteTestCase
from tests.test_certificate_import_page import FAKE_CERT, ImportPageTestCase
from tests.test_certificates import NOW, registered, with_registry
from tests.test_certificates import reading as certificate_reading

MANAGER = "mgr.example.net"
SERVED = {
    "server_name": MANAGER,
    "fingerprint_sha256": "d" * 64,
    "common_name": MANAGER,
    "sans": [MANAGER],
    "issuer": "CN=Example Issuing CA,DC=example,DC=net",
    "not_after": "2028-09-25T00:00:00Z",
    "self_signed": False,
}


def interface_entry(identifier: str = "mgr-ui", **fields: Any) -> dict[str, object]:
    entry = registered(identifier, kind="import", clusters=(), fingerprint="d" * 64, sans=[MANAGER])
    entry["interface"] = True
    entry.update(fields)
    return entry


def registry_reading(*entries: dict[str, object], served: dict[str, object] | None = SERVED) -> Any:
    reading = with_registry(certificate_reading(), registered(fingerprint="a" * 64), *entries)
    result = dict(reading.result)
    block = dict(result["registry"])
    block["manager"] = MANAGER
    block["interface_served"] = served
    result["registry"] = block
    return replace(reading, result=result)


CHOICES = certificate_form.IssueChoices(
    clusters=("alpha",),
    receivers=(),
    ndes_profiles=("corp-ca",),
    manager=MANAGER,
    interface_id="mgr-ui",
    taken=("example.com", "mgr-ui"),
    registered=("example.com", "mgr-ui"),
)


def interface_form(**fields: Any) -> certificate_form.IssueForm:
    values: dict[str, Any] = {
        "domain": MANAGER,
        "method": "dns-01",
        "clusters": (),
        "receivers": (),
        "interface": True,
    }
    return certificate_form.IssueForm(**{**values, **fields})


class TheFormInInterfaceMode(unittest.TestCase):
    def test_acme_takes_the_domain_and_no_target(self) -> None:
        payload = certificate_form.payload_from_form(interface_form(), CHOICES)

        self.assertEqual(
            payload,
            {
                "domain": MANAGER,
                "method": "dns-01",
                "clusters": [],
                "receivers": [],
                "interface": True,
            },
        )

    def test_ndes_and_a_csr_get_an_id_that_is_not_the_domain(self) -> None:
        ndes = certificate_form.payload_from_form(
            interface_form(method="ndes", ndes_profile="corp-ca"), CHOICES
        )
        csr = certificate_form.payload_from_form(interface_form(method="csr"), CHOICES)

        self.assertEqual(ndes["id"], "mgr-ui-2")
        self.assertEqual(csr["id"], "mgr-ui-2")
        self.assertEqual(ndes["domains"], [MANAGER])
        self.assertTrue(ndes["interface"] and csr["interface"])
        self.assertEqual((ndes["clusters"], csr["receivers"]), ([], []))

    def test_a_wildcard_serves_the_name_and_another_name_does_not(self) -> None:
        payload = certificate_form.payload_from_form(
            interface_form(domain="*.example.net"), CHOICES
        )
        self.assertEqual(payload["domain"], "*.example.net")

        # *.mgr.example.net would serve it: the engine's wildcard carries its base name.
        for domain in ("other.example.net", "example.net", "*.other.example.net"):
            with self.assertRaisesRegex(certificate_form.FormProblem, "must name mgr.example.net"):
                certificate_form.payload_from_form(interface_form(domain=domain), CHOICES)

    def test_targets_are_refused(self) -> None:
        with self.assertRaisesRegex(certificate_form.FormProblem, "no targets"):
            certificate_form.payload_from_form(interface_form(clusters=("alpha",)), CHOICES)

    def test_acme_for_the_name_that_already_serves_is_a_renewal(self) -> None:
        choices = replace(CHOICES, interface_id=MANAGER, taken=(MANAGER,))

        with self.assertRaisesRegex(certificate_form.FormProblem, "Renew it on the settings page"):
            certificate_form.payload_from_form(interface_form(), choices)

    def test_the_id_counts_past_every_name_in_use(self) -> None:
        self.assertEqual(certificate_form.interface_id_for(MANAGER, ()), "mgr-ui")
        self.assertEqual(
            certificate_form.interface_id_for(MANAGER, ("mgr-ui", "mgr-ui-2")), "mgr-ui-3"
        )


class TheQueue(unittest.TestCase):
    def prepare(self, operation: str, payload: dict[str, Any]) -> dict[str, Any]:
        prepared = operations.prepare(
            operation=operation, cluster=None, request_id=uuid4(), payload=payload
        )
        parameters: dict[str, Any] = json.loads(prepared.request)["parameters"]
        return parameters

    def test_interface_travels_without_targets_and_is_refused_with_them(self) -> None:
        payloads: dict[str, dict[str, object]] = {
            "cert_issue": {"domain": MANAGER, "method": "dns-01"},
            "cert_scep": {"id": "mgr-ui", "profile": "corp-ca", "domains": [MANAGER]},
            "cert_request": {"id": "mgr-ui", "domains": [MANAGER]},
        }
        for operation, payload in payloads.items():
            marked = {**payload, "clusters": [], "receivers": [], "interface": True}
            self.assertIs(self.prepare(operation, marked)["interface"], True, operation)
            with self.assertRaises(operations.BadPayload):
                self.prepare(operation, {**marked, "clusters": ["alpha"]})
            with self.assertRaises(operations.BadPayload):
                self.prepare(operation, {**payload, "clusters": [], "receivers": []})


class TheRegistryView(unittest.TestCase):
    def test_the_interface_s_entry_leaves_the_list_for_its_own_place(self) -> None:
        overview = certificates.build_certificate_overview(
            ("alpha",),
            [registry_reading(interface_entry())],
            now=NOW,
            stale_after=timedelta(minutes=5),
        )
        registry = overview.registry
        if registry is None:
            self.fail("no registry")

        self.assertEqual([c.identifier for c in registry.certificates], ["example.com"])
        self.assertEqual(registry.certificate_count, 1)
        self.assertEqual(registry.interface and registry.interface.identifier, "mgr-ui")
        if registry.served is None:
            self.fail("nothing served")
        self.assertFalse(registry.served.self_signed)
        self.assertEqual(registry.served.issuer, "CN=Example Issuing CA")

    def test_a_renewal_over_ndes_keeps_the_mark(self) -> None:
        overview = certificates.build_certificate_overview(
            ("alpha",),
            [
                registry_reading(
                    interface_entry(
                        source={"kind": "import", "lineage": None, "ndes_profile": "corp-ca"}
                    )
                )
            ],
            now=NOW,
            stale_after=timedelta(minutes=5),
        )
        if overview.registry is None or overview.registry.interface is None:
            self.fail("no interface entry")

        renewal = certificate_renew.selection(("mgr-ui",), {"mgr-ui": overview.registry.interface})
        operation, payload = certificate_renew.payload(renewal)

        self.assertEqual(operation, "cert_scep")
        self.assertIs(payload["interface"], True)
        self.assertEqual((payload["clusters"], payload["receivers"]), ([], []))


class TheSettingsPage(CertificateFormRouteTestCase):
    def setUp(self) -> None:
        super().setUp()
        patch = mock.patch(
            "haprion_ui.db.cluster_certificates", return_value=[registry_reading(interface_entry())]
        )
        patch.start()
        self.addCleanup(patch.stop)

    def test_an_admin_sees_what_is_served_and_the_ways_to_replace_it(self) -> None:
        response = self.writing_client().get("/settings")

        self.assertEqual(response.status_code, 200)
        self.assertIn("Interface certificate", response.text)
        self.assertIn(MANAGER, response.text)
        self.assertIn("/certificates/new?for=interface", response.text)
        self.assertIn("/certificates/import?for=interface", response.text)
        self.assertIn("Renew…", response.text)

    def test_a_reader_is_refused_and_the_header_link_is_for_admins(self) -> None:
        self.assertIn('href="/settings"', self.writing_client().get("/certificates").text)
        reader = self.writing_client(role="reader")
        self.assertEqual(reader.get("/settings").status_code, 403)
        self.assertNotIn('href="/settings"', reader.get("/certificates").text)

    def test_the_list_does_not_show_the_interface_s_entry(self) -> None:
        text = self.writing_client().get("/certificates?view=registry").text

        self.assertNotIn("mgr-ui", text)

    def test_the_form_opens_in_interface_mode_and_its_answer_comes_back_here(self) -> None:
        client = self.writing_client()
        page = client.get("/certificates/new?for=interface").text
        self.assertIn('name="interface" value="1"', page)
        self.assertIn(f'value="{MANAGER}"', page)
        self.assertNotIn("Clusters and receivers", page)

        response = self.post(client, domain=MANAGER, cluster=[], interface="1")

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/settings")
        self.assertEqual(self.queued[0]["payload"]["interface"], True)
        self.assertEqual(self.queued[0]["payload"]["clusters"], [])


class ImportingForTheInterface(ImportPageTestCase):
    def setUp(self) -> None:
        super().setUp()
        patch = mock.patch(
            "haprion_ui.db.cluster_certificates", return_value=[registry_reading(interface_entry())]
        )
        patch.start()
        self.addCleanup(patch.stop)

    def test_the_page_suggests_a_name_that_is_not_in_use(self) -> None:
        page = self.writing_client().get("/certificates/import?for=interface").text

        self.assertIn('value="mgr-ui-2"', page)
        self.assertIn('name="interface" value="1"', page)

    def test_the_import_is_sealed_marked_and_sent_back_to_settings(self) -> None:
        response = self.post(self.writing_client(), name="mgr-ui-2", cluster=[], interface="1")

        self.assertEqual(response.status_code, 303, response.text)
        self.assertEqual(response.headers["location"], "/settings")
        payload = self.queued[0]["payload"]
        self.assertIs(payload["interface"], True)
        self.assertEqual((payload["clusters"], payload["receivers"]), ([], []))

    def test_another_certificate_s_name_is_refused_and_the_serving_one_s_is_not(self) -> None:
        refused = self.post(self.writing_client(), name="example.com", cluster=[], interface="1")
        self.assertIn("already in use", refused.text)
        self.assertEqual(self.queued, [])

        kept = self.post(self.writing_client(), name="mgr-ui", cluster=[], interface="1")
        self.assertEqual(kept.status_code, 303)

    def test_the_row_upload_for_the_interface_keeps_the_mark(self) -> None:
        response = self.upload(self.writing_client(), "mgr-ui", FAKE_CERT)

        self.assertEqual(response.status_code, 303, response.text)
        self.assertEqual(response.headers["location"], "/settings")
        self.assertIs(self.queued[0]["payload"]["interface"], True)


del auth
