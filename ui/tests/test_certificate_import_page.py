"""The import page and the row's upload (C9, B165), as HTTP.

What is measured is the one sentence B165 turned into a promise: a file
uploaded here reaches the queue sealed, and nothing the web writes - the job
row, the audit, the page drawn back - holds the key in clear.
"""

from __future__ import annotations

import base64
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from typing import Any
from unittest import mock
from uuid import uuid4

from haproxy_mgmt import cert_upload
from haproxy_mgmt.certificates import DELIMITER
from haproxy_mgmt.dns_profile_keys import generate, render_public_key

from haproxy_ui import auth, certificate_import_form, db
from tests.test_certificates import reading as certificate_reading
from tests.test_certificates import registered, with_registry
from tests.test_login import LoginTestCase, configuration
from tests.test_queue_route import queued

KEY = str(uuid4())
KEY_MARK = "PRIVATE KEY"


def _block(kind: str) -> bytes:
    """A PEM-shaped block, assembled so the secret scanner does not meet a header in a tracked file.

    The helper is not run here; the bytes only have to be something the page
    would recognise as a key or not.
    """

    return f"{DELIMITER}BEGIN {kind}{DELIMITER}\nAAAA\n{DELIMITER}END {kind}{DELIMITER}\n".encode()


FAKE_KEY = _block(KEY_MARK)
FAKE_CERT = _block("CERTIFICATE")


class ImportPageTestCase(LoginTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.private, self.public = generate()
        self.key_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.key_dir.cleanup)
        self.public_path = Path(self.key_dir.name) / "public.key"
        self.public_path.write_text(render_public_key(self.public), encoding="utf-8")
        self.queued: list[dict[str, Any]] = []
        self.audited: list[dict[str, Any]] = []

        def queue(_c: object, **fields: Any) -> db.Job:
            self.queued.append(fields)
            return queued(operation="cert_import", cluster=None)

        def audit(_c: object, **fields: Any) -> None:
            self.audited.append(fields)

        for patch in (
            mock.patch("haproxy_ui.db.queue_job", side_effect=queue),
            mock.patch("haproxy_ui.db.record_audit_event", side_effect=audit),
            mock.patch("haproxy_ui.db.dns_profiles", return_value=[]),
            mock.patch("haproxy_ui.db.ndes_profiles", return_value=[]),
            mock.patch(
                "haproxy_ui.db.cluster_certificates",
                return_value=[
                    with_registry(
                        certificate_reading(),
                        registered(fingerprint="a" * 64),
                        registered("imported.example.net", kind="import", fingerprint="b" * 64),
                        receivers=("lb-01.example.net",),
                    )
                ],
            ),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def writing_client(self, *, role: str = "admin", sealing: bool = True) -> Any:
        self.account = replace(self.account, role=role)
        client = self.client(
            replace(
                configuration(),
                management_writes=True,
                clusters=("alpha", "beta"),
                dns_profiles_public_key=self.public_path if sealing else None,
            )
        )
        self.sign_in(client)
        return client

    def post(self, client: Any, data: bytes | None = FAKE_CERT + FAKE_KEY, **fields: Any) -> Any:
        token = auth.csrf_token(client.cookies[auth.SESSION_COOKIE])
        form: dict[str, Any] = {
            "name": "shop.example.net",
            "cluster": ["alpha"],
            "idempotency_key": KEY,
            auth.CSRF_FIELD: token,
        }
        form.update(fields)
        files = {"file": ("shop.pfx", data, "application/x-pkcs12")} if data is not None else {}
        return client.post("/certificates/import", data=form, files=files, follow_redirects=False)

    def upload(self, client: Any, certificate_id: str, data: bytes) -> Any:
        token = auth.csrf_token(client.cookies[auth.SESSION_COOKIE])
        return client.post(
            f"/certificates/{certificate_id}/upload",
            data={"idempotency_key": KEY, "csrf_token": token},
            files={"file": ("renewed.pem", data, "application/x-pem-file")},
            follow_redirects=False,
        )


class ThePage(ImportPageTestCase):
    def test_it_is_a_form_with_a_file_the_targets_and_the_promise(self) -> None:
        page = self.writing_client().get("/certificates/import").text

        self.assertIn('enctype="multipart/form-data"', page)
        self.assertIn('<input type="file" name="file" accept=', page)
        self.assertIn('name="password"', page)
        self.assertIn('name="cluster" value="alpha"', page)
        self.assertIn('name="receiver" value="lb-01.example.net"', page)
        self.assertIn("opened only by root", page)
        self.assertIn("haproxy-cert-import", page)
        self.assertIn("Import the certificate", page)

    def test_the_listing_links_to_it_for_an_admin_only(self) -> None:
        self.assertIn(
            'href="/certificates/import">Import certificate',
            self.writing_client().get("/certificates").text,
        )
        self.assertNotIn(
            "/certificates/import", self.writing_client(role="reader").get("/certificates").text
        )

    def test_it_is_not_there_when_writes_are_off_and_refused_to_a_reader(self) -> None:
        client = self.client(configuration())
        self.sign_in(client)
        self.assertEqual(client.get("/certificates/import").status_code, 404)
        self.assertEqual(
            self.writing_client(role="reader").get("/certificates/import").status_code, 403
        )

    def test_without_a_sealing_key_the_page_says_so_and_takes_nothing(self) -> None:
        client = self.writing_client(sealing=False)
        page = client.get("/certificates/import").text
        self.assertIn("sealing key is not configured", page)
        self.assertIn('name="file" accept=', page)
        self.assertIn(" disabled>", page)

        response = self.post(client)

        self.assertEqual(response.status_code, 200)
        self.assertIn("sealing key is not configured", response.text)
        self.assertEqual(self.queued, [])


class Submitting(ImportPageTestCase):
    def test_the_file_reaches_the_queue_sealed_and_nowhere_in_clear(self) -> None:
        client = self.writing_client()

        response = self.post(client, password="pw", receiver=["lb-01.example.net"])

        self.assertEqual(response.status_code, 303, response.text)
        self.assertEqual(response.headers["location"], "/certificates?view=registry")
        self.assertEqual(len(self.queued), 1)
        job = self.queued[0]
        self.assertEqual(job["operation"], "cert_import")
        self.assertIsNone(job["cluster"])
        payload = job["payload"]
        self.assertEqual(set(payload), {"id", "key_id", "ciphertext", "clusters", "receivers"})
        self.assertEqual(payload["id"], "shop.example.net")
        self.assertEqual(payload["key_id"], self.public.key_id)
        self.assertEqual(payload["clusters"], ["alpha"])
        self.assertEqual(payload["receivers"], ["lb-01.example.net"])
        #
        # The promise: nothing the web wrote holds the key or the password.
        #
        written = json.dumps(payload) + json.dumps(self.audited, default=str)
        self.assertNotIn(KEY_MARK, written)
        self.assertNotIn("pw", json.dumps(self.audited, default=str))
        self.assertNotIn(base64.b64encode(FAKE_KEY).decode(), written)
        #
        # And root can open exactly what was uploaded, bound to the name.
        #
        opened = cert_upload.open_upload(
            self.private,
            base64.b64decode(payload["ciphertext"]),
            certificate_id="shop.example.net",
        )
        self.assertEqual(opened.data, FAKE_CERT + FAKE_KEY)
        self.assertEqual(opened.password, "pw")

    def test_a_refusal_redraws_the_page_with_the_name_kept_and_the_password_not(self) -> None:
        client = self.writing_client()

        response = self.post(client, cluster=[], password="pw")

        self.assertEqual(response.status_code, 200)
        self.assertIn("Choose at least one target", response.text)
        self.assertIn('value="shop.example.net"', response.text)
        self.assertIn("Last chosen: <code>shop.pfx</code>", response.text)
        self.assertNotIn('value="pw"', response.text)
        self.assertNotIn(KEY_MARK, response.text)
        self.assertEqual(self.queued, [])

    def test_what_the_form_refuses(self) -> None:
        client = self.writing_client()
        for fields, words in (
            ({"name": ""}, "A name is required"),
            ({"name": "shop example"}, "lower-case"),
            ({"name": "example.com"}, "already registered"),
            ({"data": b""}, "Choose a certificate file"),
            ({"data": None}, "Choose a certificate file"),
            ({"data": b"x" * (certificate_import_form.MAX_UPLOAD_BYTES + 1)}, "larger than"),
            ({"password": "a\nb"}, "password"),
            ({"cluster": ["gamma"]}, "not a cluster"),
            ({"receiver": ["nobody.example.net"], "cluster": []}, "not registered"),
        ):
            with self.subTest(words=words):
                data = fields.pop("data", FAKE_CERT + FAKE_KEY)
                response = self.post(client, data, **fields)
                self.assertEqual(response.status_code, 200)
                self.assertIn(words, response.text)
        self.assertEqual(self.queued, [])

    def test_an_imported_name_may_be_replaced(self) -> None:
        response = self.post(self.writing_client(), name="imported.example.net")

        self.assertEqual(response.status_code, 303, response.text)
        self.assertEqual(self.queued[0]["payload"]["id"], "imported.example.net")

    def test_the_four_refusals_come_first(self) -> None:
        client = self.writing_client(role="reader")
        self.assertEqual(self.post(client).status_code, 403)
        client = self.writing_client()
        token = auth.csrf_token(client.cookies[auth.SESSION_COOKIE])
        self.assertEqual(self.post(client, **{auth.CSRF_FIELD: "wrong"}).status_code, 403)
        self.assertEqual(self.post(client, idempotency_key="").status_code, 400)
        del token
        self.assertEqual(self.queued, [])

    def test_a_busy_queue_is_said_on_the_page(self) -> None:
        with mock.patch("haproxy_ui.db.queue_job", side_effect=db.CertificateBusy()):
            response = self.post(self.writing_client())
        self.assertEqual(response.status_code, 200)
        self.assertIn("already running", response.text)


class TheRowUpload(ImportPageTestCase):
    def test_the_button_is_on_an_imported_row_only(self) -> None:
        client = self.writing_client()
        page = client.get("/certificates?view=registry&open=imported.example.net").text
        self.assertIn('action="/certificates/imported.example.net/upload"', page)
        self.assertIn("Upload certificate", page)
        self.assertIn('id="upload-registry-imported.example.net"', page)

        page = client.get("/certificates?view=registry&open=example.com").text
        self.assertNotIn("/upload", page)

        page = (
            self.writing_client(role="reader")
            .get("/certificates?view=registry&open=imported.example.net")
            .text
        )
        self.assertNotIn("/upload", page)

    def test_a_certificate_alone_is_sealed_with_the_row_s_own_targets(self) -> None:
        response = self.upload(self.writing_client(), "imported.example.net", FAKE_CERT)

        self.assertEqual(response.status_code, 303, response.text)
        self.assertEqual(
            response.headers["location"], "/certificates?view=registry&open=imported.example.net"
        )
        payload = self.queued[0]["payload"]
        self.assertEqual(payload["id"], "imported.example.net")
        self.assertEqual(payload["clusters"], ["alpha"])
        self.assertEqual(payload["receivers"], [])
        opened = cert_upload.open_upload(
            self.private,
            base64.b64decode(payload["ciphertext"]),
            certificate_id="imported.example.net",
        )
        self.assertEqual(opened.data, FAKE_CERT)
        self.assertIsNone(opened.password)

    def test_a_file_with_a_key_is_refused_and_pointed_at_the_import_page(self) -> None:
        response = self.upload(self.writing_client(), "imported.example.net", FAKE_CERT + FAKE_KEY)

        self.assertEqual(response.status_code, 400)
        self.assertIn("holds a private key", response.text)
        self.assertIn("Import certificate", response.text)
        self.assertNotIn(KEY_MARK, response.text)
        self.assertEqual(self.queued, [])

    def test_a_row_that_is_not_an_import_is_refused(self) -> None:
        response = self.upload(self.writing_client(), "example.com", FAKE_CERT)
        self.assertEqual(response.status_code, 400)
        self.assertIn("not an imported certificate", response.text)
        response = self.upload(self.writing_client(), "nobody.example.net", FAKE_CERT)
        self.assertEqual(response.status_code, 404)
        self.assertEqual(self.queued, [])


if __name__ == "__main__":
    unittest.main()
