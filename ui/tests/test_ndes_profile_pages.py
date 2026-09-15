"""NDES profile routes seal credentials and never echo a challenge."""

from __future__ import annotations

from typing import Any
from unittest import mock
from uuid import uuid4

from haproxy_mgmt.ndes_profiles import open_profile

from haproxy_ui import auth, db, operations
from tests.test_dns_profile_pages import GUARD, KEY, ProfileRouteTestCase, profile_row

ENDPOINT = "https://ca.example.com/certsrv/mscep/mscep.dll"


class NdesPages(ProfileRouteTestCase):
    def setUp(self) -> None:
        super().setUp()

        def create(_c: object, **fields: Any) -> db.DnsProfile:
            self.created.append(fields)
            return profile_row(id=fields["profile_id"], provider_id="ndes", key_id=fields["key_id"])

        def replacing(_c: object, **fields: Any) -> db.DnsProfile:
            self.replaced.append(fields)
            return profile_row(
                id=fields["profile_id"], provider_id="ndes", revision=fields["revision"]
            )

        for patch in (
            mock.patch("haproxy_ui.db.create_ndes_profile", side_effect=create),
            mock.patch("haproxy_ui.db.replace_ndes_profile", side_effect=replacing),
            mock.patch("haproxy_ui.db.ndes_profiles", side_effect=lambda _c: list(self.rows)),
            mock.patch(
                "haproxy_ui.db.ndes_profile",
                side_effect=lambda _c, pid: next((r for r in self.rows if r.id == pid), None),
            ),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def post_ndes(self, client: Any, path: str = "/ndes-profiles/new", **fields: Any) -> Any:
        data = {
            "profile_id": "internal-ca",
            "field.endpoint": ENDPOINT,
            "field.challenge": GUARD,
            "idempotency_key": KEY,
            auth.CSRF_FIELD: auth.csrf_token(client.cookies[auth.SESSION_COOKIE]),
        }
        data.update(fields)
        return client.post(path, data=data, follow_redirects=False)

    def test_routes_require_admin_and_csrf(self) -> None:
        self.assertEqual(self.writing_client(role="reader").get("/ndes-profiles").status_code, 403)
        client = self.writing_client()
        self.assertEqual(client.get("/ndes-profiles").status_code, 200)
        self.assertEqual(self.post_ndes(client, csrf_token=str(uuid4())).status_code, 403)
        self.assertEqual(self.created, [])

    def test_submission_seals_secret_and_queues_only_identity_revision(self) -> None:
        response = self.post_ndes(self.writing_client())
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/ndes-profiles")
        stored = self.created[0]
        opened = open_profile(
            self.private_key, stored["ciphertext"], profile_id="internal-ca", revision=1
        )
        self.assertEqual(opened.challenge, GUARD)
        self.assertNotIn(GUARD.encode(), stored["ciphertext"])
        self.assertEqual(self.queued[0]["operation"], "ndes_profile_apply")
        self.assertEqual(self.queued[0]["payload"], {"profile": "internal-ca", "revision": 1})
        self.assertNotIn(GUARD, repr(self.queued))

    def test_refusal_keeps_endpoint_but_never_challenge(self) -> None:
        response = self.post_ndes(self.writing_client(), **{"field.challenge": GUARD + "\n"})
        self.assertEqual(response.status_code, 200)
        self.assertIn(ENDPOINT, response.text)
        self.assertNotIn(GUARD, response.text)
        self.assertEqual(self.created, [])

    def test_replacement_uses_next_revision(self) -> None:
        self.rows = [profile_row(id="internal-ca", provider_id="ndes", revision=3)]
        response = self.post_ndes(self.writing_client(), "/ndes-profiles/internal-ca/replace")
        self.assertEqual(response.status_code, 303)
        self.assertEqual(self.replaced[0]["revision"], 4)

    def test_queue_failure_rolls_back_without_echoing_secret(self) -> None:
        with mock.patch("haproxy_ui.db.queue_job", side_effect=db.CertificateBusy):
            response = self.post_ndes(self.writing_client())
        self.assertEqual(response.status_code, 200)
        self.assertIn("already running", response.text)
        self.assertNotIn(GUARD, response.text)

    def test_worker_selects_exact_helper_and_refuses_dns_row(self) -> None:
        row = operations.SealedProfileRow(
            id="internal-ca",
            provider_id="ndes",
            schema_version=1,
            key_id=self.public_key.key_id,
            revision=2,
            ciphertext=b"x" * 48,
        )
        prepared = operations.prepare(
            operation="ndes_profile_apply",
            cluster=None,
            request_id=uuid4(),
            payload={"profile": "internal-ca", "revision": 1},
            profile_lookup=lambda _p: row,
        )
        self.assertTrue(prepared.argv[-1].endswith("haproxy-ndes-profile-apply-helper"))
        with self.assertRaises(operations.BadPayload):
            operations.prepare(
                operation="ndes_profile_apply",
                cluster=None,
                request_id=uuid4(),
                payload={"profile": "internal-ca", "revision": 1},
                profile_lookup=lambda _p: operations.SealedProfileRow(
                    id="internal-ca",
                    provider_id="cloudflare",
                    schema_version=1,
                    key_id=self.public_key.key_id,
                    revision=2,
                    ciphertext=b"x" * 48,
                ),
            )
