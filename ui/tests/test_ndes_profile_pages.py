"""NDES profile routes seal credentials and never echo a challenge."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest import mock
from uuid import uuid4

from haproxy_mgmt.ndes_profiles import open_profile

from haproxy_ui import auth, db, operations
from tests.test_certificates import reading as certificate_reading
from tests.test_certificates import registered, with_registry
from tests.test_dns_profile_pages import GUARD, KEY, ProfileRouteTestCase, profile_row
from tests.test_queue_route import queued

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
        self.assertTrue(prepared.argv[-1].endswith("haprion-ndes-profile-apply-helper"))
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


class RemovingAnNdesProfile(NdesPages):
    def test_removal_has_a_confirmation_page_and_queues_a_fenced_job(self) -> None:
        self.rows = [
            profile_row(id="internal-ca", provider_id="ndes", revision=3, endpoint=ENDPOINT)
        ]
        client = self.writing_client()
        listing = client.get("/ndes-profiles")
        self.assertIn(ENDPOINT, listing.text)
        self.assertIn('href="/ndes-profiles/internal-ca/remove"', listing.text)

        page = client.get("/ndes-profiles/internal-ca/remove")
        self.assertEqual(page.status_code, 200)
        self.assertIn("Remove NDES profile", page.text)
        self.assertIn('class="refusal-card"', page.text)
        self.assertIn("still registered", page.text)
        self.assertIn(ENDPOINT, page.text)
        self.assertIn(">Keep it</a>", page.text)

        token = auth.csrf_token(client.cookies[auth.SESSION_COOKIE])
        response = client.post(
            "/ndes-profiles/internal-ca/remove",
            data={auth.CSRF_FIELD: token, "idempotency_key": KEY},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/ndes-profiles?removed=internal-ca")
        self.assertEqual(
            self.queued[0]["payload"],
            {"profile": "internal-ca", "revision": 3, "remove": True},
        )
        self.assertEqual(client.get("/ndes-profiles/missing/remove").status_code, 404)

    def test_a_refused_removal_says_why_on_the_page(self) -> None:
        self.rows = [profile_row(id="certserver1", provider_id="ndes", key_id=self.public_key.key_id)]
        refused = queued(
            id=41,
            operation="ndes_profile_apply",
            cluster=None,
            state="failed",
            payload={"profile": "certserver1", "revision": 1, "remove": True},
            result={
                "error": {
                    "code": "profile_in_use",
                    "message": "profile 'certserver1' is referenced by certificate(s): webserver1-scep",
                }
            },
        )
        applied = replace(
            refused, id=40, state="done", payload={"profile": "certserver1", "revision": 1}, result=None
        )
        with mock.patch("haproxy_ui.db.recent_jobs", return_value=[refused, applied]):
            client = self.writing_client()
            page = client.get("/ndes-profiles?removed=certserver1").text
            later = client.get("/ndes-profiles").text
        self.assertIn("In effect", page)
        self.assertIn("Removal of <code>certserver1</code> was refused.", page)
        self.assertIn("webserver1-scep", page)
        # Once is enough: the next visit keeps the status column's link only.
        self.assertNotIn("was refused", later)
        self.assertIn("· Removal refused</a>", later)

        # And the link is for an hour: a refusal from this morning is not
        # the profile's state (seen 2026-09-15: "I have not tried to remove it").
        stale = replace(refused, finished_at=datetime.now(UTC) - timedelta(hours=2))
        with mock.patch("haproxy_ui.db.recent_jobs", return_value=[stale, applied]):
            old = self.writing_client().get("/ndes-profiles?removed=certserver1").text
        self.assertIn("In effect", old)
        self.assertNotIn("Removal refused", old)
        self.assertNotIn("was refused", old)

        # Once the registry no longer names the profile the reason is gone,
        # and so is the note - without waiting for another attempt.
        emptied = with_registry(certificate_reading(), registered("unrelated", kind="import"))
        with (
            mock.patch("haproxy_ui.db.recent_jobs", return_value=[refused, applied]),
            mock.patch("haproxy_ui.db.cluster_certificates", return_value=[emptied]),
        ):
            page = self.writing_client().get("/ndes-profiles").text
        self.assertIn("In effect", page)
        self.assertNotIn("was refused", page)
        self.assertNotIn("Removal refused", page)

    def test_the_replace_form_starts_with_the_stored_endpoint(self) -> None:
        self.rows = [profile_row(id="certserver1", provider_id="ndes", endpoint=ENDPOINT)]
        page = self.writing_client().get("/ndes-profiles/certserver1/replace").text
        self.assertIn(f'value="{ENDPOINT}"', page)
        self.assertIn(
            'class="form-buttons"><a class="secondary-button" href="/ndes-profiles">Cancel</a>',
            page,
        )

    def test_a_row_from_before_the_endpoint_column_says_so(self) -> None:
        self.rows = [profile_row(id="internal-ca", provider_id="ndes")]
        listing = self.writing_client().get("/ndes-profiles")
        self.assertIn("shown after the next replace", listing.text)

    def test_saving_keeps_a_plain_copy_of_the_checked_endpoint(self) -> None:
        self.post_ndes(self.writing_client())
        self.assertEqual(self.created[0]["endpoint"], ENDPOINT)

    def test_worker_removal_is_fenced_on_the_exact_revision(self) -> None:
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
            payload={"profile": "internal-ca", "revision": 2, "remove": True},
            profile_lookup=lambda _p: row,
        )
        self.assertIs(json.loads(prepared.request)["parameters"]["remove"], True)
        with self.assertRaises(operations.BadPayload):
            operations.prepare(
                operation="ndes_profile_apply",
                cluster=None,
                request_id=uuid4(),
                payload={"profile": "internal-ca", "revision": 1, "remove": True},
                profile_lookup=lambda _p: row,
            )
