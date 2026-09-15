"""The DNS provider profile pages: sealed on save, never shown again.

The form module's judgement is tested first without HTTP; the routes are
then held to the same gates as the certificate form and to the one promise
that matters here - nothing typed into a secret field appears in any
response, any stored row, any job payload or any audit record.
"""

from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from time import monotonic
from typing import Any
from unittest import mock
from uuid import UUID, uuid4

from haproxy_mgmt.dns_profile_keys import generate, render_public_key
from haproxy_mgmt.dns_profiles import open_profile

from haproxy_ui import auth, db, dns_profile_form
from tests.test_login import LoginTestCase, configuration
from tests.test_queue_route import queued

KEY = str(uuid4())
GUARD = "sample-value-never-echoed"


def profile_row(**overrides: Any) -> db.DnsProfile:
    now = datetime.now(UTC)
    fields: dict[str, Any] = {
        "id": "cf-main",
        "name": "Cloudflare main",
        "provider_id": "cloudflare",
        "schema_version": 1,
        "key_id": "0123456789abcdef",
        "revision": 1,
        "created_at": now,
        "created_by": "operator",
        "updated_at": now,
        "updated_by": "operator",
    }
    return db.DnsProfile(**{**fields, **overrides})


class TheFormModule(unittest.TestCase):
    def setUp(self) -> None:
        self.private_key, self.public_key = generate()

    def seal(self, **overrides: Any) -> dns_profile_form.Sealed:
        form = dns_profile_form.ProfileForm(
            profile_id="cf-main", provider_id="cloudflare", values={"api_token": GUARD}
        )
        return dns_profile_form.seal_submission(
            replace(form, **overrides), self.public_key, revision=1
        )

    def test_a_good_submission_seals_the_catalogue_s_fields_and_nothing_else(self) -> None:
        sealed = self.seal()
        self.assertEqual(sealed.name, "cf-main")
        self.assertEqual(sealed.key_id, self.public_key.key_id)
        opened = open_profile(
            self.private_key,
            sealed.ciphertext,
            profile_id="cf-main",
            provider_id="cloudflare",
            revision=1,
        )
        self.assertEqual(opened.credentials, f"dns_cloudflare_api_token = {GUARD}\n")

    def test_refusals_name_the_field_and_never_the_value(self) -> None:
        cases = [
            (dict(profile_id="Cf Main"), "Profile ID"),
            (dict(provider_id="example"), "Choose a DNS provider"),
            (dict(values={"api_token": ""}), "API token — required"),
            (dict(values={"api_token": GUARD + "\nx = y"}), "API token — "),
        ]
        for overrides, expected in cases:
            with self.subTest(expected=expected):
                with self.assertRaises(dns_profile_form.FormProblem) as caught:
                    self.seal(**overrides)
                self.assertIn(expected, str(caught.exception))
                self.assertNotIn(GUARD, str(caught.exception))

    def test_a_taken_id_is_refused_for_a_new_profile_only(self) -> None:
        form = dns_profile_form.ProfileForm(
            profile_id="cf-main", provider_id="cloudflare", values={"api_token": "t"}
        )
        with self.assertRaisesRegex(dns_profile_form.FormProblem, "already exists"):
            dns_profile_form.seal_submission(form, self.public_key, revision=1, taken=["cf-main"])
        dns_profile_form.seal_submission(form, self.public_key, revision=2, taken=["cf-main"])

    def test_optional_fields_lists_and_choices_take_the_form_s_shapes(self) -> None:
        form = dns_profile_form.ProfileForm(
            profile_id="bind",
            provider_id="rfc2136",
            values={"server": "192.0.2.53", "name": "acme", "secret": "YWJj", "algorithm": ""},
        )
        sealed = dns_profile_form.seal_submission(form, self.public_key, revision=1)
        opened = open_profile(
            self.private_key,
            sealed.ciphertext,
            profile_id="bind",
            provider_id="rfc2136",
            revision=1,
        )
        self.assertNotIn("algorithm", opened.credentials)
        azure = dns_profile_form.ProfileForm(
            profile_id="az",
            provider_id="azure",
            values={
                "client_id": "c",
                "client_secret": "s",
                "tenant_id": "t",
                "zone_mappings": "example.com:/subscriptions/x/resourceGroups/dns\r\n\r\n"
                "example.net:/subscriptions/x/resourceGroups/dns\n",
            },
        )
        sealed = dns_profile_form.seal_submission(azure, self.public_key, revision=1)
        opened = open_profile(
            self.private_key, sealed.ciphertext, profile_id="az", provider_id="azure", revision=1
        )
        self.assertIn("dns_azure_zone2 = example.net", opened.credentials)

    def test_redrawn_values_leave_the_secrets_out(self) -> None:
        chosen = dns_profile_form.provider("rfc2136")
        values = dns_profile_form.redraw_values(
            chosen, {"server": "192.0.2.53", "secret": "YWJj", "name": "acme"}
        )
        self.assertEqual(values, {"server": "192.0.2.53", "name": "acme", "algorithm": ""})

    def test_status_follows_the_newest_apply_job_for_the_current_revision(self) -> None:
        def job(state: str, revision: int) -> db.Job:
            return queued(
                operation="dns_profile_apply",
                cluster=None,
                state=state,
                payload={"profile": "cf-main", "revision": revision},
            )

        status = dns_profile_form.profile_status
        self.assertEqual(status("cf-main", 1, []).label, "Not applied")
        self.assertTrue(status("cf-main", 1, [job("done", 1)]).usable)
        self.assertEqual(status("cf-main", 2, [job("done", 1)]).label, "Replaced; not applied")
        self.assertEqual(
            status("cf-main", 2, [job("pending", 2), job("done", 1)]).label, "Applying"
        )
        self.assertEqual(status("cf-main", 1, [job("failed", 1)]).label, "Apply failed")
        removing = queued(
            operation="dns_profile_apply",
            cluster=None,
            state="pending",
            payload={"profile": "cf-main", "revision": 1, "remove": True},
        )
        self.assertEqual(status("cf-main", 1, [removing]).label, "Removing")
        refused = replace(
            removing,
            state="failed",
            result={"error": {"code": "profile_in_use"}},
        )
        applied = job("done", 1)
        refused_status = status("cf-main", 1, [refused, applied])
        self.assertEqual(refused_status.label, "In effect")
        self.assertTrue(refused_status.usable)
        self.assertEqual(refused_status.attention_job, refused.id)
        failed = replace(refused, result={"error": {"code": "dependency_unavailable"}})
        self.assertFalse(status("cf-main", 1, [failed]).usable)
        self.assertEqual(
            status("cf-main", 1, [queued(operation="cert_issue", cluster=None)]).label,
            "Not applied",
        )


class ProfileRouteTestCase(LoginTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.private_key, self.public_key = generate()
        self.key_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.key_dir.cleanup)
        self.public_path = Path(self.key_dir.name) / f"{self.public_key.key_id}.pub"
        self.public_path.write_text(render_public_key(self.public_key))
        self.queued: list[dict[str, Any]] = []
        self.created: list[dict[str, Any]] = []
        self.replaced: list[dict[str, Any]] = []
        self.rows: list[db.DnsProfile] = []
        self.job_states: list[str] = ["done"]
        self.state_reads = 0

        def job_state(_c: object, _job_id: int) -> str:
            self.state_reads += 1
            return self.job_states[min(self.state_reads, len(self.job_states)) - 1]

        def queue(_c: object, **fields: Any) -> db.Job:
            self.queued.append(fields)
            return queued(operation="dns_profile_apply", cluster=None)

        def create(_c: object, **fields: Any) -> db.DnsProfile:
            self.created.append(fields)
            return profile_row(id=fields["profile_id"], key_id=fields["key_id"])

        def replace_profile(_c: object, **fields: Any) -> db.DnsProfile:
            self.replaced.append(fields)
            return profile_row(id=fields["profile_id"], revision=fields["revision"])

        for patch in (
            mock.patch("haproxy_ui.db.queue_job", side_effect=queue),
            mock.patch("haproxy_ui.db.create_dns_profile", side_effect=create),
            mock.patch("haproxy_ui.db.replace_dns_profile", side_effect=replace_profile),
            mock.patch("haproxy_ui.db.dns_profiles", side_effect=lambda _c: list(self.rows)),
            mock.patch("haproxy_ui.db.job_state", side_effect=job_state),
            mock.patch("haproxy_ui.views.DNS_PROFILE_APPLY_WAIT", 1.0),
            mock.patch(
                "haproxy_ui.db.dns_profile",
                side_effect=lambda _c, pid: next((r for r in self.rows if r.id == pid), None),
            ),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def writing_client(self, *, role: str = "admin", with_key: bool = True) -> Any:
        self.account = replace(self.account, role=role)
        client = self.client(
            replace(
                configuration(),
                management_writes=True,
                dns_profiles_public_key=self.public_path if with_key else None,
            )
        )
        self.sign_in(client)
        return client

    def post(self, client: Any, path: str = "/dns-profiles/new", **fields: Any) -> Any:
        token = auth.csrf_token(client.cookies[auth.SESSION_COOKIE])
        data: dict[str, Any] = {
            "profile_id": "cf-main",
            "provider_id": "cloudflare",
            "field.api_token": GUARD,
            "idempotency_key": KEY,
            auth.CSRF_FIELD: token,
        }
        data.update(fields)
        return client.post(path, data=data, follow_redirects=False)


class ThePages(ProfileRouteTestCase):
    def test_the_gates_are_the_certificate_form_s(self) -> None:
        client = self.client(configuration())
        self.sign_in(client)
        self.assertEqual(client.get("/dns-profiles").status_code, 404)
        self.assertEqual(self.writing_client(role="reader").get("/dns-profiles").status_code, 403)
        self.assertEqual(self.writing_client().get("/dns-profiles").status_code, 200)

    def test_the_listing_shows_status_and_only_calls_out_an_old_key(self) -> None:
        self.rows = [
            profile_row(key_id=self.public_key.key_id),
            profile_row(id="old", name="Old key", key_id="ffffffffffffffff", revision=3),
        ]
        with mock.patch(
            "haproxy_ui.db.recent_jobs",
            return_value=[
                queued(
                    operation="dns_profile_apply",
                    cluster=None,
                    state="done",
                    payload={"profile": "cf-main", "revision": 1},
                )
            ],
        ):
            page = self.writing_client().get("/dns-profiles").text

        self.assertIn("In effect", page)
        self.assertIn("Not applied", page)
        self.assertIn("old sealing key", page)
        self.assertNotIn('<th scope="col">Key</th>', page)
        self.assertNotIn(self.public_key.key_id, page)
        self.assertIn("Cloudflare <span", page)
        self.assertIn('href="/dns-profiles/cf-main/replace"', page)
        self.assertIn('href="/dns-profiles/new"', page)
        self.assertNotIn(GUARD, page)

    def test_a_reference_refusal_leaves_the_profile_in_effect_and_links_to_the_job(self) -> None:
        self.rows = [profile_row(key_id=self.public_key.key_id)]
        refused = queued(
            id=41,
            operation="dns_profile_apply",
            cluster=None,
            state="failed",
            payload={"profile": "cf-main", "revision": 1, "remove": True},
            result={
                "error": {
                    "code": "profile_in_use",
                    "message": "profile 'cf-main' is referenced by certificate(s): shop",
                }
            },
        )
        applied = replace(
            refused,
            id=40,
            state="done",
            payload={"profile": "cf-main", "revision": 1},
            result=None,
        )
        with mock.patch("haproxy_ui.db.recent_jobs", return_value=[refused, applied]):
            page = self.writing_client().get("/dns-profiles").text

        self.assertIn("In effect", page)
        self.assertIn('href="/jobs#job-41">· Removal refused</a>', page)
        # The helper's reason is on the page itself, not one click away.
        self.assertIn("Removal of <code>cf-main</code> was refused.", page)
        self.assertIn("referenced by certificate(s): shop", page)

    def test_without_a_key_the_page_says_so_and_offers_no_form(self) -> None:
        page = self.writing_client(with_key=False).get("/dns-profiles").text
        self.assertIn("no DNS profile key", page)
        self.assertNotIn('href="/dns-profiles/new"', page)

    def test_the_new_form_asks_for_a_provider_then_draws_its_fields(self) -> None:
        client = self.writing_client()
        first = client.get("/dns-profiles/new").text
        self.assertIn('<option value="cloudflare"', first)
        self.assertIn("80 providers", first)
        self.assertNotIn('name="field.', first)

        second = client.get("/dns-profiles/new?provider=rfc2136").text
        self.assertIn('name="field.server"', second)
        self.assertIn('type="password" name="field.secret"', second)
        self.assertIn('<select name="field.algorithm"', second)
        self.assertIn("HMAC-SHA256", second)
        self.assertIn("Save and apply", second)
        self.assertIn('placeholder="rfc2136"', second)
        self.assertIn("Plugin and credential format tested", second)

        unknown = client.get("/dns-profiles/new?provider=example").text
        self.assertNotIn('name="field.', unknown)

    def test_providers_are_offered_in_one_alphabet_with_the_tier_as_a_suffix(self) -> None:
        offered = dns_profile_form.providers()
        names = [provider.name.lower() for provider in offered]
        self.assertEqual(names, sorted(names))
        self.assertIn("community", {provider.tier for provider in offered[:3]})
        page = self.writing_client().get("/dns-profiles/new").text
        self.assertIn(">Cloudflare</option>", page)
        self.assertIn("(community plugin)</option>", page)
        self.assertNotIn('name="name"', page)

    def test_the_certificates_page_links_here_for_an_admin(self) -> None:
        self.assertIn('href="/dns-profiles"', self.writing_client().get("/certificates").text)


class SavingAProfile(ProfileRouteTestCase):
    def test_a_good_submission_stores_a_box_and_queues_one_apply_job(self) -> None:
        response = self.post(self.writing_client())

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/dns-profiles")
        self.assertEqual(len(self.created), 1)
        stored = self.created[0]
        self.assertEqual(stored["profile_id"], "cf-main")
        self.assertEqual(stored["provider_id"], "cloudflare")
        self.assertEqual(stored["key_id"], self.public_key.key_id)
        self.assertNotIn(GUARD.encode(), stored["ciphertext"])
        opened = open_profile(
            self.private_key,
            stored["ciphertext"],
            profile_id="cf-main",
            provider_id="cloudflare",
            revision=1,
        )
        self.assertEqual(opened.fields, {"api_token": GUARD})

        self.assertEqual(len(self.queued), 1)
        job = self.queued[0]
        self.assertEqual(job["operation"], "dns_profile_apply")
        self.assertIsNone(job["cluster"])
        self.assertEqual(job["payload"], {"profile": "cf-main", "revision": 1})
        self.assertEqual(job["idempotency_key"], UUID(KEY))
        self.assertNotIn(GUARD, repr(job))
        self.assertIn("queue_job", self.audit)

    def test_saving_waits_for_the_apply_job_and_lands_on_the_result(self) -> None:
        self.job_states = ["pending", "running", "done"]
        started = monotonic()
        response = self.post(self.writing_client())
        self.assertEqual(response.status_code, 303)
        self.assertEqual(self.state_reads, 3)
        self.assertLess(monotonic() - started, 1.0)

    def test_a_slow_apply_job_is_left_to_the_list_s_own_refresh(self) -> None:
        self.job_states = ["running"]
        started = monotonic()
        response = self.post(self.writing_client())
        self.assertEqual(response.status_code, 303)
        self.assertGreaterEqual(monotonic() - started, 1.0)
        self.assertGreaterEqual(self.state_reads, 3)

        self.rows = [profile_row()]
        with mock.patch(
            "haproxy_ui.db.recent_jobs",
            return_value=[
                queued(
                    operation="dns_profile_apply",
                    cluster=None,
                    payload={"profile": "cf-main", "revision": 1},
                )
            ],
        ):
            page = self.writing_client().get("/dns-profiles").text
        self.assertIn("Applying", page)
        self.assertIn('http-equiv="refresh" content="3"', page)
        self.assertNotIn('href="/jobs"', page.split("<main")[1])

    def test_a_refusal_redraws_the_form_without_the_secret(self) -> None:
        response = self.post(self.writing_client(), **{"field.api_token": ""})
        self.assertEqual(response.status_code, 200)
        self.assertIn("API token — required", response.text)
        self.assertIn('value="cf-main"', response.text)
        self.assertEqual(self.created, [])
        self.assertEqual(self.queued, [])

        response = self.post(self.writing_client(), **{"field.api_token": GUARD + "\nx = y"})
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(GUARD, response.text)

    def test_a_replace_keeps_the_provider_and_seals_the_next_revision(self) -> None:
        self.rows = [profile_row(revision=2)]
        client = self.writing_client()
        page = client.get("/dns-profiles/cf-main/replace").text
        self.assertIn("revision 3", page)
        self.assertNotIn('name="profile_id"', page)
        self.assertNotIn('<select name="provider"', page)

        response = self.post(
            client, "/dns-profiles/cf-main/replace", provider_id="hetzner", profile_id="other"
        )
        self.assertEqual(response.status_code, 303)
        self.assertEqual(self.created, [])
        self.assertEqual(len(self.replaced), 1)
        self.assertEqual(self.replaced[0]["profile_id"], "cf-main")
        self.assertEqual(self.replaced[0]["revision"], 3)
        opened = open_profile(
            self.private_key,
            self.replaced[0]["ciphertext"],
            profile_id="cf-main",
            provider_id="cloudflare",
            revision=3,
        )
        self.assertEqual(opened.revision, 3)
        self.assertEqual(self.queued[0]["payload"], {"profile": "cf-main", "revision": 3})
        self.assertEqual(client.get("/dns-profiles/missing/replace").status_code, 404)

    def test_the_request_gates_hold(self) -> None:
        client = self.writing_client()
        self.assertEqual(self.post(client, **{auth.CSRF_FIELD: "wrong"}).status_code, 403)
        self.assertEqual(self.post(client, idempotency_key="x").status_code, 400)
        self.assertEqual(self.post(self.writing_client(role="reader")).status_code, 403)
        self.assertEqual(self.post(self.writing_client(with_key=False)).status_code, 200)
        self.assertEqual(self.created, [])

    def test_a_busy_certificate_slot_is_said_on_the_form(self) -> None:
        with mock.patch("haproxy_ui.db.queue_job", side_effect=db.CertificateBusy()):
            response = self.post(self.writing_client())
        self.assertEqual(response.status_code, 200)
        self.assertIn("already running", response.text)
        self.assertEqual(self.pool.rollbacks, 1)


class RemovingAProfile(ProfileRouteTestCase):
    def test_removal_has_a_confirmation_page_and_queues_a_fenced_job(self) -> None:
        self.rows = [profile_row(revision=3)]
        client = self.writing_client()
        page = client.get("/dns-profiles/cf-main/remove")
        self.assertEqual(page.status_code, 200)
        self.assertIn("Remove DNS profile", page.text)
        self.assertIn('class="refusal-card"', page.text)
        self.assertIn("still uses the profile", page.text)
        self.assertIn("A refused removal leaves the working profile in effect", page.text)
        self.assertIn(">Keep it</a>", page.text)

        token = auth.csrf_token(client.cookies[auth.SESSION_COOKIE])
        response = client.post(
            "/dns-profiles/cf-main/remove",
            data={auth.CSRF_FIELD: token, "idempotency_key": KEY},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/dns-profiles")
        self.assertEqual(
            self.queued[0]["payload"],
            {"profile": "cf-main", "revision": 3, "remove": True},
        )


if __name__ == "__main__":
    unittest.main()
