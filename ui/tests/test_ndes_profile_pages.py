"""NDES profile routes seal credentials and never echo a challenge."""

from __future__ import annotations

import json
import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest import mock
from uuid import uuid4

from haprion.ndes_profiles import open_profile
from haprion.ndes_servers import NdesServerError

from haprion_ui import audit, auth, db, operations
from tests.test_certificates import reading as certificate_reading
from tests.test_certificates import registered, with_registry
from tests.test_dns_profile_pages import GUARD, KEY, ProfileRouteTestCase, profile_row
from tests.test_queue_route import queued

ENDPOINT = "https://ca.example.com/certsrv/mscep/mscep.dll"


class NdesRoutes(ProfileRouteTestCase):
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

        #
        # The root helper behind /run/haprion/ndes-server.sock, as the web asks it.
        #
        self.servers = [ENDPOINT]
        self.states: dict[str, str] = {}
        self.expires: dict[str, str | None] = {}
        self.asked: list[tuple[str, dict[str, Any]]] = []
        self.authorities: list[dict[str, Any]] = [
            {
                "subject": "CN=Example Issuing CA",
                "sha256": "a" * 64,
                "sha1": "b" * 40,
                "issues_ra": True,
            },
        ]

        def ask(action: str, **parameters: Any) -> dict[str, Any]:
            self.asked.append((action, parameters))
            endpoint = parameters.get("endpoint", "")
            if action == "list":
                return {
                    "servers": [
                        {
                            "endpoint": e,
                            "issuing_ca": "/etc/haprion/ndes-ca/0.pem",
                            "expires": self.expires.get(e),
                        }
                        for e in self.servers
                    ]
                }
            if action == "fetch":
                return {
                    "endpoint": endpoint,
                    "state": self.states.get(
                        endpoint, "confirmed" if endpoint in self.servers else "new"
                    ),
                    "authorities": self.authorities,
                }
            if action == "add":
                if sorted(parameters["sha256"]) != sorted(a["sha256"] for a in self.authorities):
                    raise NdesServerError("changed", f"{endpoint} no longer gives that CA")
                if endpoint not in self.servers:
                    self.servers.append(endpoint)
                self.states.pop(endpoint, None)
                return {
                    "endpoint": endpoint,
                    "issuing_ca": "/etc/haprion/ndes-ca/1.pem",
                    "sha256": parameters["sha256"],
                }
            self.servers.remove(endpoint)
            return {"endpoint": endpoint}

        self.audited: list[dict[str, Any]] = []
        for patch in (
            mock.patch("haprion_ui.pages.profiles.ndes_server_socket.ask", side_effect=ask),
            mock.patch(
                "haprion_ui.db.record_audit_event",
                side_effect=lambda _c, **fields: self.audited.append(fields),
            ),
            mock.patch("haprion_ui.db.create_ndes_profile", side_effect=create),
            mock.patch("haprion_ui.db.replace_ndes_profile", side_effect=replacing),
            mock.patch("haprion_ui.db.ndes_profiles", side_effect=lambda _c: list(self.rows)),
            mock.patch(
                "haprion_ui.db.ndes_profile",
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


class NdesPages(NdesRoutes):
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
        with mock.patch("haprion_ui.db.queue_job", side_effect=db.CertificateBusy):
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


class TheNdesServers(NdesRoutes):
    """B383, B385: a profile chooses among servers each confirmed from its CA."""

    def test_the_server_list_says_when_each_confirmed_ca_expires(self) -> None:
        """B389: a CA running out is seen before the renewals fail on it."""

        other = "https://ca2.example.com/certsrv/mscep/mscep.dll"
        self.servers = [ENDPOINT, other]
        soon = datetime.now(UTC) + timedelta(days=10, hours=1)
        self.expires = {ENDPOINT: soon.isoformat(timespec="seconds").replace("+00:00", "Z")}
        client = self.writing_client()
        page = client.get("/ndes-profiles").text
        self.assertIn('<th scope="col" class="expires-column">CA expires</th>', page)
        self.assertIn(f'<span class="certificate-date">{soon:%y-%m-%d}</span>', page)
        self.assertIn('<span class="status-badge status-badge-warning">in 10 days</span>', page)
        row = page[page.index(f'value="{other}"') :]
        row = row[: row.index("</tr>")]
        self.assertIn('<td class="expires-column" data-label="CA expires">—</td>', row)

    def test_without_a_server_no_profile_is_offered_or_taken(self) -> None:
        self.servers = []
        client = self.writing_client()
        listing = client.get("/ndes-profiles")
        self.assertIn("No NDES server yet.", listing.text)
        self.assertIn('href="/ndes-profiles/servers/new"', listing.text)
        self.assertNotIn('href="/ndes-profiles/new"', listing.text)

        response = self.post_ndes(client)
        self.assertEqual(response.status_code, 200)
        self.assertIn("choose one of the servers confirmed on this manager", response.text)
        self.assertNotIn(GUARD, response.text)
        self.assertEqual((self.created, self.queued), ([], []))

    def test_a_server_is_added_once_its_ca_is_confirmed(self) -> None:
        other = "https://ca2.example.com/certsrv/mscep/mscep.dll"
        client = self.writing_client()
        csrf = auth.csrf_token(client.cookies[auth.SESSION_COOKIE])
        self.assertEqual(client.get("/ndes-profiles/servers/new").status_code, 200)

        shown = client.post(
            "/ndes-profiles/servers/new", data={"csrf_token": csrf, "endpoint": other}
        )
        self.assertIn("CN=Example Issuing CA", shown.text)
        self.assertIn("a" * 64, shown.text)
        self.assertIn("b" * 40, shown.text)
        self.assertNotIn(other, self.servers)

        confirmed = client.post(
            "/ndes-profiles/servers/confirm",
            data={"csrf_token": csrf, "endpoint": other, "sha256": "a" * 64},
            follow_redirects=False,
        )
        self.assertEqual(confirmed.status_code, 303)
        self.assertIn(other, self.servers)
        self.assertEqual(self.audited[-1]["action"], "ndes_server_added")
        self.assertIn(other, client.get("/ndes-profiles/new").text)

    def test_a_confirmed_server_is_not_shown_again(self) -> None:
        client = self.writing_client()
        csrf = auth.csrf_token(client.cookies[auth.SESSION_COOKIE])
        response = client.post(
            "/ndes-profiles/servers/new",
            data={"csrf_token": csrf, "endpoint": ENDPOINT},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)

    def test_a_server_whose_ca_changed_is_confirmed_again(self) -> None:
        """Review 2026-10-29, B01: a server in the policy went back to the list, whatever its CA."""

        self.states[ENDPOINT] = "changed"
        self.rows = [profile_row(id="internal-ca", provider_id="ndes", endpoint=ENDPOINT)]
        client = self.writing_client()
        csrf = auth.csrf_token(client.cookies[auth.SESSION_COOKIE])
        shown = client.post(
            "/ndes-profiles/servers/new", data={"csrf_token": csrf, "endpoint": ENDPOINT}
        )
        self.assertEqual(shown.status_code, 200)
        self.assertIn("confirmed with other CA certificates", shown.text)
        self.assertIn("a" * 64, shown.text)
        self.assertIn("Confirm this CA", shown.text)

        confirmed = client.post(
            "/ndes-profiles/servers/confirm",
            data={"csrf_token": csrf, "endpoint": ENDPOINT, "sha256": "a" * 64},
            follow_redirects=False,
        )
        self.assertEqual(confirmed.status_code, 303)
        self.assertEqual(self.asked[-1], ("add", {"endpoint": ENDPOINT, "sha256": ["a" * 64]}))
        self.assertEqual(self.audited[-1]["action"], "ndes_server_added")
        self.assertEqual(self.servers, [ENDPOINT])

    def test_a_root_completed_from_the_store_is_shown_and_confirmed_with_the_rest(self) -> None:
        other = "https://ca2.example.com/certsrv/mscep/mscep.dll"
        self.authorities.append(
            {
                "subject": "CN=Example Root CA",
                "sha256": "d" * 64,
                "sha1": "e" * 40,
                "issues_ra": False,
                "from_store": True,
            }
        )
        client = self.writing_client()
        csrf = auth.csrf_token(client.cookies[auth.SESSION_COOKIE])
        shown = client.post(
            "/ndes-profiles/servers/new", data={"csrf_token": csrf, "endpoint": other}
        ).text
        self.assertIn("CN=Example Root CA · from this manager's certificate store", shown)
        self.assertNotIn("CN=Example Issuing CA · issues for NDES · from", shown)
        self.assertIn(f'name="sha256" value="{"d" * 64}"', shown)

    def test_a_ca_that_changed_is_said_and_nothing_is_added(self) -> None:
        other = "https://ca2.example.com/certsrv/mscep/mscep.dll"
        client = self.writing_client()
        csrf = auth.csrf_token(client.cookies[auth.SESSION_COOKIE])
        response = client.post(
            "/ndes-profiles/servers/confirm",
            data={"csrf_token": csrf, "endpoint": other, "sha256": "c" * 64},
        )
        self.assertIn("no longer gives that CA", response.text)
        self.assertNotIn(other, self.servers)
        self.assertNotIn("ndes_server_added", [event["action"] for event in self.audited])

    def test_a_chain_is_confirmed_whole(self) -> None:
        # Review 2026-10-28, U02: every CA certificate shown is saved, so the
        # form sends every one, and the button says it confirms them all.
        other = "https://ca2.example.com/certsrv/mscep/mscep.dll"
        self.authorities.append(
            {
                "subject": "CN=Example Root CA",
                "sha256": "d" * 64,
                "sha1": "e" * 40,
                "issues_ra": False,
            }
        )
        client = self.writing_client()
        csrf = auth.csrf_token(client.cookies[auth.SESSION_COOKIE])
        shown = client.post(
            "/ndes-profiles/servers/new", data={"csrf_token": csrf, "endpoint": other}
        ).text
        self.assertIn("Confirm these CAs", shown)
        self.assertIn(f'name="sha256" value="{"a" * 64}"', shown)
        self.assertIn(f'name="sha256" value="{"d" * 64}"', shown)

        client.post(
            "/ndes-profiles/servers/confirm",
            data={"csrf_token": csrf, "endpoint": other, "sha256": "a" * 64},
        )
        self.assertNotIn(other, self.servers)
        confirmed = client.post(
            "/ndes-profiles/servers/confirm",
            data={"csrf_token": csrf, "endpoint": other, "sha256": ["a" * 64, "d" * 64]},
            follow_redirects=False,
        )
        self.assertEqual(confirmed.status_code, 303)
        self.assertEqual(self.asked[-1][1]["sha256"], ["a" * 64, "d" * 64])
        self.assertEqual(self.audited[-1]["detail"]["sha256"], ["a" * 64, "d" * 64])

    def test_a_server_in_use_stays_and_one_unused_is_removed(self) -> None:
        other = "https://ca2.example.com/certsrv/mscep/mscep.dll"
        self.servers.append(other)
        self.rows = [profile_row(id="internal-ca", provider_id="ndes", endpoint=ENDPOINT)]
        client = self.writing_client()
        csrf = auth.csrf_token(client.cookies[auth.SESSION_COOKIE])

        refused = client.post(
            "/ndes-profiles/servers/remove",
            data={"csrf_token": csrf, "endpoint": ENDPOINT},
            follow_redirects=True,
        )
        self.assertIn("is used by internal-ca", refused.text)
        self.assertIn(ENDPOINT, self.servers)

        client.post(
            "/ndes-profiles/servers/remove",
            data={"csrf_token": csrf, "endpoint": other},
            follow_redirects=False,
        )
        self.assertNotIn(other, self.servers)
        self.assertEqual(self.audited[-1]["action"], "ndes_server_removed")

    def test_a_change_the_service_did_not_answer_is_recorded_as_unknown(self) -> None:
        """Review 2026-10-29, B12: root may have changed the policy, and nothing said so."""

        client = self.writing_client()
        csrf = auth.csrf_token(client.cookies[auth.SESSION_COOKIE])
        unanswered = NdesServerError("unanswered", "the NDES server service did not answer")
        with mock.patch("haprion_ui.pages.profiles.ndes_server_socket.ask", side_effect=unanswered):
            shown = client.post(
                "/ndes-profiles/servers/confirm",
                data={"csrf_token": csrf, "endpoint": ENDPOINT, "sha256": "a" * 64},
            )
            client.post(
                "/ndes-profiles/servers/remove",
                data={"csrf_token": csrf, "endpoint": ENDPOINT},
                follow_redirects=False,
            )
        self.assertIn("did not answer", shown.text)
        self.assertEqual(
            [
                (e["action"], e["detail"].get("outcome"))
                for e in self.audited
                if e["action"].startswith("ndes_server")
            ],
            [("ndes_server_added", "unknown"), ("ndes_server_removed", "unknown")],
        )
        phrase = audit.ACTIVITY_PHRASES["ndes_server_added"]
        added = next(e for e in self.audited if e["action"] == "ndes_server_added")
        self.assertIn("did not answer", phrase(added["detail"]))
        # A service that could not be asked changed nothing, and says so alone.
        self.audited.clear()
        unreachable = NdesServerError("unavailable", "the NDES server service is not running")
        with mock.patch(
            "haprion_ui.pages.profiles.ndes_server_socket.ask", side_effect=unreachable
        ):
            shown = client.post(
                "/ndes-profiles/servers/confirm",
                data={"csrf_token": csrf, "endpoint": ENDPOINT, "sha256": "a" * 64},
            )
        self.assertIn("is not running", shown.text)
        self.assertEqual([e for e in self.audited if e["action"].startswith("ndes_server")], [])

    def test_server_routes_require_csrf(self) -> None:
        client = self.writing_client()
        for path in ("/ndes-profiles/servers/new", "/ndes-profiles/servers/remove"):
            with self.subTest(path=path):
                response = client.post(path, data={"csrf_token": "x", "endpoint": ENDPOINT})
                self.assertEqual(response.status_code, 403)
        self.assertEqual([action for action, _ in self.asked if action != "list"], [])


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

    def test_a_replacement_refused_for_a_waiting_request_says_so(self) -> None:
        """Review 2026-10-29 again, BB06: the row said "Apply failed" and nothing else."""

        self.rows = [
            profile_row(
                id="certserver1", provider_id="ndes", key_id=self.public_key.key_id, revision=2
            )
        ]
        refused = queued(
            id=42,
            operation="ndes_profile_apply",
            cluster=None,
            state="failed",
            payload={"profile": "certserver1", "revision": 2},
            result={
                "error": {
                    "code": "profile_request_waiting",
                    "message": "a request for webserver1-scep is waiting at the CA",
                }
            },
        )
        with mock.patch("haprion_ui.db.recent_jobs", return_value=[refused]):
            page = self.writing_client().get("/ndes-profiles").text
        self.assertIn("Apply refused", page)
        self.assertIn('href="/jobs#job-42">· A request waits at the CA</a>', page)
        self.assertNotIn("Apply failed", page)

    def test_a_refused_removal_says_why_on_the_page(self) -> None:
        self.rows = [
            profile_row(id="certserver1", provider_id="ndes", key_id=self.public_key.key_id)
        ]
        refused = queued(
            id=41,
            operation="ndes_profile_apply",
            cluster=None,
            state="failed",
            payload={"profile": "certserver1", "revision": 1, "remove": True},
            result={
                "error": {
                    "code": "profile_in_use",
                    "message": "profile 'certserver1' is referenced by certificate: webserver1-scep",
                }
            },
        )
        applied = replace(
            refused,
            id=40,
            state="done",
            payload={"profile": "certserver1", "revision": 1},
            result=None,
        )
        with mock.patch("haprion_ui.db.recent_jobs", return_value=[refused, applied]):
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
        with mock.patch("haprion_ui.db.recent_jobs", return_value=[stale, applied]):
            old = self.writing_client().get("/ndes-profiles?removed=certserver1").text
        self.assertIn("In effect", old)
        self.assertNotIn("Removal refused", old)
        self.assertNotIn("was refused", old)

        # Once the registry no longer names the profile the reason is gone,
        # and so is the note - without waiting for another attempt.
        emptied = with_registry(certificate_reading(), registered("unrelated", kind="import"))
        with (
            mock.patch("haprion_ui.db.recent_jobs", return_value=[refused, applied]),
            mock.patch("haprion_ui.db.cluster_certificates", return_value=[emptied]),
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


class TheyAreCalledProfilesEverywhere(unittest.TestCase):
    """One word for one thing (review 26-10-24, 12-09).

    The button and the page said "NDES providers" while the form, the removal
    and the manual's glossary said "profile", and the quickstart named a
    "New DNS profile" button the page does not have.
    """

    ROOT = Path(__file__).resolve().parents[2]

    def test_no_page_or_document_calls_them_providers(self) -> None:
        places = [
            *(self.ROOT / "ui/src/haprion_ui").rglob("*.html"),
            *(self.ROOT / "ui/src/haprion_ui").rglob("*.py"),
            *(self.ROOT / "docs").glob("*.md"),
        ]
        found = [
            str(path.relative_to(self.ROOT))
            for path in places
            if "NDES provider" in path.read_text(encoding="utf-8")
        ]
        self.assertEqual(found, [])

    def test_the_quickstart_names_the_button_the_profile_pages_have(self) -> None:
        quickstart = (self.ROOT / "docs/quickstart.md").read_text(encoding="utf-8")
        pages = (self.ROOT / "ui/src/haprion_ui/templates/dns-profiles.html").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("**New DNS profile**", quickstart)
        self.assertIn(">New profile</a>", pages)
