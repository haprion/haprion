"""The login flow as HTTP: cookies, CSRF, the throttle, and what is not revealed.

The database is replaced rather than mocked in detail. Every statement these
handlers issue lives in `haprion_ui.db`, so substituting those functions leaves
the whole of the flow under test - the order of the checks, what is written to
the audit trail, which cookie is set with which flags - and removes only the
part that needs PostgreSQL. The SQL itself is covered where it belongs, by the
privilege suite that runs against the real database.
"""

from __future__ import annotations

import re
import time
import unittest
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest import mock
from uuid import UUID

from fastapi.testclient import TestClient

from haprion_ui import auth, db, metrics
from haprion_ui.app import create_app
from haprion_ui.config import Config, Database, Listen, Poller, Throttle
from haprion_ui.config import Session as SessionPolicy
from haprion_ui.db import Account, AuthenticatedSession
from tests.registry_fixture import manager_of

PASSWORD = "a sufficiently long password"

#
# Every rendered form carries a fresh CSRF token, so two responses that must be
# identical are identical everywhere except there. Masking it is what lets the
# comparison be exact rather than approximate.
#
CSRF_VALUE = re.compile(r'value="[0-9a-f]{64}"')


def without_csrf(text: str) -> str:
    return CSRF_VALUE.sub('value="..."', text)


NO_TRAFFIC = metrics.BackendMeasurement(
    intervals=0,
    started_at=None,
    ended_at=None,
    totals=tuple(metrics.Total(label, 0, 0.0, 0.0) for _name, label in metrics.SUMMARY_COUNTERS),
    restarted=False,
    handed_over=False,
)


def configuration(*, cookie_secure: bool = True, max_failures: int = 3) -> Config:
    return Config(
        database=Database(name="haprion_ui_test", socket_directory="/var/run/postgresql"),
        listen=Listen(host="127.0.0.1", port=8080),
        management_writes=False,
        demo_fixture=False,
        session=SessionPolicy(
            inactivity_minutes=600, absolute_hours=168, cookie_secure=cookie_secure
        ),
        throttle=Throttle(max_failures=max_failures, window_minutes=15),
        clusters=(),
        poller=Poller(interval_seconds=60),
    )


class FakePool:
    """Hands out a connection object that records commits and does nothing else."""

    def __init__(self) -> None:
        self.commits = 0
        self.rollbacks = 0

    @contextmanager
    def connection(self) -> Any:
        yield self

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1

    def open(self, **_: object) -> None:
        return None

    def close(self) -> None:
        return None


class LoginTestCase(unittest.TestCase):
    def _save_change(self, _c: object, **values: Any) -> Any:
        """A saved network or settings document, as the table would answer (B257)."""

        self.saved_changes.append(values)
        return db.ClusterChange(
            cluster=values["cluster"],
            kind=values["kind"],
            document=values["document"],
            base_hash=values["base_hash"],
            revision=(values["expected_revision"] or 0) + 1,
            updated_by=values["updated_by"],
            updated_at=datetime(2026, 10, 8, 12, 0, tzinfo=UTC),
            id=UUID("88888888-8888-4888-8888-888888888888"),
        )

    def setUp(self) -> None:
        self.account = Account(
            id=1,
            username="operator",
            role="admin",
            disabled=False,
            password_hash=auth.hash_password(PASSWORD),
        )
        self.pool = FakePool()
        self.saved_changes: list[dict[str, Any]] = []
        self.sessions: dict[bytes, AuthenticatedSession] = {}
        self.attempts: list[tuple[str, str, bool]] = []
        self.audit: list[str] = []
        self.failures = 0
        self.account_failures = 0
        #
        # Every feature on unless a test turns one off (0040, B193): an empty
        # table reads as all on.
        #
        self.switches: dict[str, Any] = {}
        self.acks: set[tuple[str, str, str]] = set()
        # The getting started list (B316) is shown until a test hides it.
        self.getting_started_hidden_at: datetime | None = None
        self.hidden_by: list[str] = []
        self.shown_again = 0
        self.provider: Any = None
        self.id_tokens: dict[bytes, str | None] = {}

        self.patches = [
            mock.patch("haprion_ui.db.pool", return_value=self.pool),
            mock.patch("haprion_ui.db.account_by_username", side_effect=self._account),
            mock.patch("haprion_ui.db.record_login_attempt", side_effect=self._attempt),
            mock.patch("haprion_ui.db.failures_since_last_success", side_effect=self._failures),
            mock.patch(
                "haprion_ui.db.account_failures_since_last_success",
                side_effect=lambda _c, **_: self.account_failures,
            ),
            mock.patch("haprion_ui.db.create_session", side_effect=self._create_session),
            mock.patch("haprion_ui.db.session_by_hash", side_effect=self._session),
            mock.patch("haprion_ui.db.touch_session"),
            mock.patch("haprion_ui.db.revoke_session", side_effect=self._revoke),
            mock.patch("haprion_ui.db.record_audit_event", side_effect=self._audit_event),
            mock.patch("haprion_ui.db.cluster_statuses", return_value=[]),
            mock.patch("haprion_ui.db.cluster_inventories", return_value=[]),
            mock.patch("haprion_ui.db.cluster_histories", return_value=[]),
            mock.patch("haprion_ui.db.cluster_certificates", return_value=[]),
            mock.patch("haprion_ui.db.certificate_takeouts", return_value={}),
            mock.patch("haprion_ui.db.backend_rows", return_value=[]),
            #
            # From the registry the test describes, wherever it patched the
            # listings - see `tests.registry_fixture` (B304).
            #
            mock.patch(
                "haprion_ui.db.manager_certificates",
                side_effect=lambda connection: manager_of(db.cluster_certificates(connection)),
            ),
            mock.patch("haprion_ui.db.cluster_backups", return_value=[]),
            mock.patch("haprion_ui.db.cluster_networks", return_value=[]),
            mock.patch("haprion_ui.db.cluster_settings", return_value=[]),
            mock.patch("haprion_ui.db.cluster_objects", return_value=[]),
            #
            # The listing reads drafts now, so every page that renders it
            # calls this. Defaulted to none rather than left unpatched: a
            # page whose draft lookup raises is a page that does not render
            # at all, which would hide whatever the case was about.
            #
            mock.patch("haprion_ui.db.cluster_drafts", return_value=[]),
            #
            # And a cluster's saved network and settings (B257), which the
            # network page, the editor and the settings page read: none.
            #
            mock.patch("haprion_ui.db.cluster_changes", return_value={}),
            mock.patch("haprion_ui.db.save_cluster_change", side_effect=self._save_change),
            mock.patch("haprion_ui.db.discard_cluster_change"),
            mock.patch("haprion_ui.db.change_publishes", return_value=[]),
            mock.patch("haprion_ui.db.recent_jobs", return_value=[]),
            #
            # Events (B275): nobody queued anything, the record is empty, and
            # no server state was ever asked for. A test about one of them
            # patches it itself.
            #
            mock.patch("haprion_ui.db.requested_by", return_value={}),
            mock.patch("haprion_ui.db.audit_events", return_value=[]),
            mock.patch("haprion_ui.db.audit_count", return_value=0),
            mock.patch("haprion_ui.db.account_names", return_value=frozenset()),
            mock.patch("haprion_ui.db.server_state_events", return_value=[]),
            # Events → Nodes (26-10-12): nothing the nodes did yet.
            mock.patch("haprion_ui.db.node_event_page", return_value=[]),
            mock.patch("haprion_ui.db.node_event_count", return_value=0),
            # Nobody may ask /status/ (B274) unless a test says otherwise.
            mock.patch("haprion_ui.db.status_access", return_value=[]),
            mock.patch("haprion_ui.db.attention_acks", side_effect=lambda _c: set(self.acks)),
            mock.patch("haprion_ui.db.forget_attention_acks"),
            mock.patch(
                "haprion_ui.db.getting_started_hidden_at",
                side_effect=lambda _c: self.getting_started_hidden_at,
            ),
            mock.patch("haprion_ui.db.hide_getting_started", side_effect=self._hide),
            mock.patch("haprion_ui.db.show_getting_started", side_effect=self._show),
            # Every cluster read through since its last job (0068).
            mock.patch("haprion_ui.db.clusters_catching_up", return_value=[]),
            #
            # The dashboard's traffic row (B220): no readings, as an
            # installation the poller has not measured yet. A test about the
            # row patches these itself.
            #
            mock.patch(
                "haprion_ui.db.read_traffic_summaries",
                side_effect=lambda _c, *, clusters, since, until: dict.fromkeys(
                    clusters, NO_TRAFFIC
                ),
            ),
            mock.patch(
                "haprion_ui.db.read_response_times_by_cluster",
                side_effect=lambda _c, *, clusters, since, until: dict.fromkeys(
                    clusters, (0, None, None)
                ),
            ),
            # Settings draws its Users card from this; none unless a test says.
            mock.patch("haprion_ui.db.account_rows", return_value=[]),
            mock.patch("haprion_ui.db.feature_switches", side_effect=lambda _c: self.switches),
            #
            # No list from the poller yet, so the pages fall back to the
            # configured clusters - the state before the poller's first pass.
            #
            mock.patch("haprion_ui.db.cluster_list", return_value=None),
            # No OIDC provider row unless a test gives one (0041).
            mock.patch("haprion_ui.db.oidc_provider", side_effect=lambda _c: self.provider),
            mock.patch(
                "haprion_ui.db.session_id_token",
                side_effect=lambda _c, token_hash: self.id_tokens.get(token_hash),
            ),
            #
            # The profile pages read a profile's own apply jobs. Answered out
            # of whatever `recent_jobs` a test has patched in, so a test that
            # queues an apply job the old way is still read the new way.
            #
            mock.patch(
                "haprion_ui.db.operation_jobs",
                side_effect=lambda connection, operation, **_: [
                    job for job in db.recent_jobs(connection) if job.operation == operation
                ],
            ),
            mock.patch(
                "haprion_ui.db.profile_jobs",
                side_effect=lambda connection, operation: [
                    job for job in db.recent_jobs(connection) if job.operation == operation
                ],
            ),
        ]
        for patch in self.patches:
            patch.start()
        for patch in self.patches:
            self.addCleanup(patch.stop)

    # - the fake database -------------------------------------------------

    def _hide(self, _connection: object, *, actor: str) -> bool:
        self.hidden_by.append(actor)
        return True

    def _show(self, _connection: object) -> bool:
        self.shown_again += 1
        return True

    def _account(self, _connection: object, username: str) -> Account | None:
        return self.account if username.lower() == "operator" else None

    def _attempt(self, _c: object, *, username: str, client_ip: str, succeeded: bool) -> None:
        self.attempts.append((username, client_ip, succeeded))

    def _failures(self, _c: object, **_: object) -> int:
        return self.failures

    def _create_session(
        self,
        _c: object,
        *,
        token_hash: bytes,
        user_id: int,
        expires_at: datetime,
        id_token: str | None = None,
    ) -> None:
        now = datetime.now(UTC)
        self.id_tokens[token_hash] = id_token
        self.sessions[token_hash] = AuthenticatedSession(
            token_hash=token_hash,
            user_id=user_id,
            username=self.account.username,
            role=self.account.role,
            disabled=self.account.disabled,
            created_at=now,
            last_seen_at=now,
            expires_at=expires_at,
            revoked_at=None,
            source=self.account.source,
        )

    def _session(self, _c: object, token_hash: bytes) -> AuthenticatedSession | None:
        return self.sessions.get(token_hash)

    def _revoke(self, _c: object, token_hash: bytes) -> None:
        self.sessions.pop(token_hash, None)

    def _audit_event(self, _c: object, *, action: str, **_: object) -> None:
        self.audit.append(action)

    # - helpers -----------------------------------------------------------

    def client(self, config: Config | None = None) -> TestClient:
        client = TestClient(
            create_app(config or configuration()), base_url="https://manager.example.com"
        )
        client.__enter__()
        self.addCleanup(client.__exit__, None, None, None)
        return client

    def sign_in(
        self, client: TestClient, *, username: str = "operator", password: str = PASSWORD
    ) -> Any:
        page = client.get("/login")
        token = auth.csrf_token(client.cookies[auth.PRE_SESSION_COOKIE])
        self.assertIn("Sign in", page.text)
        return client.post(
            "/login",
            data={"username": username, "password": password, auth.CSRF_FIELD: token},
            follow_redirects=False,
        )


class SigningIn(LoginTestCase):
    def test_a_correct_password_signs_in_and_sets_the_session_cookie(self) -> None:
        client = self.client()
        response = self.sign_in(client)
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/")
        self.assertIn(auth.SESSION_COOKIE, client.cookies)
        self.assertEqual(self.attempts[-1][2], True)
        self.assertIn("login", self.audit)

    def test_the_cookie_is_httponly_secure_and_lax(self) -> None:
        client = self.client()
        header = self.sign_in(client).headers["set-cookie"]
        #
        # Read off the header rather than from configuration, because these three
        # flags are the entire defence for a token that is otherwise a bearer
        # credential: unreadable to script, never sent in clear, not attached to
        # a cross-site form post.
        #
        self.assertIn("HttpOnly", header)
        self.assertIn("Secure", header)
        self.assertIn("SameSite=lax", header.replace("samesite", "SameSite"))

    def test_the_landing_page_names_the_account_after_signing_in(self) -> None:
        client = self.client()
        self.sign_in(client)
        page = client.get("/")
        self.assertEqual(page.status_code, 200)
        self.assertIn("operator", page.text)
        self.assertIn("admin", page.text)
        self.assertIn("Dashboard", page.text)
        self.assertIn("Read-only mode", page.text)
        self.assertIn('href="/certificates"', page.text)

    def test_the_proxy_overview_is_an_authenticated_read_only_page(self) -> None:
        client = self.client()
        self.sign_in(client)
        page = client.get("/proxies")
        self.assertEqual(page.status_code, 200)
        self.assertIn("Proxies", page.text)
        self.assertIn('href="/proxies" aria-current="page"', page.text)
        self.assertIn("No clusters configured", page.text)

    def test_the_certificate_overview_is_an_authenticated_read_only_page(self) -> None:
        client = self.client()
        self.sign_in(client)
        page = client.get("/certificates")
        self.assertEqual(page.status_code, 200)
        self.assertIn("Certificates", page.text)
        self.assertIn('href="/certificates" aria-current="page"', page.text)
        self.assertIn("No clusters configured", page.text)

    def test_without_a_cluster_an_admin_is_shown_where_to_create_one(self) -> None:
        """A new installation has no cluster; the empty pages pointed at a
        configuration file and the poller, not at Create cluster (26-10-14)."""

        pages = ("/proxies", "/certificates", "/network", "/history", "/backups")
        client = self.client(replace(configuration(), management_writes=True))
        self.sign_in(client)
        #
        # The dashboard is the first cluster's guide (B315).
        #
        self.assertIn('action="/first-cluster/name"', client.get("/").text)
        for path in pages:
            with self.subTest(path=path):
                text = client.get(path).text
                self.assertIn('<a class="secondary-button" href="/settings/new-cluster">', text)
                self.assertNotIn("before starting the poller", text)
        self.account = replace(self.account, role="reader")
        reader = self.client(replace(configuration(), management_writes=True))
        self.sign_in(reader)
        text = reader.get("/proxies").text
        self.assertNotIn("/settings/new-cluster", text)
        self.assertIn("An administrator creates the first one under Settings.", text)

    def test_the_certificate_page_renders_every_row_it_is_given(self) -> None:
        client = self.client(replace(configuration(), demo_fixture=True))
        self.sign_in(client)
        # The cluster view by name: the fixture carries a registry since
        # 2026-09-18 (B142), and with one the page opens on the registry view.
        page = client.get("/certificates?view=clusters")
        self.assertEqual(page.status_code, 200)
        self.assertIn("Certbot", page.text)
        self.assertIn("Imported", page.text)
        self.assertIn("referenced by this cluster", page.text)
        #
        # Only what the cluster references, and therefore no Use column either:
        # every cluster reads the same shared distribution directory, so listing
        # what merely sits there put one cluster's certificates under another's
        # name, and once those rows left, the column said "Referenced" on every
        # remaining row. The registry view answers "what else exists" properly,
        # for the whole manager rather than per cluster.
        #
        self.assertNotIn("Available", page.text)
        self.assertNotIn("Referenced", page.text)

    def test_the_certificate_page_requires_a_session(self) -> None:
        page = self.client().get("/certificates", follow_redirects=False)
        self.assertEqual(page.status_code, 303)
        self.assertEqual(page.headers["location"], "/login")

    def test_the_backup_page_renders_every_node_it_is_given(self) -> None:
        client = self.client(replace(configuration(), demo_fixture=True))
        self.sign_in(client)
        page = client.get("/backups")
        self.assertEqual(page.status_code, 200)
        self.assertIn('href="/backups" aria-current="page"', page.text)
        self.assertIn("service-b", page.text)
        self.assertIn("Backup overdue", page.text)

    def test_the_backup_page_opens_on_the_newest_ten_per_node(self) -> None:
        client = self.client(replace(configuration(), demo_fixture=True))
        self.sign_in(client)
        page = client.get("/backups")
        self.assertEqual(page.status_code, 200)
        # The demo edge cluster keeps 21 per node: three pages. The service
        # cluster has 14 on one node and 2 on the one that fell behind: two.
        self.assertIn("42 retained archives on these nodes", page.text)
        self.assertEqual(page.text.count('data-archive-page="0"'), 10 + 10 + 10 + 2)
        self.assertEqual(page.text.count('data-archive-page="2" hidden'), 2)
        self.assertIn("Archives 1–10 per node · page 1 of 3", page.text)
        self.assertIn("Archives 1–10 per node · page 1 of 2", page.text)
        self.assertIn("data-archive-page-next>Older</button>", page.text)

    def test_the_archive_list_stays_as_the_reader_left_it_across_a_redraw(self) -> None:
        """Back up now redraws the page, and the job finishing redraws it again.

        Both used to arrive with the list closed on page one. The list is keyed
        by cluster so the script can put back what was open.
        """

        client = self.client(replace(configuration(), demo_fixture=True))
        self.sign_in(client)
        page = client.get("/backups")
        self.assertIn('data-archive-list data-archive-cluster="', page.text)
        script = client.get("/static/backups.js").text
        self.assertIn('list.addEventListener("toggle", remember)', script)
        self.assertIn("list.open = Boolean(kept.open)", script)
        self.assertIn('querySelectorAll("[data-backup-now]")', script)
        self.assertIn('document.addEventListener("haprion:redrawn", wireAll)', script)

    def test_a_finished_job_redraws_the_content_rather_than_reloading_the_page(self) -> None:
        """A reload blinked the page twice after Back up now: the job, then the reading.

        The content is swapped in place; a reload is left only as the answer to
        a page that came back in another shape, such as a login form.
        """

        client = self.client(replace(configuration(), demo_fixture=True))
        self.sign_in(client)
        waiting = client.get("/static/waiting.js").text
        self.assertEqual(waiting.count("redraw();"), 2)
        self.assertIn("window.haproxyUi.redraw()", waiting)
        live = client.get("/static/live.js").text
        self.assertIn("response.redirected", live)
        self.assertIn("parsed.title !== document.title", live)
        self.assertIn('fresh.querySelectorAll("script").forEach((script) => script.remove())', live)
        self.assertIn('meta[name="haproxy-live"]', live)
        self.assertIn("/static/live.js", client.get("/backups").text)

    def test_the_backup_schedule_editor_speaks_the_timer_s_calendar(self) -> None:
        """An admin with writes sees the schedule in words, and the form pre-filled from it."""

        client = self.client(replace(configuration(), management_writes=True, clusters=("alpha",)))
        self.sign_in(client)
        row = db.ClusterBackups(
            cluster="alpha",
            observed_at=datetime.now(UTC),
            outcome="done",
            result={
                "limit": 14,
                "nodes": [],
                "schedule": {
                    "unit": "haprion-state-backup@alpha.timer",
                    "known": True,
                    "enabled": True,
                    "active": True,
                    "calendar": "Mon,Fri *-*-* 22:30:00",
                    "next_run": None,
                    "last_run": None,
                    "last_result": None,
                    "scheduled": True,
                    "retention": 30,
                },
            },
            warnings=[],
            error=None,
            poll_error=None,
        )
        with mock.patch("haprion_ui.db.cluster_backups", return_value=[row]):
            page = client.get("/backups")
        self.assertEqual(page.status_code, 200)
        self.assertIn("Every Monday and Friday at 22:30", page.text)
        self.assertIn("keeps 30 per node", page.text)
        self.assertNotIn("*-*-* 22:30:00</", page.text)
        self.assertIn('name="backup_weekday" value="Mon" checked', page.text)
        self.assertIn('name="backup_weekday" value="Tue">', page.text)
        self.assertIn('<option value="22" selected>', page.text)
        self.assertIn('<option value="30" selected>', page.text)
        self.assertIn('name="backup_retention" value="30"', page.text)
        self.assertIn('<option value="weekly" selected>', page.text)
        self.assertIn("Back up now", page.text)
        # Twenty-four hours, not a browser's locale: the picker is two selects.
        self.assertNotIn('type="time"', page.text)
        self.assertIn("waiting.js", page.text)

    def test_the_backup_page_requires_a_session(self) -> None:
        page = self.client().get("/backups", follow_redirects=False)
        self.assertEqual(page.status_code, 303)
        self.assertEqual(page.headers["location"], "/login")

    def test_the_version_history_is_an_authenticated_read_only_page(self) -> None:
        client = self.client(replace(configuration(), demo_fixture=True))
        self.sign_in(client)
        page = client.get("/history")
        self.assertEqual(page.status_code, 200)
        self.assertIn('href="/history" aria-current="page"', page.text)
        self.assertIn("Versions", page.text)
        self.assertIn("2 unpublished", page.text)
        self.assertIn("Published", page.text)

    def test_the_version_history_requires_a_session(self) -> None:
        page = self.client().get("/history", follow_redirects=False)
        self.assertEqual(page.status_code, 303)
        self.assertEqual(page.headers["location"], "/login")

    def test_the_explicit_demo_fixture_is_visibly_labelled(self) -> None:
        client = self.client(replace(configuration(), demo_fixture=True))
        self.sign_in(client)
        dashboard = client.get("/")
        proxies = client.get("/proxies")
        self.assertIn("Synthetic dev data", dashboard.text)
        self.assertIn("public-web", proxies.text)
        self.assertIn('ownership-unmanaged">Manual<', proxies.text)
        self.assertIn('ownership-managed">Application<', proxies.text)
        self.assertIn(">Created by<", proxies.text)

    def test_static_design_assets_are_local_and_served(self) -> None:
        client = self.client()
        page = client.get("/login")
        #
        # Local, and versioned. Without the token a stylesheet change reaches a
        # reader only when a cache they have no reason to suspect expires - and
        # it arrives selectively, new markup against old CSS, which reads as a
        # layout bug in the new page.
        #
        self.assertIn('href="https://manager.example.com/static/app.css?v=', page.text)
        self.assertIn('src="https://manager.example.com/static/theme.js?v=', page.text)
        self.assertNotIn("cdn", page.text.lower())
        stylesheet = client.get("/static/app.css")
        script = client.get("/static/theme.js")
        font = client.get("/static/inter-var.woff2")
        self.assertEqual(stylesheet.status_code, 200)
        self.assertEqual(script.status_code, 200)
        self.assertEqual(font.status_code, 200)
        self.assertIn("--healthy", stylesheet.text)
        self.assertIn("Inter Var", stylesheet.text)
        self.assertIn("--font-features", stylesheet.text)
        self.assertIn("--text-primary", stylesheet.text)
        self.assertIn('"liga" 0', stylesheet.text)
        self.assertNotIn("prefers-color-scheme", stylesheet.text)
        self.assertIn("localStorage", script.text)
        self.assertIn('const themes = ["light", "dark"]', script.text)
        self.assertNotIn('"system"', script.text)

    def test_signing_in_over_plain_http_omits_secure_only_when_configured(self) -> None:
        client = TestClient(
            create_app(configuration(cookie_secure=False)), base_url="http://localhost"
        )
        with client:
            client.get("/login")
            token = auth.csrf_token(client.cookies[auth.PRE_SESSION_COOKIE])
            response = client.post(
                "/login",
                data={"username": "operator", "password": PASSWORD, auth.CSRF_FIELD: token},
                follow_redirects=False,
            )
        self.assertNotIn("Secure", response.headers["set-cookie"])


class RefusingToSignIn(LoginTestCase):
    def test_a_wrong_password_is_refused_and_recorded(self) -> None:
        client = self.client()
        response = self.sign_in(client, password="wrong")
        self.assertEqual(response.status_code, 401)
        self.assertNotIn(auth.SESSION_COOKIE, client.cookies)
        self.assertEqual(self.attempts[-1][2], False)
        self.assertIn("login_failed", self.audit)

    def test_an_unknown_account_answers_exactly_as_a_wrong_password_does(self) -> None:
        #
        # The two responses are compared, not merely each checked for failure.
        # Any difference between them - wording, status, a header - is a way to
        # ask this form which usernames exist.
        #
        wrong = self.sign_in(self.client(), password="wrong")
        unknown = self.sign_in(self.client(), username="nobody")
        self.assertEqual(wrong.status_code, unknown.status_code)
        self.assertEqual(without_csrf(wrong.text), without_csrf(unknown.text))

    def test_a_disabled_account_cannot_sign_in_with_the_right_password(self) -> None:
        self.account = Account(
            id=1,
            username="operator",
            role="admin",
            disabled=True,
            password_hash=self.account.password_hash,
        )
        response = self.sign_in(self.client())
        self.assertEqual(response.status_code, 401)
        self.assertNotIn(auth.SESSION_COOKIE, self.client().cookies)

    def test_a_post_without_a_csrf_token_is_not_a_login(self) -> None:
        client = self.client()
        client.get("/login")
        response = client.post(
            "/login",
            data={"username": "operator", "password": PASSWORD},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(auth.SESSION_COOKIE, client.cookies)
        #
        # Nothing was attempted: a forged post must not be able to spend a
        # victim's throttle budget either.
        #
        self.assertEqual(self.attempts, [])

    def test_a_csrf_token_from_another_visitor_is_refused(self) -> None:
        client = self.client()
        client.get("/login")
        response = client.post(
            "/login",
            data={
                "username": "operator",
                "password": PASSWORD,
                auth.CSRF_FIELD: auth.csrf_token(auth.new_session_token()),
            },
            follow_redirects=False,
        )
        self.assertNotIn(auth.SESSION_COOKIE, client.cookies)
        self.assertEqual(response.status_code, 200)

    def test_a_post_without_the_pre_session_cookie_is_not_a_login(self) -> None:
        """S09 (security review 26-10-13): with no cookie the secret was "", and
        the HMAC of "" is anyone's - a foreign page could sign a victim in as
        the attacker."""

        response = self.client().post(
            "/login",
            data={
                "username": "operator",
                "password": PASSWORD,
                auth.CSRF_FIELD: auth.csrf_token(""),
            },
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("login", self.audit)
        self.assertEqual(self.attempts, [])


class Throttling(LoginTestCase):
    def test_the_correct_password_is_refused_once_the_limit_is_reached(self) -> None:
        #
        # The point of the throttle, stated as a test: past the limit the right
        # password stops working, and it stops working without the account being
        # looked at.
        #
        self.failures = 3
        with mock.patch("haprion_ui.db.account_by_username") as lookup:
            response = self.sign_in(self.client(configuration(max_failures=3)))
            lookup.assert_not_called()
        self.assertEqual(response.status_code, 401)
        self.assertEqual(self.attempts[-1][2], False)

    def test_a_throttled_answer_is_indistinguishable_from_a_wrong_password(self) -> None:
        wrong = self.sign_in(self.client(), password="wrong")
        self.failures = 99
        throttled = self.sign_in(self.client())
        self.assertEqual(wrong.status_code, throttled.status_code)
        self.assertEqual(without_csrf(wrong.text), without_csrf(throttled.text))

    def test_a_throttled_attempt_is_not_hashed(self) -> None:
        """S01 (security review 26-10-13): every refused attempt cost an Argon2."""

        self.failures = 99
        with (
            mock.patch.object(auth, "verify_password") as verify,
            mock.patch.object(auth, "burn_absent_user_time") as burn,
        ):
            response = self.sign_in(self.client())
        self.assertEqual(response.status_code, 401)
        verify.assert_not_called()
        burn.assert_not_called()

    def test_many_sources_guessing_at_one_account_are_stopped(self) -> None:
        """S02: the budget was per name and address only (B305)."""

        self.account_failures = 3 * auth.ACCOUNT_FAILURE_FACTOR
        response = self.sign_in(self.client(configuration(max_failures=3)))
        self.assertEqual(response.status_code, 401)
        self.assertNotIn(auth.SESSION_COOKIE, response.cookies)

    def test_the_hash_runs_holding_no_database_connection(self) -> None:
        """S01: six connections serve every page, and Argon2 held one."""

        held: list[int] = []
        real = self.pool.connection

        @contextmanager
        def counted() -> Any:
            held.append(1)
            try:
                with real() as connection:
                    yield connection
            finally:
                held.pop()

        def verify(password_hash: str, password: str) -> bool:
            self.assertEqual(held, [], "Argon2 ran inside a connection")
            return True

        with (
            mock.patch.object(self.pool, "connection", counted),
            mock.patch.object(auth, "verify_password", verify),
        ):
            response = self.sign_in(self.client())
        self.assertEqual(response.status_code, 303)

    def test_when_the_hashing_is_full_the_answer_is_try_again_and_nothing_counts(self) -> None:
        for _ in range(auth.HASHING_AT_ONCE):
            auth.HASHING.acquire()
        try:
            with mock.patch.object(auth, "HASHING_WAIT_SECONDS", 0.05):
                response = self.sign_in(self.client())
        finally:
            for _ in range(auth.HASHING_AT_ONCE):
                auth.HASHING.release()
        self.assertIn("Too many sign-ins at once", response.text)
        self.assertEqual(self.attempts, [])

    def test_an_account_disabled_while_its_hash_ran_is_not_signed_in(self) -> None:
        def verify(password_hash: str, password: str) -> bool:
            self.account = replace(self.account, disabled=True)
            return True

        with mock.patch.object(auth, "verify_password", verify):
            response = self.sign_in(self.client())
        self.assertNotEqual(response.status_code, 303)
        self.assertEqual(self.attempts[-1][2], False)

    def test_the_client_address_comes_from_the_forwarded_header(self) -> None:
        client = self.client()
        client.get("/login")
        token = auth.csrf_token(client.cookies[auth.PRE_SESSION_COOKIE])
        client.post(
            "/login",
            data={"username": "operator", "password": "wrong", auth.CSRF_FIELD: token},
            headers={"X-Forwarded-For": "198.51.100.7"},
            follow_redirects=False,
        )
        self.assertEqual(self.attempts[-1][1], "198.51.100.7")

    def test_an_unparseable_forwarded_address_does_not_break_the_login_path(self) -> None:
        client = self.client()
        client.get("/login")
        token = auth.csrf_token(client.cookies[auth.PRE_SESSION_COOKIE])
        response = client.post(
            "/login",
            data={"username": "operator", "password": "wrong", auth.CSRF_FIELD: token},
            headers={"X-Forwarded-For": "not-an-address"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(self.attempts[-1][1], "127.0.0.1")


class SessionsAndSigningOut(LoginTestCase):
    def test_the_landing_page_redirects_to_the_form_when_signed_out(self) -> None:
        response = self.client().get("/", follow_redirects=False)
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/login")

    def test_an_unknown_cookie_is_not_a_session(self) -> None:
        client = self.client()
        client.cookies.set(auth.SESSION_COOKIE, auth.new_session_token())
        response = client.get("/", follow_redirects=False)
        self.assertEqual(response.status_code, 303)

    def test_signing_out_revokes_the_session_and_clears_the_cookie(self) -> None:
        client = self.client()
        self.sign_in(client)
        token = client.cookies[auth.SESSION_COOKIE]
        page = client.get("/")
        csrf = auth.csrf_token(token)
        self.assertIn(csrf, page.text)

        response = client.post("/logout", data={auth.CSRF_FIELD: csrf}, follow_redirects=False)
        self.assertEqual(response.status_code, 303)
        self.assertEqual(self.sessions, {})
        self.assertIn("logout", self.audit)
        self.assertEqual(client.get("/", follow_redirects=False).status_code, 303)

    def test_signing_out_without_a_token_leaves_the_session_alone(self) -> None:
        #
        # A cross-site post must not be able to log an operator out mid-incident.
        #
        client = self.client()
        self.sign_in(client)
        client.post("/logout", data={}, follow_redirects=False)
        self.assertEqual(len(self.sessions), 1)
        self.assertEqual(client.get("/", follow_redirects=False).status_code, 200)

    def test_signing_out_with_a_token_outside_ascii_is_a_refusal_not_a_crash(self) -> None:
        """CR-05, through the route: the review reproduced the 500 here."""

        client = self.client()
        self.sign_in(client)
        response = client.post("/logout", data={auth.CSRF_FIELD: "å"}, follow_redirects=False)

        self.assertLess(response.status_code, 500)
        self.assertEqual(len(self.sessions), 1)

    def test_a_session_that_has_gone_inactive_is_not_accepted(self) -> None:
        client = self.client()
        self.sign_in(client)
        stale = datetime.now(UTC) - timedelta(hours=11)
        for digest, session in list(self.sessions.items()):
            self.sessions[digest] = replace(session, last_seen_at=stale)
        self.assertEqual(client.get("/", follow_redirects=False).status_code, 303)


if __name__ == "__main__":
    unittest.main()


class TheLoginFormIsNotAnAccountList(unittest.TestCase):
    """Both answers cost the same, including the ones nobody thinks about.

    The interesting input is a password that is short enough in characters to
    pass `Form(max_length=...)` and long enough in bytes to hit the hashing
    limit. It reached one path's fast refusal and the other path's Argon2
    verification, which is a difference a script can time. Found by the code
    review on 2026-08-31.
    """

    #
    # Characters, not bytes: two-byte characters are what open the gap between
    # the form's limit and this module's.
    #
    OVERSIZED = "å" * 700

    def test_an_over_long_password_is_refused_by_both_paths(self) -> None:
        self.assertGreater(len(self.OVERSIZED.encode("utf-8")), auth.MAX_PASSWORD_BYTES)
        self.assertLessEqual(len(self.OVERSIZED), auth.MAX_PASSWORD_BYTES)

        stored = auth.hash_password("a password somebody actually has")

        existing = _elapsed(lambda: auth.verify_password(stored, self.OVERSIZED))
        absent = _elapsed(lambda: auth.burn_absent_user_time(self.OVERSIZED))

        #
        # Asserted as a ratio against a whole Argon2 verification rather than as
        # an absolute number of milliseconds, so this measures the presence of a
        # hash rather than the speed of whatever machine is running the suite.
        #
        one_verification = _elapsed(lambda: auth.verify_password(stored, "wrong"))
        self.assertLess(absent, one_verification / 4)
        self.assertLess(existing, one_verification / 4)


def _elapsed(work: Callable[[], object]) -> float:
    start = time.perf_counter()
    work()
    return time.perf_counter() - start
