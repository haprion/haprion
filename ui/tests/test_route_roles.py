"""Every route answers a reader and an anonymous visitor as its role allows (review 2026-10-22, 4-6).

The role check is written by hand in each handler - 117 routes, five gate
functions and the rest inline - so a route that forgot it would be found by
nobody. These walk every route the application has and ask it the way the
browser would: every form field filled, the CSRF token valid - or, for the admin, wrong. A new route that
lets a reader write, or shows a page without a sign-in, fails here until it is
named below with its reason.
"""

from __future__ import annotations

import re
import unittest
from dataclasses import replace
from datetime import UTC, datetime
from html import unescape
from typing import Any
from unittest import mock
from uuid import UUID

from fastapi.testclient import TestClient

from haprion_ui import auth, db
from tests.test_cluster_traffic import ReadingACluster
from tests.test_login import LoginTestCase, configuration
from tests.test_package import row as saved_object
from tests.test_saved_changes import saved

#
# What a reader may post: signing in and out, and their own password.
#
READER_MAY_POST = {"/login", "/logout", "/account/password"}

#
# What answers without a sign-in, and how. The sign-in pages; the fragments a
# page polls, which say 401 rather than redirect a script; the status for a
# monitor, which answers only the addresses on its list (404 to any other);
# and the probe's health check, which reads no session (503 here: no database).
#
PUBLIC = {
    "/login": 200,
    "/login/oidc/callback": 401,
    "/proxies/rows": 401,
    "/clusters/busy": 401,
    "/status/attention.json": 404,
    "/status/metrics": 404,
    "/healthz": 503,
}


#
# What does not answer 403 to a post with the wrong token: the sign-out, which
# asks again before it ends anything, and the removal of a proxy, which refuses
# with a page of its own (400).
#
REFUSED_ITS_OWN_WAY = {"/logout": 200, "/proxies/{cluster}/{name}/remove": 400}


#
# The pages a reader is told *Administrators only*: the forms where something is
# made, changed or removed, and the settings and the profiles' and receivers'
# own forms, where access is handled. The lists of API tokens, DNS and NDES
# profiles and certificate receivers are read. Every other page a
# reader reads as an admin does; a page added here says why it is not read.
#
READER_REFUSED_PAGES = {
    "/backups/restore/new",
    "/certificates/import",
    "/certificates/new",
    "/certificates/receivers/key",
    "/certificates/receivers/new",
    "/dns-profiles/new",
    "/dns-profiles/{profile_id}/remove",
    "/dns-profiles/{profile_id}/replace",
    "/first-cluster/{name}",
    "/ndes-profiles/new",
    "/ndes-profiles/servers/new",
    "/ndes-profiles/{profile_id}/remove",
    "/ndes-profiles/{profile_id}/replace",
    "/proxies/{cluster}/new",
    "/proxies/{cluster}/{name}/edit",
    "/proxies/{cluster}/{name}/remove",
    "/settings",
    "/settings/api-tokens/new",
    "/settings/api-tokens/{name}/extend",
    "/settings/api-tokens/{name}/revoke",
    "/settings/clusters/{cluster}",
    "/settings/features/{name}",
    "/settings/new-cluster",
    "/settings/new-user",
    "/settings/nodes/{cluster}",
    "/settings/oidc",
    "/settings/status-access",
    "/settings/users/{name}",
    "/settings/users/{name}/delete",
    "/waf/allow",
}


def routes(found: list[Any], out: list[Any]) -> list[Any]:
    for route in found:
        inner = getattr(route, "original_router", None)
        if inner is not None:
            routes(inner.routes, out)
        elif hasattr(route, "dependant"):
            out.append(route)
    return out


def concrete(route: Any) -> str:
    """The route's path with a value of the right kind in each parameter."""

    numbers = {
        parameter.name
        for parameter in route.dependant.path_params
        if parameter.field_info.annotation is int
    }

    def value(match: re.Match[str]) -> str:
        name = match.group(1)
        return "1" if name in numbers else "add" if name == "action" else "alpha"

    return re.sub(r"\{([^}]+)\}", value, route.path)


def form(route: Any, token: str) -> tuple[dict[str, str], dict[str, Any]]:
    """Every field the route declares, short enough to pass its validation."""

    data: dict[str, str] = {}
    files: dict[str, Any] = {}
    for field in route.dependant.body_params:
        if "UploadFile" in str(field.field_info.annotation):
            files[field.alias] = ("x.pem", b"x")
        elif field.alias == "idempotency_key":
            data[field.alias] = "00000000-0000-4000-8000-000000000001"
        else:
            data[field.alias] = "1"
    data[auth.CSRF_FIELD] = token
    return data, files


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


class EveryRouteAnswersAsTheRoleAllows(LoginTestCase):
    def app_client(self) -> Any:
        return self.client(replace(configuration(), clusters=("alpha",), management_writes=True))

    def test_a_reader_s_post_is_refused_everywhere_but_its_own(self) -> None:
        self.account = replace(self.account, role="reader")
        client = self.app_client()
        self.assertEqual(self.sign_in(client).status_code, 303)
        token = auth.csrf_token(client.cookies[auth.SESSION_COOKIE])

        answered: dict[str, int] = {}
        for route in routes(client.app.routes, []):
            if "POST" not in route.methods or route.path in READER_MAY_POST:
                continue
            data, files = form(route, token)
            response = client.post(
                concrete(route), data=data, files=files or None, follow_redirects=False
            )
            answered[route.path] = response.status_code

        self.assertGreater(len(answered), 50)
        self.assertEqual({path: code for path, code in answered.items() if code != 403}, {})

    def test_a_reader_is_refused_only_the_pages_that_change_or_hand_out_access(self) -> None:
        """A reader reads everything an admin reads; a page a reader is refused is named here."""

        self.account = replace(self.account, role="reader")
        app = self.app_client()
        client: Any = TestClient(app.app, base_url=str(app.base_url), raise_server_exceptions=False)
        self.assertEqual(self.sign_in(client).status_code, 303)

        refused = set()
        walked = 0
        for route in routes(client.app.routes, []):
            if "GET" not in route.methods or route.path in PUBLIC:
                continue
            walked += 1
            response = client.get(concrete(route), follow_redirects=False)
            if response.status_code == 403:
                refused.add(route.path)

        self.assertGreater(walked, 40)
        self.assertEqual(sorted(refused - READER_REFUSED_PAGES), [])
        self.assertEqual(sorted(READER_REFUSED_PAGES - refused), [])

    def test_an_admin_s_post_without_the_session_s_token_does_nothing(self) -> None:
        """Review 26-10-30, E5: the CSRF check is written by hand in each route, in
        a different order in each. A route that forgot it lets a page on another
        site write as the signed-in admin, and every other walk here would stay green."""

        client = self.app_client()
        self.assertEqual(self.sign_in(client).status_code, 303)
        own = auth.csrf_token(client.cookies[auth.SESSION_COOKIE])
        other = auth.csrf_token(auth.new_session_token())
        self.assertNotEqual(own, other)

        #
        # A token that is only wrong: an empty one is the framework's refusal of
        # a missing field, which never reaches the route's own check.
        #
        answered: dict[str, int] = {}
        #
        # The two replace forms look the profile up before they check the token;
        # a profile for them to find, and no more.
        #
        with (
            mock.patch("haprion_ui.db.queue_job") as queued,
            mock.patch("haprion_ui.db.dns_profile", return_value=mock.Mock()),
            mock.patch("haprion_ui.db.ndes_profile", return_value=mock.Mock()),
            #
            # A removal refuses an unread repository with the same status as an
            # expired form; with a repository to remove from, only the token's
            # refusal is left to say 400 (review 26-10-30, R5).
            #
            mock.patch(
                "haprion_ui.editor_flow.editor_state",
                return_value=mock.Mock(commit="0" * 40, stored=[]),
            ),
        ):
            for route in routes(client.app.routes, []):
                if "POST" not in route.methods or route.path == "/login":
                    continue
                data, files = form(route, other)
                audit_before = len(self.audit)
                response = client.post(
                    concrete(route), data=data, files=files or None, follow_redirects=False
                )
                self.assertEqual(len(self.audit), audit_before, f"{route.path} wrote an audit row")
                answered[route.path] = response.status_code
                if route.path in REFUSED_ITS_OWN_WAY and response.status_code == 400:
                    self.assertIn("That form had expired", response.text, route.path)

        queued.assert_not_called()
        self.assertGreater(len(answered), 50)
        self.assertEqual(
            {path: code for path, code in answered.items() if code != 403}, REFUSED_ITS_OWN_WAY
        )

    def test_with_management_writes_off_an_admin_s_post_changes_nothing_but_the_own_password(
        self,
    ) -> None:
        """Review 26-11-05: the switch is a wall in front of every write, and a
        route added without it would be the one that writes. Walked with a valid
        token, so the only thing left to refuse each is the switch."""

        client = self.client(replace(configuration(), clusters=("alpha",), management_writes=False))
        self.assertEqual(self.sign_in(client).status_code, 303)
        own = auth.csrf_token(client.cookies[auth.SESSION_COOKIE])

        answered: dict[str, int] = {}
        with (
            mock.patch("haprion_ui.db.queue_job") as queued,
            mock.patch("haprion_ui.db.dns_profile", return_value=mock.Mock()),
            mock.patch("haprion_ui.db.ndes_profile", return_value=mock.Mock()),
        ):
            for route in routes(client.app.routes, []):
                if "POST" not in route.methods or route.path in ("/login", "/logout"):
                    continue
                data, files = form(route, own)
                audit_before = len(self.audit)
                queued.reset_mock()
                response = client.post(
                    concrete(route), data=data, files=files or None, follow_redirects=False
                )
                self.assertEqual(len(self.audit), audit_before, f"{route.path} wrote an audit row")
                self.assertFalse(queued.called, f"{route.path} queued a job")
                answered[route.path] = response.status_code

        self.assertGreater(len(answered), 50)
        #
        # Not a management write: a person's own password, which the switch
        # never covered (it answers the form, here its 400 for a missing field).
        #
        self.assertEqual(
            {path: code for path, code in answered.items() if code != 404},
            {"/account/password": 400},
        )

    def test_nothing_answers_an_anonymous_visitor_but_the_public_routes(self) -> None:
        client = self.app_client()

        answered: dict[str, int] = {}
        for route in routes(client.app.routes, []):
            if "GET" not in route.methods:
                continue
            response = client.get(concrete(route), follow_redirects=False)
            if response.status_code == 303 and response.headers["location"] == "/login":
                continue
            answered[route.path] = response.status_code

        self.assertEqual(answered, PUBLIC)
        self.assertEqual(client.get("/openapi.json").status_code, 404)

    def test_an_anonymous_post_does_nothing(self) -> None:
        client = self.app_client()

        done = []
        for route in routes(client.app.routes, []):
            if "POST" not in route.methods or route.path == "/login":
                continue
            data, files = form(route, "")
            response = client.post(
                concrete(route), data=data, files=files or None, follow_redirects=False
            )
            moved = response.headers.get("location", "/login")
            if response.status_code < 300 or (response.status_code < 400 and moved != "/login"):
                done.append((route.path, response.status_code))

        self.assertEqual(done, [])


if __name__ == "__main__":
    unittest.main()


#
# The pages a reader reads as an admin does, walked on the demonstration data.
#
#
# Every page a reader may open that answers without a parameter the walk cannot
# make up. Left out: /first-cluster and /login/oidc, which redirect, and the
# pages whose path names a record (an object's editor, a version, a restore run,
# a CSR), which need a row the fixture does not hold.
#
PARITY_PAGES = (
    "/",
    "/proxies",
    "/history",
    "/network",
    "/certificates",
    "/jobs",
    "/metrics",
    "/logs",
    "/waf",
    "/waf?view=exceptions",
    "/backups",
    "/search?q=192",
    "/proxies/edge-demo/public-web",
    "/clusters/edge-demo/metrics",
    "/account/password",
    "/certificates/receivers",
    "/dns-profiles",
    "/logs/warning",
    "/ndes-profiles",
    "/search",
    "/settings/api-tokens",
)


class AReaderIsGivenWhatAnAdminIsGivenToRead(ReadingACluster):
    """A reader reads everything and changes nothing, on the page and not only at the route.

    The route walk above proves what a reader is refused; it cannot see a
    button or a link the page forgot to draw. These read the pages.
    """

    def pages(self, role: str) -> dict[str, tuple[int, str]]:
        self.account = replace(self.account, role=role)
        app = self.client(replace(configuration(), demo_fixture=True, management_writes=True))
        client: Any = TestClient(app.app, base_url=str(app.base_url), raise_server_exceptions=False)
        self.assertEqual(self.sign_in(client).status_code, 303)
        self.client_of[role] = client
        answers = {page: client.get(page) for page in PARITY_PAGES}
        #
        # A page that does not answer is not skipped: it is a page nobody compares.
        #
        self.assertEqual(
            {page: a.status_code for page, a in answers.items() if a.status_code != 200},
            {},
            f"as {role}",
        )
        return {page: (answer.status_code, answer.text) for page, answer in answers.items()}

    def setUp(self) -> None:
        super().setUp()
        self.client_of: dict[str, Any] = {}
        #
        # What the pages read from the database that the recording pool cannot
        # answer: no draft, no findings and one profile of each kind (the traffic
        # comes from `ReadingACluster`). The pages still draw their forms and
        # links, which is what these compare.
        #
        for target, value in (
            ("read_draft", None),
            ("waf_findings", []),
            ("waf_verdicts", {}),
            ("waf_request_count", 0),
            ("waf_counted", {}),
            ("dns_profiles", [profile_row()]),
            (
                "ndes_profiles",
                [profile_row(id="internal-ca", name="Internal CA", provider_id="ndes")],
            ),
        ):
            patch = mock.patch(f"haprion_ui.db.{target}", return_value=value)
            patch.start()
            self.addCleanup(patch.stop)
        #
        # Saved changes on the demonstration cluster, so Versions lists them:
        # an object that is published, one that is new, the network and the
        # settings. A link in that list is a link on a reader's page.
        #
        self.saved_rows = [
            saved_object("public-web", cluster="edge-demo"),
            saved_object(
                "brand-new", cluster="edge-demo", id=UUID("22222222-2222-4222-8222-222222222222")
            ),
        ]
        changes = {
            "network": saved("network", "{}"),
            "settings": saved("settings", "{}"),
        }
        for target, effect in (
            (
                "cluster_drafts",
                lambda _c, cluster: self.saved_rows if cluster == "edge-demo" else [],
            ),
            ("cluster_changes", lambda _c, cluster: changes if cluster == "edge-demo" else {}),
            ("draft_publishes", lambda _c, **_: []),
        ):
            patch = mock.patch(f"haprion_ui.db.{target}", side_effect=effect)
            patch.start()
            self.addCleanup(patch.stop)

    def test_the_fixture_gives_versions_a_list_of_saved_changes(self) -> None:
        self.assertIn("Pending changes", self.pages("reader")["/history"][1])

    def test_every_link_on_a_reader_s_page_leads_to_a_page_a_reader_may_open(self) -> None:
        """The other direction: a link the page draws that answers the reader with a refusal."""

        reader = self.pages("reader")
        client = self.client_of["reader"]

        refused: dict[str, list[str]] = {}
        for page, (_code, text) in reader.items():
            found = set(map(unescape, re.findall(r'(?:href|data-href)="(/[^"]*)"', text)))
            leading = [
                link
                for link in sorted(found)
                if not link.startswith(("/static", "/logout"))
                and client.get(link.split("#")[0], follow_redirects=False).status_code == 403
            ]
            if leading:
                refused[page] = leading
        self.assertEqual(refused, {})

    def test_a_reader_s_page_has_no_form_but_the_sign_out(self) -> None:
        reader = self.pages("reader")

        posted = {
            page: sorted(set(re.findall(r'<form[^>]*method="post"[^>]*action="([^"]+)"', text)))
            for page, (_code, text) in reader.items()
        }
        self.assertEqual(
            {
                page: [a for a in forms if a not in READER_MAY_POST]
                for page, forms in posted.items()
            },
            {page: [] for page in posted},
        )

    def test_a_reader_is_given_every_link_to_a_page_a_reader_may_open(self) -> None:
        admin = self.pages("admin")
        reader = self.pages("reader")
        client = self.client_of["reader"]

        missing: dict[str, list[str]] = {}
        for page, (_code, text) in reader.items():
            shown = set(map(unescape, re.findall(r'href="(/[^"]*)"', text)))
            wanted = set(map(unescape, re.findall(r'href="(/[^"]*)"', admin[page][1])))
            lacking = []
            for link in sorted(wanted - shown):
                if link.startswith("/static"):
                    continue
                if client.get(link.split("#")[0], follow_redirects=False).status_code == 200:
                    lacking.append(link)
            if lacking:
                missing[page] = lacking
        self.assertEqual(missing, {})

    def test_a_reader_has_a_link_to_the_list_of_api_tokens(self) -> None:
        reader = self.pages("reader")

        self.assertIn('href="/settings/api-tokens"', reader["/"][1])
        self.assertEqual(self.client_of["reader"].get("/settings/api-tokens").status_code, 200)
