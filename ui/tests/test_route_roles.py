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
from typing import Any
from unittest import mock

from haprion_ui import auth
from tests.test_login import LoginTestCase, configuration

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
