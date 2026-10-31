"""The API reads no cookie and the pages read no bearer token (B416).

That boundary is why the API needs no CSRF token: a browser sends a cookie
by itself, never an `Authorization` header. A route that crossed it - an API
route reading the session, a page accepting a token - would be a forged
request waiting to happen, and nothing else here would notice. These walk
every route on both sides.
"""

from __future__ import annotations

import logging
from typing import Any
from unittest import mock

from fastapi.testclient import TestClient
from starlette.routing import Mount

from haprion_ui import api, api_tokens
from haprion_ui.api import caller
from haprion_ui.api.caller import Needs
from tests.test_api import ApiTestCase
from tests.test_route_roles import PUBLIC, concrete, routes


def api_routes(client: Any) -> list[Any]:
    mounted = [
        route
        for route in client.app.routes
        if isinstance(route, Mount) and route.path == api.PREFIX
    ]
    mounted_app: Any = mounted[0].app
    return routes(mounted_app.routes, [])


#
# What any valid token may call, whatever its level: the token itself, so an
# integration can see when it ends, and the schema.
#
ANY_TOKEN = {"/token", "/openapi.json"}


def pages_of(client: Any) -> list[Any]:
    app: Any = client.app
    return list(app.routes)


def declared_level(route: Any) -> str | None:
    for dependency in route.dependant.dependencies:
        if isinstance(dependency.call, Needs):
            return dependency.call.level
    return None


def admits(route: Any, held: str) -> bool:
    """Whether the route's own declaration admits a token of level `held`.

    A level and what reaches it, unless the dependency says otherwise with
    `admits`: the route a `block` token may also read is the one place that does.
    """

    for dependency in route.dependant.dependencies:
        if isinstance(dependency.call, Needs):
            own = getattr(dependency.call, "admits", None)
            if own is not None:
                return bool(own(held))
            return api_tokens.reaches(held, dependency.call.level)
    return False


class TheCookieAndTheTokenStayOnTheirSides(ApiTestCase):
    def test_a_signed_in_browser_is_no_caller_of_the_api(self) -> None:
        # Every refusal is a failure counted against the source; the walk
        # passes more routes than the count allows in a minute.
        patch = mock.patch.object(caller, "FAILURES", caller.Failures(limit=10_000))
        patch.start()
        self.addCleanup(patch.stop)
        client = self.client()
        self.assertEqual(self.sign_in(client).status_code, 303)
        walked = 0
        for route in api_routes(client):
            for method in sorted(route.methods - {"HEAD"}):
                with (
                    self.subTest(method=method, path=route.path),
                    self.assertLogs("haprion_ui.api"),
                ):
                    response = client.request(method, api.PREFIX + concrete(route))
                    self.assertEqual(response.status_code, 401)
                walked += 1
        self.assertGreaterEqual(walked, 3)

    def test_a_token_changes_nothing_a_page_answers(self) -> None:
        client = self.client()
        bearer = {"Authorization": f"Bearer {self.issue(level='write')}"}
        walked = 0
        #
        # Caught rather than printed: `/healthz` says in the log that the
        # test's pool is no database.
        #
        with self.assertLogs("haprion_ui", "WARNING"):
            for route in routes(pages_of(client), []):
                for method in sorted(route.methods - {"HEAD"}):
                    path = concrete(route)
                    with self.subTest(method=method, path=path):
                        without = client.request(method, path, follow_redirects=False)
                        with_token = client.request(
                            method, path, headers=bearer, follow_redirects=False
                        )
                        self.assertEqual(
                            (with_token.status_code, with_token.headers.get("location")),
                            (without.status_code, without.headers.get("location")),
                        )
                        if route.path not in PUBLIC:
                            self.assertNotEqual(with_token.status_code, 200, "a page took a token")
                    walked += 1
        self.assertGreater(walked, 100)


class EachRouteAnswersOnlyItsLevel(ApiTestCase):
    """B416 6b: a `read` or `block` token reaches nothing above its level, route by route."""

    def test_every_route_names_the_level_it_needs(self) -> None:
        client = self.client()
        unnamed = [
            route.path
            for route in api_routes(client)
            if route.path not in ANY_TOKEN and declared_level(route) is None
        ]
        self.assertEqual(unnamed, [])

    def test_a_token_below_a_route_s_level_is_refused_and_one_at_it_is_not(self) -> None:
        #
        # A token that reaches a route runs it, against a pool that is no
        # database: whatever that answers is the route's business, only not
        # a 401 or a 403. Answered rather than raised, as the service would.
        #
        client = self.client()
        client = TestClient(
            client.app, base_url=str(client.base_url), raise_server_exceptions=False
        )
        quiet = mock.patch.object(logging.getLogger("haprion_ui.api"), "disabled", True)
        quiet.start()
        self.addCleanup(quiet.stop)
        secrets = {held: self.issue(level=held) for held in api_tokens.LEVELS}
        walked = 0
        for route in api_routes(client):
            needed = declared_level(route)
            if needed is None:
                continue
            for method in sorted(route.methods - {"HEAD"}):
                for held, secret in secrets.items():
                    with self.subTest(method=method, path=route.path, held=held):
                        response = client.request(
                            method,
                            api.PREFIX + concrete(route),
                            headers={"Authorization": f"Bearer {secret}"},
                            json=None if method == "GET" else {},
                        )
                        if admits(route, held):
                            self.assertNotIn(response.status_code, (401, 403))
                        else:
                            self.assertEqual(response.status_code, 403)
                            self.assertEqual(response.json()["error"]["code"], "forbidden")
                    walked += 1
        self.assertGreaterEqual(walked, 3)
