"""A database that does not answer is a page that says so (review 2026-10-20, U2)."""

from __future__ import annotations

from unittest import mock

import httpx
import psycopg
import psycopg_pool

from tests.test_login import LoginTestCase


class TheDatabaseDidNotAnswer(LoginTestCase):
    def failing(self, error: Exception, *, method: str = "get") -> httpx.Response:
        client = self.client()
        self.assertEqual(self.sign_in(client).status_code, 303)
        with mock.patch("haprion_ui.db.session_by_hash", side_effect=error):
            response: httpx.Response = (
                client.get("/proxies?cluster=alpha")
                if method == "get"
                else client.post("/proxies/alpha/new", data={}, follow_redirects=False)
            )
        return response

    def test_a_lost_database_is_a_503_page_with_a_way_on(self) -> None:
        response = self.failing(psycopg.OperationalError("connection to server failed: secret"))
        self.assertEqual(response.status_code, 503)
        self.assertIn("text/html", response.headers["content-type"])
        self.assertIn("The database did not answer", response.text)
        self.assertIn('href="https://manager.example.com/proxies?cluster=alpha"', response.text)
        self.assertNotIn("secret", response.text)

    def test_a_pool_out_of_connections_is_the_same_page(self) -> None:
        response = self.failing(psycopg_pool.PoolTimeout("couldn't get a connection"))
        self.assertEqual(response.status_code, 503)
        self.assertIn("The database did not answer", response.text)

    def test_a_query_past_its_time_limit_says_to_narrow_it(self) -> None:
        response = self.failing(psycopg.errors.QueryCanceled("canceling statement"))
        self.assertEqual(response.status_code, 503)
        self.assertIn("A narrower filter asks less of it.", response.text)

    def test_a_form_is_not_offered_again_as_a_link(self) -> None:
        response = self.failing(psycopg.OperationalError("gone"), method="post")
        self.assertEqual(response.status_code, 503)
        self.assertIn("Whether the change was saved", response.text)
        self.assertIn('href="/"', response.text)
