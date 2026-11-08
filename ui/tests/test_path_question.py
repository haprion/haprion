"""*Test a path* on an object's page (B496, 7)."""

from __future__ import annotations

import unittest
from dataclasses import replace
from typing import Any

from haprion_ui.db import ProxyDraft
from haprion_ui.path_question import PathQuestion, path_question
from tests.test_login import configuration
from tests.test_object_page import DraftReading

SHOP = """schema: 1
name: shop
hostnames: [shop.example.com]
listen:
  protocol: http
routes:
  - path: /
    backend: web
  - path: /api
    backend: api
    strip_prefix: /api
backends:
  web:
    balance: roundrobin
    health:
      type: disabled
    servers:
      - host: 192.0.2.10
        port: 8080
  api:
    balance: roundrobin
    health:
      type: disabled
    servers:
      - host: 192.0.2.20
        port: 8080
"""


def draft(stage: str) -> ProxyDraft:
    from datetime import UTC, datetime

    return ProxyDraft(
        cluster="alpha",
        object_id="shop",
        yaml=SHOP,
        base_version=1,
        base_hash="0" * 40,
        revision=1,
        updated_by="operator",
        updated_at=datetime(2026, 11, 8, tzinfo=UTC),
        deleted=False,
        stage=stage,
    )


def asked(document: str, path: str | None, work: ProxyDraft | None = None) -> PathQuestion:
    """The field for `shop`, which an http object always has."""

    question = path_question("shop", document, path, work)
    if question is None:
        raise AssertionError("an http object has the field")
    return question


class TheAnswerUnderTheField(unittest.TestCase):
    def test_nothing_asked_is_an_empty_field(self) -> None:
        for nothing in (None, ""):
            with self.subTest(nothing=nothing):
                found = asked(SHOP, nothing)
                self.assertEqual((found.asked, found.answer), ("", ""))

    def test_an_object_that_does_not_route_by_path_has_no_field(self) -> None:
        self.assertIsNone(path_question("db", None, "/", None))

    def test_the_answer_is_the_engine_s_sentence(self) -> None:
        found = asked(SHOP, "/api/users?limit=10")

        self.assertEqual(found.answer, "Route /api · pool api · the server gets /users?limit=10")
        self.assertEqual(found.tone, "healthy")

    def test_a_refused_path_says_why_where_the_answer_would_be(self) -> None:
        found = asked(SHOP, "api")

        self.assertEqual((found.tone, found.asked), ("critical", "api"))
        self.assertIn("A path starts with /", found.answer)

    def test_work_on_top_of_the_stored_object_is_said_to_be_left_out(self) -> None:
        for stage, said in (("draft", "the draft"), ("saved", "the saved change")):
            with self.subTest(stage=stage):
                found = asked(SHOP, "/", draft(stage))
                self.assertEqual(found.notes, (f"tested as stored, without {said}",))


class TheFieldOnThePage(DraftReading):
    def page(self, query: str = "") -> str:
        client: Any = self.client(replace(configuration(), demo_fixture=True))
        self.sign_in(client)
        answer = client.get(f"/proxies/edge-demo/public-web{query}")
        self.assertEqual(answer.status_code, 200)
        return str(answer.text)

    def test_the_field_sits_under_the_publication_line_for_every_reader(self) -> None:
        body = self.page()

        self.assertIn(
            '<form class="path-test" method="get" action="/proxies/edge-demo/public-web">', body
        )
        self.assertNotIn('class="path-answer"', body)

    def test_a_path_asked_is_answered_and_kept_in_the_field(self) -> None:
        body = self.page("?path=%2Fabout%3Fx%3D1")

        self.assertIn('name="path" value="/about?x=1"', body)
        self.assertIn("Route / · pool web · the server gets /about?x=1", body)


if __name__ == "__main__":
    unittest.main()
