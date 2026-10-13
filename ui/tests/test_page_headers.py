"""No page is kept in a cache, and no page runs what it did not load (review 26-10-13, S1, S2)."""

from __future__ import annotations

import re
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response
from starlette.routing import Route

from haprion_ui import page_headers
from tests.test_login import LoginTestCase

TEMPLATES = Path(page_headers.__file__).resolve().parent / "templates"
INLINE = re.compile(r'\sstyle="|\son[a-z]+="|<script(?![^>]*\ssrc=)[^>]*>|<style\b|javascript:')


class NoPageIsStored(LoginTestCase):
    def test_the_sign_in_page_and_a_signed_in_page_say_no_store(self) -> None:
        client = self.client()
        self.assertEqual(client.get("/login").headers.get("cache-control"), "no-store")
        signed_in = self.sign_in(client)
        self.assertEqual(signed_in.headers.get("cache-control"), "no-store")
        with mock.patch("haprion_ui.db.audit_events", return_value=[]):
            page = client.get("/jobs?view=audit")
        self.assertEqual(page.status_code, 200)
        self.assertEqual(page.headers.get("cache-control"), "no-store")

    def test_the_static_assets_are_left_to_the_browser(self) -> None:
        client = self.client()
        asset = client.get("/static/app.css")
        self.assertEqual(asset.status_code, 200)
        self.assertNotIn("no-store", asset.headers.get("cache-control", ""))

    def test_a_route_s_own_policy_is_kept_and_not_doubled(self) -> None:
        async def own(_request: Request) -> Response:
            return PlainTextResponse("x", headers={"Cache-Control": "private, max-age=60"})

        async def plain(_request: Request) -> Response:
            return PlainTextResponse("x")

        app = Starlette(routes=[Route("/own", own), Route("/plain", plain)])
        app.add_middleware(page_headers.PageHeadersMiddleware)
        client = TestClient(app)

        self.assertEqual(
            client.get("/own").headers.get_list("cache-control"), ["private, max-age=60"]
        )
        self.assertEqual(client.get("/plain").headers.get_list("cache-control"), ["no-store"])


class NothingInline(LoginTestCase):
    def test_every_answer_carries_the_policy(self) -> None:
        client = self.client()
        for path in ("/login", "/static/app.css"):
            with self.subTest(path=path):
                policy = client.get(path).headers.get("content-security-policy", "")
                self.assertIn("default-src 'self'", policy)
                self.assertIn("frame-ancestors 'none'", policy)

    def test_no_template_has_inline_style_or_script(self) -> None:
        # What the policy refuses would silently stop working in the browser.
        found = [
            f"{path.name}: {match.group(0)}"
            for path in sorted(TEMPLATES.glob("*.html"))
            for match in INLINE.finditer(path.read_text(encoding="utf-8"))
        ]
        self.assertEqual(found, [])
