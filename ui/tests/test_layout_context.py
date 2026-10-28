"""The layout's own variables come from the application, not from each page (review 2026-10-22, 2-9).

A page that did not pass `management_writes` drew a menu without Settings.
"""

from __future__ import annotations

import unittest
from dataclasses import replace

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.requests import Request

from haprion_ui import templates
from tests.test_login import configuration


def _request(*, writes: bool) -> Request:
    app = FastAPI()
    app.mount("/static", StaticFiles(directory=templates.STATIC_DIRECTORY), name="static")
    app.state.config = replace(configuration(), management_writes=writes)
    return Request({"type": "http", "method": "GET", "path": "/", "headers": [], "app": app})


class TheMenuDoesNotDependOnThePage(unittest.TestCase):
    def render(self, *, writes: bool) -> str:
        response = templates.TEMPLATES.TemplateResponse(
            _request(writes=writes),
            "layout.html",
            {"username": "admin", "role": "admin", "section": "history"},
        )
        return bytes(response.body).decode()

    def test_settings_is_in_the_menu_of_a_page_that_did_not_say_it(self) -> None:
        self.assertIn('href="/settings"', self.render(writes=True))
        self.assertNotIn('href="/settings"', self.render(writes=False))


if __name__ == "__main__":
    unittest.main()
