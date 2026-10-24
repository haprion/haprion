"""The jobs table keeps each value in its own column at 1280 (review 26-10-24, 04-01).

With fixed columns and `nowrap`, a long SSO name or cluster ID was drawn over
the next column. Rendered through the real view and template, so what is
measured is the markup the page sends, at the width the interface is checked at.
"""

from __future__ import annotations

import os
from dataclasses import replace
from unittest import mock

from haprion_ui.views import STATIC_DIRECTORY
from tests.test_job_page import job
from tests.test_login import LoginTestCase, configuration

if not os.environ.get("PLAYWRIGHT_BROWSERS_PATH"):
    raise RuntimeError(
        "set PLAYWRIGHT_BROWSERS_PATH to the directory holding the Playwright browsers"
    )

from playwright.sync_api import sync_playwright

CLUSTER = "a" * 63
USER = "firstname.lastname@example.com"

SPILLS = """() => Array.from(document.querySelectorAll(".job-table td"), (cell) =>
    getComputedStyle(cell).overflowX === "visible" && cell.scrollWidth > cell.clientWidth)
    .filter(Boolean).length"""


class LongNamesStayInTheirColumns(LoginTestCase):
    def test_a_long_cluster_and_an_e_mail_name_do_not_spill(self) -> None:
        row = job(state="done", outcome="done", cluster=CLUSTER)
        with (
            mock.patch("haprion_ui.db.recent_jobs", return_value=[row]),
            mock.patch("haprion_ui.db.requested_by", return_value={row.request_id: USER}),
        ):
            client = self.client(replace(configuration(), clusters=(CLUSTER,)))
            self.sign_in(client)
            html = client.get("/jobs").text
        self.assertIn(f'title="{USER}"', html)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            page = browser.new_page(viewport={"width": 1280, "height": 800})
            page.set_content(html)
            page.add_style_tag(path=str(STATIC_DIRECTORY / "app.css"))
            spilled = page.evaluate(SPILLS)
            cells = page.evaluate("() => document.querySelectorAll('.job-table td').length")
            browser.close()
        self.assertGreater(cells, 0)
        self.assertEqual(spilled, 0)
