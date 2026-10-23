"""The dashboard's four cards on one line each at the width people use (2026-10-06).

Each card is a figure, a label and a detail. Equal quarters of the row gave the
longest ("4/4 Nodes online · All reporting") 210 px of the 226 it needs at 1280
with a scrollbar, and broke it in two while the others had room to spare. The
cards are sized to their text now; this measures it with the real stylesheet
and the real font, which the HTML alone cannot say anything about.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import Any, ClassVar

from haprion_ui.views import STATIC_DIRECTORY

if not os.environ.get("PLAYWRIGHT_BROWSERS_PATH"):
    raise RuntimeError(
        "set PLAYWRIGHT_BROWSERS_PATH to the directory holding the Playwright browsers"
    )

from playwright.sync_api import sync_playwright


def card(figure: str, label: str, detail: str) -> str:
    return (
        '<article class="metric-card"><span class="metric-icon"></span>'
        f"<div><strong>{figure}</strong><span>{label}</span><small>{detail}</small></div></article>"
    )


#
# The dashboard's cards as `index.html` writes them, with the values a healthy
# installation of two clusters and four nodes shows.
#
MARKUP = f"""<!doctype html><html><head><meta charset="utf-8">
<link rel="stylesheet" href="app.css"></head><body><main class="page">
<section class="metric-grid">
{card("2", "Clusters", "2 healthy")}
{card("4<small>/4</small>", "Nodes online", "All reporting")}
{card("3<small>/3</small>", "Active VIPs", "Single owner")}
{card("2", "Converged", "Target release")}
</section></main></body></html>"""


class TheDashboardCards(unittest.TestCase):
    playwright: ClassVar[Any]
    browser: ClassVar[Any]
    page_path: ClassVar[Path]

    @classmethod
    def setUpClass(cls) -> None:
        directory = Path(tempfile.mkdtemp(prefix="dashboard-cards-"))
        cls.addClassCleanup(shutil.rmtree, directory)
        for name in ("app.css", "inter-var.woff2"):
            shutil.copy(STATIC_DIRECTORY / name, directory / name)
        cls.page_path = directory / "index.html"
        cls.page_path.write_text(MARKUP)
        cls.playwright = sync_playwright().start()
        cls.browser = cls.playwright.chromium.launch()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.browser.close()
        cls.playwright.stop()

    def lines(self, width: int) -> list[int]:
        """How many lines each card's text takes at this width: 2 when its detail moved under."""

        page = self.browser.new_page(viewport={"width": width, "height": 600})
        self.addCleanup(page.close)
        page.goto(self.page_path.as_uri())
        page.evaluate("() => document.fonts.ready")
        self.assertEqual(
            page.evaluate("() => document.fonts.check('14px \"Inter Var\"')"),
            True,
            "the app's font did not load, so the measurement is not the page's",
        )
        return list(
            page.evaluate(
                """() => [...document.querySelectorAll('.metric-card > div')].map(text => {
                     const label = text.querySelector(':scope > span').getBoundingClientRect();
                     const detail = text.querySelector(':scope > small').getBoundingClientRect();
                     return detail.top >= label.bottom ? 2 : 1; })"""
            )
        )

    def test_every_card_is_one_line_at_1280_with_a_scrollbar(self) -> None:
        """1265 px is what a 1280 px window leaves beside a classic scrollbar."""

        self.assertEqual(self.lines(1265), [1, 1, 1, 1])

    def test_a_wide_window_keeps_them_on_one_line(self) -> None:
        self.assertEqual(self.lines(1920), [1, 1, 1, 1])


def header(name: str, detail: str, badge: str, figures: tuple[str, str, str, str]) -> str:
    labels = ("Requests 24 h", "In", "Out", "Response 1 h")
    traffic = "".join(
        f"<div><dt>{label}</dt><dd>{figure}</dd></div>"
        for label, figure in zip(labels, figures, strict=True)
    )
    return (
        '<article class="cluster-card"><header class="cluster-header">'
        f'<div class="cluster-identity"><span class="status-orb"></span><div><h3>{name}</h3>'
        f"<p>{detail}</p></div></div>"
        f'<dl class="cluster-traffic">{traffic}</dl>'
        f'<div class="cluster-state"><span class="status-badge">{badge}</span>'
        '<span class="observation-age">Observed 18s ago</span></div>'
        "</header></article>"
    )


#
# Two clusters as a dashboard showed them on 26-10-11: a busy one and a quiet
# one, different names, details and badges.
#
HEADERS = f"""<!doctype html><html><head><meta charset="utf-8">
<link rel="stylesheet" href="app.css"></head><body><main class="page"><div class="cluster-list">
{
    header(
        "internal",
        "All nodes serve the published version",
        "Healthy",
        ("99.9k", "999 kbit/s", "999 kbit/s", "999 ms"),
    )
}
{
    header(
        "external",
        "1 node is not running the published release",
        "Behind",
        ("79", "0 bit/s", "0 bit/s", "4 ms"),
    )
}
</div></main></body></html>"""


class TheTrafficFiguresStayInPlace(unittest.TestCase):
    """The four figures in the same place on every cluster card (26-10-11).

    Centred in what the name and the badges left over, they moved with every
    name, badge and figure, and two clusters' rows never lined up.
    """

    def test_every_card_puts_them_in_the_same_columns_and_the_longest_figures_fit(self) -> None:
        directory = Path(tempfile.mkdtemp(prefix="cluster-traffic-"))
        self.addCleanup(shutil.rmtree, directory)
        for name in ("app.css", "inter-var.woff2"):
            shutil.copy(STATIC_DIRECTORY / name, directory / name)
        (directory / "index.html").write_text(HEADERS)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            page = browser.new_page(viewport={"width": 1280, "height": 600})
            page.goto((directory / "index.html").as_uri())
            page.evaluate("() => document.fonts.ready")
            columns = page.evaluate(
                """() => Array.from(document.querySelectorAll(".cluster-traffic"), (dl) =>
                    Array.from(dl.querySelectorAll("dt"), (dt) => Math.round(dt.getBoundingClientRect().x)))"""
            )
            spill = page.evaluate(
                """() => Array.from(document.querySelectorAll(".cluster-traffic > div"),
                    (box) => box.scrollWidth - box.clientWidth)"""
            )
            browser.close()
        self.assertEqual(columns[0], columns[1])
        self.assertEqual(set(spill), {0})
