"""A pager inside a card keeps the card's gutter below its buttons, measured with the real stylesheet.

The node backups' archive list put *Newer* and *Older* against the bottom edge
of its fold (26-11-17): its pager borrowed the traffic log's bar with the card's
side gutter but no space below, while the version list's pager, the same bar in
the same kind of card, had 12 px. This measures both, and fails when the
buttons sit closer to the edge than the version list's.
"""

from __future__ import annotations

import os
import unittest
from typing import Any, ClassVar

from haprion_ui.templates import STATIC_DIRECTORY

if not os.environ.get("PLAYWRIGHT_BROWSERS_PATH"):
    raise RuntimeError(
        "set PLAYWRIGHT_BROWSERS_PATH to the directory holding the Playwright browsers"
    )

from playwright.sync_api import sync_playwright

ROWS = "".join(f"<tr><td>v{n}</td><td>node-a</td></tr>" for n in range(3))
PAGER = (
    '<nav class="log-pagination"><span>1–10 of 30</span><div>'
    '<button class="secondary-button" type="button">Newer</button>'
    '<button class="secondary-button" type="button" data-older>Older</button></div></nav>'
)
TABLE = f'<div class="table-scroll"><table class="node-table"><tbody>{ROWS}</tbody></table></div>'
# The two pagers as backups.html and history.html write them, each in its card.
MARKUP = f"""
<main class="page">
  <article class="cluster-card backup-cluster-card">
    <details class="archive-details" open id="archives"><summary>30 retained archives</summary>{TABLE}{PAGER}</details>
  </article>
  <article class="cluster-card">
    <div data-version-list id="versions">{TABLE}{PAGER}</div>
  </article>
</main>
"""
GUTTER = 12


class APagerKeepsTheCardsGutter(unittest.TestCase):
    playwright: ClassVar[Any]
    browser: ClassVar[Any]

    @classmethod
    def setUpClass(cls) -> None:
        cls.playwright = sync_playwright().start()
        cls.browser = cls.playwright.chromium.launch()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.browser.close()
        cls.playwright.stop()

    def test_the_buttons_stand_clear_of_the_bottom_edge(self) -> None:
        css = (STATIC_DIRECTORY / "app.css").read_text(encoding="utf-8")
        for width in (1280, 600):
            page = self.browser.new_page(viewport={"width": width, "height": 900})
            self.addCleanup(page.close)
            page.set_content(
                f"<!doctype html><html><head><style>{css}</style></head><body>{MARKUP}</body></html>"
            )
            for box in ("archives", "versions"):
                with self.subTest(width=width, box=box):
                    space = page.evaluate(
                        """id => {
                            const box = document.getElementById(id);
                            return box.getBoundingClientRect().bottom
                                - box.querySelector('[data-older]').getBoundingClientRect().bottom;
                        }""",
                        box,
                    )
                    self.assertGreaterEqual(round(space), GUTTER)


if __name__ == "__main__":
    unittest.main()
