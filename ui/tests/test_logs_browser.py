"""The log controls driven by the browser code that implements them."""

from __future__ import annotations

import os
import unittest
from typing import Any, ClassVar

from haproxy_ui.views import STATIC_DIRECTORY

if not os.environ.get("PLAYWRIGHT_BROWSERS_PATH"):
    raise RuntimeError(
        "set PLAYWRIGHT_BROWSERS_PATH to the directory holding the Playwright browsers"
    )

from playwright.sync_api import sync_playwright  # noqa: E402


class LogControlsInABrowser(unittest.TestCase):
    playwright: ClassVar[Any]
    browser: ClassVar[Any]
    page: Any

    @classmethod
    def setUpClass(cls) -> None:
        cls.playwright = sync_playwright().start()
        cls.browser = cls.playwright.chromium.launch()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.browser.close()
        cls.playwright.stop()

    def setUp(self) -> None:
        self.page = self.browser.new_page()
        self.addCleanup(self.page.close)

    def load(self, markup: str) -> None:
        self.page.set_content(markup)
        self.page.add_script_tag(path=str(STATIC_DIRECTORY / "logs.js"))

    def test_the_picker_writes_a_two_digit_date_and_a_24_hour_time(self) -> None:
        self.load(
            """
            <div data-log-date-picker data-default="26-09-10 17:04">
              <input name="from" aria-expanded="false">
              <div class="log-calendar" hidden>
                <button type="button" data-log-day="26-09-08">8</button>
                <button type="button" data-log-clear>Clear</button>
                <button type="button" data-log-apply>Apply</button>
                <select data-log-hour></select><select data-log-minute></select>
              </div>
            </div>
            """
        )

        self.page.click("input[name=from]")
        self.assertEqual(self.page.locator("[data-log-hour] option").count(), 24)
        self.assertEqual(self.page.locator("[data-log-minute] option").count(), 60)
        self.page.click("[data-log-day]")
        self.page.select_option("[data-log-hour]", "23")
        self.page.select_option("[data-log-minute]", "59")
        self.page.click("[data-log-apply]")

        self.assertEqual(self.page.input_value("input[name=from]"), "26-09-08 23:59")

    def test_csv_contains_the_complete_selected_row_and_not_the_unselected_one(self) -> None:
        path = "/" + "complete-segment/" * 40
        self.load(
            f"""
            <button type="button" data-log-export disabled>Export selected (.csv)</button>
            <span data-log-selected-count></span>
            <input type="checkbox" data-log-select-all>
            <table><tbody>
              <tr data-log-row data-export-time="26-09-10 20:00:00"
                  data-export-cluster="alpha" data-export-node="node-a"
                  data-export-client="192.0.2.5" data-export-method="GET"
                  data-export-host="=not-a-formula" data-export-path="{path}"
                  data-export-status="200" data-export-destination="app.example:8080"
                  data-export-bytes="512"><td><input type="checkbox" data-log-select></td></tr>
              <tr data-log-row data-export-time="26-09-10 20:01:00"
                  data-export-cluster="alpha" data-export-node="node-b"
                  data-export-client="192.0.2.6" data-export-method="GET"
                  data-export-host="skip.example" data-export-path="/not-selected"
                  data-export-status="200" data-export-destination="app.example:8080"
                  data-export-bytes="256"><td><input type="checkbox" data-log-select></td></tr>
            </tbody></table>
            """
        )

        self.page.locator("[data-log-select]").first.check()
        self.assertFalse(self.page.locator("[data-log-export]").is_disabled())
        with self.page.expect_download() as pending:
            self.page.click("[data-log-export]")
        content = pending.value.path().read_text(encoding="utf-8-sig")

        self.assertIn(path, content)
        self.assertIn("'=not-a-formula", content)
        self.assertNotIn("/not-selected", content)
        self.assertEqual(len(content.splitlines()), 2)


if __name__ == "__main__":
    unittest.main()
