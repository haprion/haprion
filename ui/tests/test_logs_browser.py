"""The log controls driven by the browser code that implements them."""

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

    def load(self, markup: str, script: str = "logs.js") -> None:
        self.page.set_content(markup)
        self.page.add_script_tag(path=str(STATIC_DIRECTORY / script))

    PICKER = """
        <div data-log-date-picker data-default="26-09-10 17:04"
             data-min="26-08-01 00:00" data-max="26-09-10 17:04">
          <input name="from" aria-expanded="false">
          <div class="log-calendar" hidden>
            <button type="button" data-log-month-step="-1">Previous</button>
            <strong data-log-month-label></strong>
            <button type="button" data-log-month-step="1">Next</button>
            <div data-log-days></div>
            <select data-log-hour></select><select data-log-minute></select>
            <button type="button" data-log-clear>Clear</button>
            <button type="button" data-log-apply>Apply</button>
          </div>
        </div>
    """

    def test_the_picker_writes_a_two_digit_date_and_a_24_hour_time(self) -> None:
        self.load(self.PICKER, "date-picker.js")

        self.page.click("input[name=from]")
        self.assertEqual(self.page.locator("[data-log-hour] option").count(), 24)
        self.assertEqual(self.page.locator("[data-log-minute] option").count(), 60)
        self.page.click('[data-log-day="26-09-08"]')
        self.page.select_option("[data-log-hour]", "23")
        self.page.select_option("[data-log-minute]", "59")
        self.page.click("[data-log-apply]")

        self.assertEqual(self.page.input_value("input[name=from]"), "26-09-08 23:59")

    def test_the_picker_steps_a_month_at_a_time_inside_the_window(self) -> None:
        self.load(self.PICKER, "date-picker.js")

        self.page.click("input[name=from]")
        self.assertEqual(self.page.text_content("[data-log-month-label]"), "September 2026")
        self.assertTrue(self.page.is_disabled('[data-log-month-step="1"]'))
        self.assertTrue(self.page.is_disabled('[data-log-day="26-09-11"]'))
        self.page.click('[data-log-month-step="-1"]')
        self.assertEqual(self.page.text_content("[data-log-month-label]"), "August 2026")
        self.assertTrue(self.page.is_disabled('[data-log-month-step="-1"]'))
        self.page.click('[data-log-day="26-08-01"]')
        self.page.click("[data-log-apply]")

        self.assertEqual(self.page.input_value("input[name=from]"), "26-08-01 17:04")

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

    def test_a_waf_export_carries_the_rule_and_is_named_for_the_waf(self) -> None:
        """Review 26-10-24, 04-09: the WAF page's export had no rule and said traffic-logs."""

        self.load(
            """
            <div data-log-region data-log-kind="waf">
            <button type="button" data-log-export disabled>Export selected (.csv)</button>
            <span data-log-selected-count></span>
            <input type="checkbox" data-log-select-all>
            <table><tbody>
              <tr data-log-row data-export-time="26-09-10 20:00:00"
                  data-export-cluster="alpha" data-export-node="node-a"
                  data-export-client="192.0.2.5" data-export-method="GET"
                  data-export-host="app.example.com" data-export-path="/admin"
                  data-export-status="403" data-export-destination="app.example:8080"
                  data-export-bytes="0" data-export-rule="block-admin" data-export-mode="denied"
                  ><td><input type="checkbox" data-log-select></td></tr>
            </tbody></table>
            </div>
            """
        )

        self.page.locator("[data-log-select]").first.check()
        with self.page.expect_download() as pending:
            self.page.click("[data-log-export]")
        content = pending.value.path().read_text(encoding="utf-8-sig").splitlines()

        self.assertTrue(pending.value.suggested_filename.startswith("waf-logs-"))
        self.assertTrue(content[0].endswith('"Bytes","Rule","Mode"'))
        self.assertTrue(content[1].endswith('"0","block-admin","denied"'))

    def test_filter_and_clear_replace_only_the_log_region_and_update_the_address(self) -> None:
        def markup(value: str) -> str:
            return f"""
            <html><body><nav data-site-navigation>Navigation stays</nav>
              <div data-log-region>
                <form action="/logs" data-log-filters>
                  <input name="q" value=""><button type="submit">Filter</button>
                  <a href="/logs" data-log-clear-filters>Clear</a>
                </form>
                <p data-result>{value}</p>
              </div>
            </body></html>
            """

        def answer(route: Any) -> None:
            value = "Filtered" if "q=needle" in route.request.url else "All rows"
            route.fulfill(status=200, content_type="text/html", body=markup(value))

        self.page.route("https://example.test/**", answer)
        self.page.goto("https://example.test/logs")
        self.page.locator("[data-site-navigation]").evaluate("node => { node.heldByTest = true; }")
        self.page.add_script_tag(path=str(STATIC_DIRECTORY / "logs.js"))

        self.page.fill("input[name=q]", "needle")
        self.page.click("button[type=submit]")
        self.page.wait_for_function(
            "document.querySelector('[data-result]')?.textContent === 'Filtered'"
        )
        self.assertEqual(self.page.locator("[data-result]").inner_text(), "Filtered")
        self.assertIn("q=needle", self.page.url)
        self.assertTrue(
            self.page.locator("[data-site-navigation]").evaluate("node => node.heldByTest === true")
        )

        self.page.click("[data-log-clear-filters]")
        self.page.wait_for_function(
            "document.querySelector('[data-result]')?.textContent === 'All rows'"
        )
        self.assertEqual(self.page.locator("[data-result]").inner_text(), "All rows")
        self.assertEqual(self.page.url, "https://example.test/logs")

    def test_the_warning_catches_up_on_its_own_and_stays_open(self) -> None:
        def warning(text: str) -> str:
            return (
                '<div class="log-warning-slot" data-log-warning="/logs/warning">'
                f'<details class="log-warning"><summary>Log warning</summary><p data-said>{text}</p>'
                "</details></div>"
            )

        page = f"""
        <html><body><div data-log-region>{warning("455885161 bytes remaining")}
          <table><tbody><tr data-row><td>a request</td></tr></tbody></table>
        </div></body></html>
        """
        asked: list[str] = []

        def answer(route: Any) -> None:
            if route.request.url.endswith("/logs/warning"):
                asked.append(route.request.url)
                body = warning("430807573 bytes remaining")
            else:
                body = page
            route.fulfill(status=200, content_type="text/html", body=body)

        self.page.clock.install()
        self.page.route("https://example.test/**", answer)
        self.page.goto("https://example.test/logs")
        self.page.add_script_tag(path=str(STATIC_DIRECTORY / "logs.js"))
        self.page.locator("[data-row]").evaluate("node => { node.heldByTest = true; }")
        self.page.click(".log-warning summary")

        self.page.clock.run_for(14_000)
        self.assertEqual(asked, [])
        self.page.clock.run_for(2_000)
        self.page.wait_for_function(
            "document.querySelector('[data-said]').textContent.startsWith('430807573')"
        )

        self.assertEqual(len(asked), 1)
        self.assertTrue(self.page.locator(".log-warning").evaluate("node => node.open"))
        self.assertTrue(
            self.page.locator("[data-row]").evaluate("node => node.heldByTest === true"),
            "the table is not redrawn",
        )

    def test_a_heading_replaces_only_the_log_region_and_updates_the_address(self) -> None:
        def markup(value: str) -> str:
            return f"""
            <html><body><nav data-site-navigation>Navigation stays</nav>
              <div data-log-region>
                <a class="sort-link" href="/logs?status=2xx&sort=bytes">Bytes</a>
                <p data-result>{value}</p>
              </div>
            </body></html>
            """

        def answer(route: Any) -> None:
            value = "Largest first" if "sort=bytes" in route.request.url else "Newest first"
            route.fulfill(status=200, content_type="text/html", body=markup(value))

        self.page.route("https://example.test/**", answer)
        self.page.goto("https://example.test/logs?status=2xx")
        self.page.locator("[data-site-navigation]").evaluate("node => { node.heldByTest = true; }")
        self.page.add_script_tag(path=str(STATIC_DIRECTORY / "logs.js"))

        self.page.click(".sort-link")
        self.page.wait_for_function(
            "document.querySelector('[data-result]')?.textContent === 'Largest first'"
        )
        self.assertEqual(self.page.url, "https://example.test/logs?status=2xx&sort=bytes")
        self.assertTrue(
            self.page.locator("[data-site-navigation]").evaluate("node => node.heldByTest === true")
        )

    def test_pagination_keeps_cross_page_selection_and_selects_only_the_visible_page(self) -> None:
        rows = "".join(
            f'<tr data-log-row data-row="{number}"><td><input type="checkbox" data-log-select></td></tr>'
            for number in range(120)
        )
        self.load(
            f"""
            <div data-log-region>
              <button type="button" data-log-export disabled>Export selected (.csv)</button>
              <span data-log-selected-count></span>
              <input type="checkbox" data-log-select-all>
              <table><tbody>{rows}</tbody></table>
              <select data-log-page-size>
                <option value="25">25</option><option value="50" selected>50</option><option value="100">100</option>
              </select>
              <span data-log-page-range></span>
              <button type="button" data-log-page-previous>Previous</button>
              <button type="button" data-log-page-next>Next</button>
            </div>
            """
        )

        visible = self.page.locator("[data-log-row]:visible")
        self.assertEqual(visible.count(), 50)
        self.assertEqual(self.page.locator("[data-log-page-range]").inner_text(), "1–50 of 120")
        self.page.locator('[data-row="0"] [data-log-select]').check()

        self.page.click("[data-log-page-next]")
        self.assertEqual(visible.count(), 50)
        self.assertEqual(visible.first.get_attribute("data-row"), "50")
        self.assertEqual(self.page.locator("[data-log-page-range]").inner_text(), "51–100 of 120")
        self.assertEqual(self.page.locator("[data-log-selected-count]").inner_text(), "1 selected")
        self.assertFalse(self.page.locator("[data-log-select-all]").is_checked())

        self.page.locator("[data-log-select-all]").check()
        self.assertEqual(self.page.locator("[data-log-selected-count]").inner_text(), "51 selected")
        self.page.click("[data-log-page-next]")
        self.assertEqual(visible.count(), 20)
        self.assertEqual(visible.first.get_attribute("data-row"), "100")
        self.assertFalse(self.page.locator("[data-log-select-all]").is_checked())

        self.page.select_option("[data-log-page-size]", "100")
        self.assertEqual(visible.count(), 100)
        self.assertEqual(visible.first.get_attribute("data-row"), "0")
        self.assertEqual(self.page.locator("[data-log-page-range]").inner_text(), "1–100 of 120")
        self.assertTrue(
            self.page.locator("[data-log-select-all]").evaluate("node => node.indeterminate")
        )

    def test_the_arrow_opens_a_request_s_timings_and_a_page_turn_keeps_them_with_it(self) -> None:
        """B496, 1: the timings follow their row; the select-all and the page count ignore them."""

        rows = "".join(
            f'<tr data-log-row data-row="{number}"><td><input type="checkbox" data-log-select></td>'
            f'<td><button type="button" data-log-open aria-expanded="false">Timings</button></td></tr>'
            f'<tr data-log-timings data-timings="{number}" hidden><td>Total {number} ms</td></tr>'
            for number in range(30)
        )
        self.load(
            f"""
            <div data-log-region>
              <span data-log-selected-count></span>
              <input type="checkbox" data-log-select-all>
              <table><tbody>{rows}</tbody></table>
              <select data-log-page-size><option value="25" selected>25</option></select>
              <span data-log-page-range></span>
              <button type="button" data-log-page-previous>Previous</button>
              <button type="button" data-log-page-next>Next</button>
            </div>
            """
        )

        timings = self.page.locator("[data-log-timings]:visible")
        self.assertEqual(timings.count(), 0)
        self.assertEqual(self.page.locator("[data-log-page-range]").inner_text(), "1–25 of 30")

        self.page.click('[data-row="3"] [data-log-open]')
        self.assertEqual(timings.count(), 1)
        self.assertEqual(timings.first.get_attribute("data-timings"), "3")
        self.assertEqual(
            self.page.locator('[data-row="3"] [data-log-open]').get_attribute("aria-expanded"),
            "true",
        )

        self.page.click("[data-log-page-next]")
        self.assertEqual(timings.count(), 0)
        self.page.click("[data-log-page-previous]")
        self.assertEqual(timings.count(), 1)

        self.page.locator("[data-log-select-all]").check()
        self.assertEqual(self.page.locator("[data-log-selected-count]").inner_text(), "25 selected")

        self.page.click('[data-row="3"] [data-log-open]')
        self.assertEqual(timings.count(), 0)

    def test_the_heading_s_arrow_opens_every_request_on_every_page(self) -> None:
        """26-11-17: one arrow for all; the page turn keeps them open, and one closed by hand turns it back."""

        rows = "".join(
            f'<tr data-log-row data-row="{number}"><td><input type="checkbox" data-log-select></td>'
            f'<td><button type="button" data-log-open aria-expanded="false">Timings</button></td></tr>'
            f'<tr data-log-timings data-timings="{number}" hidden><td>Total {number} ms</td></tr>'
            for number in range(30)
        )
        self.load(
            f"""
            <div data-log-region>
              <span data-log-selected-count></span>
              <input type="checkbox" data-log-select-all>
              <button type="button" data-log-open-all aria-expanded="false">Every timing</button>
              <table><tbody>{rows}</tbody></table>
              <select data-log-page-size><option value="25" selected>25</option></select>
              <span data-log-page-range></span>
              <button type="button" data-log-page-previous>Previous</button>
              <button type="button" data-log-page-next>Next</button>
            </div>
            """
        )
        timings = self.page.locator("[data-log-timings]:visible")
        all_arrow = self.page.locator("[data-log-open-all]")

        all_arrow.click()
        self.assertEqual(timings.count(), 25)
        self.assertEqual(all_arrow.get_attribute("aria-expanded"), "true")
        self.page.click("[data-log-page-next]")
        self.assertEqual(timings.count(), 5)

        self.page.click('[data-row="27"] [data-log-open]')
        self.assertEqual(timings.count(), 4)
        self.assertEqual(all_arrow.get_attribute("aria-expanded"), "false")
        self.page.click('[data-row="27"] [data-log-open]')
        self.assertEqual(all_arrow.get_attribute("aria-expanded"), "true")

        all_arrow.click()
        self.assertEqual(timings.count(), 0)
        self.page.click("[data-log-page-previous]")
        self.assertEqual(timings.count(), 0)
        self.assertEqual(self.page.locator("[data-log-select-all]").is_checked(), False)


#
# Air in pixels above the first of the opened part's text and below its last,
# inside the band from the row above it to the row after.
#
AIR = """([above, opened, part]) => {
  const top = document.querySelector(above).querySelector('time, strong').getBoundingClientRect();
  const band = document.querySelector(opened).getBoundingClientRect();
  const parts = [...document.querySelector(opened).querySelectorAll(part)].map(e => e.getBoundingClientRect());
  const first = Math.min(...parts.map(r => r.top)), last = Math.max(...parts.map(r => r.bottom));
  return [first - (above === opened ? band.top : top.bottom), band.bottom - last];
}"""


class AnOpenedRowInABrowser(unittest.TestCase):
    """What a row opens sits with even air above and below it (26-11-19).

    The timings had 6.5 px above and 10.5 below, a certificate's detail 6.5
    and 14.5: the text sat high in its band. Measured with the app's own CSS.
    """

    def setUp(self) -> None:
        playwright = sync_playwright().start()
        self.addCleanup(playwright.stop)
        browser = playwright.chromium.launch()
        self.addCleanup(browser.close)
        self.page = browser.new_page()
        self.css = (STATIC_DIRECTORY / "app.css").read_text(encoding="utf-8")

    def assert_even(self, markup: str, above: str, opened: str, part: str) -> None:
        self.page.set_content(f"<style>{self.css}</style>{markup}")
        over, under = self.page.evaluate(AIR, [above, opened, part])
        self.assertLessEqual(abs(over - under), 1, (over, under))

    def test_a_request_s_timings(self) -> None:
        row = (
            "<tr id=a><td class=log-select><input type=checkbox></td><td class=log-open></td>"
            "<td><time>26-11-19 10:00:00</time></td><td>alpha</td></tr>"
        )
        timings = (
            "<tr class=log-timings id=t><td></td><td></td><td colspan=2>"
            "<div class=log-timing-line><span><em>Total</em>12 ms</span></div></td></tr>"
        )
        self.assert_even(
            f"<table class='node-table log-table'><tbody>{row}{timings}{row}</tbody></table>",
            "#a",
            "#t",
            ".log-timing-line span",
        )

    def test_a_certificate_s_detail(self) -> None:
        self.assert_even(
            "<table class='node-table registry-table'><tbody>"
            "<tr class='registry-row registry-open'><td><strong>www.example.com</strong></td></tr>"
            "<tr class=registry-detail id=d><td><div class=registry-detail-grid>"
            "<div><strong>Names</strong><span>www.example.com</span></div></div></td></tr>"
            "</tbody></table>",
            "#d",
            "#d",
            ".registry-detail-grid > div > *",
        )


if __name__ == "__main__":
    unittest.main()
