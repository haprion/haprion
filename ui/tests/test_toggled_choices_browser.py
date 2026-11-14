"""Groups chosen by a click and let go by a second, in Chromium (26-11-14).

With blocklists, *Denied — groups* and *Reachable from — groups* grew, and a
plain click chose one group and dropped the rest: more than one took Ctrl. A
click now toggles the group it lands on. The empty choice stands for none,
so it goes when a group is chosen, and comes back when the last one goes -
unless addresses are written beside it, where it is hidden.
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

ORIGIN = "https://manager.example.com"
PAGE = """<!doctype html>
<script src="/object-form.js"></script>
<form method="post" class="preview-form">
  <select name="deny_from" multiple size="5">
    <option value="" selected>Nobody</option>
    <option value="office">office</option>
    <option value="spamhaus-drop">spamhaus-drop</option>
    <option value="vpn">vpn</option>
  </select>
  <textarea name="deny_ranges"></textarea>
  <select name="protocol"><option value="https" selected>https</option><option value="dns">dns</option></select>
  <select name="allow_from" multiple size="5">
    <option value="" selected>Everywhere</option>
    <option value="office">office</option>
    <option value="vpn">vpn</option>
  </select>
  <textarea name="allow_ranges"></textarea>
  <small data-open-note hidden>Reachable from everywhere.</small>
</form>"""


class InChromium(unittest.TestCase):
    """The form's script in Chromium, on a page of the fields it wires."""

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

    def page(self) -> Any:
        page = self.browser.new_page()
        self.addCleanup(page.close)
        page.route(f"{ORIGIN}/", lambda route: route.fulfill(content_type="text/html", body=PAGE))
        page.route(
            f"{ORIGIN}/object-form.js",
            lambda route: route.fulfill(
                content_type="text/javascript",
                body=(STATIC_DIRECTORY / "object-form.js").read_text(),
            ),
        )
        page.goto(f"{ORIGIN}/")
        return page

    def chosen(self, page: Any) -> list[str]:
        values: list[str] = page.evaluate(
            "() => Array.from(document.querySelector('select[name=deny_from]').selectedOptions)"
            ".map((o) => o.value)"
        )
        return values

    def click(self, page: Any, value: str) -> None:
        page.click(f"select[name=deny_from] option[value='{value}']")


class ClickingAGroup(InChromium):
    def test_clicks_add_groups_and_a_second_click_lets_one_go(self) -> None:
        page = self.page()

        self.click(page, "office")
        self.click(page, "spamhaus-drop")
        self.assertEqual(self.chosen(page), ["office", "spamhaus-drop"])

        self.click(page, "office")
        self.assertEqual(self.chosen(page), ["spamhaus-drop"])

    def test_letting_the_last_go_chooses_nobody_and_nobody_lets_all_go(self) -> None:
        page = self.page()
        self.click(page, "vpn")
        self.click(page, "vpn")
        self.assertEqual(self.chosen(page), [""])

        self.click(page, "office")
        self.click(page, "vpn")
        self.click(page, "")
        self.assertEqual(self.chosen(page), [""])

    def test_with_addresses_written_nothing_chosen_stays_nothing(self) -> None:
        page = self.page()
        page.fill("textarea[name=deny_ranges]", "198.51.100.0/24")
        self.click(page, "office")
        self.click(page, "office")
        self.assertEqual(self.chosen(page), [])


class ChoosingWithTheKeyboard(InChromium):
    """The empty choice stands alone however the choice was made (B513)."""

    def mixed(self, page: Any, name: str) -> bool:
        chosen: list[str] = page.evaluate(
            f"() => Array.from(document.querySelector('select[name={name}]').selectedOptions)"
            ".map((o) => o.value)"
        )
        return "" in chosen and len(chosen) > 1

    def test_shift_and_arrow_never_choose_nobody_beside_a_group(self) -> None:
        for keys in ("Shift+ArrowUp", "Shift+ArrowDown"):
            with self.subTest(keys=keys):
                page = self.page()
                self.click(page, "office")
                self.click(page, "vpn")
                for _ in range(5):
                    page.keyboard.press(keys)
                    self.assertFalse(self.mixed(page, "deny_from"), self.chosen(page))

    def test_reaching_nobody_with_the_keys_leaves_it_alone(self) -> None:
        page = self.page()
        self.click(page, "office")
        page.keyboard.press("Shift+ArrowDown")
        self.assertEqual(self.chosen(page), [""])

    def test_a_group_chosen_with_the_keys_over_nobody_lets_it_go(self) -> None:
        page = self.page()
        page.focus("select[name=deny_from]")
        page.keyboard.press("Shift+ArrowDown")
        self.assertEqual(self.chosen(page), ["office"])


class TheOpenWarning(InChromium):
    def shown(self, page: Any) -> bool:
        hidden: bool = page.evaluate("() => document.querySelector('[data-open-note]').hidden")
        return not hidden

    def test_it_shows_while_nothing_narrows_and_hides_when_something_does(self) -> None:
        page = self.page()
        self.assertTrue(self.shown(page))

        page.click("select[name=allow_from] option[value='office']")
        self.assertFalse(self.shown(page))
        page.click("select[name=allow_from] option[value='office']")
        self.assertTrue(self.shown(page), "the last group let go, and no address")

        page.fill("textarea[name=allow_ranges]", "198.51.100.0/24")
        self.assertFalse(self.shown(page))
        page.fill("textarea[name=allow_ranges]", "")
        self.assertTrue(self.shown(page))

    def test_the_form_carries_the_note_this_page_stands_in_for(self) -> None:
        form = (STATIC_DIRECTORY.parent / "templates" / "_object-form.html").read_text()
        self.assertIn('<small class="warning-text" data-open-note hidden><svg', form)
        self.assertIn("</svg>Reachable from everywhere.</small>", form)

    def test_a_dns_listener_has_its_own_sentence(self) -> None:
        page = self.page()
        page.select_option("select[name=protocol]", "dns")
        self.assertFalse(self.shown(page))
        page.select_option("select[name=protocol]", "https")
        self.assertTrue(self.shown(page))


if __name__ == "__main__":
    unittest.main()
