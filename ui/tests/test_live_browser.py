"""live.js carries typed values to the same form across a redraw (review 2026-09-28 F04)."""

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


def schedule_form(cluster: str, retention: int, token: str) -> str:
    return (
        '<form method="post" action="/operations">'
        f'<input type="hidden" name="csrf_token" value="{token}">'
        f'<input type="hidden" name="idempotency_key" value="{token}-{cluster}">'
        '<input type="hidden" name="operation" value="backup_schedule">'
        f'<input type="hidden" name="cluster" value="{cluster}">'
        f'<input name="backup_retention" value="{retention}">'
        "</form>"
    )


def page(*forms: str) -> str:
    return "<!doctype html><title>Node backups</title><main>" + "".join(forms) + "</main>"


class TypedValuesStayWithTheirForm(unittest.TestCase):
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

    def redrawn(self, first: str, second: str, typing: dict[str, str]) -> dict[str, str]:
        """Each cluster's retention after typing into `first` and redrawing into `second`."""

        context = self.browser.new_context()
        self.addCleanup(context.close)
        tab = context.new_page()
        served = iter((first, second))
        tab.route(
            f"{ORIGIN}/backups",
            lambda route: route.fulfill(content_type="text/html", body=next(served)),
        )
        tab.goto(f"{ORIGIN}/backups")
        tab.add_script_tag(path=str(STATIC_DIRECTORY / "live.js"))
        for cluster, value in typing.items():
            field = tab.locator(
                f'form:has(input[name=cluster][value="{cluster}"]) input[name=backup_retention]'
            )
            field.fill(value)
        tab.evaluate("document.activeElement && document.activeElement.blur()")
        tab.evaluate("() => { window.haproxyUi.redraw(); }")
        tab.wait_for_function(
            f"document.querySelectorAll('main form').length === {second.count('<form')}"
        )
        values: dict[str, str] = tab.evaluate(
            """() => Object.fromEntries(Array.from(document.querySelectorAll('main form'), (form) => [
                form.querySelector('input[name=cluster]').value,
                form.querySelector('input[name=backup_retention]').value,
            ]))"""
        )
        return values

    def test_a_form_that_returns_ahead_of_it_does_not_take_the_value(self) -> None:
        """The review's reproduction: alpha's job finishes while beta is being edited."""

        values = self.redrawn(
            page(schedule_form("beta", 14, "t1"), schedule_form("gamma", 14, "t1")),
            page(
                schedule_form("alpha", 14, "t2"),
                schedule_form("beta", 14, "t2"),
                schedule_form("gamma", 14, "t2"),
            ),
            {"beta": "42"},
        )

        self.assertEqual(values, {"alpha": "14", "beta": "42", "gamma": "14"})

    def test_a_form_that_leaves_takes_its_value_with_it(self) -> None:
        values = self.redrawn(
            page(schedule_form("alpha", 14, "t1"), schedule_form("beta", 14, "t1")),
            page(schedule_form("beta", 14, "t2")),
            {"alpha": "42"},
        )

        self.assertEqual(values, {"beta": "14"})

    def test_forms_that_change_order_keep_their_own_values(self) -> None:
        values = self.redrawn(
            page(schedule_form("alpha", 14, "t1"), schedule_form("beta", 14, "t1")),
            page(schedule_form("beta", 14, "t2"), schedule_form("alpha", 14, "t2")),
            {"alpha": "30", "beta": "7"},
        )

        self.assertEqual(values, {"alpha": "30", "beta": "7"})


def dialog_page(drawn: str) -> str:
    return (
        "<!doctype html><title>Dashboard</title><main>"
        f'<p id="drawn">{drawn}</p>'
        '<button type="button" data-open-dialog="publish-alpha">Publish &amp; deploy</button>'
        '<dialog id="publish-alpha"><form method="post" action="/history/alpha/publish">'
        '<input name="comment"><button type="button" data-close-dialog>Close</button>'
        "</form></dialog></main>"
    )


class AnOpenDialogHoldsTheRedraw(unittest.TestCase):
    """The dashboard's Publish & deploy dialog survives the page keeping itself current (B257)."""

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

    def test_the_swap_waits_until_the_dialog_is_closed(self) -> None:
        context = self.browser.new_context()
        self.addCleanup(context.close)
        tab = context.new_page()
        served = iter((dialog_page("first"), dialog_page("second"), dialog_page("third")))
        tab.route(
            f"{ORIGIN}/",
            lambda route: route.fulfill(content_type="text/html", body=next(served)),
        )
        tab.goto(f"{ORIGIN}/")
        tab.add_script_tag(path=str(STATIC_DIRECTORY / "live.js"))
        tab.add_script_tag(path=str(STATIC_DIRECTORY / "dialogs.js"))

        tab.click("[data-open-dialog]")
        self.assertTrue(tab.evaluate("document.getElementById('publish-alpha').open"))
        tab.fill("input[name=comment]", "Move the shop")
        tab.evaluate("document.activeElement.blur()")
        tab.evaluate("() => { window.haproxyUi.redraw(); }")
        tab.wait_for_timeout(2500)

        self.assertEqual(tab.text_content("#drawn"), "first")
        self.assertTrue(tab.evaluate("document.getElementById('publish-alpha').open"))
        self.assertEqual(tab.input_value("input[name=comment]"), "Move the shop")

        tab.click("[data-close-dialog]")
        tab.wait_for_function("document.getElementById('drawn').textContent === 'second'")
        #
        # The buttons drawn by the swap are new ones, and open their dialog too.
        #
        tab.click("[data-open-dialog]")
        self.assertTrue(tab.evaluate("document.getElementById('publish-alpha').open"))

    def test_an_answer_that_arrives_after_the_reader_began_is_not_swapped_in(self) -> None:
        """Review 2026-10-20, U1: settled before the request, typing when it answered."""

        context = self.browser.new_context()
        self.addCleanup(context.close)
        tab = context.new_page()
        held: list[Any] = []
        served = iter((dialog_page("first"), dialog_page("third")))
        asking = False

        def answer(route: Any) -> None:
            if asking and not held:
                held.append(route)
                return
            route.fulfill(content_type="text/html", body=next(served))

        tab.route(f"{ORIGIN}/", answer)
        tab.goto(f"{ORIGIN}/")
        tab.add_script_tag(path=str(STATIC_DIRECTORY / "live.js"))
        tab.add_script_tag(path=str(STATIC_DIRECTORY / "dialogs.js"))

        asking = True
        tab.evaluate("() => { window.haproxyUi.redraw(); }")
        while not held:
            tab.wait_for_timeout(20)
        tab.click("[data-open-dialog]")
        tab.fill("input[name=comment]", "Move the shop")
        held[0].fulfill(content_type="text/html", body=dialog_page("second"))
        tab.wait_for_timeout(1500)

        self.assertEqual(tab.text_content("#drawn"), "first")
        self.assertTrue(tab.evaluate("document.getElementById('publish-alpha').open"))
        self.assertEqual(tab.evaluate("document.activeElement.name"), "comment")

        tab.click("[data-close-dialog]")
        tab.evaluate("document.activeElement.blur()")
        tab.wait_for_function("document.getElementById('drawn').textContent === 'third'")


class APageThatAnswersAFormKeepsStill(unittest.TestCase):
    """26-10-14: a receiver's password page, answered at the form's address, asked for
    itself again; the GET was refused, the reload sent the form a second time."""

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

    def asked(self, answered: bool) -> int:
        """How often the page's address was asked for within three live intervals."""

        context = self.browser.new_context()
        self.addCleanup(context.close)
        tab = context.new_page()
        marker = " data-answered" if answered else ""
        body = (
            f"<!doctype html><html{marker}><head><title>Receivers</title>"
            '<meta name="haproxy-live" content="1">'
            '<script src="/static/live.js"></script></head>'
            "<body><main><p>Password for 192.0.2.9</p></main></body></html>"
        )
        requests: list[str] = []

        def answer(route: Any) -> None:
            requests.append(route.request.method)
            route.fulfill(content_type="text/html", body=body)

        tab.route(f"{ORIGIN}/certificates/receivers/secret", answer)
        tab.route(
            f"{ORIGIN}/static/live.js",
            lambda route: route.fulfill(
                content_type="text/javascript",
                body=(STATIC_DIRECTORY / "live.js").read_text(),
            ),
        )
        tab.goto(f"{ORIGIN}/certificates/receivers/secret")
        tab.wait_for_timeout(3500)
        return len(requests)

    def test_an_answer_to_a_form_is_not_asked_for_again(self) -> None:
        self.assertEqual(self.asked(answered=True), 1)

    def test_a_page_that_was_asked_for_keeps_itself_current(self) -> None:
        self.assertGreater(self.asked(answered=False), 1)


if __name__ == "__main__":
    unittest.main()
