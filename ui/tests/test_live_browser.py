"""live.js carries typed values to the same form across a redraw (review 2026-09-28 F04)."""

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
            field = tab.locator(f'form:has(input[name=cluster][value="{cluster}"]) input[name=backup_retention]')
            field.fill(value)
        tab.evaluate("document.activeElement && document.activeElement.blur()")
        tab.evaluate("() => { window.haproxyUi.redraw(); }")
        tab.wait_for_function(f"document.querySelectorAll('main form').length === {second.count('<form')}")
        return tab.evaluate(
            """() => Object.fromEntries(Array.from(document.querySelectorAll('main form'), (form) => [
                form.querySelector('input[name=cluster]').value,
                form.querySelector('input[name=backup_retention]').value,
            ]))"""
        )

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


if __name__ == "__main__":
    unittest.main()
