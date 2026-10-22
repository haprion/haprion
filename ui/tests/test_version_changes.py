"""What one version changed: the kept diff, its page, and the dialog on Versions (B220)."""

from __future__ import annotations

import os
import unittest
from dataclasses import replace
from typing import Any, ClassVar
from unittest import mock

from haprion_ui import version_changes
from haprion_ui.views import STATIC_DIRECTORY
from tests.test_history import reading
from tests.test_login import LoginTestCase, configuration

if not os.environ.get("PLAYWRIGHT_BROWSERS_PATH"):
    raise RuntimeError(
        "set PLAYWRIGHT_BROWSERS_PATH to the directory holding the Playwright browsers"
    )

from playwright.sync_api import sync_playwright  # noqa: E402

VERSIONS: list[dict[str, object]] = [
    {
        "version": number,
        "hash": f"{number:040d}",
        "created_at": "2026-08-28T14:02:11+00:00",
        "comment": f"Update proxy objects: Change {number}",
        "current": number == 2,
    }
    for number in (2, 1)
]
DIFF = {
    "commit": f"{2:040d}",
    "parent": f"{1:040d}",
    "truncated": False,
    "files": [
        {
            "path": "managed/objects/app.yaml",
            "status": "modified",
            "old_path": None,
            "added": 1,
            "removed": 1,
            "binary": False,
            "lines": ["@@ -1,2 +1,2 @@", " name: app", "-port: 80", "+port: 8080"],
        },
        {
            "path": "managed/manifest.json",
            "status": "modified",
            "old_path": None,
            "added": 2,
            "removed": 2,
            "binary": False,
            "lines": [
                "@@ -1 +1 @@",
                '-  "fingerprint": "sha256:aa"',
                '+  "fingerprint": "sha256:bb"',
            ],
        },
        {
            "path": "big.cfg",
            "status": "modified",
            "old_path": None,
            "added": 9000,
            "removed": 0,
            "binary": False,
            "lines": [],
        },
    ],
}


class TheLines(unittest.TestCase):
    def test_each_line_is_marked_by_kind_and_the_counts_are_added_up(self) -> None:
        shown = version_changes.build(DIFF)
        if shown is None:
            self.fail("a kept diff builds a view")
        self.assertEqual(
            [kind for kind, _line in shown.files[0].lines], ["hunk", "ctx", "del", "add"]
        )
        self.assertEqual((shown.added, shown.removed), (9001, 1))
        self.assertTrue(shown.files[1].left_out, "counted, its lines not kept")
        self.assertNotIn(
            "managed/manifest.json",
            [item.path for item in shown.files],
            "bookkeeping, not configuration",
        )
        self.assertIsNone(version_changes.build(None), "not fetched yet")


class ThePage(LoginTestCase):
    def page(self, path: str, *, kept: Any = DIFF) -> Any:
        with (
            mock.patch(
                "haprion_ui.db.cluster_histories",
                return_value=[reading(versions=VERSIONS, published=2)],
            ),
            mock.patch("haprion_ui.db.read_version_diff", return_value=kept) as read,
        ):
            client = self.client(
                replace(configuration(), clusters=("alpha",), management_writes=True)
            )
            self.sign_in(client)
            return client.get(path), read

    def test_the_version_s_changes_are_drawn_with_its_own_words(self) -> None:
        response, read = self.page(f"/history/alpha/versions/{2:040d}")
        self.assertEqual(response.status_code, 200)
        read.assert_called_once()
        text = response.text
        self.assertIn("data-version-changes-body", text)
        self.assertIn(
            '<span class="diff-del">-port: 80</span><span class="diff-add">+port: 8080</span>', text
        )
        self.assertIn('<span class="version-comment">Change 2</span>', text)
        self.assertIn("Too large to keep with the version", text)

    def test_a_diff_not_fetched_yet_says_so(self) -> None:
        response, _ = self.page(f"/history/alpha/versions/{2:040d}", kept=None)
        self.assertIn("Not fetched yet", response.text)

    def test_only_a_listed_version_of_a_shown_cluster(self) -> None:
        for path in (
            f"/history/alpha/versions/{3:040d}",
            f"/history/beta/versions/{2:040d}",
            "/history/alpha/versions/HEAD",
        ):
            with self.subTest(path=path):
                response, read = self.page(path)
                self.assertEqual(response.status_code, 404)
                read.assert_not_called()

    def test_a_reader_is_shown_neither_the_changes_nor_the_button(self) -> None:
        """Review 26-10-22, 5-3: the difference carries the objects' documents and the
        generated configuration - backend addresses, an advanced text's passwords - which
        the object page keeps from a reader (B68, B221)."""

        self.account = replace(self.account, role="reader")
        response, read = self.page(f"/history/alpha/versions/{2:040d}")
        self.assertEqual(response.status_code, 403)
        self.assertIn("Administrators only", response.text)
        read.assert_not_called()

        response, _ = self.page("/history")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("data-version-changes", response.text)

    def test_every_row_has_changes_left_of_publish(self) -> None:
        response, _ = self.page("/history")
        self.assertIn(
            f'<a class="secondary-button" href="/history/alpha/versions/{1:040d}" '
            'data-version-changes>Diff</a><form method="post" action="/operations" ',
            response.text,
        )


class TheDialog(LoginTestCase):
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

    def test_changes_opens_in_a_dialog_and_escape_closes_it(self) -> None:
        with (
            mock.patch(
                "haprion_ui.db.cluster_histories",
                return_value=[reading(versions=VERSIONS, published=2)],
            ),
            mock.patch("haprion_ui.db.read_version_diff", return_value=DIFF),
        ):
            client = self.client(replace(configuration(), clusters=("alpha",)))
            self.sign_in(client)
            versions = client.get("/history").text
            changes = client.get(f"/history/alpha/versions/{2:040d}").text

        page = self.browser.new_page()
        self.addCleanup(page.close)
        origin = "https://manager.example.com"
        page.route(
            f"{origin}/history",
            lambda route: route.fulfill(body=versions, content_type="text/html"),
        )
        page.route(
            f"{origin}/history/alpha/versions/*",
            lambda route: route.fulfill(body=changes, content_type="text/html"),
        )
        page.route(f"{origin}/static/**", lambda route: route.fulfill(body=""))
        page.goto(f"{origin}/history")
        page.add_script_tag(path=str(STATIC_DIRECTORY / "versions.js"))

        page.click(f'a[href="/history/alpha/versions/{2:040d}"]')
        page.wait_for_selector("dialog[open] [data-version-changes-body]")
        self.assertIn("+port: 8080", page.inner_text("dialog[open] .diff-lines"))
        self.assertEqual(page.url, f"{origin}/history", "the list stays where it was")

        page.keyboard.press("Escape")
        page.wait_for_selector("dialog[open]", state="detached")
        self.assertFalse(page.evaluate("document.querySelector('dialog').open"))


if __name__ == "__main__":
    unittest.main()
