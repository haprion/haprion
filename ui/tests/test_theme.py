"""The theme the server renders, from a cookie the browser maintains.

The value is written by client-side script, so it is attacker controlled, and
it reaches an HTML attribute. It is matched against the themes that exist
rather than escaped and passed through - a rejected value has to fall back to
the default, not appear in the document.
"""

from __future__ import annotations

import unittest
from unittest import mock

from haprion_ui.views import THEME_COOKIE, selected_theme


def _request(cookies: dict[str, str]) -> mock.Mock:
    request = mock.Mock()
    request.cookies = cookies
    return request


class SelectedThemeTests(unittest.TestCase):
    def test_a_known_theme_is_rendered(self) -> None:
        self.assertEqual(selected_theme(_request({THEME_COOKIE: "dark"})), "dark")
        self.assertEqual(selected_theme(_request({THEME_COOKIE: "light"})), "light")

    def test_no_cookie_is_the_default_theme(self) -> None:
        self.assertEqual(selected_theme(_request({})), "light")

    def test_a_value_that_is_not_a_theme_never_reaches_the_document(self) -> None:
        #
        # The cookie lands in an attribute on <html>. Autoescaping would keep
        # these from breaking out of it, but a theme that does not exist is not
        # a theme, and the document should carry the default instead.
        #
        for value in ('" onload="alert(1)', "dark; light", "DARK", "", "../../etc"):
            with self.subTest(value=value):
                self.assertEqual(selected_theme(_request({THEME_COOKIE: value})), "light")
