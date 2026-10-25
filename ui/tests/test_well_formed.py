"""The check every rendered page passes through (`tests/__init__.py`)."""

from __future__ import annotations

import unittest

from tests import well_formed


class WhatTheCheckFinds(unittest.TestCase):
    def test_a_page_that_closes_what_it_opens(self) -> None:
        self.assertEqual(
            well_formed.problems('<div><p>a<br>b</p><input name="x"><svg><path d=""/></svg></div>'),
            [],
        )

    def test_an_element_left_open_inside_a_cell(self) -> None:
        found = well_formed.problems("<table><tr><td><div><div>x</div></td></tr></table>")
        self.assertEqual(found, ["line 1: </td> where </div> (opened on line 1) was due"])

    def test_one_never_closed(self) -> None:
        self.assertEqual(
            well_formed.problems("<main><div>"),
            [
                "<main> opened on line 1 is never closed",
                "<div> opened on line 1 is never closed",
            ],
        )

    def test_a_stray_end_tag(self) -> None:
        self.assertEqual(well_formed.problems("</span>"), ["line 1: </span> where nothing was due"])


if __name__ == "__main__":
    unittest.main()
