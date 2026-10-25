"""The check every rendered page passes through (`tests/__init__.py`)."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

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


class NoPageSendsAReaderToADocumentThatIsGone(unittest.TestCase):
    """The pages named "the installation guide, 1.4.5", a document and a
    numbering that no longer exist (review 26-10-24, 16-04). A page names the
    manual's section by its heading, which the manual must have.
    """

    def test_no_template_names_the_old_guide_or_its_numbers(self) -> None:
        templates = Path(__file__).resolve().parents[1] / "src/haprion_ui/templates"
        found = [
            path.name
            for path in sorted(templates.glob("*.html"))
            if re.search(r"installation guide|INSTALLATION|\b1\.4\.\d", path.read_text())
        ]
        self.assertEqual(found, [])

    def test_a_section_a_page_names_is_a_heading_in_the_manual(self) -> None:
        root = Path(__file__).resolve().parents[2]
        headings = {
            line.lstrip("#").strip()
            for line in (root / "docs/user-manual.md").read_text().splitlines()
            if line.startswith("#")
        }
        for path in sorted((root / "ui/src/haprion_ui/templates").glob("*.html")):
            for named in re.findall(r"<em>([^<]+)</em> in the user manual", path.read_text()):
                with self.subTest(page=path.name):
                    self.assertIn(named, headings)
