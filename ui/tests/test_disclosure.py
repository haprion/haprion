"""One way to fold a section open, on every page.

A section that opens - a form group, the archive list, the stored YAML, a
row editor - carries the framed `.disclosure-toggle` in its summary. Each page
used to draw its own: a native triangle, a thin arrow beside "Edit", a "+"
that turned into a "-". Read in the template source rather than a rendered
page, because most of these only render with data a fixture would have to
invent, and a new `details` is exactly what this has to catch.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

TEMPLATES = Path(__file__).resolve().parents[1] / "src" / "haprion_ui" / "templates"

#
# The `details` elements that are not a section folding open: a menu, a
# warning badge with a popover, and the job's diagnostics button. Each has a
# shape of its own on purpose.
#
NOT_A_SECTION = {"account-menu", "log-warning", "job-diagnostics"}

DETAILS = re.compile(r'<details class="([^"]+)"[^>]*>\s*<summary[^>]*>(.*?)</summary>', re.S)


class EverySectionFoldsTheSameWay(unittest.TestCase):
    def test_every_section_summary_carries_the_framed_toggle(self) -> None:
        seen = 0
        for template in sorted(TEMPLATES.glob("*.html")):
            for classes, summary in DETAILS.findall(template.read_text()):
                if NOT_A_SECTION & set(classes.split()):
                    continue
                seen += 1
                with self.subTest(template=template.name, details=classes):
                    self.assertIn('class="disclosure-toggle"', summary)
        #
        # The form groups, archives, stored YAML, three Network editors and the
        # backup schedule at the time of writing; a pattern that stopped
        # matching would otherwise pass by finding nothing.
        #
        self.assertGreaterEqual(seen, 7)

    def test_no_stylesheet_draws_its_own_marker(self) -> None:
        css = (TEMPLATES.parent / "static" / "app.css").read_text()
        self.assertNotIn(".editor-add > summary::before", css)
        self.assertNotIn(".schedule-edit::before", css)


if __name__ == "__main__":
    unittest.main()
