"""Cards drawn in a loop stand in a `cluster-list`, which spaces them.

A `cluster-card` has no margin of its own: the space between two is the list's
gap (`.cluster-list { gap: 26px }`). *Add to all proxies* drew its clusters'
cards straight into the page in 1.1.0, edge to edge (26-11-14); every other
page wrapped them. The WAF page's finding cards space themselves
(`.finding-card + .finding-card`) and are the one exception.
"""

from __future__ import annotations

import re
import unittest

from haprion_ui.templates import STATIC_DIRECTORY

TEMPLATE_DIRECTORY = STATIC_DIRECTORY.parent / "templates"

LOOPED = re.compile(r'\{%-?\s*for [^%]*%\}\s*<(?:section|article) class="cluster-card([^"]*)"')
OPENED = re.compile(r'<div class="cluster-list[ "]')


class CardsInALoopStandInAList(unittest.TestCase):
    def test_each_looped_card_is_inside_a_cluster_list(self) -> None:
        templates = sorted(TEMPLATE_DIRECTORY.glob("*.html"))
        self.assertTrue(templates, TEMPLATE_DIRECTORY)
        loose = []
        for template in templates:
            text = template.read_text()
            for found in LOOPED.finditer(text):
                if "finding-card" in found.group(1).split():
                    continue
                before = text[: found.start()]
                opened = len(OPENED.findall(before))
                if opened == 0 or before.rfind("</div>") > before.rfind('<div class="cluster-list'):
                    loose.append(f"{template.name}:{text.count(chr(10), 0, found.start()) + 1}")
        self.assertEqual(loose, [], 'wrap the loop in <div class="cluster-list">')


if __name__ == "__main__":
    unittest.main()
