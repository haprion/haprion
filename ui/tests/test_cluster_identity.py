from __future__ import annotations

import unittest
from pathlib import Path

from haproxy_ui.cluster_identity import ACCENT_COUNT, accent_index

STYLESHEET = Path(__file__).resolve().parents[1] / "src/haproxy_ui/static/app.css"


class ClusterIdentityTests(unittest.TestCase):
    def test_accent_is_stable_and_separates_generic_cluster_names(self) -> None:
        self.assertEqual(accent_index("alpha"), accent_index("alpha"))
        self.assertNotEqual(accent_index("alpha"), accent_index("bravo"))

    def test_every_index_the_helper_can_return_has_a_marker(self) -> None:
        #
        # Index 0 is the plain rule and needs no rule of its own. Widening
        # ACCENT_COUNT without adding the shape would silently give the new
        # clusters the same marker as the first one.
        #
        stylesheet = STYLESHEET.read_text(encoding="utf-8")
        for index in range(1, ACCENT_COUNT):
            self.assertIn(f".cluster-accent-{index}::before", stylesheet)

    def test_the_marker_spends_no_colour_the_status_palette_needs(self) -> None:
        #
        # Clusters are told apart by the shape of the left rule, in one neutral
        # ink. A marker that used a hue would have to be defended against green,
        # amber, blue and red meaning something - which is what four attempts at
        # a colour pair kept running into.
        #
        stylesheet = STYLESHEET.read_text(encoding="utf-8")
        markers = [line for line in stylesheet.splitlines() if ".cluster-accent-" in line]

        self.assertTrue(markers)
        for marker in markers:
            self.assertIn("var(--cluster-mark)", marker)
            for token in ("--healthy", "--warning", "--critical", "--info", "--brand"):
                self.assertNotIn(token, marker)
