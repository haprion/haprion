from __future__ import annotations

import unittest
from pathlib import Path

from haproxy_ui.cluster_identity import ACCENT_COUNT, accent_index

STYLESHEET = Path(__file__).resolve().parents[1] / "src/haproxy_ui/static/app.css"


class ClusterIdentityTests(unittest.TestCase):
    def test_accent_is_stable_and_separates_generic_cluster_names(self) -> None:
        self.assertEqual(accent_index("alpha"), accent_index("alpha"))
        self.assertNotEqual(accent_index("alpha"), accent_index("bravo"))

    def test_every_index_the_helper_can_return_has_a_tint(self) -> None:
        #
        # Every index carries a tint of its own, index 0 included. Widening
        # ACCENT_COUNT without adding the tint would silently hand the new
        # clusters an invisible rule.
        #
        stylesheet = STYLESHEET.read_text(encoding="utf-8")
        for index in range(ACCENT_COUNT):
            self.assertIn(f".cluster-accent-{index}::before", stylesheet)
            self.assertIn(f"--accent-{index}:", stylesheet)

    def test_the_tints_spend_no_colour_the_status_palette_needs(self) -> None:
        #
        # The tints are cluster identity, never operational meaning. Green,
        # amber, blue and red already state something here, and a marker that
        # borrowed one of those tokens would say it a second time by accident.
        #
        stylesheet = STYLESHEET.read_text(encoding="utf-8")
        markers = [line for line in stylesheet.splitlines() if ".cluster-accent-" in line]

        self.assertTrue(markers)
        for marker in markers:
            self.assertRegex(marker, r"var\(--accent-\d\)")
            for token in ("--healthy", "--warning", "--critical", "--info", "--brand"):
                self.assertNotIn(token, marker)
