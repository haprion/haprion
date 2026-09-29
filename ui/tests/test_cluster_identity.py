from __future__ import annotations

import unittest
from pathlib import Path

from haproxy_ui import cluster_identity
from haproxy_ui.cluster_identity import ACCENT_COUNT, accent_class, accent_index

STYLESHEET = Path(__file__).resolve().parents[1] / "src/haproxy_ui/static/app.css"


class ClusterIdentityTests(unittest.TestCase):
    def tearDown(self) -> None:
        cluster_identity.read_in((), on=False)

    def test_colours_follow_the_listed_order_not_the_name(self) -> None:
        cluster_identity.read_in(("beta", "alpha"), on=True)

        self.assertEqual((accent_index("beta"), accent_index("alpha")), (0, 1))

    def test_six_clusters_get_six_different_colours(self) -> None:
        names = [f"c{index}" for index in range(ACCENT_COUNT)]
        cluster_identity.read_in(names, on=True)

        self.assertEqual([accent_index(name) for name in names], list(range(ACCENT_COUNT)))

    def test_more_clusters_than_colours_means_no_colours(self) -> None:
        cluster_identity.read_in([f"c{index}" for index in range(ACCENT_COUNT + 1)], on=True)

        self.assertIsNone(accent_index("c0"))
        self.assertFalse(cluster_identity.fits([f"c{index}" for index in range(ACCENT_COUNT + 1)]))
        self.assertTrue(cluster_identity.fits([f"c{index}" for index in range(ACCENT_COUNT)]))

    def test_off_and_unlisted_clusters_have_no_colour(self) -> None:
        cluster_identity.read_in(("alpha",), on=False)
        self.assertIsNone(accent_index("alpha"))

        cluster_identity.read_in(("alpha",), on=True)
        self.assertIsNone(accent_index("gone"))

    def test_the_template_class_is_empty_without_a_colour(self) -> None:
        self.assertEqual(accent_class(None), "")
        self.assertEqual(accent_class(0), "cluster-accent-0")

    def test_every_index_the_helper_can_return_has_a_tint(self) -> None:
        #
        # Every index carries a tint of its own, index 0 included. Widening
        # ACCENT_COUNT without adding the tint would silently hand the new
        # clusters an invisible rule.
        #
        stylesheet = STYLESHEET.read_text(encoding="utf-8")
        for index in range(ACCENT_COUNT):
            self.assertIn(f".cluster-accent-{index}::before", stylesheet)
            self.assertEqual(stylesheet.count(f"--accent-{index}:"), 2, "light and dark")

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
