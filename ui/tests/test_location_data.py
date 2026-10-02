"""The Settings card for country lists (Fas 21, B228)."""

from __future__ import annotations

import unittest
from types import SimpleNamespace

from haproxy_ui.location_data import card


def row(cluster: str, geo: object) -> SimpleNamespace:
    return SimpleNamespace(cluster=cluster, result={"objects": [], "geo": geo})


class TheCardSaysWhichClustersAreDue(unittest.TestCase):
    def test_a_cluster_published_with_older_data_is_due(self) -> None:
        shown = card(
            [
                row("beta", {"database": "2026-10-01", "published": "2026-10-01"}),
                row("alpha", {"database": "2026-10-01", "published": "2026-09-14"}),
                row("gamma", {"database": "2026-10-01", "published": None}),
            ]
        )

        self.assertIsNotNone(shown)
        assert shown is not None  # noqa: S101 - narrows the type for mypy
        self.assertEqual(shown.database, "26-10-01")
        self.assertEqual(
            [(r.cluster, r.published, r.current) for r in shown.rows],
            [("alpha", "26-09-14", False), ("beta", "26-10-01", True)],
        )

    def test_no_country_anywhere_is_no_card(self) -> None:
        self.assertIsNone(card([row("alpha", {"database": "2026-10-01", "published": None})]))
        self.assertIsNone(card([SimpleNamespace(cluster="alpha", result=None)]))

    def test_an_unreadable_database_leaves_the_dates_unjudged(self) -> None:
        shown = card([row("alpha", {"database": None, "published": "2026-09-14"})])

        self.assertIsNotNone(shown)
        assert shown is not None  # noqa: S101 - narrows the type for mypy
        self.assertEqual(shown.database, "")
        self.assertTrue(shown.rows[0].current)
