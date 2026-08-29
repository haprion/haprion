"""One configured cluster is a supported installation, not a degenerate case.

Most environments start with a single cluster, and the plan's own first
installation ran that way for weeks. Every page therefore has to render from one
cluster's readings without a second one to compare against - a grid that assumes
a pair, a counter that divides by the cluster count, or a comparison against
"the other" node would all pass unnoticed on the two-cluster fixture.
"""

from __future__ import annotations

import unittest
from dataclasses import replace
from typing import Any
from unittest import mock

from haproxy_ui import demo
from tests.test_login import LoginTestCase, configuration

ONLY = demo.CLUSTERS[0]
OTHER = demo.CLUSTERS[1]
PAGES = ("/", "/proxies", "/certificates", "/history", "/backups", "/activity")


def only_first(rows: tuple[Any, ...]) -> list[Any]:
    return [row for row in rows if row.cluster == ONLY]


class OneConfiguredCluster(LoginTestCase):
    def setUp(self) -> None:
        super().setUp()
        readers = {
            "cluster_statuses": demo.status_rows(),
            "cluster_inventories": demo.inventory_rows(),
            "cluster_histories": demo.history_rows(),
            "cluster_certificates": demo.certificate_rows(),
            "cluster_backups": demo.backup_rows(),
        }
        for name, rows in readers.items():
            patch = mock.patch(f"haproxy_ui.db.{name}", return_value=only_first(rows))
            patch.start()
            self.addCleanup(patch.stop)

    def signed_in_client(self) -> Any:
        client = self.client(replace(configuration(), clusters=(ONLY,)))
        self.sign_in(client)
        return client

    def test_every_page_renders_from_one_cluster(self) -> None:
        client = self.signed_in_client()
        for page in PAGES:
            with self.subTest(page=page):
                response = client.get(page)
                self.assertEqual(response.status_code, 200)
                self.assertIn(ONLY, response.text)

    def test_no_page_invents_the_cluster_that_is_not_configured(self) -> None:
        #
        # The reader returns rows for one cluster only, so a second name on the
        # page could only come from the interface itself - a placeholder, a
        # hard-coded pair, or a fixture leaking into the database path.
        #
        client = self.signed_in_client()
        for page in PAGES:
            with self.subTest(page=page):
                self.assertNotIn(OTHER, client.get(page).text)


if __name__ == "__main__":
    unittest.main()
