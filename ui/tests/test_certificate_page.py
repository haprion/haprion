"""The certificates page as HTTP: two views, one switch, and one expanded row.

The read model is tested next door; this is about what the page actually
renders, because C5's two views are a routing decision as much as a layout one.
Switching is a link rather than script: the page is read-only, both views are
renderings of cached readings, and a link is something an operator can send to
somebody else.
"""

from __future__ import annotations

import unittest
from dataclasses import replace
from unittest import mock

from tests.test_certificates import (
    node,
    registered,
    with_registry,
)
from tests.test_certificates import (
    reading as certificate_reading,
)
from tests.test_certificates import (
    status as status_reading,
)
from tests.test_login import LoginTestCase, configuration


class TheCertificatePageHasTwoViews(LoginTestCase):
    def setUp(self) -> None:
        super().setUp()
        rows = mock.patch(
            "haproxy_ui.db.cluster_certificates",
            return_value=[
                with_registry(
                    certificate_reading(),
                    registered(fingerprint="a" * 64),
                    registered(
                        "lb-01.example.net",
                        clusters=(),
                        receivers=(
                            {
                                "id": "lb-01",
                                "published_at": "2026-08-01T00:00:00Z",
                                "current": True,
                            },
                        ),
                    ),
                    receivers=("lb-01",),
                )
            ],
        )
        rows.start()
        self.addCleanup(rows.stop)
        statuses = mock.patch(
            "haproxy_ui.db.cluster_statuses",
            return_value=[status_reading(node(("example.com", "a" * 64)))],
        )
        statuses.start()
        self.addCleanup(statuses.stop)

    def page(self, query: str = "") -> str:
        client = self.client(replace(configuration(), clusters=("alpha",)))
        self.sign_in(client)
        response = client.get(f"/certificates{query}")
        self.assertEqual(response.status_code, 200)
        return response.text

    def test_the_cluster_cards_stay_the_default_view(self) -> None:
        #
        # Anyone who already has this URL bookmarked gets the page they know.
        # A new default would be a silent change to something people navigate
        # by muscle memory.
        #
        page = self.page()

        self.assertIn("referenced by this cluster", page)
        self.assertNotIn("Certificate registry", page)

    def test_the_registry_view_is_reached_by_a_link_and_names_both_kinds(self) -> None:
        page = self.page("?view=registry")

        self.assertIn("Certificate registry", page)
        self.assertIn("Used by", page)
        self.assertIn("lb-01", page)
        self.assertIn("target-kind", page)
        #
        # The mockup's claim. A receiver reports nothing back, so no rendering
        # of this page may say a certificate is on one.
        #
        self.assertNotIn("On all targets", page)

    def test_a_row_expands_in_place_and_the_link_then_closes_it(self) -> None:
        opened = self.page("?view=registry&open=lb-01.example.net")

        self.assertIn("registry-detail", opened)
        self.assertIn("Published to", opened)
        #
        # The open row's own link drops the parameter, so the control that
        # opened it is the control that closes it.
        #
        self.assertIn('href="?view=registry"', opened)
        self.assertNotIn("registry-detail", self.page("?view=registry"))

    def test_an_unknown_view_falls_back_rather_than_failing(self) -> None:
        self.assertIn("referenced by this cluster", self.page("?view=nonsense"))


class WithoutARegistryThePageIsWhatItWas(LoginTestCase):
    """No registry declared, no switch drawn, and no empty second view."""

    def setUp(self) -> None:
        super().setUp()
        rows = mock.patch(
            "haproxy_ui.db.cluster_certificates", return_value=[certificate_reading()]
        )
        rows.start()
        self.addCleanup(rows.stop)

    def page(self, query: str = "") -> str:
        client = self.client(replace(configuration(), clusters=("alpha",)))
        self.sign_in(client)
        return client.get(f"/certificates{query}").text

    def test_no_switch_is_drawn(self) -> None:
        self.assertNotIn("certificate-views", self.page())

    def test_asking_for_the_registry_view_still_renders_the_cards(self) -> None:
        page = self.page("?view=registry")

        self.assertNotIn("Certificate registry", page)
        self.assertIn("referenced by this cluster", page)


if __name__ == "__main__":
    unittest.main()
