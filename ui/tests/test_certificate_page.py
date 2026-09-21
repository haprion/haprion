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

    def test_the_registry_is_the_default_view(self) -> None:
        #
        # The complete list, and the one the certificate actions return to
        # (2026-09-15). The cluster cards are one link away and keep their URL.
        #
        page = self.page()

        self.assertIn("Certificate registry", page)
        self.assertNotIn("referenced by this cluster", page)
        self.assertIn("referenced by this cluster", self.page("?view=clusters"))

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
        self.assertNotIn("certificate-cluster-card cluster-accent-", page)

    def test_only_actual_cluster_cards_have_a_cluster_accent(self) -> None:
        self.assertIn("certificate-cluster-card cluster-accent-", self.page("?view=clusters"))
        self.assertNotIn("certificate-cluster-card cluster-accent-", self.page("?view=registry"))

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

    def test_a_cluster_row_opens_the_same_detail_and_the_whole_row_is_the_control(
        self,
    ) -> None:
        #
        # Asked for on 2026-09-12: the detail on the cluster view too, and
        # opened by clicking anywhere on the row rather than only the name.
        # The row carries the address for the script; the name stays a link.
        #
        page = self.page("?view=clusters&open=example.com")

        self.assertIn("registry-detail", page)
        self.assertIn("<strong>Issuer</strong>", page)
        self.assertIn('class="registry-row registry-open" data-href="?view=clusters"', page)
        closed = self.page("?view=clusters")
        self.assertNotIn("registry-detail", closed)
        self.assertIn('data-href="?view=clusters&amp;open=example.com"', closed)
        #
        # The issuer left the row for the detail: the seven columns did not
        # fit a 1920-wide screen at the maintainer's zoom with it there.
        #
        self.assertNotIn('class="certificate-issuer" title=', closed)

    def test_an_unknown_view_falls_back_rather_than_failing(self) -> None:
        self.assertIn("Certificate registry", self.page("?view=nonsense"))

    def test_the_switch_is_pinned_named_and_swapped_in_place(self) -> None:
        #
        # Three things the maintainer asked for on 2026-09-12, having seen the
        # page: the second view is called what it shows, the switch stays put
        # while the registry scrolls under it - Traffic's own pinned bar - and
        # a click swaps the view rather than reloading the page around it.
        #
        page = self.page("?view=registry")

        self.assertIn("Certificates on clusters", page)
        #
        # The count is certificates on clusters, not clusters: one cluster is
        # configured and it references one certificate, so both would read 1
        # here - the model test tells them apart.
        #
        self.assertIn("Certificates on clusters <b>1</b>", page)
        self.assertNotIn(">Clusters <b>", page)
        self.assertIn(
            '<div class="page-ranges-sticky certificate-strip">'
            '<nav class="traffic-ranges page-ranges certificate-views"',
            page,
        )
        self.assertIn("certificates.js", page)
        self.assertEqual(page.count("data-certificates-region"), 1)
        #
        # The bold width is reserved from the label, so a segment cannot grow
        # when it becomes current. Every segment carries its label for that.
        #
        self.assertEqual(page.count('class="segment-reserve" aria-hidden="true"'), 2)

    def test_the_buttons_share_the_pinned_strip_rather_than_the_heading(self) -> None:
        #
        # Asked for on 2026-09-20: `New certificate` and the provider pages
        # kept scrolling off the top of a long registry. They sit in the same
        # pinned row as the switch now - one fixed row, not two - and the
        # heading keeps only the badges that say what kind of page this is.
        #
        client = self.client(replace(configuration(), clusters=("alpha",), management_writes=True))
        self.sign_in(client)
        page = client.get("/certificates?view=registry").text

        heading = page.split('<div class="heading-badges">', 1)[1].split("</div>", 1)[0]
        strip = page.split('<div class="page-ranges-sticky certificate-strip">', 1)[1]
        strip = strip.split("</nav>", 1)[1].split("</div></div>", 1)[0]
        self.assertNotIn("secondary-button", heading)
        self.assertTrue(strip.startswith('<div class="certificate-actions">'))
        for href in (
            "/dns-profiles",
            "/ndes-profiles",
            "/certificates/receivers",
            "/certificates/new",
        ):
            self.assertIn(f'<a class="secondary-button" href="{href}">', strip)
        self.assertEqual(page.count('class="secondary-button" href="/certificates/new"'), 1)

    def test_a_reader_gets_the_strip_without_buttons(self) -> None:
        page = self.page("?view=registry")

        self.assertIn('<div class="page-ranges-sticky certificate-strip">', page)
        self.assertNotIn("certificate-actions", page)
        self.assertNotIn("secondary-button", page.split("</section>", 1)[0])


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

    def test_the_provider_buttons_stay_in_the_heading(self) -> None:
        #
        # No registry, no strip to pin them in - and no `New certificate`,
        # because the engine would refuse the job.
        #
        client = self.client(replace(configuration(), clusters=("alpha",), management_writes=True))
        self.sign_in(client)
        page = client.get("/certificates").text

        heading = page.split('<div class="heading-badges">', 1)[1].split("</div>", 1)[0]
        self.assertIn('<a class="secondary-button" href="/dns-profiles">', heading)
        self.assertIn('<a class="secondary-button" href="/ndes-profiles">', heading)
        self.assertNotIn("/certificates/new", page)
        self.assertNotIn("certificate-actions", page)

    def test_asking_for_the_registry_view_still_renders_the_cards(self) -> None:
        page = self.page("?view=registry")

        self.assertNotIn("Certificate registry", page)
        self.assertIn("referenced by this cluster", page)


if __name__ == "__main__":
    unittest.main()
