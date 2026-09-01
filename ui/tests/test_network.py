"""The network page: a cluster's addresses, as the poller last read them.

What the tests hold to is not the layout but the things the page must not get
wrong however it is arranged: that it shows the tables an object actually
points at, that it says whether they can be changed from here, and that it
never offers the one address `deploy` checks node ownership against.
"""

from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta

from haproxy_ui import demo
from haproxy_ui.network import build_network_overview
from tests.test_login import LoginTestCase, configuration

NOW = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)
STALE_AFTER = timedelta(seconds=120)


def overview(clusters: tuple[str, ...] = demo.CLUSTERS):
    return build_network_overview(
        clusters, demo.network_rows(NOW), now=NOW, stale_after=STALE_AFTER, captured=False
    )


class TheReadingBecomesTheCard(unittest.TestCase):
    def test_a_repository_description_is_marked_editable(self) -> None:
        edge = next(view for view in overview() if view.cluster == "edge-demo")

        self.assertTrue(edge.editable)
        self.assertEqual(edge.default_vip, "public")
        self.assertEqual([vip.name for vip in edge.vips], ["partner", "public"])
        self.assertEqual([vip.is_default for vip in edge.vips], [False, True])

    def test_a_description_still_in_the_engine_s_configuration_is_not_editable(self) -> None:
        #
        # Every cluster that predates the move is in this state, and offering an
        # edit that has no path to the file would be worse than saying so.
        #
        service = next(view for view in overview() if view.cluster == "service-demo")

        self.assertFalse(service.editable)
        self.assertIn("cannot write", service.detail)

    def test_a_cluster_that_has_never_been_read_is_a_card_rather_than_a_gap(self) -> None:
        views = overview(demo.CLUSTERS + ("never-polled",))
        missing = next(view for view in views if view.cluster == "never-polled")

        self.assertEqual(missing.age_label, "Never")
        self.assertEqual(missing.vips, ())
        self.assertFalse(missing.editable)

    def test_the_ownership_address_is_carried_but_kept_out_of_every_table(self) -> None:
        edge = next(view for view in overview() if view.cluster == "edge-demo")

        self.assertEqual(edge.ownership_vip, "192.0.2.20")
        self.assertNotIn(edge.ownership_vip, [source.address for source in edge.sources])

    def test_a_vip_s_own_source_address_is_listed_as_a_source_address(self) -> None:
        #
        # It was not, and the page then told a cluster that pairs a source with
        # its VIP that it had none - under a heading named after exactly that.
        #
        edge = next(view for view in overview() if view.cluster == "edge-demo")

        addresses = {source.address: source.used_by for source in edge.sources}
        self.assertEqual(addresses["192.0.2.25"], "default for VIP public")
        self.assertEqual(addresses["192.0.2.26"], "default for VIP partner")
        self.assertEqual(addresses["192.0.2.35"], "named; an object must ask for it")

    def test_a_cluster_with_no_source_address_at_all_still_says_none(self) -> None:
        service = next(view for view in overview() if view.cluster == "service-demo")

        self.assertEqual(service.sources, ())


class ThePageIsReachableAndWritesNothing(LoginTestCase):
    def demo_client(self):
        return self.client(replace(configuration(), demo_fixture=True))

    def test_the_tables_are_rendered_for_a_signed_in_user(self) -> None:
        client = self.demo_client()
        self.sign_in(client)

        page = client.get("/network")

        self.assertEqual(page.status_code, 200)
        self.assertIn("Virtual addresses", page.text)
        self.assertIn("Source addresses", page.text)
        self.assertIn("Reachable-from groups", page.text)

    def test_the_node_half_of_the_job_is_stated_without_a_standing_warning(self) -> None:
        #
        # The hazard belongs where an address is added, not as a permanent
        # banner about something nobody is doing. Two of those per cluster
        # taught the reader to skip the colour, which is the one thing a
        # warning may not do.
        #
        client = self.demo_client()
        self.sign_in(client)

        page = client.get("/network")

        self.assertIn("keepalived's job and not this application's", page.text)
        self.assertNotIn("network-warning", page.text)

    def test_the_page_posts_nothing_yet(self) -> None:
        #
        # The layout carries a sign-out form, so the assertion is about this
        # page's own action rather than about forms existing at all.
        #
        client = self.demo_client()
        self.sign_in(client)

        page = client.get("/network")

        self.assertNotIn('action="/network"', page.text)
        self.assertIn("a control the interface can rewrite is not a control", page.text)

    def test_signing_in_is_required(self) -> None:
        page = self.client().get("/network", follow_redirects=False)

        self.assertEqual(page.status_code, 303)
        self.assertEqual(page.headers["location"], "/login")

    def test_the_navigation_marks_the_page_it_is_on(self) -> None:
        client = self.client()
        self.sign_in(client)

        page = client.get("/network")

        self.assertIn('href="/network" aria-current="page"', page.text)
