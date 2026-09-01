"""The network page: the cluster's addresses, as a page rather than a file.

A draft, and the tests say so. What they hold to is not the layout but the two
things the page must never get wrong however it is arranged: that it shows the
tables an object actually points at, and that it does not offer to edit the one
address `deploy` checks node ownership against.
"""

from __future__ import annotations

from tests.test_login import LoginTestCase


class ThePageShowsWhatAnObjectCanPointAt(LoginTestCase):
    def test_every_table_is_rendered(self) -> None:
        client = self.client()
        self.sign_in(client)

        page = client.get("/network")

        self.assertEqual(page.status_code, 200)
        for expected in ("internal", "192.0.2.20", "outbound", "192.0.2.35", "office"):
            self.assertIn(expected, page.text)

    def test_the_default_is_marked_rather_than_left_to_be_inferred(self) -> None:
        client = self.client()
        self.sign_in(client)

        page = client.get("/network")

        self.assertIn("default", page.text)
        self.assertIn("Currently", page.text)

    def test_the_keepalived_half_of_the_job_is_stated_on_the_page(self) -> None:
        #
        # Adding a VIP here does nothing until a node carries it, and the page
        # is the only place someone will be standing when they need to know.
        #
        client = self.client()
        self.sign_in(client)

        page = client.get("/network")

        self.assertIn("keepalived", page.text)
        self.assertIn("virtual_ipaddress", page.text)

    def test_the_address_deploy_checks_ownership_against_is_not_offered(self) -> None:
        client = self.client()
        self.sign_in(client)

        page = client.get("/network")

        self.assertNotIn('name="vip"', page.text)
        self.assertIn("A control the interface can rewrite is not a control", page.text)

    def test_signing_in_is_required(self) -> None:
        page = self.client().get("/network", follow_redirects=False)

        self.assertEqual(page.status_code, 303)
        self.assertEqual(page.headers["location"], "/login")

    def test_the_navigation_marks_the_page_it_is_on(self) -> None:
        client = self.client()
        self.sign_in(client)

        page = client.get("/network")

        self.assertIn('href="/network" aria-current="page"', page.text)
