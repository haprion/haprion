from __future__ import annotations

import unittest
from dataclasses import replace
from unittest import mock

from tests.test_certificates import reading as certificate_reading
from tests.test_history import reading
from tests.test_login import LoginTestCase, configuration


class RevertControlsTests(LoginTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.history_rows = mock.patch(
            "haproxy_ui.db.cluster_histories", return_value=[reading(cluster="alpha")]
        )
        self.history_rows.start()
        self.addCleanup(self.history_rows.stop)

    def test_an_admin_posts_the_full_polled_commit_not_the_display_prefix(self) -> None:
        client = self.client(replace(configuration(), management_writes=True, clusters=("alpha",)))
        self.sign_in(client)

        page = client.get("/history")

        self.assertEqual(page.status_code, 200)
        self.assertIn('name="operation" value="revert"', page.text)
        #
        # v11, not the published v12: the published version has no button, and
        # the point being made here is about the commit a form carries.
        #
        self.assertIn('name="version" value="11"', page.text)
        self.assertIn('name="expected_commit" value="' + "b" * 40 + '"', page.text)
        #
        # Publishing and deploying are two steps, and the page has to say so -
        # once, under the table, rather than under every button where it made
        # every row taller to repeat the same sentence.
        #
        self.assertIn("deploying is what reaches the nodes", page.text)
        #
        # And the deploy that does reach them is on this page, so the two steps
        # are one place rather than two tabs.
        #
        self.assertIn('name="operation" value="deploy"', page.text)
        self.assertIn("Deploy configuration", page.text)

    def test_read_only_and_reader_views_do_not_render_a_revert_control(self) -> None:
        client = self.client(replace(configuration(), clusters=("alpha",)))
        self.sign_in(client)
        self.assertNotIn('name="operation" value="revert"', client.get("/history").text)

        self.account = replace(self.account, role="reader")
        reader = self.client(replace(configuration(), management_writes=True, clusters=("alpha",)))
        self.sign_in(reader)
        self.assertNotIn('name="operation" value="revert"', reader.get("/history").text)


if __name__ == "__main__":
    unittest.main()


class DeployingFromThePageThatPublishes(LoginTestCase):
    """The deploy control belongs where the publishing happens.

    Publishing and deploying are two steps and always were; making the reader
    change tabs between them is what turned that into a thing to remember. The
    button is styled apart on purpose - on a page where every other button
    publishes, the one that reaches the nodes must not look interchangeable.
    """

    def setUp(self) -> None:
        super().setUp()
        self.history_rows = mock.patch(
            "haproxy_ui.db.cluster_histories", return_value=[reading(cluster="alpha")]
        )
        self.history_rows.start()
        self.addCleanup(self.history_rows.stop)

    def test_a_reader_gets_no_deploy_button(self) -> None:
        self.account = replace(self.account, role="reader")
        client = self.client(replace(configuration(), management_writes=True, clusters=("alpha",)))
        self.sign_in(client)

        self.assertNotIn('name="operation" value="deploy"', client.get("/history").text)

    def test_read_only_mode_gets_no_deploy_button(self) -> None:
        client = self.client(replace(configuration(), clusters=("alpha",)))
        self.sign_in(client)

        self.assertNotIn('name="operation" value="deploy"', client.get("/history").text)


class DeployingCertificatesFromTheCertificatePage(LoginTestCase):
    """The same argument as the versions page, one tab over.

    Someone looking at which certificates a cluster carries is exactly the
    person who wants to roll new ones out, and sending them to the dashboard to
    do it is a step that exists only because of how the pages were split.
    """

    def setUp(self) -> None:
        super().setUp()
        #
        # A real polled reading rather than the demo fixture: the fixture is
        # only allowed with writes disabled, so testing the button against it
        # would prove the button in a state production cannot be in.
        #
        rows = mock.patch(
            "haproxy_ui.db.cluster_certificates", return_value=[certificate_reading()]
        )
        rows.start()
        self.addCleanup(rows.stop)

    def page(self, **overrides: object):
        client = self.client(replace(configuration(), clusters=("alpha",), **overrides))
        self.sign_in(client)
        return client.get("/certificates")

    def test_an_admin_with_writes_can_deploy_certificates_here(self) -> None:
        page = self.page(management_writes=True)

        self.assertEqual(page.status_code, 200)
        self.assertIn('name="operation" value="cert_deploy"', page.text)

    def test_read_only_mode_shows_no_such_button(self) -> None:
        self.assertNotIn('name="operation" value="cert_deploy"', self.page().text)

    def test_a_reader_gets_no_such_button(self) -> None:
        self.account = replace(self.account, role="reader")

        self.assertNotIn(
            'name="operation" value="cert_deploy"', self.page(management_writes=True).text
        )


class ThePublishedVersionHasNoButton(LoginTestCase):
    """Nine identical buttons and one that would do nothing recognisable.

    Publishing the version that is already published is the repair of an
    interrupted publish - a real path, exercised on 2026-08-31 as job 31, which
    finished the run without recording a second version. It is a maintenance
    action, and as a tenth identical button it reads as something an operator
    might reasonably press to no effect.
    """

    def setUp(self) -> None:
        super().setUp()
        rows = mock.patch(
            "haproxy_ui.db.cluster_histories", return_value=[reading(cluster="alpha")]
        )
        rows.start()
        self.addCleanup(rows.stop)

    def test_the_current_version_offers_no_publish_form(self) -> None:
        client = self.client(replace(configuration(), management_writes=True, clusters=("alpha",)))
        self.sign_in(client)

        page = client.get("/history")

        self.assertIn("Current", page.text)
        self.assertNotIn('name="version" value="12"', page.text)
        #
        # The older versions keep theirs: this hides one row's control, not the
        # ability to publish.
        #
        self.assertIn('name="version" value="11"', page.text)
