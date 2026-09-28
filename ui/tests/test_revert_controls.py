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
        #
        # Bound to the published version this page shows, so a deploy that
        # waits in the queue cannot roll out one published after it.
        #
        self.assertIn('name="expected_version" value="12"', page.text)

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


class TheCertificatePageNoLongerDeploys(LoginTestCase):
    """B138's companion decision: the standing button is gone from this page.

    It was put here because someone reading which certificates a cluster
    carries is the person who wants to roll new ones out. What that missed is
    that a rollout is only needed when a certificate is not where the
    configuration says it should be, and config-deploy's preflight already
    blocks and says so. A button offered at all times invites a rollout of key
    material as a routine click, and the page's own state column now says when
    one is actually wanted. The operation itself is unchanged.
    """

    def setUp(self) -> None:
        super().setUp()
        rows = mock.patch(
            "haproxy_ui.db.cluster_certificates", return_value=[certificate_reading()]
        )
        rows.start()
        self.addCleanup(rows.stop)

    def page(self, **overrides: object):
        client = self.client(replace(configuration(), clusters=("alpha",), **overrides))
        self.sign_in(client)
        return client.get("/certificates")

    def test_not_even_an_admin_with_writes_is_offered_one_here(self) -> None:
        page = self.page(management_writes=True)

        self.assertEqual(page.status_code, 200)
        self.assertNotIn('name="operation" value="cert_deploy"', page.text)


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


PAGES = ("/", "/proxies", "/certificates", "/history", "/backups", "/jobs")


class TheModeBadgeAppearsOnlyWhenWritesAreOff(LoginTestCase):
    """One badge, seven headings, and nothing to say when all is normal.

    The badge existed in both directions once, which meant production carried a
    permanent "Management enabled" that never changed and was therefore never
    read. Writes off is the state worth naming: it is the documented rollback
    for the write path, and it is the answer to "where did the buttons go".
    Writes on needs no badge, because the buttons themselves say it.

    Every page is asserted, not only the ones carrying a control. Four of them
    stated the mode unconditionally, and three never passed `management_writes`
    to the template at all - which Jinja renders as false in silence, so the
    wrong half of the condition would have looked correct forever.
    """

    def setUp(self) -> None:
        super().setUp()
        jobs = mock.patch("haproxy_ui.db.recent_jobs", return_value=[])
        jobs.start()
        self.addCleanup(jobs.stop)

    def page(self, path: str, *, writes: bool) -> str:
        client = self.client(
            replace(configuration(), management_writes=writes, clusters=("alpha",))
        )
        self.sign_in(client)
        return client.get(path).text

    def test_every_page_names_read_only_mode_when_writes_are_off(self) -> None:
        for path in PAGES:
            with self.subTest(path=path):
                self.assertIn("Read-only mode", self.page(path, writes=False))

    def test_no_page_carries_a_mode_badge_when_writes_are_on(self) -> None:
        for path in PAGES:
            with self.subTest(path=path):
                body = self.page(path, writes=True)
                self.assertNotIn("Read-only mode", body)
                self.assertNotIn("Management enabled", body)
