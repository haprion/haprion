from __future__ import annotations

import unittest
from dataclasses import replace
from unittest import mock

from tests.test_certificates import reading as certificate_reading
from tests.test_history import reading as history_reading
from tests.test_job_page import job
from tests.test_login import LoginTestCase, configuration


class EveryPageThatDeploysSaysTheClusterIsBusy(LoginTestCase):
    """One job per cluster, so every page that offers one draws the same state.

    The dashboard learned this first and the other two pages did not follow,
    which left two buttons that looked available and answered with a 409. The
    cases below are written per page rather than once, so a page that grows a
    deploy button and forgets the state fails here instead of in front of
    somebody.
    """

    #
    # The page, the reading it needs to draw its footer at all, and the button
    # that must disappear while the cluster is busy.
    #
    PAGES = (
        ("/", "haproxy_ui.db.cluster_statuses", "Deploy configuration"),
        ("/history", "haproxy_ui.db.cluster_histories", "Deploy configuration"),
        ("/certificates", "haproxy_ui.db.cluster_certificates", "Deploy certificates"),
    )

    def reading_for(self, source: str) -> list:
        if source.endswith("cluster_histories"):
            return [history_reading(cluster="alpha")]
        if source.endswith("cluster_certificates"):
            return [certificate_reading(cluster="alpha")]
        return []

    def page(self, path: str, source: str, jobs: list):
        client = self.client(replace(configuration(), management_writes=True, clusters=("alpha",)))
        self.sign_in(client)
        with (
            mock.patch(source, return_value=self.reading_for(source)),
            mock.patch("haproxy_ui.db.recent_jobs", return_value=jobs),
        ):
            return client.get(path)

    def test_the_button_is_drawn_while_the_cluster_is_idle(self) -> None:
        for path, source, label in self.PAGES:
            with self.subTest(page=path):
                page = self.page(path, source, [])
                self.assertEqual(page.status_code, 200)
                self.assertIn(label, page.text)

    def test_the_button_is_replaced_by_what_the_cluster_is_doing(self) -> None:
        running = [job(state="running", operation="deploy", cluster="alpha")]
        for path, source, label in self.PAGES:
            with self.subTest(page=path):
                page = self.page(path, source, running)
                self.assertEqual(page.status_code, 200)
                #
                # Not the button, and not silence either: the operation names
                # itself and the reader is given somewhere to watch it.
                #
                self.assertNotIn(label, page.text)
                self.assertIn("Deploying", page.text)
                self.assertIn('href="/jobs"', page.text)

    def test_the_versions_page_hides_its_publish_buttons_too(self) -> None:
        #
        # One per row rather than one per page, and the same refusal underneath:
        # a revert is a job, and the queue takes one per cluster. The footer
        # above already names what is running, so the cells say nothing more
        # than that they are not offering anything.
        #
        idle = self.page("/history", "haproxy_ui.db.cluster_histories", [])
        self.assertIn("Publish this version", idle.text)

        busy = self.page(
            "/history",
            "haproxy_ui.db.cluster_histories",
            [job(state="running", operation="revert", cluster="alpha")],
        )
        self.assertNotIn("Publish this version", busy.text)
        self.assertIn("one job per cluster runs at a time", busy.text)

    def test_a_job_on_another_cluster_leaves_this_one_alone(self) -> None:
        elsewhere = [job(state="running", operation="deploy", cluster="beta")]
        for path, source, label in self.PAGES:
            with self.subTest(page=path):
                self.assertIn(label, self.page(path, source, elsewhere).text)


if __name__ == "__main__":
    unittest.main()
