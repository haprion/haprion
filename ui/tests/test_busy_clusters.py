from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any
from unittest import mock

from haproxy_ui.db import ClusterStatus
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


class TheBusyStateIsAlsoAvailableAsData(LoginTestCase):
    """A page drawing a spinner has to learn when to stop drawing it.

    It cannot ask the rows endpoint - the answer it wants is not a row - and it
    must not be handed markup either, because what it needs back is a form
    carrying a CSRF token and a fresh idempotency key. Neither is a browser's
    to mint. So it gets the state, compares it with what it was drawn with, and
    asks the server for itself again when the two differ.
    """

    def busy(self, jobs: list) -> Any:
        client = self.client(replace(configuration(), management_writes=True, clusters=("alpha",)))
        self.sign_in(client)
        with mock.patch("haproxy_ui.db.recent_jobs", return_value=jobs):
            return client.get("/clusters/busy")

    def test_a_running_job_names_its_cluster_and_what_it_is(self) -> None:
        answer = self.busy([job(state="running", operation="deploy", cluster="alpha")])

        self.assertEqual(answer.status_code, 200)
        self.assertEqual(answer.json()["busy"], {"alpha": "Deploying"})

    def test_a_finished_job_leaves_nothing_busy(self) -> None:
        answer = self.busy([job(state="done", operation="deploy", cluster="alpha")])

        self.assertEqual(answer.json()["busy"], {})

    def test_it_is_not_served_to_somebody_who_is_not_signed_in(self) -> None:
        client = self.client(replace(configuration(), clusters=("alpha",)))

        self.assertEqual(client.get("/clusters/busy").status_code, 401)

    def test_every_page_that_draws_a_spinner_names_the_cluster_it_is_for(self) -> None:
        #
        # The comparison is by cluster, so a page that drew the spinner without
        # saying which cluster it belonged to could never stop drawing it.
        #
        running = [job(state="running", operation="deploy", cluster="alpha")]
        for path, source, _ in self.PAGES:
            with self.subTest(page=path):
                page = self.page(path, source, running)
                self.assertIn('data-busy="alpha"', page.text)
                self.assertIn("waiting.js", page.text)

    PAGES = EveryPageThatDeploysSaysTheClusterIsBusy.PAGES
    reading_for = EveryPageThatDeploysSaysTheClusterIsBusy.reading_for
    page = EveryPageThatDeploysSaysTheClusterIsBusy.page


class WhenTheReadingCatchesUp(LoginTestCase):
    """A job finishing and the poller seeing what it did are two moments.

    Only the first is a job. A page reloaded on that alone has the buttons back
    and every number beside them still describing the release before the
    deploy - which is the state somebody reads as "it did not work".
    """

    def answer(self, statuses: list) -> Any:
        client = self.client(replace(configuration(), management_writes=True, clusters=("alpha",)))
        self.sign_in(client)
        with (
            mock.patch("haproxy_ui.db.recent_jobs", return_value=[]),
            mock.patch("haproxy_ui.db.cluster_statuses", return_value=statuses),
        ):
            return client.get("/clusters/busy").json()

    def status(self, observed: datetime | None) -> ClusterStatus:
        return ClusterStatus(
            cluster="alpha",
            observed_at=observed,
            outcome="done",
            result={},
            warnings=[],
            error=None,
            poll_error=None,
        )

    def test_it_says_when_each_cluster_was_last_read(self) -> None:
        moment = datetime(2026, 9, 3, 21, 0, tzinfo=UTC)

        self.assertEqual(
            self.answer([self.status(moment)])["observed"], {"alpha": moment.isoformat()}
        )

    def test_a_cluster_never_read_names_no_moment(self) -> None:
        self.assertEqual(self.answer([self.status(None)])["observed"], {})

    def test_the_cards_carry_the_reading_they_were_drawn_from(self) -> None:
        #
        # The comparison is against what is on the screen, so the screen has to
        # say what it was drawn from.
        #
        for path, source, _ in EveryPageThatDeploysSaysTheClusterIsBusy.PAGES:
            with self.subTest(page=path):
                page = EveryPageThatDeploysSaysTheClusterIsBusy.page(self, path, source, [])
                self.assertIn("data-observed=", page.text)

    reading_for = EveryPageThatDeploysSaysTheClusterIsBusy.reading_for
