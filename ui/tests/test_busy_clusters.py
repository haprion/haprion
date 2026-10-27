from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import timedelta
from typing import Any
from unittest import mock

from haprion_ui.db import Job
from tests.test_certificates import reading as certificate_reading
from tests.test_dashboard import reading as status_reading
from tests.test_history import reading as history_reading
from tests.test_job_page import job
from tests.test_login import LoginTestCase, configuration


class BusyPagesTestCase(LoginTestCase):
    """The pages that offer a deploy, drawn with the jobs a test chooses."""

    #
    # The page, the reading it needs to draw its footer at all, and the button
    # that must disappear while the cluster is busy.
    #
    PAGES = (
        ("/", "haprion_ui.db.cluster_statuses", "Deploy configuration"),
        ("/history", "haprion_ui.db.cluster_histories", "Deploy configuration"),
    )

    def reading_for(self, source: str) -> list[object]:
        if source.endswith("cluster_histories"):
            return [history_reading(cluster="alpha")]
        if source.endswith("cluster_certificates"):
            return [certificate_reading(cluster="alpha")]
        if source.endswith("cluster_statuses"):
            # A release is published: without one the button is not drawn (finding 60).
            return [status_reading("done-single-owner.json")]
        return []

    def page(self, path: str, source: str, jobs: list[Job]) -> Any:
        client = self.client(replace(configuration(), management_writes=True, clusters=("alpha",)))
        self.sign_in(client)
        with (
            mock.patch(source, return_value=self.reading_for(source)),
            mock.patch("haprion_ui.db.recent_jobs", return_value=jobs),
        ):
            return client.get(path)


class EveryPageThatDeploysSaysTheClusterIsBusy(BusyPagesTestCase):
    """One job per cluster, so every page that offers one draws the same state.

    The dashboard learned this first and the other two pages did not follow,
    which left two buttons that looked available and answered with a 409. The
    cases below are written per page rather than once, so a page that grows a
    deploy button and forgets the state fails here instead of in front of
    somebody.
    """

    def test_the_button_is_drawn_while_the_cluster_is_idle(self) -> None:
        for path, source, label in self.PAGES:
            with self.subTest(page=path):
                page = self.page(path, source, [])
                self.assertEqual(page.status_code, 200)
                self.assertIn(label, page.text)

    def test_no_deploy_is_offered_while_nothing_is_published(self) -> None:
        """Fas 18 finding 60: a deploy without a release failed on the first node."""

        client = self.client(replace(configuration(), management_writes=True, clusters=("alpha",)))
        self.sign_in(client)
        unpublished = status_reading("done-single-owner.json")
        result = dict(unpublished.result)
        result["summary"] = {**result["summary"], "target": None}
        with (
            mock.patch(
                "haprion_ui.db.cluster_statuses", return_value=[replace(unpublished, result=result)]
            ),
            mock.patch("haprion_ui.db.recent_jobs", return_value=[]),
        ):
            page = client.get("/")
        self.assertEqual(page.status_code, 200)
        self.assertNotIn(">Deploy configuration</button>", page.text)

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

    def test_the_versions_page_greys_its_publish_buttons_out(self) -> None:
        #
        # One per row, and the same refusal underneath: a revert is a job, and
        # the queue takes one per cluster. The button stays where it is, greyed
        # out, with why on it: replaced by a dash, the rows jumped and the
        # action was gone without a word (R2 26-10-26, F14).
        #
        idle = self.page("/history", "haprion_ui.db.cluster_histories", [])
        self.assertIn(
            '<button class="secondary-button" type="submit">Publish this version', idle.text
        )

        busy = self.page(
            "/history",
            "haprion_ui.db.cluster_histories",
            [job(state="running", operation="revert", cluster="alpha")],
        )
        self.assertIn(
            '<button class="secondary-button" type="button" disabled'
            ' title="Reverting — one job per cluster runs at a time">Publish this version</button>',
            busy.text,
        )
        self.assertNotIn(
            '<button class="secondary-button" type="submit">Publish this version', busy.text
        )
        self.assertNotIn('class="table-empty"', busy.text)

    def test_a_job_on_another_cluster_leaves_this_one_alone(self) -> None:
        elsewhere = [job(state="running", operation="deploy", cluster="beta")]
        for path, source, label in self.PAGES:
            with self.subTest(page=path):
                self.assertIn(label, self.page(path, source, elsewhere).text)


if __name__ == "__main__":
    unittest.main()


class TheBusyStateIsAlsoAvailableAsData(BusyPagesTestCase):
    """A page drawing a spinner has to learn when to stop drawing it.

    It cannot ask the rows endpoint - the answer it wants is not a row - and it
    must not be handed markup either, because what it needs back is a form
    carrying a CSRF token and a fresh idempotency key. Neither is a browser's
    to mint. So it gets the state, compares it with what it was drawn with, and
    asks the server for itself again when the two differ.
    """

    def busy(self, jobs: list[Job]) -> Any:
        client = self.client(replace(configuration(), management_writes=True, clusters=("alpha",)))
        self.sign_in(client)
        with mock.patch("haprion_ui.db.recent_jobs", return_value=jobs):
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


class WhenTheReadingCatchesUp(BusyPagesTestCase):
    """A job finishing and the poller seeing what it did are two moments (0068).

    Only the first is a job. A page redrawn on that alone had the spinner gone
    beside counts from before the job - the dashboard offering Publish & deploy
    for what it had just published. The server says which clusters the poller
    has not read through since their last job ended, and the page waits on it.
    """

    def answer(self, catching: list[str]) -> tuple[Any, mock.MagicMock]:
        client = self.client(replace(configuration(), management_writes=True, clusters=("alpha",)))
        self.sign_in(client)
        with mock.patch("haprion_ui.db.clusters_catching_up", return_value=catching) as asked:
            return client.get("/clusters/busy").json(), asked

    def test_it_names_the_clusters_still_being_read(self) -> None:
        answer, _ = self.answer(["alpha"])

        self.assertEqual(answer["catching_up"], ["alpha"])

    def test_it_asks_about_the_listed_clusters_for_two_intervals_at_most(self) -> None:
        #
        # Two intervals is the age at which a reading is called stale; a
        # poller that is down must not leave a page waiting on it for good.
        #
        _, asked = self.answer([])

        (call,) = asked.call_args_list
        self.assertEqual(list(call.args[1]), ["alpha"])
        self.assertEqual(
            call.kwargs["within"], timedelta(seconds=configuration().poller.interval_seconds * 2)
        )

    def test_the_watcher_keeps_the_spinner_until_the_reading_has_caught_up(self) -> None:
        client = self.client(replace(configuration(), demo_fixture=True))
        self.sign_in(client)
        waiting = client.get("/static/waiting.js").text

        self.assertIn("payload.catching_up", waiting)
        self.assertIn("!busy.has(one) && catching.has(one)", waiting)
        # A page drawn while catching up asks once rather than standing still.
        self.assertIn("else if (!rows()) settle();", waiting)
        self.assertNotIn("sessionStorage", waiting)
