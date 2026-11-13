"""A cluster's deploys as bands behind its traffic line (B496, 8; 26-11-08).

What is pinned here: which jobs become a band (a deploy that reached a node, or
one nothing says did not), where the band lands (on the line's own bucket
edges, never narrower than a bucket), what it says, and that both pages that
draw the card draw it - and that the Jobs page opens the job a band links to
even when it is no longer among the twenty newest.
"""

from __future__ import annotations

import re
import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest import mock
from uuid import uuid4

from haprion_ui import db, deploy_bands, metrics
from tests.test_cluster_traffic import measurement
from tests.test_login import LoginTestCase, configuration

#
# On a 10-minute edge, so a bucket's place in the window is known exactly.
#
END = datetime(2026, 11, 8, 12, 0, tzinfo=UTC)
START = END - timedelta(hours=24)
BUCKET = timedelta(minutes=10)
COMMIT = "a" * 40


def node(name: str, outcome: str) -> dict[str, Any]:
    return {
        "name": name,
        "reachable": True,
        "current_before": False,
        "action": "deploy",
        "outcome": outcome,
        "verified": outcome == "updated",
        "error": None,
    }


def deployed(*outcomes: tuple[str, str], version: int = 25) -> dict[str, Any]:
    """A deploy's stored envelope: the target and one line per node."""

    return {
        "outcome": "done",
        "result": {
            "target": {"version": version, "hash": COMMIT},
            "nodes": [node(name, outcome) for name, outcome in outcomes],
        },
    }


def deploy_job(
    *,
    began: datetime,
    took: timedelta = timedelta(minutes=2),
    state: str = "done",
    result: dict[str, Any] | None = None,
    operation: str = "deploy",
    payload: dict[str, Any] | None = None,
    job_id: int = 41,
    cluster: str = "alpha",
) -> db.Job:
    return db.Job(
        id=job_id,
        request_id=uuid4(),
        operation=operation,
        cluster=cluster,
        payload=payload or {},
        state=state,
        created_at=began - timedelta(seconds=5),
        started_at=began,
        finished_at=None if state == "running" else began + took,
        exit_code=0 if state == "done" else 65,
        outcome=state,
        result=result,
        stderr_excerpt=None,
        idempotency_key=uuid4(),
        attempts=1,
    )


def drawn(*found: db.Job, now: datetime = END) -> tuple[deploy_bands.DeployBand, ...]:
    return deploy_bands.bands(found, start=START, end=END, bucket=BUCKET, now=now)


class WhichJobsAreBands(unittest.TestCase):
    def test_a_deploy_that_updated_a_node_is_a_band(self) -> None:
        band = drawn(
            deploy_job(began=END - timedelta(hours=2), result=deployed(("node-a", "updated")))
        )

        self.assertEqual(len(band), 1)
        self.assertEqual(band[0].heading, "Deploy v25")
        self.assertEqual(band[0].tone, "done")
        self.assertEqual(band[0].job_link, "/jobs?job=41#job-41")
        self.assertEqual(band[0].version_link, f"/history/alpha/versions/{COMMIT}")

    def test_a_deploy_that_found_every_node_current_is_not(self) -> None:
        nothing = deploy_job(
            began=END - timedelta(hours=2),
            result=deployed(("node-a", "current"), ("node-b", "current")),
        )

        self.assertEqual(drawn(nothing), ())

    def test_one_refused_before_the_first_node_is_not(self) -> None:
        refused = deploy_job(
            began=END - timedelta(hours=2),
            state="blocked",
            result=deployed(("node-a", "not_attempted"), ("node-b", "unavailable")),
        )

        self.assertEqual(drawn(refused), ())

    def test_one_stopped_after_a_node_was_changed_is_a_band(self) -> None:
        stopped = deploy_job(
            began=END - timedelta(hours=2),
            state="blocked",
            result=deployed(("node-a", "updated"), ("node-b", "not_attempted")),
        )

        (band,) = drawn(stopped)
        self.assertEqual(band.tone, "warning")
        self.assertTrue(band.detail.startswith("stopped part-way · "))

    def test_a_failure_names_the_node_it_failed_on(self) -> None:
        failed = deploy_job(
            began=END - timedelta(hours=2),
            state="failed",
            result=deployed(("node-a", "updated"), ("node-b", "failed")),
        )

        (band,) = drawn(failed)
        self.assertEqual(band.tone, "failed")
        self.assertTrue(band.detail.startswith("failed on node-b · "), band.detail)

    def test_a_job_whose_answer_cannot_be_read_is_drawn(self) -> None:
        """Hiding a deploy that did reach a node is the worse of the two mistakes."""

        unknown = deploy_job(began=END - timedelta(hours=2), state="unknown", result=None)
        failed = deploy_job(began=END - timedelta(hours=3), state="failed", result=None, job_id=40)

        tones = [band.tone for band in drawn(unknown, failed)]
        self.assertEqual(tones, ["failed", "failed"])
        self.assertEqual(drawn(unknown)[0].heading, "Deploy")
        self.assertIsNone(drawn(unknown)[0].version_link)

    def test_a_running_deploy_reaches_now(self) -> None:
        now = END - timedelta(minutes=3)
        running = deploy_job(
            began=END - timedelta(minutes=14),
            state="running",
            payload={"expected_version": 26},
        )

        (band,) = drawn(running, now=now)
        self.assertEqual((band.tone, band.heading), ("running", "Deploy v26"))
        self.assertTrue(band.detail.startswith("running · since "))
        self.assertEqual(band.right, 100.0)

    def test_a_publish_and_deploy_is_a_band_and_a_publish_alone_is_not(self) -> None:
        both = deploy_job(
            began=END - timedelta(hours=2),
            operation="changes_publish",
            payload={"deploy": True},
            result={
                **deployed(("node-a", "updated")),
                "publish": {"outcome": "done"},
                "step": "deploy",
            },
        )
        publish_failed = deploy_job(
            began=END - timedelta(hours=3),
            state="failed",
            operation="changes_publish",
            payload={"deploy": True},
            result={"outcome": "failed", "result": None},
            job_id=40,
        )
        alone = replace(both, id=39, payload={})

        self.assertEqual(
            [band.job_link for band in drawn(both, publish_failed, alone)], ["/jobs?job=41#job-41"]
        )

    def test_a_revert_or_a_certificate_deploy_is_not(self) -> None:
        reverted = deploy_job(
            began=END - timedelta(hours=2),
            operation="revert",
            result=deployed(("node-a", "updated")),
        )
        certificates = replace(reverted, id=40, operation="cert_deploy")

        self.assertEqual(drawn(reverted, certificates), ())


class WhereABandLands(unittest.TestCase):
    def test_it_covers_every_bucket_the_job_touched(self) -> None:
        #
        # 09:58-10:03 touches the 09:50 and 10:00 buckets: two of the 144.
        #
        began = END - timedelta(hours=2, minutes=2)
        (band,) = drawn(
            deploy_job(
                began=began, took=timedelta(minutes=5), result=deployed(("node-a", "updated"))
            )
        )

        first = (began.replace(minute=50) - START) / (END - START)
        self.assertAlmostEqual(band.x, first * metrics.SPARK_WIDTH, places=6)
        self.assertAlmostEqual(band.width, 2 * metrics.SPARK_WIDTH / 144, places=6)

    def test_a_deploy_of_seconds_is_still_a_whole_bucket(self) -> None:
        (band,) = drawn(
            deploy_job(
                began=END - timedelta(hours=5, minutes=4),
                took=timedelta(seconds=40),
                result=deployed(("node-a", "updated")),
            )
        )

        self.assertAlmostEqual(band.width, metrics.SPARK_WIDTH / 144, places=6)

    def test_one_outside_the_window_is_left_out_and_one_across_its_edge_is_cut(self) -> None:
        before = deploy_job(
            began=START - timedelta(hours=1), result=deployed(("node-a", "updated")), job_id=40
        )
        across = deploy_job(
            began=START - timedelta(minutes=5),
            took=timedelta(minutes=12),
            result=deployed(("node-a", "updated")),
        )

        (band,) = drawn(before, across)
        self.assertEqual(band.job_link, "/jobs?job=41#job-41")
        self.assertEqual(band.x, 0.0)
        self.assertEqual(band.left, 0.0)

    def test_the_bands_are_oldest_first(self) -> None:
        later = deploy_job(
            began=END - timedelta(hours=1), result=deployed(("node-a", "updated")), job_id=42
        )
        earlier = deploy_job(began=END - timedelta(hours=6), result=deployed(("node-a", "updated")))

        self.assertEqual(
            [band.job_link for band in drawn(later, earlier)],
            ["/jobs?job=41#job-41", "/jobs?job=42#job-42"],
        )

    def test_a_week_says_the_day_and_a_day_does_not(self) -> None:
        job = deploy_job(began=END - timedelta(hours=2), result=deployed(("node-a", "updated")))
        (day,) = drawn(job)
        (week,) = deploy_bands.bands(
            [job], start=END - timedelta(days=7), end=END, bucket=timedelta(hours=1), now=END
        )

        self.assertRegex(day.detail, r"^done · \d\d:\d\d:\d\d–\d\d:\d\d:\d\d$")
        self.assertRegex(week.detail, r"^done · \d\d-\d\d-\d\d \d\d:\d\d:\d\d–\d\d:\d\d:\d\d$")


class TheCardsDrawThem(LoginTestCase):
    """Both pages that draw a traffic card draw the cluster's bands on it."""

    def setUp(self) -> None:
        super().setUp()
        readers = mock.patch("haprion_ui.reading.TRAFFIC_READERS", 1)
        readers.start()
        self.addCleanup(readers.stop)
        now = datetime.now(UTC)
        self.deploys = [
            deploy_job(
                began=now - timedelta(hours=2),
                state="failed",
                result=deployed(("node-a", "updated"), ("node-b", "failed")),
                cluster="edge-demo",
            )
        ]
        for name, value in (
            ("read_cluster_frontends", lambda *_a, **_k: []),
            ("read_cluster_backends", lambda *_a, **k: [] if k.get("kind") else ["mgd-web"]),
            ("read_backend_aliases", lambda *_a, **_k: {}),
            ("read_backend_series", lambda *_a, **_k: []),
            (
                "read_backend_totals",
                lambda *_a, **_k: metrics.BackendMeasurement(
                    intervals=0,
                    started_at=None,
                    ended_at=None,
                    totals=(),
                    restarted=False,
                    handed_over=False,
                ),
            ),
            ("deploy_jobs", self._deploys),
        ):
            patch = mock.patch(f"haprion_ui.db.{name}", side_effect=value)
            patch.start()
            self.addCleanup(patch.stop)

    def _deploys(self, _connection: object, **asked: Any) -> list[db.Job]:
        self.asked = asked
        return [job for job in self.deploys if job.cluster in asked["clusters"]]

    def test_the_cluster_view_draws_its_cluster_s_deploys(self) -> None:
        client = self.client(replace(configuration(), demo_fixture=True))
        self.sign_in(client)

        page = client.get("/clusters/edge-demo/metrics").text

        self.assertEqual(self.asked["clusters"], ["edge-demo"])
        self.assertEqual(self.asked["until"] - self.asked["since"], timedelta(hours=24))
        self.assertIn('class="deploy-band deploy-band-failed"', page)
        tips = re.findall(r'<div class="deploy-tip"[^>]*hidden>(.*?)</div>', page)
        self.assertEqual(len(tips), 1)
        self.assertIn("<strong>Deploy v25</strong> · failed on node-b · ", tips[0])
        self.assertIn('<a href="/jobs?job=41#job-41">Job</a>', tips[0])
        self.assertIn(f'<a href="/history/edge-demo/versions/{COMMIT}">Version</a>', tips[0])

    def test_the_object_page_draws_its_cluster_s_deploys(self) -> None:
        with (
            mock.patch("haprion_ui.db.read_draft", return_value=None),
            mock.patch(
                "haprion_ui.db.read_backend_totals", side_effect=lambda *_a, **_k: measurement()
            ),
        ):
            client = self.client(replace(configuration(), demo_fixture=True))
            self.sign_in(client)
            page = client.get("/proxies/edge-demo/public-web").text

        self.assertEqual(self.asked["clusters"], ["edge-demo"])
        self.assertIn('class="deploy-band deploy-band-failed"', page)
        self.assertIn('<a href="/jobs?job=41#job-41">Job</a>', page)


class EveryLinkToAJobOpensIt(unittest.TestCase):
    """26-11-08: `/jobs#job-N` landed on a page without the row once the job was
    not among the twenty newest - from Needs attention, profiles, receivers,
    restores and the record alike. A link to a job asks for it by number."""

    def test_no_link_names_a_row_without_asking_for_its_job(self) -> None:
        source = Path(__file__).parents[1] / "src" / "haprion_ui"
        found = [
            f"{path.relative_to(source)}:{number}"
            for path in sorted(source.rglob("*"))
            if path.suffix in {".py", ".html", ".js"}
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
            if "/jobs#job-" in line
        ]

        self.assertEqual(found, [])


class TheJobPageOpensTheLinkedJob(LoginTestCase):
    def test_a_job_older_than_the_newest_twenty_is_listed_when_asked_for(self) -> None:
        now = datetime.now(UTC)
        newer = [
            deploy_job(began=now - timedelta(minutes=minute), job_id=200 - minute)
            for minute in range(1, 21)
        ]
        older = deploy_job(began=now - timedelta(days=3), job_id=7)
        client = self.client()
        self.sign_in(client)
        with (
            mock.patch("haprion_ui.db.recent_jobs", return_value=newer),
            mock.patch("haprion_ui.db.job_by_id", return_value=older) as by_id,
        ):
            plain = client.get("/jobs").text
            asked = client.get("/jobs?job=7").text
            listed = client.get("/jobs?job=199").text
            nonsense = client.get("/jobs?job=seven").text

        self.assertNotIn('id="job-7"', plain)
        self.assertIn('id="job-7"', asked)
        rows = re.findall(r'<tr id="job-(\d+)"', asked)
        self.assertEqual(rows[-1], "7")
        self.assertEqual(by_id.call_count, 1)
        self.assertNotIn('id="job-7"', listed)
        self.assertNotIn('id="job-7"', nonsense)


class TheBoundKeepsTheNewestJobs(unittest.TestCase):
    def test_the_query_takes_the_newest_within_the_bound_and_gives_them_oldest_first(self) -> None:
        cursor = mock.MagicMock()
        cursor.fetchall.return_value = ["newest", "middle", "oldest"]
        connection = mock.MagicMock()
        connection.cursor.return_value.__enter__.return_value = cursor
        now = datetime(2026, 11, 8, 12, 0, tzinfo=UTC)

        found = db.deploy_jobs(connection, clusters=["alpha"], since=now, until=now)

        self.assertIn("order by started_at desc, id desc", cursor.execute.call_args.args[0])
        self.assertEqual(found, ["oldest", "middle", "newest"])


if __name__ == "__main__":
    unittest.main()
