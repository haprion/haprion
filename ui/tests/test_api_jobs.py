"""`GET /api/v1/jobs` and `/jobs/{id}`: the Jobs page's reading, as JSON (B416)."""

from __future__ import annotations

from collections.abc import Collection
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest import mock
from uuid import UUID

from haprion_ui import db
from tests.test_api import NOW, ApiTestCase

QUEUED = datetime(2026, 10, 31, 11, 0, tzinfo=UTC)
REQUEST = UUID("3f1c2b64-6f3f-4f3a-9c6e-1d2b3c4d5e6f")


def a_job(**changes: Any) -> db.Job:
    job = db.Job(
        id=41,
        request_id=REQUEST,
        operation="deploy",
        cluster="alpha",
        payload={},
        state="done",
        created_at=QUEUED,
        started_at=QUEUED + timedelta(seconds=2),
        finished_at=QUEUED + timedelta(seconds=9),
        exit_code=0,
        outcome="done",
        result={"ok": True, "outcome": "done", "warnings": [], "error": None, "result": {}},
        stderr_excerpt="redacted progress",
        idempotency_key=None,
        attempts=1,
    )
    return replace(job, **changes)


def failed_job(**changes: Any) -> db.Job:
    changes.setdefault(
        "result",
        {
            "ok": False,
            "outcome": "failed",
            "warnings": [],
            "error": {"code": "candidate_invalid", "message": "Backend node-a is not valid."},
            "result": None,
        },
    )
    return a_job(
        id=42,
        request_id=UUID("00000000-0000-4000-8000-000000000042"),
        state="failed",
        outcome="failed",
        exit_code=65,
        **changes,
    )


class JobsApiTestCase(ApiTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.rows: list[db.Job] = []
        self.listed: list[dict[str, Any]] = []
        self.actors: dict[UUID, str] = {}
        self.statuses: list[db.ClusterStatus] = []
        for patch in (
            mock.patch("haprion_ui.db.listed_jobs", side_effect=self._listed),
            mock.patch("haprion_ui.db.job_by_id", side_effect=self._by_id),
            mock.patch("haprion_ui.db.recent_jobs", side_effect=self._recent),
            mock.patch("haprion_ui.db.requested_by", side_effect=self._requested_by),
            mock.patch("haprion_ui.db.cluster_statuses", side_effect=lambda _c: self.statuses),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def _listed(
        self,
        _c: object,
        *,
        clusters: Collection[str] | None,
        state: str | None,
        limit: int,
    ) -> list[db.Job]:
        self.listed.append({"clusters": clusters, "state": state, "limit": limit})
        return [
            row
            for row in self.rows
            if (clusters is None or row.cluster in clusters)
            and (state is None or row.state == state)
        ][:limit]

    def _by_id(self, _c: object, job_id: int) -> db.Job | None:
        return next((row for row in self.rows if row.id == job_id), None)

    def _recent(self, _c: object, *, cluster: str | None = None, limit: int = 20) -> list[db.Job]:
        return [row for row in self.rows if cluster is None or row.cluster == cluster][:limit]

    def _requested_by(self, _c: object, ids: Collection[UUID]) -> dict[UUID, str]:
        return {key: who for key, who in self.actors.items() if key in ids}

    def get(self, path: str, **headers: Any) -> Any:
        level = headers.pop("level", "read")
        secret = self.issue(level=level, **headers)
        return self.api().get("/api/v1" + path, headers={"Authorization": f"Bearer {secret}"})


class TheJobList(JobsApiTestCase):
    def test_the_newest_jobs_are_listed_with_what_tells_their_outcome(self) -> None:
        certificate = a_job(
            id=43,
            request_id=UUID("00000000-0000-4000-8000-000000000043"),
            operation="cert_publish",
            cluster=None,
            payload={"certificates": ["example.com", "example.net"]},
            state="pending",
            started_at=None,
            finished_at=None,
            exit_code=None,
            outcome=None,
            result=None,
        )
        self.rows = [certificate, failed_job(), a_job()]
        self.actors = {REQUEST: "operator"}

        response = self.get("/jobs")

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["operation"], "job_list")
        self.assertEqual(body["result"]["limit"], 50)
        self.assertFalse(body["result"]["truncated"])
        pending, failed, done = body["result"]["jobs"]
        self.assertEqual(
            done,
            {
                "id": 41,
                "operation": "deploy",
                "label": "Deploy configuration",
                "cluster": "alpha",
                "state": "done",
                "state_label": "Completed",
                "outcome": "done",
                "finished": True,
                "held": False,
                "queued_at": "2026-10-31T11:00:00+00:00",
                "started_at": "2026-10-31T11:00:02+00:00",
                "finished_at": "2026-10-31T11:00:09+00:00",
                "actor": "operator",
                "subjects": [],
                "error_code": None,
                "error_message": None,
            },
        )
        self.assertEqual((failed["state"], failed["error_code"]), ("failed", "candidate_invalid"))
        self.assertTrue(failed["finished"])
        self.assertEqual(
            (pending["cluster"], pending["state"], pending["finished"], pending["finished_at"]),
            (None, "pending", False, None),
        )
        self.assertEqual(pending["subjects"], ["example.com", "example.net"])
        self.assertIsNone(pending["actor"])
        self.assertEqual(self.listed, [{"clusters": None, "state": None, "limit": 51}])

    def test_the_helper_s_sentence_goes_to_a_token_at_the_admin_s_level_only(self) -> None:
        self.rows = [failed_job()]

        reader = self.get("/jobs").json()["result"]["jobs"][0]
        writer = self.get("/jobs", level="write").json()["result"]["jobs"][0]

        self.assertEqual(
            (reader["error_code"], reader["error_message"]), ("candidate_invalid", None)
        )
        self.assertEqual(writer["error_message"], "Backend node-a is not valid.")
        self.assertNotIn("stderr", self.get("/jobs", level="write").text)
        self.assertNotIn("redacted progress", self.get("/jobs", level="write").text)

    def test_a_token_limited_to_clusters_is_given_those_clusters_jobs_only(self) -> None:
        self.rows = [
            a_job(id=1, cluster="alpha"),
            a_job(id=2, cluster="beta"),
            a_job(id=3, cluster=None, operation="cert_publish"),
        ]

        response = self.get("/jobs", clusters=["beta"])

        self.assertEqual([job["id"] for job in response.json()["result"]["jobs"]], [2])
        self.assertEqual(self.listed[-1]["clusters"], ["beta"])

    def test_a_cluster_outside_the_token_is_as_if_it_were_not_there(self) -> None:
        self.rows = [a_job(id=1, cluster="alpha")]

        outside = self.get("/jobs?cluster=alpha", clusters=["beta"])
        inside = self.get("/jobs?cluster=alpha", clusters=["alpha"])

        self.assertEqual(outside.status_code, 404)
        self.assertEqual(outside.json()["error"]["code"], "not_found")
        self.assertEqual([job["id"] for job in inside.json()["result"]["jobs"]], [1])
        self.assertEqual(inside.json()["cluster"], "alpha")

    def test_a_list_cut_by_its_limit_says_so(self) -> None:
        self.rows = [a_job(id=number) for number in range(5, 0, -1)]

        cut = self.get("/jobs?limit=3").json()["result"]
        whole = self.get("/jobs?limit=5").json()["result"]

        self.assertEqual(([job["id"] for job in cut["jobs"]], cut["truncated"]), ([5, 4, 3], True))
        self.assertEqual((len(whole["jobs"]), whole["truncated"]), (5, False))
        self.assertEqual(cut["limit"], 3)

    def test_the_state_filter_narrows_the_list(self) -> None:
        self.rows = [failed_job(), a_job()]

        response = self.get("/jobs?state=failed")

        self.assertEqual([job["id"] for job in response.json()["result"]["jobs"]], [42])
        self.assertEqual(self.listed[-1]["state"], "failed")

    def test_no_jobs_is_an_empty_list(self) -> None:
        self.assertEqual(
            self.get("/jobs").json()["result"], {"jobs": [], "limit": 50, "truncated": False}
        )

    def test_a_limit_or_state_that_is_not_allowed_is_a_400(self) -> None:
        for query in ("limit=0", "limit=501", "limit=many", "state=exploded"):
            with self.subTest(query=query):
                response = self.get("/jobs?" + query)
                self.assertEqual(response.status_code, 400)
                self.assertEqual(response.json()["error"]["code"], "bad_input")
        self.assertEqual(self.listed, [])

    def test_a_held_job_is_told_from_one_that_is_running(self) -> None:
        self.rows = [
            a_job(
                state="pending",
                started_at=None,
                finished_at=None,
                exit_code=None,
                outcome=None,
                result=None,
                held_since=QUEUED,
            )
        ]

        job = self.get("/jobs").json()["result"]["jobs"][0]

        self.assertEqual((job["state"], job["state_label"], job["held"]), ("pending", "Held", True))
        self.assertFalse(job["finished"])


class OneJob(JobsApiTestCase):
    def test_a_job_that_owes_a_deploy_says_so_and_what_it_ran(self) -> None:
        self.rows = [
            a_job(
                id=44,
                operation="changes_publish",
                payload={"drafts": [{"id": "shop"}]},
                result={
                    "ok": True,
                    "outcome": "done",
                    "warnings": [],
                    "error": None,
                    "result": {
                        "version": 7,
                        "deployment_required": True,
                        "next_command": "haprion-deploy -c alpha",
                    },
                },
            )
        ]
        self.statuses = [
            db.ClusterStatus(
                cluster="alpha",
                observed_at=NOW,
                outcome="done",
                result={"summary": {"release_state": "behind"}},
                warnings=[],
                error=None,
                poll_error=None,
            )
        ]
        self.actors = {REQUEST: "operator"}

        response = self.get("/jobs/44")

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual((body["operation"], body["cluster"]), ("job_show", "alpha"))
        self.assertEqual(
            body["result"],
            {
                "id": 44,
                "operation": "changes_publish",
                "label": "Publish saved changes",
                "cluster": "alpha",
                "state": "done",
                "state_label": "Completed",
                "outcome": "done",
                "finished": True,
                "held": False,
                "queued_at": "2026-10-31T11:00:00+00:00",
                "started_at": "2026-10-31T11:00:02+00:00",
                "finished_at": "2026-10-31T11:00:09+00:00",
                "actor": "operator",
                "subjects": [],
                "error_code": None,
                "error_message": None,
                "exit_code": 0,
                "exit_meaning": "Finished.",
                "waiting_for": None,
                "follow_up": (
                    "Published, not deployed. The nodes still run the previous version "
                    "until alpha is deployed."
                ),
                "next_command": "haprion-deploy -c alpha",
                "warning_codes": [],
                "warning_message": None,
                "note": None,
                "step_states": [{"step": "changes_publish", "state": "done"}],
                "keyed_states": [{"step": "changes_publish", "subject": None, "state": "done"}],
                "step_note": None,
                "distribution_note": None,
            },
        )

    def test_a_publish_whose_deploy_failed_names_both_steps(self) -> None:
        self.rows = [
            failed_job(
                operation="changes_publish",
                payload={"deploy": True},
                result={
                    "ok": False,
                    "outcome": "failed",
                    "warnings": [],
                    "error": {"code": "node_unreachable", "message": "node-a did not answer."},
                    "result": None,
                    "step": "deploy",
                    "publish": {"ok": True, "outcome": "done", "result": {"version": 7}},
                },
            )
        ]

        result = self.get("/jobs/42").json()["result"]

        self.assertEqual(
            result["step_states"],
            [{"step": "changes_publish", "state": "done"}, {"step": "deploy", "state": "failed"}],
        )
        self.assertEqual(
            result["keyed_states"],
            [
                {"step": "changes_publish", "subject": None, "state": "done"},
                {"step": "deploy", "subject": None, "state": "failed"},
            ],
        )
        self.assertEqual(result["step_note"], "Published as version 7; the deploy failed.")
        self.assertEqual(result["error_code"], "node_unreachable")
        self.assertEqual((result["state"], result["exit_code"]), ("failed", 65))

    def test_a_partial_run_carries_its_warnings(self) -> None:
        self.rows = [
            a_job(
                state="partial",
                outcome="partial",
                exit_code=0,
                result={
                    "ok": True,
                    "outcome": "partial",
                    "warnings": [{"code": "node_behind", "message": "node-b is behind."}],
                    "error": None,
                    "result": {},
                },
            )
        ]

        reader = self.get("/jobs/41").json()["result"]
        writer = self.get("/jobs/41", level="write").json()["result"]

        self.assertEqual((reader["state"], reader["outcome"]), ("partial", "partial"))
        self.assertEqual(reader["warning_codes"], ["node_behind"])
        self.assertIsNone(reader["warning_message"])
        self.assertEqual(writer["warning_message"], "node-b is behind.")

    def test_a_job_still_running_is_not_finished(self) -> None:
        self.rows = [
            a_job(state="running", finished_at=None, exit_code=None, outcome=None, result=None)
        ]

        result = self.get("/jobs/41").json()["result"]

        self.assertEqual(
            (result["state"], result["finished"], result["finished_at"], result["exit_code"]),
            ("running", False, None, None),
        )
        self.assertEqual(result["exit_meaning"], "The job recorded no exit code.")

    def test_a_job_in_a_cluster_outside_the_token_is_not_found(self) -> None:
        self.rows = [a_job(cluster="alpha")]

        outside = self.get("/jobs/41", clusters=["beta"])
        missing = self.get("/jobs/99", clusters=["beta"])
        inside = self.get("/jobs/41", clusters=["alpha"])

        self.assertEqual(inside.status_code, 200)
        self.assertEqual((outside.status_code, missing.status_code), (404, 404))
        self.assertEqual(outside.json()["error"], missing.json()["error"])
        self.assertEqual(outside.json()["error"]["code"], "not_found")

    def test_a_job_with_no_cluster_is_for_a_token_with_no_limit(self) -> None:
        self.rows = [a_job(operation="cert_publish", cluster=None)]

        self.assertEqual(self.get("/jobs/41").status_code, 200)
        self.assertEqual(self.get("/jobs/41", clusters=["alpha"]).status_code, 404)

    def test_a_job_that_is_not_there_is_a_404_and_a_number_that_is_no_id_a_400(self) -> None:
        self.assertEqual(self.get("/jobs/41").status_code, 404)
        for path in ("/jobs/0", "/jobs/-1", "/jobs/9223372036854775808", "/jobs/first"):
            with self.subTest(path=path):
                self.assertEqual(self.get(path).status_code, 400)


class TheLevel(JobsApiTestCase):
    """The boundary test walks the routes without a database to read; this holds the level."""

    def test_a_read_token_reaches_both_routes_and_a_block_token_neither(self) -> None:
        self.rows = [a_job()]

        for path in ("/jobs", "/jobs/41"):
            with self.subTest(path=path):
                self.assertEqual(self.get(path).status_code, 200)
                forbidden = self.get(path, level="block")
                self.assertEqual(forbidden.status_code, 403)
                self.assertEqual(forbidden.json()["error"]["code"], "forbidden")
