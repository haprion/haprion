"""Restoring a node from the backup page (§15.2, B175).

The engine and its helper are tested with the engine. This side owns the form's
refusals, the run page read from the run's jobs - against the contract's own
fixtures, so a page and a helper cannot drift apart - and the routes' gates.
"""

from __future__ import annotations

import json
import re
import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest import mock
from uuid import uuid4

from haproxy_ui import auth, db, node_restores
from tests.test_backups import reading
from tests.test_certificate_delete import DeleteRouteTestCase
from tests.test_queue_route import queued

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"
RUN = "r260101-0000aaaa"
VERSION = str(reading().result["nodes"][0]["backups"][0]["version"])
FINGERPRINT = "SHA256:" + "A" * 43
TEST = {"hostname": "node-test", "address": "192.0.2.29/24", "vip": "198.51.100.254/32"}


def fixture(helper: str, name: str) -> dict[str, Any]:
    document: dict[str, Any] = json.loads((FIXTURES / helper / "valid" / name).read_text())
    return document


def job(
    operation: str,
    state: str,
    *,
    result: dict[str, Any] | None = None,
    number: int = 1,
    **payload: Any,
) -> db.Job:
    asked_for: dict[str, dict[str, Any]] = {
        "node_restore_prepare": {
            "run": RUN,
            "node": "node-a",
            "archive": VERSION,
            "target": "192.0.2.120",
            "test": TEST,
        },
        "node_restore_preview": {"run": RUN, "fingerprint": FINGERPRINT},
        "node_restore": {"run": RUN, "confirm": "node-test"},
        "node_restore_discard": {"run": RUN},
        "node_restore_status": {"run": RUN},
    }
    asked = asked_for[operation]
    return queued(
        id=number,
        operation=operation,
        cluster="alpha",
        payload={**asked, **payload},
        state=state,
        outcome=None if state in {"pending", "running"} else state,
        result=result,
    )


PREPARED = job(
    "node_restore_prepare",
    "done",
    result=fixture("haprion-node-restore-prepare", "done.json"),
    number=1,
)
PREVIEWED = job(
    "node_restore_preview",
    "done",
    result=fixture("haprion-node-restore-preview", "done.json"),
    number=2,
)
SOON = PREPARED.created_at + timedelta(minutes=10)
LATE = PREPARED.created_at + node_restores.EXPIRES_AFTER + timedelta(minutes=1)
BLOCKED_PREVIEW = job(
    "node_restore_preview",
    "blocked",
    result=fixture("haprion-node-restore-preview", "blocked.json"),
    number=2,
)


class TheForm(unittest.TestCase):
    def payload(self, **changes: str) -> dict[str, Any]:
        fields = {
            "run": RUN,
            "node": "node-a",
            "archive": VERSION,
            "target": " 192.0.2.120 ",
            "mode": "new_vm",
            "test_hostname": "",
            "test_address": "",
            "test_vip": "",
            **changes,
        }
        return node_restores.prepare_payload(
            **fields, archives=[("node-a", VERSION), ("node-b", VERSION)]
        )

    def test_a_new_vm_carries_no_test_profile(self) -> None:
        self.assertEqual(
            self.payload(),
            {
                "run": RUN,
                "node": "node-a",
                "archive": VERSION,
                "target": "192.0.2.120",
                "test": None,
            },
        )

    def test_a_test_restore_carries_the_three_fields(self) -> None:
        payload = self.payload(
            mode="test",
            test_hostname="node-test",
            test_address="192.0.2.29/24",
            test_vip="198.51.100.254/32",
        )
        self.assertEqual(payload["test"], TEST)

    def test_what_is_refused_before_a_job_is_queued(self) -> None:
        for changes, words in (
            ({"archive": "2026-01-01_00-00-00"}, "not in this cluster's backup listing"),
            ({"node": "node-c"}, "not in this cluster's backup listing"),
            ({"mode": "image"}, "Choose the node or a test restore"),
            ({"target": "192.0.2.300"}, "The target is an IPv4 address"),
            (
                {"mode": "test", "test_hostname": "node-test", "test_address": "192.0.2.29"},
                "written address/prefix",
            ),
        ):
            with (
                self.subTest(changes=changes),
                self.assertRaisesRegex(node_restores.RestoreProblem, words),
            ):
                self.payload(**changes)

    def test_the_confirmation_is_the_name_in_the_plan(self) -> None:
        with self.assertRaisesRegex(node_restores.RestoreProblem, "Type node-test"):
            node_restores.run_payload(RUN, "node-a", "node-test")
        self.assertEqual(
            node_restores.run_payload(RUN, " node-test ", "node-test"),
            {"run": RUN, "confirm": "node-test"},
        )

    def test_a_fingerprint_is_held_to_the_helper_s_pattern(self) -> None:
        with self.assertRaisesRegex(node_restores.RestoreProblem, "SHA256: and 43"):
            node_restores.preview_payload(RUN, "SHA256:short")
        self.assertEqual(
            node_restores.preview_payload(RUN, FINGERPRINT)["fingerprint"], FINGERPRINT
        )
        line = f"256 {FINGERPRINT} root@node-test (ED25519)"
        self.assertEqual(node_restores.preview_payload(RUN, line)["fingerprint"], FINGERPRINT)

    def test_a_run_id_in_a_url_is_held_to_the_run_directory_s_pattern(self) -> None:
        self.assertTrue(node_restores.usable_run(RUN))
        self.assertTrue(node_restores.usable_run(node_restores.new_run_id()))
        for bad in ("new", "../../etc", "R260101-0000AAAA"):
            self.assertFalse(node_restores.usable_run(bad))


class TheRunPage(unittest.TestCase):
    def view(self, *jobs: db.Job) -> node_restores.RestoreRun:
        restore = node_restores.run_view(RUN, jobs)
        if restore is None:
            self.fail("the run has no view")
        return restore

    def test_a_run_with_no_prepare_job_does_not_exist(self) -> None:
        self.assertIsNone(node_restores.run_view(RUN, []))
        self.assertIsNone(node_restores.run_view(RUN, [PREVIEWED]))
        self.assertIsNone(node_restores.run_view("r260101-0000bbbb", [PREPARED]))

    def test_a_queued_job_is_working_and_names_its_step(self) -> None:
        restore = self.view(job("node_restore_prepare", "pending"))
        self.assertEqual(restore.stage, "working")
        self.assertTrue(restore.active)
        self.assertEqual(restore.working, "Preparing restore")
        self.assertEqual(
            node_restores.step_states(restore),
            {"prepare": "current", "preview": "waiting", "run": "waiting"},
        )

    def test_prepared_asks_for_the_fingerprint_with_the_line_to_paste(self) -> None:
        restore = self.view(PREPARED)
        self.assertEqual(restore.stage, "fingerprint")
        self.assertIn("haprion-restore-r260101-0000aaaa", restore.paste)
        self.assertEqual(restore.mode, "test")
        self.assertEqual(restore.node, "node-a")

    def test_a_failed_prepare_says_the_helper_s_words(self) -> None:
        restore = self.view(
            job(
                "node_restore_prepare",
                "blocked",
                result={
                    **fixture("haprion-node-restore", "refused.json"),
                    "operation": "node_restore_prepare",
                },
            )
        )
        self.assertEqual(restore.stage, "prepare_failed")
        self.assertIn("changed after the preview", restore.error)

    def test_a_clean_preview_asks_for_the_name_in_its_plan(self) -> None:
        restore = self.view(PREPARED, PREVIEWED)
        self.assertEqual(restore.stage, "confirm")
        self.assertEqual(restore.confirm_name, "node-test")
        self.assertEqual((restore.plan or {}).get("keepalived"), "mask")
        self.assertEqual(
            node_restores.step_states(restore),
            {"prepare": "done", "preview": "done", "run": "current"},
        )

    def test_a_blocked_preview_shows_its_plan_and_problems_and_asks_again(self) -> None:
        restore = self.view(PREPARED, BLOCKED_PREVIEW)
        self.assertEqual(restore.stage, "fingerprint")
        self.assertTrue(restore.problems)
        self.assertIsNotNone(restore.plan)
        self.assertTrue(restore.error)

    def test_a_rolled_back_run_is_failed_and_says_so(self) -> None:
        restore = self.view(
            PREPARED,
            PREVIEWED,
            job(
                "node_restore",
                "failed",
                result=fixture("haprion-node-restore", "rolled-back.json"),
                number=3,
            ),
        )
        self.assertEqual(restore.stage, "failed")
        self.assertTrue(restore.rolled_back)
        self.assertEqual(restore.failed_stage, "network")
        self.assertIn("never answered", restore.error)

    def test_a_refused_run_goes_back_to_the_preview(self) -> None:
        restore = self.view(
            PREPARED,
            PREVIEWED,
            job(
                "node_restore",
                "blocked",
                result=fixture("haprion-node-restore", "refused.json"),
                number=3,
            ),
        )
        self.assertEqual(restore.stage, "fingerprint")
        self.assertIn("preview again", restore.error)

    def test_a_done_run_carries_its_address_and_warnings(self) -> None:
        done = fixture("haprion-node-restore", "done.json")
        done["result"]["sessions"]["finish"]["warnings"] = ["prune timer state unknown"]
        restore = self.view(PREPARED, PREVIEWED, job("node_restore", "done", result=done, number=3))
        self.assertEqual(restore.stage, "done")
        self.assertEqual((restore.result or {}).get("address"), "192.0.2.29")
        self.assertEqual(restore.warnings, ("prune timer state unknown",))
        self.assertEqual(restore.warning_commands, ("",))

    def test_a_warning_one_command_answers_carries_that_command(self) -> None:
        done = fixture("haprion-node-restore", "done.json")
        done["result"]["sessions"]["apply"]["warnings"] = [
            "node preparation: /run/haproxy/keepalived.state does not exist yet. A config reload"
            " does not always produce a state transition - force one by restarting keepalived"
            " on this node once."
        ]
        restore = self.view(PREPARED, PREVIEWED, job("node_restore", "done", result=done, number=3))
        self.assertEqual(restore.warning_commands, ("sudo systemctl restart keepalived",))

    def test_the_phrases_are_still_what_the_node_script_prints(self) -> None:
        script = (Path(__file__).resolve().parents[2] / "install" / "04-node-prepare").read_text()
        printed = " ".join(re.findall(r'warn "\s*([^"]*)"', script))
        for phrase, _command in node_restores.WARNING_COMMANDS:
            self.assertIn(phrase, printed)


class RecentRuns(unittest.TestCase):
    def test_each_run_once_newest_first_read_as_its_page_reads_it(self) -> None:
        other = "r260101-0000bbbb"
        rows = [
            PREPARED,
            PREVIEWED,
            PREVIEWED,  # the same job from a second query
            replace(
                job("node_restore_prepare", "running", run=other, number=5),
                created_at=PREPARED.created_at + timedelta(minutes=5),
            ),
        ]
        recent = node_restores.recent_runs(rows, shown=lambda moment: moment, now=SOON)
        self.assertEqual([run.run for run in recent["alpha"]], [other, RUN])
        self.assertEqual(recent["alpha"][0].label, "Running")
        self.assertEqual(recent["alpha"][1].label, "Waiting for confirmation")
        self.assertEqual(recent["alpha"][1].mode, "test")

    def test_a_restored_run_is_not_listed(self) -> None:
        done = job(
            "node_restore", "done", result=fixture("haprion-node-restore", "done.json"), number=3
        )
        self.assertEqual(
            node_restores.recent_runs([PREPARED, PREVIEWED, done], shown=lambda m: m, now=SOON), {}
        )

    def test_a_rolled_back_run_says_so_and_a_cluster_lists_five(self) -> None:
        failed = job(
            "node_restore",
            "failed",
            result=fixture("haprion-node-restore", "rolled-back.json"),
            number=3,
        )
        recent = node_restores.recent_runs(
            [PREPARED, PREVIEWED, failed], shown=lambda moment: moment, now=SOON
        )
        self.assertEqual(recent["alpha"][0].label, "Failed · rolled back")
        many = [
            job("node_restore_prepare", "done", run=f"r260101-0000{index:04d}", number=index)
            for index in range(10, 17)
        ]
        self.assertEqual(
            len(node_restores.recent_runs(many, shown=lambda m: m, now=SOON)["alpha"]),
            node_restores.RECENT_PER_CLUSTER,
        )


def viewed(rows: list[db.Job], now: datetime) -> node_restores.RestoreRun:
    restore = node_restores.run_view(RUN, rows, now=now)
    if restore is None:
        raise AssertionError("the run has no view")
    return restore


class TheHour(unittest.TestCase):
    """B182: a run waiting on its operator expires an hour after it was prepared."""

    def test_a_waiting_run_expires_and_a_finished_one_keeps_its_stage(self) -> None:
        waiting = viewed([PREPARED], LATE)
        self.assertEqual(waiting.stage, "expired")
        self.assertTrue(waiting.discardable)
        confirm = viewed([PREPARED, PREVIEWED], LATE)
        self.assertEqual(confirm.stage, "expired")
        self.assertEqual(viewed([PREPARED, PREVIEWED], SOON).stage, "confirm")
        failed = job(
            "node_restore",
            "failed",
            result=fixture("haprion-node-restore", "rolled-back.json"),
            number=3,
        )
        self.assertEqual(viewed([PREPARED, PREVIEWED, failed], LATE).stage, "failed")

    def test_the_hour_is_the_engine_s(self) -> None:
        self.assertEqual(node_restores.EXPIRES_AFTER.total_seconds(), 3600)

    def test_past_its_hour_a_run_leaves_the_list_unless_it_is_working(self) -> None:
        self.assertEqual(node_restores.recent_runs([PREPARED], shown=lambda m: m, now=LATE), {})
        failed = job(
            "node_restore",
            "failed",
            result=fixture("haprion-node-restore", "rolled-back.json"),
            number=3,
        )
        self.assertEqual(
            node_restores.recent_runs([PREPARED, PREVIEWED, failed], shown=lambda m: m, now=LATE),
            {},
        )
        running = job("node_restore", "running", number=3)
        recent = node_restores.recent_runs(
            [PREPARED, PREVIEWED, running], shown=lambda m: m, now=LATE
        )
        self.assertEqual(recent["alpha"][0].label, "Running")
        self.assertFalse(recent["alpha"][0].discardable)


class Discarding(unittest.TestCase):
    def test_a_done_discard_gives_the_run_up_and_it_leaves_the_list(self) -> None:
        discarded = job("node_restore_discard", "done", number=3)
        restore = viewed([PREPARED, PREVIEWED, discarded], SOON)
        self.assertEqual(restore.stage, "discarded")
        self.assertFalse(restore.discardable)
        self.assertEqual(
            node_restores.recent_runs(
                [PREPARED, PREVIEWED, discarded], shown=lambda m: m, now=SOON
            ),
            {},
        )

    def test_a_queued_discard_is_working_and_a_refused_one_leaves_the_stage(self) -> None:
        pending = job("node_restore_discard", "pending", number=3)
        restore = viewed([PREPARED, pending], SOON)
        self.assertEqual((restore.stage, restore.working), ("working", "Discarding restore"))
        self.assertEqual(node_restores.step_states(restore)["prepare"], "done")
        refused = job(
            "node_restore_discard",
            "blocked",
            result=fixture("haprion-node-restore-discard", "refused.json"),
            number=3,
        )
        restore = viewed([PREPARED, refused], SOON)
        self.assertEqual(restore.stage, "fingerprint")
        self.assertIn("being worked on", restore.error)

    def test_the_payload_is_the_run_alone(self) -> None:
        self.assertEqual(node_restores.discard_payload(RUN), {"run": RUN})


LOST = job("node_restore", "unknown", number=3)


def asked(state: str, name: str | None = None, *, body: dict[str, Any] | None = None) -> db.Job:
    """A status job after the lost run job: a fixture's answer, or one standing."""

    if name is not None:
        result = fixture("haprion-node-restore-status", name)
    elif body is not None:
        result = {**fixture("haprion-node-restore-status", "not-started.json"), "result": body}
    else:
        result = None
    return job("node_restore_status", state, result=result, number=4)


class AskingForTheOutcome(unittest.TestCase):
    """Review 2026-09-25, track 8: a run job that lost its answer may be asked again."""

    def test_a_lost_run_is_unknown_and_may_be_asked_but_not_discarded(self) -> None:
        restore = viewed([PREPARED, PREVIEWED, LOST], SOON)
        self.assertEqual(restore.stage, "unknown")
        self.assertTrue(restore.askable)
        self.assertFalse(restore.discardable)
        self.assertEqual(node_restores.step_states(restore)["run"], "current")
        recent = node_restores.recent_runs([PREPARED, PREVIEWED, LOST], shown=lambda m: m, now=SOON)
        self.assertEqual(recent["alpha"][0].label, "Outcome unknown")

    def test_a_question_on_its_way_is_working(self) -> None:
        restore = viewed([PREPARED, PREVIEWED, LOST, asked("pending")], SOON)
        self.assertEqual((restore.stage, restore.working), ("working", "Asking for the outcome"))
        self.assertEqual(node_restores.step_states(restore)["run"], "current")

    def test_a_finished_answer_is_drawn_as_the_run_s_own(self) -> None:
        restore = viewed([PREPARED, PREVIEWED, LOST, asked("done", "finished-done.json")], SOON)
        self.assertEqual(restore.stage, "done")
        self.assertEqual((restore.result or {}).get("address"), "192.0.2.29")
        failed = viewed([PREPARED, PREVIEWED, LOST, asked("done", "finished-failed.json")], SOON)
        self.assertEqual((failed.stage, failed.failed_stage, failed.rolled_back),
                         ("failed", "network", True))  # fmt: skip
        self.assertIn("never answered", failed.error)

    def test_any_other_answer_leaves_it_unknown_with_what_was_found(self) -> None:
        for name, words in (
            ("running.json", "still running"),
            ("stopped.json", "Look at the target"),
            ("not-started.json", "never began writing"),
            ("busy.json", "ask again when it has finished"),
            ("gone.json", "no restore run"),
        ):
            with self.subTest(name=name):
                state = "blocked" if name in {"busy.json", "gone.json"} else "done"
                restore = viewed([PREPARED, PREVIEWED, LOST, asked(state, name)], SOON)
                self.assertEqual(restore.stage, "unknown")
                self.assertTrue(restore.askable)
                self.assertIn(words, restore.standing)

    def test_a_question_before_the_run_job_is_not_its_answer(self) -> None:
        early = replace(asked("done", "finished-done.json"), id=3)
        restore = viewed([PREPARED, PREVIEWED, early, replace(LOST, id=4)], SOON)
        self.assertEqual(restore.stage, "unknown")

    def test_the_payload_is_the_run_alone(self) -> None:
        self.assertEqual(node_restores.status_payload(RUN), {"run": RUN})


class RestoreRouteTestCase(DeleteRouteTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.runs: list[db.Job] = []

        def queue(_c: object, **fields: Any) -> db.Job:
            # As the database does: the row comes back with what was stored.
            self.queued.append(fields)
            return queued(
                operation=fields["operation"], cluster=fields["cluster"], payload=fields["payload"]
            )

        for patch in (
            mock.patch("haproxy_ui.db.queue_job", side_effect=queue),
            mock.patch("haproxy_ui.db.cluster_backups", return_value=[reading()]),
            mock.patch("haproxy_ui.db.restore_jobs", side_effect=lambda _c, _run: list(self.runs)),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def post(self, client: Any, path: str, **fields: str) -> Any:
        data = {
            "idempotency_key": str(uuid4()),
            auth.CSRF_FIELD: auth.csrf_token(client.cookies[auth.SESSION_COOKIE]),
            **fields,
        }
        return client.post(path, data=data, follow_redirects=False)

    def start(self, client: Any, **fields: str) -> Any:
        return self.post(
            client,
            "/backups/restore/new",
            **{
                "cluster": "alpha",
                "node": "node-a",
                "archive": VERSION,
                "target": "192.0.2.120",
                "mode": "new_vm",
                **fields,
            },
        )


class TheBackupPageOffersIt(RestoreRouteTestCase):
    def test_an_admin_gets_a_restore_link_per_archive_row(self) -> None:
        page = self.writing_client().get("/backups").text
        self.assertIn(
            f'<a class="secondary-button" href="/backups/restore/new?cluster=alpha&amp;node=node-a&amp;archive={VERSION}">Restore</a>',
            page,
        )
        self.assertIn("archive-table-restore", page)

    def test_recent_runs_are_listed_under_their_cluster_for_everyone(self) -> None:
        with mock.patch(
            "haproxy_ui.db.operation_jobs",
            side_effect=lambda _c, operation, **_k: [
                row for row in (PREPARED, PREVIEWED) if row.operation == operation
            ],
        ):
            for role in ("admin", "reader"):
                page = self.writing_client(role=role).get("/backups").text
                self.assertIn("Unfinished restores", page)
                self.assertIn(f'<a href="/backups/restore/{RUN}"><code>{RUN}</code></a>', page)
                self.assertIn("node-a · test", page)

    def test_a_reader_gets_none(self) -> None:
        page = self.writing_client(role="reader").get("/backups").text
        self.assertNotIn("/backups/restore/new", page)


class StartingARun(RestoreRouteTestCase):
    def test_the_form_names_the_archive_and_its_node(self) -> None:
        page = self.writing_client().get(
            f"/backups/restore/new?cluster=alpha&node=node-a&archive={VERSION}"
        )
        self.assertEqual(page.status_code, 200)
        self.assertIn("<h1>Restore node-a</h1>", page.text)
        self.assertIn('name="mode" value="new_vm" checked', page.text)

    def test_the_gates(self) -> None:
        path = f"/backups/restore/new?cluster=alpha&node=node-a&archive={VERSION}"
        self.assertEqual(self.writing_client(role="reader").get(path).status_code, 403)
        self.assertEqual(self.writing_client(writes=False).get(path).status_code, 404)
        client = self.writing_client()
        self.assertEqual(client.get(path.replace(VERSION, "2026-01-01_00-00-00")).status_code, 404)
        self.assertEqual(self.start(client, **{auth.CSRF_FIELD: "bad"}).status_code, 403)
        self.assertEqual(self.queued, [])

    def test_it_queues_prepare_under_a_new_run_and_goes_to_the_run(self) -> None:
        response = self.start(self.writing_client())

        self.assertEqual(response.status_code, 303)
        self.assertEqual(len(self.queued), 1)
        queued_job = self.queued[0]
        self.assertEqual(queued_job["operation"], "node_restore_prepare")
        self.assertEqual(queued_job["cluster"], "alpha")
        run = queued_job["payload"]["run"]
        self.assertTrue(node_restores.usable_run(run))
        self.assertEqual(response.headers["location"], f"/backups/restore/{run}")
        self.assertEqual(
            queued_job["payload"],
            {
                "run": run,
                "node": "node-a",
                "archive": VERSION,
                "target": "192.0.2.120",
                "test": None,
            },
        )
        self.assertEqual(self.audit[-1], "queue_job")

    def test_a_refused_form_is_drawn_again_with_what_was_typed(self) -> None:
        response = self.start(self.writing_client(), target="lb-01.example.net")
        self.assertEqual(response.status_code, 200)
        self.assertIn("The target is an IPv4 address", response.text)
        self.assertIn('value="lb-01.example.net"', response.text)
        self.assertEqual(self.queued, [])

    def test_a_busy_cluster_is_said_on_the_form(self) -> None:
        with mock.patch("haproxy_ui.db.queue_job", side_effect=db.ClusterBusy()):
            response = self.start(self.writing_client())
        self.assertEqual(response.status_code, 200)
        self.assertIn("A job is already running for alpha", response.text)


class FollowingARun(RestoreRouteTestCase):
    def test_an_unknown_or_malformed_run_is_not_found(self) -> None:
        client = self.writing_client()
        self.assertEqual(client.get(f"/backups/restore/{RUN}").status_code, 404)
        self.assertEqual(client.get("/backups/restore/NOT-A-RUN").status_code, 404)

    def test_a_working_run_refreshes_itself(self) -> None:
        self.runs = [job("node_restore_prepare", "running")]
        page = self.writing_client().get(f"/backups/restore/{RUN}").text
        self.assertIn(
            '<meta name="haproxy-live" content="5"><noscript><meta http-equiv="refresh" content="5"></noscript>',
            page,
        )
        self.assertIn("Preparing restore.", page)

    def test_a_warning_s_command_is_offered_with_a_copy_button(self) -> None:
        done = fixture("haprion-node-restore", "done.json")
        done["result"]["sessions"]["apply"]["warnings"] = [
            "node preparation: /run/haproxy/keepalived.state does not exist yet."
        ]
        self.runs = [PREPARED, PREVIEWED, job("node_restore", "done", result=done, number=3)]
        page = self.writing_client().get(f"/backups/restore/{RUN}").text
        self.assertIn(
            '<pre class="receiver-command" data-copy-beside><code>sudo systemctl restart keepalived</code></pre>',
            page,
        )

    def test_a_prepared_run_shows_the_line_and_asks_for_the_fingerprint(self) -> None:
        self.runs = [PREPARED]
        page = self.writing_client().get(f"/backups/restore/{RUN}").text
        self.assertIn("haprion-restore-r260101-0000aaaa", page)
        self.assertIn('<pre class="receiver-command" data-copy-beside>', page)
        self.assertIn('maxlength="512"', page)
        self.assertIn("/copy-command.js", page)
        self.assertIn(f'action="/backups/restore/{RUN}/preview"', page)
        self.assertNotIn("http-equiv", page)

    def test_the_plan_names_the_node_bundle_and_what_the_archive_does_not_give(self) -> None:
        """B178/B180: the release's bundle writes the scripts; the VM keeps its own files."""

        self.runs = [PREPARED, PREVIEWED]
        page = self.writing_client().get(f"/backups/restore/{RUN}").text
        self.assertIn("<code>haproxy-manager-node-000000000000</code> from this manager", page)
        self.assertIn("in place of the archive's 2", page)
        self.assertIn("turns the traffic log on, as it was", page)
        self.assertIn("account svc-logread gets a free UID", page)
        self.assertIn(
            "<code>/etc/ssh/sshd_config,</code> <code>/etc/sudoers.d/90-cloud-init-users</code>",
            page,
        )

    def test_a_blocked_preview_offers_the_way_back(self) -> None:
        self.runs = [PREPARED, BLOCKED_PREVIEW]
        page = self.writing_client().get(f"/backups/restore/{RUN}").text
        stops = page.split("What stops this restore", 1)[1].split("</section>", 1)[0]
        self.assertIn('<a class="secondary-button" href="/backups">Back to backups</a>', stops)

    def test_a_reader_sees_the_run_but_no_forms(self) -> None:
        self.runs = [PREPARED]
        page = self.writing_client(role="reader").get(f"/backups/restore/{RUN}").text
        self.assertIn("<h1>Restore node-a</h1>", page)
        #
        # The header's two forms are on every page: signing out, and the search.
        #
        chrome = r'<form (?:method="post" action="/logout"|class="header-search").*?</form>'
        self.assertNotIn("<form", re.sub(chrome, "", page, flags=re.S))

    def test_the_fingerprint_queues_the_preview(self) -> None:
        self.runs = [PREPARED]
        response = self.post(
            self.writing_client(), f"/backups/restore/{RUN}/preview", fingerprint=FINGERPRINT
        )
        self.assertEqual(response.status_code, 303)
        self.assertEqual(self.queued[0]["operation"], "node_restore_preview")
        self.assertEqual(self.queued[0]["payload"], {"run": RUN, "fingerprint": FINGERPRINT})

    def test_a_clean_preview_shows_the_plan_and_the_confirmation(self) -> None:
        self.runs = [PREPARED, PREVIEWED]
        page = self.writing_client().get(f"/backups/restore/{RUN}").text
        self.assertIn("Masked — never started", page)
        self.assertIn("Type <code>node-test</code> to confirm", page)
        self.assertIn(f'action="/backups/restore/{RUN}/run"', page)

    def test_a_blocked_preview_says_each_problem_once_and_asks_again(self) -> None:
        self.runs = [PREPARED, BLOCKED_PREVIEW]
        page = self.writing_client().get(f"/backups/restore/{RUN}").text
        preview = BLOCKED_PREVIEW.result or {}
        (problem,) = preview["result"]["problems"][:1]
        self.assertEqual(page.count(problem), 1)
        self.assertIn("What stops this restore", page)
        self.assertIn(f'action="/backups/restore/{RUN}/preview"', page)
        self.assertNotIn(f'action="/backups/restore/{RUN}/run"', page)

    def test_the_wrong_name_is_refused_and_the_right_one_queues_the_run(self) -> None:
        self.runs = [PREPARED, PREVIEWED]
        client = self.writing_client()
        refused = self.post(client, f"/backups/restore/{RUN}/run", confirm="node-a")
        self.assertEqual(refused.status_code, 200)
        self.assertIn("Type node-test to restore this node.", refused.text)
        self.assertEqual(self.queued, [])

        response = self.post(client, f"/backups/restore/{RUN}/run", confirm="node-test")
        self.assertEqual(response.status_code, 303)
        self.assertEqual(self.queued[0]["operation"], "node_restore")
        self.assertEqual(self.queued[0]["payload"], {"run": RUN, "confirm": "node-test"})

    def test_a_finished_run_offers_the_way_back(self) -> None:
        self.runs = [
            PREPARED,
            PREVIEWED,
            job(
                "node_restore",
                "done",
                result=fixture("haprion-node-restore", "done.json"),
                number=3,
            ),
        ]
        page = self.writing_client().get(f"/backups/restore/{RUN}").text
        self.assertIn("<strong>Restored.</strong>", page)
        self.assertIn('href="/backups">Back to node backups</a>', page)

    def test_the_jobs_page_leads_back_to_the_run(self) -> None:
        stray = job("node_restore_preview", "done", run="../../etc", number=9)
        with mock.patch("haproxy_ui.db.recent_jobs", return_value=[PREVIEWED, PREPARED, stray]):
            page = self.writing_client().get("/jobs").text
        self.assertEqual(page.count(f'<a href="/backups/restore/{RUN}">'), 2)
        self.assertNotIn("/backups/restore/../", page)

    def test_a_step_out_of_order_is_refused(self) -> None:
        self.runs = [PREPARED]
        response = self.post(
            self.writing_client(), f"/backups/restore/{RUN}/run", confirm="node-test"
        )
        self.assertIn("no preview waiting for confirmation", response.text)
        self.assertEqual(self.queued, [])

    def test_the_step_routes_have_the_form_s_gates(self) -> None:
        self.runs = [PREPARED]
        path = f"/backups/restore/{RUN}/preview"
        self.assertEqual(
            self.post(
                self.writing_client(role="reader"), path, fingerprint=FINGERPRINT
            ).status_code,
            403,
        )
        self.assertEqual(
            self.post(
                self.writing_client(), path, fingerprint=FINGERPRINT, **{auth.CSRF_FIELD: "bad"}
            ).status_code,
            403,
        )
        self.assertEqual(self.queued, [])


OVERWRITE_PREPARED = job(
    "node_restore_prepare",
    "done",
    result=fixture("haprion-node-restore-prepare", "done.json"),
    number=1,
    target="192.0.2.21",
    test=None,
)
OVERWRITE_PREVIEWED = job(
    "node_restore_preview",
    "done",
    result=fixture("haprion-node-restore-preview", "overwrite.json"),
    number=2,
)


class OverwritingANode(RestoreRouteTestCase):
    """B172/B183: the archive over the running node, confirmed in three steps."""

    def test_the_form_asks_only_node_or_test(self) -> None:
        """B184: over the node or onto a VM is the preview's to tell, not the form's."""

        page = (
            self.writing_client()
            .get(f"/backups/restore/new?cluster=alpha&node=node-a&archive={VERSION}")
            .text
        )
        self.assertNotIn('value="overwrite"', page)
        self.start(self.writing_client(), mode="new_vm", target="192.0.2.21")
        self.assertNotIn("overwrite", self.queued[0]["payload"])

    def test_before_its_preview_a_run_as_the_node_is_not_yet_an_overwrite(self) -> None:
        restore = node_restores.run_view(RUN, [OVERWRITE_PREPARED])
        if restore is None:
            self.fail("the run has a prepare job")
        self.assertEqual(restore.mode, "new_vm")

    def test_the_form_suggests_the_nodes_own_address(self) -> None:
        status = SimpleNamespace(
            cluster="alpha",
            result={"nodes": [{"name": "node-a", "mgmt_host": "node-a.example.com"}]},
        )
        found = node_restores.node_address(
            [status], "alpha", "node-a", resolve=lambda host: "192.0.2.21"
        )
        self.assertEqual(found, "192.0.2.21")
        literal = SimpleNamespace(
            cluster="alpha", result={"nodes": [{"name": "node-a", "mgmt_host": "192.0.2.21"}]}
        )
        self.assertEqual(node_restores.node_address([literal], "alpha", "node-a"), "192.0.2.21")
        self.assertEqual(
            node_restores.node_address([status], "alpha", "node-a", resolve=lambda _h: ""), ""
        )
        self.assertEqual(node_restores.node_address([status], "beta", "node-a"), "")

    def test_a_lost_answer_is_an_unknown_outcome_not_a_failure(self) -> None:
        unknown = job("node_restore", "unknown", number=3, confirm="node-a")
        self.runs = [OVERWRITE_PREPARED, OVERWRITE_PREVIEWED, unknown]
        page = self.writing_client().get(f"/backups/restore/{RUN}").text
        self.assertIn("<strong>Outcome unknown.</strong>", page)
        self.assertIn(f'action="/backups/restore/{RUN}/status"', page)
        self.assertNotIn("The node was not put back", page)

    def test_the_run_is_read_as_an_overwrite(self) -> None:
        restore = node_restores.run_view(RUN, [OVERWRITE_PREPARED, OVERWRITE_PREVIEWED])
        if restore is None:
            self.fail("the run has a prepare job")
        self.assertEqual((restore.mode, restore.stage), ("overwrite", "confirm"))
        self.assertTrue(restore.backup_failed)
        self.assertFalse(restore.traffic_at_risk)

    def test_the_page_says_what_changes_and_asks_for_every_tick(self) -> None:
        self.runs = [OVERWRITE_PREPARED, OVERWRITE_PREVIEWED]
        page = self.writing_client().get(f"/backups/restore/{RUN}").text
        self.assertIn("Overwrite the node", page)
        self.assertIn("/etc/keepalived/keepalived.conf", page)
        self.assertIn("1 of 42 files", page)
        self.assertNotIn("Not from the archive", page)
        self.assertIn("/etc/haprion/stray", page)
        self.assertIn("Unchanged · not applied", page)
        self.assertIn("node-a holds it; keepalived stops first and it moves to node-b", page)
        self.assertIn("none could be taken", page)
        self.assertNotIn('name="acknowledged"', page)
        self.assertIn('name="backup_failed_ok"', page)
        self.assertNotIn('name="break_traffic"', page)
        self.assertIn("Overwrite node-a</button>", page)

    def test_a_sick_neighbour_under_the_vip_asks_for_the_traffic_tick(self) -> None:
        document = fixture("haprion-node-restore-preview", "overwrite.json")
        document["result"]["overwrite"].update(neighbour_healthy=False, detail="HAProxy down")
        self.runs = [
            OVERWRITE_PREPARED,
            job("node_restore_preview", "done", result=document, number=2),
        ]
        page = self.writing_client().get(f"/backups/restore/{RUN}").text
        self.assertIn('name="break_traffic"', page)
        self.assertIn("This WILL break live traffic", page)

    def test_the_run_needs_the_tick_and_passes_the_others_on(self) -> None:
        self.runs = [OVERWRITE_PREPARED, OVERWRITE_PREVIEWED]
        client = self.writing_client()
        # The name is the confirmation; the backup tick is passed on to the helper.
        response = self.post(
            client,
            f"/backups/restore/{RUN}/run",
            confirm="node-a",
            backup_failed_ok="yes",
        )
        self.assertEqual(response.status_code, 303)
        self.assertEqual(
            self.queued[0]["payload"],
            {"run": RUN, "confirm": "node-a", "backup_failed_ok": True, "break_traffic": False},
        )

    def test_a_node_put_back_says_so(self) -> None:
        failed = job(
            "node_restore",
            "failed",
            result=fixture("haprion-node-restore", "overwrite-rolled-back.json"),
            number=3,
            confirm="node-a",
        )
        self.runs = [OVERWRITE_PREPARED, OVERWRITE_PREVIEWED, failed]
        page = self.writing_client().get(f"/backups/restore/{RUN}").text
        self.assertIn("The node was put back from its copy", page)


class AskingOnThePage(RestoreRouteTestCase):
    def test_an_admin_is_offered_the_question_and_a_reader_is_not(self) -> None:
        self.runs = [PREPARED, PREVIEWED, LOST]
        page = self.writing_client().get(f"/backups/restore/{RUN}").text
        self.assertIn("Ask for the outcome", page)
        self.assertNotIn(f'action="/backups/restore/{RUN}/discard"', page)
        reader = self.writing_client(role="reader").get(f"/backups/restore/{RUN}").text
        self.assertNotIn("/status", reader)

    def test_it_queues_the_status_job_and_returns_to_the_run(self) -> None:
        self.runs = [PREPARED, PREVIEWED, LOST]
        response = self.post(self.writing_client(), f"/backups/restore/{RUN}/status")
        self.assertEqual(response.headers["location"], f"/backups/restore/{RUN}")
        self.assertEqual(
            [(q["operation"], q["cluster"], q["payload"]) for q in self.queued],
            [("node_restore_status", "alpha", {"run": RUN})],
        )

    def test_a_known_outcome_is_not_asked_for(self) -> None:
        self.runs = [PREPARED, PREVIEWED, LOST, asked("done", "finished-done.json")]
        client = self.writing_client()
        self.assertIn("<strong>Restored.</strong>", client.get(f"/backups/restore/{RUN}").text)
        response = self.post(client, f"/backups/restore/{RUN}/status")
        self.assertIn("This run&#39;s outcome is already known.", response.text)
        self.assertEqual(self.queued, [])

    def test_what_asking_found_is_shown_beside_the_question(self) -> None:
        self.runs = [PREPARED, PREVIEWED, LOST, asked("done", "stopped.json")]
        page = self.writing_client().get(f"/backups/restore/{RUN}").text
        self.assertIn("left no outcome. Look at the target.", page)
        self.assertIn("Ask for the outcome", page)


class DiscardingARun(RestoreRouteTestCase):
    """B182: Discard on the run's page and on its line; the hour on the page."""

    def old(self, *rows: db.Job) -> list[db.Job]:
        before = datetime.now(UTC) - node_restores.EXPIRES_AFTER - timedelta(minutes=5)
        return [replace(row, created_at=before) for row in rows]

    def test_a_waiting_run_offers_discard_to_an_admin_only(self) -> None:
        self.runs = [PREPARED]
        page = self.writing_client().get(f"/backups/restore/{RUN}").text
        self.assertIn(f'action="/backups/restore/{RUN}/discard"', page)
        self.assertIn("Start the restore by ", page)
        reader = self.writing_client(role="reader").get(f"/backups/restore/{RUN}").text
        self.assertNotIn("/discard", reader)

    def test_discard_queues_the_fourth_job_and_goes_back_where_it_was_asked(self) -> None:
        self.runs = [PREPARED]
        client = self.writing_client()
        response = self.post(client, f"/backups/restore/{RUN}/discard", return_to="backups")
        self.assertEqual((response.status_code, response.headers["location"]), (303, "/backups"))
        response = self.post(client, f"/backups/restore/{RUN}/discard")
        self.assertEqual(response.headers["location"], f"/backups/restore/{RUN}")
        self.assertEqual(
            [(q["operation"], q["cluster"], q["payload"]) for q in self.queued],
            [("node_restore_discard", "alpha", {"run": RUN})] * 2,
        )
        self.assertEqual(self.audit[-1], "queue_job")

    def test_a_restored_or_working_run_is_not_discarded(self) -> None:
        done = job(
            "node_restore", "done", result=fixture("haprion-node-restore", "done.json"), number=3
        )
        client = self.writing_client()
        for rows in ([PREPARED, PREVIEWED, done], [job("node_restore_prepare", "running")]):
            self.runs = rows
            response = self.post(client, f"/backups/restore/{RUN}/discard")
            self.assertIn("This run cannot be discarded now.", response.text)
        self.assertEqual(self.queued, [])
        self.assertEqual(
            self.post(
                self.writing_client(role="reader"), f"/backups/restore/{RUN}/discard"
            ).status_code,
            403,
        )

    def test_an_expired_run_says_so_and_takes_no_fingerprint(self) -> None:
        self.runs = self.old(PREPARED)
        client = self.writing_client()
        page = client.get(f"/backups/restore/{RUN}").text
        self.assertIn("<strong>Expired.</strong>", page)
        self.assertNotIn(f'action="/backups/restore/{RUN}/preview"', page)
        self.assertIn(f'action="/backups/restore/{RUN}/discard"', page)
        response = self.post(client, f"/backups/restore/{RUN}/preview", fingerprint=FINGERPRINT)
        self.assertIn("This run has expired", response.text)
        self.runs = self.old(PREPARED, PREVIEWED)
        response = self.post(client, f"/backups/restore/{RUN}/run", confirm="node-test")
        self.assertIn("This run has expired", response.text)
        self.assertEqual(self.queued, [])

    def test_a_discarded_run_says_its_key_is_gone(self) -> None:
        self.runs = [PREPARED, job("node_restore_discard", "done", number=2)]
        page = self.writing_client().get(f"/backups/restore/{RUN}").text
        self.assertIn("<strong>Discarded.</strong>", page)
        self.assertNotIn("/discard", page)

    def test_the_backup_page_offers_discard_on_the_line_and_drops_an_expired_run(self) -> None:
        rows: list[db.Job] = [PREPARED]

        def listed(_c: object, operation: str, **_k: Any) -> list[db.Job]:
            return [row for row in rows if row.operation == operation]

        with mock.patch("haproxy_ui.db.operation_jobs", side_effect=listed):
            page = self.writing_client().get("/backups").text
            self.assertIn(
                f'<form method="post" action="/backups/restore/{RUN}/discard" class="restore-run-discard">',
                page,
            )
            reader = self.writing_client(role="reader").get("/backups").text
            self.assertNotIn("restore-run-discard", reader)
            rows[:] = self.old(PREPARED)
            self.assertNotIn("Unfinished restores", self.writing_client().get("/backups").text)
