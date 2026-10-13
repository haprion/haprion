"""Events → Audit and the names beside jobs and drains (B275)."""

from __future__ import annotations

import re
import unittest
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest import mock
from uuid import uuid4

from haprion_ui import audit, views
from haprion_ui.db import AuditEvent
from tests.test_job_page import job
from tests.test_login import LoginTestCase

SOURCE = Path(__file__).resolve().parents[1] / "src" / "haprion_ui"
AT = datetime(2026, 10, 11, 18, 17, 2, tzinfo=UTC)

#
# Every way the interface writes an action name: as a keyword, as the admin
# command's first argument, as a pair an account change collects, or as a
# variable the recovery path sets.
#
WRITTEN = (
    re.compile(r'\baction="([a-z_]+)"'),
    re.compile(r'_audit\(\s*connection,\s*"([a-z_]+)"'),
    re.compile(r'changes\.append\(\s*\(\s*"([a-z_]+)"'),
    re.compile(r'\baction = "([a-z_]+)"'),
    re.compile(r'failed_action="([a-z_]+)"'),
)
#
# Keyword arguments named `action` that are not audit actions: a node's or a
# receiver's add and remove, and a certificate overlay's target action.
#
NOT_AUDIT = {"add", "append", "host", "remove", "publish", "store_true"}


def event(action: str, actor: str | None = "admin", **detail: Any) -> AuditEvent:
    return AuditEvent(
        id=1, at=AT, actor=actor, action=action, cluster=None, request_id=None, detail=detail
    )


class EveryActionHasASentence(unittest.TestCase):
    def test_the_table_knows_every_action_the_code_writes(self) -> None:
        written: set[str] = set()
        for path in SOURCE.glob("*.py"):
            text = path.read_text()
            for pattern in WRITTEN:
                written.update(pattern.findall(text))
        written -= NOT_AUDIT

        self.assertGreaterEqual(len(written), 25)
        self.assertEqual(written - set(audit.ACTIVITY_PHRASES), set())

    def test_every_queueable_operation_has_a_name(self) -> None:
        prepared = set(
            re.findall(r'if operation == "([a-z_]+)"', (SOURCE / "operations.py").read_text())
        )

        self.assertGreaterEqual(len(prepared), 20)
        self.assertEqual(prepared - set(audit.OPERATION_NAMES), set())


class TheSentences(unittest.TestCase):
    def test_a_drain_names_the_servers_the_object_and_the_state(self) -> None:
        text = audit.what(
            event(
                "queue_job",
                operation="server_state",
                job=2407,
                object="shop",
                state="maint",
                servers=["192.0.2.10:8080"],
            )
        )

        self.assertEqual(text, "Set 192.0.2.10:8080 on shop to maintenance (job 2407)")

    def test_a_queued_job_names_what_was_asked_for(self) -> None:
        self.assertEqual(
            audit.what(event("queue_job", operation="changes_publish", job=7)),
            "Queued Publish & deploy (job 7)",
        )

    def test_an_unknown_action_is_shown_by_its_own_name(self) -> None:
        self.assertEqual(audit.what(event("something_new")), "something_new")

    def test_a_failed_sign_in_under_an_unknown_name_hides_the_name(self) -> None:
        typed = event("login_failed", actor="hunter2", reason="rejected")
        known = event("login_failed", actor="Operator", reason="rejected")

        self.assertEqual(audit.who(typed, frozenset({"operator"})), audit.UNKNOWN_USER)
        self.assertEqual(audit.who(known, frozenset({"operator"})), "Operator")
        self.assertEqual(audit.what(typed), "Sign-in failed")

    def test_set_by_takes_the_newest_queue_for_each_server_and_state(self) -> None:
        newest = event("queue_job", actor="operator", state="drain", servers=["a:1", "b:2"])
        older = event("queue_job", actor="admin", state="drain", servers=["a:1"])

        found = audit.set_by([newest, older])

        self.assertEqual(found[("a:1", "drain")].actor, "operator")
        self.assertEqual(found[("b:2", "drain")].actor, "operator")


class ThePage(LoginTestCase):
    def test_jobs_say_who_queued_them(self) -> None:
        row = job(state="done", outcome="done")
        client = self.client()
        self.sign_in(client)
        with (
            mock.patch("haprion_ui.db.recent_jobs", return_value=[row]),
            mock.patch("haprion_ui.db.requested_by", return_value={row.request_id: "operator"}),
        ):
            page = client.get("/jobs").text

        self.assertIn("<th>By</th>", page)
        self.assertIn('<td data-label="By">operator</td>', page)
        self.assertIn(">Events</a>", page)

    def test_an_admin_reads_the_record(self) -> None:
        client = self.client()
        self.sign_in(client)
        rows = [
            AuditEvent(
                id=12,
                at=AT,
                actor="nobody-here",
                action="login_failed",
                cluster=None,
                request_id=None,
                detail={"client_ip": "192.0.2.10", "reason": "rejected"},
            ),
            AuditEvent(
                id=11,
                at=AT,
                actor="operator",
                action="queue_job",
                cluster="alpha",
                request_id=uuid4(),
                detail={"operation": "deploy", "job": 9},
            ),
        ]
        with mock.patch("haprion_ui.db.audit_events", return_value=rows):
            page = client.get("/jobs?view=audit").text

        self.assertIn('<td data-label="Who">unknown user</td>', page)
        self.assertNotIn("nobody-here", page)
        self.assertIn("Queued a deploy (job 9)", page)
        self.assertIn('<td data-label="Where">alpha</td>', page)

    def test_a_row_opens_its_detail_under_itself(self) -> None:
        client = self.client()
        self.sign_in(client)
        rows = [
            AuditEvent(
                id=21,
                at=AT,
                actor="operator",
                action="login",
                cluster=None,
                request_id=None,
                detail={"client_ip": "192.0.2.10", "role": "admin"},
            )
        ]
        with mock.patch("haprion_ui.db.audit_events", return_value=rows):
            closed = client.get("/jobs?view=audit").text
            opened = client.get("/jobs?view=audit&open=21").text

        self.assertIn('&amp;page=1&amp;open=21"', closed)
        self.assertNotIn("registry-detail", closed)
        self.assertIn("<strong>Address</strong><span>192.0.2.10</span>", opened)
        self.assertIn("<strong>Role</strong><span>admin</span>", opened)
        self.assertNotIn("tojson", opened)

    def test_pages_and_dates_are_asked_of_the_database(self) -> None:
        client = self.client()
        self.sign_in(client)
        with (
            mock.patch("haprion_ui.db.audit_events", return_value=[]) as listed,
            mock.patch("haprion_ui.db.audit_count", return_value=120),
        ):
            page = client.get("/jobs?view=audit&size=25&page=2&from=26-10-01%2000:00").text

        self.assertEqual(listed.call_args.kwargs["offset"], 25)
        self.assertEqual(listed.call_args.kwargs["limit"], 25)
        self.assertIsNotNone(listed.call_args.kwargs["since"])
        self.assertIn("26–50 of 120", page)
        self.assertIn("page=1", page)
        self.assertIn("page=3", page)
        self.assertIn('<option value="25" selected>', page)

    def test_a_page_or_row_that_is_not_a_number_is_the_first_page(self) -> None:
        # Review 26-10-13, K2: `²` passed isdigit() and int() raised.
        client = self.client()
        self.sign_in(client)
        for asked in ("²", "-1", "", "9" * 5000, "١٢"):
            with (
                self.subTest(asked=asked[:8]),
                mock.patch("haprion_ui.db.audit_events", return_value=[]) as listed,
                mock.patch("haprion_ui.db.audit_count", return_value=120),
            ):
                answer = client.get("/jobs", params={"view": "audit", "page": asked, "open": asked})
                self.assertEqual(answer.status_code, 200)
                self.assertEqual(listed.call_args.kwargs["offset"], 0)

    def test_a_time_outside_the_record_is_refused_in_words(self) -> None:
        client = self.client()
        self.sign_in(client)

        page = client.get("/jobs?view=audit&from=99-99-99%2099:99").text

        self.assertIn("Choose a valid date and time.", page)

    def test_the_page_and_the_retention_keep_the_same_two_years(self) -> None:
        script = (
            Path(__file__).resolve().parents[2] / "install/platform/bin/haprion-retention"
        ).read_text()

        self.assertIn(f"AUDIT_KEEP_DAYS={views.AUDIT_KEEP_DAYS}\n", script)

    def test_a_heading_sorts_the_whole_record_in_the_database(self) -> None:
        client = self.client()
        self.sign_in(client)
        with mock.patch("haprion_ui.db.audit_events", return_value=[]) as listed:
            default = client.get("/jobs?view=audit").text
            client.get("/jobs?view=audit&sort=who")
            by_who = dict(listed.call_args.kwargs)
            client.get("/jobs?view=audit&sort=-time")
            oldest = dict(listed.call_args.kwargs)

        self.assertIn('aria-sort="descending"', default)
        self.assertIn("sort=-time", default)
        self.assertEqual((by_who["order"], by_who["descending"]), ("who", False))
        self.assertEqual((oldest["order"], oldest["descending"]), ("time", False))

    def test_a_reader_has_no_audit_view(self) -> None:
        self.account = replace(self.account, role="reader")
        client = self.client()
        self.sign_in(client)

        page = client.get("/jobs?view=audit").text

        self.assertNotIn('href="/jobs?view=audit"', page)
        self.assertIn("<th>Operation</th>", page)


if __name__ == "__main__":
    unittest.main()
