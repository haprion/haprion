"""The files changed by hand in core/ and manual/: the row, the page and its one button (B529)."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any
from unittest import mock
from uuid import uuid4

from haprion_ui import attention, auth, db, handwritten, operations
from tests.test_history import reading
from tests.test_login import LoginTestCase, configuration

HEAD = "a" * 40
FINGERPRINT = "d" * 64
DIFF = {
    "commit": HEAD,
    "parent": None,
    "truncated": False,
    "files": [
        {
            "path": "core/haproxy.cfg",
            "status": "modified",
            "old_path": None,
            "added": 1,
            "removed": 1,
            "binary": False,
            "lines": [
                "@@ -1,2 +1,2 @@",
                " global",
                "-    tune.stick-counters 4",
                "+    tune.stick-counters 6",
            ],
        }
    ],
}
BUTTON = 'type="submit">Publish &amp; deploy</button>'


def handwritten_row(
    state: str = "pending", *, reading_outcome: str = "done", **more: Any
) -> db.ClusterHandwritten:
    result: dict[str, Any] = {"state": state, "head": HEAD}
    if state == "pending":
        result |= {
            "fingerprint": FINGERPRINT,
            "pending": [{"path": "core/haproxy.cfg", "kind": "changed"}],
            "diff": DIFF,
        }
    if state == "refused":
        result["message"] = "'core/alias.cfg' is a symbolic link"
    result |= more
    return db.ClusterHandwritten(
        cluster="alpha",
        observed_at=datetime(2026, 11, 23, 12, 0, tzinfo=UTC),
        outcome=reading_outcome,
        result=result if reading_outcome == "done" else {},
        warnings=[],
        error=None,
        poll_error=None,
    )


class TheRow(LoginTestCase):
    def test_files_waiting_are_a_row_that_leads_to_the_page(self) -> None:
        (item,) = attention.from_handwritten([handwritten_row()])

        self.assertEqual(item.kind, "handwritten")
        self.assertEqual(item.message, "Handwritten changes not published: core/haproxy.cfg")
        self.assertEqual(item.link, "/history/alpha/handwritten")
        self.assertEqual(attention.PAGES["handwritten"], "Versions")

    def test_a_draft_no_publish_can_take_is_a_row_too(self) -> None:
        (item,) = attention.from_handwritten([handwritten_row("refused")])

        self.assertIn("cannot be published", item.message)
        self.assertIn("core/alias.cfg", item.message)

    def test_clean_and_unread_are_no_row(self) -> None:
        self.assertEqual(
            attention.from_handwritten(
                [handwritten_row("clean"), handwritten_row(reading_outcome="failed")]
            ),
            [],
        )

    def test_the_files_are_named_three_and_how_many_more(self) -> None:
        many = [{"path": f"manual/conf.d/{n}.cfg", "kind": "new"} for n in range(5)]

        self.assertEqual(
            attention.handwritten_files({"pending": many}),
            "manual/conf.d/0.cfg, manual/conf.d/1.cfg, manual/conf.d/2.cfg and 2 more",
        )

    def test_other_files_are_a_new_row(self) -> None:
        (first,) = attention.from_handwritten([handwritten_row()])
        (second,) = attention.from_handwritten([handwritten_row(fingerprint="e" * 64)])

        self.assertNotEqual(first.variant, second.variant)


class TheView(LoginTestCase):
    def test_the_comment_names_the_files(self) -> None:
        view = handwritten.build("alpha", handwritten_row())

        self.assertEqual(view.comment, "Handwritten changes: core/haproxy.cfg")
        self.assertEqual(view.files, (("core/haproxy.cfg", "Changed"),))

    def test_a_reading_that_was_not_made_or_failed_has_nothing_to_publish(self) -> None:
        failed = replace(handwritten_row(reading_outcome="failed"), poll_error="no sudo rule")

        self.assertEqual(handwritten.build("alpha", None).state, "unread")
        self.assertEqual(
            (handwritten.build("alpha", failed).state, handwritten.build("alpha", failed).message),
            ("failed", "no sudo rule"),
        )


class ThePage(LoginTestCase):
    def page(
        self,
        row: db.ClusterHandwritten | None,
        *,
        role: str = "admin",
        writes: bool = True,
        head: str = HEAD,
        path: str = "/history/alpha/handwritten",
    ) -> Any:
        self.account = replace(self.account, role=role)
        client = self.client(
            replace(configuration(), clusters=("alpha",), management_writes=writes)
        )
        self.sign_in(client)
        history = reading(
            published=11,
            versions=[
                {
                    "version": 12,
                    "hash": head,
                    "created_at": "2026-08-28T14:02:11+00:00",
                    "comment": "Add a maintenance backend",
                    "current": True,
                }
            ],
        )
        with (
            mock.patch("haprion_ui.db.cluster_handwritten", return_value=[row] if row else []),
            mock.patch("haprion_ui.db.cluster_histories", return_value=[history]),
            mock.patch("haprion_ui.db.recent_jobs", return_value=[]),
        ):
            return client.get(path)

    def test_the_difference_the_comment_and_the_button_are_drawn(self) -> None:
        text = self.page(handwritten_row()).text

        self.assertIn("Handwritten changes in alpha are not published", text)
        self.assertIn('<span class="diff-add">+    tune.stick-counters 6</span>', text)
        self.assertIn('value="Handwritten changes: core/haproxy.cfg"', text)
        self.assertIn(f'name="fingerprint" value="{FINGERPRINT}"', text)
        self.assertIn(f'name="expected_head" value="{HEAD}"', text)
        self.assertIn(BUTTON, text)

    def test_a_reader_reads_the_difference_and_has_no_button(self) -> None:
        text = self.page(handwritten_row(), role="reader").text

        self.assertIn("tune.stick-counters 6", text)
        self.assertNotIn(BUTTON, text)

    def test_a_reading_made_on_an_older_version_offers_nothing(self) -> None:
        text = self.page(handwritten_row(), head="b" * 40).text

        self.assertIn("A newer version was recorded", text)
        self.assertNotIn(BUTTON, text)

    def test_nothing_to_publish_is_said_plainly(self) -> None:
        for row, words in (
            (handwritten_row("clean"), "Nothing changed by hand waits"),
            (handwritten_row("refused"), "core/alias.cfg"),
            (None, "has not been read for alpha yet"),
        ):
            with self.subTest(words=words):
                text = self.page(row).text
                self.assertIn(words, text)
                self.assertNotIn(BUTTON, text)

    def test_a_cluster_that_is_not_listed_is_a_404(self) -> None:
        self.assertEqual(
            self.page(handwritten_row(), path="/history/beta/handwritten").status_code, 404
        )


class ThePublish(LoginTestCase):
    def post(
        self,
        row: db.ClusterHandwritten | None,
        *,
        role: str = "admin",
        **form: Any,
    ) -> tuple[Any, mock.Mock]:
        self.account = replace(self.account, role=role)
        client = self.client(replace(configuration(), clusters=("alpha",), management_writes=True))
        self.sign_in(client)
        queued = mock.Mock(return_value=SimpleNamespace(id=9, request_id=uuid4()))
        data = {
            "csrf_token": auth.csrf_token(client.cookies[auth.SESSION_COOKIE]),
            "expected_head": HEAD,
            "fingerprint": FINGERPRINT,
            "comment": "Handwritten changes: core/haproxy.cfg",
            "idempotency_key": str(uuid4()),
            **form,
        }
        with (
            mock.patch("haprion_ui.db.cluster_handwritten", return_value=[row] if row else []),
            mock.patch("haprion_ui.db.cluster_histories", return_value=[reading(published=11)]),
            mock.patch("haprion_ui.db.queue_job", queued),
        ):
            return client.post(
                "/history/alpha/handwritten", data=data, follow_redirects=False
            ), queued

    def test_it_queues_the_publish_of_the_files_with_a_deploy(self) -> None:
        answer, queued = self.post(handwritten_row(), comment="  stick counters for B525  ")

        self.assertEqual(answer.status_code, 303, answer.text)
        self.assertEqual(queued.call_args.kwargs["operation"], "changes_publish")
        self.assertEqual(
            queued.call_args.kwargs["payload"],
            {
                "handwritten": FINGERPRINT,
                "expected_head": HEAD,
                "comment": "stick counters for B525",
                "requested_by": "operator",
                "deploy": True,
            },
        )
        self.assertIn("queue_job", self.audit)

    def test_a_page_drawn_before_the_files_or_the_head_moved_publishes_nothing(self) -> None:
        for form in ({"fingerprint": "e" * 64}, {"expected_head": "c" * 40}):
            with self.subTest(form=form):
                answer, queued = self.post(handwritten_row(), **form)
                self.assertEqual(answer.status_code, 400)
                self.assertIn("Read it again before publishing", answer.text)
                queued.assert_not_called()

    def test_an_empty_comment_publishes_nothing(self) -> None:
        answer, queued = self.post(handwritten_row(), comment="   ")

        self.assertEqual(answer.status_code, 400)
        queued.assert_not_called()

    def test_nothing_waiting_publishes_nothing(self) -> None:
        for row in (handwritten_row("clean"), handwritten_row("refused"), None):
            answer, queued = self.post(row)
            self.assertEqual(answer.status_code, 400)
            queued.assert_not_called()

    def test_a_reader_publishes_nothing(self) -> None:
        _, queued = self.post(handwritten_row(), role="reader")
        queued.assert_not_called()


class TheJob(LoginTestCase):
    def test_the_payload_reaches_the_helper_as_the_parameter(self) -> None:
        prepared = operations.prepare(
            operation="changes_publish",
            cluster="alpha",
            request_id=uuid4(),
            payload={
                "handwritten": FINGERPRINT,
                "expected_head": HEAD,
                "comment": "Handwritten changes: core/haproxy.cfg",
                "deploy": True,
            },
        )

        self.assertIn(f'"handwritten":"{FINGERPRINT}"', prepared.request)

    def test_it_carries_nothing_else_and_only_a_fingerprint(self) -> None:
        for extra in (
            {"handwritten": "not one"},
            {"handwritten": FINGERPRINT, "regenerate": True},
            {"handwritten": FINGERPRINT, "objects": {"shop": None}},
        ):
            with self.subTest(extra=extra), self.assertRaises(operations.BadPayload):
                operations.prepare(
                    operation="changes_publish",
                    cluster="alpha",
                    request_id=uuid4(),
                    payload={"expected_head": HEAD, "comment": "x", **extra},
                )


class TheRegeneratedPageWaits(LoginTestCase):
    """A regeneration is a publish too, and waits while files changed by hand do (B529)."""

    def test_the_page_leads_to_the_handwritten_page_and_the_publish_is_refused(self) -> None:
        from tests.test_regenerated_page import BUTTON as REGENERATE
        from tests.test_regenerated_page import changed

        client = self.client(replace(configuration(), clusters=("alpha",), management_writes=True))
        self.sign_in(client)
        with (
            mock.patch("haprion_ui.db.cluster_regeneration", return_value=[changed()]),
            mock.patch("haprion_ui.db.cluster_handwritten", return_value=[handwritten_row()]),
            mock.patch("haprion_ui.db.cluster_histories", return_value=[reading(published=11)]),
            mock.patch("haprion_ui.db.recent_jobs", return_value=[]),
            mock.patch("haprion_ui.db.queue_job") as queued,
        ):
            text = client.get("/history/alpha/regenerated").text
            answer = client.post(
                "/history/alpha/regenerated",
                data={
                    "csrf_token": auth.csrf_token(client.cookies[auth.SESSION_COOKIE]),
                    "expected_head": HEAD,
                    "fingerprint": "a" * 64,
                    "idempotency_key": str(uuid4()),
                },
                follow_redirects=False,
            )

        self.assertIn('<a href="/history/alpha/handwritten">Handwritten changes</a>', text)
        self.assertNotIn(REGENERATE, text)
        self.assertEqual(answer.status_code, 400)
        self.assertIn("Changed by hand and not published", answer.text)
        queued.assert_not_called()
