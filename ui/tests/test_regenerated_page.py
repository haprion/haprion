"""What publishing a cluster again would change: the page and its one button (0.99.11)."""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace
from typing import Any
from unittest import mock
from uuid import uuid4

from haprion_ui import auth, db, regenerated
from tests.test_attention import regeneration
from tests.test_history import reading
from tests.test_login import LoginTestCase, configuration

HEAD = "a" * 40
DIFF = {
    "commit": HEAD,
    "parent": None,
    "truncated": False,
    "files": [
        {
            "path": "nodes/node-a/haproxy.cfg",
            "status": "modified",
            "old_path": None,
            "added": 1,
            "removed": 1,
            "binary": False,
            "lines": ["@@ -1,2 +1,2 @@", " frontend shop", "-    option old", "+    option new"],
        }
    ],
}
CAUSE = {"kind": "rule_set", "published": "4.25.1", "installed": "4.25.2"}


def changed(**more: Any) -> db.ClusterRegeneration:
    return regeneration(causes=[CAUSE], diff=DIFF, **more)


class TheView(LoginTestCase):
    def test_a_reading_that_was_not_made_has_nothing_to_show(self) -> None:
        for row in (None, regeneration(reading="failed"), regeneration(reading="unavailable")):
            self.assertEqual(regenerated.build("alpha", row).state, "unread")

    def test_the_states_are_the_engines_outcomes(self) -> None:
        for outcome in ("changed", "refused", "unchanged", "unpublished"):
            row = regeneration(outcome=outcome)
            self.assertEqual(regenerated.build("alpha", row).state, outcome)


class ThePage(LoginTestCase):
    def page(
        self,
        row: db.ClusterRegeneration | None,
        *,
        role: str = "admin",
        writes: bool = True,
        unpublished: int = 0,
        path: str = "/history/alpha/regenerated",
        running: list[Any] | None = None,
    ) -> Any:
        self.account = replace(self.account, role=role)
        client = self.client(
            replace(configuration(), clusters=("alpha",), management_writes=writes)
        )
        self.sign_in(client)
        with (
            mock.patch("haprion_ui.db.cluster_regeneration", return_value=[row] if row else []),
            mock.patch(
                "haprion_ui.db.cluster_histories",
                return_value=[reading(published=11, unpublished=unpublished)],
            ),
            mock.patch("haprion_ui.db.recent_jobs", return_value=running or []),
        ):
            return client.get(path)

    def test_the_causes_the_objects_and_the_difference_are_drawn(self) -> None:
        row = changed(
            objects=[{"name": "shop", "change": "changed", "parts": ["backends", "routing"]}]
        )
        text = self.page(row).text

        self.assertIn("Publishing again would change what alpha runs", text)
        self.assertIn("The WAF rule set 4.25.1 → 4.25.2", text)
        self.assertIn("<strong>shop</strong>", text)
        self.assertIn("backends, routing", text)
        self.assertIn(
            '<span class="diff-del">-    option old</span><span class="diff-add">+    option new</span>',
            text,
        )

    def test_an_admin_with_writes_on_publishes_and_deploys_from_it(self) -> None:
        text = self.page(changed()).text

        self.assertIn('action="/history/alpha/regenerated"', text)
        self.assertIn("Publish &amp; deploy", text)
        self.assertIn(f'name="expected_head" value="{HEAD}"', text)
        self.assertIn(f'name="fingerprint" value="{"a" * 64}"', text)

    def test_with_writes_off_the_difference_is_there_and_the_form_is_not(self) -> None:
        text = self.page(changed(), writes=False).text

        self.assertIn("option new", text)
        self.assertNotIn("Publish &amp; deploy", text)
        self.assertNotIn('method="post"', text.split("<main", 1)[1])

    def test_a_reader_sees_what_would_change_but_not_the_files_nor_the_form(self) -> None:
        """The generated files carry what an object page keeps from a reader (review 26-10-22, 5-3)."""

        text = self.page(changed(), role="reader").text

        self.assertIn("Publishing again would change what alpha runs", text)
        self.assertIn("<strong>shop</strong>", text)
        self.assertNotIn("option new", text)
        self.assertNotIn("Publish &amp; deploy", text)

    def test_versions_saved_after_the_published_one_are_said_to_come_along(self) -> None:
        self.assertIn(
            "Publishing also carries the 2 versions saved after the published one",
            self.page(changed(), unpublished=2).text,
        )
        self.assertNotIn("Publishing also carries", self.page(changed(), unpublished=0).text)

    def test_a_refusal_says_why_and_offers_nothing(self) -> None:
        text = self.page(regeneration(outcome="refused", message="a listener clashes")).text

        self.assertIn("The installed version cannot publish alpha again", text)
        self.assertIn("a listener clashes", text)
        self.assertNotIn("Publish &amp; deploy", text)

    def test_when_there_is_nothing_to_show_the_page_says_so_plainly(self) -> None:
        for row, words in (
            (regeneration(outcome="unchanged"), "would not change what alpha runs"),
            (regeneration(outcome="unpublished"), "Nothing is published for alpha yet"),
            (None, "has not been read for alpha yet"),
            (regeneration(reading="failed"), "has not been read for alpha yet"),
        ):
            with self.subTest(words=words):
                text = self.page(row).text
                self.assertIn(words, text)
                self.assertNotIn("Publish &amp; deploy", text)

    def test_a_busy_cluster_has_the_badge_in_place_of_the_form(self) -> None:
        from tests.test_job_page import job

        text = self.page(changed(), running=[job(state="running", operation="deploy")]).text
        self.assertNotIn("Publish &amp; deploy", text)
        self.assertIn('data-busy="alpha"', text)

    def test_a_cluster_that_is_not_listed_is_a_404(self) -> None:
        self.assertEqual(self.page(changed(), path="/history/beta/regenerated").status_code, 404)


class ThePublish(LoginTestCase):
    def post(
        self,
        row: db.ClusterRegeneration | None,
        *,
        role: str = "admin",
        writes: bool = True,
        **form: Any,
    ) -> tuple[Any, mock.Mock]:
        self.account = replace(self.account, role=role)
        client = self.client(
            replace(configuration(), clusters=("alpha",), management_writes=writes)
        )
        self.sign_in(client)
        queued = mock.Mock(return_value=SimpleNamespace(id=9, request_id=uuid4()))
        data = {
            "csrf_token": auth.csrf_token(client.cookies[auth.SESSION_COOKIE]),
            "expected_head": HEAD,
            "fingerprint": "a" * 64,
            "idempotency_key": str(uuid4()),
            **form,
        }
        with (
            mock.patch("haprion_ui.db.cluster_regeneration", return_value=[row] if row else []),
            mock.patch("haprion_ui.db.cluster_histories", return_value=[reading(published=11)]),
            mock.patch("haprion_ui.db.queue_job", queued),
        ):
            return client.post(
                "/history/alpha/regenerated", data=data, follow_redirects=False
            ), queued

    def test_it_queues_the_publish_of_the_layer_made_again_with_a_deploy(self) -> None:
        answer, queued = self.post(changed())

        self.assertEqual(answer.status_code, 303, answer.text)
        self.assertEqual(queued.call_args.kwargs["operation"], "changes_publish")
        self.assertEqual(
            queued.call_args.kwargs["payload"],
            {
                "regenerate": True,
                "expected_head": HEAD,
                "comment": "Regenerated with the installed version.",
                "requested_by": "operator",
                "deploy": True,
            },
        )
        self.assertIn("queue_job", self.audit)

    def test_the_same_form_sent_twice_is_one_request(self) -> None:
        key = str(uuid4())
        _, first = self.post(changed(), idempotency_key=key)
        _, second = self.post(changed(), idempotency_key=key)

        self.assertEqual(
            first.call_args.kwargs["idempotency_key"], second.call_args.kwargs["idempotency_key"]
        )

    def test_a_page_drawn_before_the_answer_or_the_head_moved_publishes_nothing(self) -> None:
        forms: tuple[dict[str, Any], ...] = ({"fingerprint": "b" * 64}, {"expected_head": "c" * 40})
        for form in forms:
            with self.subTest(form=form):
                answer, queued = self.post(changed(), **form)
                self.assertEqual(answer.status_code, 400)
                self.assertIn("Read it again before publishing", answer.text)
                queued.assert_not_called()

    def test_there_is_nothing_to_publish_where_nothing_would_change(self) -> None:
        for row in (
            regeneration(outcome="unchanged"),
            regeneration(outcome="refused"),
            None,
        ):
            answer, queued = self.post(row)
            self.assertEqual(answer.status_code, 400)
            queued.assert_not_called()

    def test_a_reader_and_writes_off_publish_nothing(self) -> None:
        _, queued = self.post(changed(), role="reader")
        queued.assert_not_called()
        answer, queued = self.post(changed(), writes=False)
        self.assertEqual(answer.status_code, 404)
        queued.assert_not_called()

    def test_a_wrong_csrf_token_publishes_nothing(self) -> None:
        answer, queued = self.post(changed(), csrf_token="0" * 64)
        self.assertEqual(answer.status_code, 403)
        queued.assert_not_called()
