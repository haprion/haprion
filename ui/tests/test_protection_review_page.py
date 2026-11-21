"""Protection review as a page: the view, Accept, Undo, its switches and the links into the form (B517, 12)."""

from __future__ import annotations

import re
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any
from unittest import mock

from haprion_ui.db import ClusterInventory, ReviewAck, ReviewView
from haprion_ui.templates import STATIC_DIRECTORY
from tests.test_editor_page import OBJECTS, EditorTestCase

AT = datetime(2026, 11, 20, 9, 0, tzinfo=UTC)


def inventory(*by_hand: str, poll_error: str | None = None) -> ClusterInventory:
    """alpha's published frontends, with the proxies written by hand named."""

    return ClusterInventory(
        cluster="alpha",
        observed_at=AT,
        outcome="done",
        result={
            "version": "v9",
            "proxies": [
                {
                    "name": name,
                    "protocol": "http",
                    "managed": False,
                    "enabled": True,
                    "hostnames": [f"{name}.example.com"],
                    "ports": [80],
                    "backend_count": 1,
                }
                for name in by_hand
            ],
        }
        if poll_error is None
        else {},
        warnings=[],
        error=None,
        poll_error=poll_error,
    )


class TheReviewPage(EditorTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.review_acks: dict[tuple[str, str], ReviewAck] = {}
        self.view = ReviewView()
        self.accepted: list[dict[str, Any]] = []
        self.undone: list[dict[str, Any]] = []
        self.views: list[ReviewView] = []
        self.audited: list[str] = []
        self.forgotten: list[set[tuple[str, str]]] = []
        for target, side_effect in (
            ("review_state", lambda _c: (dict(self.review_acks), self.view)),
            ("accept_review", self._accept),
            ("undo_review", self._undo),
            ("set_review_view", self._set_view),
            ("record_audit_event", self._audit),
            ("forget_review_acks", lambda _c, gone: self.forgotten.append(set(gone))),
        ):
            patch = mock.patch(f"haprion_ui.db.{target}", side_effect=side_effect)
            patch.start()
            self.addCleanup(patch.stop)

    def _accept(self, _c: object, **values: Any) -> None:
        self.accepted.append(values)

    def _undo(self, _c: object, **values: Any) -> bool:
        self.undone.append(values)
        return True

    def _set_view(self, _c: object, view: ReviewView, **_kw: Any) -> None:
        self.views.append(view)

    def _audit(self, _c: object, **values: Any) -> None:
        if values["action"] != "login":
            self.audited.append(values["action"])

    def row(self, page: str, name: str) -> str:
        found = re.search(rf'<tr data-href="/proxies/alpha/{name}"[^>]*>.*?</tr>', page, re.S)
        if found is None:
            self.fail(f"no row for {name}")
        return found[0]

    def test_a_row_says_what_protects_it_less_and_an_admin_may_accept_it(self) -> None:
        page = self.editor().get("/proxies/review").text

        shop = self.row(page, "shop")
        self.assertIn("No rate limit", shop)
        self.assertIn('href="/proxies/alpha/shop/edit?open=limits&amp;focus=rate_limit"', shop)
        self.assertIn(">Everywhere<", shop)
        self.assertIn(">Accept</button>", shop)
        self.assertRegex(page, r"Protection review <b>1</b>")
        self.assertIn("1 to review", page)

    def test_accept_takes_the_marks_the_row_has_now(self) -> None:
        client = self.editor()

        answer = self.submit(client, "/proxies/review/accept", cluster="alpha", name="shop")

        self.assertEqual(answer.status_code, 303)
        self.assertEqual(len(self.accepted), 1)
        self.assertEqual(self.accepted[0]["subject"], "shop")
        self.assertIn("no-rate-limit", self.accepted[0]["weaknesses"])
        self.assertEqual(self.audited, ["protection_review_accepted"])

    def test_a_row_the_page_does_not_show_is_accepted_by_nothing(self) -> None:
        self.submit(self.editor(), "/proxies/review/accept", cluster="alpha", name="nobody")

        self.assertEqual(self.accepted, [])
        self.assertEqual(self.audited, [])

    def test_an_accepted_row_is_dimmed_with_who_and_undo(self) -> None:
        self.review_acks[("alpha", "shop")] = ReviewAck(
            frozenset({"waf-off", "no-rate-limit"}), "operator", AT
        )
        page = self.editor().get("/proxies/review").text

        shop = self.row(page, "shop")
        self.assertIn('class="is-accepted"', shop)
        self.assertIn("Accepted by operator", shop)
        self.assertIn(">Undo</button>", shop)
        self.assertRegex(page, r"Protection review <b>0</b>")

    def test_a_mark_that_came_since_says_new(self) -> None:
        self.review_acks[("alpha", "shop")] = ReviewAck(frozenset({"waf-off"}), "operator", AT)
        shop = self.row(self.editor().get("/proxies/review").text, "shop")

        self.assertIn('<span class="review-new">New</span>&nbsp;· No rate limit', shop)
        self.assertIn("was-accepted", shop)

    def test_undo_takes_the_acceptance_back(self) -> None:
        self.submit(self.editor(), "/proxies/review/undo", cluster="alpha", name="shop")

        self.assertEqual(self.undone, [{"cluster": "alpha", "subject": "shop"}])
        self.assertEqual(self.audited, ["protection_review_undone"])

    def test_a_cluster_switch_hides_it_for_everybody(self) -> None:
        client = self.editor()

        self.submit(client, "/proxies/review/view", switch="cluster", cluster="alpha", on="0")
        self.submit(client, "/proxies/review/view", switch="clean", on="0")

        self.assertEqual(
            self.views,
            [
                ReviewView(show_clean=True, hidden_clusters=frozenset({"alpha"})),
                ReviewView(show_clean=False, hidden_clusters=frozenset()),
            ],
        )
        self.view = self.views[0]
        page = client.get("/proxies/review").text
        self.assertNotIn('id="review-alpha"', page)
        self.assertRegex(page, r"Protection review <b>0</b>")

    def test_a_switch_asked_for_nothing_is_refused(self) -> None:
        answer = self.submit(self.editor(), "/proxies/review/view", switch="other", on="1")

        self.assertEqual(answer.status_code, 400)
        self.assertEqual(self.views, [])

    def test_a_reader_reads_the_review_and_changes_nothing(self) -> None:
        self.account = replace(self.account, role="reader")
        client = self.client(replace(self.editor().app.state.config, management_writes=True))
        self.sign_in(client)

        page = client.get("/proxies/review").text

        self.assertIn("No rate limit", page)
        self.assertIn('href="/proxies/alpha/shop"', page)
        self.assertNotIn("/edit?open=", page)
        self.assertNotIn(">Accept</button>", page)
        self.assertRegex(page, r'class="toggle-switch"[^>]*disabled')

    def test_a_failed_reading_forgets_no_acceptance(self) -> None:
        self.review_acks[("alpha", "shop")] = ReviewAck(frozenset({"waf-off"}), "operator", AT)
        failed = replace(OBJECTS, outcome="unavailable", result={})

        with mock.patch("haprion_ui.db.cluster_objects", return_value=[failed]):
            self.assertEqual(self.editor().get("/proxies/review").status_code, 200)

        self.assertEqual(self.forgotten, [])

    def test_a_good_reading_without_the_object_forgets_its_acceptance(self) -> None:
        self.review_acks[("alpha", "old")] = ReviewAck(frozenset({"waf-off"}), "operator", AT)

        with mock.patch("haprion_ui.db.cluster_inventories", return_value=[inventory()]):
            self.assertEqual(self.editor().get("/proxies/review").status_code, 200)

        self.assertEqual(self.forgotten, [{("alpha", "old")}])

    def test_a_failed_inventory_forgets_no_acceptance_of_a_proxy_written_by_hand(self) -> None:
        self.review_acks[("alpha", "legacy")] = ReviewAck(frozenset({"waf-off"}), "operator", AT)
        failed = inventory(poll_error="the helper did not answer")

        with mock.patch("haprion_ui.db.cluster_inventories", return_value=[failed]):
            self.assertEqual(self.editor().get("/proxies/review").status_code, 200)

        self.assertEqual(self.forgotten, [])

    def test_a_good_inventory_keeps_the_acceptance_of_a_proxy_written_by_hand(self) -> None:
        self.review_acks[("alpha", "legacy")] = ReviewAck(frozenset({"waf-off"}), "operator", AT)

        with mock.patch("haprion_ui.db.cluster_inventories", return_value=[inventory("legacy")]):
            self.assertEqual(self.editor().get("/proxies/review").status_code, 200)

        self.assertEqual(self.forgotten, [])

    def test_every_form_on_the_page_keeps_the_reader_s_place(self) -> None:
        """Pass U: Accept, Undo and the switches redirect back; page.js puts the reader back."""

        page = self.editor().get("/proxies/review").text
        forms = re.findall(r"<form [^>]*>", page)
        self.assertTrue(any("/proxies/review/accept" in form for form in forms))
        self.assertTrue(any("/proxies/review/view" in form for form in forms))
        template = (STATIC_DIRECTORY.parent / "templates" / "proxy-review.html").read_text()
        self.assertEqual(template.count('method="post"'), template.count("data-keep-place"))
        for form in forms:
            if 'action="/proxies/review/' in form:
                with self.subTest(form):
                    self.assertIn("data-keep-place", form)

    def test_the_tab_is_on_the_proxies_page_too(self) -> None:
        page = self.editor().get("/proxies").text

        self.assertIn('href="/proxies/review"', page)
        self.assertRegex(page, r"Protection review <b>1</b>")


class TheFormOpensAtAField(EditorTestCase):
    def test_a_link_opens_its_group_and_names_the_field(self) -> None:
        page = self.editor().get("/proxies/alpha/shop/edit?open=limits&focus=rate_limit").text

        self.assertIn('data-focus="rate_limit"', page)
        title = page.index('<span class="form-group-title">Limits</span>')
        opening = page[page.rindex("<details", 0, title) : title].split(">")[0]
        self.assertIn(" open", opening)

    def test_a_group_or_field_the_form_does_not_have_is_ignored(self) -> None:
        page = self.editor().get("/proxies/alpha/shop/edit?open=nothing&focus=x%22y").text

        self.assertNotIn("data-focus", page)
        self.assertNotRegex(page, r'<details class="form-group"[^>]* open')
