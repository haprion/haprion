"""A draft whose object a publish changed after it was written (0080, 26-10-20).

Every publish of anything moves the version a draft was written against, so a
draft was called older than the cluster on any publish, and opening it and
saving again - what the page asked for - wrote a change made to the same object
in between away without a word: the page's fingerprint (CR-01) is taken when it
opens, from the object as it is published then. The draft now keeps the object
it was written against, and the page shows what moved since and asks.
"""

from __future__ import annotations

import unittest
from typing import Any

from haprion_ui import editor as editor_module
from haprion_ui import preview
from haprion_ui.db import ProxyDraft
from tests.test_advanced_dialog import AdvancedRouteTestCase
from tests.test_editor_page import OBSERVED, SHOP, SHOP_9090, EditorTestCase

LATER = "b" * 40


def draft(**overrides: Any) -> ProxyDraft:
    values: dict[str, Any] = {
        "cluster": "alpha",
        "object_id": "shop",
        "yaml": SHOP.replace("shop.example.com", "store.example.com"),
        "base_version": 11,
        "base_hash": LATER,
        "revision": 4,
        "updated_by": "operator",
        "updated_at": OBSERVED,
        "deleted": False,
        "stage": "draft",
        "base_document": SHOP_9090,
    }
    values.update(overrides)
    return ProxyDraft(**values)


class TheEditorShowsWhatMoved(EditorTestCase):
    PATH = "/proxies/alpha/shop/edit"

    def test_the_fields_a_publish_changed_are_shown_and_save_says_it_writes_over_them(
        self,
    ) -> None:
        self.draft = draft()

        text = self.editor().get(self.PATH).text

        self.assertIn("shop was changed by a publish after this draft was saved", text)
        self.assertIn("<dt>Servers</dt>", text)
        self.assertIn("192.0.2.10:9090", text)
        self.assertIn(">Save over them</button>", text)
        self.assertNotIn('class="primary-button">Save</button>', text)
        # One Discard, where the choice is made.
        self.assertEqual(text.count(">Discard the draft</button>"), 1)

    def test_a_saved_change_says_so(self) -> None:
        self.draft = draft(stage="saved")

        text = self.editor().get(self.PATH).text

        self.assertIn("after these changes were saved", text)
        self.assertEqual(text.count(">Discard the changes</button>"), 1)

    def test_nothing_is_shown_when_only_the_cluster_moved(self) -> None:
        self.draft = draft(base_document=SHOP)

        text = self.editor().get(self.PATH).text

        self.assertNotIn("was changed by a publish after", text)
        self.assertIn('class="primary-button">Save</button>', text)

    def test_a_row_from_before_is_left_as_it_was(self) -> None:
        self.draft = draft(base_document=None)

        text = self.editor().get(self.PATH).text

        self.assertNotIn("was changed by a publish after", text)
        self.assertIn('class="primary-button">Save</button>', text)


class WhatEachWriteKeepsAsItsBase(EditorTestCase):
    PATH = "/proxies/alpha/shop/edit"

    def test_save_from_the_form_takes_the_object_as_it_is_now(self) -> None:
        self.draft = draft()

        answer = self.submit(self.editor(), self.PATH, action="save", expected_revision="4")

        self.assertEqual(answer.status_code, 303)
        self.assertEqual(self.changes[0]["base_document"], SHOP)

    def test_save_as_draft_keeps_the_base_it_had(self) -> None:
        # A draft saved again has not been looked at against what moved; it
        # keeps saying so until Save, where the page shows it.
        self.draft = draft()

        answer = self.submit(self.editor(), self.PATH, action="draft", expected_revision="4")

        self.assertEqual(answer.status_code, 303)
        self.assertEqual(self.saved[0]["base_document"], SHOP_9090)

    def test_a_first_draft_takes_the_object_as_it_is_now(self) -> None:
        answer = self.submit(self.editor(), self.PATH, action="draft")

        self.assertEqual(answer.status_code, 303)
        self.assertEqual(self.saved[0]["base_document"], SHOP)

    def test_a_new_object_has_nothing_published_under_its_name(self) -> None:
        answer = self.submit(self.editor(), "/proxies/alpha/new", action="draft", name="bazaar")

        self.assertEqual(answer.status_code, 303)
        self.assertEqual(self.saved[0]["base_document"], "")


class TheAdvancedDialogKeepsTheSavedChangesBase(AdvancedRouteTestCase):
    def test_a_line_added_to_saved_changes_keeps_their_base(self) -> None:
        self.draft = draft(stage="saved", yaml=SHOP, revision=2)

        self.post(self.editor(), action="save", advanced="retries 5\n", expected_revision="2")

        self.assertEqual(self.changes[0]["base_document"], SHOP_9090)


class FieldByField(unittest.TestCase):
    def test_every_field_of_the_form_has_its_words(self) -> None:
        self.assertEqual(set(editor_module.FIELD_LABELS), set(preview.DEFAULTS))

    def test_a_field_is_shown_before_and_now(self) -> None:
        lines = editor_module.moved(SHOP_9090, SHOP)

        self.assertEqual(
            [(line.label, line.before, line.after) for line in lines],
            [("Servers", "192.0.2.10:9090", "192.0.2.10:8080")],
        )

    def test_an_object_published_or_removed_meanwhile_is_one_line(self) -> None:
        self.assertEqual(
            editor_module.moved("", SHOP),
            (editor_module.Moved("Object", "Not published", "Published"),),
        )
        self.assertEqual(
            editor_module.moved(SHOP, ""), (editor_module.Moved("Object", "Published", "Removed"),)
        )

    def test_the_same_object_is_nothing(self) -> None:
        self.assertEqual(editor_module.moved(SHOP, SHOP + "\n"), ())


if __name__ == "__main__":
    unittest.main()
