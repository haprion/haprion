"""The advanced config dialog: what it opens with, what Check says, and what Save writes (Fas 17).

The placement itself is the engine's and tested there (`tests/test_advanced.py`).
What is worth testing here is the dialog's own part: that only the text and the
pool choice change, that a refused text is not saved, that the draft is the
editor's draft, and that the switch hides the way in (B224).
"""

from __future__ import annotations

import re
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import yaml

from haproxy_ui import advanced_dialog
from haproxy_ui.db import ProxyDraft
from tests.test_editor_page import COMMIT, OBSERVED, SHOP, EditorTestCase
from tests.test_login import configuration
from tests.test_object_page import DraftReading

GOLDEN = Path(__file__).resolve().parents[2] / "tests" / "golden" / "advanced"

WRITTEN_POOL = """schema: 1
name: shop
hostnames:
- shop.example.com
listen:
  protocol: http
routes:
- path: /
  backend: web
backends:
  web:
    servers: []
advanced: |
  balance leastconn
  server app1 192.0.2.30:8080 check
  server app2 192.0.2.31:8081
"""


class OnlyTheTextAndThePoolChange(unittest.TestCase):
    def test_the_text_is_set_and_the_rest_is_kept(self) -> None:
        written = yaml.safe_load(
            advanced_dialog.apply("shop", SHOP, "retries 5\r\n", handwritten=False)
        )

        self.assertEqual(written["advanced"], "retries 5\n")
        self.assertEqual(
            {key: value for key, value in written.items() if key != "advanced"},
            yaml.safe_load(SHOP),
        )

    def test_an_empty_text_removes_the_advanced_config(self) -> None:
        stored = yaml.safe_load(SHOP) | {"advanced": "retries 5\n"}

        written = yaml.safe_load(
            advanced_dialog.apply("shop", yaml.safe_dump(stored), "  \n", handwritten=False)
        )

        self.assertNotIn("advanced", written)

    def test_ticking_the_box_hands_the_pool_to_the_text(self) -> None:
        written = yaml.safe_load(
            advanced_dialog.apply("shop", SHOP, "server app1 192.0.2.30:8080\n", handwritten=True)
        )

        self.assertEqual(written["backends"], {"web": {"servers": []}})

    def test_unticking_gives_the_pool_back_with_the_texts_servers(self) -> None:
        text = yaml.safe_load(WRITTEN_POOL)["advanced"]

        written = yaml.safe_load(
            advanced_dialog.apply("shop", WRITTEN_POOL, text, handwritten=False)
        )

        self.assertEqual(
            written["backends"],
            {
                "web": {
                    "balance": "roundrobin",
                    "health": {"type": "disabled"},
                    "servers": [
                        {"host": "192.0.2.30", "port": 8080},
                        {"host": "192.0.2.31", "port": 8081},
                    ],
                }
            },
        )

    def test_a_pool_is_not_given_back_without_servers_the_form_can_show(self) -> None:
        for text in ("balance leastconn\n", "server app1 192.0.2.30\n"):
            with self.subTest(text), self.assertRaises(ValueError):
                advanced_dialog.apply("shop", WRITTEN_POOL, text, handwritten=False)

    def test_only_an_object_with_one_pool_may_have_it_written(self) -> None:
        stored = yaml.safe_load(SHOP)
        stored["backends"]["api"] = stored["backends"]["web"]

        with self.assertRaises(ValueError):
            advanced_dialog.apply("shop", yaml.safe_dump(stored), "retries 5\n", handwritten=True)

    def test_the_dialog_opens_with_what_the_document_says(self) -> None:
        opened = advanced_dialog.opened(WRITTEN_POOL)

        self.assertTrue(opened.handwritten)
        self.assertTrue(opened.one_pool)
        self.assertIn("server app1", opened.text)
        self.assertEqual(advanced_dialog.opened(SHOP).text, "")


class CheckSaysWhereEachLineGoes(unittest.TestCase):
    def test_every_line_has_a_fate(self) -> None:
        answer = advanced_dialog.check("shop", (GOLDEN / "shop.yaml").read_text(encoding="utf-8"))

        self.assertEqual(answer.problem, "")
        self.assertIn(("placed", "pool"), {(line.fate, line.where) for line in answer.lines})

    def test_a_refused_line_is_shown_and_the_object_refused(self) -> None:
        document = advanced_dialog.apply("shop", SHOP, "use_backend other\n", handwritten=False)

        answer = advanced_dialog.check("shop", document)

        self.assertEqual([line.fate for line in answer.lines], ["refused"])
        self.assertTrue(answer.problem)


class TheDialogsRoute(EditorTestCase):
    PATH = "/proxies/alpha/shop/advanced"

    def post(self, client: object, **fields: str) -> object:
        data = {"csrf_token": self.token(client), "action": "check", "advanced": ""} | fields
        return client.post(self.PATH, data=data, follow_redirects=False)  # type: ignore[attr-defined]

    def test_check_draws_the_lines_and_saves_nothing(self) -> None:
        answer = self.post(self.editor(), advanced="retries 5\n")

        self.assertEqual(answer.status_code, 200)  # type: ignore[attr-defined]
        self.assertIn("retries 5", answer.text)  # type: ignore[attr-defined]
        self.assertIn("status-badge-healthy", answer.text)  # type: ignore[attr-defined]
        self.assertEqual(self.saved, [])

    def test_save_writes_the_draft_and_names_the_page(self) -> None:
        answer = self.post(self.editor(), action="save", advanced="retries 5\n")

        self.assertIn('data-advanced-saved="/proxies/alpha/shop?saved=1"', answer.text)  # type: ignore[attr-defined]
        self.assertEqual(yaml.safe_load(self.saved[0]["yaml"])["advanced"], "retries 5\n")
        self.assertEqual(self.saved[0]["base_hash"], COMMIT)
        self.assertIsNone(self.saved[0]["expected_revision"])

    def test_a_refused_text_is_not_saved(self) -> None:
        answer = self.post(self.editor(), action="save", advanced="use_backend other\n")

        self.assertIn("status-badge-critical", answer.text)  # type: ignore[attr-defined]
        self.assertNotIn("data-advanced-saved", answer.text)  # type: ignore[attr-defined]
        self.assertEqual(self.saved, [])

    def test_nothing_changed_is_not_a_draft(self) -> None:
        answer = self.post(self.editor(), action="save", advanced="")

        self.assertIn("Nothing changed", answer.text)  # type: ignore[attr-defined]
        self.assertEqual(self.saved, [])

    def test_the_draft_is_edited_against_its_revision(self) -> None:
        self.draft = ProxyDraft(
            cluster="alpha",
            object_id="shop",
            yaml=SHOP.replace("192.0.2.10", "192.0.2.11"),
            base_version=12,
            base_hash=COMMIT,
            revision=3,
            updated_by="operator",
            updated_at=OBSERVED,
            deleted=False,
        )

        self.post(self.editor(), action="save", advanced="retries 5\n", expected_revision="3")

        saved = yaml.safe_load(self.saved[0]["yaml"])
        self.assertEqual(saved["backends"]["web"]["servers"][0]["host"], "192.0.2.11")
        self.assertEqual(self.saved[0]["expected_revision"], 3)

    def test_a_revision_somebody_else_moved_is_said_in_the_dialog(self) -> None:
        self.conflict = True

        answer = self.post(self.editor(), action="save", advanced="retries 5\n")

        self.assertIn("Reload the page", answer.text)  # type: ignore[attr-defined]

    def test_the_switch_off_is_no_route(self) -> None:
        self.switches = {"advanced_config": SimpleNamespace(enabled=False)}

        answer = self.post(self.editor(), advanced="retries 5\n")

        self.assertEqual(answer.status_code, 404)  # type: ignore[attr-defined]

    def test_a_post_without_a_csrf_token_is_refused(self) -> None:
        answer = self.post(self.editor(), csrf_token="", advanced="retries 5\n")

        self.assertEqual(answer.status_code, 403)  # type: ignore[attr-defined]


class TheButtonAndTheDialogOnThePage(DraftReading):
    def page(self) -> str:
        client = self.client(replace(configuration(), demo_fixture=True, management_writes=True))
        self.sign_in(client)
        return client.get("/proxies/edge-demo/public-web").text  # type: ignore[attr-defined]

    def test_the_button_sits_between_edit_and_remove(self) -> None:
        body = self.page()

        self.assertRegex(
            body, r">Edit</a><button[^>]*data-advanced-open>Advanced config</button><a[^>]*>Remove<"
        )
        self.assertIn('<dialog class="advanced-dialog"', body)

    def test_the_switch_off_hides_the_button_and_the_dialog(self) -> None:
        self.switches = {"advanced_config": SimpleNamespace(enabled=False)}

        body = self.page()

        self.assertNotIn("data-advanced-open", body)
        self.assertNotIn("advanced-dialog", body)

    def test_the_dialog_opens_on_the_drafts_text_and_pool_choice(self) -> None:
        self.draft = ProxyDraft(
            cluster="edge-demo",
            object_id="public-web",
            yaml=WRITTEN_POOL.replace("name: shop", "name: public-web"),
            base_version=1,
            base_hash="abc",
            revision=4,
            updated_by="operator",
            updated_at=OBSERVED,
            deleted=False,
        )

        body = self.page()

        self.assertIn("server app1 192.0.2.30:8080 check", body)
        self.assertRegex(body, r'name="handwritten_pool" checked')
        self.assertRegex(body, r'name="expected_revision" value="4"')
        self.assertTrue(re.search(r"<textarea[^>]*>\n", body))
