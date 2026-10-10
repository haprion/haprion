"""The WAF page as a place to work (Fas 21 steg 5, B234, B235)."""

from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any
from unittest import mock

import yaml
from haprion.crs import Rule

from haprion_ui import waf
from haprion_ui.db import WafFinding
from tests.test_editor_page import OBJECTS, SHOP, EditorTestCase

SEEN = datetime(2026, 10, 2, 14, 30, tzinfo=UTC)
LOGGING = SHOP + "waf:\n  mode: log\n"
CATALOG = {
    942100: Rule(942100, "SQL Injection Attack Detected via libinjection", "critical", 942, 1),
    920350: Rule(920350, "Host header is a numeric IP address", "warning", 920, 1),
}


def finding(
    rule: int = 942100, field: str = "ARGS:q", paths: tuple[str, ...] = ("/search",), **values: Any
) -> WafFinding:
    fields: dict[str, Any] = {
        "cluster": "alpha",
        "object": "shop",
        "rule_id": rule,
        "field": field,
        "requests": 11,
        "clients": 2,
        "last_seen": SEEN,
        "matched": "1' OR 1=1--",
        "paths": list(paths),
        "path_count": len(paths),
    }
    fields.update(values)
    return WafFinding(**fields)


class WhatIsShownAsAFinding(unittest.TestCase):
    def build(
        self, *rows: WafFinding, stored: str = LOGGING, draft: str | None = None
    ) -> list[waf.ObjectFindings]:
        drafted = {("alpha", "shop"): draft} if draft is not None else {}
        return waf.build_findings(
            rows, {("alpha", "shop"): (14, 3)}, {("alpha", "shop"): stored}, drafted, CATALOG
        )

    def test_per_object_and_rule_in_words(self) -> None:
        [card] = self.build(
            finding(), finding(920350, "", ("/health", "/status"), matched="192.0.2.10")
        )
        self.assertEqual((card.name, card.mode, card.judged, card.clients), ("shop", "log", 14, 3))
        first, second = card.findings
        self.assertEqual(
            (first.kind, first.message, first.severity),
            ("SQL injection", CATALOG[942100].message, "critical"),
        )
        self.assertEqual((first.shown_field, first.matched), ("q", "1' OR 1=1--"))
        self.assertIn("rule=942100", first.allow_href)
        self.assertIn("field=ARGS%3Aq", first.allow_href)
        self.assertEqual(
            (second.kind, second.shown_field, second.paths),
            ("Protocol", "", ("/health", "/status")),
        )

    def test_what_a_published_exception_covers_needs_no_decision(self) -> None:
        stored = LOGGING + "  exceptions: [{rule: 942100, field: 'ARGS:q', paths: [/search]}]\n"
        self.assertEqual(self.build(finding(), stored=stored), [])
        # Narrower than the finding: still a finding.
        stored = LOGGING + "  exceptions: [{rule: 942100, field: 'ARGS:q', paths: [/other]}]\n"
        self.assertEqual(len(self.build(finding(), stored=stored)[0].findings), 1)
        # The whole object: covers every field and path.
        self.assertEqual(
            self.build(finding(), stored=LOGGING + "  exceptions: [{rule: 942100}]\n"), []
        )

    def test_one_the_draft_lets_through_says_so_until_published(self) -> None:
        draft = (
            LOGGING.replace("mode: log", "mode: block")
            + "  exceptions: [{rule: 942100, field: 'ARGS:q'}]\n"
        )
        [card] = self.build(finding(), draft=draft)
        self.assertTrue(card.findings[0].in_draft)
        self.assertEqual(card.mode, "block")

    def test_an_object_with_the_engine_off_has_no_findings_to_decide(self) -> None:
        off = LOGGING.replace("mode: log", "mode: 'off'")
        self.assertEqual(self.build(finding(), stored=off), [])
        # Without WAF settings, or without the object, the engine inspects nothing either.
        self.assertEqual(self.build(finding(), stored=SHOP), [])
        self.assertEqual(self.build(finding(), stored=""), [])
        # The draft is what the card shows: turned off there, gone; turned back on, back.
        self.assertEqual(self.build(finding(), draft=off), [])
        [card] = self.build(finding(), stored=off, draft=LOGGING)
        self.assertEqual(card.mode, "log")

    def test_a_rule_the_catalog_does_not_know_is_still_shown(self) -> None:
        [card] = self.build(finding(999999, "", ("/x",)))
        self.assertEqual(
            (card.findings[0].kind, card.findings[0].message), ("Rule set 999", "Rule 999999")
        )


class ChangingTheObject(unittest.TestCase):
    def test_an_exception_is_added_once_and_removed_by_its_scope(self) -> None:
        exception = waf.exception_for(
            "field_paths",
            rule=942100,
            field="ARGS:q",
            paths=["/b", "/a"],
            by="admin",
            at="2026-10-03T09:10:00Z",
        )
        self.assertEqual(
            exception,
            {
                "rule": 942100,
                "field": "ARGS:q",
                "paths": ["/a", "/b"],
                "by": "admin",
                "at": "2026-10-03T09:10:00Z",
            },
        )
        added = waf.with_exception("shop", LOGGING, exception)
        self.assertEqual(yaml.safe_load(added)["waf"]["exceptions"], [exception])
        self.assertEqual(waf.with_exception("shop", added, dict(exception, by="other")), added)
        removed = waf.without_exception(
            "shop", added, rule=942100, field="ARGS:q", paths=["/b", "/a"]
        )
        self.assertNotIn("exceptions", yaml.safe_load(removed)["waf"])
        with self.assertRaises(ValueError):
            waf.without_exception("shop", removed, rule=942100, field="ARGS:q", paths=["/a"])

    def test_the_last_exception_of_an_object_with_the_engine_off_takes_the_block_with_it(
        self,
    ) -> None:
        document = SHOP + "waf:\n  mode: 'off'\n  exceptions: [{rule: 920350}]\n"
        self.assertNotIn(
            "waf",
            yaml.safe_load(
                waf.without_exception("shop", document, rule=920350, field="", paths=[])
            ),
        )

    def test_an_object_without_the_engine_takes_no_exception(self) -> None:
        with self.assertRaises(ValueError):
            waf.with_exception("shop", SHOP, {"rule": 942100})

    def test_a_choice_needs_what_it_names(self) -> None:
        for scope, field, paths in (("field", "", []), ("paths", "", []), ("nowhere", "", ["/a"])):
            with self.subTest(scope=scope), self.assertRaises(ValueError):
                waf.exception_for(scope, rule=942100, field=field, paths=paths, by="admin", at="")
        self.assertEqual(
            waf.exception_for(
                "object", rule=920350, field="ARGS:q", paths=["/a"], by="admin", at=""
            )["rule"],
            920350,
        )


def objects(document: str) -> Any:
    result = dict(OBJECTS.result, objects=[dict(OBJECTS.result["objects"][0], document=document)])
    return [replace(OBJECTS, result=result)]


class ThePage(EditorTestCase):
    def setUp(self) -> None:
        super().setUp()
        for target, value in (
            ("haprion_ui.db.waf_findings", [finding()]),
            ("haprion_ui.db.waf_verdicts", {("alpha", "shop"): (14, 3)}),
            ("haprion_ui.db.waf_request_count", 1297),
            ("haprion_ui.db.cluster_objects", objects(LOGGING)),
            ("haprion.crs.installed_catalog", CATALOG),
        ):
            patch = mock.patch(target, return_value=value)
            patch.start()
            self.addCleanup(patch.stop)

    def test_findings_per_object_with_allow(self) -> None:
        page = self.editor().get("/waf")
        self.assertEqual(page.status_code, 200)
        text = page.text
        self.assertIn("<h3>shop</h3>", text)
        self.assertIn(
            "Would have blocked <strong>14 requests</strong> from <strong>3 clients</strong>", text
        )
        self.assertIn('status-badge-warning">Logging', text)
        self.assertIn("q: 1&#39; OR 1=1--", text)
        self.assertIn("/waf/allow?cluster=alpha&amp;object=shop&amp;rule=942100", text)
        self.assertIn("Findings <b>1</b>", text)
        self.assertIn("Exceptions <b>0</b>", text)
        self.assertIn("Requests <b>1297</b>", text)

    def test_allow_offers_the_narrowest_choice_first(self) -> None:
        text = (
            self.editor()
            .get(
                "/waf/allow?cluster=alpha&object=shop&rule=942100&field=ARGS:q&path=/search&path=/a%20b"
            )
            .text
        )
        self.assertIn("Let this through on shop", text)
        self.assertIn('value="field_paths" checked', text)
        self.assertIn('value="/search" checked', text)
        self.assertIn(
            "data-allow-cancel", text, "the dialog's Cancel closes it rather than leaving"
        )
        self.assertNotIn("/a b", text, "a path the engine could not be told exactly is not offered")

    def test_allow_saves_the_exception_into_the_draft(self) -> None:
        client = self.editor()
        answer = client.post(
            "/waf/allow",
            data={
                "csrf_token": self.token(client),
                "cluster": "alpha",
                "object": "shop",
                "rule": "942100",
                "field": "ARGS:q",
                "path": ["/search"],
                "chosen_path": ["/search"],
                "scope": "field_paths",
            },
            follow_redirects=False,
        )
        self.assertEqual(answer.status_code, 303)
        self.assertEqual(answer.headers["location"], "/waf?saved=shop&in=alpha")
        [saved] = self.saved
        exception = yaml.safe_load(saved["yaml"])["waf"]["exceptions"][0]
        self.assertEqual(
            {k: v for k, v in exception.items() if k != "at"},
            {"rule": 942100, "field": "ARGS:q", "paths": ["/search"], "by": "operator"},
        )
        self.assertRegex(exception["at"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertIsNone(saved["expected_revision"])

    def test_allow_keeps_the_reason_on_one_line(self) -> None:
        client = self.editor()
        answer = client.post(
            "/waf/allow",
            data={
                "csrf_token": self.token(client),
                "cluster": "alpha",
                "object": "shop",
                "rule": "942100",
                "scope": "object",
                "reason": "  SQL examples\r\n in the docs  ",
            },
            follow_redirects=False,
        )
        self.assertEqual(answer.status_code, 303)
        exception = yaml.safe_load(self.saved[0]["yaml"])["waf"]["exceptions"][0]
        self.assertEqual(exception["reason"], "SQL examples in the docs")
        self.assertEqual(list(exception), ["rule", "reason", "by", "at"])

    def test_the_reason_has_a_column_of_its_own(self) -> None:
        document = LOGGING + "  exceptions: [{rule: 920350, reason: The probe sends no Accept}]\n"
        with mock.patch("haprion_ui.db.cluster_objects", return_value=objects(document)):
            listing = self.editor().get("/waf?view=exceptions").text
        self.assertIn("<th>Where</th><th>Reason</th><th>Added</th>", listing)
        self.assertIn('title="The probe sends no Accept">The probe sends no Accept</td>', listing)

    def test_a_choice_without_its_paths_is_answered_on_the_dialog(self) -> None:
        client = self.editor()
        answer = client.post(
            "/waf/allow",
            data={
                "csrf_token": self.token(client),
                "cluster": "alpha",
                "object": "shop",
                "rule": "920350",
                "path": ["/health"],
                "scope": "paths",
            },
        )
        self.assertEqual(answer.status_code, 409)
        self.assertIn("choose at least one path", answer.text)
        self.assertEqual(self.saved, [])

    def test_remove_takes_the_exception_out_of_the_draft(self) -> None:
        with mock.patch(
            "haprion_ui.db.cluster_objects",
            return_value=objects(LOGGING + "  exceptions: [{rule: 920350, paths: [/health]}]\n"),
        ):
            client = self.editor()
            listing = client.get("/waf?view=exceptions").text
            self.assertIn("Host header is a numeric IP address", listing)
            self.assertIn(">/health<", listing)
            answer = client.post(
                "/waf/exceptions/remove",
                data={
                    "csrf_token": self.token(client),
                    "cluster": "alpha",
                    "object": "shop",
                    "rule": "920350",
                    "field": "",
                    "path": ["/health"],
                },
                follow_redirects=False,
            )
        self.assertEqual(answer.status_code, 303)
        self.assertNotIn("exceptions", yaml.safe_load(self.saved[0]["yaml"])["waf"])

    def test_an_exception_already_gone_is_answered_on_the_exceptions_page(self) -> None:
        client = self.editor()
        answer = client.post(
            "/waf/exceptions/remove",
            data={
                "csrf_token": self.token(client),
                "cluster": "alpha",
                "object": "shop",
                "rule": "920350",
                "field": "",
                "path": ["/health"],
            },
        )
        self.assertEqual(answer.status_code, 409)
        self.assertIn("text/html", answer.headers["content-type"])
        self.assertIn("that exception is no longer on the object", answer.text)
        self.assertIn('role="alert"', answer.text)
        self.assertIn("<h1>WAF logs</h1>", answer.text)
        self.assertEqual(self.saved, [])

    def test_the_saved_notice_leads_to_where_the_draft_is_published(self) -> None:
        # 26-10-03: to the editor with Save and publish, WAF open, not the object page.
        text = self.editor().get("/waf?saved=shop&in=alpha").text
        self.assertIn('href="/proxies/alpha/shop/edit?open=waf">shop</a>', text)

    def test_a_reader_sees_findings_and_changes_nothing(self) -> None:
        self.account = replace(self.account, role="reader")
        client = self.editor()
        text = client.get("/waf").text
        self.assertIn("<h3>shop</h3>", text)
        self.assertNotIn("Allow…", text)
        self.assertNotIn("Edit object", text)
        answer = client.post(
            "/waf/allow",
            data={
                "csrf_token": self.token(client),
                "cluster": "alpha",
                "object": "shop",
                "rule": "942100",
                "scope": "object",
            },
        )
        self.assertEqual(answer.status_code, 403)
        self.assertEqual(self.saved, [])


if __name__ == "__main__":
    unittest.main()
