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
from haprion_ui.db import WafCounted, WafFinding
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


class AnExceptionThatDoesNotWork(unittest.TestCase):
    """Matches it covers after it reached the nodes are shown, not hidden (26-10-11).

    An exception on `/` let nothing through, and the page hid every match it
    covered - so the one exception that did not work was the one nobody saw.
    """

    MADE = datetime(2026, 10, 2, 14, 0, tzinfo=UTC)
    DEPLOYED = datetime(2026, 10, 2, 14, 5, tzinfo=UTC)
    STORED = LOGGING + (
        "  exceptions: [{rule: 942100, field: 'ARGS:q', paths: [/search], "
        "at: '2026-10-02T14:00:00Z', reason: sync}]\n"
    )

    def build(
        self, *rows: WafFinding, stored: str = STORED, reached: Any = None
    ) -> tuple[list[waf.ObjectFindings], list[waf.ExceptionRow]]:
        documents = {("alpha", "shop"): stored}
        if reached is None:
            reached = {("alpha", self.MADE): self.DEPLOYED}
        findings = waf.build_findings(rows, {}, documents, {}, CATALOG, reached)
        exceptions = waf.build_exceptions(
            documents, {}, CATALOG, waf.ineffective_exceptions(rows, documents, reached)
        )
        return findings, exceptions

    def test_a_match_after_the_deploy_is_shown_on_both_tabs(self) -> None:
        [card], [exception] = self.build(finding())
        self.assertTrue(card.findings[0].ineffective)
        self.assertTrue(exception.ineffective)
        self.assertEqual(exception.exception.reason, "sync")

    def test_what_the_page_asks_the_jobs_about(self) -> None:
        self.assertEqual(
            waf.exception_moments([finding()], {("alpha", "shop"): self.STORED}),
            {"alpha": {self.MADE}},
        )

    def test_before_it_reached_the_nodes_a_match_is_no_sign(self) -> None:
        for rows, reached in (
            ((finding(last_seen=self.DEPLOYED),), None),  # during the deploy's margin
            ((finding(last_seen=datetime(2026, 10, 2, 14, 5, 59, tzinfo=UTC)),), None),
            ((finding(),), {}),  # published, no deploy since
        ):
            with self.subTest(rows=rows, reached=reached):
                findings, [exception] = self.build(*rows, reached=reached)
                self.assertEqual(findings, [])
                self.assertFalse(exception.ineffective)

    def test_an_exception_without_its_time_cannot_be_judged(self) -> None:
        stored = LOGGING + "  exceptions: [{rule: 942100, field: 'ARGS:q', paths: [/search]}]\n"
        findings, [exception] = self.build(finding(), stored=stored)
        self.assertEqual(findings, [])
        self.assertFalse(exception.ineffective)

    def test_a_finding_on_more_paths_than_are_named_is_not_covered(self) -> None:
        # The reading names the first few paths; an exception on those is not one on the rest.
        [card], [exception] = self.build(finding(path_count=4))
        self.assertFalse(card.findings[0].ineffective)
        self.assertFalse(exception.ineffective)
        # One on every path still covers it.
        stored = self.STORED.replace(", paths: [/search]", "")
        findings, _ = self.build(finding(path_count=4), stored=stored)
        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0].findings[0].ineffective)


class WhatAnExceptionLetThrough(unittest.TestCase):
    """B273: each exception's counter, as the generator numbers it, summed on its field."""

    STORED = LOGGING + (
        "  exceptions:\n"
        "    - {rule: 942100, field: 'ARGS:q', paths: [/search]}\n"
        "    - {rule: 942100}\n"
        "    - {rule: 941100, field: 'ARGS:z'}\n"
    )

    def rows(
        self, counted: dict[Any, WafCounted] | None = None, draft: str | None = None
    ) -> list[waf.ExceptionRow]:
        drafted = {("alpha", "shop"): draft} if draft is not None else {}
        return waf.build_exceptions(
            {("alpha", "shop"): self.STORED}, drafted, CATALOG, (), counted or {}
        )

    def test_each_counted_exception_is_asked_about_within_what_it_covers(self) -> None:
        scopes = waf.counter_scopes({("alpha", "shop"): self.STORED}, CATALOG)
        self.assertEqual(
            [(scope.counter, scope.field, scope.paths) for scope in scopes],
            # 941100 is not in the installed catalog here: no counter to ask.
            [(342100, "ARGS:q", ("/search",)), (442100, "", ())],
        )

    def test_each_row_shows_what_its_own_scope_counted(self) -> None:
        narrow_scope, whole_scope = waf.counter_scopes({("alpha", "shop"): self.STORED}, CATALOG)
        narrow, whole, unknown = self.rows(
            {
                narrow_scope: WafCounted(requests=6, clients=2, last_seen=SEEN),
                whole_scope: WafCounted(requests=7, clients=5, last_seen=None),
            }
        )
        self.assertEqual(
            (narrow.counted, narrow.requests, narrow.clients, narrow.last_seen),
            (True, 6, 2, SEEN),
        )
        self.assertEqual((whole.requests, whole.clients), (7, 5))
        # A rule the installed rule set does not define has no counter.
        self.assertEqual((unknown.counted, unknown.requests), (False, 0))

    def test_nothing_counted_is_zero_and_a_draft_counts_nothing(self) -> None:
        narrow = self.rows()[0]
        self.assertEqual((narrow.counted, narrow.requests, narrow.last_seen), (True, 0, None))
        draft = self.STORED + "    - {rule: 942100, field: 'ARGS:new'}\n"
        added = self.rows(draft=draft)[-1]
        self.assertTrue(added.in_draft)
        self.assertFalse(added.counted)


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
            ("haprion_ui.db.waf_counted", {}),
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

    def test_a_rule_that_logs_no_data_shows_a_dash_rather_than_an_empty_box(self) -> None:
        # CRS's empty-header rules (920310, 920330) write no log data (26-10-11).
        empty = finding(920350, "", ("/",), matched="")
        with mock.patch("haprion_ui.db.waf_findings", return_value=[empty]):
            text = self.editor().get("/waf").text
        self.assertNotIn('<code class="matched"></code>', text)
        self.assertIn('<td><span class="table-empty">—</span></td>', text)

    def test_an_exception_that_does_not_work_is_said_on_both_tabs(self) -> None:
        stored = AnExceptionThatDoesNotWork.STORED
        moment, deployed = AnExceptionThatDoesNotWork.MADE, AnExceptionThatDoesNotWork.DEPLOYED
        with (
            mock.patch("haprion_ui.db.cluster_objects", return_value=objects(stored)),
            mock.patch("haprion_ui.db.deploys_carrying", return_value={moment: deployed}) as asked,
        ):
            client = self.editor()
            findings = client.get("/waf").text
            exceptions = client.get("/waf?view=exceptions").text
        self.assertEqual(asked.call_args.kwargs, {"cluster": "alpha", "moments": [moment]})
        self.assertIn('status-badge-warning">Not working<', findings)
        self.assertNotIn("/waf/allow?cluster=alpha&amp;object=shop&amp;rule=942100", findings)
        self.assertIn('status-badge-warning" title="0 let through">Not working<', exceptions)

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
        self.assertIn(
            "<th>Where</th><th>Reason</th><th>Let through</th><th>Clients</th>"
            "<th>Last seen</th><th>Added</th>",
            listing,
        )
        self.assertIn('title="The probe sends no Accept">The probe sends no Accept</td>', listing)

    def test_exceptions_sit_on_a_card_of_the_object_that_carries_them(self) -> None:
        # One table over every object read as if the exceptions were global (26-10-11).
        document = LOGGING + "  exceptions: [{rule: 920350, paths: [/health]}]\n"
        with mock.patch("haprion_ui.db.cluster_objects", return_value=objects(document)):
            listing = self.editor().get("/waf?view=exceptions").text
        opened = listing.split('<section class="cluster-card finding-card', 1)[1]
        card = opened.split("</section>", 1)[0]
        self.assertIn("<h3>shop</h3><p>alpha</p>", card)
        self.assertIn('href="/proxies/alpha/shop/edit">Edit object</a>', card)
        self.assertIn("<thead><tr><th>Finding</th><th>Where</th>", card)
        self.assertNotIn("<th>Object</th>", listing)

    def test_no_exception_anywhere_says_so_once(self) -> None:
        listing = self.editor().get("/waf?view=exceptions").text
        self.assertEqual(listing.count("No object has an exception."), 1)
        self.assertNotIn("finding-card", listing)

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
