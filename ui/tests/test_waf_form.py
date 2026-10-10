"""The WAF group on the object form (Fas 21 steg 5, B231, B234)."""

from __future__ import annotations

import json
import unittest
from dataclasses import replace
from types import SimpleNamespace
from typing import Any
from unittest import mock

import yaml

from haprion_ui import waf
from haprion_ui.db import ClusterObjects, FeatureSwitch
from haprion_ui.form_groups import form_groups
from haprion_ui.preview import DEFAULTS, build_document, form_from_document
from tests.test_editor_page import OBJECTS, OBSERVED, SHOP, EditorTestCase

EXCEPTION = {
    "rule": 942100,
    "field": "ARGS:q",
    "paths": ["/search"],
    "by": "admin",
    "at": "2026-10-03T09:10:00Z",
}


def stored(block: str) -> str:
    return SHOP + block


class TheFormSaysWhatTheObjectSays(unittest.TestCase):
    def test_an_object_with_the_engine_opens_and_is_written_back_the_same(self) -> None:
        document = stored(
            "waf:\n  mode: block\n  on_engine_error: deny\n  paranoia: 2\n  exceptions:\n"
            "  - rule: 942100\n    field: ARGS:q\n    paths: [/search, /find]\n"
            "    by: admin\n    at: 2026-10-03T09:10:00Z\n"
        )
        form = form_from_document(document)
        self.assertEqual(
            (form["waf_mode"], form["waf_engine_error"], form["waf_paranoia"]),
            ("block", "deny", "2"),
        )
        carried = json.loads(form["waf_exceptions"])
        self.assertEqual(carried[0]["paths"], ["/find", "/search"])
        self.assertEqual(carried[0]["at"], "2026-10-03T09:10:00Z")
        written = yaml.safe_load(build_document(form))["waf"]
        self.assertEqual(written["mode"], "block")
        self.assertEqual(written["exceptions"][0]["rule"], 942100)

    def test_defaults_left_unsaid_and_an_unquoted_off_are_the_same_settings(self) -> None:
        form = form_from_document(stored("waf:\n  mode: off\n  exceptions: [{rule: 920350}]\n"))
        self.assertEqual(form["waf_mode"], "off")
        self.assertEqual(json.loads(form["waf_exceptions"]), [{"rule": 920350}])
        written = yaml.safe_load(build_document(form))["waf"]
        self.assertEqual(
            written,
            {
                "mode": "off",
                "on_engine_error": "allow",
                "paranoia": 1,
                "exceptions": [{"rule": 920350}],
            },
        )
        self.assertEqual(form_from_document(stored("waf: {}\n"))["waf_mode"], "log")

    def test_off_with_nothing_to_keep_is_an_object_without_the_engine(self) -> None:
        self.assertNotIn("waf", yaml.safe_load(build_document(dict(DEFAULTS, name="shop"))))
        form = form_from_document(stored("waf: {mode: 'off'}\n"))
        self.assertNotIn("waf", yaml.safe_load(build_document(form)))

    def test_large_bodies_survive_the_form_and_are_written_one_path_a_line(self) -> None:
        # Review 2026-10-04 F1, B243: a save from the form must not drop them.
        form = form_from_document(
            stored("waf:\n  mode: block\n  large_bodies: [/upload, /api/files]\n")
        )
        self.assertEqual(form["waf_large_bodies"], "/upload\n/api/files")
        self.assertEqual(
            yaml.safe_load(build_document(form))["waf"]["large_bodies"], ["/upload", "/api/files"]
        )
        written = yaml.safe_load(build_document(dict(form, waf_large_bodies="\r\n /x \r\n\r\n")))
        self.assertEqual(written["waf"]["large_bodies"], ["/x"])
        self.assertNotIn(
            "large_bodies", yaml.safe_load(build_document(dict(form, waf_large_bodies="")))["waf"]
        )

    def test_exceptions_the_form_cannot_read_are_refused(self) -> None:
        for carried in ("{", '{"rule": 1}', "[1"):
            with self.subTest(carried=carried), self.assertRaises(ValueError):
                build_document(dict(DEFAULTS, name="shop", waf_mode="log", waf_exceptions=carried))

    def test_the_closed_group_says_mode_strictness_and_exceptions_with_a_shield(self) -> None:
        def line(**fields: str) -> tuple[str, tuple[tuple[str, str, str], ...]]:
            state = form_groups(dict(DEFAULTS, **fields))["waf"]
            return state.summary, tuple((b.text, b.kind, b.icon) for b in state.badges)

        self.assertEqual(line(), ("Off", ()))
        self.assertEqual(
            line(waf_mode="log"), ("Logging · strictness 1", (("Logging", "warning", "shield"),))
        )
        exceptions = json.dumps([EXCEPTION, {"rule": 920350}])
        self.assertEqual(
            line(waf_mode="block", waf_paranoia="3", waf_exceptions=exceptions),
            (
                "Blocking · strictness 3 · 2 exceptions",
                (("Blocking", "critical", "shield"),),
            ),
        )
        self.assertEqual(line(waf_exceptions=json.dumps([EXCEPTION])), ("Off · 1 exception", ()))


def node(name: str, version: str | None, *, reported: bool = True) -> dict[str, Any]:
    status: dict[str, Any] = {}
    if reported:
        status["waf_engine"] = {"version": version, "active": False}
    return {"name": name, "status": status}


class WhereTheEngineIs(unittest.TestCase):
    def test_the_manager_and_every_node_of_the_cluster(self) -> None:
        objects = [SimpleNamespace(result={"waf": {"engine": "0.9.0-2", "crs": "4.25.1"}})]
        statuses = [
            SimpleNamespace(
                cluster="alpha",
                result={"nodes": [node("node-a", "0.9.0-2"), node("node-b", "0.9.0-2")]},
            ),
            SimpleNamespace(
                cluster="beta",
                result={
                    "nodes": [
                        node("lb-01", None),
                        node("lb-02", "x", reported=False),
                        node("lb-03", "0.9.0-1"),
                    ]
                },
            ),
        ]
        engine = waf.engine(objects, statuses)
        self.assertEqual(engine.unavailable("alpha"), "")
        self.assertEqual(
            engine.unavailable("beta"), "The WAF engine is not installed on lb-01 and lb-02."
        )
        without = waf.engine(
            [SimpleNamespace(result={"waf": {"engine": None, "crs": "4.25.1"}})], statuses
        )
        self.assertEqual(
            without.unavailable("alpha"), "The WAF engine is not installed on the manager."
        )
        self.assertEqual(
            waf.engine([], statuses).unavailable("beta"),
            "The WAF engine is not installed on lb-01, lb-02 and the manager.",
        )


def objects_with(document: str, versions: dict[str, Any] | None) -> ClusterObjects:
    result = dict(OBJECTS.result, objects=[dict(OBJECTS.result["objects"][0], document=document)])
    if versions is not None:
        result["waf"] = versions
    return replace(OBJECTS, result=result)


STATUS = SimpleNamespace(
    cluster="alpha",
    observed_at=OBSERVED,
    outcome="done",
    result={"nodes": [node("node-a", "0.9.0-2"), node("node-b", "0.9.0-2")]},
    warnings=[],
    error=None,
    poll_error=None,
)
VERSIONS = {"engine": "0.9.0-2", "crs": "4.25.1"}


class TheGroupOnTheEditor(EditorTestCase):
    def page(
        self,
        document: str = SHOP,
        *,
        versions: dict[str, Any] | None = VERSIONS,
        statuses: list[Any] | None = None,
    ) -> str:
        with (
            mock.patch(
                "haprion_ui.db.cluster_objects", return_value=[objects_with(document, versions)]
            ),
            mock.patch(
                "haprion_ui.db.cluster_statuses",
                return_value=[STATUS] if statuses is None else statuses,
            ),
        ):
            return str(self.editor().get("/proxies/alpha/shop/edit").text)

    def switch_off(self) -> None:
        self.switches = {
            "waf_engine": FeatureSwitch(
                name="waf_engine",
                enabled=False,
                remembered={},
                updated_at=OBSERVED,
                updated_by="admin",
            )
        }

    def test_offered_where_the_engine_is_installed(self) -> None:
        text = self.page()
        self.assertIn('<select name="waf_mode"', text)
        self.assertIn('<textarea name="waf_large_bodies"', text)
        self.assertIn("Strictness", text)
        self.assertNotIn("is not installed", text)

    def test_the_closed_group_draws_its_shield_in_the_mode_colour(self) -> None:
        # 26-10-04: whether the engine refuses visitors, seen at a glance.
        text = self.page(stored("waf:\n  mode: block\n"))
        head = text.split('<span class="form-group-title">WAF</span>', 1)[1].split("</summary>", 1)[
            0
        ]
        self.assertIn("Blocking · strictness 1", head)
        self.assertIn(
            'class="status-badge status-badge-critical form-group-badge form-group-icon"'
            ' role="img" aria-label="Blocking"',
            head,
        )
        self.assertNotIn("form-group-icon", self.page().split("</form>", 1)[0])

    def test_waiting_for_the_engine_says_where_it_is_missing_and_offers_no_mode(self) -> None:
        text = self.page(versions={"engine": None, "crs": "4.25.1"})
        self.assertIn("The WAF engine is not installed on the manager.", text)
        self.assertNotIn('<select name="waf_mode"', text)
        self.assertIn('<input type="hidden" name="waf_mode" value="off">', text)
        # B231: the sentence alone - nothing to set that the engine would not be there to do.
        self.assertNotIn('<select name="waf_engine_error"', text)
        self.assertNotIn('<select name="waf_paranoia"', text)
        self.assertNotIn("Findings and exceptions in WAF logs", text)
        self.assertIn('<input type="hidden" name="waf_paranoia" value="1">', text)
        self.assertIn('<input type="hidden" name="waf_large_bodies" value="">', text)

    def test_with_the_switch_off_an_object_without_it_carries_hidden_defaults(self) -> None:
        self.switch_off()
        text = self.page()
        self.assertNotIn('<select name="waf_mode"', text)
        self.assertIn('<input type="hidden" name="waf_mode" value="off">', text)

    def test_an_object_that_uses_it_shows_it_whatever_the_switch_says(self) -> None:
        self.switch_off()
        text = self.page(stored("waf:\n  mode: log\n  exceptions: [{rule: 920350}]\n"))
        self.assertIn('<select name="waf_mode"', text)
        self.assertIn('class="node-table form-exception-table"', text)
        self.assertIn("Findings and exceptions in WAF logs", text)

    def test_the_exceptions_are_listed_and_the_unpublished_ones_marked(self) -> None:
        # 26-10-03: see which exceptions Save and publish sends, not a count.
        published = stored(yaml.safe_dump({"waf": {"mode": "log", "exceptions": [EXCEPTION]}}))
        new = {"rule": 920273, "field": "ARGS:id", "by": "admin", "at": "2026-10-03T20:20:02Z"}
        client = self.editor()
        with (
            mock.patch(
                "haprion_ui.db.cluster_objects", return_value=[objects_with(published, VERSIONS)]
            ),
            mock.patch("haprion_ui.db.cluster_statuses", return_value=[STATUS]),
        ):
            text = self.submit(
                client,
                "/proxies/alpha/shop/edit",
                action="check",
                waf_mode="log",
                waf_engine_error="allow",
                waf_paranoia="1",
                waf_exceptions=json.dumps([EXCEPTION, new]),
            ).text
        rows = text.split('class="node-table form-exception-table"', 1)[1].split("</table>", 1)[0]
        self.assertIn("q on /search", rows)
        self.assertIn("id, every path", rows)
        self.assertEqual(rows.count("In draft"), 1, "only the exception not yet published")

    def test_remove_draws_the_page_without_it_and_saves_nothing(self) -> None:
        # 26-10-03: change one's mind on the publishing page, not back in WAF logs.
        other = {"rule": 920273, "field": "ARGS:id", "by": "admin", "at": "2026-10-03T20:20:02Z"}
        client = self.editor()
        with mock.patch("haprion_ui.db.cluster_statuses", return_value=[STATUS]):
            text = self.submit(
                client,
                "/proxies/alpha/shop/edit",
                drop_exception="0",
                waf_mode="log",
                waf_engine_error="allow",
                waf_paranoia="1",
                waf_exceptions=json.dumps([EXCEPTION, other]),
            ).text
        rows = text.split('class="node-table form-exception-table"', 1)[1].split("</table>", 1)[0]
        self.assertNotIn("q on /search", rows)
        self.assertIn("id, every path", rows)
        self.assertIn('value="0" class="secondary-button" formnovalidate>Remove', rows)
        carried = text.split('name="waf_exceptions" value="', 1)[1].split('"', 1)[0]
        self.assertEqual(json.loads(carried.replace("&#34;", '"').replace("&quot;", '"')), [other])
        self.assertEqual(self.saved, [], "removed from the form, not saved")
        self.assertNotIn("lines of YAML", text, "a change, not a question: no verdict")

    def test_the_group_opens_when_the_waf_page_sent_the_person(self) -> None:
        document = stored("waf:\n  mode: log\n")
        with (
            mock.patch(
                "haprion_ui.db.cluster_objects", return_value=[objects_with(document, VERSIONS)]
            ),
            mock.patch("haprion_ui.db.cluster_statuses", return_value=[STATUS]),
        ):
            sent = self.editor().get("/proxies/alpha/shop/edit?open=waf").text
            plain = self.editor().get("/proxies/alpha/shop/edit").text

        def opened(text: str) -> bool:
            head = text.split('<span class="form-group-title">WAF</span>', 1)[0]
            return head.rsplit("<details", 1)[1].split(">", 1)[0].endswith(" open")

        self.assertTrue(opened(sent))
        self.assertFalse(opened(plain))

    def test_a_save_keeps_the_exceptions_the_page_carried(self) -> None:
        client = self.editor()
        carried = json.dumps([EXCEPTION])
        with mock.patch("haprion_ui.db.cluster_statuses", return_value=[STATUS]):
            self.submit(
                client,
                "/proxies/alpha/shop/edit",
                action="save",
                waf_mode="log",
                waf_engine_error="allow",
                waf_paranoia="1",
                waf_exceptions=carried,
            )
        saved = yaml.safe_load(self.saved[-1]["yaml"])
        self.assertEqual(saved["waf"]["exceptions"], [EXCEPTION])


if __name__ == "__main__":
    unittest.main()
