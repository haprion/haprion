"""The WAF's findings and exceptions over the API: what the WAF page's two views build (B416)."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime
from typing import Any
from unittest import mock

from haprion_ui import waf
from haprion_ui.db import WafCounted
from tests.test_api import ApiTestCase
from tests.test_editor_page import OBJECTS
from tests.test_waf_page import CATALOG, LOGGING, SEEN, AnExceptionThatDoesNotWork, finding


def objects_with(document: str) -> Any:
    result = dict(OBJECTS.result, objects=[dict(OBJECTS.result["objects"][0], document=document)])
    return [replace(OBJECTS, result=result)]


class WafCase(ApiTestCase):
    document = LOGGING
    findings = [finding(), finding(920350, "", ("/health", "/status"), matched="192.0.2.10")]
    reached: dict[datetime, datetime] = {}

    def setUp(self) -> None:
        super().setUp()
        counted = self.counted()
        for target, value in (
            ("haprion_ui.db.cluster_objects", objects_with(self.document)),
            ("haprion_ui.db.waf_findings", self.findings),
            ("haprion_ui.db.waf_verdicts", {("alpha", "shop"): (14, 3)}),
            ("haprion_ui.db.waf_request_count", 1297),
            ("haprion_ui.db.waf_counted", counted),
            ("haprion_ui.db.deploys_carrying", self.reached),
            ("haprion_ui.waf_work.settled_drafts", []),
            ("haprion.crs.installed_catalog", CATALOG),
        ):
            patch = mock.patch(target, return_value=value)
            patch.start()
            self.addCleanup(patch.stop)

    def counted(self) -> dict[Any, WafCounted]:
        return {}

    def get(self, path: str, cluster: str = "alpha", **token: Any) -> Any:
        secret = self.issue(**token)
        return self.api().get(
            f"/api/v1/clusters/{cluster}/waf/{path}", headers={"Authorization": f"Bearer {secret}"}
        )


class TheFindings(WafCase):
    def test_findings_per_object_and_rule(self) -> None:
        response = self.get("findings")
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual((body["operation"], body["cluster"]), ("waf_findings", "alpha"))
        self.assertEqual(
            body["result"],
            {
                "days": 7,
                "objects": [
                    {
                        "object": "shop",
                        "mode": "log",
                        "requests_judged": 14,
                        "clients": 3,
                        "findings": [
                            {
                                "rule": 942100,
                                "kind": "SQL injection",
                                "explanation": waf.kind(942)[1],
                                "message": CATALOG[942100].message,
                                "severity": "critical",
                                "field": "ARGS:q",
                                "field_label": "q",
                                "matched": "1' OR 1=1--",
                                "paths": ["/search"],
                                "more_paths": 0,
                                "requests": 11,
                                "clients": 2,
                                "last_seen": SEEN.isoformat(),
                                "in_draft": False,
                                "not_working": False,
                            },
                            {
                                "rule": 920350,
                                "kind": "Protocol",
                                "explanation": waf.kind(920)[1],
                                "message": CATALOG[920350].message,
                                "severity": "warning",
                                "field": "",
                                "field_label": "",
                                "matched": "192.0.2.10",
                                "paths": ["/health", "/status"],
                                "more_paths": 0,
                                "requests": 11,
                                "clients": 2,
                                "last_seen": SEEN.isoformat(),
                                "in_draft": False,
                                "not_working": False,
                            },
                        ],
                    }
                ],
            },
        )

    def test_no_findings_is_an_empty_list(self) -> None:
        with mock.patch("haprion_ui.db.waf_findings", return_value=[]):
            self.assertEqual(self.get("findings").json()["result"], {"days": 7, "objects": []})

    def test_exceptions_are_empty_where_the_objects_carry_none(self) -> None:
        self.assertEqual(self.get("exceptions").json()["result"], {"days": 7, "exceptions": []})


class TheExceptions(WafCase):
    document = AnExceptionThatDoesNotWork.STORED
    findings = [finding()]
    reached = {AnExceptionThatDoesNotWork.MADE: AnExceptionThatDoesNotWork.DEPLOYED}

    def counted(self) -> dict[Any, WafCounted]:
        [scope] = waf.counter_scopes({("alpha", "shop"): self.document}, CATALOG)
        return {scope: WafCounted(5, 2, SEEN)}

    def test_a_finding_an_exception_covers_is_said_not_to_work(self) -> None:
        [card] = self.get("findings").json()["result"]["objects"]
        [shown] = card["findings"]
        # Covered by a published exception, and matched after it reached the nodes.
        self.assertEqual(
            (shown["rule"], shown["not_working"], shown["in_draft"]), (942100, True, False)
        )

    def test_exceptions_with_what_each_let_through(self) -> None:
        response = self.get("exceptions")
        body = response.json()
        self.assertEqual((body["operation"], body["cluster"]), ("waf_exceptions", "alpha"))
        self.assertEqual(
            body["result"],
            {
                "days": 7,
                "exceptions": [
                    {
                        "object": "shop",
                        "rule": 942100,
                        "kind": "SQL injection",
                        "explanation": waf.kind(942)[1],
                        "message": CATALOG[942100].message,
                        "severity": "critical",
                        "field": "ARGS:q",
                        "paths": ["/search"],
                        "reason": "sync",
                        "added_by": "",
                        "added_at": "2026-10-02T14:00:00Z",
                        "in_draft": False,
                        "not_working": True,
                        "let_through": {
                            "counted": True,
                            "requests": 5,
                            "clients": 2,
                            "last_seen": SEEN.isoformat(),
                        },
                    }
                ],
            },
        )

    def test_each_route_stays_in_its_cluster(self) -> None:
        for path in ("findings", "exceptions"):
            for cluster, token in (("alpha", {"clusters": ["beta"]}), ("gamma", {})):
                with self.subTest(path=path, cluster=cluster):
                    response = self.get(path, cluster=cluster, **token)
                    self.assertEqual(response.status_code, 404)
                    self.assertEqual(response.json()["error"]["code"], "not_found")

    def test_a_token_limited_to_objects_sees_only_those(self) -> None:
        for path, key in (("findings", "objects"), ("exceptions", "exceptions")):
            with self.subTest(path=path):
                self.assertNotEqual(self.get(path).json()["result"][key], [])
                self.assertEqual(self.get(path, objects=["intranet"]).json()["result"][key], [])
