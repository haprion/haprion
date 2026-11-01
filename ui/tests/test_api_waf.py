"""The WAF's findings and exceptions over the API: what the WAF page's two views build (B416)."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from typing import Any
from unittest import mock

from haprion_ui import waf
from haprion_ui.db import ProxyDraft, WafCounted, WafFindings
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
                "truncated": False,
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
            self.assertEqual(
                self.get("findings").json()["result"],
                {"days": 7, "truncated": False, "objects": []},
            )

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
                        "added_by": None,
                        "added_at": "2026-10-02T14:00:00+00:00",
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


class TheMomentAnExceptionWasAdded(WafCase):
    """`added_at` is a time or null, whatever the document holds."""

    findings: list[Any] = []
    base = LOGGING + "  exceptions: [{{rule: 942100{extra}}}]\n"

    def added(self, extra: str) -> dict[str, Any]:
        document = self.base.format(extra=extra)
        with mock.patch("haprion_ui.db.cluster_objects", return_value=objects_with(document)):
            exceptions: list[dict[str, Any]] = self.get("exceptions").json()["result"]["exceptions"]
        [shown] = exceptions
        return shown

    def test_a_form_written_time_with_z_is_iso_with_an_offset(self) -> None:
        self.assertEqual(
            self.added(", at: '2026-10-02T14:00:00Z'")["added_at"], "2026-10-02T14:00:00+00:00"
        )

    def test_an_unquoted_time_that_yaml_reads_as_a_date_is_iso_too(self) -> None:
        self.assertEqual(
            self.added(", at: 2026-10-02T14:00:00Z")["added_at"], "2026-10-02T14:00:00+00:00"
        )

    def test_a_missing_or_unreadable_time_is_null_and_so_is_an_empty_text(self) -> None:
        for extra in ("", ", at: ''", ", at: yesterday"):
            with self.subTest(extra=extra):
                shown = self.added(extra)
                self.assertIsNone(shown["added_at"])
                self.assertEqual(
                    (shown["added_by"], shown["reason"], shown["field"]), (None, None, None)
                )


#
# A string only the draft holds. An admin's unfinished work is for `write`
# (B417); a `read` token that is handed it has been given more than the
# objects list gives it.
#
CANARY = "canary-pentest-for-customer-x"
DRAFT = LOGGING.replace("name: shop", "name: newsite") + (
    "  exceptions: [{rule: 942100, field: 'ARGS:q', paths: [/secret-admin], "
    f"at: '2026-10-02T14:00:00Z', reason: {CANARY}, by: admin}}]\n"
)


class TheDraftsOfAnAdmin(WafCase):
    def setUp(self) -> None:
        super().setUp()
        draft = ProxyDraft(
            cluster="alpha",
            object_id="newsite",
            yaml=DRAFT,
            base_version=None,
            base_hash="",
            revision=1,
            updated_by="admin",
            updated_at=datetime(2026, 10, 2, 14, 0, tzinfo=UTC),
            deleted=False,
            stage="draft",
            replaces=None,
        )
        patch = mock.patch("haprion_ui.waf_work.settled_drafts", return_value=[draft])
        patch.start()
        self.addCleanup(patch.stop)

    def test_a_read_token_is_given_none_of_it(self) -> None:
        for path in ("exceptions", "findings"):
            with self.subTest(path=path):
                response = self.get(path, level="read")
                self.assertEqual(response.status_code, 200)
                for each in (CANARY, "newsite", "/secret-admin"):
                    self.assertNotIn(each, response.text)

    def test_a_write_token_is_given_it(self) -> None:
        response = self.get("exceptions", level="write")
        self.assertIn(CANARY, response.text)
        [row] = [r for r in response.json()["result"]["exceptions"] if r["object"] == "newsite"]
        self.assertTrue(row["in_draft"])


class TheFindingsThatWereCut(WafCase):
    def test_a_cut_is_said(self) -> None:
        cut = WafFindings(self.findings)
        cut.truncated = True
        with mock.patch("haprion_ui.db.waf_findings", return_value=cut):
            self.assertTrue(self.get("findings").json()["result"]["truncated"])

    def test_the_request_count_is_not_asked_for(self) -> None:
        with mock.patch("haprion_ui.db.waf_request_count") as counted:
            self.get("findings")
            self.get("exceptions")
        counted.assert_not_called()
