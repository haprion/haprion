"""`/api/v1` keeps its promise: every answer is held to the schema that describes it (B416, review P2-3).

Fields are added and never removed or renamed, and a script is the other
reader of every one of them. Each route is called with a `read` and a `write`
token against data rich enough to fill its fields, and the answer is checked
against `haprion_ui/api/schemas/<operation>.schema.json`: every field the
schema requires is there with its type, and every field the route returns is
described in it. A route with no schema fails, so a new route comes with one.
"""

from __future__ import annotations

import json
import re
import tempfile
import tomllib
import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from fnmatch import fnmatch
from functools import cache
from pathlib import Path
from typing import Any, ClassVar, get_args
from unittest import mock
from uuid import UUID

from haprion.config import SOURCE_KINDS
from haprion.proxy_model import PROTOCOLS
from haprion.proxy_model import WAF_MODES as ENGINE_WAF_MODES
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource
from referencing._core import Resolver

import haprion_ui
from haprion_ui import api, api_tokens, attention, dashboard, db, demo, probe, waf
from haprion_ui.api import contract
from haprion_ui.api import jobs as api_jobs
from haprion_ui.config import TrafficLogs
from haprion_ui.db import ProxyDraft, WafCounted
from haprion_ui.jobs import OPERATION_LABELS
from haprion_ui.traffic_logs import Reading
from tests.test_api import ApiTestCase
from tests.test_api_blocks import BLOCKING, SHOP, held, status, stored
from tests.test_api_boundary import api_routes
from tests.test_api_certificate_writes import CertificateWriteCase
from tests.test_api_certificates import entry as certificate_entry
from tests.test_api_certificates import registry as certificate_registry
from tests.test_api_changes import SECOND, SHOP_CHANGED, ChangesTestCase, saved_row
from tests.test_api_clusters_objects import ReadingTestCase, renamed
from tests.test_api_jobs import REQUEST, JobsApiTestCase, a_job, failed_job
from tests.test_api_servers import KEY as WRITE_KEY
from tests.test_api_servers import HealthCheckCase, Queueing
from tests.test_api_traffic import NODE
from tests.test_api_traffic import entry as traffic_entry
from tests.test_api_waf import WafCase
from tests.test_api_writing import a_job as queued_job
from tests.test_certificates import NOW as CERTIFICATES_NOW
from tests.test_editor_page import OBJECTS
from tests.test_login import configuration
from tests.test_waf_page import CATALOG, AnExceptionThatDoesNotWork, finding
from tests.test_waf_page import SEEN as WAF_SEEN

WHEN = "2026-10-31T09:30:00+00:00"
INGEST = """schema: 1
name: ingest
listen:
  protocol: tcp
  port: 5432
backend: db
backends:
  db:
    servers:
      - host: 192.0.2.30
        port: 5432
"""
PACKAGE = Path(haprion_ui.__file__).resolve().parent
SCHEMAS = PACKAGE / "api" / "schemas"
ROOT = Path(__file__).resolve().parents[2]
BASE = "https://example.com/haprion/schemas/v1/api/"
NGINX = (ROOT / "install/platform/examples/haprion.nginx.example").read_text("utf-8")
PROSE = ("Code.", "Text.", "Value.")


@cache
def registry() -> Registry:
    """The API's schemas and the CLI's common definitions, by `$id`."""

    found = Registry()
    for path in [*sorted(SCHEMAS.glob("*.schema.json")), ROOT / "schemas/v1/common.schema.json"]:
        schema = json.loads(path.read_text(encoding="utf-8"))
        found = found.with_resource(str(schema["$id"]), Resource.from_contents(schema))
    return found


def checker(schema: dict[str, Any]) -> Draft202012Validator:
    return Draft202012Validator(schema, registry=registry(), format_checker=FormatChecker())


@cache
def result_checker(operation: str) -> Draft202012Validator:
    return checker(json.loads((SCHEMAS / f"{operation}.schema.json").read_text(encoding="utf-8")))


@cache
def envelope_checker() -> Draft202012Validator:
    return checker(
        {"$ref": "https://example.com/haprion/schemas/v1/common.schema.json#/$defs/envelope"}
    )


Parts = list[tuple[dict[str, Any], Resolver[Any]]]


def parts(schema: dict[str, Any], resolver: Resolver[Any]) -> Parts:
    """A schema with what it refers to and what it is all of, each with the resolver it reads in."""

    found: Parts = []
    if "$ref" in schema:
        looked = resolver.lookup(schema["$ref"])
        found += parts(looked.contents, looked.resolver)
    for each in schema.get("allOf", []):
        found += parts(each, resolver)
    found.append((schema, resolver))
    return found


def undeclared(data: Any, where: Parts, path: str = "result") -> list[str]:
    """Fields of the answer that no schema describes.

    The schemas allow more fields, so that v1 can add them, but a field the
    route returns that the schema does not describe has no word on whether it
    is a code or text, and that is how the next P3-6 gets in.
    """

    problems: list[str] = []
    if isinstance(data, dict):
        declared = {key for schema, _ in where for key in schema.get("properties", {})}
        if not declared:
            # Free-form on purpose, like an object's own document.
            return problems
        for key, value in data.items():
            if key not in declared:
                problems.append(f"{path}.{key}")
                continue
            inner: Parts = []
            for schema, resolver in where:
                if key in schema.get("properties", {}):
                    inner += parts(schema["properties"][key], resolver)
            problems += undeclared(value, inner, f"{path}.{key}")
    elif isinstance(data, list):
        inner = []
        for schema, resolver in where:
            if "items" in schema:
                inner += parts(schema["items"], resolver)
        for number, value in enumerate(data):
            problems += undeclared(value, inner, f"{path}[{number}]")
    return problems


def held_to(case: unittest.TestCase, operation: str, body: dict[str, Any]) -> None:
    """The answer is the contract's envelope, its result is the operation's schema's, and it says no more than that."""

    for errors in (
        sorted(envelope_checker().iter_errors(body), key=str),
        sorted(result_checker(operation).iter_errors(body["result"]), key=str),
    ):
        case.assertEqual([f"{list(e.path)}: {e.message}" for e in errors], [])
    case.assertEqual(body["operation"], operation)
    top = json.loads((SCHEMAS / f"{operation}.schema.json").read_text(encoding="utf-8"))
    resolver = registry().resolver(str(top["$id"]))
    case.assertEqual(undeclared(body["result"], parts(top, resolver)), [])


class Checked(ApiTestCase):
    """Calls its routes with both tokens and holds each answer to its schema."""

    CALLS: ClassVar[dict[str, tuple[str, ...]]] = {}
    # A change is asked with a token that reaches it, and answered 202.
    LEVELS: ClassVar[tuple[str, ...]] = ("read", "write")
    STATUS: ClassVar[int] = 200

    @classmethod
    def setUpClass(cls) -> None:
        if cls is Checked:
            raise unittest.SkipTest("the base of the route groups")
        super().setUpClass()

    def call(self, path: str, secret: str) -> Any:
        return self.api().get("/api/v1" + path, headers={"Authorization": f"Bearer {secret}"})

    def test_every_answer_is_the_one_its_schema_describes(self) -> None:
        for level in self.LEVELS:
            secret = self.issue(level=level)
            for operation, paths in self.CALLS.items():
                for path in paths:
                    with self.subTest(level=level, operation=operation, path=path):
                        response = self.call(path, secret)
                        self.assertEqual(response.status_code, self.STATUS, response.text)
                        held_to(self, operation, response.json())


Change = tuple[str, str, dict[str, Any], tuple[str, ...]]


class Written(ApiTestCase):
    """Calls its changing routes with each level that reaches them and holds each answer to its schema.

    `CALLS` maps the operation to the method, the path, the body and the
    levels of token it is called with.
    """

    CALLS: ClassVar[dict[str, Change]] = {}

    @classmethod
    def setUpClass(cls) -> None:
        if cls is Written:
            raise unittest.SkipTest("the base of the route groups")
        super().setUpClass()

    def test_every_answer_is_the_one_its_schema_describes(self) -> None:
        for operation, (method, path, body, levels) in self.CALLS.items():
            for level in levels:
                with self.subTest(level=level, operation=operation):
                    response = self.api().request(
                        method,
                        "/api/v1" + path,
                        json=body,
                        headers={
                            "Authorization": f"Bearer {self.issue(level=level)}",
                            "Idempotency-Key": "00000000-0000-4000-8000-000000000041",
                        },
                    )
                    self.assertIn(response.status_code, (200, 202), response.text)
                    held_to(self, operation, response.json())


class TheClusterAndObjectRoutes(Checked, ReadingTestCase):
    CALLS = {
        "token_show": ("/token",),
        "cluster_list": ("/clusters",),
        "cluster_show": ("/clusters/alpha", "/clusters/beta"),
        "attention_list": ("/attention",),
        "object_list": ("/clusters/alpha/objects", "/clusters/beta/objects"),
        "object_show": (
            "/clusters/alpha/objects/public-web",
            "/clusters/alpha/objects/shop",
            "/clusters/alpha/objects/staging",
            "/clusters/alpha/objects/metrics",
            "/clusters/alpha/objects/ingest",
        ),
        "object_history": ("/clusters/alpha/objects/public-web/history",),
    }

    def setUp(self) -> None:
        super().setUp()
        when = datetime(2026, 10, 31, 9, 30, tzinfo=UTC)
        items = (
            attention.Item("certificate", "critical", None, "web", "expires in 3 days", when, "/"),
            attention.Item("node", "warning", "alpha", "node-a", "behind", when, "/", "Behind"),
            attention.Item("node", "warning", "beta", "node-c", "behind", None, "/"),
        )
        drafts = [
            ProxyDraft(
                cluster="alpha",
                object_id=name,
                yaml="schema: 1\n",
                base_version=None,
                base_hash="",
                revision=1,
                updated_by="operator",
                updated_at=when,
                deleted=deleted,
                stage=stage,
                replaces=replaces,
            )
            for name, stage, deleted, replaces in (
                ("blog", "draft", False, "journal"),
                ("shop", "saved", True, None),
            )
        ]
        #
        # The nullable fields the demo leaves empty, filled once each, so that
        # their types are held to the schema when there is a value (review
        # 26-10-31, P3-7): a site that redirects HTTP, an object with servers,
        # and a version somebody saved.
        #
        objects = renamed(demo.object_rows())
        listed = objects[0].result["objects"]
        listed[0]["redirect_http"] = True
        listed.append({**listed[0], "name": "ingest", "document": INGEST, "protocol": "tcp"})
        listed[-1].update({"hostnames": [], "redirect_http": None, "runtime_backends": []})
        histories = renamed(demo.history_rows())
        histories[0].result["versions"][0]["requested_by"] = "operator"
        for target, value in (
            ("haprion_ui.db.cluster_objects", objects),
            ("haprion_ui.db.cluster_histories", histories),
            ("haprion_ui.api.clusters.attention_items", attention.Attention(when, items, {}, True)),
            ("haprion_ui.db.cluster_drafts", drafts),
            # One publish still running and one refused, for the fields they fill.
            (
                "haprion_ui.db.recent_jobs",
                [
                    a_job(
                        id=51,
                        operation="changes_publish",
                        state="running",
                        outcome=None,
                        payload={"objects": {"public-web": {}}},
                    ),
                    failed_job(operation="changes_publish", payload={"objects": {"shop": {}}}),
                ],
            ),
        ):
            patch = mock.patch(target, return_value=value)
            patch.start()
            self.addCleanup(patch.stop)

    def test_a_write_token_s_list_holds_a_draft_and_a_removal(self) -> None:
        # The groups' data is rich only if it reaches the fields it is meant to fill.
        listed = self.result("/clusters/alpha/objects", level="write")["objects"]
        self.assertEqual(
            {o["state"] for o in listed},
            {"serving", "inactive", "unreadable", "draft"},
        )
        self.assertIsNotNone(next(o for o in listed if o["name"] == "shop")["draft"])
        by_name = {o["name"]: o for o in listed}
        self.assertEqual(by_name["public-web"]["publishing"]["label"], "Publishing")
        self.assertEqual(by_name["shop"]["publish_refused"], "candidate_invalid")

    def test_the_fields_the_demo_leaves_empty_are_filled(self) -> None:
        listed = {o["name"]: o for o in self.result("/clusters/alpha/objects")["objects"]}
        self.assertTrue(listed["public-web"]["redirect_http"])
        self.assertEqual(listed["ingest"]["servers"], ["192.0.2.30"])
        history = self.result("/clusters/alpha/objects/public-web/history")["versions"]
        self.assertEqual(history[0]["saved_by"], "operator")
        self.assertEqual(self.result("/clusters/alpha")["attention"][0]["since"], WHEN)

    def test_a_drafts_replaced_object_is_held_to_the_schema(self) -> None:
        # Only a write token sees a draft, so the group's both-levels walk cannot.
        response = self.get("/clusters/alpha/objects/blog", level="write")
        self.assertEqual(response.status_code, 200, response.text)
        held_to(self, "object_show", response.json())
        self.assertEqual(response.json()["result"]["draft"]["replaces"], "journal")


class TheTokenRoute(ApiTestCase):
    def test_a_token_with_a_scope_is_held_to_the_schema(self) -> None:
        """Review 26-10-31, P3-7: the arrays of a scoped token were never filled."""

        secret = self.issue(
            level="block",
            clusters=["alpha", "beta"],
            objects=["shop"],
            sources=["192.0.2.0/24", "127.0.0.0/8"],
        )
        response = self.api().get("/api/v1/token", headers={"Authorization": f"Bearer {secret}"})
        self.assertEqual(response.status_code, 200, response.text)
        held_to(self, "token_show", response.json())
        token = response.json()["result"]["token"]
        self.assertEqual(
            (token["clusters"], token["objects"], token["sources"]),
            (["alpha", "beta"], ["shop"], ["192.0.2.0/24", "127.0.0.0/8"]),
        )


class TheCertificateRoute(Checked):
    CALLS = {"certificate_list": ("/certificates",)}

    def setUp(self) -> None:
        super().setUp()
        entries = [
            certificate_entry("web", clusters=("alpha",)),
            certificate_entry("intranet", kind="import", clusters=("beta",), days_left=3),
            certificate_entry(
                "offline",
                kind="import",
                clusters=(),
                receivers=(
                    {
                        "id": "web-host",
                        "published_at": CERTIFICATES_NOW.isoformat(),
                        "current": True,
                    },
                ),
            ),
            certificate_entry(
                "broken",
                kind="import",
                clusters=("alpha",),
                readable=False,
                validation_error="Not a certificate",
            ),
        ]
        patch = mock.patch(
            "haprion_ui.db.cluster_certificates",
            side_effect=lambda *_a, **_k: certificate_registry(*entries),
        )
        patch.start()
        self.addCleanup(patch.stop)


class TheCertificateWriteRoutes(Checked, CertificateWriteCase):
    CALLS = {
        "certificate_issue": ("/certificates",),
        "certificate_renew": ("/certificates/example.com/renew",),
        "certificate_targets": ("/certificates/example.com/targets",),
        "certificate_delete": ("/certificates/example.com",),
    }
    LEVELS = ("write",)
    STATUS = 202
    ASKED: ClassVar[dict[str, tuple[str, dict[str, Any] | None]]] = {
        "/certificates": (
            "POST",
            {"domain": "new.example.net", "method": "dns-01", "clusters": ["alpha"]},
        ),
        "/certificates/example.com/renew": ("POST", None),
        "/certificates/example.com/targets": ("PUT", {"action": "add", "clusters": ["beta"]}),
        "/certificates/example.com": ("DELETE", None),
    }

    def call(self, path: str, secret: str) -> Any:
        method, body = self.ASKED[path]
        self.queued.clear()
        self.events.clear()
        return self.send(method, path, secret, body)


class TheObjectWriteRoutes(Checked, ChangesTestCase):
    """A write is called with a write token only: below it, every route's 403 is the boundary test's."""

    CALLS = {
        "object_create": ("POST /clusters/alpha/objects",),
        "object_replace": ("PUT /clusters/alpha/objects/shop",),
        "object_remove": ("DELETE /clusters/alpha/objects/shop",),
        "cluster_publish": ("POST /clusters/alpha/publish",),
        "cluster_revert": ("POST /clusters/alpha/revert",),
    }
    BODIES: ClassVar[dict[str, Any]] = {
        "object_create": SECOND,
        "object_replace": SHOP_CHANGED,
        "cluster_publish": {"comment": "Move the shop"},
        "cluster_revert": {"version": 1},
    }
    STATUSES: ClassVar[dict[str, int]] = {
        "object_create": 201,
        "cluster_publish": 202,
        "cluster_revert": 202,
    }

    def test_every_answer_is_the_one_its_schema_describes(self) -> None:
        # The token's own change, which a removal takes without being told its revision.
        self.rows = [saved_row(updated_by=f"token{':'}monitoring")]
        for operation, calls in self.CALLS.items():
            for call in calls:
                method, path = call.split(" ")
                with self.subTest(operation=operation, call=call):
                    response = self.send(method, path, body=self.BODIES.get(operation))
                    self.assertEqual(
                        response.status_code, self.STATUSES.get(operation, 200), response.text
                    )
                    held_to(self, operation, response.json())


class TheBlocksRoute(Checked):
    CALLS = {"object_blocks": ("/clusters/alpha/objects/shop/blocks",)}

    def setUp(self) -> None:
        super().setUp()
        observed = datetime.now(UTC) - timedelta(minutes=1)
        documents = stored(("shop", BLOCKING), ("intranet", SHOP))
        statuses = status(
            observed,
            ("node-a", {"shop": held(2, ("192.0.2.10", 3_600_000), ("192.0.2.7", 1_800_000))}),
            ("node-b", {"shop": held(1, ("192.0.2.7", 2_400_000))}),
        )
        for name, rows in (("cluster_objects", documents), ("cluster_statuses", statuses)):
            patch = mock.patch(
                f"haprion_ui.db.{name}", side_effect=lambda *_a, rows=rows, **_k: rows
            )
            patch.start()
            self.addCleanup(patch.stop)


class TheBlockRoutes(Written):
    CALLS = {
        "object_block": (
            "POST",
            "/clusters/alpha/objects/shop/blocks",
            {"addresses": ["203.0.113.7", "not-an-address"]},
            ("block", "write"),
        ),
        "object_unblock": (
            "DELETE",
            "/clusters/alpha/objects/shop/blocks",
            {"addresses": ["203.0.113.7"]},
            ("write",),
        ),
    }

    def setUp(self) -> None:
        super().setUp()
        reached = [
            {
                "node": name,
                "outcome": "done",
                "message": None,
                "addresses": [{"address": "203.0.113.7", "outcome": "done"}],
            }
            for name in ("node-a", "node-b")
        ]
        answer = {
            "outcome": "partial",
            "result": {"object": "shop", "nodes": reached},
            "warnings": [
                {
                    "code": "address_exempt",
                    "message": "x",
                    "node": None,
                    "details": {"address": "192.0.2.7"},
                }
            ],
            "error": None,
        }
        for patch in (
            mock.patch("haprion_ui.db.cluster_objects", return_value=stored(("shop", BLOCKING))),
            mock.patch("haprion.block_api_socket.ask", return_value=answer),
            mock.patch("haprion_ui.db.record_audit_event"),
            mock.patch("haprion_ui.db.queue_job", return_value=queued_job()),
            mock.patch("haprion_ui.operations.prepare"),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def api(self) -> Any:
        return self.client(
            replace(configuration(), clusters=("alpha", "beta"), management_writes=True)
        )


class TheTrafficRoute(Checked):
    CALLS = {"traffic_list": ("/clusters/alpha/traffic",)}

    def setUp(self) -> None:
        super().setUp()
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        rows = (
            traffic_entry(),
            traffic_entry(rule="admin-post:deny", termination="SH", status=403),
        )
        for patch in (
            mock.patch("haprion_ui.db.cluster_objects", side_effect=lambda _c, **_kw: [OBJECTS]),
            mock.patch(
                "haprion_ui.traffic_logs.read_database",
                return_value=Reading(rows, (NODE,), 0, False),
            ),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def call(self, path: str, secret: str) -> Any:
        config = replace(
            configuration(),
            clusters=("alpha", "beta"),
            traffic_logs=TrafficLogs(
                enabled=True, directory=Path(self.directory.name), max_lines=500
            ),
        )
        return self.client(config).get(
            "/api/v1" + path, headers={"Authorization": f"Bearer {secret}"}
        )


class TheWafRoutes(Checked, WafCase):
    CALLS = {
        "waf_findings": ("/clusters/alpha/waf/findings",),
        "waf_exceptions": ("/clusters/alpha/waf/exceptions",),
    }
    # `by` names who added the exception: filled once, as the schema says it may be.
    document = AnExceptionThatDoesNotWork.STORED.replace(
        "reason: sync}", "reason: sync, by: operator}"
    )
    findings = [finding(), finding(920350, "", ("/health", "/status"), matched="192.0.2.10")]
    reached = {AnExceptionThatDoesNotWork.MADE: AnExceptionThatDoesNotWork.DEPLOYED}

    def counted(self) -> dict[Any, WafCounted]:
        [scope] = waf.counter_scopes({("alpha", "shop"): self.document}, CATALOG)
        return {scope: WafCounted(5, 2, WAF_SEEN)}


class TheQueuedServerRoutes(Checked, Queueing):
    LEVELS = ("write",)
    STATUS = 202
    CALLS = {
        "object_servers": ("/clusters/edge-demo/objects/public-web/servers",),
        "cluster_deploy": ("/clusters/edge-demo/deploy",),
    }

    def call(self, path: str, secret: str) -> Any:
        body = {"servers": ["web/192.0.2.10:8080"], "state": "drain"} if "servers" in path else None
        return self.writing().post(
            "/api/v1" + path,
            json=body,
            headers={"Authorization": f"Bearer {secret}", "Idempotency-Key": WRITE_KEY},
        )


class TheHealthCheckRoute(Checked, HealthCheckCase):
    LEVELS = ("write",)
    CALLS = {"object_health_check": ("/clusters/alpha/objects/shop/health-check",)}

    def call(self, path: str, secret: str) -> Any:
        report = probe.ProbeReport(
            ran=True,
            source="192.0.2.25",
            nodes=(
                probe.NodeReport(
                    node="node-a",
                    reachable=True,
                    error=None,
                    source_held=True,
                    results=(
                        probe.Reached(
                            host="192.0.2.10", port=8080, ok=True, status=200, error=None, ms=3
                        ),
                    ),
                ),
            ),
            caveats=("A caveat.",),
            tested_at=datetime.now(UTC),
        )
        with mock.patch("haprion_ui.probe.run", return_value=report):
            return self.writing().post(
                "/api/v1" + path, headers={"Authorization": f"Bearer {secret}"}
            )


class TheJobRoutes(Checked, JobsApiTestCase):
    CALLS = {
        "job_list": ("/jobs",),
        "job_show": (
            "/jobs/41",
            "/jobs/42",
            "/jobs/43",
            "/jobs/44",
            "/jobs/45",
            "/jobs/46",
            "/jobs/47",
        ),
    }

    def setUp(self) -> None:
        super().setUp()
        self.rows = [
            a_job(
                id=43,
                request_id=UUID("00000000-0000-4000-8000-000000000043"),
                operation="cert_publish",
                cluster=None,
                payload={"certificates": ["example.com", "example.net"]},
                state="pending",
                started_at=None,
                finished_at=None,
                exit_code=None,
                outcome=None,
                result=None,
            ),
            failed_job(),
            a_job(),
            *self.filled(),
        ]
        self.statuses = [
            db.ClusterStatus(
                cluster="alpha",
                observed_at=datetime.now(UTC),
                outcome="done",
                result={"summary": {"release_state": "behind"}},
                warnings=[],
                error=None,
                poll_error=None,
            )
        ]
        self.actors = {REQUEST: "operator"}

    @staticmethod
    def filled() -> list[Any]:
        """Jobs that fill the nullable fields the others leave empty (review 26-10-31, P3-7)."""

        def answer(code: str, message: str, **more: Any) -> dict[str, Any]:
            return {
                "ok": False,
                "outcome": "failed",
                "warnings": [],
                "error": {"code": code, "message": message},
                "result": None,
                **more,
            }

        return [
            # Published and not deployed: the follow-up line and its command.
            a_job(
                id=44,
                operation="changes_publish",
                payload={"drafts": [{"id": "shop"}]},
                result={
                    "ok": True,
                    "outcome": "done",
                    "warnings": [],
                    "error": None,
                    "result": {
                        "version": 7,
                        "deployment_required": True,
                        "next_command": "haprion-deploy -c alpha",
                    },
                },
            ),
            # A publish whose deploy failed: the step note, and so the note.
            a_job(
                id=45,
                state="failed",
                outcome="failed",
                exit_code=65,
                operation="changes_publish",
                payload={"deploy": True},
                result=answer(
                    "node_unreachable",
                    "node-a did not answer.",
                    step="deploy",
                    publish={"ok": True, "outcome": "done", "result": {"version": 7}},
                ),
            ),
            # A run that waits on the CA: what it waits for, and its warning.
            a_job(
                id=46,
                operation="cert_publish",
                cluster=None,
                state="partial",
                outcome="partial",
                result={
                    "ok": True,
                    "outcome": "partial",
                    "warnings": [{"code": "request_pending", "message": "Waiting for the CA."}],
                    "error": None,
                    "result": {},
                },
            ),
            # A certificate issued and registered, and not distributed.
            a_job(
                id=47,
                state="failed",
                outcome="failed",
                exit_code=65,
                operation="cert_issue",
                cluster=None,
                result=answer(
                    "publish_failed",
                    "The certificate is registered but not published.",
                    result={
                        "id": "web",
                        "publish": {
                            "certificates": [{"status": "failed"}],
                            "deployments": [{"cluster": "alpha", "exit_code": 1}],
                        },
                    },
                ),
            ),
        ]

    def test_the_jobs_fill_the_fields_they_are_meant_to(self) -> None:
        shown = {
            number: self.call(f"/jobs/{number}", self.issue(level="write")).json()["result"]
            for number in (44, 45, 46, 47)
        }
        self.assertEqual(shown[44]["next_command"], "haprion-deploy -c alpha")
        self.assertIsNotNone(shown[44]["follow_up"])
        self.assertIsNotNone(shown[45]["step_note"])
        self.assertEqual(shown[46]["warning_codes"], ["request_pending"])
        self.assertIsNotNone(shown[46]["waiting_for"])
        self.assertIsNotNone(shown[46]["warning_message"])
        self.assertIsNotNone(shown[47]["distribution_note"])
        self.assertIsNotNone(shown[47]["note"])


class TheRefusals(ReadingTestCase):
    """Every refusal is the one envelope, whichever route gave it."""

    def refused(self, response: Any, status: int, code: str) -> None:
        self.assertEqual(response.status_code, status, response.text)
        body = response.json()
        self.assertEqual(body["error"]["code"], code)
        self.assertEqual(sorted(envelope_checker().iter_errors(body), key=str), [])
        refusal = checker(json.loads((SCHEMAS / "refusal.schema.json").read_text("utf-8")))
        self.assertEqual(sorted(refusal.iter_errors(body), key=str), [])

    def test_the_codes_a_script_is_told_to_expect(self) -> None:
        client = self.api()
        with self.assertLogs("haprion_ui.api"):
            self.refused(client.get("/api/v1/clusters"), 401, "unauthorized")
        self.refused(self.get("/clusters", level="block"), 403, "forbidden")
        self.refused(self.get("/clusters/gamma"), 404, "not_found")
        self.refused(self.get("/clusters/alpha/objects", limit=0), 400, "bad_input")
        secret = self.issue()
        self.refused(
            client.post("/api/v1/clusters", headers={"Authorization": f"Bearer {secret}"}),
            405,
            "method_not_allowed",
        )
        guess = {"Authorization": f"Bearer {api_tokens.new_secret()}"}
        with self.assertLogs("haprion_ui.api"):
            for _ in range(api.caller.FAILURES_PER_MINUTE):
                client.get("/api/v1/token", headers=guess)
        with self.assertLogs("haprion_ui.api", "WARNING"):
            self.refused(client.get("/api/v1/token", headers=guess), 429, "rate_limited")

    def test_the_schema_lists_the_codes_the_api_gives(self) -> None:
        refusal = json.loads((SCHEMAS / "refusal.schema.json").read_text("utf-8"))
        listed = set(refusal["properties"]["error"]["properties"]["code"]["enum"])
        sources = "".join(path.read_text("utf-8") for path in (PACKAGE / "api").glob("*.py"))
        for code in listed:
            with self.subTest(code=code):
                # Review 26-10-31, P3-6: nginx gives two of them, in the example it ships.
                self.assertTrue(f'"{code}"' in sources or f'"code":"{code}"' in NGINX, code)

    def test_what_nginx_answers_is_a_refusal_the_schema_describes(self) -> None:
        refusal = checker(json.loads((SCHEMAS / "refusal.schema.json").read_text("utf-8")))
        bodies = re.findall(r"return \d{3} '(\{.*\})';", NGINX)
        self.assertGreaterEqual(len(bodies), 5)
        for text in bodies:
            with self.subTest(body=text[:90]):
                body = json.loads(
                    text.replace("$haprion_request_uuid", "6f1c0a52-3d4e-4b7a-9c21-0e5f6a7b8c9d")
                )
                self.assertEqual(sorted(refusal.iter_errors(body), key=str), [])
                self.assertEqual(sorted(envelope_checker().iter_errors(body), key=str), [])


class EveryRouteHasItsSchema(ApiTestCase):
    def named(self) -> dict[str, Any]:
        routes = api_routes(self.client())
        return {route.name: route for route in routes if route.path != "/openapi.json"}

    def test_the_routes_and_the_schemas_are_the_same_set(self) -> None:
        names = set(self.named())
        schemas = set(contract.operations())
        self.assertEqual((sorted(names - schemas), sorted(schemas - names)), ([], []))

    def test_every_route_is_called_with_both_tokens_by_a_group_above(self) -> None:
        called = {name for group in Checked.__subclasses__() for name in group.CALLS} | {
            name for group in Written.__subclasses__() for name in group.CALLS
        }
        self.assertEqual(sorted(set(self.named()) - called), [])

    def test_the_openapi_document_describes_every_answer(self) -> None:
        response = self.api().get(
            "/api/v1/openapi.json", headers={"Authorization": f"Bearer {self.issue()}"}
        )
        self.assertEqual(response.status_code, 200)
        paths = response.json()["paths"]
        for name, route in self.named().items():
            with self.subTest(operation=name):
                [method] = route.methods - {"HEAD"}
                answered = paths[route.path][method.lower()]["responses"]
                [success] = [code for code in answered if code.startswith("2")]
                shown = answered[success]["content"]["application/json"]
                self.assertEqual(int(success), route.status_code or 200)
                schema = shown["schema"]
                self.assertEqual(schema["properties"]["operation"], {"const": name})
                self.assertTrue(schema["properties"]["result"], "an empty schema")
                # One document: no reference left that points at a file.
                self.assertNotIn('"$ref"', json.dumps(schema))
                Draft202012Validator.check_schema(schema)
                refusal = answered["default"]
                self.assertIn("unauthorized", json.dumps(refusal))


class TheSchemasSayWhatEachFieldIs(unittest.TestCase):
    """Code, text or value, said in each field's own description."""

    def documents(self) -> list[tuple[str, dict[str, Any]]]:
        return [
            (path.name, json.loads(path.read_text("utf-8")))
            for path in sorted(SCHEMAS.glob("*.schema.json"))
        ]

    def properties(self) -> list[tuple[str, dict[str, Any], Parts]]:
        found: list[tuple[str, dict[str, Any], Parts]] = []

        def walk(node: Any, where: str, resolver: Resolver[Any]) -> None:
            if isinstance(node, list):
                for item in node:
                    walk(item, where, resolver)
            elif isinstance(node, dict):
                for key, prop in node.get("properties", {}).items():
                    if isinstance(prop, dict):
                        found.append((f"{where}.{key}", prop, parts(prop, resolver)))
                for value in node.values():
                    walk(value, where, resolver)

        for name, document in self.documents():
            walk(document, name, registry().resolver(str(document["$id"])))
        return found

    def test_every_field_has_a_description_and_a_leaf_says_which_kind(self) -> None:
        found = self.properties()
        self.assertGreater(len(found), 200)
        for where, prop, _ in found:
            with self.subTest(field=where):
                text = prop.get("description", "")
                self.assertNotEqual(text, "", "no description")
                container = "properties" in prop or (
                    prop.get("type") == "array"
                    and any(key in prop.get("items", {}) for key in ("properties", "$ref"))
                )
                if not container:
                    self.assertTrue(text.startswith(PROSE), text)

    def test_a_code_is_a_list_of_values_or_a_pattern(self) -> None:
        for where, prop, resolved in self.properties():
            if not prop.get("description", "").startswith("Code."):
                continue
            with self.subTest(field=where):
                if prop.get("type") == "array":
                    resolved = [
                        part
                        for schema, resolver in resolved
                        for part in parts(schema["items"], resolver)
                    ]
                self.assertTrue(
                    any(
                        key in schema
                        for schema, _ in resolved
                        for key in ("enum", "pattern", "const")
                    )
                )


class TheCodesAreTheOnesTheCodeUses(unittest.TestCase):
    """An enumeration is written out in the schema, so a test holds it to the code that produces it."""

    def enum(self, document: str, *keys: str) -> list[Any]:
        found: Any = json.loads((SCHEMAS / document).read_text("utf-8"))
        for key in keys:
            found = found[key]
        return list(found["enum"])

    def test_the_enumerations_match_their_sources(self) -> None:
        definitions = "definitions.schema.json"
        pairs = {
            "attention kind": (
                self.enum(definitions, "$defs", "attention_item", "properties", "kind"),
                attention.KINDS,
            ),
            "severity": (self.enum(definitions, "$defs", "severity"), attention.SEVERITIES),
            "tone": (self.enum(definitions, "$defs", "tone"), get_args(dashboard.Tone.__value__)),
            "job operation": (
                self.enum(definitions, "$defs", "job_operation"),
                tuple(OPERATION_LABELS),
            ),
            "job state": (self.enum(definitions, "$defs", "job_state"), get_args(api_jobs.State)),
            "protocol": (
                [
                    p
                    for p in self.enum(
                        definitions, "$defs", "object_entry", "properties", "protocol"
                    )
                    if p not in {"unknown", None}
                ],
                PROTOCOLS,
            ),
            "token level": (
                self.enum("token_show.schema.json", "properties", "token", "properties", "level"),
                api_tokens.LEVELS,
            ),
            "certificate source": (
                [
                    s
                    for s in self.enum(
                        "certificate_list.schema.json",
                        "properties",
                        "certificates",
                        "items",
                        "properties",
                        "source",
                    )
                    if s != "unknown"
                ],
                SOURCE_KINDS,
            ),
            "waf mode": (
                self.enum(
                    "waf_findings.schema.json",
                    "properties",
                    "objects",
                    "items",
                    "properties",
                    "mode",
                ),
                [m for m in ENGINE_WAF_MODES if m != "off"],
            ),
        }
        for name, (written, used) in pairs.items():
            with self.subTest(enumeration=name):
                self.assertEqual(sorted(written), sorted(used))


class TheSchemasReachTheWheel(unittest.TestCase):
    def test_every_schema_file_is_package_data(self) -> None:
        manifest = tomllib.loads((ROOT / "ui" / "pyproject.toml").read_text("utf-8"))
        patterns = manifest["tool"]["setuptools"]["package-data"]["haprion_ui"]
        files = sorted(SCHEMAS.glob("*.json"))
        self.assertGreater(len(files), 14)
        for path in files:
            with self.subTest(file=path.name):
                relative = path.relative_to(PACKAGE).as_posix()
                self.assertTrue(any(fnmatch(relative, pattern) for pattern in patterns))


if __name__ == "__main__":
    unittest.main()
