"""A job or a draft refused because of another is one page wherever it is met (review 26-10-24, 07-02).

The application answers the four refusals (`app.py`); a route catches one only
to do something of its own first, and the routes that may are named below with
why. Bare text, a page, a redirect with a query, a form drawn again and JSON
were five answers to one question.
"""

from __future__ import annotations

import ast
import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

from starlette.requests import Request

from haprion_ui import db, refusals, views
from tests.test_jobs import queued_job
from tests.test_login import configuration

PACKAGE = Path(views.__file__).parent
REFUSALS = {"ClusterBusy", "CertificateBusy", "RequestConflict", "DraftConflict"}

#
# Where a route still catches one of them, and why the application's page is
# not the answer there.
#
CAUGHT = {
    ("pages/backups.py", "_queue_restore_job"): "a second click is answered with the first's job",
    ("pages/certificates.py", "_queue_import"): "a second click is answered with the first's job",
    ("views.py", "queue_node_job"): "a second click is answered with the first's job",
    ("pages/certificates.py", "new_certificate_submit"): "the form is drawn again as it was typed",
    ("pages/certificates.py", "certificate_renew_confirm"): "the question is drawn again",
    ("pages/certificates.py", "certificate_retarget_confirm"): "the question is drawn again",
    ("pages/certificates.py", "_queue_receiver_job"): "the receiver's form is drawn again",
    ("pages/certificates.py", "certificate_delete_confirm"): "the question is drawn again",
    ("pages/certificates.py", "certificate_abandon_confirm"): "the question is drawn again",
    ("pages/profiles.py", "_dns_profile_submit"): "the form is drawn again as it was typed",
    ("pages/profiles.py", "_ndes_profile_submit"): "the form is drawn again as it was typed",
    ("pages/settings.py", "cluster_settings_save"): "the form is drawn again as it was typed",
    ("pages/proxies.py", "proxy_servers"): "the server card says it in place",
    ("pages/proxies.py", "proxy_unblock"): "the blocked-address card says it in place",
    ("saved_work.py", "_discard_shown"): "a newer draft is kept, not refused",
    ("saved_work.py", "settled_changes"): "a newer saved change is kept, not refused",
    ("editor_flow.py", "advanced_submit"): "the dialog answers in its own document",
    ("waf_work.py", "_waf_save"): "the dialog answers in its own document",
    # Found when the scan widened from pages/ and views.py to the package (K01).
    ("feature_switch.py", "switch"): "the switch is refused with its own sentence",
    ("profile_apply.py", "_queue"): "the command answers in its own contract",
}


def caught() -> set[tuple[str, str]]:
    found: set[tuple[str, str]] = set()
    for path in [*sorted(PACKAGE.glob("*.py")), *sorted((PACKAGE / "pages").glob("*.py"))]:
        name = str(path.relative_to(PACKAGE))

        def visit(node: ast.AST, function: str) -> None:
            for child in ast.iter_child_nodes(node):
                if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef):
                    visit(child, child.name)
                    continue
                if isinstance(child, ast.ExceptHandler) and child.type is not None:
                    types = child.type.elts if isinstance(child.type, ast.Tuple) else [child.type]
                    if {t.attr for t in types if isinstance(t, ast.Attribute)} & REFUSALS:
                        found.add((name, function))  # noqa: B023 - read at once
                visit(child, function)

        visit(ast.parse(path.read_text(encoding="utf-8")), "<module>")
    return found


def caught_busy() -> set[tuple[str, str]]:
    """The named routes whose handler catches a busy queue, as opposed to a draft."""

    busy = {"ClusterBusy", "CertificateBusy"}
    found: set[tuple[str, str]] = set()
    for name, function in CAUGHT:
        tree = ast.parse((PACKAGE / name).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name == function:
                for handler in ast.walk(node):
                    if isinstance(handler, ast.ExceptHandler) and handler.type is not None:
                        types = (
                            handler.type.elts
                            if isinstance(handler.type, ast.Tuple)
                            else [handler.type]
                        )
                        if {t.attr for t in types if isinstance(t, ast.Attribute)} & busy:
                            found.add((name, function))
    return found


def calls(path: Path, function: str) -> set[str]:
    """The names of what `function` in `path` calls."""

    called: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name == function:
            for call in ast.walk(node):
                if isinstance(call, ast.Call):
                    target = call.func
                    if isinstance(target, ast.Attribute):
                        called.add(target.attr)
                    elif isinstance(target, ast.Name):
                        called.add(target.id)
    return called


def request(content_type: str) -> Request:
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/operations",
            "headers": [(b"content-type", content_type.encode())],
            "query_string": b"",
        }
    )


class OneAnswer(unittest.TestCase):
    def test_only_the_named_routes_catch_a_refusal_themselves(self) -> None:
        self.assertEqual(caught(), set(CAUGHT))

    def test_a_route_that_catches_one_answers_a_conflict_with_the_page(self) -> None:
        """Review 26-10-25, 2-04: three second-click branches still answered in bare text."""

        for path in [*sorted(PACKAGE.glob("*.py")), *sorted((PACKAGE / "pages").glob("*.py"))]:
            with self.subTest(path=path.name):
                self.assertNotIn("asked for something else", path.read_text(encoding="utf-8"))

    def test_a_route_that_catches_a_busy_queue_says_it_by_the_one_rule(self) -> None:
        """Review 26-10-29, A3: thirteen routes and twelve forms said "wait for it to
        finish" of a held job, each with a sentence of its own."""

        for name, function in sorted(caught_busy()):
            with self.subTest(route=f"{name}:{function}"):
                self.assertTrue(
                    calls(PACKAGE / name, function)
                    & {"conflict_sentence", "busy_query", "not_finishing"},
                    "say a busy queue by refusals.conflict_sentence, busy_query or not_finishing",
                )
        #
        # The command says a merely busy queue in its own words, by the same rule.
        #
        for path in [*sorted(PACKAGE.glob("*.py")), *sorted((PACKAGE / "pages").glob("*.py"))]:
            if path.name in {"refusals.py", "jobs.py", "profile_apply.py"}:
                continue
            with self.subTest(path=path.name):
                self.assertNotIn("already running", path.read_text(encoding="utf-8"))
        for path in sorted((PACKAGE / "templates").glob("*.html")):
            if path.name == "_certificate_job.html":
                continue
            with self.subTest(template=path.name):
                self.assertNotIn("{{ certificate_job }}", path.read_text(encoding="utf-8"))
        #
        # Nor may a form say a job "has finished" outside the one macro that knows
        # whether it will (D3): the node restore's own sentence said it of a
        # held job.
        #
        for path in sorted((PACKAGE / "templates").glob("*.html")):
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if "once it has finished" in line and path.name != "_certificate_job.html":
                    with self.subTest(template=path.name, line=number):
                        self.assertTrue(line.lstrip().startswith("{% call certificate_job_notice"))

    def test_a_script_is_answered_in_text_with_the_same_sentence(self) -> None:
        answer = refusals.conflict_page(
            request("application/json"), configuration(), db.ClusterBusy()
        )

        self.assertEqual(answer.status_code, 409)
        self.assertEqual(bytes(answer.body).decode(), refusals.CONFLICT_SENTENCES[db.ClusterBusy])

    def test_a_job_that_will_not_finish_by_itself_is_said_as_it_is(self) -> None:
        """Review 26-10-29, Q07/R05: "try again when it has finished" of a held job."""

        now = datetime.now(UTC)
        held = replace(queued_job(), held_since=now)
        gone = replace(
            queued_job(),
            state="running",
            started_at=now,
            lease_lapsed_since=now - timedelta(hours=1),
        )
        for refused, sentence in (
            (db.ClusterBusy("alpha", active=held), refusals.HELD_BUSY),
            (db.CertificateBusy(active=held), refusals.HELD_BUSY),
            (db.ClusterBusy("alpha", active=gone), refusals.NO_WORKER_BUSY),
            (
                db.ClusterBusy("alpha", active=queued_job()),
                refusals.CONFLICT_SENTENCES[db.ClusterBusy],
            ),
            (db.CertificateBusy(), refusals.CONFLICT_SENTENCES[db.CertificateBusy]),
        ):
            with self.subTest(refused=refused, active=refused.active):
                answer = refusals.conflict_page(
                    request("application/json"), configuration(), refused
                )
                self.assertEqual(bytes(answer.body).decode(), sentence)
        self.assertIn("Run or Discard on Events", refusals.HELD_BUSY)

    def test_the_page_it_came_from_is_only_ever_one_of_ours(self) -> None:
        for referer, back in (
            ("https://manager.example.com/settings/clusters/alpha?x=1", "/settings/clusters/alpha"),
            ("https://example.net/elsewhere", "/"),
            ("//example.net/elsewhere", "/"),
            ("", "/"),
        ):
            with self.subTest(referer=referer):
                scope = request("application/x-www-form-urlencoded").scope
                scope["headers"] = [
                    (b"host", b"manager.example.com"),
                    (b"referer", referer.encode()),
                ]
                self.assertEqual(refusals._page_it_came_from(Request(scope)), back)


if __name__ == "__main__":
    unittest.main()
