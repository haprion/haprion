"""A job or a draft refused because of another is one page wherever it is met (review 26-10-24, 07-02).

The application answers the four refusals (`app.py`); a route catches one only
to do something of its own first, and the routes that may are named below with
why. Bare text, a page, a redirect with a query, a form drawn again and JSON
were five answers to one question.
"""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

from starlette.requests import Request

from haprion_ui import db, views
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
    ("views.py", "_queue_node_job"): "a second click is answered with the first's job",
    ("pages/certificates.py", "new_certificate_submit"): "the form is drawn again as it was typed",
    ("pages/certificates.py", "certificate_renew_confirm"): "the question is drawn again",
    ("pages/certificates.py", "certificate_retarget_confirm"): "the question is drawn again",
    ("pages/certificates.py", "_queue_receiver_job"): "the receiver's form is drawn again",
    ("pages/certificates.py", "certificate_delete_confirm"): "the question is drawn again",
    ("pages/profiles.py", "_dns_profile_submit"): "the form is drawn again as it was typed",
    ("pages/profiles.py", "_ndes_profile_submit"): "the form is drawn again as it was typed",
    ("pages/settings.py", "cluster_settings_save"): "the form is drawn again as it was typed",
    ("pages/proxies.py", "proxy_servers"): "the server card says it in place",
    ("pages/proxies.py", "proxy_unblock"): "the blocked-address card says it in place",
    ("views.py", "_discard_shown"): "a newer draft is kept, not refused",
    ("views.py", "_settled_changes"): "a newer saved change is kept, not refused",
    ("views.py", "_advanced_submit"): "the dialog answers in its own document",
    ("views.py", "_waf_save"): "the dialog answers in its own document",
}


def caught() -> set[tuple[str, str]]:
    found: set[tuple[str, str]] = set()
    for path in [*sorted((PACKAGE / "pages").glob("*.py")), PACKAGE / "views.py"]:
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

        for path in [*sorted((PACKAGE / "pages").glob("*.py")), PACKAGE / "views.py"]:
            with self.subTest(path=path.name):
                self.assertNotIn("asked for something else", path.read_text(encoding="utf-8"))

    def test_a_script_is_answered_in_text_with_the_same_sentence(self) -> None:
        answer = views.conflict_page(request("application/json"), configuration(), db.ClusterBusy())

        self.assertEqual(answer.status_code, 409)
        self.assertEqual(bytes(answer.body).decode(), views.CONFLICT_SENTENCES[db.ClusterBusy])

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
                self.assertEqual(views._page_it_came_from(Request(scope)), back)


if __name__ == "__main__":
    unittest.main()
