"""`tools/check-codeql-sarif.py` holds every acceptance to the findings it covers (2026-10-22).

An entry carries no line number, so it covers every finding with its message in
its file. The redirect entry for views.py had come to cover fourteen findings
while its reason described three, and when K1 moved the pages out, the stale
entry ended the run before the thirteen it no longer covered were listed.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
SCRIPT = BASE / "tools" / "check-codeql-sarif.py"

REDIRECT = "Untrusted URL redirection depends on a [user-provided value](1)."


def _load() -> Any:
    spec = importlib.util.spec_from_file_location("check_codeql_sarif", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _result(path: str, line: int, message: str = REDIRECT) -> dict[str, Any]:
    return {
        "ruleId": "py/url-redirection",
        "level": "error",
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": path},
                    "region": {"startLine": line},
                }
            }
        ],
    }


def _entry(path: str, count: Any = 1, message: str = REDIRECT) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "rule": "py/url-redirection",
        "path": path,
        "message": message,
        "decided": "2026-10-22",
        "reason": "A literal path first, and the value past an allowlist.",
    }
    if count is not None:
        entry["count"] = count
    return entry


class CodeqlGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.gate = _load()
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))

    def verdict(
        self, entries: list[dict[str, Any]], results: list[dict[str, Any]]
    ) -> tuple[int, str]:
        accepted = self.directory / "accepted.json"
        accepted.write_text(json.dumps({"accepted": entries}), encoding="utf-8")
        sarif = self.directory / "python.sarif"
        sarif.write_text(json.dumps({"runs": [{"results": results}]}), encoding="utf-8")
        output = io.StringIO()
        with (
            mock.patch.object(self.gate, "ACCEPTED_PATH", accepted),
            mock.patch("sys.argv", ["check-codeql-sarif.py", str(sarif)]),
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(output),
        ):
            code = self.gate.main()
        return code, output.getvalue()

    def test_an_entry_covering_as_many_findings_as_it_counts_passes(self) -> None:
        code, output = self.verdict(
            [_entry("pages/a.py", count=2)], [_result("pages/a.py", 10), _result("pages/a.py", 20)]
        )

        self.assertEqual(code, 0, output)
        self.assertIn("CodeQL gate: OK", output)

    def test_a_new_finding_in_an_accepted_file_fails_until_the_entry_names_it(self) -> None:
        code, output = self.verdict(
            [_entry("pages/a.py", count=1)], [_result("pages/a.py", 10), _result("pages/a.py", 20)]
        )

        self.assertEqual(code, 1)
        self.assertIn("covers a different number of alerts", output)
        self.assertIn("pages/a.py: 2 found, the entry accepts 1", output)

    def test_a_stale_entry_does_not_hide_the_findings_nobody_accepted(self) -> None:
        code, output = self.verdict(
            [_entry("views.py", count=3)], [_result("pages/a.py", 10), _result("pages/b.py", 20)]
        )

        self.assertEqual(code, 1)
        self.assertIn("acceptance no longer matches any alert", output)
        self.assertIn("FAIL (2 alerts)", output)
        self.assertIn("pages/a.py:10", output)
        self.assertIn("pages/b.py:20", output)

    def test_an_entry_without_a_count_is_refused(self) -> None:
        for count in (None, 0, "2", True):
            with self.subTest(count=count):
                code, output = self.verdict(
                    [_entry("pages/a.py", count=count)], [_result("pages/a.py", 10)]
                )

                self.assertEqual(code, 2)
                self.assertIn("count", output)

    def test_every_recorded_acceptance_states_its_count(self) -> None:
        document = json.loads((BASE / "tools" / "codeql-accepted.json").read_text(encoding="utf-8"))

        self.gate._load_accepted(BASE / "tools" / "codeql-accepted.json")
        for entry in document["accepted"]:
            self.assertEqual(
                list(entry),
                ["rule", "path", "message", "count", "decided", "reason"],
                entry["path"],
            )


if __name__ == "__main__":
    unittest.main()
