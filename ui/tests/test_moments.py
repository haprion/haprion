"""One format for a moment on every page (review 2026-10-22, 2-5, 2-6, 7-18).

Versions and Node backups wrote a four-digit year, Needs attention left out
the seconds, and one of its rows held two clocks in two formats. `moments`
writes a moment, a day and a time; the source check refuses a format written
anywhere else in the interface.
"""

from __future__ import annotations

import ast
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest import mock

from haprion_ui import metrics, moments

PACKAGE = Path(__file__).resolve().parents[1] / "src" / "haprion_ui"
#
# The module that writes them, the one that draws the charts' axes in their
# own short labels, and four formats that are not a moment on a page: a
# schedule's time of day with its zone, the ISO stamp a WAF exception stores
# and the one it is compared in, and an archive's name in the demo data.
#
WRITERS = {"moments.py", "metrics.py"}
NOT_A_MOMENT = {
    ("backups.py", "%H:%M %Z"),
    ("waf_work.py", "%Y-%m-%dT%H:%M:%SZ"),
    ("preview.py", "%Y-%m-%dT%H:%M:%SZ"),
    ("demo.py", "%Y-%m-%d_%H-%M-%S"),
}


def _formats(path: Path) -> list[tuple[str, int]]:
    found = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Call) and getattr(node.func, "attr", "") == "strftime":
            argument = node.args[0] if node.args else ast.Constant("")
            text = argument.value if isinstance(argument, ast.Constant) else ast.unparse(argument)
            found.append((str(text), node.lineno))
        elif (
            isinstance(node, ast.Call)
            and getattr(node.func, "attr", "") == "isoformat"
            and isinstance(node.func.value, ast.Call)  # type: ignore[attr-defined]
            and getattr(node.func.value.func, "attr", "") == "date"  # type: ignore[attr-defined]
        ):
            found.append(("date().isoformat()", node.lineno))
        elif isinstance(node, ast.FormattedValue) and isinstance(node.format_spec, ast.JoinedStr):
            spec = "".join(
                str(part.value)
                for part in node.format_spec.values
                if isinstance(part, ast.Constant)
            )
            if "%" in spec:
                found.append((spec, node.lineno))
    return found


class OneFormat(unittest.TestCase):
    def test_no_page_formats_a_moment_of_its_own(self) -> None:
        written = [
            f"{path.relative_to(PACKAGE)}:{line} {text}"
            for path in sorted(PACKAGE.rglob("*.py"))
            if path.name not in WRITERS
            for text, line in _formats(path)
            if (path.name, text) not in NOT_A_MOMENT
        ]
        self.assertEqual(written, [], "use haprion_ui.moments or its filters")

    def test_no_template_formats_one(self) -> None:
        templates = [
            str(path.relative_to(PACKAGE))
            for path in sorted((PACKAGE / "templates").rglob("*.html"))
            if "strftime" in path.read_text(encoding="utf-8")
        ]
        self.assertEqual(templates, [], "use the shown_at, shown_day and shown_time filters")

    def test_the_three_forms(self) -> None:
        at = datetime(2026, 10, 23, 7, 5, 9, tzinfo=UTC)
        with mock.patch.object(metrics, "shown", side_effect=lambda moment: moment):
            self.assertEqual(
                (moments.moment(at), moments.day(at), moments.time_of_day(at)),
                ("26-10-23 07:05:09", "26-10-23", "07:05:09"),
            )


if __name__ == "__main__":
    unittest.main()
