"""A function, class or method of the packages that nothing names is dead code (review 2026-10-22, 4-10).

Four were found by hand: `run_list_helper`, whose docstring said the poller
used it; `require_session`; an editor's `_validation_cluster`; and
`_moved_servers`. Each name occurred once in the tree - its own definition -
and lint passes over a function nobody calls. This counts every name in the
tracked source (Python, templates, scripts, units; not the prose under docs/)
and refuses a top-level definition whose name occurs only where it is defined.
A decorated one is reached through its decorator - a route, a fixture - and is
left out.
"""

from __future__ import annotations

import ast
import re
import subprocess
import unittest
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGES = (ROOT / "src" / "haprion", ROOT / "ui" / "src" / "haprion_ui")
NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _names() -> Counter[str]:
    tracked = subprocess.run(  # fixed program, the repository's own file list
        ["/usr/bin/git", "-C", str(ROOT), "ls-files", "-z"],
        capture_output=True,
        check=True,
    ).stdout.decode()
    counts: Counter[str] = Counter()
    for name in filter(None, tracked.split("\0")):
        # Not the prose, and not this file, whose docstring names the four.
        if name.startswith("docs/") or name == "tests/test_no_dead_code.py":
            continue
        path = ROOT / name
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        counts.update(NAME.findall(text))
    return counts


class NothingIsDefinedThatNothingUses(unittest.TestCase):
    def test_every_top_level_definition_is_named_somewhere_else(self) -> None:
        counts = _names()
        found = [
            f"{path.relative_to(ROOT)}:{node.lineno} {node.name}"
            for package in PACKAGES
            for path in sorted(package.rglob("*.py"))
            for node in ast.parse(path.read_text(encoding="utf-8")).body
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef)
            and not node.decorator_list
            and counts[node.name] <= 1
        ]
        self.assertEqual(found, [])


if __name__ == "__main__":
    unittest.main()
