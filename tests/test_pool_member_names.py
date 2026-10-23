"""A pool member's name is made in one place (review 2026-10-22, 4-8).

`s{n}` was written by hand in four modules - the generator, dnsdist's
configuration, the server card and the traffic log's addresses - so a change to
the name in one would have left the pages reading counters under the old one.
`proxy_model.server_name` makes it; this refuses an f-string that makes it again.
"""

from __future__ import annotations

import ast
import unittest
from pathlib import Path
from typing import TypeGuard

from haprion import proxy_model

ROOT = Path(__file__).resolve().parents[1]
PACKAGES = (ROOT / "src" / "haprion", ROOT / "ui" / "src" / "haprion_ui")


def _makes_a_server_name(node: ast.AST) -> TypeGuard[ast.JoinedStr]:
    return (
        isinstance(node, ast.JoinedStr)
        and len(node.values) == 2
        and isinstance(node.values[0], ast.Constant)
        and node.values[0].value == "s"
        and isinstance(node.values[1], ast.FormattedValue)
    )


class OnePlaceNamesAPoolMember(unittest.TestCase):
    def test_the_name_is_the_position_from_one(self) -> None:
        self.assertEqual([proxy_model.server_name(index) for index in range(3)], ["s1", "s2", "s3"])

    def test_no_module_writes_the_name_itself(self) -> None:
        found = [
            f"{path.relative_to(ROOT)}:{node.lineno}"
            for package in PACKAGES
            for path in sorted(package.rglob("*.py"))
            if path != Path(proxy_model.__file__)
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
            if _makes_a_server_name(node)
        ]
        self.assertEqual(found, [])


if __name__ == "__main__":
    unittest.main()
