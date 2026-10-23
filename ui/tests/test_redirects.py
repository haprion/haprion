"""A redirect's address is a literal path with values after it, written so CodeQL can see that (26-10-23).

Every target already began with one of the interface's own paths, but as an
f-string: CodeQL's `py/url-redirection` takes the right side of a `+` as safe -
only the prefix of an address can send a browser elsewhere - and does not look
into formatting. Fifteen alerts stood in code scanning for that alone, accepted
locally and open on GitHub, and they came back whenever the code moved. Measured
against CodeQL 2.26.3: `"/proxies/" + cluster + "/" + name` is not an alert, the
same in an f-string is, and a target the request supplies whole still is.
"""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

from haprion_ui import views

PACKAGE = Path(views.__file__).parent


def _formatted(node: ast.AST) -> bool:
    return any(
        isinstance(inner, ast.JoinedStr)
        and any(isinstance(value, ast.FormattedValue) for value in inner.values)
        for inner in ast.walk(node)
    )


def _called_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
    return None


class RedirectsBeginWithALiteralPath(unittest.TestCase):
    def test_no_redirect_target_is_formatted(self) -> None:
        trees = {
            path: ast.parse(path.read_text(encoding="utf-8"))
            for path in sorted(PACKAGE.rglob("*.py"))
        }
        returns: dict[str, list[ast.expr]] = {}
        for tree in trees.values():
            for function in ast.walk(tree):
                if isinstance(function, ast.FunctionDef):
                    returns.setdefault(function.name, []).extend(
                        node.value
                        for node in ast.walk(function)
                        if isinstance(node, ast.Return) and node.value is not None
                    )
        found = []
        for path, tree in trees.items():
            for function in ast.walk(tree):
                if not isinstance(function, ast.FunctionDef):
                    continue
                assigned: dict[str, list[ast.expr]] = {}
                for node in ast.walk(function):
                    if isinstance(node, ast.Assign):
                        for target in node.targets:
                            if isinstance(target, ast.Name):
                                assigned.setdefault(target.id, []).append(node.value)
                for node in ast.walk(function):
                    if not (
                        isinstance(node, ast.Call)
                        and getattr(node.func, "id", None) == "RedirectResponse"
                        and node.args
                    ):
                        continue
                    target = node.args[0]
                    sources = [target]
                    sources += [
                        value
                        for name in ast.walk(target)
                        if isinstance(name, ast.Name)
                        for value in assigned.get(name.id, [])
                    ]
                    sources += [
                        value
                        for call in ast.walk(target)
                        if isinstance(call, ast.expr) and (called := _called_name(call)) in returns
                        for value in returns[called]
                    ]
                    if any(_formatted(source) for source in sources):
                        found.append(f"{path.relative_to(PACKAGE)}:{node.lineno}")
        self.assertEqual(found, [])


if __name__ == "__main__":
    unittest.main()
