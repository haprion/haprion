"""Every way to save an object holds it to what a write may be (review 26-10-25, 5-01).

A stored object is read as it was stored; one being saved is held to the rules
for what is written (`load_written`, 15-06). A WAF exception saved an object
through `load_proxy` alone, and the publish then refused it with everybody's
saved changes behind it. The rule is held here for every caller of
`db.save_change`, not for the one that was found.
"""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / "src" / "haprion_ui"
#
# The checks that hold a document to the write rules themselves, and are held
# to calling `load_written` below.
#
CHECKS = {("editor_module", "check"), ("advanced_dialog", "check")}


def _called(node: ast.AST) -> set[tuple[str, str]]:
    """(owner, name) of every call in `node`; owner "" for a bare name."""

    found = set()
    for call in ast.walk(node):
        if not isinstance(call, ast.Call):
            continue
        if isinstance(call.func, ast.Name):
            found.add(("", call.func.id))
        elif isinstance(call.func, ast.Attribute):
            owner = call.func.value
            found.add((owner.id if isinstance(owner, ast.Name) else "", call.func.attr))
    return found


def _saves_a_document(function: ast.AST) -> bool:
    for call in ast.walk(function):
        if (
            isinstance(call, ast.Call)
            and isinstance(call.func, ast.Attribute)
            and call.func.attr == "save_change"
        ):
            deleted = next((word for word in call.keywords if word.arg == "deleted"), None)
            if not (isinstance(deleted, ast.keyword) and isinstance(deleted.value, ast.Constant)):
                return True
            if deleted.value.value is not True:
                return True
    return False


class EveryWayToSaveAnObject(unittest.TestCase):
    def test_holds_it_to_what_a_write_may_be(self) -> None:
        savers = []
        unchecked = []
        for path in sorted(SOURCE.rglob("*.py")):
            for function in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if not isinstance(function, ast.FunctionDef) or not _saves_a_document(function):
                    continue
                savers.append(function.name)
                called = _called(function)
                if ("", "load_written") not in called and not called & CHECKS:
                    unchecked.append(f"{path.name}: {function.name}")
        self.assertGreaterEqual(len(savers), 4, savers)
        self.assertEqual(unchecked, [], "call load_written on the document before it is saved")

    def test_the_checks_it_accepts_call_load_written(self) -> None:
        for module, name in sorted(CHECKS):
            path = SOURCE / f"{module.removesuffix('_module')}.py"
            tree = ast.parse(path.read_text(encoding="utf-8"))
            (function,) = (
                node
                for node in tree.body
                if isinstance(node, ast.FunctionDef) and node.name == name
            )
            with self.subTest(module=module):
                self.assertIn(("", "load_written"), _called(function))


if __name__ == "__main__":
    unittest.main()
