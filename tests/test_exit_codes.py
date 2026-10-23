"""One table of exit codes, and nothing outside it that picks one by number.

Review 2026-10-22, 4-1: `EXIT_NOT_ROOT` was 77 in nineteen modules and 68 in
two, `EXIT_UNAVAILABLE` 68, 69 or 78, and a deploy refused by split brain ended
65 while one refused by the lock ended 75. Each module had its own constants,
so a correction reached one of them. These tests read the source, as the
contract's other source checks do.
"""

from __future__ import annotations

import ast
import io
import unittest
from pathlib import Path

from haprion import exit_codes
from haprion.envelope import Message, envelope
from haprion.helper_protocol import write_document

ROOT = Path(__file__).resolve().parents[1]
SOURCES = (ROOT / "src" / "haprion", ROOT / "ui" / "src" / "haprion_ui")
TABLE = ROOT / "src" / "haprion" / "exit_codes.py"

#
# The values a command could end with that the table names. 0 and 1 are left
# out of the literal check: `return 0` is everywhere, and so is a count.
#
EXITS = {value for value in exit_codes.MEANINGS if value > 1}
#
# Calls whose exit-code argument is given positionally.
#
EXIT_TAKERS = {
    "write_document",
    "refuse",
    "_refuse",
    "refused",
    "fail",
    "answer",
    "SystemExit",
    "exit",
    "FetchResult",
    "CertbotResult",
}


def _modules() -> list[Path]:
    return sorted(
        path for root in SOURCES for path in root.rglob("*.py") if path.resolve() != TABLE
    )


def _name(call: ast.Call) -> str:
    func = call.func
    return func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")


def _exit_literals(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found = []

    def literal(node: ast.AST | None) -> bool:
        return isinstance(node, ast.Constant) and type(node.value) is int and node.value in EXITS

    for node in ast.walk(tree):
        if isinstance(node, ast.keyword) and node.arg in {"exit_code", "blocked_exit"}:
            if literal(node.value):
                found.append(f"{path.name}:{node.value.lineno} exit_code={ast.unparse(node.value)}")
        elif isinstance(node, ast.arguments):
            pairs = list(zip(node.kwonlyargs, node.kw_defaults, strict=True))
            positional = node.posonlyargs + node.args
            pairs += list(
                zip(positional[len(positional) - len(node.defaults) :], node.defaults, strict=True)
            )
            for argument, default in pairs:
                if argument.arg == "exit_code" and literal(default):
                    found.append(f"{path.name}:{argument.lineno} exit_code default")
        elif isinstance(node, ast.Call) and _name(node) in EXIT_TAKERS:
            for given in node.args:
                if literal(given):
                    found.append(f"{path.name}:{node.lineno} {_name(node)}(..., {given.value})")  # type: ignore[attr-defined]
        elif isinstance(node, ast.Return):
            values = node.value.elts if isinstance(node.value, ast.Tuple) else [node.value]
            for value in values:
                if literal(value):
                    found.append(f"{path.name}:{node.lineno} return {value.value}")  # type: ignore[union-attr]
        elif isinstance(node, ast.IfExp):
            for value in (node.body, node.orelse):
                if literal(value):
                    found.append(f"{path.name}:{node.lineno} conditional {value.value}")  # type: ignore[attr-defined]
    return found


class OneTable(unittest.TestCase):
    def test_no_module_names_an_exit_code_of_its_own(self) -> None:
        named = []
        for path in _modules():
            for node in ast.parse(path.read_text(encoding="utf-8")).body:
                targets = node.targets if isinstance(node, ast.Assign) else []
                if isinstance(node, ast.AnnAssign):
                    targets = [node.target]
                for target in targets:
                    if isinstance(target, ast.Name) and (
                        target.id.startswith("EXIT_") or target.id.endswith("_EXIT")
                    ):
                        named.append(f"{path.relative_to(ROOT)}:{node.lineno} {target.id}")
        self.assertEqual(named, [], "exit codes belong in haprion.exit_codes")

    def test_no_module_writes_an_exit_code_as_a_number(self) -> None:
        written = [found for path in _modules() for found in _exit_literals(path)]
        self.assertEqual(written, [], "name the code from haprion.exit_codes")

    def test_every_code_has_one_value_and_a_meaning(self) -> None:
        constants = {
            name: value
            for name, value in vars(exit_codes).items()
            if name.isupper() and isinstance(value, int)
        }
        self.assertEqual(sorted(constants.values()), sorted(set(constants.values())))
        self.assertEqual(set(constants.values()), set(exit_codes.MEANINGS))

    def test_the_contract_lists_the_table(self) -> None:
        contract = (ROOT / "docs" / "CONTRACT.md").read_text(encoding="utf-8")
        for name, value in vars(exit_codes).items():
            if name.isupper() and isinstance(value, int):
                with self.subTest(name):
                    self.assertIn(f"| {value} | `{name}` |", contract)


class TheExitFollowsTheOutcome(unittest.TestCase):
    def document(self, outcome: str) -> dict[str, object]:
        error = Message("refused", "no") if outcome in {"failed", "blocked"} else None
        warnings = (Message("gap", "some"),) if outcome == "partial" else ()
        return envelope(
            operation="deploy",
            outcome=outcome,  # type: ignore[arg-type]
            cluster="alpha",
            result=None,
            warnings=warnings,
            error=error,
        )

    def test_each_outcome_has_its_code(self) -> None:
        for outcome, code in (
            ("done", exit_codes.OK),
            ("partial", exit_codes.PARTIAL),
            ("blocked", exit_codes.BLOCKED),
            ("failed", exit_codes.REFUSED),
            ("failed", exit_codes.UNAVAILABLE),
        ):
            with self.subTest(outcome, code=code):
                stream = io.StringIO()
                self.assertEqual(write_document(stream, self.document(outcome), code), code)
                self.assertTrue(stream.getvalue())

    def test_a_contradiction_is_refused_before_anything_is_written(self) -> None:
        for outcome, code in (
            ("blocked", exit_codes.REFUSED),
            ("partial", exit_codes.OK),
            ("failed", exit_codes.PARTIAL),
            ("done", exit_codes.FAILED),
            ("failed", 42),
        ):
            with self.subTest(outcome, code=code):
                stream = io.StringIO()
                with self.assertRaises(ValueError):
                    write_document(stream, self.document(outcome), code)
                self.assertEqual(stream.getvalue(), "")

    def test_a_passed_on_document_takes_its_outcome_s_code(self) -> None:
        self.assertEqual(exit_codes.for_outcome("partial"), exit_codes.PARTIAL)
        self.assertEqual(exit_codes.for_outcome("blocked"), exit_codes.BLOCKED)
        self.assertEqual(exit_codes.for_outcome("unknown"), exit_codes.FAILED)


if __name__ == "__main__":
    unittest.main()
