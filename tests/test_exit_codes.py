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
import json
import os
import unittest
from pathlib import Path
from unittest import mock

from haprion import exit_codes, helper_protocol
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
            #
            # `return code or 70` too: the number is the second operand
            # (review 26-10-24, 06-09).
            #
            values = [
                operand
                for value in values
                for operand in (value.values if isinstance(value, ast.BoolOp) else [value])
            ]
            for value in values:
                if literal(value):
                    found.append(f"{path.name}:{node.lineno} return {value.value}")  # type: ignore[union-attr]
        elif isinstance(node, ast.IfExp):
            for value in (node.body, node.orelse):
                if literal(value):
                    found.append(f"{path.name}:{node.lineno} conditional {value.value}")  # type: ignore[attr-defined]
    return found


class OneTable(unittest.TestCase):
    def test_every_command_parses_with_the_parser_that_exits_usage(self) -> None:
        """Review 26-10-24, 06-06: argparse's own 2 is in no table."""

        cli = Path(__file__).resolve().parents[1] / "src/haprion/cli"
        own = [
            path.name
            for path in sorted(cli.glob("*.py"))
            if path.name != "arguments.py" and "argparse.ArgumentParser(" in path.read_text()
        ]
        self.assertEqual(own, [])

    def test_a_mistyped_flag_exits_usage(self) -> None:
        from haprion.cli import cert_target

        with (
            mock.patch("sys.stderr", new_callable=io.StringIO) as said,
            self.assertRaises(SystemExit) as stopped,
        ):
            cert_target.main(["--no-such-flag"])
        self.assertEqual(stopped.exception.code, exit_codes.USAGE)
        self.assertIn("haprion-cert-target: error:", said.getvalue())

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


class AForeignExit(unittest.TestCase):
    def test_a_code_of_the_table_is_kept_and_needs_no_sentence(self) -> None:
        self.assertEqual(exit_codes.foreign(exit_codes.BLOCKED, "x helper"), (75, None))

    def test_a_signal_or_a_stranger_is_internal_and_may_have_acted(self) -> None:
        """Review 26-10-24, 13-05."""

        for returncode, said in ((-9, "was stopped by signal 9"), (3, "ended with 3")):
            with self.subTest(returncode=returncode):
                code, sentence = exit_codes.foreign(returncode, "revert helper")
                self.assertEqual(code, exit_codes.INTERNAL)
                assert sentence is not None
                self.assertIn(f"the revert helper {said}", sentence)
                self.assertTrue(sentence.endswith("it may have acted"))


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

    CONTRADICTIONS = (
        ("blocked", exit_codes.REFUSED, exit_codes.BLOCKED),
        ("partial", exit_codes.OK, exit_codes.PARTIAL),
        ("failed", exit_codes.PARTIAL, exit_codes.FAILED),
        ("done", exit_codes.FAILED, exit_codes.OK),
        ("failed", 42, exit_codes.FAILED),
        ("failed", -9, exit_codes.FAILED),
    )

    def test_a_contradiction_fails_the_test_suites_before_anything_is_written(self) -> None:
        for outcome, code, _ in self.CONTRADICTIONS:
            with (
                self.subTest(outcome, code=code),
                mock.patch.dict(os.environ, {helper_protocol.STRICT_VARIABLE: "1"}),
            ):
                stream = io.StringIO()
                with self.assertRaises(ValueError):
                    write_document(stream, self.document(outcome), code)
                self.assertEqual(stream.getvalue(), "")

    def test_in_use_a_contradiction_still_writes_the_document_with_the_outcome_s_code(
        self,
    ) -> None:
        """Part 06's own point: work done and no answer was the worst way out."""

        for outcome, code, used in self.CONTRADICTIONS:
            with (
                self.subTest(outcome, code=code),
                mock.patch.dict(os.environ, {helper_protocol.STRICT_VARIABLE: "0"}),
                mock.patch("sys.stderr", new_callable=io.StringIO) as said,
            ):
                stream = io.StringIO()
                self.assertEqual(write_document(stream, self.document(outcome), code), used)
                self.assertEqual(json.loads(stream.getvalue())["outcome"], outcome)
                self.assertIn(f"exiting {used}", said.getvalue())

    def test_a_test_run_on_its_own_is_strict_too(self) -> None:
        """Review 26-10-25, part 1's own point: only `run-tests` set it, not one module run alone."""

        environment = {k: v for k, v in os.environ.items() if k != helper_protocol.STRICT_VARIABLE}
        with mock.patch.dict(os.environ, environment, clear=True), self.assertRaises(ValueError):
            write_document(io.StringIO(), self.document("blocked"), exit_codes.REFUSED)

    def test_a_passed_on_document_takes_its_outcome_s_code(self) -> None:
        self.assertEqual(exit_codes.for_outcome("partial"), exit_codes.PARTIAL)
        self.assertEqual(exit_codes.for_outcome("blocked"), exit_codes.BLOCKED)
        self.assertEqual(exit_codes.for_outcome("unknown"), exit_codes.FAILED)


class OneWayToWriteADocument(unittest.TestCase):
    """Review 26-10-24, 06-07: the refusals' copies had drifted apart.

    Two wrote `json.dumps(failure(...))` past `write_document`, without its
    exit check or its one form, and eleven spelled out `config_error_code` by
    hand.
    """

    def test_no_envelope_is_serialised_outside_write_document(self) -> None:
        found = []
        for path in _modules():
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if (
                    isinstance(node, ast.Call)
                    and _name(node) == "dumps"
                    and node.args
                    and isinstance(node.args[0], ast.Call)
                    and _name(node.args[0]) in {"failure", "envelope"}
                ):
                    found.append(f"{path.relative_to(ROOT)}:{node.lineno}")
        self.assertEqual(found, [], "write the document with helper_protocol.write_document")

    def test_the_code_of_a_configuration_failure_is_chosen_in_one_place(self) -> None:
        found = []
        for path in _modules():
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if (
                    isinstance(node, ast.IfExp)
                    and isinstance(node.body, ast.Constant)
                    and node.body.value == "bad_input"
                    and isinstance(node.orelse, ast.Constant)
                    and node.orelse.value == "dependency_unavailable"
                    and path.name != "helper_protocol.py"
                ):
                    found.append(f"{path.relative_to(ROOT)}:{node.lineno}")
        self.assertEqual(found, [], "use helper_protocol.config_error_code")


if __name__ == "__main__":
    unittest.main()
