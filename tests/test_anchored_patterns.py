"""A pattern that ends in `$` is matched whole (review 2026-10-22, 5-12).

`re.match` with `$` lets one trailing newline through: `NAME.match("shop\\n")`
is true, and the newline went on into a `server` line and a file name. The
source check finds `.match` on a module's compiled pattern ending in `$` -
resolved to the module that defines it, so a name one module anchors and
another does not is not confused - and wants `fullmatch` there.
"""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

from haprion import exit_codes
from haprion.candidate_validation import _allowed_path
from haprion.helper_protocol import HelperProtocolError
from haprion.proxy_model import HOSTNAME, NAME

ROOT = Path(__file__).resolve().parents[1]
ROOTS = [ROOT / "src" / "haprion", ROOT / "ui" / "src" / "haprion_ui"]


def module_name(path: Path, roots: list[Path]) -> str:
    for root in roots:
        try:
            relative = path.relative_to(root.parent)
        except ValueError:
            continue
        return ".".join(relative.with_suffix("").parts)
    raise SystemExit(f"{path} is under no root")


def anchored_names(tree: ast.Module) -> set[str]:
    names: set[str] = set()
    for node in tree.body:
        if not (isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)):
            continue
        func = node.value.func
        if not (isinstance(func, ast.Attribute) and func.attr == "compile" and node.value.args):
            continue
        first = node.value.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            pattern = first.value
            if pattern.endswith("$") and not pattern.endswith("\\$"):
                names.update(t.id for t in node.targets if isinstance(t, ast.Name))
    return names


def _anchored_matches() -> list[str]:
    files = [path for root in ROOTS for path in sorted(root.rglob("*.py"))]
    trees = {path: ast.parse(path.read_text(encoding="utf-8")) for path in files}
    modules = {module_name(path, ROOTS): path for path in files}
    defined = {module_name(path, ROOTS): anchored_names(tree) for path, tree in trees.items()}
    found = []
    for path, tree in trees.items():
        here = module_name(path, ROOTS)
        imported_names: dict[str, tuple[str, str]] = {}
        imported_modules: dict[str, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                for alias in node.names:
                    target = f"{node.module}.{alias.name}"
                    if target in modules:
                        imported_modules[alias.asname or alias.name] = target
                    else:
                        imported_names[alias.asname or alias.name] = (node.module, alias.name)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in modules:
                        imported_modules[alias.asname or alias.name] = alias.name
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "match"
            ):
                continue
            value = node.func.value
            hit = False
            if isinstance(value, ast.Name):
                if value.id in defined.get(here, set()):
                    hit = True
                elif value.id in imported_names:
                    module, name = imported_names[value.id]
                    hit = name in defined.get(module, set())
            elif isinstance(value, ast.Attribute) and isinstance(value.value, ast.Name):
                owner = imported_modules.get(value.value.id)
                hit = owner is not None and value.attr in defined.get(owner, set())
            if hit:
                found.append(f"{path.relative_to(ROOT)}:{node.lineno}")
    return found


class AnAnchoredPatternIsMatchedWhole(unittest.TestCase):
    def test_no_module_matches_one_with_match(self) -> None:
        self.assertEqual(_anchored_matches(), [], "use fullmatch")

    def test_a_trailing_newline_is_not_a_name(self) -> None:
        self.assertIsNone(NAME.fullmatch("shop\n"))
        self.assertIsNone(HOSTNAME.fullmatch("app.example.com\n"))

    def test_a_candidate_path_with_a_control_character_is_refused(self) -> None:
        for raw in ("conf.d/1001-shop\n.cfg", "maps/a\tb", "conf.d/x\x7f.cfg"):
            with self.subTest(raw=raw), self.assertRaises(HelperProtocolError) as raised:
                _allowed_path(raw)
            self.assertEqual(raised.exception.exit_code, exit_codes.REFUSED)


if __name__ == "__main__":
    unittest.main()
