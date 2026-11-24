"""`haprion_ui.db` is one namespace over its modules (K1, 26-10-22).

Every caller reaches the database layer as `db.<name>`, and the tests patch it
there. A name a module defines but the package does not export is out of
their reach: the caller fails at import, or a test patches an attribute no
code reads.
"""

from __future__ import annotations

import ast
import importlib
import unittest
from pathlib import Path

from haprion_ui import db

PACKAGE = Path(db.__file__).parent


def defined(module: Path) -> list[str]:
    names: list[str] = []
    for node in ast.parse(module.read_text()).body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.append(node.name)
        elif isinstance(node, ast.Assign):
            names += [target.id for target in node.targets if isinstance(target, ast.Name)]
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.append(node.target.id)
        elif isinstance(node, ast.TypeAlias):
            names.append(node.name.id)
    return names


class TheDatabaseLayerIsOneNamespace(unittest.TestCase):
    def test_the_export_list_is_in_order(self) -> None:
        """Constants, then classes, then functions, each alphabetical (review 26-11-24)."""

        def key(name: str) -> tuple[int, str]:
            bare = name.lstrip("_")
            if bare.isupper():
                return (1 if name.startswith("_") else 0, name)
            if bare[0].isupper():
                return (2, name)
            return (3 if name.startswith("_") else 4, name)

        self.assertEqual(list(db.__all__), sorted(db.__all__, key=key))

    def test_every_definition_is_reached_through_the_package(self) -> None:
        modules = sorted(path for path in PACKAGE.glob("*.py") if path.name != "__init__.py")
        self.assertGreater(len(modules), 5)
        seen: dict[str, str] = {}
        for path in modules:
            module = importlib.import_module(f"haprion_ui.db.{path.stem}")
            for name in defined(path):
                with self.subTest(module=path.stem, name=name):
                    self.assertNotIn(name, seen, f"also defined in {seen.get(name)}")
                    seen[name] = path.stem
                    self.assertIs(getattr(db, name, None), getattr(module, name))
        self.assertGreater(len(seen), 200)


if __name__ == "__main__":
    unittest.main()
