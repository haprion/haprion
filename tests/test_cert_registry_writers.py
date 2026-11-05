"""Every place that writes a certificate's registry entry builds it through `written_entry` (C07).

The builder keeps what a writer does not own (an NDES profile, the interface
and exportable marks, a key the reader gains later). A writer that assembled
its own dict would drop them. The per-writer tests sit with the writers
(`test_cert_registry`, `test_cert_import`, `test_cert_issue`); this module holds
the guard that finds a writer nobody has tested, and the two paths that copy an
entry instead of building one.
"""

from __future__ import annotations

import ast
import unittest
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from haprion import cert_registry, cluster_definition

SOURCE = Path(__file__).resolve().parents[1] / "src" / "haprion"

#
# Every write to the registry's certificates in the engine, found in the syntax
# tree and not in the text: `certificates[<id>] = ...`, the same through any
# other name the mapping was given (`entries = document["certificates"]`),
# `document["certificates"][<id>] = ...`, `.update(...)`, `.setdefault(...)`,
# `.pop(...)` (a copy is excused for the one key it names), `.popitem()`, `.clear()`, `.__setitem__(...)`, `del ...[<id>]`, `|=`, `x = certificates | new`,
# `dict(certificates, a=...)` and a mapping built by hand or rebuilt with `{**certificates, ...}`. The value
# must be the builder's, except where it is a copy of an entry already on file
# with one key changed; those sites are named below, by function, and tested
# further down. Not followed: a dict comprehension, an entry passed as a
# parameter and an alias made in a nested function (it takes data-flow analysis;
# the per-writer tests are the protection there). A new site is a new writer and fails here until it is built with
# `written_entry` or named (26-11-05, XX07).
#
KEY = "certificates"
WRITING_METHODS = {"update", "setdefault", "pop", "popitem", "clear", "__setitem__"}
COPIES = {
    # The loader building its read-only view of an entry, not writing one.
    ("config.py", "load_registry", "certificates[certificate_id]"),
    # The interface mark moves from one entry to another.
    ("cert_registry.py", "claim_interface", "certificates[other_id]"),
    ("cert_registry.py", "claim_interface", "entry['interface']"),
    # A cluster added to, or taken out of, the entries that name it.
    ("cluster_definition.py", "_registry_with", "certificates[certificate]"),
    ("cluster_definition.py", "_registry_with", "entry['clusters']"),
    ("cluster_definition.py", "_registry_without", "certificates[certificate]"),
    ("cluster_definition.py", "_registry_without", "entry['clusters']"),
    ("cluster_definition.py", "_registry_without", "entry.pop('clusters')"),
}


def _is_key(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and node.value == KEY


def _names_registry(node: ast.AST, names: set[str]) -> bool:
    """Whether the expression is, or is read out of, the registry's certificates.

    A name that holds it, `x["certificates"]` or `x.get("certificates")`. The word
    as a key of a dict being built (a report, an answer) is not a read of it.
    """

    for part in ast.walk(node):
        if isinstance(part, ast.Name) and part.id in names:
            return True
        if isinstance(part, ast.Subscript) and _is_key(part.slice):
            return True
        if (
            isinstance(part, ast.Call)
            and isinstance(part.func, ast.Attribute)
            and part.func.attr in {"get", "pop", "setdefault"}
            and part.args
            and _is_key(part.args[0])
        ):
            return True
    return False


def _is_mapping(node: ast.AST, names: set[str]) -> bool:
    """Whether the operand is the mapping itself (a name, `x["certificates"]`, `{**x}`).

    Not a set or a list made from something read out of it.
    """

    if isinstance(node, ast.Name):
        return node.id in names
    if isinstance(node, ast.Subscript):
        return _is_key(node.slice) or _is_mapping(node.value, names)
    return isinstance(node, ast.Dict) and _names_registry(node, names)


def _own_nodes(scope: ast.AST) -> Iterator[ast.AST]:
    """The nodes of a function or module, without those of the functions inside it."""

    stack = list(ast.iter_child_nodes(scope))
    while stack:
        node = stack.pop()
        yield node
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda):
            stack.extend(ast.iter_child_nodes(node))


def _bound_names(scope: ast.AST) -> set[str]:
    """The names in a function that hold the mapping or an entry of it, as far as it says."""

    names = {KEY}
    for _ in range(3):  # a name bound from a name bound from the registry
        for node in _own_nodes(scope):
            if isinstance(node, ast.Assign) and _names_registry(node.value, names):
                names.update(t.id for t in node.targets if isinstance(t, ast.Name))
            elif isinstance(node, ast.For) and _names_registry(node.iter, names):
                names.update(n.id for n in ast.walk(node.target) if isinstance(n, ast.Name))
            elif isinstance(node, ast.AnnAssign | ast.NamedExpr) and node.value is not None:
                target = node.target
                if isinstance(target, ast.Name) and _names_registry(node.value, names):
                    names.add(target.id)
    return names


def writes_in(source: str) -> Iterator[tuple[str, str, ast.AST | None]]:
    """(function, what is written to, the value or None) for each write to the registry."""

    tree = ast.parse(source)
    scopes: list[tuple[str, ast.AST]] = [("<module>", tree)]
    scopes += [
        (n.name, n) for n in ast.walk(tree) if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)
    ]
    for scope_name, scope in scopes:
        names = _bound_names(scope)
        for node in _own_nodes(scope):
            found = _write(node, names)
            if found is not None:
                yield scope_name, found[0], found[1]


def _write(node: ast.AST, names: set[str]) -> tuple[str, ast.AST | None] | None:
    if isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
        value = node.value
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        for target in targets:
            if isinstance(target, ast.Subscript) and (
                _names_registry(target.value, names) or _is_key(target.slice)
            ):
                return ast.unparse(target).replace('"', "'"), value
            if (
                isinstance(target, ast.Name)
                and target.id == KEY
                and isinstance(value, ast.Dict)
                and (value.keys or any(key is None for key in value.keys))
            ):
                return ast.unparse(target), value
    if isinstance(node, ast.Delete):
        for target in node.targets:
            if isinstance(target, ast.Subscript) and (
                _names_registry(target.value, names) or _is_key(target.slice)
            ):
                return "del " + ast.unparse(target).replace('"', "'"), None
    if (
        isinstance(node, ast.AugAssign)
        and isinstance(node.op, ast.BitOr)
        and isinstance(node.target, ast.Name)
        and node.target.id in names
    ):
        return f"{node.target.id} |=", node.value
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in WRITING_METHODS
        and _names_registry(node.func.value, names)
    ):
        # A `pop` is told apart by its key, so an exception covers that key only.
        argument = ast.unparse(node.args[0]).replace('"', "'") if node.func.attr == "pop" else ""
        return f"{ast.unparse(node.func.value)}.{node.func.attr}({argument})", None
    if isinstance(node, ast.Assign):
        value = node.value
        union = (
            isinstance(value, ast.BinOp)
            and isinstance(value.op, ast.BitOr)
            and (_is_mapping(value.left, names) or _is_mapping(value.right, names))
        )
        # `dict(certificates)` alone is a copy; with more it is a rebuilt mapping.
        extended = (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Name)
            and value.func.id == "dict"
            and bool(value.args)
            and _names_registry(value.args[0], names)
            and (len(value.args) > 1 or bool(value.keywords))
        )
        if union or extended:
            return f"{ast.unparse(node.targets[0])} = {'|' if union else 'dict(...)'}", value
    if isinstance(node, ast.Dict) and any(
        key is None and _names_registry(value, names)
        for key, value in zip(node.keys, node.values, strict=True)
    ):
        return "{**...}", node
    return None


def _is_builder(value: ast.AST | None) -> bool:
    return (
        isinstance(value, ast.Call)
        and isinstance(value.func, ast.Name | ast.Attribute)
        and (getattr(value.func, "id", None) or getattr(value.func, "attr", None))
        == "written_entry"
    )


def unexpected(source: str, name: str) -> list[tuple[str, str, str]]:
    return [
        (name, function, target)
        for function, target, value in writes_in(source)
        if not _is_builder(value) and (name, function, target) not in COPIES
    ]


class TheWritersOfTheEntry(unittest.TestCase):
    def test_every_write_to_the_entries_is_the_builder_or_a_known_copy(self) -> None:
        found = [
            site
            for path in sorted(SOURCE.rglob("*.py"))
            for site in unexpected(path.read_text(encoding="utf-8"), path.name)
        ]

        self.assertEqual(found, [], "a new writer of the entry: build it with written_entry")

    def test_the_four_writers_are_found_to_use_the_builder(self) -> None:
        builders = [
            path.name
            for path in sorted(SOURCE.rglob("*.py"))
            for _, _, value in writes_in(path.read_text(encoding="utf-8"))
            if _is_builder(value)
        ]

        self.assertGreaterEqual(len(builders), 4, "set_targets, import, authority, issue")

    def test_every_named_copy_is_still_there(self) -> None:
        present = {
            (path.name, function, target)
            for path in sorted(SOURCE.rglob("*.py"))
            for function, target, _ in writes_in(path.read_text(encoding="utf-8"))
        }

        self.assertEqual(sorted(COPIES - present), [], "a copy that went: take it off the list")

    def test_a_hand_built_writer_is_found_in_every_form(self) -> None:
        planted = {
            "named mapping": "def f(certificates, cid):\n    certificates[cid] = {'source': {}}\n",
            "under the document": (
                "def f(document, cid):\n    document['certificates'][cid] = {'clusters': []}\n"
            ),
            "another name": (
                "def f(document, cid):\n"
                "    entries = dict(document.get('certificates') or {})\n"
                "    entries[cid] = {'clusters': []}\n"
            ),
            "a variable called entry": (
                "def f(document, cid):\n"
                "    entry = dict(document['certificates'][cid])\n"
                "    entry['clusters'] = []\n"
            ),
            "update": "def f(certificates):\n    certificates.update({'a': {}})\n",
            "setdefault": "def f(certificates):\n    certificates.setdefault('a', {})\n",
            "unpacking": (
                "def f(certificates, cid):\n    return {**certificates, cid: {'clusters': []}}\n"
            ),
            "rebuilt": "def f(cid):\n    certificates = {cid: {'clusters': []}}\n",
            "del": "def f(certificates, cid):\n    del certificates[cid]\n",
            "del of a key": (
                "def f(document, cid):\n"
                "    entry = document['certificates'][cid]\n"
                "    del entry['clusters']\n"
            ),
            "pop": "def f(certificates, cid):\n    certificates.pop(cid)\n",
            "pop on an entry": (
                "def f(document, cid):\n"
                "    entry = document['certificates'][cid]\n"
                "    entry.pop('clusters')\n"
            ),
            "clear": "def f(document):\n    document['certificates'].clear()\n",
            "in-place union": "def f(certificates, new):\n    certificates |= new\n",
            "__setitem__": "def f(certificates):\n    certificates.__setitem__('a', {})\n",
            "popitem": "def f(certificates):\n    certificates.popitem()\n",
            "union": "def f(certificates, new):\n    certificates = certificates | new\n",
            "dict with keywords": (
                "def f(certificates, x):\n    certificates = dict(certificates, a=x)\n"
            ),
        }
        for form, source in planted.items():
            with self.subTest(form=form):
                self.assertTrue(unexpected(source, "planted.py"), form)

    def test_the_copy_exception_covers_the_key_and_no_other_pop(self) -> None:
        other = (
            "def _registry_without(document, cid):\n"
            "    entry = document['certificates'][cid]\n"
            "    entry.pop('source')\n"
        )
        key = other.replace("'source'", "'clusters', None")

        self.assertTrue(unexpected(other, "cluster_definition.py"))
        self.assertEqual(
            [t for _, _, t in unexpected(key, "cluster_definition.py")],
            [],
        )

    def test_the_builder_and_a_read_are_not_taken_for_a_writer(self) -> None:
        fine = (
            "def f(document, cid):\n"
            "    certificates = dict(document.get('certificates') or {})\n"
            "    certificates[cid] = cert_registry.written_entry(a, b)\n"
            "    return [x for x in certificates.values()]\n"
        )

        self.assertEqual(unexpected(fine, "planted.py"), [])
        self.assertEqual(
            unexpected("def f():\n    entry = {}\n    entry['clusters'] = []\n", "planted.py"),
            [],
        )


class TheCopiesKeepWhatTheyDoNotTouch(unittest.TestCase):
    ENTRY: dict[str, Any] = {
        "source": {"kind": "import", "ndes_profile": "corp"},
        "clusters": ["alpha"],
        "exportable": True,
        "future_key": {"kept": 1},
    }

    def test_a_cluster_added_to_an_entry_keeps_the_rest(self) -> None:
        document = {"certificates": {"a": dict(self.ENTRY)}}
        rendered = cluster_definition._registry_with(document, "a", "beta").decode()

        written = _parsed(rendered)["certificates"]["a"]
        self.assertEqual(written["clusters"], ["alpha", "beta"])
        self.assertEqual(
            {k: v for k, v in written.items() if k != "clusters"},
            {k: v for k, v in self.ENTRY.items() if k != "clusters"},
        )

    def test_a_cluster_taken_out_of_every_entry_keeps_the_rest(self) -> None:
        document = {"certificates": {"a": dict(self.ENTRY)}}
        rendered = cluster_definition._registry_without(document, "alpha").decode()

        written = _parsed(rendered)["certificates"]["a"]
        self.assertNotIn("clusters", written)
        self.assertEqual(written["source"], self.ENTRY["source"])
        self.assertEqual(written["future_key"], self.ENTRY["future_key"])

    def test_the_interface_mark_taken_from_an_entry_leaves_the_rest(self) -> None:
        certificates = {
            "old": {**self.ENTRY, "interface": True},
            "new": {"source": {"kind": "import"}, "clusters": []},
        }
        displaced = cert_registry.claim_interface(certificates, "new")

        self.assertEqual(displaced, "old")
        self.assertEqual(certificates["old"], self.ENTRY)
        self.assertTrue(certificates["new"]["interface"])


def _parsed(text: str) -> dict[str, Any]:
    import yaml

    return dict(yaml.safe_load(text))


if __name__ == "__main__":
    unittest.main()
