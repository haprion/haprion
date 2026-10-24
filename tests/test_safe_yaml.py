"""The engine's one YAML reader (review 2026-10-03, K7).

LibYAML's safe loader where it is installed, PyYAML's own where it is not. The
point of these cases is that the choice changes the speed and nothing else:
the same documents give the same values, and the same documents are refused.
"""

from __future__ import annotations

import importlib
import re
import unittest
from pathlib import Path
from unittest import mock

import yaml

from haprion import safe_yaml
from haprion.proxy_model import load_proxy

ACCEPTED = (
    "a: 1\nb: [x, y]\n",
    "anchors: &base {port: 80}\nuse: *base\n",
    "text: 'räksmörgås ✓'\n",
    "on: yes\noff: no\nnull_value: ~\nfloat: 1.5\noctal: 010\ntime: 2026-10-03T09:10:00Z\n",
    "﻿bom: true\n",
    "- 1\n- two\n",
    "",
)
#
# `yaml.load(` or `yaml.safe_load(`, and not `safe_yaml.load(`.
#
DIRECT = re.compile(r"(?<![\w.])yaml\.(?:safe_)?load\(")
REFUSED = (
    "a: [1, 2\n",
    "!!python/object/apply:os.system ['true']\n",
    "a: !!binary 'not base64 ***'\n",
    "\tbad: indentation\n",
)


class BothLoadersReadTheSame(unittest.TestCase):
    def test_libyaml_is_used_where_it_is_installed(self) -> None:
        self.assertIs(safe_yaml.SafeLoader, getattr(yaml, "CSafeLoader", yaml.SafeLoader))

    def test_the_same_documents_give_the_same_values(self) -> None:
        for document in ACCEPTED:
            with self.subTest(document=document):
                self.assertEqual(
                    safe_yaml.load(document), yaml.load(document, Loader=yaml.SafeLoader)
                )

    def test_the_same_documents_are_refused_as_yaml_errors(self) -> None:
        for document in REFUSED:
            with self.subTest(document=document):
                with self.assertRaises(yaml.YAMLError):
                    yaml.load(document, Loader=yaml.SafeLoader)
                with self.assertRaises(yaml.YAMLError):
                    safe_yaml.load(document)

    def test_a_key_given_twice_is_refused_with_its_line(self) -> None:
        """Review 26-10-24, 15-02: the second silently replaced the first."""

        for document in ("same: 1\nsame: 2\n", "vips:\n  a: {address: 1}\n  a: {address: 2}\n"):
            with self.subTest(document=document):
                with self.assertRaisesRegex(yaml.YAMLError, "a second time") as caught:
                    safe_yaml.load(document)
                self.assertIn("line", str(caught.exception))

    def test_a_merge_and_a_key_beside_it_are_not_a_repeat(self) -> None:
        document = "base: &b {port: 80, host: x}\nuse:\n  <<: *b\n  port: 81\n"
        self.assertEqual(safe_yaml.load(document)["use"], {"port": 81, "host": "x"})

    def test_only_safe_yaml_reads_yaml(self) -> None:
        """A reader beside it would take a repeated key again (15-02)."""

        root = Path(__file__).resolve().parents[1]
        found = [
            f"{path.relative_to(root)}:{number}"
            for tree in ("src", "ui/src", "install", "tools")
            for path in sorted((root / tree).rglob("*.py"))
            if path.name != "safe_yaml.py"
            for number, line in enumerate(path.read_text().splitlines(), start=1)
            if DIRECT.search(line)
        ]
        self.assertEqual(found, [])

    def test_without_libyaml_the_python_loader_reads_the_same(self) -> None:
        saved = yaml.__dict__.pop("CSafeLoader", None)
        try:
            fallback = importlib.reload(safe_yaml)
            self.assertIs(fallback.SafeLoader, yaml.SafeLoader)
            self.assertEqual(
                fallback.load(ACCEPTED[1]), {"anchors": {"port": 80}, "use": {"port": 80}}
            )
        finally:
            if saved is not None:
                yaml.__dict__["CSafeLoader"] = saved
            importlib.reload(safe_yaml)

    def test_every_golden_object_loads_to_the_same_model_either_way(self) -> None:
        goldens = sorted((Path(__file__).resolve().parent / "golden").rglob("*.yaml"))
        self.assertTrue(goldens)
        for path in goldens:
            text = path.read_text()
            with self.subTest(path.name):
                self.assertEqual(safe_yaml.load(text), yaml.load(text, Loader=yaml.SafeLoader))
        for path in (Path(__file__).resolve().parents[1] / "examples").rglob("*.yaml"):
            text = path.read_text()
            with self.subTest(path.name):
                self.assertEqual(safe_yaml.load(text), yaml.load(text, Loader=yaml.SafeLoader))

    def test_a_proxy_object_is_read_through_it(self) -> None:
        with mock.patch.object(safe_yaml, "load", wraps=safe_yaml.load) as read:
            load_proxy(
                "shop",
                b"schema: 1\nname: shop\nhostnames: [shop.example.com]\nlisten: {protocol: http}\n"
                b"routes: [{path: /, backend: web}]\n"
                b"backends: {web: {balance: roundrobin, health: {type: disabled},"
                b" servers: [{host: 192.0.2.10, port: 8080}]}}\n",
            )
        read.assert_called_once()


if __name__ == "__main__":
    unittest.main()
