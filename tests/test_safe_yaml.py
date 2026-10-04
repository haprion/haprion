"""The engine's one YAML reader (review 2026-10-03, K7).

LibYAML's safe loader where it is installed, PyYAML's own where it is not. The
point of these cases is that the choice changes the speed and nothing else:
the same documents give the same values, and the same documents are refused.
"""

from __future__ import annotations

import importlib
import unittest
from pathlib import Path
from unittest import mock

import yaml

from haproxy_mgmt import safe_yaml
from haproxy_mgmt.proxy_model import load_proxy

ACCEPTED = (
    "a: 1\nb: [x, y]\n",
    "anchors: &base {port: 80}\nuse: *base\n",
    "text: 'räksmörgås ✓'\n",
    "on: yes\noff: no\nnull_value: ~\nfloat: 1.5\noctal: 010\ntime: 2026-10-03T09:10:00Z\n",
    "same: 1\nsame: 2\n",
    "﻿bom: true\n",
    "- 1\n- two\n",
    "",
)
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
                yaml.CSafeLoader = saved
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
