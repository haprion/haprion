"""The repository's key and source, written out the same way wherever a reader meets them.

README, the quickstart and Installing each give the two commands for Ubuntu
26.04 and for Debian 13 (26-10-18). Three copies drift unless they are held
to one another, to the suites the repository has and to the path the keyring
package takes over.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import re
import sys
import unittest
from pathlib import Path
from typing import Any

BASE = Path(__file__).resolve().parents[1]
DOCUMENTS = ("README.md", "docs/quickstart.md", "docs/install.md")
BLOCK = re.compile(r"^```bash\n(.*?)^```$", re.M | re.S)


def load(name: str, relative: str) -> Any:
    loader = importlib.machinery.SourceFileLoader(name, str(BASE / relative))
    spec = importlib.util.spec_from_loader(name, loader)
    assert spec is not None  # noqa: S101 - local tool must exist
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    loader.exec_module(module)
    return module


REPO = load("build_apt_repo_docs", "tools/build-apt-repo")
KEYRING = load("build_keyring_package_docs", "tools/build-keyring-package.py")


def source_blocks(document: str) -> list[str]:
    text = (BASE / document).read_text()
    return [block for block in BLOCK.findall(text) if "haprion.sources" in block]


class TheSourceIsWrittenOnce(unittest.TestCase):
    def test_each_document_has_one_block_per_suite_in_the_same_order(self) -> None:
        for document in DOCUMENTS:
            suites = [
                re.search(r"^Suites: (\S+)$", block, re.M).group(1)  # type: ignore[union-attr]
                for block in source_blocks(document)
            ]
            self.assertEqual(suites, ["ubuntu26.04", "deb13"], document)
        self.assertEqual(set(REPO.SUITES), {"ubuntu26.04", "deb13"})

    def test_the_copies_are_word_for_word_the_same(self) -> None:
        first = source_blocks(DOCUMENTS[0])
        for document in DOCUMENTS[1:]:
            self.assertEqual(source_blocks(document), first, document)

    def test_the_key_goes_where_the_keyring_package_takes_it_over(self) -> None:
        for block in source_blocks(DOCUMENTS[0]):
            self.assertIn(f"/{KEYRING.TARGET}", block)
            self.assertIn(f"Signed-By: /{KEYRING.TARGET}\n", block)


if __name__ == "__main__":
    unittest.main()
