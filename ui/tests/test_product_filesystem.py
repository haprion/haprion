"""The fixture that moves the product's directories reaches every call that takes a path (Z08, 26-11-05)."""

from __future__ import annotations

import itertools
import os
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from tests.product_filesystem import PRODUCT_ROOTS, product_directories

CALLS: dict[str, tuple[Any, ...]] = {
    "stat": (),
    "statvfs": (),
    "lchown": (0, 0),
    "mkfifo": (),
    "setxattr": ("user.x", b"1"),
    "getxattr": ("user.x",),
    "listxattr": (),
    "removexattr": ("user.x",),
    "unlink": (),
}


class TheProductsDirectoriesAreMoved(unittest.TestCase):
    def given(self, name: str, path: Any) -> str:
        """What the real `os.<name>` is called with when the block is asked for `path`."""

        with tempfile.TemporaryDirectory() as raw, mock.patch.object(os, name) as spy:
            with product_directories(Path(raw)):
                getattr(os, name)(path, *CALLS[name])
            seen = os.fsdecode(spy.call_args.args[0])
        return seen.replace(raw, "<scratch>", 1)

    def test_every_call_that_takes_a_path_is_given_the_one_below_the_scratch_directory(
        self,
    ) -> None:
        for name, root in itertools.product(CALLS, PRODUCT_ROOTS):
            with self.subTest(name=name, root=root):
                self.assertEqual(self.given(name, f"{root}/x"), f"<scratch>{root}/x")

    def test_a_path_in_bytes_is_moved_too(self) -> None:
        for name in CALLS:
            with self.subTest(name=name):
                self.assertEqual(self.given(name, b"/etc/haprion/x"), "<scratch>/etc/haprion/x")

    def test_the_lock_directory_and_the_certificate_store_are_product_directories(self) -> None:
        self.assertIn("/run/lock", PRODUCT_ROOTS)
        self.assertIn("/etc/letsencrypt", PRODUCT_ROOTS)

    def test_a_path_elsewhere_is_left_alone(self) -> None:
        with tempfile.TemporaryDirectory() as raw, mock.patch.object(os, "statvfs") as spy:
            with product_directories(Path(raw)):
                os.statvfs("/usr/lib")
            spy.assert_called_once_with("/usr/lib")


if __name__ == "__main__":
    unittest.main()
