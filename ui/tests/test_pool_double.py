"""The page tests' pool double sees a connection held while readers run on other threads."""

from __future__ import annotations

import unittest

from haprion_ui import reading
from tests.test_login import FakePool


class ThePoolDouble(unittest.TestCase):
    def test_a_held_connection_with_concurrent_readers_is_counted(self) -> None:
        pool = FakePool()
        with pool.connection():
            reading.read_concurrently(pool, [lambda _c: 1, lambda _c: 2])
        self.assertEqual(pool.nested, [], "the readers ran on threads of their own")
        self.assertGreater(pool.peak, 1)

    def test_readers_with_none_held_peak_without_nesting(self) -> None:
        pool = FakePool()
        reading.read_concurrently(pool, [lambda _c: 1, lambda _c: 2])
        self.assertEqual(pool.nested, [])
