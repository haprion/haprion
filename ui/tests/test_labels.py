"""The interface counts with the engine's rule (review 2026-10-22, 7-2).

The repository-wide gate on the bracketed plural is the engine's
`tests/test_labels.py`.
"""

from __future__ import annotations

import unittest

from haprion import labels as engine

from haprion_ui import labels


class OneRule(unittest.TestCase):
    def test_the_interface_s_words_are_the_engine_s(self) -> None:
        self.assertIs(labels.counted, engine.counted)
        self.assertEqual(labels.counted(2, "node"), "2 nodes")


if __name__ == "__main__":
    unittest.main()
