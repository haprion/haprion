"""What a tcp check sends: a line protocol needs its line ending (review 2026-10-22).

The form offered `PING\\r\\n` as its example and the model refused every
backslash, so a Redis or SMTP check could only time out. HAProxy writes `\\r`
and `\\n` as CR and LF (measured against 3.4.7); any other backslash would
change the configuration line rather than the check.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

from haprion import proxy_model

FORM = Path(__file__).resolve().parents[1] / "ui/src/haprion_ui/templates/_object-form.html"


class WhatACheckSends(unittest.TestCase):
    def test_the_line_ending_escapes_are_accepted(self) -> None:
        for value in ("PING\\r\\n", "HELO\\n", "PONG"):
            with self.subTest(value):
                self.assertIsNotNone(proxy_model.PROBE.fullmatch(value))

    def test_any_other_backslash_is_refused(self) -> None:
        for value in ("PING\\", "a\\x41", "a\\ b", 'a\\"', "PING\\\\r"):
            with self.subTest(value):
                self.assertIsNone(proxy_model.PROBE.fullmatch(value))

    def test_the_form_s_example_is_one_the_model_takes(self) -> None:
        text = FORM.read_text(encoding="utf-8")
        for name in ("health_send", "health_expect"):
            with self.subTest(name):
                example = re.search(rf'name="{name}"[^>]*placeholder="([^"]*)"', text)
                assert example is not None
                self.assertIsNotNone(proxy_model.PROBE.fullmatch(example.group(1)))


if __name__ == "__main__":
    unittest.main()
