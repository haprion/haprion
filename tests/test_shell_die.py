"""A shell `die` that takes an exit code says only its message (R2 26-10-27, F9).

`haprion-drain` printed `... try again when it is done 75`: its `die` echoed
`$*`, the exit code included.
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIE = re.compile(r"^\s*die\(\)\s*\{(?P<body>[^}]*)\}", re.MULTILINE)


def shell_scripts() -> list[Path]:
    scripts = []
    for top in ("install", "tools", "examples"):
        for path in sorted((ROOT / top).rglob("*")):
            if not path.is_file() or path.suffix == ".py" or "__pycache__" in path.parts:
                continue
            first_line = path.read_bytes()[:64].split(b"\n", 1)[0]
            if path.suffix == ".sh" or (first_line.startswith(b"#!") and b"sh" in first_line):
                scripts.append(path)
    return scripts


class TheExitCodeIsNotPartOfTheMessage(unittest.TestCase):
    def test_no_die_that_takes_a_code_echoes_every_argument(self) -> None:
        offending = [
            str(path.relative_to(ROOT))
            for path in shell_scripts()
            for match in DIE.finditer(path.read_text(encoding="utf-8", errors="replace"))
            if "${2" in match["body"] and "$*" in match["body"]
        ]
        self.assertEqual(offending, [])

    def test_drain_says_its_refusal_without_the_code(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            done = subprocess.run(
                [str(ROOT / "install/platform/bin/haprion-drain"), "pause", "--wait", "x"],
                capture_output=True,
                text=True,
                check=False,
                env={**os.environ, "HAPRION_UI_DRAIN_CONFIG": directory},
                timeout=30,
            )
        self.assertEqual(done.returncode, 64)
        self.assertEqual(done.stderr, "ERROR: --wait takes whole seconds\n")


if __name__ == "__main__":
    unittest.main()
