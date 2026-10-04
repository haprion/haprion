"""A migration that has run somewhere is never edited again (B241, review 2026-10-04 F7).

`0052` was changed after production had run it. `test-database` builds the
schema from the first migration every time and could not tell the two versions
apart; production kept the first, and the collector failed from the first WAF
request (26-10-03 19:44). The rule is that a change is a new migration. This
holds it: `migrations/frozen.sha256` lists each migration that has shipped,
in `sha256sum` form, and every migration but the newest must be listed - the
newest may still change until a release carries it or the next one is added.
"""

from __future__ import annotations

import hashlib
import re
import unittest
from pathlib import Path

MIGRATIONS = Path(__file__).resolve().parents[1] / "migrations"
FROZEN = MIGRATIONS / "frozen.sha256"
LINE = re.compile(r"(?P<digest>[0-9a-f]{64})  (?P<path>versions/[0-9]{4}_[a-z0-9_]+\.py)")


def frozen() -> dict[str, str]:
    listed: dict[str, str] = {}
    for number, line in enumerate(FROZEN.read_text().splitlines(), start=1):
        if not line or line.startswith("#"):
            continue
        match = LINE.fullmatch(line)
        if match is None:
            raise AssertionError(f"frozen.sha256 line {number} is not `<sha256>  versions/<file>`")
        listed[match["path"]] = match["digest"]
    return listed


class RunMigrationsStayAsTheyRan(unittest.TestCase):
    def test_a_frozen_migration_is_unchanged(self) -> None:
        for path, digest in frozen().items():
            with self.subTest(path):
                file = MIGRATIONS / path
                self.assertTrue(file.is_file(), f"{path} is frozen and gone")
                self.assertEqual(
                    hashlib.sha256(file.read_bytes()).hexdigest(),
                    digest,
                    f"{path} has run somewhere and was edited; write a new migration instead",
                )

    def test_every_migration_but_the_newest_is_frozen(self) -> None:
        present = sorted(
            f"versions/{file.name}" for file in (MIGRATIONS / "versions").glob("[0-9]*.py")
        )
        self.assertEqual(
            sorted(set(present[:-1]) - set(frozen())),
            [],
            "add these to migrations/frozen.sha256 - an older migration than the newest has shipped",
        )
