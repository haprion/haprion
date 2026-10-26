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

import ast
import hashlib
import re
import subprocess
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


class NoMigrationGoesBack(unittest.TestCase):
    """A schema is never downgraded (B360, B369): no migration carries the way back."""

    def test_no_migration_defines_a_downgrade(self) -> None:
        found = sorted(
            path.name
            for path in (MIGRATIONS / "versions").glob("[0-9]*.py")
            for node in ast.parse(path.read_text()).body
            if isinstance(node, ast.FunctionDef) and node.name == "downgrade"
        )
        self.assertTrue(list((MIGRATIONS / "versions").glob("[0-9]*.py")))
        self.assertEqual(found, [])

    def test_the_migrate_command_refuses_a_downgrade_before_reaching_alembic(self) -> None:
        text = (MIGRATIONS.parents[1] / "install/platform/migrate").read_text()
        start = text.index('[[ "$1" != downgrade ]]')
        refusal = text[start : text.index("\n\n", start)]
        self.assertLess(start, text.index("-m alembic"))
        for arguments, refused in ((["downgrade", "-1"], True), (["upgrade", "head"], False)):
            with self.subTest(arguments=arguments):
                done = subprocess.run(  # noqa: S603 - fixed interpreter, the script's own line
                    [
                        "/bin/bash",
                        "-c",
                        f'die() {{ echo "$*" >&2; exit 1; }}\n{refusal}\necho passed',
                        "migrate",
                        *arguments,
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(done.returncode, 1 if refused else 0, done.stderr)
                if refused:
                    self.assertIn("never downgraded", done.stderr)
                else:
                    self.assertEqual(done.stdout, "passed\n")
