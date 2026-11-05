"""A migration that has run somewhere is never edited again (B241, review 2026-10-04 F7).

`0052` was changed after production had run it. `test-database` builds the
schema from the first migration every time and could not tell the two versions
apart; production kept the first, and the collector failed from the first WAF
request (26-10-03 19:44). The rule is that a change is a new migration. This
holds it: `migrations/frozen.sha256` lists each migration that has shipped,
in `sha256sum` form, and every migration but the newest must be listed - the
newest may still change until a release carries it or the next one is added.

That second half was kept by hand and was missed: 0115 went out in three
releases without a line (review 26-11-05, G04). The release tags are the
record of what has shipped, so `RunMigrationsStayAsTheyRan` also reads them:
a migration file in any `v*` tag must be listed, the newest included.

Needs the tags. CI's checkout is shallow and without them (`actions/checkout`
with no `fetch-depth`); there that test is skipped, with the reason shown, and
it runs wherever the tags are - the maintainer's gate before a release.
"""

from __future__ import annotations

import ast
import hashlib
import re
import shutil
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


def shipped(root: Path) -> set[str] | None:
    """`versions/<file>` of every migration in any `v*` tag, or None where there are no tags.

    No git, or no tags, is None and the test says it skipped. A tag that is there
    and cannot be read fails: a partial clone read as "nothing shipped" would pass
    without looking (re-review H03).
    """

    def git(*arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603 - git, fixed arguments
            ["git", "-C", str(root), *arguments],  # noqa: S607
            capture_output=True,
            text=True,
            check=False,
        )

    if shutil.which("git") is None:
        return None
    listed = git("tag", "--list", "v*")
    tags = listed.stdout.split() if listed.returncode == 0 else []
    if not tags:
        return None
    found: set[str] = set()
    for tag in tags:
        prefix = "ui/migrations/"
        tree = git("ls-tree", "-r", "--name-only", tag, "--", f"{prefix}versions/")
        if tree.returncode != 0:
            raise AssertionError(f"git ls-tree {tag} failed: {tree.stderr.strip()}")
        for name in tree.stdout.split():
            if re.fullmatch(r"[0-9]{4}_[a-z0-9_]+\.py", name.rsplit("/", 1)[-1]):
                found.add(name.removeprefix(prefix))
    return found


def unfrozen(released: set[str], present: set[str], listed: set[str]) -> list[str]:
    """The migrations in the tree that a release carried and `frozen.sha256` does not list."""

    return sorted((released & present) - listed)


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

    def test_every_migration_a_release_carried_is_frozen(self) -> None:
        released = shipped(MIGRATIONS.parents[1])
        if released is None:
            self.skipTest(
                "no v* tags in this clone (a shallow checkout): the release freeze is not read"
            )
        present = {f"versions/{file.name}" for file in (MIGRATIONS / "versions").glob("[0-9]*.py")}
        self.assertEqual(
            unfrozen(released, present, set(frozen())),
            [],
            "add these to migrations/frozen.sha256 - a release has carried them",
        )

    def test_a_migration_in_a_release_and_not_listed_is_named(self) -> None:
        self.assertEqual(
            unfrozen(
                {"versions/0114_a.py", "versions/0115_a.py"},
                {"versions/0115_a.py", "versions/0116_b.py"},
                {"versions/0114_a.py"},
            ),
            ["versions/0115_a.py"],
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
