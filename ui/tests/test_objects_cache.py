"""What the objects cache must say, checked where a database cannot be.

The same weaker kind of test `test_drafts` describes. What it catches is the
failure that would otherwise be silent: a recorder that inserts without the
conflict clause grows a duplicate-key error the first time a cluster is polled
twice, and one that writes `observed_at` lets a reading claim to be fresher
than it is - which is exactly the field every page uses to decide whether to
trust what it is showing.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path
from typing import Any

from haprion_ui import db


class FakeCursor:
    def __init__(self) -> None:
        self.statements: list[str] = []
        self.parameters: Any = None

    def __enter__(self) -> FakeCursor:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def execute(self, statement: str, parameters: Any = None) -> None:
        self.statements.append(" ".join(statement.split()))
        self.parameters = parameters


class FakeConnection:
    def __init__(self) -> None:
        self.last = FakeCursor()

    def cursor(self, **_: object) -> FakeCursor:
        return self.last


class RecordingAReading(unittest.TestCase):
    def record(self, connection: FakeConnection) -> None:
        db.record_cluster_objects(
            connection,  # type: ignore[arg-type]
            cluster="alpha",
            outcome="done",
            result={"commit": "a" * 40, "objects": []},
        )

    def test_a_second_poll_replaces_the_row_instead_of_failing(self) -> None:
        connection = FakeConnection()

        self.record(connection)

        statement = connection.last.statements[0]
        self.assertIn("insert into cluster_objects", statement)
        self.assertIn("on conflict (cluster) do update set", statement)

    def test_the_reading_never_carries_its_own_timestamp(self) -> None:
        """It comes from the default and the trigger, as with every other cache.

        A poller that could set it could make a stale reading look current, and
        staleness is the one thing every view asks this table about.
        """

        connection = FakeConnection()

        self.record(connection)

        self.assertNotIn("observed_at", connection.last.statements[0])

    def test_the_cluster_is_a_bound_parameter(self) -> None:
        connection = FakeConnection()

        self.record(connection)

        self.assertEqual(connection.last.parameters["cluster"], "alpha")


class TheTableIsTheOneTheRecorderWritesTo(unittest.TestCase):
    """Migration and recorder are one shape written twice, held together here."""

    def migration(self) -> str:
        """The last migration to speak of the table, in lower case."""

        versions = Path(__file__).resolve().parents[1] / "migrations" / "versions"
        speaking = [
            path
            for path in sorted(versions.glob("[0-9]*.py"))
            if "cluster_objects" in path.read_text(encoding="utf-8")
        ]
        self.assertTrue(speaking, "no migration makes the objects cache")
        return speaking[-1].read_text(encoding="utf-8").lower()

    def test_the_web_role_may_read_and_never_write(self) -> None:
        """The cache is the poller's answer. A page that could write it could
        hide a failed reading behind an invented one."""

        migration = self.migration()
        on = r"[^;\n]* on (?:table )?(?:public\.)?cluster_objects to "

        self.assertRegex(migration, r"select ?\(outcome\)" + on + "app_web")
        self.assertRegex(migration, r"insert ?\(outcome\)" + on + "app_poller")
        self.assertNotRegex(migration, r"(?:insert|update|delete)" + on + "app_web")

    def test_the_outcome_values_are_the_ones_the_poller_writes(self) -> None:
        text = self.migration()
        check = text[text.index("cluster_objects_outcome_allowed") :].split("\n", 1)[0]
        self.assertEqual(set(re.findall(r"'([a-z_]+)'", check)), {"done", "failed", "unavailable"})


if __name__ == "__main__":
    unittest.main()
