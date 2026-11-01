"""A name typed at a failed sign-in is stored as `throttle_name` gives it (0114).

The database does the work (a definer function with a key no application role can
read), so what is held here is that every statement of the throttle - the lock, the
write and both readings - goes through it, and none lower-cases the typed text
itself. The behaviour against a real database is in `test_database_integration`.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path
from typing import Any

from haprion_ui import db
from haprion_ui.db import accounts as accounts_module


class Recorder:
    """A connection that keeps the statements it is asked to run."""

    def __init__(self) -> None:
        self.statements: list[str] = []

    def cursor(self) -> Recorder:
        return self

    def __enter__(self) -> Recorder:
        return self

    def __exit__(self, *exc: Any) -> None:
        return None

    def execute(self, statement: str, parameters: Any = None) -> None:
        self.statements.append(statement)

    def fetchone(self) -> tuple[bool]:
        return (False,)


class TheThrottleNeverStoresATypedNameAsItIs(unittest.TestCase):
    def test_the_write_stores_the_name_the_function_gives(self) -> None:
        connection = Recorder()
        db.record_login_attempt(
            connection,  # type: ignore[arg-type]
            username="hunter2-pass",
            client_ip="192.0.2.1",
            succeeded=False,
        )
        self.assertIn("throttle_name(%(username)s)", connection.statements[0])
        self.assertNotIn("lower(", connection.statements[0])

    def test_the_lock_and_the_reading_use_the_same_stored_form(self) -> None:
        connection = Recorder()
        db.lock_sign_in(connection, username="hunter2-pass")  # type: ignore[arg-type]
        db.login_locked(
            connection,  # type: ignore[arg-type]
            username="hunter2-pass",
            client_ip="192.0.2.1",
            window_minutes=15,
            max_failures=5,
        )
        lock, reading = connection.statements
        self.assertIn("throttle_name(%(username)s)", lock)
        self.assertNotIn("lower(", lock)
        self.assertIn("a.username_normalised = throttle_name(%(username)s)", reading)
        self.assertNotIn("lower(%(username)s)", reading)

    def test_nothing_else_writes_a_typed_name_to_the_table(self) -> None:
        source = Path(accounts_module.__file__).read_text(encoding="utf-8")
        inserts = re.findall(r"insert into login_attempt[^\"]*\"\s*\"values \(([^,]*),", source)
        self.assertEqual(inserts, ["throttle_name(%(username)s)"])


if __name__ == "__main__":
    unittest.main()
