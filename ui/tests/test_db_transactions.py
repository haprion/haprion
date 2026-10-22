"""The database layer never commits a caller's transaction (review 2026-10-22, 3-1).

`connection.transaction()` is a savepoint only inside an open transaction; on a
connection just taken from the pool it is the outermost one and commits as it
closes. Twelve functions used it as though it were a savepoint, so a row was
committed before the job or the audit entry that belonged with it. They use
`db.core.savepoint` now, and this keeps any other from coming back.
"""

from __future__ import annotations

import unittest
from pathlib import Path

DB = Path(__file__).resolve().parents[1] / "src" / "haprion_ui" / "db"


class NothingInTheDatabaseLayerCommitsOnItsOwn(unittest.TestCase):
    def test_transaction_blocks_are_savepoints(self) -> None:
        found = [
            f"{path.name}:{number}"
            for path in sorted(DB.glob("*.py"))
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
            if "connection.transaction()" in line and path.name != "core.py"
        ]
        self.assertEqual(found, [], "use db.core.savepoint(connection)")


if __name__ == "__main__":
    unittest.main()
