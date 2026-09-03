"""What the draft write path must say, checked where a database cannot be.

The same weaker kind of test `test_jobs` describes, and written down for the
same reason: a green result here is not proof that the SQL runs. The behaviour
needs PostgreSQL and is proved on the development platform.

What it does catch is the failure that would otherwise be silent. Optimistic
concurrency lives entirely in a `where` clause and a returned row; a predicate
that quietly disappears from a write turns it off, one admin's edit starts
overwriting another's, and nothing about that looks wrong in a diff.
"""

from __future__ import annotations

import unittest
from contextlib import nullcontext
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from haproxy_mgmt import proxy_model

from haproxy_ui import db

DRAFT = db.ProxyDraft(
    cluster="alpha",
    object_id="shop",
    yaml="schema: 1\nname: shop\n",
    base_version=7,
    base_hash="a" * 40,
    revision=3,
    updated_by="admin",
    updated_at=datetime(2026, 9, 2, 12, 0, tzinfo=UTC),
    deleted=False,
)


class FakeCursor:
    def __init__(self, row: Any, rowcount: int = 1) -> None:
        self.row = row
        self.rowcount = rowcount
        self.statements: list[str] = []
        self.parameters: Any = None

    def __enter__(self) -> FakeCursor:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def execute(self, statement: str, parameters: Any = None) -> None:
        self.statements.append(" ".join(statement.split()))
        self.parameters = parameters

    def fetchone(self) -> Any:
        return self.row

    def fetchall(self) -> list[Any]:
        return [] if self.row is None else [self.row]


class FakeConnection:
    def __init__(self, row: Any = None, rowcount: int = 1) -> None:
        self.last = FakeCursor(row, rowcount)

    def cursor(self, **_: object) -> FakeCursor:
        return self.last

    def transaction(self) -> Any:
        return nullcontext()


class SavingADraft(unittest.TestCase):
    def save(self, connection: FakeConnection, expected_revision: int | None) -> Any:
        return db.save_draft(
            connection,  # type: ignore[arg-type]
            cluster="alpha",
            object_id="shop",
            yaml="schema: 1\nname: shop\n",
            base_version=7,
            base_hash="a" * 40,
            updated_by="admin",
            expected_revision=expected_revision,
        )

    def test_a_first_save_inserts_and_refuses_to_overwrite(self) -> None:
        """`on conflict do nothing`, so a draft that appeared meanwhile is a conflict.

        A caller that believed the object had no draft must not silently
        replace one somebody else created between the read and the write.
        """

        connection = FakeConnection(DRAFT)

        self.save(connection, None)

        statement = connection.last.statements[0]
        self.assertIn("insert into proxy_draft", statement)
        self.assertIn("on conflict do nothing", statement)

    def test_a_later_save_carries_the_revision_it_read(self) -> None:
        """The predicate that makes two tabs safe.

        Without it the update matches the row whatever its revision is, and the
        edit that was made against an older version wins by arriving last.
        """

        connection = FakeConnection(DRAFT)

        self.save(connection, 3)

        statement = connection.last.statements[0]
        self.assertIn("update proxy_draft", statement)
        self.assertIn("and revision = %(revision)s", statement)
        self.assertEqual(connection.last.parameters["revision"], 3)

    def test_a_save_never_sets_the_revision_itself(self) -> None:
        """It is the database's counter, raised by a trigger.

        A writer that set it could hold it still, and optimistic concurrency
        would be off while every statement still looked correct.
        """

        connection = FakeConnection(DRAFT)

        self.save(connection, 3)

        statement = connection.last.statements[0]
        self.assertNotIn("set revision", statement)
        self.assertNotIn("revision =%(revision)s,", statement)

    def test_a_row_that_moved_underneath_is_a_conflict_not_an_overwrite(self) -> None:
        connection = FakeConnection(None)

        with self.assertRaises(db.DraftConflict) as raised:
            self.save(connection, 3)

        self.assertIn("shop", str(raised.exception))
        self.assertIn("reload", str(raised.exception))

    def test_the_saved_row_comes_back_from_the_database(self) -> None:
        """So a caller holds the new revision without reading again."""

        saved = self.save(FakeConnection(DRAFT), 3)

        self.assertEqual(saved.revision, 3)
        self.assertEqual(saved.base_hash, "a" * 40)


class DiscardingADraft(unittest.TestCase):
    def test_it_deletes_only_the_revision_the_caller_saw(self) -> None:
        connection = FakeConnection(None)

        db.discard_draft(
            connection,  # type: ignore[arg-type]
            cluster="alpha",
            object_id="shop",
            expected_revision=3,
        )

        statement = connection.last.statements[0]
        self.assertIn("delete from proxy_draft", statement)
        self.assertIn("and revision = %(revision)s", statement)

    def test_discarding_a_draft_that_moved_is_refused(self) -> None:
        connection = FakeConnection(None, rowcount=0)

        with self.assertRaises(db.DraftConflict):
            db.discard_draft(
                connection,  # type: ignore[arg-type]
                cluster="alpha",
                object_id="shop",
                expected_revision=3,
            )

    def test_discarding_is_a_delete_and_not_the_deleted_flag(self) -> None:
        """`deleted` means "publish the removal of this object".

        An abandoned edit that stayed in the table as a flag would be
        indistinguishable from a decision to remove the site.
        """

        connection = FakeConnection(None)

        db.discard_draft(
            connection,  # type: ignore[arg-type]
            cluster="alpha",
            object_id="shop",
            expected_revision=3,
        )

        self.assertNotIn("deleted", connection.last.statements[0])


class ReadingDrafts(unittest.TestCase):
    def test_a_listing_is_scoped_to_one_cluster_and_ordered(self) -> None:
        connection = FakeConnection(DRAFT)

        db.cluster_drafts(connection, "alpha")  # type: ignore[arg-type]

        statement = connection.last.statements[0]
        self.assertIn("where cluster = %(cluster)s", statement)
        self.assertIn("order by object_id", statement)

    def test_an_object_with_no_draft_reads_as_none(self) -> None:
        connection = FakeConnection(None)

        self.assertIsNone(
            db.read_draft(connection, "alpha", "shop")  # type: ignore[arg-type]
        )

    def test_the_cluster_and_the_name_are_bound_parameters(self) -> None:
        """Never text pasted into the statement, for the reason `recent_jobs` gives."""

        connection = FakeConnection(DRAFT)

        db.read_draft(connection, "alpha", "shop")  # type: ignore[arg-type]

        self.assertEqual(connection.last.parameters, {"cluster": "alpha", "object_id": "shop"})


class TheTableAgreesWithTheEngine(unittest.TestCase):
    """The constraint and the model are one rule written in two languages.

    Nothing makes them agree by construction - one is SQL in a migration, the
    other a pattern in the engine - so a test holds them together, the same way
    the TLS policy names and their syntax are held together. A draft accepted
    under a name the publish refuses is an edit somebody makes and then cannot
    deliver, and the refusal arrives at the worst possible moment.
    """

    def migration(self) -> str:
        path = (
            Path(__file__).resolve().parents[1] / "migrations" / "versions" / "0013_proxy_drafts.py"
        )
        return path.read_text(encoding="utf-8")

    def latest_shape(self) -> str:
        """The last migration that has an opinion about the object name.

        Reading 0013 alone stopped being enough the first time the constraint
        was widened: the original text still says what it always said, and a
        test that only reads it would keep passing while the database had moved
        on. What has to match the model is whichever migration spoke last.
        """

        versions = Path(__file__).resolve().parents[1] / "migrations" / "versions"
        speaking = [
            path
            for path in sorted(versions.glob("[0-9]*.py"))
            if "proxy_draft_object_shape" in path.read_text(encoding="utf-8")
        ]
        self.assertTrue(speaking, "no migration constrains the object name")
        return speaking[-1].read_text(encoding="utf-8")

    def test_the_object_name_constraint_is_the_model_s_own_pattern(self) -> None:
        pattern = proxy_model.NAME.pattern

        self.assertIn(f"check (object_id ~ '{pattern}')", self.latest_shape())

    def test_the_document_limit_is_the_model_s_own_limit(self) -> None:
        """A draft the model would refuse to read has no business being stored."""

        self.assertIn(
            f"check (octet_length(yaml) <= {proxy_model.MAX_MODEL_BYTES})", self.migration()
        )


if __name__ == "__main__":
    unittest.main()
