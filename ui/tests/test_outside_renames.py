"""A publish made outside the web (`haprion-objects apply`) is followed by the poller (B411)."""

from __future__ import annotations

import unittest
import unittest.mock
from typing import Any

from haprion_ui import db, pending, poller

HEAD_A = "a" * 40
HEAD_B = "b" * 40
HEAD_C = "c" * 40


def document(name: str, pool: str, path: str = "/") -> str:
    return (
        f"schema: 1\nname: {name}\nhostnames: [{name}.example.com]\n"
        f"listen:\n  protocol: http\nroutes:\n  - path: {path}\n    backend: {pool}\n"
        f"backends:\n  {pool}:\n    balance: roundrobin\n    servers:\n"
        f"      - host: 198.51.100.10\n        port: 8080\n"
    )


def reading(commit: str, parent: str | None = None, **pools: str) -> dict[str, Any]:
    return {
        "commit": commit,
        "parent": parent,
        "objects": [
            {"name": name, "document": document(name, pool), "readable": True}
            for name, pool in pools.items()
        ],
    }


def kept(result: dict[str, Any], outcome: str = "done") -> db.ClusterObjects:
    from datetime import UTC, datetime

    return db.ClusterObjects("alpha", datetime.now(UTC), outcome, result, [], None, None)


class WhatTheCommandLineRenamed(unittest.TestCase):
    def test_one_pool_in_each_of_two_objects(self) -> None:
        before = kept(reading(HEAD_A, shop="web", blog="site"))
        after = reading(HEAD_B, HEAD_A, shop="front", blog="pages")

        renamed, introduced = poller.outside_renames(before, after)

        self.assertEqual(renamed, {"web": "front", "site": "pages"})
        self.assertEqual(introduced, ["front", "pages"])

    def test_the_same_head_again_renames_nothing(self) -> None:
        before = kept(reading(HEAD_A, shop="web"))

        self.assertEqual(
            poller.outside_renames(before, reading(HEAD_A, HEAD_A, shop="front")), ({}, [])
        )

    def test_two_publishes_between_readings_rename_nothing(self) -> None:
        """One removed the pool `web` and the next added `front`: neither renamed it (R2)."""

        before = kept(reading(HEAD_A, shop="web"))
        later = reading(HEAD_C, HEAD_B, shop="front")

        self.assertEqual(poller.outside_renames(before, later), ({}, []))

    def test_a_listing_that_does_not_say_what_it_was_made_on_renames_nothing(self) -> None:
        before = kept(reading(HEAD_A, shop="web"))

        for parent in (None, "", 7):
            with self.subTest(parent=parent):
                after = {**reading(HEAD_B, shop="front"), "parent": parent}
                self.assertEqual(poller.outside_renames(before, after), ({}, []))
        without = reading(HEAD_B, shop="front")
        del without["parent"]
        self.assertEqual(poller.outside_renames(before, without), ({}, []))

    def test_a_name_the_alias_table_would_refuse_is_not_tried(self) -> None:
        """R1: its check is 1 to 128 characters, and a name outside it never reaches the write."""

        before = kept(reading(HEAD_A, shop="web"))
        long = "r" * 129

        with unittest.mock.patch.object(
            pending,
            "backend_renames",
            return_value=({"web": long, long: "ok", "fine": "good"}, [long, "ok", ""]),
        ):
            renamed, introduced = poller.outside_renames(
                before, reading(HEAD_B, HEAD_A, shop="front")
            )

        self.assertEqual((renamed, introduced), ({"fine": "good"}, ["ok"]))

    def test_a_revert_is_a_publish_like_any_other(self) -> None:
        """R6: a revert is a new version on the head, so it is followed (a -> b, then b -> a)."""

        forward = poller.outside_renames(
            kept(reading(HEAD_A, shop="a")), reading(HEAD_B, HEAD_A, shop="b")
        )
        back = poller.outside_renames(
            kept(reading(HEAD_B, HEAD_A, shop="b")), reading(HEAD_C, HEAD_B, shop="a")
        )

        self.assertEqual(forward, ({"a": "b"}, ["b"]))
        self.assertEqual(back, ({"b": "a"}, ["a"]))

    def test_a_head_moved_back_without_a_new_version_renames_nothing(self) -> None:
        """R6: the stored head is the new head's child, not its parent."""

        before = kept(reading(HEAD_B, HEAD_A, shop="b"))

        self.assertEqual(
            poller.outside_renames(before, reading(HEAD_A, HEAD_C, shop="a")), ({}, [])
        )

    def test_a_failed_reading_in_between_loses_the_rename_and_never_draws_a_wrong_one(self) -> None:
        """R3: the failed reading replaced the stored row, so nothing is held to compare."""

        failed = kept({}, "failed")

        self.assertEqual(
            poller.outside_renames(failed, reading(HEAD_C, HEAD_B, shop="b")), ({}, [])
        )

    def test_nothing_without_a_good_reading_before(self) -> None:
        after = reading(HEAD_B, HEAD_A, shop="front")

        self.assertEqual(poller.outside_renames(None, after), ({}, []))
        self.assertEqual(poller.outside_renames(kept({}, "failed"), after), ({}, []))
        self.assertEqual(poller.outside_renames(kept({"objects": []}), after), ({}, []))
        self.assertEqual(
            poller.outside_renames(kept(reading(HEAD_A, shop="web")), {"unchanged": True}),
            ({}, []),
        )


def connection() -> unittest.mock.MagicMock:
    """A connection whose savepoints let an exception through, as psycopg's do."""

    fake = unittest.mock.MagicMock()
    fake.transaction.return_value.__exit__.return_value = False
    return fake


class TheObjectsSourceRecordsThem(unittest.TestCase):
    def record(
        self,
        before: db.ClusterObjects | None,
        result: dict[str, Any],
        *,
        renames_fail: bool = False,
    ) -> Any:
        fake = connection()
        head = None if before is None else before.result.get("commit")
        with (
            unittest.mock.patch.object(db, "objects_head", return_value=head) as held,
            unittest.mock.patch.object(
                db, "cluster_objects", return_value=[before] if before else []
            ) as read,
            unittest.mock.patch.object(db, "record_cluster_objects") as objects,
            unittest.mock.patch.object(
                db,
                "record_backend_renames",
                side_effect=RuntimeError("x") if renames_fail else None,
            ) as renames,
        ):
            poller.record_objects(fake, cluster="alpha", outcome="done", result=result)
        objects.assert_called_once()
        self.held, self.read, self.fake = held, read, fake
        return renames

    def test_a_rename_is_written_with_the_reading(self) -> None:
        renames = self.record(
            kept(reading(HEAD_A, shop="web")), reading(HEAD_B, HEAD_A, shop="front")
        )

        renames.assert_called_once_with(
            unittest.mock.ANY,
            cluster="alpha",
            renamed={"web": "front"},
            introduced=["front"],
            keep_recorded=True,
        )

    def test_a_head_already_seen_writes_nothing_and_reads_nothing(self) -> None:
        """R4: an `unchanged` answer reads nothing; the same head reads its commit, not the reading."""

        same = reading(HEAD_B, HEAD_A, shop="web")
        renames = self.record(kept(reading(HEAD_B, HEAD_A, shop="web")), same)
        renames.assert_not_called()
        self.read.assert_not_called()

        renames = self.record(
            kept(reading(HEAD_A, shop="web")), {"commit": HEAD_A, "unchanged": True}
        )
        renames.assert_not_called()
        self.held.assert_not_called()
        self.read.assert_not_called()

    def test_the_whole_reading_is_fetched_only_when_its_commit_is_the_parent(self) -> None:
        renames = self.record(
            kept(reading(HEAD_A, shop="web")), reading(HEAD_C, HEAD_B, shop="front")
        )

        renames.assert_not_called()
        self.held.assert_called_once()
        self.read.assert_not_called()

    def test_a_first_reading_writes_nothing(self) -> None:
        self.assertFalse(self.record(None, reading(HEAD_B, HEAD_A, shop="web")).called)

    def test_the_reading_is_stored_when_the_comparison_fails(self) -> None:
        fake = connection()
        with (
            unittest.mock.patch.object(db, "objects_head", side_effect=RuntimeError("x")),
            unittest.mock.patch.object(db, "record_cluster_objects") as objects,
            unittest.mock.patch.object(db, "record_backend_renames") as renames,
        ):
            poller.record_objects(
                fake, cluster="alpha", outcome="done", result=reading(HEAD_B, HEAD_A, shop="web")
            )
        objects.assert_called_once()
        renames.assert_not_called()

    def test_the_comparison_runs_in_a_savepoint(self) -> None:
        """R5: an SQL error there is rolled back to the savepoint, not to the start."""

        self.record(kept(reading(HEAD_A, shop="web")), reading(HEAD_B, HEAD_A, shop="front"))

        self.assertEqual(self.fake.transaction.call_count, 2)

    def test_a_rename_that_cannot_be_written_leaves_the_reading_stored(self) -> None:
        """R1: the exception does not reach the caller, and the reading was stored first."""

        renames = self.record(
            kept(reading(HEAD_A, shop="web")),
            reading(HEAD_B, HEAD_A, shop="front"),
            renames_fail=True,
        )

        renames.assert_called_once()
        savepoint = self.fake.transaction.return_value.__exit__
        self.assertEqual(savepoint.call_args_list[-1].args[0], RuntimeError)


if __name__ == "__main__":
    unittest.main()
