"""A publish made outside the web (`haprion-objects apply`) is followed by the poller (B411)."""

from __future__ import annotations

import unittest
import unittest.mock
from typing import Any

from haprion_ui import db, poller

HEAD_A = "a" * 40
HEAD_B = "b" * 40


def document(name: str, pool: str, path: str = "/") -> str:
    return (
        f"schema: 1\nname: {name}\nhostnames: [{name}.example.com]\n"
        f"listen:\n  protocol: http\nroutes:\n  - path: {path}\n    backend: {pool}\n"
        f"backends:\n  {pool}:\n    balance: roundrobin\n    servers:\n"
        f"      - host: 198.51.100.10\n        port: 8080\n"
    )


def reading(commit: str, **pools: str) -> dict[str, Any]:
    return {
        "commit": commit,
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
        after = reading(HEAD_B, shop="front", blog="pages")

        renamed, introduced = poller.outside_renames(before, after)

        self.assertEqual(renamed, {"web": "front", "site": "pages"})
        self.assertEqual(introduced, ["front", "pages"])

    def test_the_same_head_again_renames_nothing(self) -> None:
        before = kept(reading(HEAD_A, shop="web"))

        self.assertEqual(poller.outside_renames(before, reading(HEAD_A, shop="front")), ({}, []))

    def test_nothing_without_a_good_reading_before(self) -> None:
        after = reading(HEAD_B, shop="front")

        self.assertEqual(poller.outside_renames(None, after), ({}, []))
        self.assertEqual(poller.outside_renames(kept({}, "failed"), after), ({}, []))
        self.assertEqual(poller.outside_renames(kept({"objects": []}), after), ({}, []))
        self.assertEqual(
            poller.outside_renames(kept(reading(HEAD_A, shop="web")), {"unchanged": True}),
            ({}, []),
        )


class TheObjectsSourceRecordsThem(unittest.TestCase):
    def record(self, before: db.ClusterObjects | None, result: dict[str, Any]) -> Any:
        with (
            unittest.mock.patch.object(
                db, "cluster_objects", return_value=[before] if before else []
            ),
            unittest.mock.patch.object(db, "record_cluster_objects") as objects,
            unittest.mock.patch.object(db, "record_backend_renames") as renames,
        ):
            poller.record_objects(object(), cluster="alpha", outcome="done", result=result)
        objects.assert_called_once()
        return renames

    def test_a_rename_is_written_with_the_reading(self) -> None:
        renames = self.record(kept(reading(HEAD_A, shop="web")), reading(HEAD_B, shop="front"))

        renames.assert_called_once_with(
            unittest.mock.ANY,
            cluster="alpha",
            renamed={"web": "front"},
            introduced=["front"],
            keep_recorded=True,
        )

    def test_a_head_already_seen_writes_nothing(self) -> None:
        renames = self.record(kept(reading(HEAD_B, shop="web")), reading(HEAD_B, shop="web"))

        renames.assert_not_called()

    def test_a_first_reading_writes_nothing(self) -> None:
        self.assertFalse(self.record(None, reading(HEAD_B, shop="web")).called)

    def test_the_reading_is_stored_when_the_comparison_fails(self) -> None:
        with (
            unittest.mock.patch.object(db, "cluster_objects", side_effect=RuntimeError("x")),
            unittest.mock.patch.object(db, "record_cluster_objects") as objects,
            unittest.mock.patch.object(db, "record_backend_renames") as renames,
        ):
            poller.record_objects(
                object(), cluster="alpha", outcome="done", result=reading(HEAD_B, shop="web")
            )
        objects.assert_called_once()
        renames.assert_not_called()


if __name__ == "__main__":
    unittest.main()
