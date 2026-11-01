"""The rows of a cluster's package link each saved object to the page that reads it."""

from __future__ import annotations

import unittest
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest import mock

from haprion_ui import db, pending


def saved(object_id: str, *, deleted: bool = False) -> SimpleNamespace:
    return SimpleNamespace(
        id="00000000-0000-4000-8000-000000000001",
        revision=1,
        stage=db.SAVED,
        object_id=object_id,
        deleted=deleted,
        replaces=None,
        yaml="name: x\n",
        updated_by="alice",
        updated_at=datetime(2026, 11, 1, tzinfo=UTC),
        base_document=None,
        base_hash="head",
    )


class TheRowsOfThePackage(unittest.TestCase):
    def rows(
        self, *objects: SimpleNamespace, published: tuple[str, ...] = ()
    ) -> list[pending.PendingRow]:
        state = SimpleNamespace(
            commit="head", stored=[SimpleNamespace(name=name) for name in published]
        )
        request = mock.MagicMock()
        patches = {
            "editor_state": state,
            "reading_heads": {},
            "state_reading": None,
            "settled_drafts": list(objects),
            "settled_changes": {},
            "object_moved": False,
            "removal_bookkeeping": {},
            "backend_renames": ({}, []),
        }
        with mock.patch.multiple(
            pending, **{name: mock.Mock(return_value=value) for name, value in patches.items()}
        ):
            return list(pending.pending_package(request, mock.Mock(), "alpha").rows)

    def test_an_object_only_saved_has_the_page_that_reads_it(self) -> None:
        (row,) = self.rows(saved("brand-new"))
        self.assertEqual(row.what, "New")
        self.assertEqual(row.read_link, "/proxies/alpha/brand-new")

    def test_a_published_object_has_it_too(self) -> None:
        (row,) = self.rows(saved("edge"), published=("edge",))
        self.assertEqual(row.what, "Changed")
        self.assertEqual(row.read_link, "/proxies/alpha/edge")
