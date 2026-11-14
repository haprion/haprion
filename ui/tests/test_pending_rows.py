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


PUBLISHED = {
    "cluster": "alpha",
    "head": "head",
    "stored": True,
    "log_targets": [],
    "metrics": None,
    "peers": {"port": 10000},
    "acme_challenge": {"address": "192.0.2.5", "port": 80},
}


class ASavedSettingsChangeIsNamedAfterWhatItChanges(unittest.TestCase):
    def name_of(self, document: str, result: object = PUBLISHED) -> tuple[str, str]:
        reading = SimpleNamespace(cluster="alpha", outcome="done", result=result)
        with mock.patch.object(pending, "read_source", return_value=(("alpha",), [reading])):
            return pending._settings_label(mock.Mock(), mock.Mock(), "alpha", document)

    PUBLISHED_DOCUMENT = "peers:\n  port: 10000\nacme_challenge: {address: 192.0.2.5, port: 80}\n"

    def test_only_the_challenge_changed(self) -> None:
        document = self.PUBLISHED_DOCUMENT.replace("192.0.2.5,", "192.0.2.9,")
        self.assertEqual(self.name_of(document), ("HTTP-01", "/http01/alpha"))

    def test_the_challenge_removed_is_the_challenge_changed(self) -> None:
        document = self.PUBLISHED_DOCUMENT.split("acme_challenge")[0]
        self.assertEqual(self.name_of(document), ("HTTP-01", "/http01/alpha"))

    def test_only_the_rest_changed(self) -> None:
        document = self.PUBLISHED_DOCUMENT.replace("10000", "10001")
        self.assertEqual(self.name_of(document), ("Logs & metrics", "/settings/clusters/alpha"))

    def test_both_changed_is_one_row_that_names_both(self) -> None:
        document = self.PUBLISHED_DOCUMENT.replace("10000", "10001").replace(
            "192.0.2.5,", "192.0.2.9,"
        )
        self.assertEqual(
            self.name_of(document),
            ("HTTP-01 and Logs & metrics", "/settings/clusters/alpha"),
        )

    def test_an_unreadable_reading_or_document_is_logs_and_metrics_as_before(self) -> None:
        expected = ("Logs & metrics", "/settings/clusters/alpha")
        self.assertEqual(self.name_of(self.PUBLISHED_DOCUMENT, result=None), expected)
        self.assertEqual(self.name_of("log_targets: nonsense\n"), expected)


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
