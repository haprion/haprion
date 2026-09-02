"""One proxy as it is written, beside the row the nodes are serving.

The cases worth holding are the ones where the two answers differ. A page that
merged them would render something plausible for every one of these, and the
one thing worth seeing - that the stored document and the running configuration
no longer agree - would be the thing it hid.
"""

from __future__ import annotations

import unittest
from datetime import UTC, datetime, timedelta

from haproxy_ui.db import ClusterObjects
from haproxy_ui.objects import build_object_detail
from haproxy_ui.proxies import ProxyView

NOW = datetime(2026, 9, 2, 10, 0, tzinfo=UTC)
STALE_AFTER = timedelta(seconds=120)

APP = "schema: 1\nname: app\nhostnames: [app.example.com]\n"

PUBLISHED = ProxyView(
    name="app",
    protocol="https",
    managed=True,
    enabled=True,
    hostnames=("app.example.com",),
    ports=(443,),
    backend_count=2,
)


def reading(
    *,
    age_seconds: int = 15,
    outcome: str = "done",
    poll_error: str | None = None,
    objects: list[dict[str, object]] | None = None,
) -> ClusterObjects:
    return ClusterObjects(
        cluster="alpha",
        observed_at=NOW - timedelta(seconds=age_seconds),
        outcome=outcome,
        result={
            "commit": "a" * 40,
            "generated_at": "2026-09-02T09:59:45Z",
            "objects": objects
            if objects is not None
            else [
                {
                    "name": "app",
                    "document": APP,
                    "readable": True,
                    "problem": None,
                    "protocol": "https",
                    "hostnames": ["app.example.com"],
                }
            ],
        },
        warnings=[],
        error=None,
        poll_error=poll_error,
    )


def detail(name: str = "app", **kwargs: object) -> object:
    rows = kwargs.pop("readings", [reading()])
    published = kwargs.pop("published", [PUBLISHED])
    return build_object_detail(
        "alpha",
        name,
        rows,  # type: ignore[arg-type]
        published,  # type: ignore[arg-type]
        now=NOW,
        stale_after=STALE_AFTER,
    )


class AStoredObject(unittest.TestCase):
    def test_the_document_is_carried_through_exactly(self) -> None:
        """Not reformatted, not re-serialised from a parse.

        The point of reading the source is that it is the source. A page that
        rendered the model's idea of the document would show something the
        author never wrote and could not diff against their own edit.
        """

        view = detail()

        self.assertEqual(view.stored.document, APP)  # type: ignore[union-attr]

    def test_the_commit_is_shown_short_and_kept_whole(self) -> None:
        view = detail()

        self.assertEqual(view.commit, "a" * 40)
        self.assertEqual(view.short_commit, "a" * 12)

    def test_the_published_row_is_carried_beside_and_never_merged(self) -> None:
        view = detail()

        self.assertIs(view.published, PUBLISHED)
        self.assertEqual(view.stored.name, "app")  # type: ignore[union-attr]


class AnObjectThisVersionCannotRead(unittest.TestCase):
    def test_it_is_shown_with_the_refusal_rather_than_hidden(self) -> None:
        """It is the file somebody has to open."""

        rows = [
            reading(
                objects=[
                    {
                        "name": "app",
                        "document": APP,
                        "readable": False,
                        "problem": "app.listen must be a mapping",
                        "protocol": None,
                        "hostnames": [],
                    }
                ]
            )
        ]

        view = detail(readings=rows)

        self.assertFalse(view.stored.readable)  # type: ignore[union-attr]
        self.assertEqual(view.stored.problem, "app.listen must be a mapping")  # type: ignore[union-attr]
        self.assertEqual(view.stored.document, APP)  # type: ignore[union-attr]
        self.assertIn("cannot read", view.detail)

    def test_readable_is_the_helper_s_answer_and_not_re_derived(self) -> None:
        """The command line and the page must agree about the same object.

        A page that decided readability from whether `problem` is set would
        disagree with `haproxy-objects` the moment the two ever differ, and the
        contract check already refuses an entry where they do.
        """

        rows = [
            reading(
                objects=[
                    {
                        "name": "app",
                        "document": APP,
                        "readable": False,
                        "problem": None,
                        "protocol": None,
                        "hostnames": [],
                    }
                ]
            )
        ]

        self.assertFalse(detail(readings=rows).stored.readable)  # type: ignore[union-attr]


class WhereTheTwoAnswersDiffer(unittest.TestCase):
    def test_an_unmanaged_proxy_has_no_object_and_that_is_not_an_error(self) -> None:
        """Served from configuration that was never written here."""

        legacy = ProxyView(
            name="legacy",
            protocol="tcp",
            managed=False,
            enabled=True,
            hostnames=(),
            ports=(8443,),
            backend_count=1,
        )

        view = detail("legacy", published=[legacy])

        self.assertIsNone(view.stored)
        self.assertIs(view.published, legacy)
        self.assertIn("not written here", view.detail)

    def test_an_object_stored_but_not_yet_published_keeps_its_document(self) -> None:
        view = detail(published=[])

        self.assertIsNotNone(view.stored)
        self.assertIsNone(view.published)


class WhenTheReadingCannotBeTrusted(unittest.TestCase):
    def test_a_failed_reading_is_unavailable_rather_than_empty(self) -> None:
        """An editor that opened an empty document would offer to publish it."""

        view = detail(readings=[reading(outcome="failed", objects=[])])

        self.assertFalse(view.available)
        self.assertIn("could not be read", view.detail)

    def test_a_poll_error_is_unavailable_even_when_the_outcome_says_done(self) -> None:
        view = detail(readings=[reading(poll_error="the helper could not be run", objects=[])])

        self.assertFalse(view.available)

    def test_a_cluster_never_read_says_so_instead_of_claiming_nothing_is_stored(self) -> None:
        view = detail(readings=[])

        self.assertFalse(view.available)
        self.assertIsNone(view.observed_at)
        self.assertIn("not been read", view.detail)

    def test_a_stale_reading_is_still_shown_and_says_it_is_stale(self) -> None:
        view = detail(readings=[reading(age_seconds=600)])

        self.assertTrue(view.stale)
        self.assertIsNotNone(view.stored)


if __name__ == "__main__":
    unittest.main()
