"""One proxy as it is written, beside the row the nodes are serving.

The cases worth holding are the ones where the two answers differ. A page that
merged them would render something plausible for every one of these, and the
one thing worth seeing - that the stored document and the running configuration
no longer agree - would be the thing it hid.
"""

from __future__ import annotations

import unittest
from datetime import UTC, datetime, timedelta

from haproxy_ui import dashboard
from haproxy_ui.db import ClusterObjects
from haproxy_ui.history import VersionView
from haproxy_ui.objects import ObjectDetail, build_object_detail, publication, stored_only
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


def detail(
    name: str = "app",
    *,
    readings: list[ClusterObjects] | None = None,
    published: list[ProxyView] | None = None,
) -> ObjectDetail:
    return build_object_detail(
        "alpha",
        name,
        [reading()] if readings is None else readings,
        [PUBLISHED] if published is None else published,
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
        disagree with `haprion-objects` the moment the two ever differ, and the
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


class WhetherTheChangeReachedTheNodes(unittest.TestCase):
    """Three questions, not one: committed, released, serving.

    Pairing an object with "the published row of the same name" was the first
    design and it was wrong. The published inventory names frontends -
    `mgd-<vip>-<protocol>` - and one of them carries every object on that
    address, so the two never share a name. The fixture agreed with the
    assumption only because the same hand wrote both.
    """

    def version(self, number: int, *, published: bool) -> VersionView:
        return VersionView(
            number=number,
            version=f"v{number}",
            expected_commit=f"{number:040d}",
            date="2026-09-02",
            comment="",
            published=published,
            current=False,
        )

    def test_the_release_the_nodes_pull_is_serving(self) -> None:
        state = publication(
            f"{29:040d}", [self.version(29, published=True)], release_state="Converged"
        )

        self.assertEqual(state.label, "Serving")
        self.assertEqual(state.version, "v29")

    def test_the_word_for_deployed_is_the_dashboard_s_own(self) -> None:
        """This compared against "Current", which nothing produces.

        The dashboard says `converged`, title-cased for display. The mismatch
        made every object read as waiting for a deploy - including ones the
        nodes were already serving - and the first version of the test above
        agreed with the bug because it was written from the same wrong word.
        The state must therefore be checked against a value the dashboard
        actually emits.
        """

        emitted = dashboard.ClusterView(
            cluster="alpha",
            accent=0,
            configured=True,
            label="",
            tone="healthy",
            behind=False,
            detail="",
            observed_at=NOW,
            observed_iso=NOW.isoformat(),
            age_label="",
            stale=False,
            nodes=(),
            configured_nodes=2,
            reachable_nodes=2,
            vip="",
            version="v29",
            release_state="converged".replace("_", " ").title(),
        )

        state = publication(
            f"{29:040d}",
            [self.version(29, published=True)],
            release_state=emitted.release_state,
        )

        self.assertEqual(state.label, "Serving")

    def test_a_release_the_nodes_have_not_taken_is_not_serving(self) -> None:
        """The distinction the whole card exists for.

        Publishing writes a release; a deploy is what makes the nodes pull it.
        Reporting the first as live would say a change is in traffic while
        every node still serves the previous one.
        """

        state = publication(
            f"{29:040d}",
            [self.version(29, published=True)],
            release_state="Deploy Pending",
            node_version="v25",
            object_state="changed",
        )

        self.assertEqual(state.label, "Waiting for deploy")
        self.assertIn("v25", state.detail)

    def test_an_object_the_pending_deploy_does_not_carry_is_serving(self) -> None:
        """The cluster owes a deploy; this object does not.

        A release carries only the objects its publish named. Every other
        object is byte for byte what the nodes already serve, so opening one
        during somebody else's pending deploy must not claim it is waiting.
        """

        state = publication(
            f"{29:040d}",
            [self.version(29, published=True)],
            release_state="Deploy Pending",
            node_version="v25",
            object_state="current",
        )

        self.assertEqual(state.label, "Serving")
        self.assertIn("v25", state.detail)

    def test_an_object_the_nodes_have_never_had_is_waiting(self) -> None:
        """A published object absent from the release the nodes run."""

        state = publication(
            f"{29:040d}",
            [self.version(29, published=True)],
            release_state="Deploy Pending",
            node_version="v25",
            object_state="absent",
        )

        self.assertEqual(state.label, "Waiting for deploy")

    def test_an_object_nothing_could_be_read_about_claims_neither(self) -> None:
        """The default, and the reason the parameter stopped being a boolean.

        A boolean had to pick one of two claims when the truth was that the
        comparison could not be made - and it picked "serving", so a release
        with no manifest, or a node that never said what it runs, reported
        every object as reaching the nodes.
        """

        state = publication(
            f"{29:040d}",
            [self.version(29, published=True)],
            release_state="Deploy Pending",
            node_version="v25",
        )

        self.assertEqual(state.label, "Unknown")
        self.assertEqual(state.tone, "unknown")

    def test_a_commit_that_is_versioned_but_not_released_is_awaiting_publish(self) -> None:
        state = publication(
            f"{30:040d}",
            [self.version(30, published=False), self.version(29, published=True)],
        )

        self.assertEqual(state.label, "Awaiting publish")
        self.assertIn("v29", state.detail)

    def test_a_commit_no_version_names_is_not_released(self) -> None:
        state = publication(f"{31:040d}", [self.version(29, published=True)])

        self.assertEqual(state.label, "Not released")
        self.assertIsNone(state.version)

    def test_an_unread_listing_is_unknown_rather_than_a_claim(self) -> None:
        self.assertEqual(publication(None, []).label, "Unknown")

    def test_an_object_that_is_not_stored_has_no_publication_at_all(self) -> None:
        """There is nothing to say about the travel of a file that does not exist."""

        self.assertIsNone(detail("legacy", published=[]).publication)


class ReachingAnObjectNoFrontendServesYet(unittest.TestCase):
    def test_an_object_whose_hostnames_are_unserved_is_listed(self) -> None:
        """Otherwise the object somebody is working on is the one they cannot open."""

        pending = stored_only(reading(), published=[])

        self.assertEqual([view.name for view in pending], ["app"])

    def test_an_object_already_carried_by_a_frontend_is_not_listed(self) -> None:
        self.assertEqual(stored_only(reading(), published=[PUBLISHED]), ())

    def test_matching_is_by_hostname_and_never_by_name(self) -> None:
        """A shared frontend is named after the address, never after an object,
        so comparing names would report every object as unpublished."""

        frontend = ProxyView(
            name="mgd-main-http",
            protocol="http",
            managed=True,
            enabled=True,
            hostnames=("app.example.com",),
            ports=(80,),
            backend_count=1,
        )

        self.assertEqual(stored_only(reading(), published=[frontend]), ())


class ThePortAnObjectWillBeServedOn(unittest.TestCase):
    """Read from the engine, never restated in the interface.

    The port is not a property of the object - the document does not carry one
    for http or https - it is what the generator binds for that protocol. A
    number written here instead would be a second opinion, and it would go on
    looking right for exactly as long as the engine kept the same table.
    """

    def test_it_is_the_engine_s_own_table(self) -> None:
        from haproxy_mgmt.generate import PORTS

        view = detail().stored

        self.assertEqual(view.ports, (PORTS["https"],))  # type: ignore[union-attr]

    def test_an_object_this_version_cannot_read_claims_no_port(self) -> None:
        """Its protocol is unknown, so there is nothing to look up."""

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

        self.assertEqual(detail(readings=rows).stored.ports, ())  # type: ignore[union-attr]

    def test_a_tcp_object_claims_no_port_rather_than_guessing(self) -> None:
        """Its port is written in the document and is not carried in the
        envelope, so the honest answer is that this page does not know it."""

        rows = [
            reading(
                objects=[
                    {
                        "name": "app",
                        "document": APP,
                        "readable": True,
                        "problem": None,
                        "protocol": "tcp",
                        "hostnames": [],
                    }
                ]
            )
        ]

        self.assertEqual(detail(readings=rows).stored.ports, ())  # type: ignore[union-attr]
