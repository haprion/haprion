"""The network page: a cluster's addresses, as the poller last read them.

What the tests hold to is not the layout but the things the page must not get
wrong however it is arranged: that it shows the tables an object actually
points at, that it says whether they can be changed from here, and that it
never offers the one address `deploy` checks node ownership against.
"""

from __future__ import annotations

import json
import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest import mock

from haproxy_ui import demo
from haproxy_ui.network import (
    FormProblem,
    NetworkForm,
    build_network_overview,
    document_from_form,
    row_numbers,
)
from tests.test_login import LoginTestCase, configuration

NOW = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)
STALE_AFTER = timedelta(seconds=120)


def overview(clusters: tuple[str, ...] = demo.CLUSTERS):
    return build_network_overview(
        clusters, demo.network_rows(NOW), now=NOW, stale_after=STALE_AFTER, captured=False
    )


class TheReadingBecomesTheCard(unittest.TestCase):
    def test_a_repository_description_is_marked_editable(self) -> None:
        edge = next(view for view in overview() if view.cluster == "edge-demo")

        self.assertTrue(edge.editable)
        self.assertEqual(edge.head, "a" * 40)
        self.assertEqual(edge.default_vip, "public")
        self.assertEqual([vip.name for vip in edge.vips], ["partner", "public"])
        self.assertEqual([vip.is_default for vip in edge.vips], [False, True])

    def test_a_description_still_in_the_engine_s_configuration_is_not_editable(self) -> None:
        #
        # Every cluster that predates the move is in this state, and offering an
        # edit that has no path to the file would be worse than saying so.
        #
        service = next(view for view in overview() if view.cluster == "service-demo")

        self.assertFalse(service.editable)
        self.assertIn("cannot write", service.detail)

    def test_a_cluster_that_has_never_been_read_is_a_card_rather_than_a_gap(self) -> None:
        views = overview(demo.CLUSTERS + ("never-polled",))
        missing = next(view for view in views if view.cluster == "never-polled")

        self.assertEqual(missing.age_label, "Never")
        self.assertEqual(missing.vips, ())
        self.assertFalse(missing.editable)

    def test_a_vip_s_own_source_address_is_listed_as_a_source_address(self) -> None:
        #
        # It was not, and the page then told a cluster that pairs a source with
        # its VIP that it had none - under a heading named after exactly that.
        #
        edge = next(view for view in overview() if view.cluster == "edge-demo")

        addresses = {source.address: source.used_by for source in edge.sources}
        self.assertEqual(addresses["192.0.2.25"], "default for VIP public")
        self.assertEqual(addresses["192.0.2.26"], "default for VIP partner")
        self.assertEqual(addresses["192.0.2.35"], "named; a site must ask for it")

    def test_a_cluster_with_no_source_address_at_all_still_says_none(self) -> None:
        service = next(view for view in overview() if view.cluster == "service-demo")

        self.assertEqual(service.sources, ())

    def test_the_editable_source_rows_leave_out_the_ones_a_vip_already_carries(self) -> None:
        #
        # The reading merges them; the form may not. A paired address is edited
        # in its VIP's row, and offering it in two fields would let one
        # submission carry two answers for one value.
        #
        edge = next(view for view in overview() if view.cluster == "edge-demo")

        self.assertEqual([source.name for source in edge.named_sources], ["outbound"])
        self.assertEqual([source.address for source in edge.named_sources], ["192.0.2.35"])


class TheRowsBecomeTheDocument(unittest.TestCase):
    """What the editor posts, turned into the one shape the engine parses."""

    def form(self, **overrides: object) -> NetworkForm:
        fields: dict[str, object] = {
            "vip_names": ("public", ""),
            "vip_addresses": ("192.0.2.20", ""),
            "vip_sources": ("192.0.2.25", ""),
            "default_vip_row": "0",
            "source_names": ("egress", ""),
            "source_addresses": ("192.0.2.35", ""),
            "group_names": ("partners", ""),
            "group_members": ("198.51.100.0/24\n203.0.113.10\n", ""),
        }
        fields.update(overrides)
        return NetworkForm(**fields)  # type: ignore[arg-type]

    def test_the_filled_in_rows_become_the_document(self) -> None:
        document = json.loads(document_from_form(self.form()))

        self.assertEqual(
            document,
            {
                "vips": {"public": {"address": "192.0.2.20", "source": "192.0.2.25"}},
                "default_vip": "public",
                "sources": {"egress": "192.0.2.35"},
                "networks": {"partners": ["198.51.100.0/24", "203.0.113.10"]},
            },
        )

    def test_an_untouched_spare_row_is_left_out_rather_than_published_empty(self) -> None:
        document = json.loads(document_from_form(self.form()))

        self.assertEqual(list(document["vips"]), ["public"])
        self.assertEqual(list(document["sources"]), ["egress"])

    def test_a_vip_without_a_source_carries_no_source_key(self) -> None:
        document = json.loads(document_from_form(self.form(vip_sources=("", ""))))

        self.assertEqual(document["vips"], {"public": {"address": "192.0.2.20"}})

    def test_empty_tables_are_absent_rather_than_present_and_empty(self) -> None:
        #
        # `sources: {}` and no `sources` at all mean the same thing to the
        # engine, but only one of them survives a diff without asking a reader
        # what was removed.
        #
        document = json.loads(
            document_from_form(
                self.form(
                    source_names=("", ""),
                    source_addresses=("", ""),
                    group_names=("", ""),
                    group_members=("", ""),
                )
            )
        )

        self.assertNotIn("sources", document)
        self.assertNotIn("networks", document)

    def test_a_cluster_cannot_be_left_without_a_vip(self) -> None:
        with self.assertRaises(FormProblem):
            document_from_form(self.form(vip_names=("", ""), vip_addresses=("", "")))

    def test_two_rows_with_one_name_are_refused_rather_than_collapsed(self) -> None:
        #
        # A mapping keyed by name silently keeps the last of them. The row that
        # disappeared would have been an address somebody meant to publish.
        #
        with self.assertRaises(FormProblem) as refusal:
            document_from_form(
                self.form(
                    vip_names=("public", "public"), vip_addresses=("192.0.2.20", "192.0.2.21")
                )
            )

        self.assertEqual(str(refusal.exception), "VIP row 2 repeats a name used above it.")

    def test_a_refusal_never_repeats_what_was_typed_into_the_row(self) -> None:
        with self.assertRaises(FormProblem) as refusal:
            document_from_form(
                self.form(vip_names=("public", "<script>"), vip_addresses=("192.0.2.20", ""))
            )

        self.assertNotIn("<script>", str(refusal.exception))

    def test_a_ticked_row_is_taken_out_of_the_document(self) -> None:
        document = json.loads(
            document_from_form(
                self.form(
                    vip_names=("public", "partner"),
                    vip_addresses=("192.0.2.20", "192.0.2.21"),
                    vip_sources=("192.0.2.25", ""),
                    removed_vip_rows=frozenset({1}),
                    removed_source_rows=frozenset({0}),
                    removed_group_rows=frozenset({0}),
                )
            )
        )

        self.assertEqual(list(document["vips"]), ["public"])
        self.assertNotIn("sources", document)
        self.assertNotIn("networks", document)

    def test_a_removed_row_is_not_asked_to_be_filled_in_first(self) -> None:
        #
        # The row still posts whatever was in it. Reading it at all would meet
        # a person who emptied the fields before ticking the box with a
        # complaint about the row they had just said to remove.
        #
        document = json.loads(
            document_from_form(self.form(source_names=("", ""), removed_source_rows=frozenset({0})))
        )

        self.assertNotIn("sources", document)

    def test_the_default_vip_cannot_be_removed_without_naming_another(self) -> None:
        #
        # Silently moving every object that names no VIP is the one change this
        # form makes a person confirm, so it may not happen as a side effect of
        # a tick in the last column.
        #
        with self.assertRaises(FormProblem) as refusal:
            document_from_form(
                self.form(
                    vip_names=("public", "partner"),
                    vip_addresses=("192.0.2.20", "192.0.2.21"),
                    removed_vip_rows=frozenset({0}),
                )
            )

        self.assertIn("default", str(refusal.exception))

    def test_removing_every_vip_is_refused_like_an_emptied_table(self) -> None:
        with self.assertRaises(FormProblem):
            document_from_form(self.form(default_vip_row="9", removed_vip_rows=frozenset({0, 1})))

    def test_a_row_number_the_form_never_drew_removes_nothing(self) -> None:
        self.assertEqual(row_numbers(("0", "", "not-a-row", "2")), frozenset({0, 2}))

    def test_members_may_be_separated_by_commas_as_well_as_lines(self) -> None:
        document = json.loads(
            document_from_form(self.form(group_members=("198.51.100.0/24, 203.0.113.10", "")))
        )

        self.assertEqual(document["networks"]["partners"], ["198.51.100.0/24", "203.0.113.10"])


class ThePageIsReachableAndWritesNothing(LoginTestCase):
    def demo_client(self):
        return self.client(replace(configuration(), demo_fixture=True))

    def test_the_tables_are_rendered_for_a_signed_in_user(self) -> None:
        client = self.demo_client()
        self.sign_in(client)

        page = client.get("/network")

        self.assertEqual(page.status_code, 200)
        self.assertIn("Virtual addresses", page.text)
        self.assertIn("Source addresses", page.text)
        self.assertIn("Reachable-from groups", page.text)

    def test_the_node_half_of_the_job_is_stated_without_a_standing_warning(self) -> None:
        #
        # The hazard belongs where an address is added, not as a permanent
        # banner about something nobody is doing. Two of those per cluster
        # taught the reader to skip the colour, which is the one thing a
        # warning may not do.
        #
        client = self.demo_client()
        self.sign_in(client)

        page = client.get("/network")

        self.assertIn("Nodes carry it through keepalived", page.text)
        self.assertNotIn("network-warning", page.text)

    def test_the_page_posts_nothing_yet(self) -> None:
        #
        # The layout carries a sign-out form, so the assertion is about this
        # page's own action rather than about forms existing at all.
        #
        client = self.demo_client()
        self.sign_in(client)

        page = client.get("/network")

        self.assertNotIn('action="/network"', page.text)
        self.assertIn("cannot be changed from here", page.text)

    def test_the_editable_page_says_nothing_about_the_ownership_address(self) -> None:
        #
        # The note claimed that address was in none of the tables. On a cluster
        # whose default VIP is the one `deploy` checks ownership against, it sat
        # directly under a table containing it. A note that contradicts the
        # table above it teaches a reader to trust neither.
        #
        page = self.editable_page()

        self.assertNotIn("Node ownership is checked against", page.text)

    def editable_page(self) -> Any:
        """The page as an admin sees it on a cluster it may publish to."""

        with mock.patch("haproxy_ui.db.cluster_networks", return_value=demo.network_rows(NOW)):
            client = self.client(
                replace(configuration(), management_writes=True, clusters=demo.CLUSTERS)
            )
            self.sign_in(client)
            return client.get("/network")

    def test_an_editable_repository_description_gets_a_fenced_publish_form(self) -> None:
        page = self.editable_page()

        self.assertIn('name="operation" value="network_publish"', page.text)
        self.assertIn('name="expected_head" value="' + "a" * 40 + '"', page.text)
        self.assertIn("3 managed objects follow it", page.text)
        self.assertIn("keepalived", page.text)

    def test_the_editor_is_the_tables_as_fields_rather_than_a_document_to_write(self) -> None:
        #
        # The first version of this form was one textarea holding the whole
        # document. It published, but it asked a person to hand-write the
        # engine's file - a shape nothing else in the interface asks for.
        #
        page = self.editable_page()

        self.assertIn('name="vip_address" value="192.0.2.20"', page.text)
        self.assertIn('name="source_name" value="outbound"', page.text)
        self.assertIn('name="default_vip_row"', page.text)
        self.assertNotIn('name="network"', page.text)

    def test_the_editable_cluster_shows_each_address_once(self) -> None:
        #
        # The editor replaces the reading rather than sitting under a copy of
        # it. Two tables of the same addresses raise the question of which one
        # is the real one, and the answer would be the one further from the eye.
        #
        page = self.editable_page()

        # Not the default VIP's address: that one is also this cluster's
        # ownership address, and the note naming it is a third mention by
        # design.
        self.assertEqual(page.text.count("192.0.2.21"), 1)

    def test_the_blank_rows_are_folded_away_but_still_in_the_form(self) -> None:
        #
        # A closed `details` still posts its fields. That is what the whole
        # scheme rests on: the default-VIP radio carries a row number, and a
        # spare row that stopped being submitted would shift every number
        # after it.
        #
        page = self.editable_page()

        self.assertIn('<details class="editor-add">', page.text)
        self.assertEqual(page.text.count('name="vip_name"'), 4)
        self.assertEqual(page.text.count('name="source_name"'), 3)
        self.assertIn('name="default_vip_row" value="3"', page.text)

    def test_each_editable_row_carries_its_own_removal(self) -> None:
        #
        # Removal used to be "clear the fields", which the form then refused as
        # a half-filled row. The box is the whole difference between a table a
        # person can edit and one they can only add to.
        #
        page = self.editable_page()

        self.assertIn('name="vip_remove" value="0"', page.text)
        self.assertIn('name="source_remove" value="0"', page.text)
        # The spare rows below the fold have nothing to remove yet.
        self.assertEqual(page.text.count('name="vip_remove"'), 2)

    def test_an_address_its_vip_carries_is_shown_here_and_changed_one_table_up(self) -> None:
        #
        # Leaving it out was right about where it is edited and wrong about
        # what a person reads: a cluster whose only source is paired with its
        # VIP got an empty table under the heading it was looking for.
        #
        page = self.editable_page()

        self.assertIn("edited in its VIP row above", page.text)
        self.assertIn('<span class="locked-value">192.0.2.25</span>', page.text)
        self.assertNotIn('name="source_name" value="public"', page.text)

    def test_signing_in_is_required(self) -> None:
        page = self.client().get("/network", follow_redirects=False)

        self.assertEqual(page.status_code, 303)
        self.assertEqual(page.headers["location"], "/login")

    def test_the_navigation_marks_the_page_it_is_on(self) -> None:
        client = self.client()
        self.sign_in(client)

        page = client.get("/network")

        self.assertIn('href="/network" aria-current="page"', page.text)
