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
from uuid import uuid4

from fastapi.testclient import TestClient
from haprion import address_ranges

from haprion_ui import demo
from haprion_ui.db import Job
from haprion_ui.jobs import Failure
from haprion_ui.network import (
    FormProblem,
    NetworkClusterView,
    NetworkForm,
    awaiting_deploy,
    build_network_overview,
    deployment,
    document_from_form,
    row_numbers,
)
from tests.test_login import LoginTestCase, configuration

NOW = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)
STALE_AFTER = timedelta(seconds=120)


def overview(clusters: tuple[str, ...] = demo.CLUSTERS) -> tuple[NetworkClusterView, ...]:
    return build_network_overview(
        clusters, demo.network_rows(NOW), now=NOW, stale_after=STALE_AFTER
    )


class TheReadingBecomesTheCard(unittest.TestCase):
    def test_a_repository_description_is_marked_editable(self) -> None:
        edge = next(view for view in overview() if view.cluster == "edge-demo")

        self.assertTrue(edge.editable)
        #
        # B331: where the network is kept, not whether this user may edit it now.
        #
        self.assertEqual(edge.label, "Managed here")
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
        self.assertEqual(service.label, "Not managed here")
        self.assertIn("cannot write", service.detail)

    def test_a_cluster_that_has_never_been_read_is_a_card_rather_than_a_gap(self) -> None:
        views = overview(demo.CLUSTERS + ("never-polled",))
        missing = next(view for view in views if view.cluster == "never-polled")

        self.assertEqual(missing.age_label, "Never")
        self.assertEqual(missing.vips, ())
        self.assertFalse(missing.editable)

    def test_the_policy_a_description_names_reaches_the_view(self) -> None:
        """It did not, and the page could not show what it had published.

        The helper reported a VIP as name, address and source and nothing
        else, so a policy written by this page came back missing on the next
        read - which looked exactly like a save that had not worked.
        """

        edge = next(view for view in overview() if view.cluster == "edge-demo")
        policies = {vip.name: vip.tls_policy for vip in edge.vips}

        self.assertEqual(policies["public"], "intermediate")

    def test_a_vip_that_names_no_policy_carries_none_rather_than_a_dash(self) -> None:
        """A dash matches no option, so the editor's select fell to its first.

        Which is how a VIP nobody had given a policy came to show one. The
        empty state has to be empty all the way to the template.
        """

        edge = next(view for view in overview() if view.cluster == "edge-demo")
        policies = {vip.name: vip.tls_policy for vip in edge.vips}

        self.assertIsNone(policies["partner"])

    def test_a_vip_s_own_source_address_is_listed_as_a_source_address(self) -> None:
        #
        # It was not, and the page then told a cluster that pairs a source with
        # its VIP that it had none - under a heading named after exactly that.
        #
        edge = next(view for view in overview() if view.cluster == "edge-demo")

        addresses = {source.address: source.name for source in edge.sources}
        self.assertEqual(addresses["192.0.2.25"], "public")
        self.assertEqual(addresses["192.0.2.26"], "partner")
        self.assertEqual(addresses["192.0.2.35"], "outbound")

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


class PublishedIsNotDeployed(unittest.TestCase):
    """The state the page could not say, which is why it sent people away.

    Publishing writes a release; a deploy is what makes the nodes pull it. The
    network page stated neither, so the interface moved somebody to the jobs
    page after every publish - and the button they needed was there by accident
    of being a follow-up row rather than by design.
    """

    # A publish of saved changes that carried the network description (B257).
    NETWORK: dict[str, Any] = {"network": "vips: {}\n"}

    def job(
        self,
        operation: str,
        cluster: str,
        state: str = "done",
        payload: dict[str, Any] | None = None,
        result: dict[str, Any] | None = None,
    ) -> Job:
        return Job(
            id=1,
            request_id=uuid4(),
            operation=operation,
            cluster=cluster,
            payload=payload or {},
            state=state,
            created_at=NOW,
            started_at=NOW,
            finished_at=NOW,
            exit_code=0,
            outcome="done",
            result=result,
            stderr_excerpt=None,
            idempotency_key=uuid4(),
            attempts=1,
        )

    def test_a_publish_with_no_deploy_after_it_is_waiting(self) -> None:
        waiting = awaiting_deploy([self.job("changes_publish", "alpha", payload=self.NETWORK)])

        self.assertEqual(waiting, frozenset({"alpha"}))

    def test_a_deploy_after_the_publish_ends_the_wait(self) -> None:
        """Jobs arrive newest first, so the deploy is the first row here."""

        waiting = awaiting_deploy(
            [
                self.job("deploy", "alpha"),
                self.job("changes_publish", "alpha", payload=self.NETWORK),
            ]
        )

        self.assertEqual(waiting, frozenset())

    def test_a_deploy_for_another_cluster_ends_nothing(self) -> None:
        """A deploy is per cluster, and so is what it settles."""

        waiting = awaiting_deploy(
            [self.job("deploy", "beta"), self.job("changes_publish", "alpha", payload=self.NETWORK)]
        )

        self.assertEqual(waiting, frozenset({"alpha"}))

    def test_a_publish_that_has_not_finished_is_not_waiting_for_a_deploy(self) -> None:
        """It is waiting for itself, and the running badge says so instead."""

        waiting = awaiting_deploy(
            [self.job("changes_publish", "alpha", state="running", payload=self.NETWORK)]
        )

        self.assertEqual(waiting, frozenset())

    #
    # Saved changes are published together since B257: the payload says which
    # parts the publish carried, and *Publish & deploy* is a deploy as well.
    #

    def test_saved_changes_that_carried_the_network_are_waiting(self) -> None:
        carried = self.job("changes_publish", "alpha", payload={"network": "vips: {}\n"})
        objects_only = self.job("changes_publish", "beta", payload={"objects": {"shop": "x"}})

        self.assertEqual(awaiting_deploy([carried, objects_only]), frozenset({"alpha"}))
        self.assertEqual(awaiting_deploy([carried], part="settings"), frozenset())

    def test_publish_and_deploy_that_finished_is_the_deploy(self) -> None:
        both = self.job("changes_publish", "alpha", payload={"network": "x", "deploy": True})

        self.assertEqual(
            awaiting_deploy([both, self.job("changes_publish", "alpha", payload={"network": "x"})]),
            frozenset(),
        )

    def test_a_deploy_that_failed_after_its_publish_leaves_it_waiting(self) -> None:
        failed = self.job(
            "changes_publish",
            "alpha",
            state="failed",
            payload={"network": "x", "deploy": True},
            result={"outcome": "failed", "publish": {"outcome": "done"}},
        )
        refused = self.job(
            "changes_publish",
            "beta",
            state="failed",
            payload={"network": "x", "deploy": True},
            result={"outcome": "failed"},
        )

        self.assertEqual(awaiting_deploy([failed, refused]), frozenset({"alpha"}))


class WhereTheConfigurationHasGotTo(unittest.TestCase):
    """One badge, in the order the four answers matter.

    A state rather than an announcement. The version before this said
    "Deployed successfully" for five seconds and then removed itself, which
    answered a question only the person who had just pressed the button was
    asking - and missed it for anyone who looked away.
    """

    def test_a_running_job_is_what_the_badge_says(self) -> None:
        state = deployment(running="Deploying", release_state="Converged", version="v53")

        self.assertEqual(state.label, "Deploying")
        self.assertTrue(state.running)

    def test_a_failure_beats_a_cluster_that_looks_well(self) -> None:
        """Which it does, because a refused job changed nothing.

        The configuration is as it was and the nodes are content. This is the
        one state the machine cannot report, so it comes from the jobs.
        """

        state = deployment(
            failure=Failure("Deploy failed", "deploy_refused"),
            release_state="Converged",
            version="v53",
        )

        self.assertEqual(state.tone, "critical")
        self.assertEqual(state.code, "deploy_refused")

    def test_a_publish_this_cluster_owes_a_deploy_says_so(self) -> None:
        state = deployment(awaiting=True, release_state="Converged", version="v53")

        self.assertEqual(state.label, "Reconfigured · deploy to activate")

    def test_nodes_off_the_release_are_not_described_as_a_publish(self) -> None:
        """A node nobody can reach reads as behind, and no button mends that."""

        state = deployment(release_state="Deploy Pending", version="v53")

        self.assertEqual(state.label, "Behind")
        self.assertEqual(state.tone, "warning")

    def test_a_node_that_is_not_reporting_leaves_save_in_place(self) -> None:
        """Review 26-10-24, 12-02: Save gave way to a deploy that mends nothing."""

        state = deployment(release_state="Incomplete", version="v53")

        self.assertEqual(state.label, "A node is not reporting")
        self.assertNotEqual(state.tone, "warning")

    def test_a_converged_cluster_names_the_version_it_is_on(self) -> None:
        state = deployment(release_state="Converged", version="v53")

        self.assertEqual(state.label, "v53 deployed")
        self.assertEqual(state.tone, "healthy")

    def test_an_unread_status_claims_nothing(self) -> None:
        state = deployment()

        self.assertEqual(state.tone, "unknown")

    def test_a_status_that_could_not_be_read_is_not_a_deploy_that_is_owed(self) -> None:
        """ "Unknown" is the dashboard's word for a cluster it could not read.

        Reading it as "not converged" had a cluster whose status was merely
        stale telling somebody to deploy - and offering the button for it.
        """

        state = deployment(release_state="Unknown", version="—")

        self.assertEqual(state.tone, "unknown")


class TheRowsBecomeTheDocument(unittest.TestCase):
    """What the editor posts, turned into the one shape the engine parses."""

    def form(self, **overrides: object) -> NetworkForm:
        fields: dict[str, object] = {
            "vip_names": ("public", ""),
            "vip_addresses": ("192.0.2.20", ""),
            "vip_sources": ("192.0.2.25", ""),
            "vip_tls": ("", ""),
            "default_vip_row": "0",
            "source_names": ("egress", ""),
            "source_addresses": ("192.0.2.35", ""),
            "group_names": ("partners", ""),
            "group_members": ("198.51.100.0/24\n203.0.113.10\n", ""),
        }
        fields.update(overrides)
        return NetworkForm(**fields)  # type: ignore[arg-type]

    def test_a_group_range_with_host_bits_is_refused_in_the_engine_s_words(self) -> None:
        """Review 26-10-24, 15-06: said when the change is saved, not when it is published."""

        with self.assertRaises(FormProblem) as refusal:
            document_from_form(self.form(group_members=("198.51.100.7/24\n", "")))

        self.assertEqual(str(refusal.exception), f"Group row 1: {address_ranges.HOST_BITS}.")

    def test_a_ticked_http3_box_is_written_on_its_row_only(self) -> None:
        """B280: by row number, like a removal; an unticked box posts nothing."""

        document = json.loads(
            document_from_form(
                self.form(
                    vip_names=("public", "mail"),
                    vip_addresses=("192.0.2.20", "192.0.2.21"),
                    vip_sources=("", ""),
                    http3_vip_rows=frozenset({0}),
                )
            )
        )

        self.assertIs(document["vips"]["public"]["http3"], True)
        self.assertNotIn("http3", document["vips"]["mail"])

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
    def demo_client(self) -> TestClient:
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

    def editable_page(self, objects: Any = None) -> Any:
        """The page as an admin sees it on a cluster it may publish to."""

        with (
            mock.patch("haprion_ui.db.cluster_networks", return_value=demo.network_rows(NOW)),
            mock.patch(
                "haprion_ui.db.cluster_objects",
                return_value=demo.object_rows(NOW) if objects is None else objects,
            ),
        ):
            client = self.client(
                replace(configuration(), management_writes=True, clusters=demo.CLUSTERS)
            )
            self.sign_in(client)
            return client.get("/network")

    def test_each_address_and_group_names_the_objects_using_it(self) -> None:
        page = self.editable_page().text

        vips = page.split("Add a virtual address", 1)[0]
        self.assertIn(
            '<a href="/proxies?cluster=edge-demo&amp;vip=public">2 proxies</a>',
            vips,
            "two or more are a count leading to the listing narrowed to them",
        )
        self.assertNotIn('<a href="/proxies/edge-demo/shop">', vips)
        self.assertIn(
            '<a href="/proxies?cluster=edge-demo&amp;source=192.0.2.25">2 proxies</a>', page
        )
        self.assertIn('<a href="/proxies/service-demo/api">api</a>', page, "one by name")
        self.assertIn('<span class="table-empty">not used</span>', page)

    def test_a_reader_reads_the_names_without_links(self) -> None:
        self.account = replace(self.account, role="reader")
        page = self.editable_page().text

        self.assertIn('<td data-label="Used by">api</td>', page)
        self.assertNotIn('<a href="/proxies/service-demo/api">', page)
        self.assertIn('<a href="/proxies?cluster=edge-demo&amp;vip=public">2 proxies</a>', page)

    def test_objects_that_could_not_be_read_say_nothing(self) -> None:
        page = self.editable_page(objects=[]).text

        self.assertNotIn("not used", page)
        self.assertIn('<td class="editor-used"><span class="table-empty">—</span></td>', page)

    def test_an_editable_repository_description_gets_a_fenced_publish_form(self) -> None:
        page = self.editable_page()

        self.assertIn('name="operation" value="network_save"', page.text)
        self.assertIn('name="expected_head" value="' + "a" * 40 + '"', page.text)
        self.assertIn("3 proxies follow it", page.text)
        self.assertIn("keepalived", page.text)

    def owed_page(self) -> Any:
        """The same page, with the editable cluster owed a deploy.

        The fixture's behind cluster is the one that cannot be edited, so its
        deploy button lands in a footer rather than in a form's action row.
        Here the two are put on the same cluster, which is the case the swap
        exists for.
        """

        behind = next(row for row in demo.status_rows(NOW) if row.cluster == "service-demo")
        statuses = tuple(
            replace(row, result=behind.result) if row.cluster == "edge-demo" else row
            for row in demo.status_rows(NOW)
        )
        with (
            mock.patch("haprion_ui.db.cluster_networks", return_value=demo.network_rows(NOW)),
            mock.patch("haprion_ui.db.cluster_statuses", return_value=statuses),
        ):
            client = self.client(
                replace(configuration(), management_writes=True, clusters=demo.CLUSTERS)
            )
            self.sign_in(client)
            return client.get("/network")

    def test_the_button_says_the_step_that_is_actually_due(self) -> None:
        """One button, not two. A description that is published and not

        deployed has a deploy owed before another edit is worth writing, so the
        row carries that instead of a publish button beside a deploy button
        that is wrong most of the time.
        """

        card = self.owed_page().text.split("service-demo", 1)[0]

        self.assertIn('form="deploy-', card)
        self.assertIn("Deploy before writing another change", card)
        self.assertNotIn('name="network_action" value="save"', card)

    def test_the_owed_deploy_is_bound_to_the_version_the_page_shows(self) -> None:
        card = self.owed_page().text.split("service-demo", 1)[0]

        self.assertIn('name="expected_version" value="24"', card)

    def test_a_cluster_with_nothing_owed_keeps_its_save_button(self) -> None:
        """And the swap is only ever one of the two, never both at once."""

        card = self.editable_page().text.split("service-demo", 1)[0]

        self.assertIn('name="network_action" value="save"', card)
        self.assertNotIn('form="deploy-', card)

    def test_the_editor_is_the_tables_as_fields_rather_than_a_document_to_write(self) -> None:
        #
        # The first version of this form was one textarea holding the whole
        # document. It published, but it asked a person to hand-write the
        # engine's file - a shape nothing else in the interface asks for.
        #
        page = self.editable_page()

        self.assertIn('name="vip_address" value="192.0.2.20"', page.text)
        #
        # And it comes back here afterwards. Publishing used to land on the
        # jobs page, which was the only page that knew what had happened.
        #
        self.assertIn('name="return_to" value="network"', page.text)
        self.assertIn('<option value="intermediate" selected>TLS 1.2 and 1.3</option>', page.text)
        self.assertIn('<option value="" selected disabled>Not set</option>', page.text)
        self.assertIn('name="source_name" value="outbound"', page.text)
        self.assertIn('name="default_vip_row"', page.text)
        self.assertNotIn('name="network"', page.text)

    def test_the_page_can_stop_a_spinner_it_starts(self) -> None:
        """The watcher is on the page.

        Drawing a running job is only half of it: this page was rendered once
        and never asked again, so the badge turned until somebody left the tab
        and came back. `data-busy` is what it watches; whether the poller has
        caught up with the job the server answers itself (0068).
        """

        page = self.editable_page()

        self.assertIn("waiting.js", page.text)

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

    def test_the_spare_rows_line_up_with_the_rows_above_them(self) -> None:
        """As many columns as cells, and the same as the table above.

        The spare rows carry a TLS cell like the rows above, but their
        colgroup named five columns - so the select landed in the width meant
        for a radio button and showed its option cut off mid-word.
        """

        page = self.editable_page()
        above, rest = page.text.split("Add a virtual address", 1)
        listed = above.rsplit("<colgroup>", 1)[1].split("</colgroup>", 1)[0]
        spare = rest.split("</table>", 1)[0]
        row = spare.split("<tr>", 1)[1].split("</tr>", 1)[0]

        self.assertEqual(spare.count("<col "), row.count("<td"))
        self.assertEqual(spare.count("<col "), listed.count("<col "))
        self.assertIn('<col class="col-tls">', spare)

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


class WhatAVipSaysAboutTls(TheRowsBecomeTheDocument):
    """The column exists because a bind line belongs to an address.

    Several sites answer on one VIP through SNI and share its bind line, so the
    policy is the VIP's and not the site's. What a site may override is a
    separate question with a separate mechanism.
    """

    def test_a_policy_a_row_named_reaches_the_document(self) -> None:
        document = json.loads(document_from_form(self.form(vip_tls=("modern", ""))))

        self.assertEqual(document["vips"]["public"]["tls"], "modern")

    def test_the_ceiling_policy_reaches_the_document_too(self) -> None:
        """`tls12only` is a name the engine knows; the form only carries it."""

        document = json.loads(document_from_form(self.form(vip_tls=("tls12only", ""))))

        self.assertEqual(document["vips"]["public"]["tls"], "tls12only")

    def test_a_row_that_named_none_writes_no_key_at_all(self) -> None:
        """Not an empty string.

        The engine refuses a policy it does not know, so `""` would be a
        refusal rather than inheritance - and inheritance is what every VIP
        written before this column existed has. The page shows that state as
        "Not set" and offers no way back to it, but a cluster nobody has opened
        this page for must still publish unchanged.
        """

        document = json.loads(document_from_form(self.form()))

        self.assertNotIn("tls", document["vips"]["public"])

    def test_the_source_and_the_policy_are_independent(self) -> None:
        """Two cells on one row, and neither is the other's condition."""

        document = json.loads(
            document_from_form(self.form(vip_sources=("", ""), vip_tls=("intermediate", "")))
        )

        self.assertEqual(document["vips"]["public"]["tls"], "intermediate")
        self.assertNotIn("source", document["vips"]["public"])
