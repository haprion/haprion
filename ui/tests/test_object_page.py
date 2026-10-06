"""The page behind a proxy row: who may open it, and what it refuses to invent.

The route is the first place the objects cache reaches a screen, so what is
worth testing here is not the rendering but the two boundaries around it - the
role that may see a document naming certificates and backend addresses, and the
refusal to render a page for a name that does not exist.
"""

from __future__ import annotations

import re
import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest import mock
from uuid import UUID, uuid4

from haproxy_ui import demo, metrics
from haproxy_ui.db import ClusterInventory, Job, ProxyDraft
from haproxy_ui.snapshot import ProductionSnapshot
from tests.test_cluster_traffic import measurement
from tests.test_login import LoginTestCase, configuration

CAPTURED = datetime(2026, 9, 2, 9, 0, tzinfo=UTC)
#
# One cluster serving one proxy, and no objects row at all - which is what a
# snapshot holds.
#
SNAPSHOT = ProductionSnapshot(
    captured_at=CAPTURED,
    clusters=("alpha",),
    status_rows=(),
    inventory_rows=(
        ClusterInventory(
            cluster="alpha",
            observed_at=CAPTURED,
            outcome="done",
            result={
                "version": 12,
                "proxies": [
                    {
                        "name": "app",
                        "protocol": "https",
                        "managed": True,
                        "enabled": True,
                        "hostnames": ["app.example.com"],
                        "bind_ports": [443],
                        "backend_count": 2,
                    }
                ],
            },
            warnings=[],
            error=None,
            poll_error=None,
        ),
    ),
    history_rows=(),
    certificate_rows=(),
    backup_rows=(),
    network_rows=(),
)


class DraftReading(LoginTestCase):
    """The page reads a draft now, so every case here has to answer that call.

    Defaulted to "no draft" rather than left unpatched: a page whose draft
    lookup fails is a page that does not render at all, which would hide
    whatever the case was actually about.
    """

    draft: ProxyDraft | None = None

    def setUp(self) -> None:
        super().setUp()
        patch = mock.patch("haproxy_ui.db.read_draft", side_effect=lambda *_a, **_k: self.draft)
        patch.start()
        self.addCleanup(patch.stop)
        #
        # And the backend traffic the page draws for a readable fixture object,
        # which the recording pool here cannot answer.
        #
        for name, answer in (
            ("read_backend_series", lambda *_a, **_k: []),
            ("read_backend_totals", lambda *_a, **_k: measurement()),
            ("read_backend_aliases", lambda *_a, **_k: {}),
        ):
            patch = mock.patch(f"haproxy_ui.db.{name}", side_effect=answer)
            patch.start()
            self.addCleanup(patch.stop)


class OpeningAnObject(DraftReading):
    def demo_client(self) -> object:
        client = self.client(replace(configuration(), demo_fixture=True))
        self.sign_in(client)
        return client

    def test_an_admin_sees_the_document_as_it_is_stored(self) -> None:
        page = self.demo_client().get("/proxies/edge-demo/public-web")  # type: ignore[attr-defined]

        self.assertEqual(page.status_code, 200)
        self.assertIn("app.demo.example", page.text)
        self.assertIn("managed/proxies/public-web.yaml", page.text)

    def test_an_object_this_version_cannot_read_shows_the_refusal_and_the_file(self) -> None:
        """It is the one somebody has to open, so it must open."""

        page = self.demo_client().get("/proxies/edge-demo/staging")  # type: ignore[attr-defined]

        self.assertEqual(page.status_code, 200)
        self.assertIn("cannot read", page.text)
        self.assertIn("routes is required", page.text)

    def test_an_unmanaged_proxy_opens_and_says_where_it_comes_from(self) -> None:
        page = self.demo_client().get("/proxies/edge-demo/metrics")  # type: ignore[attr-defined]

        self.assertEqual(page.status_code, 200)
        self.assertIn("not written here", page.text)

    def test_a_proxy_with_no_object_never_names_a_file(self) -> None:
        """The card said "managed/proxies/<name>.yaml at <commit>" beside
        "nothing stored", because the path was keyed off the reading's commit
        rather than off this object. It named a file that does not exist."""

        page = self.demo_client().get("/proxies/edge-demo/metrics")  # type: ignore[attr-defined]

        self.assertNotIn("managed/proxies/metrics.yaml", page.text)

    def test_a_name_that_is_neither_stored_nor_served_is_not_a_page(self) -> None:
        """Otherwise every typo looks like a proxy somebody deleted."""

        page = self.demo_client().get("/proxies/edge-demo/nothing-here")  # type: ignore[attr-defined]

        self.assertEqual(page.status_code, 404)

    def test_an_unknown_cluster_is_not_a_page(self) -> None:
        page = self.demo_client().get("/proxies/no-such-cluster/public-web")  # type: ignore[attr-defined]

        self.assertEqual(page.status_code, 404)

    def test_signing_out_is_a_redirect_and_never_the_document(self) -> None:
        client = self.client(replace(configuration(), demo_fixture=True))

        page = client.get("/proxies/edge-demo/public-web", follow_redirects=False)

        self.assertEqual(page.status_code, 303)
        self.assertEqual(page.headers["location"], "/login")


class InSnapshotMode(DraftReading):
    """Dev runs against a captured production snapshot, which carries no objects.

    The reason is in `OBJECTS_SOURCE`: a snapshot is a file copied into the
    development platform, and a stored document names every backend address the
    cluster talks to. The page must say that rather than "not read yet", which
    reads as a poller that is failing and sends somebody looking for a fault
    that is not there.
    """

    def test_the_page_says_the_snapshot_leaves_objects_out(self) -> None:
        client = self.client(replace(configuration(), production_snapshot=True))
        self.sign_in(client)

        with mock.patch("haproxy_ui.snapshot.load_production_snapshot", return_value=SNAPSHOT):
            page = client.get("/proxies/alpha/app")

        self.assertEqual(page.status_code, 200)
        self.assertIn("Not carried in a snapshot", page.text)
        self.assertNotIn("have not been read yet", page.text)


class TheOverviewOrdering(LoginTestCase):
    def test_an_undeployed_object_keeps_its_alphabetical_place(self) -> None:
        """Not a section below the table, and not moved to the top either.

        Waiting rows went first once, so the one that changed was not missed;
        editing an object then moved it, which read as the list reshuffling
        itself. The badge says it is waiting; the position is alphabetical.
        """

        client = self.client(replace(configuration(), demo_fixture=True))
        self.sign_in(client)

        text = client.get("/proxies").text
        rows = re.findall(r'href="/proxies/edge-demo/([a-z-]+)"', text)

        self.assertIn("shop", rows)
        self.assertEqual(rows, sorted(rows))
        self.assertNotIn("Stored, not yet serving", text)

    def test_the_whole_row_opens_the_object(self) -> None:
        """The name is a link, and the rest of the row follows it (proxy-rows.js)."""

        client = self.client(replace(configuration(), demo_fixture=True))
        self.sign_in(client)

        text = client.get("/proxies").text

        self.assertIn("/proxy-rows.js", text)
        self.assertIn('data-href="/proxies/edge-demo/shop"', text)

    def test_published_rows_are_alphabetical_and_not_in_file_order(self) -> None:
        """Section order is an artefact of how the file was assembled."""

        client = self.client(replace(configuration(), demo_fixture=True))
        self.sign_in(client)

        text = client.get("/proxies").text
        rows = re.findall(r'href="/proxies/service-demo/([a-z-]+)"', text)

        self.assertEqual(rows, sorted(rows))

    def test_an_undeployed_row_is_still_an_object_of_ours(self) -> None:
        """It is the object somebody wrote, whether or not a node serves it yet.

        The row used to describe a published frontend, so an undeployed one had
        no backend count and no ownership to state. It describes the object
        now, and an object has backends and is ours from the moment it exists.
        """

        client = self.client(replace(configuration(), demo_fixture=True))
        self.sign_in(client)

        text = client.get("/proxies").text
        row = text.split('class="proxy-waiting"', 1)[1].split("</tr>", 1)[0]
        self.assertIn("shop", row)

        self.assertIn("Inactive · deploy to add", row)
        self.assertIn("ownership-managed", row)

    def test_the_state_takes_the_protocol_cell_and_spares_the_hostnames(self) -> None:
        """A badge beside the hostnames was a second thing in a column sized for
        one, and on a narrow screen it ran into the column after it.

        It moved into hosts / ports and replaced them, which cost more than it
        saved: the longest badge is wider than that column, so it was clipped
        mid-word and drew over the health lamp - and the hostnames it displaced
        are what somebody opened the listing to read. It sits in the protocol
        cell now, which carries one word that is also on the object's own page.
        """

        client = self.client(replace(configuration(), demo_fixture=True))
        self.sign_in(client)

        text = client.get("/proxies").text
        row = text.split('href="/proxies/edge-demo/shop"', 1)[1].split("</tr>", 1)[0]
        protocol = row.split('data-label="Protocol"', 1)[1].split("</td>", 1)[0]
        hosts = row.split('data-label="Hosts / ports"', 1)[1].split("</td>", 1)[0]

        self.assertIn("Inactive · deploy to add", protocol)
        self.assertIn("shop.demo.example", hosts)
        self.assertNotIn("Inactive", hosts)

    def test_the_listing_does_not_count_backends_at_all(self) -> None:
        """It counted backends, which the form writes exactly one of.

        So the column was a column of ones, under a heading that reads as the
        servers behind a site - and the health cell beside it already says how
        many of those there are and how many are up.
        """

        client = self.client(replace(configuration(), demo_fixture=True))
        self.sign_in(client)

        text = client.get("/proxies").text

        self.assertNotIn("<th>Backends</th>", text)
        self.assertNotIn('data-label="Backends"', text)

    def test_a_row_with_nothing_to_report_shows_its_hosts(self) -> None:
        client = self.client(replace(configuration(), demo_fixture=True))
        self.sign_in(client)

        text = client.get("/proxies").text
        serving = [
            cell.split("</td>", 1)[0]
            for cell in text.split('data-label="Hosts / ports"')[1:]
            if "waiting-badge" not in cell.split("</td>", 1)[0]
        ]

        self.assertTrue(serving, "every row is reporting something")
        self.assertTrue(any("example" in cell for cell in serving))


class WhoMayRead(LoginTestCase):
    def test_a_non_admin_is_refused(self) -> None:
        """The document names certificates and every backend address behind a
        site, which the overview deliberately does not show. B68 settled the
        same question for the preview, and this is the same data."""

        self.account = replace(self.account, role="operator")
        client = self.client(replace(configuration(), demo_fixture=True))
        self.sign_in(client)

        page = client.get("/proxies/edge-demo/public-web")

        self.assertEqual(page.status_code, 403)

    def test_the_overview_offers_the_link_only_to_an_admin(self) -> None:
        """A link that always refuses is worse than no link."""

        self.account = replace(self.account, role="operator")
        client = self.client(replace(configuration(), demo_fixture=True))
        self.sign_in(client)

        page = client.get("/proxies")

        self.assertEqual(page.status_code, 200)
        self.assertIn("public-web", page.text)
        self.assertNotIn('href="/proxies/edge-demo/public-web"', page.text)


class TheFixtureDescribesARealCluster(LoginTestCase):
    def test_it_carries_an_object_that_does_not_parse(self) -> None:
        """Without one, a page could ship that renders only what parses."""

        rows = demo.object_rows()
        entries = [
            entry for row in rows for entry in row.result["objects"] if not entry["readable"]
        ]

        self.assertTrue(entries)
        self.assertTrue(all(entry["document"] for entry in entries))

    def test_unmanaged_proxies_have_no_object(self) -> None:
        """Which is what a cluster part-way through the move looks like."""

        stored = {entry["name"] for row in demo.object_rows() for entry in row.result["objects"]}

        self.assertNotIn("metrics", stored)
        self.assertNotIn("legacy-tcp", stored)


class TheDraftOnTheObjectPage(DraftReading):
    """A draft is why this page exists after a save, so it has to be on it.

    It also has to make the page exist at all: an object written here and never
    published is stored nowhere and served nowhere, and without the draft it
    would be a 404 - met immediately after saving the first draft of it.
    """

    def drafted(self, **fields: object) -> ProxyDraft:
        values: dict[str, object] = {
            "cluster": "edge-demo",
            "object_id": "public-web",
            "yaml": "",
            "base_version": 1,
            "base_hash": "abc",
            "revision": 3,
            "updated_by": "operator",
            "updated_at": CAPTURED,
            "deleted": False,
        }
        values.update(fields)
        return ProxyDraft(**values)  # type: ignore[arg-type]

    def page(self, path: str = "/proxies/edge-demo/public-web") -> object:
        client = self.client(replace(configuration(), demo_fixture=True))
        self.sign_in(client)
        return client.get(path)

    def test_the_draft_is_named_with_who_changed_it(self) -> None:
        self.draft = self.drafted()
        body = self.page().text  # type: ignore[attr-defined]

        self.assertIn("An unpublished draft", body)
        self.assertIn("operator", body)
        self.assertIn("revision 3", body)

    def test_a_draft_that_removes_the_object_says_so(self) -> None:
        self.draft = self.drafted(deleted=True)

        self.assertIn("should be <strong>removed</strong>", self.page().text)  # type: ignore[attr-defined]

    def test_without_one_the_page_says_nothing_about_drafts(self) -> None:
        self.assertNotIn("An unpublished draft", self.page().text)  # type: ignore[attr-defined]

    def test_the_save_is_confirmed_where_it_landed(self) -> None:
        """A 303 leaves nothing behind, so the page has to carry the answer."""

        self.draft = self.drafted()
        body = self.page("/proxies/edge-demo/public-web?saved=1").text  # type: ignore[attr-defined]

        self.assertIn("Saved as a draft", body)

    def test_a_discard_is_confirmed_too(self) -> None:
        body = self.page("/proxies/edge-demo/public-web?discarded=1").text  # type: ignore[attr-defined]

        self.assertIn("draft was discarded", body)


class ADraftInTheListing(DraftReading):
    """A draft is a row of its own, one step before "waiting for deploy".

    Waiting means committed to the cluster repository and not yet deployed. A
    draft has not reached the repository at all, so it is in neither the
    inventory nor the objects cache - and the period when somebody needs to
    find their work is exactly the period before it is anywhere else.
    """

    def listing(self, drafts: list[object]) -> str:
        client = self.client(replace(configuration(), demo_fixture=True))
        self.sign_in(client)
        with mock.patch("haproxy_ui.db.cluster_drafts", return_value=drafts):
            return str(client.get("/proxies").text)

    def drafted(self, name: str, *, deleted: bool = False) -> ProxyDraft:
        return ProxyDraft(
            cluster="edge-demo",
            object_id=name,
            yaml="",
            base_version=1,
            base_hash="abc",
            revision=1,
            updated_by="operator",
            updated_at=CAPTURED,
            deleted=deleted,
        )

    def test_a_draft_is_listed_and_says_it_is_one(self) -> None:
        body = self.listing([self.drafted("half-done")])

        self.assertIn("half-done", body)
        self.assertIn(">Draft<", body)

    def test_a_draft_that_removes_the_object_says_which_kind_it_is(self) -> None:
        self.assertIn("Draft: removal", self.listing([self.drafted("going", deleted=True)]))

    def test_the_badge_is_not_a_warning(self) -> None:
        """Unfinished work is not a fault, and must not be coloured like one."""

        body = self.listing([self.drafted("half-done")])

        self.assertIn("status-badge-info waiting-badge", body)

    def test_a_draft_of_a_stored_object_keeps_the_rest_of_its_row(self) -> None:
        # 26-10-03: a draft is a badge on the object's row, as a pending deploy is,
        # not a row of dashes - unless the object has never been stored. edge-demo
        # stores public-web; service-demo does not, so its draft there is new.
        body = self.listing([self.drafted("public-web")])
        stored = body.split('class="proxy-draft" data-href="/proxies/edge-demo/public-web"', 1)
        row = stored[1].split("</tr>", 1)[0]
        new = body.split('class="proxy-draft" data-href="/proxies/service-demo/public-web"', 1)
        new_row = new[1].split("</tr>", 1)[0]

        self.assertIn(">Draft<", row)
        self.assertIn("app.demo.example", row)
        self.assertIn("ownership-managed", row)
        self.assertEqual(body.count('href="/proxies/edge-demo/public-web"><strong>'), 1)
        self.assertIn('<td data-label="Hosts / ports"><span class="table-empty">', new_row)

    def test_without_drafts_the_listing_says_nothing_about_them(self) -> None:
        self.assertNotIn(">Draft<", self.listing([]))


class ADraftOnItsWay(DraftReading):
    """Between the click and the row, the page has to say the work is moving.

    A publish is a job. There is a stretch where the object is neither a draft
    somebody is still editing nor a published row, and "Draft" through all of
    it reads as though the button did nothing.
    """

    def listing(self, jobs: list[object]) -> str:
        drafts = [
            ProxyDraft(
                cluster="edge-demo",
                object_id="half-done",
                yaml="",
                base_version=1,
                base_hash="abc",
                revision=1,
                updated_by="operator",
                updated_at=CAPTURED,
                deleted=False,
            )
        ]
        client = self.client(replace(configuration(), demo_fixture=True))
        self.sign_in(client)
        with (
            mock.patch("haproxy_ui.db.cluster_drafts", return_value=drafts),
            mock.patch("haproxy_ui.db.recent_jobs", return_value=jobs),
        ):
            return str(client.get("/proxies").text)

    def job(self, state: str, name: str = "half-done") -> Job:
        return Job(
            id=1,
            request_id=uuid4(),
            operation="objects_publish",
            cluster="edge-demo",
            payload={"objects": {name: "schema: 1"}},
            state=state,
            created_at=CAPTURED,
            started_at=None,
            finished_at=None,
            exit_code=None,
            outcome=None,
            result=None,
            stderr_excerpt=None,
            idempotency_key=None,
            attempts=0,
        )

    def test_a_queued_publish_turns_the_badge_into_waiting(self) -> None:
        body = self.listing([self.job("pending")])

        self.assertIn("Waiting for publish", body)
        self.assertIn("badge-spinner", body)

    def test_the_page_carries_what_makes_it_come_back(self) -> None:
        """A publish resolves in seconds, and the reader is looking right then.

        The listing is rendered once and then sits still, so without this the
        spinner turns until somebody leaves the page and returns - which is how
        it was found.
        """

        self.assertIn("waiting.js", self.listing([self.job("pending")]))

    def test_a_running_publish_says_the_same(self) -> None:
        self.assertIn("Waiting for publish", self.listing([self.job("running")]))

    def test_a_refused_publish_says_so_instead_of_spinning_or_going_quiet(self) -> None:
        """Neither still trying nor an ordinary draft. It stopped, and nothing changed.

        Saying only "Draft" was how a refused publish read as the interface
        turning the object back into one by itself - the reason existed, on the
        jobs page, behind a click nobody had a reason to make.
        """

        body = self.listing([self.job("failed")])

        self.assertNotIn("Waiting for publish", body)
        self.assertIn("Publish refused", body)

    def test_the_reason_the_helper_gave_is_what_the_row_names(self) -> None:
        """The code from the envelope, not the word "failed".

        `objects_invalid` sends somebody to the document; a bare "failed" sends
        them nowhere. The jobs page reads the same field, so the two cannot
        come to disagree about why one publish stopped.
        """

        job = replace(
            self.job("failed"),
            result={"error": {"code": "objects_invalid", "message": "unknown field"}},
        )

        self.assertIn("objects_invalid", self.listing([job]))

    def test_a_later_publish_that_worked_clears_the_reason(self) -> None:
        """Jobs arrive newest first, and only the newest verdict counts.

        A failure the next attempt fixed is history. Left on the row it would
        send somebody after a problem that is already gone.
        """

        newer = replace(self.job("done"), id=2)
        older = replace(self.job("failed"), id=1)

        body = self.listing([newer, older])

        self.assertNotIn("Publish refused", body)

    def test_another_object_s_publish_does_not_claim_this_row(self) -> None:
        body = self.listing([self.job("pending", name="something-else")])

        self.assertNotIn("Waiting for publish", body)


class ADraftThatWasPublished(DraftReading):
    """Published work is not a draft any more, and a stale row is not tidy-up.

    The editor opens a draft in preference to the stored object, so one left
    behind hands somebody their pre-publish copy of a document they already
    published - and the next save writes it back.
    """

    #
    # One draft row, named the way the job names it. Fixed rather than random,
    # because the pairing between the two is the thing under test.
    #
    DRAFT_ID = UUID("11111111-2222-3333-4444-555555555555")

    def drafted(
        self, yaml: str = "schema: 1\n", *, revision: int = 1, name: str = "half-done"
    ) -> ProxyDraft:
        return ProxyDraft(
            cluster="edge-demo",
            object_id=name,
            yaml=yaml,
            base_version=1,
            base_hash="abc",
            revision=revision,
            updated_by="operator",
            updated_at=CAPTURED,
            deleted=False,
            id=self.DRAFT_ID,
        )

    def job(
        self, state: str, yaml: str = "schema: 1\n", *, revision: int = 1, name: str = "half-done"
    ) -> Job:
        from haproxy_ui.views import _publish_key

        payload = {
            "objects": {name: "schema: 1"},
            "draft": {"id": str(self.DRAFT_ID), "revision": revision},
        }
        return Job(
            id=1,
            request_id=uuid4(),
            operation="objects_publish",
            cluster="edge-demo",
            payload=payload,
            state=state,
            created_at=CAPTURED,
            started_at=None,
            finished_at=None,
            exit_code=None,
            outcome=None,
            result=None,
            stderr_excerpt=None,
            idempotency_key=_publish_key("edge-demo", "objects_publish", payload),
            attempts=0,
        )

    def listing(self, draft: ProxyDraft, jobs: list[Job]) -> tuple[str, list[dict[str, Any]]]:
        discarded: list[dict[str, Any]] = []
        client = self.client(replace(configuration(), demo_fixture=True))
        self.sign_in(client)

        #
        # Per cluster, because the fixture has more than one and a draft that
        # belonged to all of them would count every deletion twice.
        #
        def drafts(_c: object, cluster: str) -> list[ProxyDraft]:
            return [draft] if cluster == draft.cluster else []

        def only(_c: object, cluster: str) -> list[Job]:
            return jobs if cluster == draft.cluster else []

        with (
            mock.patch("haproxy_ui.db.cluster_drafts", side_effect=drafts),
            mock.patch("haproxy_ui.db.recent_jobs", side_effect=only),
            mock.patch(
                "haproxy_ui.db.discard_draft", side_effect=lambda *a, **k: discarded.append(k)
            ),
        ):
            return str(client.get("/proxies").text), discarded

    def test_a_finished_publish_holds_the_draft_until_the_object_is_readable(self) -> None:
        #
        # The publish is done and the poller has not read the repository again,
        # so the object is in no cache yet. Clearing the draft here made the row
        # vanish from every page for that stretch: the spinner said "waiting for
        # publish", the publish finished, and the work was nowhere.
        #
        body, discarded = self.listing(self.drafted(), [self.job("done")])

        self.assertEqual(discarded, [])
        self.assertIn(">Draft<", body)

    def test_the_draft_is_cleared_once_the_object_can_be_read(self) -> None:
        #
        # `public-web` is in the cluster's objects reading, so the publish this
        # draft asked for is visible and the draft has nothing left to carry.
        #
        body, discarded = self.listing(
            self.drafted(name="public-web"), [self.job("done", name="public-web")]
        )

        self.assertEqual(len(discarded), 1)
        self.assertEqual(discarded[0]["object_id"], "public-web")
        self.assertNotIn(">Draft<", body)

    def test_a_draft_edited_after_the_publish_is_left_alone(self) -> None:
        """An edit raises the revision, and the job published the one before it."""

        body, discarded = self.listing(
            self.drafted(yaml="schema: 1\nname: changed\n", revision=2), [self.job("done")]
        )

        self.assertEqual(discarded, [])
        self.assertIn(">Draft<", body)

    def test_a_draft_reverted_to_a_published_text_is_not_thrown_away(self) -> None:
        #
        # The same bytes as a version published earlier, which is somebody
        # deliberately going back - and while the key was derived from the
        # document, that read as work already finished and deleted it.
        #
        body, discarded = self.listing(self.drafted(revision=3), [self.job("done", revision=1)])

        self.assertEqual(discarded, [])
        self.assertIn(">Draft<", body)

    def test_a_publish_that_failed_keeps_the_work_and_names_the_reason(self) -> None:
        body, discarded = self.listing(self.drafted(), [self.job("failed")])

        self.assertEqual(discarded, [])
        self.assertIn("Publish refused", body)


class OneObjectIsOneRow(DraftReading):
    """The name in the document, once, whatever it takes to implement.

    The listing used to show frontends. The generator names those after the
    address and protocol they bind - `mgd-<vip>-<protocol>` - and every object
    on that address shares them, so an https object that redirects plain HTTP
    appeared as two rows, under two names its author never chose, neither of
    which was the name in the document.
    """

    def listing(self) -> str:
        client = self.client(replace(configuration(), demo_fixture=True))
        self.sign_in(client)
        return str(client.get("/proxies").text)

    def test_no_row_is_named_after_a_generated_frontend(self) -> None:
        body = self.listing()

        self.assertNotIn("mgd-main-http", body)
        self.assertNotIn("mgd-main-https", body)

    def test_the_object_is_named_as_its_author_named_it(self) -> None:
        self.assertIn("public-web", self.listing())


class WhichPoolsTheTrafficCardAsksAbout(unittest.TestCase):
    """Both sources, because each answers for a kind the other cannot.

    A managed object is served under the shared VIP frontend's name, so the
    inventory never knows it by its own - `published` is None for every one of
    them. An unmanaged proxy has no stored document, so the generator's naming
    rule has nothing to work from. Keying the card off either alone loses half
    the pages, and losing the managed half is how the card disappeared from
    production after it had been working there.
    """

    def test_the_view_reads_both_and_neither_hides_the_other(self) -> None:
        source = (
            Path(__file__).resolve().parents[1] / "src" / "haproxy_ui" / "views.py"
        ).read_text()
        block = source.split("# Which backends this page can ask about", 1)[1].split(
            "if served:", 1
        )[0]
        self.assertIn("detail.published.backends", block)
        self.assertIn("metrics.backend_targets({name: proxy})", block)
        self.assertIn("not in served", block)


class OneCardPerBackendAcrossTheRename(DraftReading):
    """B250: a pool's history is under `mgd-<object>-<pool>` until the cluster is
    deployed with the newer engine, and under the pool's own name after. The
    page draws one card under the pool's name that reads both."""

    def cards_with_readings_under(self, name: str) -> tuple[int, list[str]]:
        asked: list[str] = []

        def series(*_a: Any, backend: str, earlier: Any = (), **_k: Any) -> list[Any]:
            names = [backend, *(item.name for item in earlier)]
            asked.extend(names)
            if name not in names:
                return []
            moment = datetime.now(UTC)
            return [
                metrics.Interval(
                    started_at=moment - timedelta(minutes=2),
                    ended_at=moment - timedelta(minutes=1),
                    counters={"req_tot": 5},
                    restarted=False,
                )
            ]

        patch = mock.patch("haproxy_ui.db.read_backend_series", side_effect=series)
        patch.start()
        self.addCleanup(patch.stop)
        client = self.client(replace(configuration(), demo_fixture=True))
        self.sign_in(client)
        page = client.get("/proxies/edge-demo/public-web")
        self.assertEqual(page.status_code, 200)
        return page.text.count('<div class="traffic-card">'), asked

    def test_before_the_deploy_the_older_name_is_the_card(self) -> None:
        cards, asked = self.cards_with_readings_under("mgd-public-web-web")

        self.assertEqual(cards, 1)
        self.assertIn("web", asked)
        self.assertIn("mgd-public-web-web", asked)

    def test_after_the_deploy_the_pools_own_name_is(self) -> None:
        cards, _asked = self.cards_with_readings_under("web")

        self.assertEqual(cards, 1)


class ADnsObjectsCard(DraftReading):
    """Fas 19a B4: a dns object's pool is drawn with a resolver's figures and its servers.

    The fixture has no dns object, so the stored document is read as one: the
    view asks the engine's reader, and that reader is what decides the kind.
    """

    DOCUMENT = b"""schema: 1
name: public-web
listen: {protocol: dns, port: 53}
backend: resolver
backends:
  resolver:
    balance: roundrobin
    servers: [{host: 192.0.2.53, port: 53}, {host: 192.0.2.54, port: 53}]
    health: {type: dns}
"""

    def page(self) -> str:
        from haproxy_mgmt.proxy_model import load_proxy

        totals: list[Any] = []

        def read_totals(*_a: Any, **k: Any) -> metrics.BackendMeasurement:
            totals.append(k.get("counters"))
            return measurement(counters=k.get("counters", metrics.CARD_COUNTERS))

        for name, answer in (
            (
                "haproxy_ui.views.load_proxy",
                lambda name, _document: load_proxy(name, self.DOCUMENT),
            ),
            ("haproxy_ui.db.read_backend_totals", read_totals),
        ):
            patch = mock.patch(name, side_effect=answer)
            patch.start()
            self.addCleanup(patch.stop)
        client = self.client(replace(configuration(), demo_fixture=True))
        self.sign_in(client)
        page = client.get("/proxies/edge-demo/public-web")
        self.assertEqual(page.status_code, 200)
        self.assertEqual(totals, [metrics.DNS_SUMMED])
        return str(page.text)

    def test_the_figures_are_a_resolver_s(self) -> None:
        text = self.page()
        card = text.split('<div class="traffic-card">', 1)[1]
        figures = [part.split("</dt>")[0] for part in card.split("<dt>")[1:]]
        self.assertEqual(figures, ["Queries", "Answered", "Refused", "Unanswered", "Over TCP"])
