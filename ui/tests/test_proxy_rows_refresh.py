from __future__ import annotations

import re
import unittest
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest import mock
from uuid import uuid4

from haprion_ui import objects
from haprion_ui.db import ClusterInventory, ClusterObjects, ClusterStatus, Job
from haprion_ui.objects import ListedObject
from haprion_ui.views import TEMPLATES
from tests.test_login import LoginTestCase, configuration

OBSERVED = datetime(2026, 9, 3, 9, 0, tzinfo=UTC)

DOCUMENT = """schema: 1
name: {name}
hostnames:
- {name}.example.com
listen:
  protocol: http
routes:
- path: /
  backend: web
backends:
  web:
    servers:
    - host: 192.0.2.10
      port: 8080
"""


def objects_reading(*names: str) -> ClusterObjects:
    return ClusterObjects(
        cluster="alpha",
        observed_at=OBSERVED,
        outcome="done",
        result={
            "commit": "a" * 40,
            "objects": [
                {
                    "name": name,
                    "document": DOCUMENT.format(name=name),
                    "readable": True,
                    "protocol": "http",
                    "hostnames": [f"{name}.example.com"],
                    "runtime_backends": [f"{name}-web"],
                }
                for name in names
            ],
        },
        warnings=[],
        error=None,
        poll_error=None,
    )


def inventory(*served: str) -> ClusterInventory:
    """The published frontends, naming the hostnames the nodes answer for."""

    return ClusterInventory(
        cluster="alpha",
        observed_at=OBSERVED,
        outcome="done",
        result={
            "version": "v9",
            "proxies": [
                {
                    "name": "mgd-main-http",
                    "protocol": "http",
                    "managed": True,
                    "enabled": True,
                    "hostnames": [f"{name}.example.com" for name in served],
                    "ports": [80],
                    "backend_count": len(served),
                }
            ]
            if served
            else [],
        },
        warnings=[],
        error=None,
        poll_error=None,
    )


class TheRowsCatchUpWithoutTheWholePageBeingDrawn(LoginTestCase):
    """A row moves for reasons that happen elsewhere, and it has to move here.

    A row's badge changes when the nodes start serving it, and that moment
    arrives while somebody is looking at the page. Its position does not: the
    list is alphabetical whatever state a row is in, so an edit or a deploy
    never reshuffles it (2026-09-25; it used to put waiting rows first).
    """

    def rows(self, *, served: tuple[str, ...], sort: str = "") -> Any:
        client = self.client(replace(configuration(), clusters=("alpha",)))
        self.sign_in(client)
        with (
            mock.patch(
                "haprion_ui.db.cluster_objects",
                return_value=[objects_reading("zeta", "alpha-site", "middle")],
            ),
            mock.patch("haprion_ui.db.cluster_inventories", return_value=[inventory(*served)]),
        ):
            if sort:
                self.assertEqual(client.get(f"/proxies?sort={sort}").status_code, 200)
            return client.get("/proxies/rows")

    def order(self, markup: str) -> list[str]:
        return [
            part.split("</strong>")[0]
            for part in markup.split('data-label="Proxy"')[1:]
            if "<strong>" in part
            for part in [part.split("<strong>")[1]]
        ]

    def test_nothing_deployed_is_alphabetical(self) -> None:
        answer = self.rows(served=())

        self.assertEqual(answer.status_code, 200)
        self.assertEqual(
            self.order(answer.json()["clusters"]["alpha"]), ["alpha-site", "middle", "zeta"]
        )

    def test_the_refresh_keeps_the_order_the_reader_chose(self) -> None:
        answer = self.rows(served=(), sort="-name")

        self.assertEqual(
            self.order(answer.json()["clusters"]["alpha"]), ["zeta", "middle", "alpha-site"]
        )

    def test_a_row_waiting_for_a_deploy_keeps_its_alphabetical_place(self) -> None:
        #
        # `middle` and `zeta` are waiting and `alpha-site` is served. The old
        # order put the waiting two first; this one must not move anything.
        #
        answer = self.rows(served=("alpha-site",))

        self.assertEqual(
            self.order(answer.json()["clusters"]["alpha"]), ["alpha-site", "middle", "zeta"]
        )

    def test_every_row_carries_the_address_its_name_links_to(self) -> None:
        """The whole row opens the object (proxy-rows.js), so it needs the address."""

        markup = self.rows(served=("alpha-site",)).json()["clusters"]["alpha"]

        for name in ("alpha-site", "middle", "zeta"):
            self.assertIn(f'data-href="/proxies/alpha/{name}"', markup)

    def test_the_counts_come_back_with_the_rows(self) -> None:
        counts = self.rows(served=()).json()["counts"]

        self.assertEqual(counts, {"published": 3, "managed": 3, "unmanaged": 0})

    def test_the_rows_are_not_served_to_somebody_who_is_not_signed_in(self) -> None:
        client = self.client(replace(configuration(), clusters=("alpha",)))

        self.assertEqual(client.get("/proxies/rows").status_code, 401)

    def test_the_listing_no_longer_repeats_the_redirect_on_every_row(self) -> None:
        #
        # A property of the object, answered on its own page. In a list of
        # sites it is a line of noise under a name.
        #
        self.assertNotIn("Redirects HTTP", self.rows(served=()).json()["clusters"]["alpha"])


if __name__ == "__main__":
    unittest.main()


class ARemovalIsStillServedUntilItIsDeployed(LoginTestCase):
    """A removal takes the object out of the repository, not off the nodes.

    Between the two the object is gone from the objects cache while the site is
    still answering, and the listing showed neither - so a page that lists what
    is being served said a site was gone while it was up. A row too many says
    "this is on its way out"; a row too few is the failure that matters.
    """

    def job(self, name: str, *, state: str = "done", document: object = None) -> Job:
        return Job(
            id=9,
            request_id=uuid4(),
            operation="objects_publish",
            cluster="alpha",
            payload={
                "objects": {name: document},
                **({"removed_backends": {name: [f"{name}-web"]}} if document is None else {}),
            },
            state=state,
            created_at=OBSERVED,
            started_at=None,
            finished_at=None,
            exit_code=None,
            outcome="done" if state == "done" else None,
            result=None,
            stderr_excerpt=None,
            idempotency_key=uuid4(),
            attempts=1,
        )

    def status(self, *backends: str) -> ClusterStatus:
        """What the nodes report, which is what decides whether a row stays."""

        return ClusterStatus(
            cluster="alpha",
            observed_at=OBSERVED,
            outcome="done",
            result={
                "nodes": [
                    {
                        "node": "node-a",
                        "status": {
                            "servers": [
                                {"backend": f"{name}-web", "server": "s1", "status": "UP"}
                                for name in backends
                            ]
                        },
                    }
                ]
            },
            warnings=[],
            error=None,
            poll_error=None,
        )

    def listing(self, jobs: list[Job], *backends: str) -> str:
        client = self.client(replace(configuration(), clusters=("alpha",)))
        self.sign_in(client)
        with (
            mock.patch("haprion_ui.db.cluster_objects", return_value=[objects_reading("shop")]),
            mock.patch("haprion_ui.db.cluster_inventories", return_value=[inventory("shop")]),
            mock.patch("haprion_ui.db.recent_jobs", return_value=jobs),
            mock.patch("haprion_ui.db.cluster_statuses", return_value=[self.status(*backends)]),
        ):
            return str(client.get("/proxies").text)

    def test_a_removed_object_stays_listed_while_a_node_still_serves_it(self) -> None:
        body = self.listing([self.job("gone")], "shop", "gone")

        self.assertIn("gone", body)
        self.assertIn("Active · deploy to remove", body)
        #
        # Not the badge the rows above it carry: that one reads as something on
        # its way in, and this is on its way out.
        #
        self.assertNotIn("Removed · waiting for deploy", body)

    def test_it_leaves_the_page_when_the_nodes_stop_reporting_it(self) -> None:
        body = self.listing([self.job("gone")], "shop")

        self.assertNotIn("Active · deploy to remove", body)

    def test_a_removal_the_nodes_never_served_never_appears(self) -> None:
        #
        # An object published and removed without a deploy in between. Asking
        # the jobs alone listed it for as long as the cluster was behind, which
        # on a cluster nobody had deployed was for ever.
        #
        body = self.listing([self.job("never-deployed")], "shop")

        self.assertNotIn("never-deployed", body)

    def test_a_publish_that_carried_a_document_put_it_there_rather_than_took_it_away(self) -> None:
        body = self.listing([self.job("gone", document="schema: 1\n")], "shop", "gone")

        self.assertNotIn("Active · deploy to remove", body)

    def test_an_unfinished_removal_is_not_one_yet(self) -> None:
        body = self.listing([self.job("gone", state="running")], "shop", "gone")

        self.assertNotIn("Active · deploy to remove", body)

    def test_an_object_that_came_back_is_not_reported_as_removed(self) -> None:
        #
        # Removed, then written again before the deploy. It is in the cache, so
        # it is an ordinary row - naming it twice would be a page arguing with
        # itself.
        #
        body = self.listing([self.job("shop")], "shop")

        self.assertNotIn("Active · deploy to remove", body)


class TheTwoDeployBadgesAreAPair(LoginTestCase):
    """First word what is true now, then what the deploy does.

    They are opposite ends of the same wait: one object is not on the nodes and
    a deploy adds it, another's removal is published and a deploy takes it
    away. Both said "waiting for deploy" once, which described the wait and hid
    the direction - and the direction is the whole of what a reader needs.
    """

    def listing(self, *, served: str = "gone-web") -> str:
        """One row of each kind in one page, with `served` naming what the node has."""

        client = self.client(replace(configuration(), clusters=("alpha",)))
        self.sign_in(client)
        removal = Job(
            id=9,
            request_id=uuid4(),
            operation="objects_publish",
            cluster="alpha",
            payload={"objects": {"gone": None}, "removed_backends": {"gone": ["gone-web"]}},
            state="done",
            created_at=OBSERVED,
            started_at=None,
            finished_at=None,
            exit_code=None,
            outcome="done",
            result=None,
            stderr_excerpt=None,
            idempotency_key=uuid4(),
            attempts=1,
        )
        #
        # The node still has the removed object and does not have the new one:
        # one row each way, in one listing.
        #
        behind = ClusterStatus(
            cluster="alpha",
            observed_at=OBSERVED,
            outcome="done",
            result={
                "nodes": [
                    {
                        "node": "node-a",
                        "status": {
                            "servers": [{"backend": served, "server": "s1", "status": "UP"}]
                        },
                    }
                ]
            },
            warnings=[],
            error=None,
            poll_error=None,
        )
        with (
            mock.patch("haprion_ui.db.cluster_objects", return_value=[objects_reading("shop")]),
            #
            # Nothing served, so `shop` is written and not on the nodes.
            #
            mock.patch("haprion_ui.db.cluster_inventories", return_value=[inventory()]),
            mock.patch("haprion_ui.db.recent_jobs", return_value=[removal]),
            mock.patch("haprion_ui.db.cluster_statuses", return_value=[behind]),
        ):
            return str(client.get("/proxies").text)

    def test_the_two_rows_say_opposite_things(self) -> None:
        body = self.listing()

        self.assertIn("Inactive · deploy to add", body)
        self.assertIn("Active · deploy to remove", body)
        self.assertNotIn("Waiting for deploy", body)

    def test_neither_end_of_the_wait_claims_a_protocol(self) -> None:
        """The column says what the nodes serve, not what a document intends.

        Nothing can name the protocol of an object being removed - the
        repository no longer has it - so a row waiting to be added that showed
        one made the two ends of the same wait look like two different kinds of
        thing. The pending object's protocol is on its own page.
        """

        body = self.listing()

        self.assertIn("Inactive · deploy to add", body)
        self.assertNotIn("protocol-badge", body)

    def test_an_object_the_nodes_serve_does_say_which_protocol(self) -> None:
        """The column is not merely blanked; it fills in when there is an answer."""

        body = self.listing(served="shop-web")

        self.assertNotIn("Inactive · deploy to add", body)
        self.assertIn("protocol-badge", body)


class AServingObjectSaysWhenTheNodesAreBehind(unittest.TestCase):
    """The third way to say that publishing does not deploy.

    The other two are for an object on its way in or out. This one is for a
    site that is up and serving a configuration the nodes were never given -
    which said nothing at all until now, because it is neither being added nor
    removed.
    """

    SERVING = ListedObject(
        name="shop",
        protocol="https",
        hostnames=("shop.example.com",),
        ports=(443,),
        backend_count=1,
        redirect_http=False,
        readable=True,
        problem=None,
        serving=True,
    )

    def rendered(self, reconfigured: tuple[str, ...] = ()) -> str:
        module: Any = TEMPLATES.env.get_template("_proxy-rows.html").module
        macro = module.proxy_rows
        return str(macro("alpha", "admin", (), (), (self.SERVING,), (), {}, (), {}, reconfigured))

    def test_the_badge_takes_the_protocol_cell_and_leaves_the_hostnames(self) -> None:
        """What the row serves is why somebody opened the listing.

        The badge sat in hosts / ports first and replaced them. It was the
        wrong trade: the protocol is one word that is also on the object's own
        page, while the hostnames are the thing being looked up.
        """

        body = self.rendered(("shop",))

        self.assertIn("Reconfigured · deploy to activate", body)
        self.assertIn("shop.example.com", body)
        self.assertNotIn("protocol-badge", body)

    def test_an_object_nobody_republished_is_left_alone(self) -> None:
        """The mistake worth a test: the fact is per object, not per cluster.

        Worn cluster-wide it appeared on every row, so untouched sites looked
        like work somebody had forgotten. Tried a second time on 2026-09-06 as
        a badge for "could not be compared", with the same result on every row
        of the cluster, and reverted the same afternoon.
        """

        self.assertNotIn("Reconfigured", self.rendered(("something-else",)))

    def test_nothing_awaiting_a_deploy_says_nothing(self) -> None:
        self.assertNotIn("Reconfigured", self.rendered())


class WhichObjectsAPendingDeployCarries(unittest.TestCase):
    """The releases answer; the jobs fill in only what the releases cannot.

    Two manifests compared say which object changed, whoever changed it and
    however long ago. They say nothing at all when the nodes run a release
    built before manifests existed - and that silence must not become a badge
    on every row, which is what the cluster-wide claim looked like.
    """

    def job(
        self,
        operation: str,
        *names: str,
        state: str = "done",
        deploy: bool = False,
        result: dict[str, Any] | None = None,
    ) -> Job:
        return Job(
            id=1,
            request_id=uuid4(),
            operation=operation,
            cluster="alpha",
            payload={
                "objects": {name: "document" for name in names},
                **({"deploy": True} if deploy else {}),
            },
            state=state,
            created_at=OBSERVED,
            started_at=None,
            finished_at=None,
            exit_code=None,
            outcome="done",
            result=result,
            stderr_excerpt=None,
            idempotency_key=uuid4(),
            attempts=1,
        )

    def test_the_releases_decide_when_they_can(self) -> None:
        states = {"shop": "changed", "intranet": "current"}
        jobs = [self.job("objects_publish", "intranet")]

        self.assertEqual(objects.awaiting_deploy(states, jobs), frozenset({"shop"}))

    def test_an_object_absent_from_the_running_release_counts_too(self) -> None:
        self.assertEqual(objects.awaiting_deploy({"shop": "absent"}, []), frozenset({"shop"}))

    def test_the_jobs_are_asked_only_where_nothing_could_be_compared(self) -> None:
        """The case the whole fallback exists for: no manifest on the nodes."""

        states = {"shop": "unknown", "intranet": "unknown", "wiki": "unknown"}
        jobs = [self.job("objects_publish", "shop")]

        self.assertEqual(objects.awaiting_deploy(states, jobs), frozenset({"shop"}))

    def test_nothing_known_and_no_job_leaves_every_row_alone(self) -> None:
        states = {"shop": "unknown", "intranet": "unknown"}

        self.assertEqual(objects.awaiting_deploy(states, []), frozenset())

    def test_a_job_older_than_the_last_deploy_is_not_carried(self) -> None:
        jobs = [self.job("deploy"), self.job("objects_publish", "shop")]

        self.assertEqual(objects.awaiting_deploy({"shop": "unknown"}, jobs), frozenset())

    def test_the_jobs_never_overrule_a_release_that_answered(self) -> None:
        """Absence from a bounded window is not a claim that anything is in step."""

        jobs = [self.job("objects_publish", "shop")]

        self.assertEqual(objects.awaiting_deploy({"shop": "current"}, jobs), frozenset())

    #
    # *Publish & deploy* (B257): one job that publishes and then deploys, and
    # ends as the deploy ended.
    #

    def test_publish_and_deploy_that_finished_carried_nothing_further(self) -> None:
        jobs = [
            self.job("changes_publish", "shop", deploy=True),
            self.job("changes_publish", "wiki"),
        ]

        self.assertEqual(objects.awaiting_deploy({"wiki": "unknown"}, jobs), frozenset())

    def test_a_deploy_that_failed_after_its_publish_still_carries_the_objects(self) -> None:
        jobs = [
            self.job(
                "changes_publish",
                "shop",
                state="failed",
                deploy=True,
                result={"outcome": "failed", "publish": {"outcome": "done"}},
            )
        ]

        self.assertEqual(objects.awaiting_deploy({"shop": "unknown"}, jobs), frozenset({"shop"}))
        self.assertEqual(objects.publish_failures(jobs), {})

    def test_a_publish_that_failed_before_its_deploy_is_a_publish_failure(self) -> None:
        jobs = [
            self.job(
                "changes_publish",
                "shop",
                state="failed",
                deploy=True,
                result={"outcome": "failed", "error": {"code": "changes_invalid"}},
            )
        ]

        self.assertEqual(objects.awaiting_deploy({"shop": "unknown"}, jobs), frozenset())
        self.assertEqual(objects.publish_failures(jobs), {"shop": "changes_invalid"})


class TheRowStateBadgesFitTheColumnTheySitIn(unittest.TestCase):
    """The badges share one cell, so the longest of them sets its width.

    A pixel width cannot be measured here - the page is drawn by a browser in
    a font this repository ships as a binary - so what is held instead is the
    vocabulary: every badge in the listing is a literal in one template, and
    a new one longer than the ones the column was sized for has to be a
    deliberate act rather than a surprise on somebody's screen.

    The budget is characters, and it is honest about being an approximation.
    It was set from the longest badge in use plus headroom, and the column it
    guards is `.proxy-table` column two, at a width measured from the longest
    badge (225 px in the rig, 2026-10-01). Widen one and
    the other has to follow; that is the whole reason this test names both.
    """

    BUDGET = 36
    COLUMN_SHARE = "256px"

    def badges(self) -> list[str]:
        markup = (
            Path(__file__).resolve().parents[1] / "src/haprion_ui/templates/_proxy-rows.html"
        ).read_text()
        #
        # The spinner is a span inside a span, and a non-greedy match would end
        # the badge at its closing tag - so "Waiting for publish" was silently
        # not measured by the first version of this. Removed before matching,
        # so the badge is one element again.
        #
        markup = re.sub(r'<span class="badge-spinner"[^>]*></span>', "", markup)
        found = re.findall(r'class="status-badge[^"]*"[^>]*>(.*?)</(?:span|a)>', markup)
        texts: list[str] = []
        for block in found:
            #
            # A badge may be written as a choice - "Draft: removal" or "Draft"
            # - so the branches are separated and measured one at a time. The
            # cell shows one of them, never their concatenation.
            #
            for part in re.split(r"{%.*?%}", re.sub(r"<[^>]+>", "", block)):
                #
                # A badge carrying a value has no length this repository
                # decides; the refusal badge takes an exit code from a helper.
                # That one is guarded by clipping at its own cell instead.
                #
                if "{{" not in part and part.strip():
                    texts.append(part.strip())
        return texts

    def test_every_badge_is_short_enough_for_its_column(self) -> None:
        found = self.badges()

        self.assertTrue(found, "no badge literals were found to check")
        for text in found:
            with self.subTest(badge=text):
                self.assertLessEqual(len(text), self.BUDGET)

    def test_the_longest_badge_is_the_one_the_column_was_sized_for(self) -> None:
        """So that widening a badge cannot quietly outgrow the column."""

        css = (Path(__file__).resolve().parents[1] / "src/haprion_ui/static/app.css").read_text()

        self.assertIn(
            f".proxy-table th:nth-child(2), .proxy-table td:nth-child(2) "
            f"{{ width: {self.COLUMN_SHARE}; }}",
            css,
        )
