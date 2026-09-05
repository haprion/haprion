"""The editor: who may reach it, what it opens with, and what it refuses to write.

The document machinery is tested next door, in `test_object_form`. What is
worth testing here are the boundaries the route owns - the role, the write
switch, the revision two tabs disagree about, and the two shapes of refusal
that must not become a saved draft.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any
from unittest import mock
from uuid import uuid4

from haproxy_ui import auth, health
from haproxy_ui import probe as probe_module
from haproxy_ui.db import ClusterNetwork, ClusterObjects, DraftConflict, Job, ProxyDraft
from tests.test_login import LoginTestCase, configuration

OBSERVED = datetime(2026, 9, 2, 9, 0, tzinfo=UTC)
COMMIT = "a" * 40

SHOP = """schema: 1
name: shop
hostnames:
- shop.example.com
listen:
  protocol: http
routes:
- path: /
  backend: web
backends:
  web:
    balance: roundrobin
    health:
      type: disabled
    servers:
    - host: 192.0.2.10
      port: 8080
"""

OBJECTS = ClusterObjects(
    cluster="alpha",
    observed_at=OBSERVED,
    outcome="done",
    result={
        "commit": COMMIT,
        "objects": [
            {
                "name": "shop",
                "document": SHOP,
                "readable": True,
                "protocol": "http",
                "hostnames": ["shop.example.com"],
            }
        ],
    },
    warnings=[],
    error=None,
    poll_error=None,
)

NETWORK = ClusterNetwork(
    cluster="alpha",
    observed_at=OBSERVED,
    outcome="done",
    result={
        "editable": True,
        "head": COMMIT,
        "default_vip": "main",
        "vips": [{"name": "main", "address": "192.0.2.20", "source": "192.0.2.25"}],
        "sources": [],
        "groups": [{"name": "office", "members": ["198.51.100.0/24"]}],
    },
    warnings=[],
    error=None,
    poll_error=None,
)


def writing_configuration() -> Any:
    return replace(configuration(), management_writes=True, clusters=("alpha",))


class EditorTestCase(LoginTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.saved: list[dict[str, Any]] = []
        self.renamed: list[dict[str, Any]] = []
        self.discarded: list[tuple[str, str, int]] = []
        self.draft: ProxyDraft | None = None
        self.conflict = False
        for target, side_effect in (
            ("cluster_objects", lambda _c: [OBJECTS]),
            ("cluster_networks", lambda _c: [NETWORK]),
            ("read_draft", self._read_draft),
            ("save_draft", self._save_draft),
            ("rename_draft", self._rename_draft),
            ("discard_draft", self._discard_draft),
        ):
            patch = mock.patch(f"haproxy_ui.db.{target}", side_effect=side_effect)
            patch.start()
            self.addCleanup(patch.stop)

    def _read_draft(self, _c: object, cluster: str, object_id: str) -> ProxyDraft | None:
        #
        # Keyed by the object asked for, as the table is. It used to answer
        # with the one draft whatever was asked, which was harmless until
        # something looked up a *different* name to see whether it was free -
        # a fixture that answers yes to every question cannot measure that.
        #
        del cluster
        if self.draft is not None and self.draft.object_id == object_id:
            return self.draft
        return None

    def _save_draft(self, _c: object, **values: Any) -> ProxyDraft:
        if self.conflict:
            raise DraftConflict("the draft for shop changed since it was read")
        self.saved.append(values)
        return ProxyDraft(
            cluster=values["cluster"],
            object_id=values["object_id"],
            yaml=values["yaml"],
            base_version=values["base_version"],
            base_hash=values["base_hash"],
            revision=(values["expected_revision"] or 0) + 1,
            updated_by=values["updated_by"],
            updated_at=OBSERVED,
            deleted=False,
        )

    def _rename_draft(self, _c: object, **values: Any) -> ProxyDraft:
        if self.conflict:
            raise DraftConflict("the draft for shop changed since it was read")
        self.renamed.append(values)
        return ProxyDraft(
            cluster=values["cluster"],
            object_id=values["new_object_id"],
            yaml=values["yaml"],
            base_version=values["base_version"],
            base_hash=values["base_hash"],
            revision=values["expected_revision"] + 1,
            updated_by=values["updated_by"],
            updated_at=OBSERVED,
            deleted=False,
        )

    def _discard_draft(
        self, _c: object, *, cluster: str, object_id: str, expected_revision: int
    ) -> None:
        self.discarded.append((cluster, object_id, expected_revision))

    def editor(self) -> Any:
        client = self.client(writing_configuration())
        self.sign_in(client)
        return client

    def token(self, client: Any) -> str:
        return auth.csrf_token(client.cookies[auth.SESSION_COOKIE])

    def submit(self, client: Any, path: str, **fields: Any) -> Any:
        data = {
            "name": "shop",
            "protocol": "http",
            "hostnames": "shop.example.com",
            "balance": "roundrobin",
            "health_type": "disabled",
            "servers": "192.0.2.10:8080",
            "redirect_status": "301",
            auth.CSRF_FIELD: self.token(client),
        }
        data.update(fields)
        return client.post(path, data=data, follow_redirects=False)


class ReachingTheEditor(EditorTestCase):
    def test_an_object_opens_with_its_own_values(self) -> None:
        page = self.editor().get("/proxies/alpha/shop/edit")

        self.assertEqual(page.status_code, 200)
        self.assertIn('value="shop"', page.text)
        self.assertIn("192.0.2.10:8080", page.text)

    def test_a_published_name_is_editable(self) -> None:
        """A rename is a publish that adds one name and removes the other."""

        page = self.editor().get("/proxies/alpha/shop/edit")

        self.assertNotIn("readonly", page.text)

    def test_a_new_object_opens_on_a_blank_name(self) -> None:
        page = self.editor().get("/proxies/alpha/new")

        self.assertEqual(page.status_code, 200)

    def test_a_reader_is_refused(self) -> None:
        self.account = replace(self.account, role="reader")
        client = self.client(writing_configuration())
        self.sign_in(client)

        self.assertEqual(client.get("/proxies/alpha/shop/edit").status_code, 403)

    def test_the_editor_does_not_exist_without_management_writes(self) -> None:
        """404 and not 403, as `/operations` answers.

        Turning writes off is the documented rollback for the whole write path.
        A route that answered "forbidden" would announce an editor waiting to
        be switched on.
        """

        client = self.client(replace(configuration(), clusters=("alpha",)))
        self.sign_in(client)

        self.assertEqual(client.get("/proxies/alpha/shop/edit").status_code, 404)

    def test_an_unknown_cluster_is_not_a_page(self) -> None:
        self.assertEqual(self.editor().get("/proxies/beta/shop/edit").status_code, 404)


class SavingADraft(EditorTestCase):
    def test_a_saved_draft_records_the_commit_it_was_made_against(self) -> None:
        client = self.editor()

        answer = self.submit(client, "/proxies/alpha/shop/edit", action="save")

        self.assertEqual(answer.status_code, 303)
        self.assertEqual(self.saved[0]["base_hash"], COMMIT)
        self.assertEqual(self.saved[0]["object_id"], "shop")
        self.assertIn("name: shop", self.saved[0]["yaml"])

    def test_checking_writes_nothing(self) -> None:
        client = self.editor()

        answer = self.submit(client, "/proxies/alpha/shop/edit", action="check")

        self.assertEqual(answer.status_code, 200)
        self.assertEqual(self.saved, [])

    def test_a_document_that_is_not_an_object_is_not_saved(self) -> None:
        """The refusal is about the object, so there is nothing to keep yet."""

        client = self.editor()

        answer = self.submit(client, "/proxies/alpha/shop/edit", action="save", servers="")

        self.assertEqual(answer.status_code, 200)
        self.assertEqual(self.saved, [])

    def test_an_object_that_clashes_with_a_neighbour_is_still_saved(self) -> None:
        """A publish answers that. Refusing to save would stop the work that resolves it."""

        client = self.editor()

        answer = self.submit(
            client,
            "/proxies/alpha/new",
            action="save",
            name="other",
            hostnames="shop.example.com",
        )

        self.assertEqual(answer.status_code, 303)
        self.assertEqual(self.saved[0]["object_id"], "other")

    def test_the_new_object_form_ignores_a_revision_it_was_handed(self) -> None:
        """A new object has no draft to be a revision of.

        `expected_revision` is a hidden input, and a browser restores hidden
        inputs when somebody navigates back into a form - so the revision of
        the object saved a moment ago reached the new-object form, and the save
        became an update of a row that had never existed. It answered "the
        draft changed since it was read", about a draft nobody had made.
        """

        client = self.editor()

        answer = self.submit(
            client, "/proxies/alpha/new", action="save", name="console", expected_revision="1"
        )

        self.assertEqual(answer.status_code, 303)
        self.assertIsNone(self.saved[0]["expected_revision"])

    def test_the_match_choice_is_dimmed_rather_than_disabled(self) -> None:
        """A disabled select is not submitted, and this one's default decides.

        Left disabled, a form where somebody filled in a redirect but the
        script had not run would post no match mode at all and fall back to
        `prefix` - the one answer that makes a redirect on the site root
        collide with the pool. The cue must not change what gets saved.
        """

        page = self.editor().get("/proxies/alpha/new").text

        self.assertNotIn("disabled", page.split('name="redirect_match"')[1].split(">")[0])

    def test_a_drafted_object_posts_to_its_own_address(self) -> None:
        """The form action was chosen by the stored document, not the address.

        An object that has only ever been drafted has no stored document, so
        every submission from its editor went to the new-object route - where
        the name comes out of the form and each save looks like a first one. A
        rename made a second draft beside the first instead of moving it, and a
        discard asked a route that knew of no draft to throw one away.
        """

        page = self.editor().get("/proxies/alpha/nodraftyet/edit").text

        self.assertIn('action="/proxies/alpha/nodraftyet/edit"', page)

    def test_a_published_object_may_be_renamed(self) -> None:
        """The draft moves to the new name; removing the old one is the publish's job.

        Nothing was ever drafted under the old name here, so there is no row to
        move - the work is saved under the new name, and the stored object
        stays until a publish removes it.
        """

        client = self.editor()

        answer = self.submit(client, "/proxies/alpha/shop/edit", action="save", name="bazaar")

        self.assertEqual(answer.status_code, 303)
        self.assertEqual(answer.headers["location"], "/proxies/alpha/bazaar/edit?saved=1")
        self.assertEqual(self.saved[0]["object_id"], "bazaar")

    def test_an_unpublished_draft_may_be_renamed(self) -> None:
        """A draft where one field cannot be changed is not a draft.

        Nothing outside `proxy_draft` knows this name yet - it is not an
        address anybody has, not a document on a node, not a line in a
        published release - so the name is still being chosen like every other
        answer on the form.

        The write is one transaction: the new row first, then the old one, and
        the old revision is enforced on the delete because that is the row the
        person was actually reading.
        """

        self.draft = ProxyDraft(
            cluster="alpha",
            object_id="console",
            yaml=SHOP.replace("shop", "console"),
            base_version=12,
            base_hash=COMMIT,
            revision=3,
            updated_by="operator",
            updated_at=OBSERVED,
            deleted=False,
        )
        client = self.editor()

        answer = self.submit(
            client,
            "/proxies/alpha/console/edit",
            action="save",
            name="terminal",
            expected_revision="3",
        )

        self.assertEqual(answer.status_code, 303)
        self.assertEqual(answer.headers["location"], "/proxies/alpha/terminal/edit?saved=1")
        self.assertEqual(self.saved, [])
        self.assertEqual(self.discarded, [])
        self.assertEqual(self.renamed[0]["object_id"], "console")
        self.assertEqual(self.renamed[0]["new_object_id"], "terminal")
        self.assertEqual(self.renamed[0]["expected_revision"], 3)

    def test_renaming_a_published_object_that_already_has_a_draft_moves_the_row(self) -> None:
        """Two things at once: the draft key moves, and the old object is still there.

        The row move and the removal answer different questions - one is where
        the unfinished work lives, the other is what the cluster serves - and
        confusing them would either strand the draft under the old name or
        remove an object nobody had replaced yet.
        """

        self.draft = ProxyDraft(
            cluster="alpha",
            object_id="shop",
            yaml=SHOP,
            base_version=12,
            base_hash=COMMIT,
            revision=4,
            updated_by="operator",
            updated_at=OBSERVED,
            deleted=False,
        )
        client = self.editor()

        answer = self.submit(
            client,
            "/proxies/alpha/shop/edit",
            action="save",
            name="bazaar",
            expected_revision="4",
        )

        self.assertEqual(answer.status_code, 303)
        self.assertEqual(self.renamed[0]["object_id"], "shop")
        self.assertEqual(self.renamed[0]["new_object_id"], "bazaar")
        self.assertEqual(self.renamed[0]["expected_revision"], 4)

    def test_a_draft_may_not_be_renamed_onto_a_published_object(self) -> None:
        self.draft = ProxyDraft(
            cluster="alpha",
            object_id="console",
            yaml=SHOP.replace("shop", "console"),
            base_version=12,
            base_hash=COMMIT,
            revision=3,
            updated_by="operator",
            updated_at=OBSERVED,
            deleted=False,
        )
        client = self.editor()

        answer = self.submit(
            client,
            "/proxies/alpha/console/edit",
            action="save",
            name="shop",
            expected_revision="3",
        )

        self.assertEqual(answer.status_code, 400)
        self.assertEqual(self.saved, [])
        self.assertEqual(self.renamed, [])
        self.assertEqual(self.discarded, [])

    def test_a_draft_may_not_be_renamed_onto_another_draft(self) -> None:
        """A draft is not on the listing, so nothing else would show the clash.

        Without this the rename would land on somebody else's unfinished work
        and take its revision with it.
        """

        self.draft = ProxyDraft(
            cluster="alpha",
            object_id="terminal",
            yaml=SHOP.replace("shop", "terminal"),
            base_version=12,
            base_hash=COMMIT,
            revision=1,
            updated_by="someone-else",
            updated_at=OBSERVED,
            deleted=False,
        )
        client = self.editor()

        answer = self.submit(
            client,
            "/proxies/alpha/console/edit",
            action="save",
            name="terminal",
            expected_revision="3",
        )

        self.assertEqual(answer.status_code, 400)
        self.assertEqual(self.saved, [])
        self.assertEqual(self.renamed, [])
        self.assertEqual(self.discarded, [])

    def test_a_name_the_engine_could_not_use_is_refused_here(self) -> None:
        """Refused where it was typed, rather than by a job an hour later.

        It is also what lets every link these pages build treat the name as a
        name: the value reaching a `Location` header has passed the engine's own
        rule, so it cannot carry a slash, a dot or anything else that would make
        the address mean something other than this object.
        """

        client = self.editor()

        answer = self.submit(client, "/proxies/alpha/new", action="save", name="Shop.One")

        self.assertEqual(answer.status_code, 400)
        self.assertEqual(self.saved, [])
        self.assertIn("capital letters are not allowed", answer.text)

    def test_a_new_object_may_not_take_a_name_that_exists(self) -> None:
        client = self.editor()

        answer = self.submit(client, "/proxies/alpha/new", action="save", name="shop")

        self.assertEqual(answer.status_code, 400)
        self.assertEqual(self.saved, [])

    def test_a_revision_somebody_else_moved_is_refused(self) -> None:
        self.conflict = True
        client = self.editor()

        answer = self.submit(
            client, "/proxies/alpha/shop/edit", action="save", expected_revision="1"
        )

        self.assertEqual(answer.status_code, 400)
        self.assertEqual(self.pool.rollbacks, 1)

    def test_a_post_without_a_csrf_token_is_refused(self) -> None:
        client = self.editor()

        answer = client.post(
            "/proxies/alpha/shop/edit", data={"name": "shop"}, follow_redirects=False
        )

        self.assertEqual(answer.status_code, 403)
        self.assertEqual(self.saved, [])


class WorkingFromADraft(EditorTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.draft = ProxyDraft(
            cluster="alpha",
            object_id="shop",
            yaml=SHOP.replace("192.0.2.10", "192.0.2.11"),
            base_version=12,
            base_hash=COMMIT,
            revision=3,
            updated_by="operator",
            updated_at=OBSERVED,
            deleted=False,
        )

    def test_the_draft_is_what_the_form_opens_with(self) -> None:
        page = self.editor().get("/proxies/alpha/shop/edit")

        self.assertIn("192.0.2.11:8080", page.text)
        self.assertNotIn("192.0.2.10:8080", page.text)

    def test_the_page_says_a_draft_is_unpublished(self) -> None:
        page = self.editor().get("/proxies/alpha/shop/edit")

        self.assertIn("unpublished draft", page.text)

    def test_a_discard_names_the_revision_it_was_looking_at(self) -> None:
        client = self.editor()

        answer = self.submit(
            client, "/proxies/alpha/shop/edit", action="discard", expected_revision="3"
        )

        self.assertEqual(answer.status_code, 303)
        self.assertEqual(self.discarded, [("alpha", "shop", 3)])


class TheShapeDecidesWhichFieldsApply(EditorTestCase):
    """The tcp port is greyed out where it means nothing.

    Rendered by the server as well as maintained by the script, because a page
    that arrived correct and then changed under a reader would be the worse of
    the two behaviours.
    """

    def test_the_tcp_port_is_disabled_for_an_http_object(self) -> None:
        page = self.editor().get("/proxies/alpha/shop/edit")

        self.assertRegex(page.text, r'name="tcp_port"[^>]*disabled')

    def test_the_tcp_port_is_usable_for_a_tcp_object(self) -> None:
        client = self.editor()

        page = self.submit(
            client, "/proxies/alpha/shop/edit", action="check", protocol="tcp", tcp_port="5432"
        )

        self.assertNotRegex(page.text, r'name="tcp_port"[^>]*disabled')


class TheHealthCardOnThePage(EditorTestCase):
    """What the probe's answer looks like once it is rendered.

    The filtering is in the template, so asserting on the report alone proves
    nothing about the page. These render it.
    """

    def probe(self, nodes: list[probe_module.NodeReport], source: str = "192.0.2.25") -> str:
        report = probe_module.ProbeReport(ran=True, source=source, nodes=tuple(nodes))
        with (
            mock.patch("haproxy_ui.probe.run", return_value=report),
            mock.patch("haproxy_ui.db.wake_poller"),
        ):
            client = self.editor()
            response = self.submit(client, "/proxies/alpha/shop/edit", action="recheck")
        self.assertEqual(response.status_code, 200)
        return response.text

    def node(self, name: str, *, held: bool | None, ok: bool = True) -> probe_module.NodeReport:
        return probe_module.NodeReport(
            node=name,
            reachable=True,
            error=None,
            source_held=held,
            results=(
                probe_module.Reached(
                    host="198.51.100.10", port=8080, ok=ok, status=200, error=None, ms=2
                ),
            )
            if held is not False
            else (),
        )

    def test_a_node_without_the_address_is_not_on_the_page_at_all(self) -> None:
        body = self.probe([self.node("node-a", held=True), self.node("node-b", held=False)])
        self.assertIn("node-a", body)
        self.assertNotIn("node-b", body)

    def test_the_heading_says_which_node_holds_the_address(self) -> None:
        body = self.probe([self.node("node-a", held=True), self.node("node-b", held=False)])
        self.assertIn("from 192.0.2.25, held by node-a", body)

    def test_without_a_source_every_node_is_still_listed(self) -> None:
        body = self.probe(
            [self.node("node-a", held=None), self.node("node-b", held=None)], source=""
        )
        self.assertIn("node-a", body)
        self.assertIn("node-b", body)


class WhereASaveLands(EditorTestCase):
    """Saving finishes a round of work, so it leaves the form.

    Back to the editor, because the work is not finished: saving a draft is
    something people do part-way through, and it is the page that can say so -
    the listing reads no such flag, so the receipt written for this was never
    shown to anybody. See `SavingSaysSo`.

    Validating deliberately stays too: its whole answer - the refusal, or the
    configuration this would generate - is on the page, and navigating away
    would throw away what was just asked for.
    """

    def test_discarding_the_only_draft_of_a_new_object_goes_to_the_listing(self) -> None:
        """Its page stops existing the moment the draft does.

        A name that is neither stored, served nor drafted is a 404 by design.
        After discarding the only draft of an object that was never published,
        that is what the name has become - so the object's page answered "Not
        Found" as the last step of an ordinary act.
        """

        self.draft = ProxyDraft(
            cluster="alpha",
            object_id="console",
            yaml="",
            base_version=1,
            base_hash="abc",
            revision=2,
            updated_by="operator",
            updated_at=OBSERVED,
            deleted=False,
        )
        client = self.editor()

        answer = self.submit(
            client, "/proxies/alpha/console/edit", action="discard", expected_revision="2"
        )

        self.assertEqual(answer.status_code, 303)
        self.assertEqual(answer.headers["location"], "/proxies?discarded=console")
        self.assertEqual(self.discarded, [("alpha", "console", 2)])

    def test_a_discard_goes_to_the_object_and_says_so(self) -> None:
        self.draft = ProxyDraft(
            cluster="alpha",
            object_id="shop",
            yaml="",
            base_version=1,
            base_hash="abc",
            revision=2,
            updated_by="operator",
            updated_at=OBSERVED,
            deleted=False,
        )
        client = self.editor()
        answer = self.submit(
            client, "/proxies/alpha/shop/edit", action="discard", expected_revision="2"
        )

        self.assertEqual(answer.status_code, 303)
        self.assertEqual(answer.headers["location"], "/proxies/alpha/shop?discarded=1")

    def test_validating_stays_on_the_form(self) -> None:
        client = self.editor()
        answer = self.submit(client, "/proxies/alpha/shop/edit", action="check")

        self.assertEqual(answer.status_code, 200)


class SaveAndPublish(EditorTestCase):
    """One button, two acts, and the second one is a job.

    They are one button because saving and then publishing separately was three
    screens for one change. They stay two acts underneath, and the order matters:
    a publish that is refused has to leave the work saved rather than lost.
    """

    def setUp(self) -> None:
        super().setUp()
        self.queued: list[dict[str, Any]] = []
        patch = mock.patch("haproxy_ui.db.queue_job", side_effect=self._queue)
        patch.start()
        self.addCleanup(patch.stop)

    def _queue(self, _c: object, **values: Any) -> Any:
        self.queued.append(values)
        return SimpleNamespace(id=1, request_id=uuid4())

    def publish(self) -> Any:
        client = self.editor()
        return self.submit(client, "/proxies/alpha/shop/edit", action="publish")

    def test_it_saves_the_draft_and_queues_the_publish(self) -> None:
        answer = self.publish()

        self.assertEqual(answer.status_code, 303)
        self.assertEqual(answer.headers["location"], "/proxies?published=shop")
        self.assertEqual(len(self.saved), 1)
        self.assertEqual(len(self.queued), 1)
        self.assertEqual(self.queued[0]["operation"], "objects_publish")
        self.assertEqual(self.queued[0]["cluster"], "alpha")

    def test_the_object_is_published_under_its_own_name(self) -> None:
        self.publish()
        payload = self.queued[0]["payload"]

        self.assertEqual(list(payload["objects"]), ["shop"])
        self.assertIn("name: shop", payload["objects"]["shop"])
        self.assertTrue(payload["comment"])

    def test_a_rename_publishes_the_new_name_and_the_removal_together(self) -> None:
        """Sent apart, the first half is a cluster with two objects on one hostname.

        `_refuse_shared_hostnames` would refuse that, and removing the old one
        first would take the site down until the new one was published. One
        publish means `haproxy -c` validates the state afterwards and never the
        moment in between.
        """

        client = self.editor()
        self.submit(client, "/proxies/alpha/shop/edit", action="publish", name="bazaar")
        payload = self.queued[0]["payload"]

        self.assertEqual(sorted(payload["objects"]), ["bazaar", "shop"])
        self.assertIsNone(payload["objects"]["shop"])
        self.assertIn("name: bazaar", payload["objects"]["bazaar"])
        self.assertEqual(payload["comment"], "Rename shop to bazaar")

    def test_the_same_publish_asked_for_twice_carries_one_key(self) -> None:
        """A double-click is the same request, not a second publish."""

        first = self.publish()
        keys = {self.queued[0]["idempotency_key"]}
        self.publish()
        keys.add(self.queued[1]["idempotency_key"])

        self.assertEqual(first.status_code, 303)
        self.assertEqual(len(keys), 1)

    def test_publishing_a_change_and_changing_it_back_asks_twice(self) -> None:
        """The key was the draft revision, and a cleared draft starts at 1 again.

        So publishing an object, changing it, and changing it back asked twice
        under one key with two different documents. The queue refused the third
        - correctly - and told somebody their publish had already been asked for
        with different content, while they looked at a form that said otherwise.
        """

        client = self.editor()
        self.submit(client, "/proxies/alpha/shop/edit", action="publish")
        self.submit(
            client, "/proxies/alpha/shop/edit", action="publish", hostnames="other.example.com"
        )
        self.submit(client, "/proxies/alpha/shop/edit", action="publish")

        keys = [entry["idempotency_key"] for entry in self.queued]
        self.assertEqual(len(keys), 3)
        #
        # The first and the third are the same document and so the same
        # request; the middle one is a different document and its own.
        #
        self.assertEqual(keys[0], keys[2])
        self.assertNotEqual(keys[0], keys[1])

    def test_an_object_the_model_refuses_is_never_published(self) -> None:
        client = self.editor()
        answer = self.submit(client, "/proxies/alpha/shop/edit", action="publish", servers="")

        self.assertEqual(answer.status_code, 200)
        self.assertEqual(self.queued, [])
        self.assertEqual(self.saved, [])


class WhichNodeReportsOnThePool(EditorTestCase):
    """The passive card follows the same rule the probe does.

    An object that leaves from a source address can only be checked from the
    node carrying it. The other runs the same check, binds an address it does
    not have, and reports the pool down - HAProxy telling the truth about the
    binding and a lie about the pool.
    """

    def node(self, name: str, *, owner: bool | None, up: bool) -> dict[str, Any]:
        return {
            "name": name,
            "status": {
                "vip": {"owner": owner},
                "pool_members": [
                    {
                        "backend": "mgd-shop-web",
                        "server": "s1",
                        "status": "UP" if up else "DOWN",
                        "up": up,
                    }
                ],
            },
        }

    def card(self, nodes: list[dict[str, Any]], source: str):
        row = SimpleNamespace(cluster="alpha", result={"nodes": nodes}, observed_at=OBSERVED)
        return health.pool_health([row], cluster="alpha", obj="shop", pool="web", source=source)

    def test_a_node_without_the_address_is_left_off(self) -> None:
        card = self.card(
            [self.node("node-a", owner=True, up=True), self.node("node-b", owner=False, up=False)],
            source="192.0.2.25",
        )

        self.assertEqual([node.node for node in card.nodes], ["node-a"])
        self.assertEqual(card.held_by, ("node-a",))

    def test_without_a_source_every_node_still_answers(self) -> None:
        card = self.card(
            [self.node("node-a", owner=True, up=True), self.node("node-b", owner=False, up=False)],
            source="",
        )

        self.assertEqual([node.node for node in card.nodes], ["node-a", "node-b"])

    def test_a_node_that_did_not_say_is_kept(self) -> None:
        """Hiding a node on a fact nobody stated is worse than one row too many."""

        card = self.card(
            [self.node("node-a", owner=None, up=True), self.node("node-b", owner=False, up=False)],
            source="192.0.2.25",
        )

        self.assertEqual([node.node for node in card.nodes], ["node-a"])


class WhereTheFormOpens(EditorTestCase):
    """At the top, unless a button that answers here put the reader somewhere.

    The position is stored on submit and read on the next load of the same URL.
    Save and publish leave the page, so their value was never consumed - and the
    next visit to the editor picked it up and opened halfway down, at a position
    from an earlier session, for somebody who had come to read from the start.
    """

    def script(self) -> str:
        client = self.editor()
        return client.get("/static/object-form.js").text

    def test_every_button_that_answers_on_this_page_keeps_the_position(self) -> None:
        """The list is the point of this test.

        Test health check was added to the form and not to the list, so pressing it
        threw the reader back to the top of a form they were reading the bottom
        of - and the answer they had asked for rendered off-screen. A button
        added here later fails this test rather than being noticed by somebody
        scrolling.
        """

        script = self.script()

        self.assertIn('const STAYS_ON_THIS_PAGE = ["check", "recheck"]', script)
        self.assertIn("STAYS_ON_THIS_PAGE.includes(pressed)", script)
        self.assertIn("removeItem(POSITION)", script)

    def test_the_position_is_still_consumed_once(self) -> None:
        """A fresh visit or a second tab opens at the top either way."""

        self.assertIn("removeItem(POSITION)", self.script())


class AnObjectTheFormCannotOpen(EditorTestCase):
    """A stored document the form cannot express is refused, not crashed on.

    The round trip is what decides that, and it reports the refusal by raising
    `Unexpressible`. A shape that raised something else instead - a route that
    is a string, where reading it called `.get` on it - went past the catch and
    left the editor answering 500 to a question it has a sentence for.
    """

    def test_a_route_that_is_not_a_mapping_is_a_refusal_and_not_a_crash(self) -> None:
        from haproxy_ui import preview

        document = (
            "schema_version: 1\n"
            "name: bad-routes\n"
            "hostnames: [a.example.com]\n"
            "listen: {vip: main, protocol: http}\n"
            "routes: [{backend: web}, just-a-string]\n"
            "backends: {web: {servers: [{host: 192.0.2.10, port: 80}]}}\n"
        )

        with self.assertRaises(preview.Unexpressible):
            preview.form_from_document(document)


class WhatEnterDoes(EditorTestCase):
    """A browser submits with the first submit button in tree order.

    That was "Test health check", which is inside the form because it asks about the
    pool being edited - so Enter in any field ran a live probe against a node
    instead of validating what had been typed. The form now names its own
    default, so the answer does not depend on where a button happens to sit.
    """

    def form(self) -> str:
        client = self.client(writing_configuration())
        self.sign_in(client)
        page = client.get("/proxies/alpha/shop/edit")
        self.assertEqual(page.status_code, 200)
        #
        # The editor's form, not the sign-out form in the header above it.
        #
        return page.text[page.text.index('class="preview-form"') :]

    def test_the_first_submit_in_the_form_validates(self) -> None:
        body = self.form()
        first = body.index('type="submit"')

        self.assertIn('value="check"', body[first : first + 200])
        self.assertLess(first, body.index('value="recheck"'))


class SavingSaysSo(EditorTestCase):
    """A save that worked must not look like a page that was merely opened.

    The redirect carried the object's name to a listing that reads no such
    flag, while the two pages that do read one look for "1" - so the notice was
    written, had two readers, and was never shown to anybody.
    """

    def save(self, url: str, **fields: str) -> Any:
        return self.submit(self.editor(), url, action="save", **fields)

    def test_a_saved_draft_returns_to_the_editor_and_says_it_was_saved(self) -> None:
        answer = self.save("/proxies/alpha/shop/edit")

        self.assertEqual(answer.status_code, 303)
        self.assertEqual(answer.headers["location"], "/proxies/alpha/shop/edit?saved=1")

    def test_the_editor_shows_the_notice_that_url_asks_for(self) -> None:
        client = self.editor()

        page = client.get("/proxies/alpha/shop/edit?saved=1")

        self.assertIn("Saved as a draft", page.text)
        self.assertNotIn("Saved as a draft", client.get("/proxies/alpha/shop/edit").text)

    def test_a_new_object_lands_on_the_object_it_just_created(self) -> None:
        #
        # Not back on the empty form, which would read as though nothing had
        # been saved.
        #
        answer = self.save("/proxies/alpha/new", name="console")

        self.assertEqual(answer.headers["location"], "/proxies/alpha/console/edit?saved=1")


class RemovingAnObject(EditorTestCase):
    """A removal is a publish like any other, asked for on a page of its own.

    It is the one action here that takes a site off the internet, going back
    cannot undo it, and a confirmation inside a browser dialog is one people
    click through without reading. So it is a page that says what will happen,
    and the button on it is the only thing that writes.
    """

    def setUp(self) -> None:
        super().setUp()
        self.queued: list[dict[str, Any]] = []

        def queue(_c: object, **values: Any) -> Any:
            self.queued.append(values)
            return Job(
                id=7,
                request_id=uuid4(),
                operation="objects_publish",
                cluster="alpha",
                payload=values["payload"],
                state="pending",
                created_at=OBSERVED,
                started_at=None,
                finished_at=None,
                exit_code=None,
                outcome=None,
                result=None,
                stderr_excerpt=None,
                idempotency_key=values["idempotency_key"],
                attempts=0,
            )

        patch = mock.patch("haproxy_ui.db.queue_job", side_effect=queue)
        patch.start()
        self.addCleanup(patch.stop)

    def test_the_page_says_what_will_happen_and_writes_nothing(self) -> None:
        page = self.editor().get("/proxies/alpha/shop/remove")

        self.assertEqual(page.status_code, 200)
        self.assertIn("Publish the removal", page.text)
        self.assertIn("Deploy is a separate step", page.text)
        self.assertEqual(self.queued, [])
        self.assertEqual(self.saved, [])

    def test_an_object_that_is_not_there_is_a_refusal_and_not_a_form(self) -> None:
        page = self.editor().get("/proxies/alpha/nothing-here/remove")

        self.assertNotIn("Publish the removal", page.text)
        self.assertIn("no object of that name", page.text)

    def test_confirming_publishes_a_null_document_for_that_object(self) -> None:
        client = self.editor()

        answer = client.post(
            "/proxies/alpha/shop/remove",
            data={auth.CSRF_FIELD: self.token(client)},
            follow_redirects=False,
        )

        self.assertEqual(answer.status_code, 303)
        self.assertEqual(answer.headers["location"], "/proxies?published=shop")
        self.assertEqual(len(self.queued), 1)
        payload = self.queued[0]["payload"]
        #
        # `null` is what asks the helper to remove it. The draft carries the
        # stored text so the row says what is going, and the publish never
        # sends that text.
        #
        self.assertEqual(payload["objects"], {"shop": None})
        self.assertEqual(payload["comment"], "Remove shop")
        self.assertIn("draft", payload)

    def test_the_draft_it_writes_says_the_object_should_go(self) -> None:
        client = self.editor()
        client.post(
            "/proxies/alpha/shop/remove",
            data={auth.CSRF_FIELD: self.token(client)},
            follow_redirects=False,
        )

        self.assertEqual(len(self.saved), 1)
        self.assertTrue(self.saved[0]["deleted"])

    def test_a_form_without_its_token_writes_nothing(self) -> None:
        client = self.editor()

        answer = client.post("/proxies/alpha/shop/remove", data={}, follow_redirects=False)

        self.assertEqual(self.queued, [])
        self.assertEqual(self.saved, [])
        self.assertIn("expired", answer.text)

    def test_a_reader_may_not_reach_it(self) -> None:
        self.account = replace(self.account, role="reader")
        client = self.client(writing_configuration())
        self.sign_in(client)

        self.assertEqual(client.get("/proxies/alpha/shop/remove").status_code, 403)
        self.assertEqual(client.post("/proxies/alpha/shop/remove", data={}).status_code, 403)

    def test_an_installation_without_management_writes_has_no_such_page(self) -> None:
        client = self.client(replace(configuration(), clusters=("alpha",)))
        self.sign_in(client)

        self.assertEqual(client.get("/proxies/alpha/shop/remove").status_code, 404)
