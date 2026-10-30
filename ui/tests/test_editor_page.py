"""The editor: who may reach it, what it opens with, and what it refuses to write.

The document machinery is tested next door, in `test_object_form`. What is
worth testing here are the boundaries the route owns - the role, the write
switch, the revision two tabs disagree about, and the two shapes of refusal
that must not become a saved draft.
"""

from __future__ import annotations

import html
import json
import re
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from unittest import mock
from uuid import uuid4

import yaml

from haprion_ui import auth, db, editor_flow, health, objects
from haprion_ui import editor as editor_module
from haprion_ui import probe as probe_module
from haprion_ui.db import (
    ClusterInventory,
    ClusterNetwork,
    ClusterObjects,
    ClusterSettingsRow,
    DraftConflict,
    Job,
    ProxyDraft,
)
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
#
# The settings reading at the same commit as the objects and the network, as a
# poll pass that read all three after the last version leaves them.
#
SETTINGS = ClusterSettingsRow(
    cluster="alpha",
    observed_at=OBSERVED,
    outcome="done",
    result={"cluster": "alpha", "head": COMMIT, "stored": True, "log_targets": []},
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
        self.changes: list[dict[str, Any]] = []
        self.renamed: list[dict[str, Any]] = []
        self.discarded: list[tuple[str, str, int]] = []
        self.backend_renames: list[dict[str, Any]] = []
        self.draft: ProxyDraft | None = None
        self.conflict = False
        for target, side_effect in (
            ("cluster_objects", lambda _c, **_kw: [OBJECTS]),
            ("cluster_networks", lambda _c, **_kw: [NETWORK]),
            ("cluster_settings", lambda _c, **_kw: [SETTINGS]),
            ("read_draft", self._read_draft),
            ("save_draft", self._save_draft),
            ("save_change", self._save_change),
            ("rename_draft", self._rename_draft),
            ("discard_draft", self._discard_draft),
            ("record_backend_renames", self._record_renames),
            ("draft_publishes", lambda _c, **_kw: []),
        ):
            patch = mock.patch(f"haprion_ui.db.{target}", side_effect=side_effect)
            patch.start()
            self.addCleanup(patch.stop)

    def _record_renames(self, _c: object, **values: Any) -> None:
        self.backend_renames.append(values)

    def _read_draft(
        self, _c: object, cluster: str, object_id: str, stage: str = "draft"
    ) -> ProxyDraft | None:
        #
        # Keyed by the object asked for, as the table is. It used to answer
        # with the one draft whatever was asked, which was harmless until
        # something looked up a *different* name to see whether it was free -
        # a fixture that answers yes to every question cannot measure that.
        #
        del cluster
        if (
            self.draft is not None
            and self.draft.object_id == object_id
            and self.draft.stage == stage
        ):
            return self.draft
        return None

    def _save_change(self, _c: object, **values: Any) -> ProxyDraft:
        """`save_change`, recorded beside the drafts as what was written (B257).

        Recorded under the name it lands on and the revision it was held to,
        so a test about what a save wrote reads the same either way.
        """

        if self.conflict:
            raise DraftConflict("the changes to shop changed since they were read")
        target = values.get("new_object_id") or values["object_id"]
        self.changes.append(values)
        self.saved.append(
            dict(values, object_id=target, expected_revision=values["saved_revision"])
        )
        return ProxyDraft(
            cluster=values["cluster"],
            object_id=target,
            yaml=values["yaml"],
            base_version=values["base_version"],
            base_hash=values["base_hash"],
            revision=(values["saved_revision"] or 0) + 1,
            updated_by=values["updated_by"],
            updated_at=OBSERVED,
            deleted=values.get("deleted", False),
            stage="saved",
            replaces=values.get("replaces"),
        )

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
        self,
        _c: object,
        *,
        cluster: str,
        object_id: str,
        expected_revision: int,
        stage: str = "draft",
    ) -> None:
        del stage
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
            #
            # The stored object's pool, as the page fills it in. Left out, the
            # pool would take the object's name - a rename nobody asked for.
            #
            "backend": "web",
            auth.CSRF_FIELD: self.token(client),
            "object_fingerprint": self.shown(path),
        }
        data.update(fields)
        return client.post(path, data=data, follow_redirects=False)

    def shown(self, path: str) -> str:
        """The fingerprint the page at `path` carries: the stored object as the cache holds it."""

        found = re.fullmatch(r"/proxies/alpha/([^/]+)/(?:edit|advanced)", path)
        if found is None:
            return ""
        documents = {
            entry["name"]: entry["document"]
            for row in db.cluster_objects(cast(Any, None))
            for entry in (row.result or {}).get("objects", ())
        }
        return editor_module.fingerprint(documents.get(found[1]))


class ReachingTheEditor(EditorTestCase):
    def test_editor_reads_the_cluster_list_once_and_only_its_four_sources(self) -> None:
        request = mock.Mock()
        request.app.state.pool = self.pool
        with (
            mock.patch("haprion_ui.db.cluster_list", return_value=("alpha", "beta")) as listed,
            mock.patch("haprion_ui.db.cluster_objects", return_value=[OBJECTS]) as objects_read,
            mock.patch("haprion_ui.db.cluster_networks", return_value=[NETWORK]) as networks_read,
            mock.patch("haprion_ui.db.cluster_certificates", return_value=[]) as certificates_read,
            mock.patch("haprion_ui.db.cluster_histories", return_value=[]) as histories_read,
        ):
            state = editor_flow.editor_state(request, writing_configuration(), "alpha")
        self.assertEqual(state.commit, COMMIT)
        self.assertEqual([obj.name for obj in state.stored], ["shop"])
        self.assertEqual(listed.call_count, 1)
        for reader in (objects_read, networks_read, certificates_read, histories_read):
            # The fixture's manager reading is drawn from every cluster's listing.
            per_cluster = [call.kwargs for call in reader.call_args_list if call.kwargs]
            self.assertEqual(per_cluster, [{"cluster": "alpha"}])

    def test_the_ca_certificates_of_the_cluster_are_offered(self) -> None:
        # The registry is the manager's reading (B304); without it no CA could be chosen.
        request = mock.Mock()
        request.app.state.pool = self.pool
        registry = {
            "certificates": [
                {
                    "id": "corp-root",
                    "source": {"kind": "authority"},
                    "readable": True,
                    "targets": {"clusters": ["alpha"]},
                },
                {
                    "id": "other-root",
                    "source": {"kind": "authority"},
                    "readable": True,
                    "targets": {"clusters": ["beta"]},
                },
            ]
        }
        reading = db.ManagerCertificates(
            observed_at=datetime.now(UTC),
            outcome="done",
            result={"interface_served": None, "registry": registry},
            warnings=[],
            error=None,
            poll_error=None,
        )
        with (
            mock.patch("haprion_ui.db.cluster_list", return_value=("alpha", "beta")),
            mock.patch("haprion_ui.db.cluster_objects", return_value=[OBJECTS]),
            mock.patch("haprion_ui.db.cluster_networks", return_value=[NETWORK]),
            mock.patch("haprion_ui.db.cluster_certificates", return_value=[]),
            mock.patch("haprion_ui.db.cluster_histories", return_value=[]),
            mock.patch("haprion_ui.db.manager_certificates", return_value=reading),
        ):
            state = editor_flow.editor_state(request, writing_configuration(), "alpha")
        self.assertEqual(state.choices.authority_ids, ("corp-root",))

    def test_removed_cluster_is_refused_before_its_cached_objects_are_read(self) -> None:
        client = self.editor()
        with (
            mock.patch("haprion_ui.db.cluster_list", return_value=("beta",)),
            mock.patch("haprion_ui.db.cluster_objects") as objects_read,
        ):
            self.assertEqual(client.get("/proxies/alpha/shop/edit").status_code, 404)
        objects_read.assert_not_called()

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

        answer = self.submit(client, "/proxies/alpha/shop/edit", action="draft")

        self.assertEqual(answer.status_code, 303)
        self.assertEqual(self.saved[0]["base_hash"], COMMIT)
        self.assertEqual(self.saved[0]["object_id"], "shop")
        self.assertIn("name: shop", self.saved[0]["yaml"])

    def test_checking_writes_nothing(self) -> None:
        client = self.editor()

        answer = self.submit(client, "/proxies/alpha/shop/edit", action="check")

        self.assertEqual(answer.status_code, 200)
        self.assertEqual(self.saved, [])

    def test_a_name_the_cluster_reserves_is_refused_by_the_check(self) -> None:
        """Review 26-10-24, 15-07: the publish refused it after the check passed."""

        inventory = ClusterInventory(
            cluster="alpha",
            observed_at=OBSERVED,
            outcome="done",
            result={
                "reservations": {
                    "hostnames": ["shop.example.com"],
                    "tcp_ports": [],
                    "tcp_listeners": [],
                }
            },
            warnings=[],
            error=None,
            poll_error=None,
        )
        client = self.editor()
        fresh = replace(NETWORK, observed_at=datetime.now(UTC))
        with (
            mock.patch("haprion_ui.db.cluster_networks", return_value=[fresh]),
            mock.patch("haprion_ui.db.cluster_inventories", return_value=[inventory]),
        ):
            answer = self.submit(client, "/proxies/alpha/shop/edit", action="check")

        self.assertIn("reserved in manual/reservations.yaml", answer.text)
        self.assertNotIn("<strong>Valid", answer.text)

    def test_an_object_written_on_the_command_line_with_many_names_opens_and_saves(self) -> None:
        """Review 26-10-24, 15-08: it opened, and Save refused it as too long."""

        names = [f"host-{number:03d}.shop.example.com" for number in range(90)]
        document = SHOP.replace("- shop.example.com\n", "".join(f"- {n}\n" for n in names))
        stored = replace(
            OBJECTS,
            result={
                **OBJECTS.result,
                "objects": [{**OBJECTS.result["objects"][0], "document": document}],
            },
        )
        client = self.editor()
        with mock.patch("haprion_ui.db.cluster_objects", return_value=[stored]):
            page = client.get("/proxies/alpha/shop/edit")
            answer = self.submit(
                client, "/proxies/alpha/shop/edit", action="draft", hostnames="\n".join(names)
            )

        self.assertEqual(page.status_code, 200)
        self.assertIn(names[-1], page.text)
        self.assertEqual(answer.status_code, 303, answer.text[-2000:])
        self.assertIn(names[-1], self.saved[0]["yaml"])

    def test_an_object_beyond_what_the_form_takes_says_so_when_opened(self) -> None:
        """Review 26-10-24, 15-08: the form's limit is said where the object is opened."""

        names = [f"host-{number:04d}.shop.example.com" for number in range(2600)]
        document = SHOP.replace("- shop.example.com\n", "".join(f"- {n}\n" for n in names))
        stored = replace(
            OBJECTS,
            result={
                **OBJECTS.result,
                "objects": [{**OBJECTS.result["objects"][0], "document": document}],
            },
        )
        client = self.editor()
        with mock.patch("haprion_ui.db.cluster_objects", return_value=[stored]):
            page = client.get("/proxies/alpha/shop/edit")

        self.assertEqual(page.status_code, 200)
        self.assertIn("cannot be opened in the form", page.text)
        self.assertIn("<code>hostnames</code>", page.text)

    def test_a_document_that_is_not_an_object_is_not_saved(self) -> None:
        """The refusal is about the object, so there is nothing to keep yet."""

        client = self.editor()

        answer = self.submit(client, "/proxies/alpha/shop/edit", action="draft", servers="")

        self.assertEqual(answer.status_code, 200)
        self.assertEqual(self.saved, [])

    def test_an_object_that_clashes_with_a_neighbour_is_still_saved(self) -> None:
        """A publish answers that. Refusing to save would stop the work that resolves it."""

        client = self.editor()

        answer = self.submit(
            client,
            "/proxies/alpha/new",
            action="draft",
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
            client, "/proxies/alpha/new", action="draft", name="console", expected_revision="1"
        )

        self.assertEqual(answer.status_code, 303)
        self.assertIsNone(self.saved[0]["expected_revision"])

    def test_the_match_choice_is_dimmed_rather_than_disabled(self) -> None:
        """A disabled select is not submitted, and this one's default decides.

        Left disabled, a form where somebody filled in a redirect but the
        script had not run would post no match mode at all and fall back to
        `prefix` - the one answer that makes a redirect on the site root
        collide with the backend. The cue must not change what gets saved.
        """

        page = self.editor().get("/proxies/alpha/new").text

        self.assertNotIn("disabled", page.split('name="redirect_match"')[1].split(">")[0])

    def test_a_new_object_s_pool_is_offered_a_check(self) -> None:
        """7-3: a new pool started with no check, so a server that went away kept its share."""

        page = self.editor().get("/proxies/alpha/new").text

        self.assertIn('<select name="health_type" data-proposed="http">', page)
        self.assertIn('name="health_expect_status" value="200-499"', page)

    def test_the_maintenance_page_is_not_named_as_the_server_button(self) -> None:
        """7-1: the group shared its name with a server's Maintenance button."""

        page = self.editor().get("/proxies/alpha/new").text

        self.assertIn('<span class="form-group-title">Maintenance page</span>', page)
        self.assertNotIn('<span class="form-group-title">Maintenance</span>', page)

    def test_the_certificate_is_asked_for_rather_than_offered_as_none(self) -> None:
        """7-15: an https object must have one, and the list started at *None*."""

        page = self.editor().get("/proxies/alpha/new").text

        self.assertIn(
            '<select name="certificate">\n          <option value="">Choose a certificate</option>',
            page,
        )

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

        answer = self.submit(client, "/proxies/alpha/shop/edit", action="draft", name="bazaar")

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
            action="draft",
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
            action="draft",
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
            action="draft",
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
            action="draft",
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

        answer = self.submit(client, "/proxies/alpha/new", action="draft", name="Shop.One")

        self.assertEqual(answer.status_code, 400)
        self.assertEqual(self.saved, [])
        self.assertIn("capital letters are not allowed", answer.text)

    def test_a_new_object_may_not_take_a_name_that_exists(self) -> None:
        client = self.editor()

        answer = self.submit(client, "/proxies/alpha/new", action="draft", name="shop")

        self.assertEqual(answer.status_code, 400)
        self.assertEqual(self.saved, [])

    def test_a_revision_somebody_else_moved_is_refused(self) -> None:
        self.conflict = True
        client = self.editor()

        answer = self.submit(
            client, "/proxies/alpha/shop/edit", action="draft", expected_revision="1"
        )

        self.assertEqual(answer.status_code, 409)
        self.assertIn("<h1>Not done</h1>", answer.text)
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

        self.assertIn("A draft", page.text)
        self.assertIn("Not published until it is saved.", page.text)

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

    def test_everywhere_is_chosen_while_nothing_restricts_the_object(self) -> None:
        page = self.editor().get("/proxies/alpha/shop/edit")

        self.assertRegex(page.text, r'<option value="" selected>Everywhere')

    def test_everywhere_leaves_the_list_once_an_address_is_written(self) -> None:
        client = self.editor()

        page = self.submit(
            client, "/proxies/alpha/shop/edit", action="check", allow_ranges="country:SE"
        )

        self.assertRegex(page.text, r'<option value="" hidden>Everywhere')

    def test_a_range_with_host_bits_is_refused_as_written(self) -> None:
        """Review 26-10-24, 15-06: the form is a write; the engine's words."""

        page = self.submit(
            self.editor(), "/proxies/alpha/shop/edit", action="check", allow_ranges="192.0.2.1/24"
        )

        self.assertIn("host bits must be zero", page.text)

    def test_nobody_leaves_the_list_once_a_denied_address_is_written(self) -> None:
        client = self.editor()

        page = self.submit(
            client, "/proxies/alpha/shop/edit", action="check", deny_ranges="country:CN"
        )

        self.assertRegex(page.text, r'<option value="" hidden>Nobody')
        self.assertRegex(page.text, r'<option value="" selected>Everywhere')


class TheHealthCardOnThePage(EditorTestCase):
    """What the probe's answer looks like once it is rendered.

    The filtering is in the template, so asserting on the report alone proves
    nothing about the page. These render it.
    """

    def probe(
        self,
        nodes: list[probe_module.NodeReport],
        source: str = "192.0.2.25",
        caveats: tuple[str, ...] = (),
    ) -> str:
        report = probe_module.ProbeReport(
            ran=True, source=source, nodes=tuple(nodes), caveats=caveats
        )
        with (
            mock.patch("haprion_ui.probe.run", return_value=report),
            mock.patch("haprion_ui.db.wake_poller"),
        ):
            client = self.editor()
            response = self.submit(client, "/proxies/alpha/shop/edit", action="recheck")
        self.assertEqual(response.status_code, 200)
        return str(response.text)

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

    def test_the_note_says_where_the_test_left_from(self) -> None:
        body = self.probe([self.node("node-a", held=True), self.node("node-b", held=False)])
        self.assertIn("from 192.0.2.25, with the check as it stands on screen", body)

    def test_without_a_source_every_node_is_still_listed(self) -> None:
        body = self.probe(
            [self.node("node-a", held=None), self.node("node-b", held=None)], source=""
        )
        self.assertIn("node-a", body)
        self.assertIn("node-b", body)

    def test_a_tested_server_says_up_and_is_marked_as_tested(self) -> None:
        body = self.probe([self.node("node-a", held=True)])

        self.assertIn("UP</td>", body)
        self.assertIn("answered 200 · 2 ms · tested", body)
        self.assertNotIn("status-warning", body)

    def test_the_table_is_where_the_in_place_test_looks_for_it(self) -> None:
        """object-form.js replaces `form.preview-form .node-health` from the answer."""

        body = self.probe([self.node("node-a", held=True)])
        form = body.index('class="preview-form"')

        self.assertLess(form, body.index('class="node-health"'), body.index("</form>", form))
        self.assertLess(body.index('class="node-health"'), body.index("</form>", form))

    def test_there_is_one_table_and_not_a_second_one_for_the_test(self) -> None:
        """The test answers the question the nodes' table asks (2026-09-30)."""

        body = self.probe([self.node("node-a", held=True)])

        self.assertEqual(body.count('class="node-health-table"'), 1)
        self.assertNotIn("What the nodes just tried", body)

    def test_what_the_test_could_not_run_is_said_under_the_table(self) -> None:
        """In a sentence, not in the colour of a row that answered."""

        body = self.probe(
            [self.node("node-a", held=True)],
            caveats=("The expected body is not checked here.",),
        )

        self.assertIn("The expected body is not checked here.", body)
        self.assertNotIn("status-warning", body)

    def test_a_server_that_failed_says_down(self) -> None:
        body = self.probe(
            [self.node("node-a", held=True, ok=False)],
            caveats=("The expected body is not checked here.",),
        )

        self.assertIn("DOWN", body)


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

    def test_a_check_that_passes_says_so(self) -> None:
        # 26-10-03: the stored object alone did not say whether the check passed.
        fresh = replace(NETWORK, observed_at=datetime.now(UTC))
        with mock.patch("haprion_ui.db.cluster_networks", return_value=[fresh]):
            answer = self.submit(self.editor(), "/proxies/alpha/shop/edit", action="check")

        self.assertIn(
            "<strong>Valid.</strong> Checked with the other proxies in alpha", answer.text
        )
        self.assertNotIn("This proxy was refused", answer.text)

    def test_the_document_is_folded_under_the_verdict(self) -> None:
        # 26-10-03: the verdict is the answer; the YAML is there to open, as on the object page.
        answer = self.submit(self.editor(), "/proxies/alpha/shop/edit", action="check")
        tail = answer.text.split("<strong>Valid", 1)[1]

        self.assertIn('<details class="archive-details config-details">', tail)
        self.assertIn("lines of YAML · ", tail)
        self.assertIn("managed/proxies/shop.yaml", tail)
        self.assertNotIn('<details class="archive-details config-details" open', tail)

    def test_without_the_cluster_it_says_only_what_was_checked(self) -> None:
        answer = self.submit(self.editor(), "/proxies/alpha/shop/edit", action="check")

        self.assertIn("<strong>Valid on its own.</strong> Not checked with the other", answer.text)
        self.assertNotIn("<strong>Valid.</strong>", answer.text)

    def test_a_refused_check_says_nothing_of_passing(self) -> None:
        answer = self.submit(self.editor(), "/proxies/alpha/shop/edit", action="check", servers="")

        self.assertIn("This proxy was refused", answer.text)
        self.assertNotIn("<strong>Valid", answer.text)


class NoPublishHere(EditorTestCase):
    """B257: the editor saves; Versions publishes what is saved, together."""

    def test_an_identical_document_may_still_be_saved(self) -> None:
        client = self.editor()
        answer = self.submit(client, "/proxies/alpha/shop/edit", action="save")

        self.assertEqual(answer.status_code, 303)
        self.assertEqual(len(self.saved), 1)

    def test_a_publish_asked_of_the_editor_writes_nothing(self) -> None:
        with mock.patch("haprion_ui.db.queue_job") as queue:
            answer = self.submit(
                self.editor(),
                "/proxies/alpha/shop/edit",
                action="publish",
                servers="192.0.2.11:8080",
            )

        self.assertEqual(answer.status_code, 400)
        self.assertEqual(self.saved, [])
        queue.assert_not_called()

    def test_the_page_has_no_publish_button(self) -> None:
        page = self.editor().get("/proxies/alpha/shop/edit").text

        self.assertNotIn('value="publish"', page)
        self.assertIn('name="action" value="save" class="primary-button">Save</button>', page)


LATER = "b" * 40
SHOP_9090 = SHOP.replace("port: 8080", "port: 9090")


def objects_at(commit: str, **documents: str) -> ClusterObjects:
    """The cluster's objects cache as read at `commit`, holding these documents."""

    return replace(
        OBJECTS,
        result={
            "commit": commit,
            "objects": [
                {**OBJECTS.result["objects"][0], "name": name, "document": document}
                for name, document in documents.items()
            ],
        },
    )


class WhatThePageShowed(EditorTestCase):
    """A tab opened before somebody else's publish must not write it away (CR-01).

    The scenario the review reproduced: no draft, B publishes port 9090, A's
    tab - opened on 8080 - changes only the address and presses save.
    """

    def opened(self, client: Any) -> str:
        page = client.get("/proxies/alpha/shop/edit")
        found = re.search(r'name="object_fingerprint" value="([0-9a-f]*)"', page.text)
        self.assertIsNotNone(found, "the editor carries no fingerprint")
        return found[1] if found else ""

    def test_the_page_carries_the_stored_object_it_showed(self) -> None:
        client = self.editor()

        self.assertEqual(self.opened(client), editor_module.fingerprint(SHOP))

    def test_an_old_tab_is_refused_after_somebody_else_published(self) -> None:
        client = self.editor()
        shown = self.opened(client)
        later = objects_at(LATER, shop=SHOP_9090)
        with mock.patch("haprion_ui.db.cluster_objects", return_value=[later]):
            answer = self.submit(
                client,
                "/proxies/alpha/shop/edit",
                action="save",
                servers="192.0.2.11:8080",
                object_fingerprint=shown,
            )

        self.assertEqual(answer.status_code, 200)
        self.assertIn("was changed by a publish after this page was opened", answer.text)
        self.assertEqual(self.saved, [])
        # The person's edit is still on the form.
        self.assertIn("192.0.2.11:8080", answer.text)
        # And the page now carries the object as it is, so saving again is a choice.
        self.assertIn(
            f'name="object_fingerprint" value="{editor_module.fingerprint(SHOP_9090)}"',
            answer.text,
        )

    def test_saving_again_after_the_refusal_is_a_decision_and_is_taken(self) -> None:
        client = self.editor()
        later = objects_at(LATER, shop=SHOP_9090)
        with mock.patch("haprion_ui.db.cluster_objects", return_value=[later]):
            answer = self.submit(
                client,
                "/proxies/alpha/shop/edit",
                action="save",
                servers="192.0.2.11:8080",
                object_fingerprint=editor_module.fingerprint(SHOP_9090),
            )

        self.assertEqual(answer.status_code, 303)
        self.assertEqual(len(self.saved), 1)

    def test_a_save_is_refused_after_somebody_else_published_too(self) -> None:
        client = self.editor()
        shown = self.opened(client)
        with mock.patch(
            "haprion_ui.db.cluster_objects", return_value=[objects_at(LATER, shop=SHOP_9090)]
        ):
            self.submit(client, "/proxies/alpha/shop/edit", action="save", object_fingerprint=shown)

        self.assertEqual(self.saved, [])

    def test_a_publish_of_another_object_does_not_stop_this_one(self) -> None:
        """The commit moved, this object did not: nothing of it is overwritten."""

        client = self.editor()
        shown = self.opened(client)
        other = SHOP.replace("name: shop", "name: other").replace("shop.example", "other.example")
        with mock.patch(
            "haprion_ui.db.cluster_objects",
            return_value=[objects_at(LATER, shop=SHOP, other=other)],
        ):
            answer = self.submit(
                client,
                "/proxies/alpha/shop/edit",
                action="save",
                servers="192.0.2.11:8080",
                object_fingerprint=shown,
            )

        self.assertEqual(answer.status_code, 303)
        self.assertEqual(self.saved[0]["base_hash"], LATER)

    def test_an_object_removed_meanwhile_is_not_written_back(self) -> None:
        client = self.editor()
        shown = self.opened(client)
        with mock.patch("haprion_ui.db.cluster_objects", return_value=[objects_at(LATER)]):
            self.submit(
                client,
                "/proxies/alpha/shop/edit",
                action="save",
                servers="192.0.2.11:8080",
                object_fingerprint=shown,
            )

        self.assertEqual(self.saved, [])


def published(changed: bool) -> dict[str, Any]:
    """A finished publish's answer as the helper writes it: the contract's own fixture.

    Built by hand as `{"changed": ...}` until 2026-10-08, the shape the
    interface wrongly read - so the test agreed with the bug. Taken from the
    contract instead, the two cannot drift apart again.
    """

    path = Path(__file__).resolve().parents[2] / "fixtures/haprion-changes-publish/valid/done.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    document["result"]["changed"] = changed
    return cast(dict[str, Any], document)


DRAFT_ID = uuid4()


class ThePublishedDraftWaitsForTheCache(EditorTestCase):
    """A published draft is kept until the cache has read past the publish (CR-03, CR-04)."""

    def setUp(self) -> None:
        super().setUp()
        self.draft = ProxyDraft(
            cluster="alpha",
            object_id="shop",
            yaml=SHOP_9090,
            base_version=1,
            base_hash=COMMIT,
            revision=1,
            updated_by="admin",
            updated_at=OBSERVED,
            deleted=False,
            id=DRAFT_ID,
        )
        self.publishes: list[Job] = [self.done(changed=True)]
        patch = mock.patch(
            "haprion_ui.db.draft_publishes", side_effect=lambda _c, **_kw: self.publishes
        )
        patch.start()
        self.addCleanup(patch.stop)

    def done(self, *, changed: bool, revision: int = 1) -> Job:
        return Job(
            id=1,
            request_id=uuid4(),
            operation="changes_publish",
            cluster="alpha",
            payload={
                "objects": {"shop": SHOP_9090},
                "expected_head": COMMIT,
                "drafts": [{"id": str(DRAFT_ID), "revision": revision}],
            },
            state="done",
            created_at=OBSERVED,
            started_at=OBSERVED,
            finished_at=OBSERVED,
            exit_code=0,
            outcome="done",
            result=published(changed),
            stderr_excerpt=None,
            idempotency_key=None,
            attempts=1,
        )

    def opened(self, objects: ClusterObjects) -> str:
        with mock.patch("haprion_ui.db.cluster_objects", return_value=[objects]):
            return str(self.editor().get("/proxies/alpha/shop/edit").text)

    def test_a_cache_still_at_the_base_keeps_the_published_draft(self) -> None:
        """The review's case: done job, old cache - the form opened on 8080 and the draft went."""

        page = self.opened(objects_at(COMMIT, shop=SHOP))

        self.assertEqual(self.discarded, [])
        self.assertIn("192.0.2.10:9090", page)
        self.assertNotIn("192.0.2.10:8080", page)

    def test_a_cache_past_the_base_clears_it(self) -> None:
        page = self.opened(objects_at(LATER, shop=SHOP_9090))

        self.assertEqual(self.discarded, [("alpha", "shop", 1)])
        self.assertIn("192.0.2.10:9090", page)

    def test_a_later_publish_read_first_clears_it_as_well(self) -> None:
        """Somebody published again before this GET: the cache is past both."""

        later = SHOP_9090.replace("192.0.2.10", "192.0.2.12")
        page = self.opened(objects_at("c" * 40, shop=later))

        self.assertEqual(self.discarded, [("alpha", "shop", 1)])
        self.assertIn("192.0.2.12:9090", page)

    def test_a_publish_that_changed_nothing_needs_no_new_commit(self) -> None:
        self.publishes = [self.done(changed=False)]

        self.opened(objects_at(COMMIT, shop=SHOP_9090))

        self.assertEqual(self.discarded, [("alpha", "shop", 1)])

    def test_a_draft_edited_after_its_publish_is_not_cleared_by_it(self) -> None:
        self.draft = replace(cast(ProxyDraft, self.draft), revision=2)

        self.opened(objects_at(LATER, shop=SHOP_9090))

        self.assertEqual(self.discarded, [])

    def test_a_new_object_waits_for_the_cache_too(self) -> None:
        self.opened(objects_at(COMMIT))

        self.assertEqual(self.discarded, [])

    def test_the_evidence_is_asked_for_by_the_draft_not_out_of_recent_jobs(self) -> None:
        """Twenty later jobs pushed the publish out of the window (CR-04)."""

        with mock.patch("haprion_ui.db.recent_jobs", side_effect=AssertionError("window")):
            self.opened(objects_at(LATER, shop=SHOP_9090))

        self.assertEqual(self.discarded, [("alpha", "shop", 1)])


class AFormTooLongForTheModel(EditorTestCase):
    """CR-06: three hundred server lines met pydantic's JSON instead of a page."""

    def test_a_list_longer_than_the_limit_is_answered_with_a_page(self) -> None:
        client = self.editor()
        answer = self.submit(
            client,
            "/proxies/alpha/shop/edit",
            action="save",
            servers="\n".join(["192.0.2.10:8080"] * (editor_module.FORM_TEXT // 15)),
        )

        self.assertEqual(answer.status_code, 400)
        self.assertIn("text/html", answer.headers["content-type"])
        self.assertIn(f"Servers is longer than {editor_module.FORM_TEXT:,} characters", answer.text)
        self.assertNotIn("192.0.2.10:8080", answer.text)
        self.assertEqual(self.saved, [])

    def test_an_api_answer_keeps_its_json(self) -> None:
        client = self.editor()
        answer = client.post(
            "/proxies/alpha/shop/edit",
            json={"servers": "x" * (editor_module.FORM_TEXT + 1)},
            follow_redirects=False,
        )

        self.assertNotIn("text/html", answer.headers.get("content-type", ""))


class WhichNodeReportsOnThePool(EditorTestCase):
    """The passive card follows the same rule the probe does.

    An object that leaves from a source address can only be checked from the
    node carrying it. The other runs the same check, binds an address it does
    not have, and reports the backend down - HAProxy telling the truth about the
    binding and a lie about the backend.
    """

    def node(self, name: str, *, owner: bool | None, up: bool) -> dict[str, Any]:
        return {
            "name": name,
            "status": {
                "vip": {"owner": owner},
                "backend_members": [
                    {
                        "backend": "mgd-shop-web",
                        "server": "s1",
                        "status": "UP" if up else "DOWN",
                        "up": up,
                    }
                ],
            },
        }

    def card(self, nodes: list[dict[str, Any]], source: str) -> health.BackendHealth:
        row = SimpleNamespace(cluster="alpha", result={"nodes": nodes}, observed_at=OBSERVED)
        return health.backend_health(
            [row], cluster="alpha", obj="shop", backend="web", source=source
        )

    def test_the_published_servers_are_read_from_the_stored_document(self) -> None:
        """Review 26-10-24, 02-10: the card compares the form's servers with these."""

        stored = objects.object_view({"name": "shop", "document": SHOP, "readable": True})
        self.assertEqual(editor_flow._published_servers(stored, ()), ["192.0.2.10:8080"])
        self.assertEqual(editor_flow._published_servers(None, ()), [])

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
        return str(client.get("/static/object-form.js").text)

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
        from haprion_ui import preview

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
    backend being edited - so Enter in any field ran a live probe against a node
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
        return str(page.text[page.text.index('class="preview-form"') :])

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

    def save(self, url: str, action: str = "draft", **fields: str) -> Any:
        return self.submit(self.editor(), url, action=action, **fields)

    def test_a_saved_draft_returns_to_the_editor_and_says_it_was_saved(self) -> None:
        answer = self.save("/proxies/alpha/shop/edit")

        self.assertEqual(answer.status_code, 303)
        self.assertEqual(answer.headers["location"], "/proxies/alpha/shop/edit?saved=1")

    def test_a_finished_save_goes_back_to_the_list(self) -> None:
        """As *Save and publish* did before B257: the row says what waits."""

        for url, fields in (
            ("/proxies/alpha/shop/edit", {}),
            ("/proxies/alpha/new", {"name": "console"}),
        ):
            with self.subTest(url=url):
                answer = self.save(url, action="save", **fields)

                self.assertEqual(
                    (answer.status_code, answer.headers["location"]), (303, "/proxies")
                )

    def test_a_server_name_the_manager_cannot_resolve_keeps_the_save_in_the_editor(self) -> None:
        """Finding 72: said where it is typed, not first by a node's deploy; never refused."""

        with mock.patch("haprion.resolve_socket.unresolved", side_effect=lambda hosts: list(hosts)):
            answer = self.save(
                "/proxies/alpha/shop/edit", action="save", servers="typo.example.com:8080"
            )
            page = self.save(
                "/proxies/alpha/shop/edit", action="check", servers="typo.example.com:8080"
            )
            clean = self.save("/proxies/alpha/shop/edit", action="check")

        self.assertEqual(answer.status_code, 303)
        self.assertEqual(answer.headers["location"], "/proxies/alpha/shop/edit?saved=1")
        self.assertIn("typo.example.com is not in DNS as the manager sees it", page.text)
        #
        # A warning, and drawn as one (B330): it stood in blue beside "Saved.".
        #
        self.assertIn('class="preview-notice notice-warning" data-unresolved', page.text)
        self.assertNotIn("data-unresolved", clean.text)

    def test_a_renamed_object_s_unresolved_server_keeps_the_save_in_the_editor(self) -> None:
        """Code review 26-10-30 again, R14: the check read the document under the old
        name, the model refused it for not matching, and the warning was lost."""

        with mock.patch("haprion.resolve_socket.unresolved", side_effect=lambda hosts: list(hosts)):
            answer = self.save(
                "/proxies/alpha/shop/edit",
                action="save",
                name="bazaar",
                servers="typo.example.com:8080",
            )

        self.assertEqual(answer.status_code, 303)
        self.assertEqual(answer.headers["location"], "/proxies/alpha/bazaar/edit?saved=1")

    def test_a_server_written_with_two_colons_is_refused_where_it_is_typed(self) -> None:
        """Finding 82: `name::8080` became the host `name:`, was saved, called valid, and
        stopped the deploy on a node."""

        with mock.patch("haprion.resolve_socket.unresolved", side_effect=lambda hosts: []):
            for action in ("save", "check"):
                with self.subTest(action=action):
                    page = self.save(
                        "/proxies/alpha/shop/edit", action=action, servers="mgr.example.com::8080"
                    )
                    self.assertNotEqual(page.status_code, 303)
                    self.assertIn("must be an IP address or a host name", page.text)
                    self.assertNotIn("<strong>Valid.</strong>", page.text)

    def test_the_editor_shows_the_notice_that_url_asks_for(self) -> None:
        client = self.editor()

        page = client.get("/proxies/alpha/shop/edit?saved=1")

        self.assertIn("<strong>Saved.</strong>", page.text)
        self.assertNotIn("<strong>Saved.</strong>", client.get("/proxies/alpha/shop/edit").text)

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
                operation="changes_publish",
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

        patch = mock.patch("haprion_ui.db.queue_job", side_effect=queue)
        patch.start()
        self.addCleanup(patch.stop)

    def test_the_page_says_what_will_happen_and_writes_nothing(self) -> None:
        page = self.editor().get("/proxies/alpha/shop/remove")

        self.assertEqual(page.status_code, 200)
        self.assertIn("Save the removal", page.text)
        self.assertIn("Deploy is a separate step", page.text)
        self.assertEqual(self.queued, [])
        self.assertEqual(self.saved, [])

    def test_looking_up_again_saves_the_object_and_goes_back_to_the_list(self) -> None:
        """B257: saved as it is stored, for the next publish; nothing queued."""

        client = self.editor()

        answer = client.post(
            "/proxies/alpha/shop/lookup",
            data={auth.CSRF_FIELD: self.token(client)},
            follow_redirects=False,
        )

        self.assertEqual((answer.status_code, answer.headers["location"]), (303, "/proxies"))
        self.assertEqual(self.queued, [])
        (change,) = self.changes
        self.assertEqual(change["object_id"], "shop")
        self.assertFalse(change.get("deleted", False))

    def test_an_object_that_is_not_there_is_a_refusal_and_not_a_form(self) -> None:
        page = self.editor().get("/proxies/alpha/nothing-here/remove")

        self.assertNotIn("Save the removal", page.text)
        self.assertIn("no proxy of that name", page.text)

    def test_confirming_saves_the_removal_and_queues_nothing(self) -> None:
        """B257: the removal goes out with the next publish; back to the list."""

        client = self.editor()

        answer = client.post(
            "/proxies/alpha/shop/remove",
            data={auth.CSRF_FIELD: self.token(client)},
            follow_redirects=False,
        )

        self.assertEqual(answer.status_code, 303)
        self.assertEqual(answer.headers["location"], "/proxies")
        self.assertEqual(self.queued, [])
        (change,) = self.changes
        self.assertTrue(change["deleted"])

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


HANDWRITTEN = """schema: 1
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
    servers: []
advanced: |
  balance leastconn
  server app1 192.0.2.30:8080 check
  http-request set-header X-Seen "%[src]"
"""


class TheAdvancedConfigSurvivesTheForm(EditorTestCase):
    """Edit and Save keep an object's advanced config, which the form does not show (Fas 17)."""

    def setUp(self) -> None:
        super().setUp()
        self.draft = ProxyDraft(
            cluster="alpha",
            object_id="shop",
            yaml=HANDWRITTEN,
            base_version=12,
            base_hash=COMMIT,
            revision=3,
            updated_by="operator",
            updated_at=OBSERVED,
            deleted=False,
        )

    def carried(self, page: str, name: str) -> str | None:
        found = re.search(rf'<input type="hidden" name="{name}" value="([^"]*)">', page)
        return html.unescape(found.group(1)) if found else None

    def test_the_page_carries_the_text_and_shows_no_pool_fields(self) -> None:
        page = self.editor().get("/proxies/alpha/shop/edit").text

        self.assertEqual(self.carried(page, "advanced"), yaml.safe_load(HANDWRITTEN)["advanced"])
        self.assertEqual(self.carried(page, "handwritten_pool"), "on")
        self.assertNotIn('name="servers"', page)
        self.assertNotIn('name="balance"', page)
        self.assertNotIn('name="health_type"', page)
        self.assertIn("Written in the advanced config", page)

    def test_a_save_writes_the_text_back_as_it_was(self) -> None:
        client = self.editor()
        page = client.get("/proxies/alpha/shop/edit").text
        #
        # As a browser posts it: every line ending in CRLF.
        #
        text = self.carried(page, "advanced") or ""
        self.assertTrue(text)

        answer = self.submit(
            client,
            "/proxies/alpha/shop/edit",
            action="save",
            expected_revision="3",
            servers="",
            advanced=text.replace("\n", "\r\n"),
            handwritten_pool="on",
        )

        self.assertEqual(answer.status_code, 303)
        saved = yaml.safe_load(self.saved[0]["yaml"])
        self.assertEqual(saved["advanced"], yaml.safe_load(HANDWRITTEN)["advanced"])
        self.assertEqual(saved["backends"], {"web": {"servers": []}})

    def test_an_object_without_text_carries_an_empty_one(self) -> None:
        self.draft = None

        page = self.editor().get("/proxies/alpha/shop/edit").text

        self.assertEqual(self.carried(page, "advanced"), "")
        self.assertIsNone(self.carried(page, "handwritten_pool"))
        self.assertIn('name="servers"', page)


class SavedChangesAndDrafts(EditorTestCase):
    """B257: a draft is unfinished and never published; a saved change is."""

    def setUp(self) -> None:
        super().setUp()
        self.queued: list[dict[str, Any]] = []
        patch = mock.patch("haprion_ui.db.queue_job", side_effect=self._queue)
        patch.start()
        self.addCleanup(patch.stop)

    def _queue(self, _c: object, **values: Any) -> Any:
        self.queued.append(values)
        return SimpleNamespace(id=1, request_id=uuid4())

    def row(self, stage: str, revision: int, **overrides: Any) -> ProxyDraft:
        return ProxyDraft(
            cluster="alpha",
            object_id=overrides.pop("object_id", "shop"),
            yaml=overrides.pop("yaml", SHOP),
            base_version=12,
            base_hash=COMMIT,
            revision=revision,
            updated_by="operator",
            updated_at=OBSERVED,
            deleted=False,
            stage=stage,
            **overrides,
        )

    def test_save_writes_the_saved_change_and_drops_the_draft_it_came_from(self) -> None:
        self.draft = self.row("draft", 4)
        client = self.editor()

        answer = self.submit(
            client, "/proxies/alpha/shop/edit", action="save", expected_revision="4"
        )

        self.assertEqual(answer.status_code, 303)
        (change,) = self.changes
        self.assertEqual((change["draft_revision"], change["saved_revision"]), (4, None))

    def test_save_as_draft_leaves_the_saved_change_alone(self) -> None:
        self.draft = self.row("saved", 2)
        client = self.editor()
        page = client.get("/proxies/alpha/shop/edit").text
        self.assertIn('name="saved_revision" value="2"', page)

        self.submit(client, "/proxies/alpha/shop/edit", action="draft", saved_revision="2")

        self.assertEqual(self.changes, [])
        self.assertEqual(self.saved[0]["expected_revision"], None)

    def test_a_saved_rename_is_published_with_the_removal_later(self) -> None:
        """Renamed and saved first, the publish from the new name still removes the old.

        Worked out at the moment of publishing, the old name was lost once the
        rename had been saved: the editor then sat on the new name, and its
        publish added the new object beside the old one.
        """

        client = self.editor()
        self.submit(client, "/proxies/alpha/shop/edit", action="save", name="bazaar")
        self.assertEqual(self.changes[0]["replaces"], "shop")

        #
        # And a later save from the new name keeps it, so the publish that
        # eventually carries the row removes the old name (see the package
        # tests for that publish).
        #
        self.draft = self.row(
            "saved", 1, object_id="bazaar", yaml=SHOP.replace("shop", "bazaar"), replaces="shop"
        )
        self.submit(
            client,
            "/proxies/alpha/bazaar/edit",
            action="save",
            name="bazaar",
            saved_revision="1",
            servers="192.0.2.11:8080",
        )

        self.assertEqual(self.changes[-1]["replaces"], "shop")

    def test_renamed_back_it_replaces_nothing(self) -> None:
        self.draft = self.row(
            "saved", 1, object_id="bazaar", yaml=SHOP.replace("shop", "bazaar"), replaces="shop"
        )
        client = self.editor()

        answer = self.submit(
            client, "/proxies/alpha/bazaar/edit", action="save", name="shop", saved_revision="1"
        )

        self.assertEqual(answer.status_code, 303)
        self.assertIsNone(self.changes[0]["replaces"])
        self.assertEqual(self.saved[0]["object_id"], "shop")

    def test_a_draft_cannot_rename_an_object_with_saved_changes(self) -> None:
        self.draft = self.row("saved", 2)
        client = self.editor()

        answer = self.submit(
            client, "/proxies/alpha/shop/edit", action="draft", name="bazaar", saved_revision="2"
        )

        self.assertEqual(answer.status_code, 400)
        self.assertIn("can only change with Save", answer.text)
        self.assertEqual((self.saved, self.renamed), ([], []))

    def test_discard_without_a_draft_discards_the_saved_change(self) -> None:
        self.draft = self.row("saved", 2)
        client = self.editor()

        with mock.patch("haprion_ui.db.discard_draft") as discard:
            self.submit(client, "/proxies/alpha/shop/edit", action="discard", saved_revision="2")

        self.assertEqual(discard.call_args.kwargs["stage"], "saved")
        self.assertEqual(discard.call_args.kwargs["expected_revision"], 2)

    def test_the_page_says_which_it_is(self) -> None:
        self.draft = self.row("saved", 2)

        page = self.editor().get("/proxies/alpha/shop/edit").text

        self.assertIn("<h3>Saved, not published</h3>", page)
        self.assertNotIn("The form below was opened", page)
        self.assertIn("Discard the changes", page)
