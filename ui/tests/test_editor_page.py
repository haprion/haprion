"""The editor: who may reach it, what it opens with, and what it refuses to write.

The document machinery is tested next door, in `test_object_form`. What is
worth testing here are the boundaries the route owns - the role, the write
switch, the revision two tabs disagree about, and the two shapes of refusal
that must not become a saved draft.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from typing import Any
from unittest import mock

from haproxy_ui import auth
from haproxy_ui.db import ClusterNetwork, ClusterObjects, DraftConflict, ProxyDraft
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
        self.discarded: list[tuple[str, str, int]] = []
        self.draft: ProxyDraft | None = None
        self.conflict = False
        for target, side_effect in (
            ("cluster_objects", lambda _c: [OBJECTS]),
            ("cluster_networks", lambda _c: [NETWORK]),
            ("read_draft", self._read_draft),
            ("save_draft", self._save_draft),
            ("discard_draft", self._discard_draft),
        ):
            patch = mock.patch(f"haproxy_ui.db.{target}", side_effect=side_effect)
            patch.start()
            self.addCleanup(patch.stop)

    def _read_draft(self, _c: object, cluster: str, object_id: str) -> ProxyDraft | None:
        del cluster, object_id
        return self.draft

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

    def test_the_name_cannot_be_changed_on_an_existing_object(self) -> None:
        page = self.editor().get("/proxies/alpha/shop/edit")

        self.assertIn("readonly", page.text)

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

    def test_a_rename_is_refused(self) -> None:
        client = self.editor()

        answer = self.submit(client, "/proxies/alpha/shop/edit", action="save", name="bazaar")

        self.assertEqual(answer.status_code, 400)
        self.assertEqual(self.saved, [])

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
