"""Deleting certificates from the registry view: the boxes, the question, the job.

What is held here is the interface's half of B139: a box per row and a button
that is grey until something is ticked; a confirmation page that says what
deleting each chosen certificate means and refuses, on the row, the one a
draft still names; and a job that carries only what passed. The helper's
guards are tested with the engine.
"""

from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any
from unittest import mock
from uuid import uuid4

from haproxy_ui import auth, certificate_delete, db, jobs
from tests.test_certificates import reading as certificate_reading
from tests.test_certificates import registered, with_registry
from tests.test_login import LoginTestCase, configuration
from tests.test_queue_route import queued

SHOP_DRAFT = db.ProxyDraft(
    cluster="alpha",
    object_id="shop",
    yaml=(
        "schema: 1\nname: shop\nhostnames: [shop.example.com]\n"
        "listen:\n  protocol: https\n  certificate: old.example.com\n"
        "routes:\n  - path: /\n    backend: web\n"
        "backends:\n  web:\n    balance: roundrobin\n    health:\n      type: disabled\n"
        "    servers:\n      - host: 192.0.2.10\n        port: 8080\n"
    ),
    base_version=7,
    base_hash="a" * 40,
    revision=1,
    updated_by="admin",
    updated_at=datetime(2026, 9, 13, 20, 0, tzinfo=UTC),
    deleted=False,
)


class DraftReferences(unittest.TestCase):
    def test_a_live_draft_naming_the_certificate_is_found_and_an_unparsable_one_is_not(
        self,
    ) -> None:
        broken = replace(SHOP_DRAFT, object_id="broken", yaml="listen: [")
        found = certificate_delete.draft_references(
            [SHOP_DRAFT, broken], ["old.example.com", "other.example"]
        )
        self.assertEqual(found, {"old.example.com": ("alpha/shop",)})


class DeleteRouteTestCase(LoginTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.queued: list[dict[str, Any]] = []
        self.drafts: list[db.ProxyDraft] = []

        def queue(_c: object, **fields: Any) -> db.Job:
            self.queued.append(fields)
            return queued(operation="cert_delete", cluster=None)

        for patch in (
            mock.patch("haproxy_ui.db.queue_job", side_effect=queue),
            mock.patch("haproxy_ui.db.live_drafts", side_effect=lambda _c: list(self.drafts)),
            mock.patch("haproxy_ui.db.recent_jobs", return_value=[]),
            mock.patch(
                "haproxy_ui.db.cluster_certificates",
                return_value=[
                    with_registry(
                        certificate_reading(),
                        registered(fingerprint="a" * 64),
                        registered("old.example.com", fingerprint="b" * 64),
                        registered("imported.example", kind="import", fingerprint="d" * 64),
                    )
                ],
            ),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def writing_client(self, *, role: str = "admin", writes: bool = True) -> Any:
        self.account = replace(self.account, role=role)
        client = self.client(
            replace(configuration(), management_writes=writes, clusters=("alpha",))
        )
        self.sign_in(client)
        return client

    def review(self, client: Any, *ids: str) -> Any:
        token = auth.csrf_token(client.cookies[auth.SESSION_COOKIE])
        return client.post(
            "/certificates/delete", data={"certificate": list(ids), auth.CSRF_FIELD: token}
        )

    def confirm(self, client: Any, *ids: str, key: str | None = None) -> Any:
        token = auth.csrf_token(client.cookies[auth.SESSION_COOKIE])
        return client.post(
            "/certificates/delete/confirm",
            data={
                "certificate": list(ids),
                "idempotency_key": key or str(uuid4()),
                auth.CSRF_FIELD: token,
            },
            follow_redirects=False,
        )


class TheRegistryViewOffersTheBoxes(DeleteRouteTestCase):
    def test_an_admin_with_writes_gets_a_box_per_row_and_a_grey_button(self) -> None:
        page = self.writing_client().get("/certificates?view=registry").text
        self.assertIn('action="/certificates/delete"', page)
        self.assertEqual(page.count("data-delete-pick"), 3)
        self.assertIn("data-delete-submit disabled>Delete selected", page)
        #
        # The detail row spans the box column too.
        #
        opened = self.writing_client().get("/certificates?view=registry&open=old.example.com").text
        self.assertIn('<tr class="registry-detail"><td colspan="8">', opened)

    def test_a_reader_and_a_read_only_installation_get_no_boxes(self) -> None:
        self.assertNotIn(
            "data-delete-pick",
            self.writing_client(role="reader").get("/certificates?view=registry").text,
        )
        self.assertNotIn(
            "data-delete-pick",
            self.writing_client(writes=False).get("/certificates?view=registry").text,
        )


class TheConfirmationPage(DeleteRouteTestCase):
    def test_it_says_what_each_chosen_certificate_loses(self) -> None:
        page = self.review(self.writing_client(), "old.example.com", "imported.example").text
        self.assertIn("Delete <strong>2</strong> certificates?", page)
        self.assertIn("Certbot lineage is deleted", page)
        self.assertIn("import store is removed", page)
        self.assertIn('name="certificate" value="old.example.com"', page)
        self.assertIn('name="certificate" value="imported.example"', page)
        self.assertIn(">Delete 2 certificates</button>", page)
        self.assertEqual(self.queued, [])

    def test_a_certificate_a_draft_names_is_kept_on_its_row_and_left_out_of_the_form(
        self,
    ) -> None:
        self.drafts = [SHOP_DRAFT]
        page = self.review(self.writing_client(), "old.example.com", "imported.example").text
        self.assertIn("A draft still names it: alpha/shop.", page)
        self.assertIn("Delete <strong>1</strong> certificate?", page)
        self.assertNotIn('name="certificate" value="old.example.com"', page)
        self.assertIn('name="certificate" value="imported.example"', page)

    def test_an_unregistered_id_and_an_empty_selection_are_said(self) -> None:
        client = self.writing_client()
        self.assertIn("Not in the registry", self.review(client, "nobody.example").text)
        self.assertIn("Nothing is selected", self.review(client).text)

    def test_the_gates_are_the_certificate_form_s(self) -> None:
        self.assertEqual(
            self.review(self.writing_client(role="reader"), "x.example").status_code, 403
        )
        self.assertEqual(
            self.review(self.writing_client(writes=False), "x.example").status_code, 404
        )
        client = self.writing_client()
        without_token = client.post("/certificates/delete", data={"certificate": ["x.example"]})
        self.assertEqual(without_token.status_code, 403)


class Confirming(DeleteRouteTestCase):
    def test_queues_one_clusterless_job_with_exactly_the_deletable_ids(self) -> None:
        response = self.confirm(self.writing_client(), "old.example.com", "imported.example")
        self.assertEqual(response.status_code, 303)
        # Back to the listing, whose State cell now follows the job.
        self.assertEqual(response.headers["location"], "/certificates?view=registry")
        (job,) = self.queued
        self.assertEqual(job["operation"], "cert_delete")
        self.assertIsNone(job["cluster"])
        #
        # In the registry's order, not the form's: the page lists by name.
        #
        self.assertEqual(job["payload"], {"certificates": ["imported.example", "old.example.com"]})
        self.assertIn("queue_job", self.audit)

    def test_a_draft_written_since_the_question_asks_it_again_and_queues_nothing(self) -> None:
        self.drafts = [SHOP_DRAFT]
        response = self.confirm(self.writing_client(), "old.example.com", "imported.example")
        self.assertEqual(response.status_code, 200)
        self.assertIn("something changed for old.example.com", response.text)
        self.assertIn("A draft still names it", response.text)
        self.assertEqual(self.queued, [])

    def test_nothing_deletable_draws_the_page_again_and_queues_nothing(self) -> None:
        self.drafts = [SHOP_DRAFT]
        response = self.confirm(self.writing_client(), "old.example.com")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Nothing in the selection can be deleted", response.text)
        self.assertEqual(self.queued, [])

    def test_a_busy_certificate_slot_is_said_on_the_page(self) -> None:
        with mock.patch("haproxy_ui.db.queue_job", side_effect=db.CertificateBusy()):
            response = self.confirm(self.writing_client(), "old.example.com")
        self.assertEqual(response.status_code, 200)
        self.assertIn("already running", response.text)


class TheJobsPageSaysWhatHappened(unittest.TestCase):
    def test_the_note_lists_each_state_with_its_reason(self) -> None:
        job = queued(operation="cert_delete", cluster=None)
        job = replace(
            job,
            state="done",
            outcome="partial",
            result={
                "result": {
                    "certificates": [
                        {"certificate": "old.example.com", "state": "removed"},
                        {
                            "certificate": "shop.example.com",
                            "state": "refused",
                            "code": "referenced_by_object",
                        },
                        {
                            "certificate": "gone.example.com",
                            "state": "incomplete",
                            "layers": [{"layer": "registry", "state": "removed"}],
                            "nodes": [{"cluster": "alpha", "node": "node-b", "state": "kept"}],
                        },
                    ]
                }
            },
        )
        self.assertEqual(
            jobs.deletion_note(job),
            "Deleted: old.example.com. Refused: shop.example.com (referenced_by_object). "
            "Left; delete them again to finish: gone.example.com (node-b kept).",
        )
        self.assertIsNone(jobs.deletion_note(queued(operation="cert_issue", cluster=None)))

    def test_a_target_change_says_why_it_refused_and_why_it_stopped(self) -> None:
        """The helper's reason is the sentence the operator needs; the code alone was not.

        Seen on a machine: a refused target change showed only
        `(https_receiver_isolated)`, and one that stopped half-way borrowed
        the deletion's "delete them again", which is not what fixes it.
        """

        job = replace(
            queued(operation="cert_target", cluster=None),
            state="blocked",
            outcome="blocked",
            result={
                "result": {
                    "certificates": [
                        {
                            "certificate": "wild.example",
                            "state": "refused",
                            "code": "https_receiver_isolated",
                            "reason": "receiver 192.0.2.40 fetches over https, and wild.example "
                            "is carried by a cluster.",
                        },
                        {
                            "certificate": "plain.example",
                            "state": "incomplete",
                            "code": "write_failed",
                            "reason": "registered but not published: /srv/x/fullchain.pem: "
                            "[Errno 1] Operation not permitted",
                            "added": ["192.0.2.40"],
                        },
                        {"certificate": "other.example", "state": "changed"},
                    ]
                }
            },
        )
        self.assertEqual(
            jobs.deletion_note(job),
            "Changed: other.example. "
            "Refused: wild.example (https_receiver_isolated) - receiver 192.0.2.40 fetches "
            "over https, and wild.example is carried by a cluster. "
            "Registered but not published; publish again once the cause is fixed: "
            "plain.example (write_failed) - registered but not published: "
            "/srv/x/fullchain.pem: [Errno 1] Operation not permitted.",
        )

    def test_a_deletion_where_every_row_went_has_no_note(self) -> None:
        job = replace(
            queued(operation="cert_delete", cluster=None),
            state="done",
            outcome="done",
            result={
                "result": {"certificates": [{"certificate": "old.example.com", "state": "removed"}]}
            },
        )
        self.assertIsNone(jobs.deletion_note(job))


if __name__ == "__main__":
    unittest.main()
