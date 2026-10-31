"""Settings -> External blocking (B412): the card, the page, and the jobs they queue."""

from __future__ import annotations

import base64
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any
from unittest import mock

from haprion_ui import auth, external_blocking
from tests.test_login import configuration
from tests.test_queue_route import KEY, QueueRouteTestCase


def made_key(fill: int) -> str:
    """An ed25519 public key's shape around 32 made-up bytes: no key anybody holds."""

    blob = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + bytes([fill]) * 32
    return "ssh-ed25519 " + base64.b64encode(blob).decode()


ROW = external_blocking.ClientRow(
    client_id="app-f2b",
    host="app.example.com",
    cluster="alpha",
    objects=("shop",),
    fingerprint="SHA256:abc",
    added_by="admin",
    added_at=datetime(2026, 10, 31, 12, 0, tzinfo=UTC),
)


class Page(QueueRouteTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.rows: tuple[external_blocking.ClientRow, ...] = (ROW,)
        patch = mock.patch(
            "haprion_ui.external_blocking.read",
            side_effect=lambda _path: external_blocking.Clients(self.rows),
        )
        patch.start()
        self.addCleanup(patch.stop)
        choices = mock.patch(
            "haprion_ui.external_blocking.blocking_objects",
            side_effect=lambda _readings, cluster: ("shop", "store") if cluster == "alpha" else (),
        )
        choices.start()
        self.addCleanup(choices.stop)

    def admin(self) -> Any:
        client = self.client(
            replace(configuration(), management_writes=True, clusters=("alpha", "beta"))
        )
        self.sign_in(client)
        return client

    def post_to(self, browser: Any, path: str, **fields: Any) -> Any:
        token = browser.cookies[auth.SESSION_COOKIE]
        data = {auth.CSRF_FIELD: auth.csrf_token(token), "idempotency_key": KEY, **fields}
        return browser.post(path, data=data, follow_redirects=False)


class TheCardAndThePage(Page):
    def test_the_card_lists_each_client_and_leads_to_its_page(self) -> None:
        client = self.admin()

        card = client.get("/settings").text.split('id="external-blocking"', 1)[1]
        card = card.split("</section>", 1)[0]

        self.assertIn("<h3>External blocking</h3>", card)
        self.assertIn("<strong>app-f2b</strong>", card)
        self.assertIn("<code>app.example.com</code>", card)
        self.assertIn('href="/settings/external-blocking">Edit</a>', card)

    def test_without_clients_the_card_says_so(self) -> None:
        self.rows = ()
        card = self.admin().get("/settings").text.split('id="external-blocking"', 1)[1]

        self.assertIn("No client may block", card.split("</section>", 1)[0])

    def test_the_page_offers_the_proxies_that_block_as_boxes(self) -> None:
        page = self.admin().get("/settings/external-blocking").text

        self.assertIn('value="alpha/shop"', page)
        self.assertIn('value="alpha/store"', page)
        self.assertIn("<code>SHA256:abc</code>", page)
        self.assertIn('href="/settings/external-blocking?remove=app-f2b">Remove</a>', page)


class AddingAndRemoving(Page):
    def test_an_addition_queues_the_client_with_who_asked(self) -> None:
        response = self.post_to(
            self.admin(),
            "/settings/external-blocking/add",
            client="web-f2b",
            host="web.example.com",
            objects=["alpha/shop", "alpha/store"],
            key=made_key(3),
        )

        self.assertEqual(response.status_code, 303, response.text)
        (queued,) = self.queued
        self.assertEqual((queued["operation"], queued["cluster"]), ("block_client", "alpha"))
        self.assertEqual(
            queued["payload"],
            {
                "action": "add",
                "client": "web-f2b",
                "host": "web.example.com",
                "objects": ["shop", "store"],
                "key": made_key(3),
                "requested_by": "operator",
            },
        )

    def test_proxies_from_two_clusters_or_none_queue_nothing(self) -> None:
        for objects in (["alpha/shop", "beta/api"], []):
            with self.subTest(objects):
                response = self.post_to(
                    self.admin(),
                    "/settings/external-blocking/add",
                    client="web-f2b",
                    host="web.example.com",
                    objects=objects,
                    key=made_key(3),
                )
                self.assertEqual(response.status_code, 400)
        self.assertEqual(self.queued, [])

    def test_a_key_that_is_not_one_is_refused_on_the_page(self) -> None:
        response = self.post_to(
            self.admin(),
            "/settings/external-blocking/add",
            client="web-f2b",
            host="web.example.com",
            objects=["alpha/shop"],
            key="ssh-rsa AAAA",
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("<h1>External blocking</h1>", response.text)
        self.assertIn("not an ssh-ed25519 key", response.text)
        self.assertEqual(self.queued, [])

    def test_a_removal_asks_for_the_name_and_then_queues_it(self) -> None:
        browser = self.admin()

        asked = self.post_to(browser, "/settings/external-blocking/remove", client="app-f2b")
        wrong = self.post_to(
            browser, "/settings/external-blocking/remove", client="app-f2b", confirm="app"
        )
        done = self.post_to(
            browser, "/settings/external-blocking/remove", client="app-f2b", confirm="app-f2b"
        )

        self.assertEqual(asked.status_code, 200)
        self.assertIn("Type app-f2b to remove it", asked.text)
        self.assertEqual(wrong.status_code, 400)
        self.assertEqual(done.status_code, 303, done.text)
        (queued,) = self.queued
        self.assertEqual(
            (queued["operation"], queued["cluster"], queued["payload"]),
            (
                "block_client",
                "alpha",
                {"action": "remove", "client": "app-f2b", "requested_by": "operator"},
            ),
        )
