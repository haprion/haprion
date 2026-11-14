"""Certificates -> HTTP-01: where each cluster sends Let's Encrypt's challenge (PL17).

Held here: the list says one line per cluster and offers *Edit* to an admin only;
the cluster's page saves the `acme_challenge` field through the settings draft and
keeps everything else the settings hold - the other page of the same file keeps the
challenge in turn; an address is an IP address, never a name; the Certificates page
offers the button only where HTTP-01 is, and the certificate form says when no
cluster sends the challenge anywhere.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from typing import Any
from unittest import mock

from haprion.cluster_settings import AcmeChallenge, load_document

from haprion_ui import auth, demo, http01_page
from haprion_ui.cluster_settings_page import FormProblem
from tests.test_login import configuration
from tests.test_queue_route import KEY, QueueRouteTestCase
from tests.test_settings_cluster import SettingsClusterTestCase

NOW = datetime(2026, 11, 14, 12, 0, tzinfo=UTC)


class TheRows(QueueRouteTestCase):
    def test_one_line_per_cluster_in_the_listed_order(self) -> None:
        rows = http01_page.rows(
            ("service-demo", "edge-demo", "never-read"), demo.settings_rows(NOW)
        )
        self.assertEqual(
            [(row.cluster, row.readable, row.sent_to) for row in rows],
            [
                ("service-demo", True, http01_page.NOT_SENT),
                ("edge-demo", True, "192.0.2.5:80"),
                ("never-read", False, ""),
            ],
        )

    def test_an_ipv6_address_is_bracketed(self) -> None:
        self.assertEqual(
            http01_page.target(AcmeChallenge("2001:db8::5", 8080)), "[2001:db8::5]:8080"
        )


class TheForm(QueueRouteTestCase):
    def test_a_name_is_not_an_address_and_is_said_in_the_forms_words(self) -> None:
        with self.assertRaisesRegex(
            FormProblem, r"^The manager address must be an IP address, not a name"
        ):
            http01_page.challenge_from(http01_page.Http01Form(True, "manager.example.com", "80"))

    def test_the_port_is_80_when_left_empty_and_a_number_otherwise(self) -> None:
        self.assertEqual(
            http01_page.challenge_from(http01_page.Http01Form(True, "192.0.2.5", "")),
            AcmeChallenge("192.0.2.5", 80),
        )
        with self.assertRaisesRegex(FormProblem, "port must be a number"):
            http01_page.challenge_from(http01_page.Http01Form(True, "192.0.2.5", "http"))
        with self.assertRaisesRegex(FormProblem, "^The port must be a port"):
            http01_page.challenge_from(http01_page.Http01Form(True, "192.0.2.5", "70000"))

    def test_off_is_no_challenge_whatever_else_was_typed(self) -> None:
        self.assertIsNone(http01_page.challenge_from(http01_page.Http01Form(False, "x", "y")))


class ThePages(SettingsClusterTestCase):
    def save(self, client: Any, cluster: str = "edge-demo", **fields: Any) -> Any:
        token = client.cookies[auth.SESSION_COOKIE]
        data: dict[str, Any] = {
            auth.CSRF_FIELD: auth.csrf_token(token),
            "expected_head": "a" * 40,
            "idempotency_key": KEY,
            **fields,
        }
        return client.post(f"/http01/{cluster}", data=data, follow_redirects=False)

    def test_the_list_is_a_readers_and_the_edit_an_admins(self) -> None:
        admin = self.client_for().get("/http01")
        self.assertEqual(admin.status_code, 200)
        self.assertIn('data-href="/http01/edge-demo"', admin.text)
        self.assertIn("<code>192.0.2.5:80</code>", admin.text)
        self.assertIn("Not sent — HTTP-01 cannot be used", admin.text)
        reader = self.client_for(role="reader").get("/http01")
        self.assertEqual(reader.status_code, 200)
        self.assertNotIn("/http01/edge-demo", reader.text)
        self.assertNotIn(">Edit<", reader.text)
        self.assertEqual(self.client_for(role="reader").get("/http01/edge-demo").status_code, 403)
        self.assertEqual(self.client_for().get("/http01/elsewhere").status_code, 404)

    def test_the_list_shows_a_saved_change_that_is_not_published_yet(self) -> None:
        draft = mock.Mock(document="acme_challenge: {address: 192.0.2.9, port: 8080}\n", revision=1)
        with mock.patch(
            "haprion_ui.pages.settings.settled_changes", return_value={"settings": draft}
        ):
            page = self.client_for().get("/http01").text

        self.assertIn("<code>192.0.2.9:8080</code>", page)
        self.assertIn("Saved · not published", page)
        self.assertNotIn("<code>192.0.2.5:80</code>", page)

    def test_the_list_says_a_published_change_waits_for_the_deploy(self) -> None:
        with mock.patch(
            "haprion_ui.pages.settings.network.awaiting_deploy",
            return_value=frozenset({"edge-demo"}),
        ):
            page = self.client_for().get("/http01").text

        self.assertEqual(page.count("Reconfigured · deploy to activate"), 1)
        self.assertNotIn("Saved · not published", page)

    def test_the_list_says_nothing_extra_when_nothing_is_saved_or_waiting(self) -> None:
        page = self.client_for().get("/http01").text

        self.assertNotIn("Saved · not published", page)
        self.assertNotIn("deploy to activate", page)

    def test_the_form_shows_the_clusters_address(self) -> None:
        page = self.client_for().get("/http01/edge-demo").text
        self.assertIn('value="192.0.2.5"', page)
        self.assertIn("checked", page.split('name="acme_on"')[1].split(">")[0])
        self.assertIn(
            "The challenge path answers from everywhere, also on proxies that are reachable "
            "from some addresses only.",
            page,
        )

    def test_a_save_changes_the_challenge_and_keeps_every_other_setting(self) -> None:
        response = self.save(
            self.client_for(), acme_on="on", acme_address="192.0.2.9", acme_port="8080"
        )

        self.assertEqual(response.status_code, 303, response.text)
        self.assertEqual(response.headers["location"], "/http01")
        self.assertEqual(self.queued, [])
        (change,) = self.saved_changes
        settings = load_document(change["document"].encode())
        self.assertEqual(settings.acme_challenge, AcmeChallenge("192.0.2.9", 8080))
        self.assertEqual([target.name for target in settings.log_targets], ["graylog", "loki"])
        self.assertTrue(settings.log_targets[1].tls)
        self.assertEqual(settings.metrics.port, 8405)  # type: ignore[union-attr]
        self.assertEqual(settings.peers.port, 10000)  # type: ignore[union-attr]
        self.assertEqual((change["base_hash"], change["updated_by"]), ("a" * 40, "operator"))

    def test_off_removes_only_the_challenge(self) -> None:
        response = self.save(self.client_for())

        self.assertEqual(response.status_code, 303, response.text)
        (change,) = self.saved_changes
        settings = load_document(change["document"].encode())
        self.assertIsNone(settings.acme_challenge)
        self.assertEqual(settings.peers.port, 10000)  # type: ignore[union-attr]
        self.assertNotIn("acme_challenge", change["document"])

    def test_a_cluster_with_no_settings_gets_a_document_of_the_challenge_alone(self) -> None:
        response = self.save(
            self.client_for(), "service-demo", acme_on="on", acme_address="2001:db8::5"
        )

        self.assertEqual(response.status_code, 303, response.text)
        (change,) = self.saved_changes
        self.assertEqual(
            load_document(change["document"].encode()).acme_challenge,
            AcmeChallenge("2001:db8::5", 80),
        )

    def test_a_saved_draft_is_what_the_save_starts_from(self) -> None:
        draft = mock.Mock(document="peers:\n  port: 10001\n", revision=3, updated_by="operator")
        with mock.patch(
            "haprion_ui.pages.settings.settled_changes", return_value={"settings": draft}
        ):
            response = self.save(
                self.client_for(), saved_revision="3", acme_on="on", acme_address="192.0.2.9"
            )
            page = self.client_for().get("/http01/edge-demo").text

        self.assertEqual(response.status_code, 303, response.text)
        (change,) = self.saved_changes
        settings = load_document(change["document"].encode())
        self.assertEqual(settings.peers.port, 10001)  # type: ignore[union-attr]
        self.assertEqual(settings.log_targets, ())
        self.assertEqual(change["expected_revision"], 3)
        self.assertIn("Saved changes", page)

    def test_a_name_is_refused_on_the_page_and_saves_nothing(self) -> None:
        response = self.save(self.client_for(), acme_on="on", acme_address="manager.example.com")

        self.assertEqual(response.status_code, 400)
        self.assertIn("The manager address must be an IP address, not a name", response.text)
        self.assertIn('value="manager.example.com"', response.text)
        self.assertEqual(self.saved_changes, [])

    def test_an_address_is_needed_when_it_is_on(self) -> None:
        response = self.save(self.client_for(), acme_on="on", acme_address=" ")

        self.assertEqual(response.status_code, 400)
        self.assertIn("The manager address is needed.", response.text)

    def test_a_forged_form_is_refused(self) -> None:
        response = self.client_for().post(
            "/http01/edge-demo",
            data={auth.CSRF_FIELD: "forged", "expected_head": "a" * 40},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.saved_changes, [])

    def test_saving_logs_and_metrics_keeps_the_challenge(self) -> None:
        client = self.client_for()
        token = client.cookies[auth.SESSION_COOKIE]
        response = client.post(
            "/settings/clusters/edge-demo",
            data={
                auth.CSRF_FIELD: auth.csrf_token(token),
                "expected_head": "a" * 40,
                "target_name": ["graylog", ""],
                "target_address": ["192.0.2.60", ""],
                "target_port": ["6514", ""],
                "target_disk": ["", ""],
                "target_tls": ["no", "no"],
            },
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303, response.text)
        (change,) = self.saved_changes
        self.assertEqual(
            load_document(change["document"].encode()).acme_challenge,
            AcmeChallenge("192.0.2.5", 80),
        )


class TheCertificatePages(SettingsClusterTestCase):
    def certificates(self, *, webroot: bool) -> str:
        with mock.patch("haprion_ui.certificate_form.http01_offered", return_value=webroot):
            return str(self.client_for().get("/certificates").text)

    def test_the_button_is_beside_the_profile_buttons_and_only_with_a_webroot(self) -> None:
        with_webroot = self.certificates(webroot=True)
        self.assertIn(
            '<a class="secondary-button" href="/ndes-profiles">NDES profiles</a>'
            '<a class="secondary-button" href="/http01">HTTP-01</a>',
            with_webroot,
        )
        self.assertNotIn('href="/http01"', self.certificates(webroot=False))

    def test_the_form_says_when_no_cluster_sends_the_challenge(self) -> None:
        said = "No cluster sends the challenge to this manager yet."
        sent = mock.patch("haprion_ui.certificate_form.http01_offered", return_value=True)
        with sent:
            self.assertNotIn(said, self.client_for().get("/certificates/new").text)
        silent = [
            replace(row, result={**row.result, "acme_challenge": None})
            for row in demo.settings_rows(NOW)
        ]
        with (
            sent,
            mock.patch("haprion_ui.db.cluster_settings", return_value=silent),
        ):
            page = self.client_for().get("/certificates/new").text
        self.assertIn(said, page)
        self.assertIn('<a href="/http01">HTTP-01</a>', page)
        with (
            mock.patch("haprion_ui.certificate_form.http01_offered", return_value=False),
            mock.patch("haprion_ui.db.cluster_settings", return_value=silent),
        ):
            self.assertNotIn(said, self.client_for().get("/certificates/new").text)


_ = configuration
