"""A BMC receiver's page (B526, B536, B538): Add a BMC, Check, Save and install, Install now, Change… and Remove….

The page is the control: only an admin with writes reaches the BMC service,
the account is sealed in the request that typed it and never drawn again, and
what is saved is only what the administrator confirmed, carrying the
certificate that was chosen.
"""

from __future__ import annotations

import base64
import json
import tempfile
from dataclasses import replace
from pathlib import Path
from typing import Any
from unittest import mock

from haprion.bmc_socket import BmcAskError
from haprion.dns_profile_keys import generate, open_sealed, render_public_key

from haprion_ui import auth, db
from tests.test_certificate_form import KEY, CertificateFormRouteTestCase
from tests.test_certificates import reading as certificate_reading
from tests.test_certificates import registered, with_registry
from tests.test_external_certificates import DEVICE, PINNED, external, with_bmc
from tests.test_login import configuration

SERVED = "4f" * 32
NEW = "192.0.2.7"
#
# Assembled, so the secret scanner does not take it for one.
#
SECRET = "-".join(("not", "the", "real", "one"))
CHECKED = {
    "id": NEW,
    "address": NEW,
    "port": 443,
    "served_sha256": SERVED,
    "subject": DEVICE,
    "issuer": "Example Issuing CA",
    "not_after": "2026-12-20T00:00:00Z",
    "model": "X13SCL-IF",
    "firmware": "01.09.06",
    "may_upload": True,
}
PAGE = f"/certificates/receivers/bmc/{DEVICE}"


def bmc_record(identifier: str = DEVICE, certificate: str | None = DEVICE) -> dict[str, Any]:
    return {
        "id": identifier,
        "port": 443,
        "username": "admin",
        "fingerprint_sha256": PINNED,
        "certificate": certificate,
    }


class BmcPageTestCase(CertificateFormRouteTestCase):
    entry: dict[str, Any] = external()
    bmcs: tuple[dict[str, Any], ...] = ()

    def setUp(self) -> None:
        super().setUp()
        self.private_key, self.public_key = generate()
        keys = tempfile.TemporaryDirectory()
        self.addCleanup(keys.cleanup)
        self.public_path = Path(keys.name) / f"{self.public_key.key_id}.pub"
        self.public_path.write_text(render_public_key(self.public_key))
        self.asked: list[tuple[str, str, dict[str, Any]]] = []
        self.answers: dict[str, Any] = {
            "check": CHECKED,
            "save": {
                "id": NEW,
                "address": NEW,
                "port": 443,
                "fingerprint_sha256": SERVED,
                "username": "admin",
                "certificate": DEVICE,
            },
            "assign": {"id": DEVICE, "certificate": DEVICE},
            "remove": {"id": DEVICE, "removed": True},
        }

        def ask(action: str, receiver_id: str, **parameters: Any) -> dict[str, Any]:
            self.asked.append((action, receiver_id, parameters))
            answer = self.answers[action]
            if isinstance(answer, Exception):
                raise answer
            return dict(answer)

        listing = with_registry(certificate_reading(), registered(fingerprint="a" * 64), self.entry)
        listing.result["registry"]["bmc_records"] = list(self.bmcs)  # type: ignore[index]
        for patch in (
            mock.patch("haprion.bmc_socket.ask", side_effect=ask),
            mock.patch("haprion_ui.db.wake_poller"),
            mock.patch("haprion_ui.db.cluster_certificates", return_value=[listing]),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def writing_client(self, *, role: str = "admin") -> Any:
        self.account = replace(self.account, role=role)
        client = self.client(
            replace(
                configuration(),
                management_writes=True,
                clusters=("alpha", "beta"),
                dns_profiles_public_key=self.public_path,
            )
        )
        self.sign_in(client)
        return client

    def send(self, client: Any, path: str, **fields: Any) -> Any:
        token = auth.csrf_token(client.cookies[auth.SESSION_COOKIE])
        return client.post(path, data={auth.CSRF_FIELD: token, **fields}, follow_redirects=False)

    def check(self, client: Any, **fields: Any) -> Any:
        return self.send(
            client,
            "/certificates/receivers/bmc/check",
            **{
                "address": NEW,
                "bmc_username": "admin",
                "password": SECRET,
                "certificate": DEVICE,
                **fields,
            },
        )

    def save(self, client: Any, **fields: Any) -> Any:
        return self.send(
            client,
            "/certificates/receivers/bmc/save",
            **{
                "address": NEW,
                "port": "443",
                "certificate": DEVICE,
                "fingerprint_sha256": SERVED,
                "key_id": self.public_key.key_id,
                "ciphertext_base64": base64.b64encode(b"x" * 64).decode(),
                "confirmed": "yes",
                "idempotency_key": KEY,
                **fields,
            },
        )


class AddingABmc(BmcPageTestCase):
    def test_the_page_asks_for_the_bmc_and_its_certificate_and_cannot_save_before_check(
        self,
    ) -> None:
        page = self.writing_client().get("/certificates/receivers/bmc/new").text

        self.assertIn("Add a BMC", page)
        for field in (
            'name="address"',
            'name="bmc_username"',
            'name="password"',
            'name="certificate"',
        ):
            self.assertIn(field, page)
        self.assertIn(f'<option value="{DEVICE}">{DEVICE}</option>', page)
        self.assertIn(">Check</button>", page)
        self.assertRegex(page, r'type="submit" disabled>Save and install</button>')
        self.assertEqual(self.asked, [])

    def test_check_seals_the_account_for_the_bmc_and_shows_what_it_serves(self) -> None:
        answer = self.check(self.writing_client())

        self.assertEqual(answer.status_code, 200)
        action, receiver_id, sent = self.asked[0]
        self.assertEqual((action, receiver_id, sent["port"]), ("check", NEW, 443))
        opened = json.loads(open_sealed(self.private_key, sent["ciphertext"]))
        self.assertEqual(
            (opened["receiver_id"], opened["username"], opened["password"]),
            (NEW, "admin", SECRET),
        )
        page = answer.text
        self.assertIn("4F:4F:4F", page)
        self.assertIn("X13SCL-IF · 01.09.06", page)
        self.assertIn("Signed in, may upload certificates", page)
        self.assertIn(base64.b64encode(sent["ciphertext"]).decode(), page)
        self.assertIn(f'name="certificate" value="{DEVICE}"', page)
        self.assertNotIn(SECRET, page)
        self.assertRegex(page, r'deploy-button" type="submit">Save and install</button>')

    def test_an_account_that_may_not_upload_cannot_be_saved(self) -> None:
        self.answers["check"] = {**CHECKED, "may_upload": False}
        page = self.check(self.writing_client()).text

        self.assertIn("the account needs the Administrator role", page)
        self.assertRegex(page, r'type="submit" disabled>Save and install</button>')

    def test_a_bmc_that_does_not_answer_names_the_port_to_open(self) -> None:
        self.answers["check"] = BmcAskError(
            "bmc_unreachable", f"{NEW}:443 did not answer: timed out"
        )
        page = self.check(self.writing_client()).text

        self.assertIn(f"{NEW} did not answer on port 443", page)
        self.assertIn("blocks port 443", page)
        self.assertIn(f'value="{NEW}"', page)
        self.assertNotIn(SECRET, page)

    def test_an_address_that_is_none_is_said_and_nothing_is_asked(self) -> None:
        page = self.check(self.writing_client(), address="bmc 01").text

        self.assertIn("bmc 01 is not a name or address.", page)
        self.assertEqual(self.asked, [])

    def test_save_writes_what_was_confirmed_with_its_certificate_and_starts_the_install(
        self,
    ) -> None:
        answer = self.save(self.writing_client())

        self.assertEqual(answer.status_code, 303)
        self.assertEqual(answer.headers["location"], f"/certificates/receivers/bmc/{NEW}")
        action, receiver_id, sent = self.asked[0]
        self.assertEqual(
            (
                action,
                receiver_id,
                sent["certificate"],
                sent["fingerprint_sha256"],
                sent["ciphertext"],
            ),
            ("save", NEW, DEVICE, SERVED, b"x" * 64),
        )
        self.assertIn("bmc_target_saved", self.audit)
        self.assertEqual(
            [(job["operation"], job["payload"]) for job in self.queued],
            [("bmc_install", {"id": NEW, "certificate": DEVICE, "by": "save"})],
        )

    def test_save_without_the_confirmation_or_a_certificate_asks_nothing(self) -> None:
        client = self.writing_client()
        answer = self.save(client, confirmed="")
        self.assertIn("Confirm that the fingerprint", answer.text)
        answer = self.save(client, certificate="")
        self.assertIn("Choose the certificate the BMC carries.", answer.text)
        answer = self.save(client, certificate="nowhere.example")
        self.assertIn("Choose the certificate the BMC carries.", answer.text)
        self.assertEqual((self.asked, self.queued), ([], []))

    def test_a_save_behind_another_certificate_job_is_saved_and_says_so(self) -> None:
        with mock.patch("haprion_ui.db.queue_job", side_effect=db.CertificateBusy()):
            answer = self.save(self.writing_client())

        self.assertIn("The BMC was saved, but its install was not started", answer.text)
        self.assertIn("bmc_target_saved", self.audit)

    def test_a_reader_is_refused_and_nothing_is_asked(self) -> None:
        client = self.writing_client(role="reader")
        self.assertEqual(client.get("/certificates/receivers/bmc/new").status_code, 403)
        self.assertEqual(self.check(client).status_code, 403)
        self.assertEqual(self.asked, [])

    def test_a_bmc_that_is_not_here_has_no_page(self) -> None:
        page = self.writing_client().get("/certificates/receivers/bmc/bmc09.example.com").text

        self.assertIn("bmc09.example.com is not a BMC here.", page)

    def test_the_certificates_bar_has_no_bmc_button_and_receivers_offers_add_a_bmc(self) -> None:
        client = self.writing_client()
        self.assertNotIn("BMC…</button>", client.get("/certificates?view=registry").text)
        page = client.get("/certificates/receivers").text
        self.assertIn('href="/certificates/receivers/bmc/new">Add a BMC</a>', page)
        self.assertIn("No BMC is added.", page)


class ABmcCarryingACertificate(BmcPageTestCase):
    entry = with_bmc(
        "installed",
        attempt={
            "fingerprint_sha256": "a" * 64,
            "at": "2026-11-26T03:12:00Z",
            "by": "timer",
            "outcome": "done",
            "code": None,
            "message": None,
            "seconds": 130.0,
            "firmware": "X13SCL-IF 01.09.06",
        },
    )
    bmcs = (bmc_record(), bmc_record("bmc02.example.com", None))

    def test_the_receivers_page_lists_each_bmc_with_what_it_carries(self) -> None:
        page = self.writing_client().get("/certificates/receivers").text

        self.assertIn(f'data-href="{PAGE}"', page)
        self.assertIn('data-href="/certificates/receivers/bmc/bmc02.example.com"', page)
        self.assertIn(">Installed</span>", page)
        self.assertIn(">No certificate</span>", page)
        self.assertIn("2 BMCs the manager installs a certificate on.", page)

    def test_the_page_says_where_with_whom_and_what_it_is_trusted_with(self) -> None:
        page = self.writing_client().get(PAGE).text

        self.assertIn("<strong>Redfish user</strong><span>admin</span>", page)
        self.assertIn(":".join(["AB"] * 32), page)
        self.assertIn("automatically · took 2 min 10 s", page)
        self.assertIn("Installed", page)
        self.assertIn(f'<option value="{DEVICE}" selected>{DEVICE}</option>', page)
        for control in ("Remove…", "Change…", ">Install now</button>", "Save certificate"):
            self.assertIn(control, page)
        self.assertNotIn('name="password"', page)

    def test_install_now_is_a_job_for_the_bmc(self) -> None:
        answer = self.send(self.writing_client(), f"{PAGE}/install", idempotency_key=KEY)

        self.assertEqual(answer.status_code, 303)
        self.assertEqual(
            [(job["operation"], job["payload"]) for job in self.queued],
            [("bmc_install", {"id": DEVICE, "certificate": DEVICE, "by": "install_now"})],
        )

    def test_another_certificate_is_chosen_without_the_account(self) -> None:
        answer = self.send(self.writing_client(), f"{PAGE}/assign", certificate=DEVICE)

        self.assertEqual(answer.status_code, 303)
        self.assertEqual(self.asked, [("assign", DEVICE, {"certificate": DEVICE})])
        self.assertIn("bmc_assigned", self.audit)

    def test_change_types_the_account_again_from_the_saved_bmc(self) -> None:
        page = self.writing_client().get(f"{PAGE}?do=change").text

        self.assertIn(f'name="address" value="{DEVICE}"', page)
        self.assertIn("readonly", page)
        self.assertIn('name="bmc_username" value="admin"', page)
        self.assertIn('name="password" type="password"', page)

    def test_remove_is_confirmed_on_its_own_page_and_then_asked_of_root(self) -> None:
        client = self.writing_client()
        page = client.get(f"{PAGE}?do=remove").text
        self.assertIn("The BMC keeps the certificate it serves now.", page)
        self.assertEqual(self.asked, [])

        answer = self.send(client, f"{PAGE}/remove")

        self.assertEqual(answer.status_code, 303)
        self.assertEqual(answer.headers["location"], "/certificates/receivers")
        self.assertEqual([action for action, *_ in self.asked], ["remove"])
        self.assertIn("bmc_target_removed", self.audit)

    def test_a_check_that_was_not_answered_says_nothing_changed(self) -> None:
        """Review 26-11-27, BX05: it said the change might have been made."""

        self.answers["check"] = BmcAskError("unanswered", "the BMC helper did not answer")
        page = self.check(self.writing_client()).text

        self.assertIn("Nothing was changed; check again.", page)
        self.assertNotIn("may have made the change", page)

    def test_a_removal_under_an_install_is_said_in_its_own_words(self) -> None:
        self.answers["remove"] = BmcAskError(
            "bmc_busy", "another install on a BMC is running; ask again when it has ended"
        )
        answer = self.send(self.writing_client(), f"{PAGE}/remove")

        self.assertEqual(answer.status_code, 409)
        self.assertIn("another install on a BMC is running", answer.text)
        self.assertNotIn("bmc_target_removed", self.audit)

    def test_an_unanswered_removal_is_recorded_as_unknown(self) -> None:
        self.answers["remove"] = BmcAskError("unanswered", "the BMC helper did not answer")
        self.send(self.writing_client(), f"{PAGE}/remove")

        self.assertIn("bmc_target_removed", self.audit)

    def test_the_certificates_row_names_its_bmc_and_links_to_it(self) -> None:
        page = self.writing_client().get(f"/certificates?view=registry&open={DEVICE}").text

        self.assertIn(f'{DEVICE} <span class="target-kind">BMC</span>', page)
        self.assertIn(f'<a href="{PAGE}">{DEVICE}</a>', page)


class AFailedInstallOnTheDashboard(BmcPageTestCase):
    entry = with_bmc("failed", served_sha256="ab" * 32)
    bmcs = (bmc_record(),)

    def test_needs_attention_offers_the_bmc_and_install_now_to_an_admin(self) -> None:
        page = self.writing_client().get("/").text

        self.assertIn(f'href="{PAGE}">BMC</a>', page)
        self.assertIn(f'action="{PAGE}/install"', page)

    def test_a_reader_is_given_neither(self) -> None:
        page = self.writing_client(role="reader").get("/").text

        self.assertIn(DEVICE, page)
        self.assertNotIn(PAGE, page)


class AnUntrustedBmc(BmcPageTestCase):
    entry = with_bmc("untrusted", served_sha256="cd" * 32)
    bmcs = (bmc_record(),)

    def test_install_now_is_not_offered_where_nothing_would_be_sent(self) -> None:
        """Review 26-11-27, BX06: the page offered it; *Change…* is the way."""

        page = self.writing_client().get(PAGE).text

        self.assertIn("Change…", page)
        self.assertNotIn(">Install now</button>", page)
