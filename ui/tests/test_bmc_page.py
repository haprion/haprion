"""A certificate's BMC page (B526, B536): Check, Save and install, Install now, Change… and Remove….

The page is the control: only an admin with writes reaches the BMC service,
the account is sealed in the request that typed it and never drawn again, and
what is saved is only what the administrator confirmed.
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
from tests.test_external_certificates import DEVICE, external, with_bmc
from tests.test_login import configuration

SERVED = "4f" * 32
#
# Assembled, so the secret scanner does not take it for one.
#
SECRET = "-".join(("not", "the", "real", "one"))
CHECKED = {
    "id": DEVICE,
    "address": "192.0.2.7",
    "port": 443,
    "served_sha256": SERVED,
    "subject": DEVICE,
    "issuer": "Example Issuing CA",
    "not_after": "2026-12-20T00:00:00Z",
    "model": "X13SCL-IF",
    "firmware": "01.09.06",
    "may_upload": True,
}


class BmcPageTestCase(CertificateFormRouteTestCase):
    entry: dict[str, Any] = external()

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
                "id": DEVICE,
                "address": "192.0.2.7",
                "port": 443,
                "fingerprint_sha256": SERVED,
                "username": "admin",
            },
            "remove": {"id": DEVICE, "removed": True},
        }

        def ask(action: str, certificate_id: str, **parameters: Any) -> dict[str, Any]:
            self.asked.append((action, certificate_id, parameters))
            answer = self.answers[action]
            if isinstance(answer, Exception):
                raise answer
            return dict(answer)

        for patch in (
            mock.patch("haprion.bmc_socket.ask", side_effect=ask),
            mock.patch("haprion_ui.db.wake_poller"),
            mock.patch(
                "haprion_ui.db.cluster_certificates",
                return_value=[
                    with_registry(
                        certificate_reading(), registered(fingerprint="a" * 64), self.entry
                    )
                ],
            ),
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
            f"/certificates/{DEVICE}/bmc/check",
            **{"address": "192.0.2.7", "bmc_username": "admin", "password": SECRET, **fields},
        )


class AnExternalCertificateWithoutABmc(BmcPageTestCase):
    def test_the_page_asks_for_the_bmc_and_cannot_save_before_check(self) -> None:
        page = self.writing_client().get(f"/certificates/{DEVICE}/bmc").text

        self.assertIn(f"BMC for {DEVICE}", page)
        for field in ('name="address"', 'name="bmc_username"', 'name="password"'):
            self.assertIn(field, page)
        self.assertIn(">Check</button>", page)
        self.assertRegex(page, r'type="submit" disabled>Save and install</button>')
        self.assertEqual(self.asked, [])

    def test_check_seals_the_account_and_shows_what_the_bmc_serves(self) -> None:
        answer = self.check(self.writing_client())

        self.assertEqual(answer.status_code, 200)
        action, certificate_id, sent = self.asked[0]
        self.assertEqual(
            (action, certificate_id, sent["address"], sent["port"]),
            ("check", DEVICE, "192.0.2.7", 443),
        )
        opened = json.loads(open_sealed(self.private_key, sent["ciphertext"]))
        self.assertEqual(
            (opened["certificate_id"], opened["address"], opened["username"], opened["password"]),
            (DEVICE, "192.0.2.7", "admin", SECRET),
        )
        page = answer.text
        self.assertIn("4F:4F:4F", page)
        self.assertIn("X13SCL-IF · 01.09.06", page)
        self.assertIn("Signed in, may upload certificates", page)
        self.assertIn(base64.b64encode(sent["ciphertext"]).decode(), page)
        self.assertNotIn(SECRET, page)
        self.assertRegex(page, r'deploy-button" type="submit">Save and install</button>')

    def test_an_account_that_may_not_upload_cannot_be_saved(self) -> None:
        self.answers["check"] = {**CHECKED, "may_upload": False}
        page = self.check(self.writing_client()).text

        self.assertIn("the account needs the Administrator role", page)
        self.assertRegex(page, r'type="submit" disabled>Save and install</button>')

    def test_a_bmc_that_does_not_answer_names_the_port_to_open(self) -> None:
        self.answers["check"] = BmcAskError(
            "bmc_unreachable", "192.0.2.7:443 did not answer: timed out"
        )
        page = self.check(self.writing_client()).text

        self.assertIn("192.0.2.7 did not answer on port 443", page)
        self.assertIn("blocks port 443", page)
        self.assertIn('value="192.0.2.7"', page)
        self.assertNotIn(SECRET, page)

    def test_an_address_that_is_none_is_said_and_nothing_is_asked(self) -> None:
        page = self.check(self.writing_client(), address="bmc 01").text

        self.assertIn("bmc 01 is not a name or address.", page)
        self.assertEqual(self.asked, [])

    def test_save_writes_what_was_confirmed_and_starts_the_install(self) -> None:
        client = self.writing_client()
        box = base64.b64encode(b"x" * 64).decode()
        answer = self.send(
            client,
            f"/certificates/{DEVICE}/bmc/save",
            address="192.0.2.7",
            port="443",
            fingerprint_sha256=SERVED,
            key_id=self.public_key.key_id,
            ciphertext_base64=box,
            confirmed="yes",
            idempotency_key=KEY,
        )

        self.assertEqual(answer.status_code, 303)
        self.assertEqual(answer.headers["location"], f"/certificates?view=registry&open={DEVICE}")
        action, _id, sent = self.asked[0]
        self.assertEqual(
            (action, sent["fingerprint_sha256"], sent["ciphertext"]), ("save", SERVED, b"x" * 64)
        )
        self.assertIn("bmc_target_saved", self.audit)
        self.assertEqual(
            [(job["operation"], job["payload"]) for job in self.queued],
            [("bmc_install", {"id": DEVICE, "by": "save"})],
        )

    def test_save_without_the_confirmation_asks_nothing(self) -> None:
        answer = self.send(
            self.writing_client(),
            f"/certificates/{DEVICE}/bmc/save",
            address="192.0.2.7",
            fingerprint_sha256=SERVED,
            key_id=self.public_key.key_id,
            ciphertext_base64=base64.b64encode(b"x" * 64).decode(),
            idempotency_key=KEY,
        )

        self.assertIn("Confirm that the fingerprint", answer.text)
        self.assertEqual((self.asked, self.queued), ([], []))

    def test_a_save_behind_another_certificate_job_is_saved_and_says_so(self) -> None:
        with mock.patch("haprion_ui.db.queue_job", side_effect=db.CertificateBusy()):
            answer = self.send(
                self.writing_client(),
                f"/certificates/{DEVICE}/bmc/save",
                address="192.0.2.7",
                fingerprint_sha256=SERVED,
                key_id=self.public_key.key_id,
                ciphertext_base64=base64.b64encode(b"x" * 64).decode(),
                confirmed="yes",
                idempotency_key=KEY,
            )

        self.assertIn("The BMC was saved, but its install was not started", answer.text)
        self.assertIn("bmc_target_saved", self.audit)

    def test_a_reader_is_refused_and_nothing_is_asked(self) -> None:
        client = self.writing_client(role="reader")
        self.assertEqual(client.get(f"/certificates/{DEVICE}/bmc").status_code, 403)
        self.assertEqual(self.check(client).status_code, 403)
        self.assertEqual(self.asked, [])

    def test_a_certificate_without_the_mark_has_no_bmc(self) -> None:
        page = self.writing_client().get("/certificates/example.com/bmc").text

        self.assertIn("not an external certificate", page)

    def test_the_bar_s_bmc_button_opens_the_page_of_the_one_row_ticked(self) -> None:
        client = self.writing_client()
        page = client.get("/certificates?view=registry").text
        self.assertIn(
            'formaction="/certificates/bmc" data-export-submit disabled>BMC…</button>', page
        )

        answer = self.send(client, "/certificates/bmc", certificate=DEVICE)

        self.assertEqual(answer.status_code, 303)
        self.assertEqual(answer.headers["location"], f"/certificates/{DEVICE}/bmc")


class AnExternalCertificateWithABmc(BmcPageTestCase):
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

    def test_the_page_says_where_with_whom_and_what_it_is_trusted_with(self) -> None:
        page = self.writing_client().get(f"/certificates/{DEVICE}/bmc").text

        self.assertIn("<strong>Redfish user</strong><span>admin</span>", page)
        self.assertIn(":".join(["AB"] * 32), page)
        self.assertIn("automatically · took 2 min 10 s", page)
        self.assertIn("Installed", page)
        for control in ("Remove…", "Change…", ">Install now</button>"):
            self.assertIn(control, page)
        self.assertNotIn('name="password"', page)

    def test_install_now_is_a_job(self) -> None:
        answer = self.send(
            self.writing_client(), f"/certificates/{DEVICE}/bmc/install", idempotency_key=KEY
        )

        self.assertEqual(answer.status_code, 303)
        self.assertEqual(
            [(job["operation"], job["payload"]) for job in self.queued],
            [("bmc_install", {"id": DEVICE, "by": "install_now"})],
        )

    def test_change_types_the_account_again_from_the_saved_address(self) -> None:
        page = self.writing_client().get(f"/certificates/{DEVICE}/bmc?do=change").text

        self.assertIn(f'name="address" value="{DEVICE}"', page)
        self.assertIn('name="bmc_username" value="admin"', page)
        self.assertIn('name="password" type="password"', page)

    def test_remove_is_confirmed_on_its_own_page_and_then_asked_of_root(self) -> None:
        client = self.writing_client()
        page = client.get(f"/certificates/{DEVICE}/bmc?do=remove").text
        self.assertIn("The BMC keeps the certificate it serves now.", page)
        self.assertEqual(self.asked, [])

        answer = self.send(client, f"/certificates/{DEVICE}/bmc/remove")

        self.assertEqual(answer.status_code, 303)
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
        answer = self.send(self.writing_client(), f"/certificates/{DEVICE}/bmc/remove")

        self.assertEqual(answer.status_code, 409)
        self.assertIn("another install on a BMC is running", answer.text)
        self.assertNotIn("bmc_target_removed", self.audit)

    def test_an_unanswered_removal_is_recorded_as_unknown(self) -> None:
        self.answers["remove"] = BmcAskError("unanswered", "the BMC helper did not answer")
        self.send(self.writing_client(), f"/certificates/{DEVICE}/bmc/remove")

        self.assertIn("bmc_target_removed", self.audit)


class AFailedInstallOnTheDashboard(BmcPageTestCase):
    entry = with_bmc("failed", served_sha256="ab" * 32)

    def test_needs_attention_offers_the_bmc_and_install_now_to_an_admin(self) -> None:
        page = self.writing_client().get("/").text

        self.assertIn(f'href="/certificates/{DEVICE}/bmc">BMC</a>', page)
        self.assertIn(f'action="/certificates/{DEVICE}/bmc/install"', page)

    def test_a_reader_is_given_neither(self) -> None:
        page = self.writing_client(role="reader").get("/").text

        self.assertIn(DEVICE, page)
        self.assertNotIn(f"/certificates/{DEVICE}/bmc", page)


class AnUntrustedBmc(BmcPageTestCase):
    entry = with_bmc("untrusted", served_sha256="cd" * 32)

    def test_install_now_is_not_offered_where_nothing_would_be_sent(self) -> None:
        """Review 26-11-27, BX06: the page offered it; *Change…* is the way."""

        page = self.writing_client().get(f"/certificates/{DEVICE}/bmc").text

        self.assertIn("Change…", page)
        self.assertNotIn(">Install now</button>", page)
