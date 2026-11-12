"""*Blocklists* in the interface (B496, 13; B500): the poller's reading and where it is said.

Pinned here: the poller asks what the refresh timer last did in the manager's
readings call and writes it whole, and a reading that did not answer leaves
the rows as they were rather than saying nothing was ever fetched. The form
holds a list to the engine's own rule and never draws a secret back; a save
stores the row and queues its apply job together; a removal is refused while
an object names the list; and `haprion-blocklists` plans the same changes the
form would make.
"""

from __future__ import annotations

import contextlib
import json
import os
import subprocess
import tempfile
import unittest
from collections.abc import Mapping
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest import mock
from uuid import UUID, uuid4

from haprion import blocklist_store
from haprion.blocklist_check import AddressCheck, CheckError, Listed, Tested
from haprion.dns_profile_keys import generate, render_public_key

from haprion_ui import auth, blocklist_apply, blocklist_form, db, poller
from tests.test_login import LoginTestCase, configuration
from tests.test_poller import document
from tests.test_queue_route import queued

GUARD = "sample-secret-never-echoed"
KEY = str(uuid4())
NOW = datetime(2026, 11, 12, 8, 0, tzinfo=UTC)


def blocklist_row(**overrides: Any) -> db.Blocklist:
    fields: dict[str, Any] = {
        "name": "community",
        "description": "",
        "url": "https://lists.example.com/community.txt",
        "auth": "none",
        "username": "",
        "every_hours": 24,
        "excepts": [],
        "key_id": None,
        "revision": 1,
        "created_at": NOW,
        "updated_at": NOW,
        "updated_by": "admin",
    }
    return db.Blocklist(**{**fields, **overrides})


def state_row(**overrides: Any) -> db.BlocklistState:
    fields: dict[str, Any] = {
        "name": "community",
        "fetched_at": NOW,
        "attempted_at": NOW,
        "failed_at": None,
        "error": "",
        "entries": 14812,
        "skipped": 2,
        "seen_at": NOW,
    }
    return db.BlocklistState(**{**fields, **overrides})


class Pool:
    def connection(self) -> Any:
        return contextlib.nullcontext(mock.Mock())


def manager_readings(states: Any, *, exit_code: int = 0) -> Any:
    """The readings helper answering the certificates and, as given, the blocklists' state."""

    asked: list[Mapping[str, Any]] = []

    def run(cluster: str | None, request_id: str, reads: Mapping[str, Any]) -> Any:
        asked.append(reads)
        certs = document(
            "cert_list",
            result={"interface_served": None, "registry": {"certificates": [], "receivers": []}},
            cluster=None,
            request_id=request_id,
        )
        answer = (
            document("blocklist_states", result=states, cluster=None, request_id=request_id)
            if states is not None
            else None
        )
        outer = document(
            "readings",
            result={
                "reads": {
                    "cert_list": {"exit_code": 0, "envelope": certs, "stderr": ""},
                    "blocklist_states": {"exit_code": exit_code, "envelope": answer, "stderr": ""},
                }
            },
            cluster=None,
            request_id=request_id,
        )
        return subprocess.CompletedProcess([], 0, json.dumps(outer), "")

    run.asked = asked  # type: ignore[attr-defined]
    return run


STATES = {
    "lists": [
        {
            "name": "community",
            "fetched_at": "2026-11-12T06:00:02Z",
            "attempted_at": "2026-11-12T06:00:02Z",
            "failed_at": None,
            "error": "",
            "entries": 14812,
            "skipped": 2,
        },
        {
            "name": "drop",
            "fetched_at": None,
            "attempted_at": "2026-11-12T06:00:01Z",
            "failed_at": "2026-11-12T06:00:01Z",
            "error": "the source answered 503",
            "entries": 0,
            "skipped": 0,
        },
    ]
}


class ThePollerReading(unittest.TestCase):
    def poll(self, run: Any) -> mock.Mock:
        with (
            mock.patch("haprion_ui.db.record_manager_certificates"),
            mock.patch("haprion_ui.db.replace_search_entries"),
            mock.patch("haprion_ui.db.record_blocklist_states") as recorded,
        ):
            self.assertTrue(poller.poll_manager(Pool(), run, blocklists=True))
        return recorded

    def test_is_asked_with_the_certificates_and_written_whole(self) -> None:
        run = manager_readings(STATES)
        recorded = self.poll(run)

        self.assertEqual(sorted(run.asked[0]), ["blocklist_states", "cert_list"])
        self.assertEqual(run.asked[0]["blocklist_states"], {})
        (states,) = recorded.call_args.args[1:]
        self.assertEqual([state.name for state in states], ["community", "drop"])
        self.assertEqual(states[0].fetched_at, datetime(2026, 11, 12, 6, 0, 2, tzinfo=UTC))
        self.assertEqual((states[0].entries, states[0].skipped), (14812, 2))
        self.assertIsNone(states[1].fetched_at)
        self.assertEqual(states[1].error, "the source answered 503")

    def test_a_reading_that_did_not_answer_leaves_the_rows(self) -> None:
        recorded = self.poll(manager_readings(None, exit_code=74))
        recorded.assert_not_called()

    def test_without_the_flag_it_is_not_asked(self) -> None:
        run = manager_readings(STATES)
        with (
            mock.patch("haprion_ui.db.record_manager_certificates"),
            mock.patch("haprion_ui.db.replace_search_entries"),
            mock.patch("haprion_ui.db.record_blocklist_states") as recorded,
        ):
            poller.poll_manager(Pool(), run)

        self.assertEqual(sorted(run.asked[0]), ["cert_list"])
        recorded.assert_not_called()


class TheForm(unittest.TestCase):
    def test_a_list_is_held_to_the_engine_s_rule(self) -> None:
        good = blocklist_form.Form(name="community", url="https://lists.example.com/l.txt")
        self.assertEqual(blocklist_form.checked(good).every_hours, 24)
        cases = (
            (replace(good, name="Community"), "name is lowercase"),
            (replace(good, url="http://lists.example.com/l.txt"), "must start with https://"),
            (replace(good, every_hours="2"), "Fetch every is 1, 6, 12 or 24 hours."),
            (replace(good, excepts="192.0.2.10\n0.0.0.0/0"), "entire address family"),
            (replace(good, auth="basic"), "Basic authorization needs a username"),
        )
        for form, said in cases:
            with self.subTest(said=said):
                with self.assertRaises(blocklist_form.FormProblem) as caught:
                    blocklist_form.checked(form)
                self.assertIn(said, str(caught.exception))
                self.assertFalse(str(caught.exception)[0].islower())

    def test_an_empty_secret_keeps_the_stored_one_until_the_authorization_changes(self) -> None:
        stored = blocklist_row(auth="basic", username="svc-app", key_id="0123456789abcdef")
        basic = blocklist_form.Form(auth="basic", username="svc-app")
        self.assertEqual(blocklist_form.secret_choice(basic, stored), ("", True))
        self.assertEqual(
            blocklist_form.secret_choice(replace(basic, secret=GUARD), stored), (GUARD, False)
        )
        with self.assertRaisesRegex(blocklist_form.FormProblem, "Token is needed for Bearer"):
            blocklist_form.secret_choice(blocklist_form.Form(auth="bearer"), stored)
        with self.assertRaisesRegex(blocklist_form.FormProblem, "Password is needed"):
            blocklist_form.secret_choice(basic, None)
        self.assertEqual(blocklist_form.secret_choice(blocklist_form.Form(), stored), ("", False))

    def test_the_posted_secret_and_username_follow_the_authorization(self) -> None:
        form = blocklist_form.from_posted(
            {"name": "community", "auth": "none", "username": "x", "secret": GUARD}, None
        )
        self.assertEqual((form.username, form.secret), ("", ""))
        renamed = blocklist_form.from_posted({"name": "other"}, blocklist_row())
        self.assertEqual(renamed.name, "community")
        self.assertNotIn(
            GUARD, repr(blocklist_form.from_posted({"auth": "bearer", "secret": GUARD}, None))
        )


class TheCardRows(unittest.TestCase):
    def rows(self, state: db.BlocklistState | None, **overrides: Any) -> blocklist_form.Row:
        (row,) = blocklist_form.rows(
            [blocklist_row(**overrides)], [state] if state else [], {}, writes=True
        )
        return row

    def test_a_fetched_list_says_its_count_its_excepts_and_when(self) -> None:
        row = self.rows(state_row(), excepts=["192.0.2.10", "partner-sites", "198.51.100.0/24"])
        self.assertEqual(row.source, "lists.example.com")
        self.assertEqual(row.every, "24 h")
        self.assertEqual(row.addresses, "14 812 · 3 excepted")
        self.assertEqual(row.fetched_tone, "")
        self.assertEqual(row.href, "/settings/blocklists/community/edit")

    def test_a_failed_fetch_says_the_list_kept_and_why_in_its_title(self) -> None:
        failed = NOW + timedelta(hours=12)
        row = self.rows(
            state_row(attempted_at=failed, failed_at=failed, error="the source answered 503")
        )
        self.assertTrue(row.fetched.startswith("Failed · kept "), row.fetched)
        self.assertEqual(row.fetched_tone, "warning")
        self.assertIn("the source answered 503", row.fetched_title)

    def test_never_fetched_is_said_and_holds_no_count(self) -> None:
        self.assertEqual(self.rows(None).fetched, "Not fetched yet")
        never = self.rows(state_row(fetched_at=None, failed_at=NOW, entries=0))
        self.assertEqual((never.fetched, never.addresses), ("Failed · never fetched", ""))

    def test_a_failed_apply_of_the_revision_links_to_its_job(self) -> None:
        job = queued(
            id=31,
            operation="blocklist_apply",
            cluster=None,
            payload={"name": "community", "revision": 2},
            state="failed",
        )
        (row,) = blocklist_form.rows(
            [blocklist_row(revision=2)], [state_row()], {"community": job}, writes=True
        )
        self.assertEqual((row.status, row.job_href), ("Apply failed", "/jobs/31"))
        (older,) = blocklist_form.rows(
            [blocklist_row(revision=3)], [state_row()], {"community": job}, writes=True
        )
        self.assertEqual(older.status, "")


def objects_reading(cluster: str, groups: dict[str, list[str]]) -> db.ClusterObjects:
    return db.ClusterObjects(
        cluster=cluster,
        observed_at=NOW,
        outcome="done",
        result={
            "objects": [
                {"name": name, "document": f"{name}.yaml", "readable": True, "groups": names}
                for name, names in groups.items()
            ]
        },
        warnings=[],
        error=None,
        poll_error=None,
    )


class BlocklistRouteTestCase(LoginTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.private_key, self.public_key = generate()
        directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.public_path = directory / f"{self.public_key.key_id}.pub"
        self.public_path.write_text(render_public_key(self.public_key))
        self.saved: list[dict[str, Any]] = []
        self.queued: list[dict[str, Any]] = []
        self.object_rows: list[db.ClusterObjects] = []

        def save(_c: object, **fields: Any) -> db.Blocklist:
            self.saved.append(fields)
            return blocklist_row(name=fields["name"], revision=(fields["previous"] or 0) + 1)

        def queue(_c: object, **fields: Any) -> db.Job:
            self.queued.append(fields)
            return queued(operation="blocklist_apply", cluster=None, payload=fields["payload"])

        for patch in (
            mock.patch("haprion_ui.db.save_blocklist", side_effect=save),
            mock.patch("haprion_ui.db.queue_job", side_effect=queue),
            mock.patch("haprion_ui.db.job_for_key", return_value=None),
            mock.patch("haprion_ui.db.job_state", return_value="done"),
            mock.patch(
                "haprion_ui.db.blocklist",
                side_effect=lambda _c, name: next(
                    (row for row in self.blocklists if row.name == name), None
                ),
            ),
            mock.patch(
                "haprion_ui.db.cluster_objects", side_effect=lambda _c: list(self.object_rows)
            ),
            mock.patch("haprion_ui.pages.blocklists.APPLY_WAIT", 0.3),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def admin(self) -> Any:
        client = self.client(
            replace(
                configuration(), management_writes=True, dns_profiles_public_key=self.public_path
            )
        )
        self.sign_in(client)
        return client

    def post(self, client: Any, path: str = "/settings/blocklists/new", **fields: Any) -> Any:
        data: dict[str, Any] = {
            "name": "community",
            "url": "https://lists.example.com/community.txt",
            "auth": "basic",
            "username": "svc-app",
            "secret": GUARD,
            "every_hours": "24",
            "excepts": "192.0.2.10\npartner-sites\n",
            "action": "save",
            "idempotency_key": KEY,
            auth.CSRF_FIELD: auth.csrf_token(client.cookies[auth.SESSION_COOKIE]),
        }
        data.update(fields)
        return client.post(path, data=data, follow_redirects=False)


class TheSettingsCard(BlocklistRouteTestCase):
    def test_the_card_lists_each_list_and_offers_the_form(self) -> None:
        self.blocklists = [blocklist_row()]
        self.blocklist_states = [state_row()]
        page = self.admin().get("/settings").text

        self.assertIn('id="blocklists"', page)
        self.assertIn('href="/settings/blocklists/new"', page)
        self.assertIn("<code>lists.example.com</code>", page)
        self.assertIn("14 812", page)
        self.assertIn("Check address", page)

    def test_check_address_answers_under_the_heading(self) -> None:
        self.blocklists = [blocklist_row()]
        found = AddressCheck(
            address="203.0.113.7",
            lists=(Listed("community", "203.0.113.0/24", "2026-11-12T06:00:00Z", (), ("alpha",)),),
            unfetched=(),
        )
        with mock.patch(
            "haprion.blocklist_check_socket.check_address", return_value=found
        ) as asked:
            page = self.admin().get("/settings?address=203.0.113.7").text
        asked.assert_called_once_with("203.0.113.7")
        self.assertIn("203.0.113.7 is on community (203.0.113.0/24)", page)

        with mock.patch("haprion.blocklist_check_socket.check_address") as asked:
            page = self.admin().get("/settings?address=not-an-address").text
        asked.assert_not_called()
        self.assertIn("Not-an-address is not an IPv4 or IPv6 address.", page)


class SavingABlocklist(BlocklistRouteTestCase):
    def test_a_save_seals_the_secret_and_queues_its_apply_job(self) -> None:
        response = self.post(self.admin())

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/settings#blocklists")
        (saved,) = self.saved
        self.assertEqual(
            (saved["name"], saved["previous"], saved["auth"]), ("community", None, "basic")
        )
        self.assertEqual(saved["excepts"], ("192.0.2.10/32", "partner-sites"))
        self.assertEqual(saved["key_id"], self.public_key.key_id)
        self.assertNotIn(GUARD.encode(), saved["ciphertext"])
        secret, revision = blocklist_store.open_secret(
            self.private_key, saved["ciphertext"], name="community", revision=1
        )
        self.assertEqual((secret, revision), (GUARD, 1))
        (job,) = self.queued
        self.assertEqual(job["operation"], "blocklist_apply")
        self.assertEqual(job["payload"], {"name": "community", "revision": 1})
        self.assertEqual(job["idempotency_key"], UUID(KEY))
        self.assertIn("queue_job", self.audit)
        self.assertNotIn(GUARD, repr(self.audit))

    def test_an_edit_keeps_the_stored_secret_when_none_is_typed(self) -> None:
        self.blocklists = [
            blocklist_row(auth="basic", username="svc-app", key_id="0" * 16, revision=4)
        ]
        response = self.post(
            self.admin(), "/settings/blocklists/community/edit", secret="", name="renamed"
        )

        self.assertEqual(response.status_code, 303)
        (saved,) = self.saved
        self.assertEqual(
            (saved["name"], saved["previous"], saved["keep_secret"]), ("community", 4, True)
        )
        self.assertIsNone(saved["ciphertext"])

    def test_a_refusal_redraws_the_form_without_the_secret(self) -> None:
        response = self.post(self.admin(), url="http://lists.example.com/l.txt")

        self.assertEqual(response.status_code, 400)
        self.assertIn("must start with https://", response.text)
        self.assertNotIn(GUARD, response.text)
        self.assertEqual(self.saved, [])

    def test_a_busy_certificate_slot_keeps_nothing(self) -> None:
        with mock.patch("haprion_ui.db.queue_job", side_effect=db.CertificateBusy()):
            response = self.post(self.admin())
        self.assertEqual(response.status_code, 409)
        self.assertNotIn(GUARD, response.text)

    def test_test_fetches_as_the_form_holds_it_and_keeps_nothing(self) -> None:
        tested = Tested("community", "fetched", 14812, 2, ("192.0.2.10/32",), (), None)
        client = self.admin()
        with mock.patch("haprion.blocklist_check_socket.test", return_value=tested) as asked:
            drawn = self.post(client, action="test")
            answered = client.post(
                "/settings/blocklists/new",
                data={
                    "name": "community",
                    "url": "https://lists.example.com/community.txt",
                    "auth": "bearer",
                    "secret": GUARD,
                    "every_hours": "24",
                    "action": "test",
                    auth.CSRF_FIELD: auth.csrf_token(client.cookies[auth.SESSION_COOKIE]),
                },
                headers={"Accept": "application/json"},
            )

        self.assertEqual(asked.call_args_list[0].kwargs["secret"], GUARD)
        self.assertEqual(asked.call_args_list[0].kwargs["authorization"], "basic")
        self.assertEqual(drawn.status_code, 200)
        self.assertIn("14 812 addresses · 2 lines skipped", drawn.text)
        self.assertNotIn(GUARD, drawn.text)
        self.assertEqual(answered.status_code, 200)
        self.assertEqual(answered.json()["tone"], "healthy")
        self.assertIn("14 812 addresses", answered.json()["answer"])
        self.assertNotIn(GUARD, answered.text)
        self.assertEqual((self.saved, self.queued), ([], []))

    def test_a_test_that_cannot_fetch_says_why(self) -> None:
        with mock.patch(
            "haprion.blocklist_check_socket.test",
            side_effect=CheckError("unavailable", "the helper did not answer"),
        ):
            page = self.post(self.admin(), action="test").text
        self.assertIn("The helper did not answer.", page)


class RemovingABlocklist(BlocklistRouteTestCase):
    def test_a_list_an_object_names_is_not_removed(self) -> None:
        self.blocklists = [blocklist_row()]
        self.object_rows = [objects_reading("alpha", {"web": ["community"], "api": []})]
        client = self.admin()
        page = client.get("/settings/blocklists/community/remove").text
        self.assertIn("community is under Denied in web on alpha", page)

        token = auth.csrf_token(client.cookies[auth.SESSION_COOKIE])
        response = client.post(
            "/settings/blocklists/community/remove",
            data={auth.CSRF_FIELD: token, "idempotency_key": KEY},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 409)
        self.assertEqual(self.queued, [])

    def test_an_unused_list_is_removed_by_its_job(self) -> None:
        self.blocklists = [blocklist_row(revision=3)]
        client = self.admin()
        token = auth.csrf_token(client.cookies[auth.SESSION_COOKIE])
        response = client.post(
            "/settings/blocklists/community/remove",
            data={auth.CSRF_FIELD: token, "idempotency_key": KEY},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)
        (job,) = self.queued
        self.assertEqual(job["payload"], {"name": "community", "revision": 3, "remove": True})


class TheCommand(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))

    def file(self, body: str, mode: int = 0o600) -> Path:
        path = self.directory / "blocklists.yaml"
        path.write_text(body)
        os.chmod(path, mode)
        return path

    def test_a_file_is_read_by_the_engine_s_rule(self) -> None:
        found = blocklist_apply.read_file(
            self.file(
                "blocklists:\n"
                "  - name: community\n"
                "    url: https://lists.example.com/community.txt\n"
                "    every_hours: 24\n"
                "    authorization: bearer\n"
                f"    secret: {GUARD}\n"
                "    except: [192.0.2.10]\n"
            )
        )
        (wanted,) = found
        self.assertEqual(wanted.definition.excepts, ("192.0.2.10/32",))
        self.assertNotIn(GUARD, repr(wanted))

    def test_a_secret_others_may_read_or_a_bad_list_is_refused(self) -> None:
        body = (
            "blocklists:\n  - name: community\n    url: https://lists.example.com/l.txt\n"
            f"    every_hours: 24\n    authorization: bearer\n    secret: {GUARD}\n"
        )
        with self.assertRaisesRegex(blocklist_apply.ApplyError, "mode 0600"):
            blocklist_apply.read_file(self.file(body, 0o644))
        with self.assertRaisesRegex(blocklist_apply.ApplyError, "1, 6, 12 or 24"):
            blocklist_apply.read_file(self.file(body.replace("every_hours: 24", "every_hours: 2")))
        with self.assertRaisesRegex(blocklist_apply.ApplyError, "unknown field: color"):
            blocklist_apply.read_file(self.file(body + "    color: red\n"))

    def plan(
        self, body: str, stored: list[db.Blocklist], latest: dict[str, db.Job], **options: Any
    ) -> Any:
        return blocklist_apply.plan(
            blocklist_apply.read_file(self.file(body)),
            {row.name: row for row in stored},
            latest,
            replace_secret=options.get("replace_secret", []),
            prune=options.get("prune", False),
        )

    def test_the_plan_creates_replaces_applies_again_and_prunes(self) -> None:
        body = (
            "blocklists:\n"
            "  - name: community\n    url: https://lists.example.com/community.txt\n    every_hours: 24\n"
            "  - name: drop\n    url: https://lists.example.com/drop.txt\n    every_hours: 12\n"
            "  - name: fresh\n    url: https://lists.example.com/fresh.txt\n    every_hours: 6\n"
        )
        done = queued(
            operation="blocklist_apply",
            cluster=None,
            payload={"name": "community", "revision": 1},
            state="done",
        )
        failed = queued(
            operation="blocklist_apply",
            cluster=None,
            payload={"name": "drop", "revision": 2},
            state="failed",
        )
        stored = [
            blocklist_row(),
            blocklist_row(
                name="drop", url="https://lists.example.com/drop.txt", every_hours=12, revision=2
            ),
            blocklist_row(name="old"),
        ]
        plan = self.plan(body, stored, {"community": done, "drop": failed}, prune=True)
        self.assertEqual(
            [(change.name, change.action) for change in plan.changes],
            [("drop", "apply"), ("fresh", "create"), ("old", "remove")],
        )
        self.assertEqual(plan.unchanged, ("community",))

        changed = self.plan(
            body.replace("every_hours: 24", "every_hours: 6"), stored[:1], {"community": done}
        )
        self.assertEqual(changed.changes[0].action, "replace")

    def test_the_stored_secret_is_kept_unless_asked_or_the_authorization_changes(self) -> None:
        stored = [blocklist_row(auth="bearer", key_id="0" * 16)]
        body = (
            "blocklists:\n  - name: community\n    url: https://lists.example.com/other.txt\n"
            f"    every_hours: 24\n    authorization: bearer\n    secret: {GUARD}\n"
        )
        kept = self.plan(body, stored, {}).changes[0]
        self.assertEqual((kept.action, kept.keep), ("replace", True))
        self.assertEqual(kept.wanted.secret, "")
        asked = self.plan(body, stored, {}, replace_secret=["community"]).changes[0]
        self.assertEqual((asked.keep, asked.wanted.secret), (False, GUARD))
        with self.assertRaisesRegex(blocklist_apply.ApplyError, "Password is needed"):
            self.plan(
                body.replace("bearer\n    secret: " + GUARD, "basic\n    username: svc-app"),
                stored,
                {},
            )


if __name__ == "__main__":
    unittest.main()
