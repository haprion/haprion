"""The receivers page (B142): the rows, the commands each host runs, the two jobs.

The engine's registration is tested with the engine. This side owns the
reading of the registry block, the derivation of the fetch commands from a
row, the form's refusals said before a job is queued, and the routes' gates.
"""

from __future__ import annotations

import json
import re
import unittest
from dataclasses import replace
from typing import Any
from unittest import mock
from uuid import uuid4

from haprion.cert_receiver import crypt

from haprion_ui import auth, certificate_receivers
from tests.test_certificate_delete import DeleteRouteTestCase
from tests.test_certificates import reading as certificate_reading
from tests.test_certificates import registered
from tests.test_login import configuration
from tests.test_queue_route import queued

KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB5s root@lb-02.example.net"


def record(
    identifier: str = "lb-01",
    *,
    transport: str = "rsync",
    layout: str = "per-certificate",
    owner: str | None = None,
    allow: tuple[str, ...] = (),
    certificates: tuple[str, ...] = (),
) -> dict[str, object]:
    return {
        "id": identifier,
        "transport": transport,
        "layout": layout,
        "owner": owner or f"crx-{identifier.replace('.', '-')}",
        "path": f"/srv/certdist/receivers/{identifier}",
        "allow": list(allow),
        "certificates": list(certificates),
    }


def block(*records: dict[str, object], manager: str | None = "mgr.example.net") -> dict[str, Any]:
    return {
        "certificates": [
            registered(
                "app.example.com",
                kind="import",
                clusters=(),
                receivers=({"id": "lb-01", "format": "pkcs12"}, {"id": "lb-02.example.net"}),
            )
        ],
        "receivers": [str(item["id"]) for item in records],
        "manager": manager,
        "receiver_records": list(records),
    }


class ReadingTheRows(unittest.TestCase):
    def test_rows_carry_the_format_from_the_certificate_s_side(self) -> None:
        manager, rows = certificate_receivers.parse_receiver_rows(
            block(
                record("lb-01", transport="sftp", certificates=("app.example.com",)),
                record("lb-02.example.net", certificates=("app.example.com",)),
                record("192.0.2.9", transport="https", allow=("192.0.2.9/32",)),
            )
        )

        self.assertEqual(manager, "mgr.example.net")
        self.assertEqual(
            [row.identifier for row in rows], ["lb-01", "lb-02.example.net", "192.0.2.9"]
        )
        self.assertEqual(rows[0].holds[0].format, "pkcs12")
        self.assertEqual(rows[1].holds[0].format, "pem")
        self.assertEqual(rows[2].allow, ("192.0.2.9/32",))
        self.assertFalse(rows[0].removable)
        self.assertTrue(rows[2].removable)

    def test_a_block_from_an_older_helper_has_no_rows_and_no_manager(self) -> None:
        manager, rows = certificate_receivers.parse_receiver_rows(
            {"certificates": [], "receivers": ["lb-01"]}
        )
        self.assertIsNone(manager)
        self.assertEqual(rows, ())


class WhatTheHostRuns(unittest.TestCase):
    def rows(self, *records: dict[str, object]) -> tuple[Any, ...]:
        return certificate_receivers.parse_receiver_rows(block(*records))[1]

    def test_rsync_names_the_account_the_manager_and_each_certificate(self) -> None:
        (row,) = self.rows(record("lb-02.example.net", certificates=("app.example.com",)))
        steps = certificate_receivers.fetch_steps(row, "mgr.example.net")
        commands = [step.command for step in steps]
        self.assertEqual(len(commands), 1)
        self.assertIn("crx-lb-02-example-net@mgr.example.net:app.example.com/", commands[0])
        self.assertIn("-o IdentitiesOnly=yes", commands[0])

    def test_sftp_gets_the_pkcs12_pair_by_name_on_linux_and_windows(self) -> None:
        (row,) = self.rows(record("lb-01", transport="sftp", certificates=("app.example.com",)))
        steps = certificate_receivers.fetch_steps(row, "mgr.example.net")
        self.assertEqual(len(steps), 1)
        (step,) = steps
        self.assertIn("sftp -b - -i /root/.ssh/certfetch", step.command)
        self.assertIn("get /app.example.com/app.example.com.pfx", step.command)
        self.assertIn("get /app.example.com/app.example.com.password", step.command)
        self.assertIn('@"', step.windows_command)
        self.assertIn("C:\\certs\\app.example.com.pfx", step.windows_command)
        self.assertIn("install-pkcs12.ps1", step.note)

    def test_https_pins_the_interface_and_fetches_under_the_allowlist(self) -> None:
        (row,) = self.rows(record("192.0.2.9", transport="https", allow=("192.0.2.9/32",)))
        steps = certificate_receivers.fetch_steps(row, "mgr.example.net")
        self.assertEqual(steps[0].title, "Once: decide what the fetches trust")
        # No openssl needed: the manager serves its own certificate as a file.
        self.assertEqual(
            steps[0].command,
            "curl -k -o manager-ui.pem https://mgr.example.net/certdist/manager-ui.pem",
        )
        self.assertEqual(
            steps[0].windows_command,
            "mkdir C:\\certs -Force | Out-Null\ncurl.exe -k -o C:\\certs\\manager-ui.pem "
            "https://mgr.example.net/certdist/manager-ui.pem",
        )
        self.assertEqual(steps[0].note.count("\n"), 1)
        self.assertIn("skip this step and drop --cacert", steps[0].note)
        # B306: the password once, in a file curl reads - never on a command line.
        self.assertEqual(steps[1].title, "Once: store this receiver's password")
        self.assertIn(
            "machine mgr.example.net login 192.0.2.9 password <password>", steps[1].command
        )
        self.assertIn("install -m 600 /dev/null /root/.certfetch.netrc", steps[1].command)
        self.assertIn("C:\\certs\\certfetch.netrc", steps[1].windows_command)
        self.assertIn("--cacert C:\\certs\\manager-ui.pem", steps[2].windows_command)
        self.assertIn("--netrc-file C:\\certs\\certfetch.netrc", steps[2].windows_command)
        self.assertIn(
            "https://mgr.example.net/certdist/192.0.2.9/<certificate>/fullchain.pem",
            steps[2].command,
        )
        self.assertIn("--cacert manager-ui.pem", steps[2].command)
        self.assertIn("--netrc-file /root/.certfetch.netrc", steps[2].command)

    def test_a_receiver_holding_nothing_still_gets_its_commands(self) -> None:
        (row,) = self.rows(record("lb-02.example.net"))
        steps = certificate_receivers.fetch_steps(row, None)
        self.assertIn("crx-lb-02-example-net@<manager>:<certificate>/", steps[0].command)

    def test_the_key_is_made_on_the_receiver_and_named_after_it_on_both_systems(self) -> None:
        first, second = certificate_receivers.key_steps("lb-02.example.net")
        self.assertEqual(
            first.command,
            "ssh-keygen -t ed25519 -N '' -C lb-02.example.net -f /root/.ssh/certfetch",
        )
        self.assertEqual(
            first.windows_command,
            "mkdir C:\\certs -Force | Out-Null\n"
            "ssh-keygen -t ed25519 -N '\"\"' -C lb-02.example.net -f C:\\certs\\certfetch",
        )
        self.assertEqual(second.command, "cat /root/.ssh/certfetch.pub")
        self.assertEqual(second.windows_command, "Get-Content C:\\certs\\certfetch.pub")
        # The first Windows command makes the directory the rest write into.
        self.assertTrue(first.windows_command.startswith("mkdir C:\\certs -Force | Out-Null\n"))
        self.assertEqual(certificate_receivers.WINDOWS_TRANSPORTS, {"sftp"})


class TheFormRefuses(unittest.TestCase):
    def payload(self, **fields: str) -> dict[str, Any]:
        values = {"receiver_id": "lb-02.example.net", "transport": "rsync", "public_key": KEY}
        values.update(fields)
        return certificate_receivers.payload(
            values["receiver_id"],
            values["transport"],
            values["public_key"],
            values.get("allow_text", ""),
            certificate_receivers.parse_receiver_rows(block(record("lb-01")))[1],
        )

    def test_an_ssh_transport_takes_the_pasted_line_and_lowercases_the_name(self) -> None:
        payload = self.payload(receiver_id=" LB-02.Example.NET ", public_key=f"\n{KEY}\n")
        self.assertEqual(
            payload,
            {
                "receiver": "lb-02.example.net",
                "action": "add",
                "transport": "rsync",
                "public_key": KEY,
            },
        )

    def test_https_takes_the_allowlist_split_on_lines_and_commas(self) -> None:
        payload = self.payload(
            transport="https",
            public_key="",
            allow_text="192.0.2.9/32\n198.51.100.0/24, 203.0.113.7",
        )
        self.assertEqual(payload["allow"], ["192.0.2.9/32", "198.51.100.0/24", "203.0.113.7"])
        self.assertNotIn("public_key", payload)

    def test_what_is_refused_before_a_job_is_queued(self) -> None:
        cases = {
            "name": dict(receiver_id=""),
            "shape": dict(receiver_id="lb 02"),
            "registered": dict(receiver_id="lb-01"),
            "transport": dict(transport="ftp"),
            "no key": dict(public_key=""),
            "two keys": dict(public_key=f"{KEY}\n{KEY}"),
            "private key": dict(public_key="-----BEGIN " + "OPENSSH PRIVATE" + " KEY-----"),
            "https with key": dict(transport="https", allow_text="192.0.2.9"),
            "https without allow": dict(transport="https", public_key=""),
            "rsync with allow": dict(allow_text="192.0.2.9"),
            "allow all": dict(transport="https", public_key="", allow_text="all"),
            "allow host bits": dict(transport="https", public_key="", allow_text="192.0.2.1/24"),
        }
        for name, fields in cases.items():
            with self.subTest(name), self.assertRaises(certificate_receivers.ReceiverProblem):
                self.payload(**fields)

    def test_an_allow_entry_that_is_not_an_address_is_said_on_the_form(self) -> None:
        with self.assertRaises(certificate_receivers.ReceiverProblem) as caught:
            self.payload(transport="https", public_key="", allow_text="192.0.2.9, all")
        self.assertIn("[1] is not an address or network: 'all'", str(caught.exception))
        self.assertIn("192.0.2.0/24", str(caught.exception))

    def test_a_registered_name_says_its_transport_and_what_to_do_instead(self) -> None:
        with self.assertRaises(certificate_receivers.ReceiverProblem) as caught:
            self.payload(receiver_id="lb-01")
        self.assertEqual(
            str(caught.exception),
            "lb-01 already fetches over rsync. Publish more certificates to it using the "
            "existing rsync way from the registry. To change the transport mode, remove it first.",
        )

    def test_a_removal_needs_a_registered_receiver_nothing_names(self) -> None:
        rows = certificate_receivers.parse_receiver_rows(
            block(
                record("lb-01", certificates=("app.example.com",)),
                record("lb-02.example.net"),
            )
        )[1]
        self.assertEqual(
            certificate_receivers.removal("lb-02.example.net", rows),
            {"receiver": "lb-02.example.net", "action": "remove"},
        )
        for name in ("lb-01", "nobody"):
            with self.subTest(name), self.assertRaises(certificate_receivers.ReceiverProblem):
                certificate_receivers.removal(name, rows)


class TheActivityLine(unittest.TestCase):
    def test_each_job_state_has_its_sentence(self) -> None:
        running = queued(
            operation="cert_receiver",
            cluster=None,
            state="running",
            payload={"receiver": "lb-02.example.net", "action": "add"},
        )
        done = replace(
            running,
            id=2,
            state="done",
            outcome="done",
            result={"outcome": "done", "result": {"layers": []}, "error": None},
        )
        refused = replace(
            running,
            id=3,
            state="done",
            outcome="failed",
            result={"outcome": "failed", "result": None, "error": {"code": "x", "message": "no"}},
        )
        partial = replace(
            running,
            id=4,
            state="done",
            outcome="partial",
            payload={"receiver": "lb-02.example.net", "action": "remove"},
            result={
                "outcome": "partial",
                "result": {"layers": [{"layer": "account", "state": "failed", "detail": "busy"}]},
                "error": None,
            },
        )
        activity = certificate_receivers.recent_activity([running, done, refused, partial])
        self.assertEqual(
            [(item.tone, item.label, item.message) for item in activity],
            [
                ("info", "Registering lb-02.example.net", ""),
                ("healthy", "Registered lb-02.example.net", ""),
                ("critical", "Registering lb-02.example.net failed", "no"),
                ("warning", "Removing lb-02.example.net: a layer was left", "busy"),
            ],
        )
        self.assertEqual(
            [item.badge for item in activity],
            ["Registering", "Registered", "Registration failed", "A layer was left"],
        )
        self.assertEqual([item.busy for item in activity], [True, False, False, False])


class WhatTheRowsCarry(unittest.TestCase):
    """A job's state sits on the row it concerns, or on a row of its own."""

    def activity(self, *jobs: tuple[str, str, str]) -> tuple[Any, ...]:
        items = []
        for index, (receiver, action, tone) in enumerate(jobs):
            items.append(certificate_receivers.Activity(index + 1, receiver, action, "", tone, ""))
        return tuple(items)

    def rows(self) -> tuple[Any, ...]:
        return certificate_receivers.parse_receiver_rows(
            block(record("lb-01"), record("lb-02.example.net"))
        )[1]

    def test_a_running_job_is_always_on_its_row_and_a_registration_has_a_row_of_its_own(
        self,
    ) -> None:
        on_rows, ghosts = certificate_receivers.on_the_rows(
            self.rows(),
            self.activity(
                ("lb-03.example.net", "add", "info"),
                ("lb-02.example.net", "remove", "info"),
            ),
        )
        self.assertEqual(set(on_rows), {"lb-02.example.net"})
        self.assertEqual([g.receiver for g in ghosts], ["lb-03.example.net"])

    def test_a_failure_is_shown_only_while_it_is_the_newest_job(self) -> None:
        newest_failed = self.activity(
            ("lb-03.example.net", "add", "critical"),
            ("lb-02.example.net", "remove", "critical"),
        )
        on_rows, ghosts = certificate_receivers.on_the_rows(self.rows(), newest_failed)
        self.assertEqual(on_rows, {})
        self.assertEqual([g.receiver for g in ghosts], ["lb-03.example.net"])

        older_failed = self.activity(
            ("lb-01", "add", "healthy"),
            ("lb-02.example.net", "remove", "critical"),
        )
        on_rows, ghosts = certificate_receivers.on_the_rows(self.rows(), older_failed)
        self.assertEqual((on_rows, ghosts), ({}, ()))

    def test_a_verdict_older_than_an_hour_is_history(self) -> None:
        from datetime import UTC, datetime, timedelta

        now = datetime.now(UTC)
        fresh = certificate_receivers.Activity(
            1, "lb-03.example.net", "add", "", "critical", "", now - timedelta(minutes=50)
        )
        stale = certificate_receivers.Activity(
            2, "lb-03.example.net", "add", "", "critical", "", now - timedelta(minutes=70)
        )
        _, ghosts = certificate_receivers.on_the_rows(self.rows(), (fresh,), now=now)
        self.assertEqual([g.job_id for g in ghosts], [1])
        _, ghosts = certificate_receivers.on_the_rows(self.rows(), (stale,), now=now)
        self.assertEqual(ghosts, ())

    def test_a_row_carries_its_newest_job_only(self) -> None:
        on_rows, _ = certificate_receivers.on_the_rows(
            self.rows(),
            self.activity(
                ("lb-02.example.net", "remove", "info"),
                ("lb-02.example.net", "remove", "critical"),
            ),
        )
        self.assertEqual(on_rows["lb-02.example.net"].job_id, 1)


class ReceiverRouteTestCase(DeleteRouteTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.records = [
            record("lb-01", transport="sftp", certificates=("app.example.com",)),
            record("lb-02.example.net"),
        ]
        self.activity: list[Any] = []
        for patch in (
            mock.patch(
                "haprion_ui.db.cluster_certificates",
                side_effect=lambda *_a, **_k: [
                    replace(
                        certificate_reading(),
                        result={**certificate_reading().result, "registry": block(*self.records)},
                    )
                ],
            ),
            mock.patch(
                "haprion_ui.db.operation_jobs", side_effect=lambda *_a, **_k: list(self.activity)
            ),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def writing_client(
        self, *, role: str = "admin", writes: bool = True, clusters: tuple[str, ...] = ("alpha",)
    ) -> Any:
        self.account = replace(self.account, role=role)
        client = self.client(replace(configuration(), management_writes=writes, clusters=clusters))
        self.sign_in(client)
        return client

    def add(self, client: Any, **fields: str) -> Any:
        token = auth.csrf_token(client.cookies[auth.SESSION_COOKIE])
        data = {
            "receiver": "lb-03.example.net",
            "transport": "rsync",
            "public_key": KEY,
            "allow": "",
            "idempotency_key": str(uuid4()),
            auth.CSRF_FIELD: token,
        }
        data.update(fields)
        return client.post("/certificates/receivers/new", data=data, follow_redirects=False)

    def remove(self, client: Any, receiver: str, *, token: str | None = None) -> Any:
        token = auth.csrf_token(client.cookies[auth.SESSION_COOKIE]) if token is None else token
        return client.post(
            "/certificates/receivers/remove",
            data={"receiver": receiver, "idempotency_key": str(uuid4()), auth.CSRF_FIELD: token},
            follow_redirects=False,
        )


class ThePage(ReceiverRouteTestCase):
    def test_it_lists_the_rows_with_their_commands_and_links_to_the_form(self) -> None:
        page = self.writing_client().get("/certificates/receivers").text

        self.assertIn("<h1>Receivers</h1>", page)
        self.assertIn("<strong>lb-01</strong>", page)
        self.assertIn('app.example.com <span class="target-kind">pkcs12</span>', page)
        self.assertIn("get /app.example.com/app.example.com.pfx", page)
        self.assertIn("crx-lb-02-example-net@mgr.example.net:&lt;certificate&gt;/", page)
        self.assertIn("Ready-made:</strong> <code>examples/receivers/fetch-sftp</code>", page)
        self.assertIn("install-pkcs12.ps1</code> imports the <code>.pfx</code>", page)
        # In use: no Remove; nothing yet: Remove.
        self.assertIn('title="Use Remove from… on the certificate first"', page)
        self.assertIn('name="receiver" value="lb-02.example.net"', page)
        self.assertIn('href="/certificates/receivers/new">Register a receiver</a>', page)
        # The form is its own page: nothing from before the job is here.
        self.assertNotIn("Register the receiver", page)
        self.assertNotIn("ssh-keygen", page)
        self.assertNotIn("legacy-layout receiver is migrated", page)

    def test_the_form_is_its_own_page_with_the_key_steps_for_both_systems(self) -> None:
        page = self.writing_client().get("/certificates/receivers/new").text

        self.assertIn("<h1>Register a receiver</h1>", page)
        self.assertIn("Register the receiver", page)
        self.assertIn('href="/certificates/receivers">Cancel', page)
        self.assertIn('data-os="linux">Linux:</span>', page)
        self.assertIn("Windows (PowerShell, OpenSSH client installed):", page)
        self.assertIn(
            "ssh-keygen -t ed25519 -N &#39;&#34;&#34;&#39; -C &lt;receiver&gt; -f C:\\certs\\certfetch",
            page,
        )
        self.assertIn("Get-Content C:\\certs\\certfetch.pub", page)
        self.assertIn('value="sftp" checked data-transport-choice data-windows>', page)
        self.assertIn('value="rsync" data-transport-choice>', page)
        # sftp is preset, so the Windows pair is visible; the transport help says why.
        self.assertNotIn('data-os="windows" hidden', page)
        self.assertIn("Can hold any certificate, wildcards included", page)
        self.assertNotIn("Fetch commands", page)

    def test_the_form_hides_windows_for_rsync_before_any_script_runs(self) -> None:
        response = self.add(self.writing_client(), public_key="not a key")
        self.assertIn('data-os="windows" hidden', response.text)

    def test_the_gates_are_the_registry_s(self) -> None:
        self.assertEqual(
            self.writing_client(role="reader").get("/certificates/receivers").status_code, 403
        )
        self.assertEqual(
            self.writing_client(writes=False).get("/certificates/receivers").status_code, 404
        )
        client = self.writing_client()
        self.assertEqual(self.remove(client, "lb-02.example.net", token="bad").status_code, 403)

    def test_the_certificate_form_links_here_and_lists_receivers_one_per_row(self) -> None:
        page = self.writing_client().get("/certificates/new").text
        self.assertIn('href="/certificates/receivers">Manage receivers</a>', page)
        self.assertEqual(
            self.writing_client(role="reader").get("/certificates/receivers/new").status_code,
            403,
        )
        self.assertIn('<span class="target-what">receiver · sftp</span>', page)
        self.assertIn('href="/certificates?view=registry">Cancel</a>', page)

    def test_the_registry_page_offers_the_button(self) -> None:
        page = self.writing_client().get("/certificates?view=registry").text
        self.assertIn('href="/certificates/receivers">Receivers</a>', page)


class TheJobs(ReceiverRouteTestCase):
    def test_registering_queues_one_add_job_and_audits_the_name_not_the_key(self) -> None:
        response = self.add(self.writing_client())

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/certificates/receivers")
        self.assertEqual(len(self.queued), 1)
        self.assertEqual(self.queued[0]["operation"], "cert_receiver")
        self.assertEqual(
            self.queued[0]["payload"],
            {
                "receiver": "lb-03.example.net",
                "action": "add",
                "transport": "rsync",
                "public_key": KEY,
            },
        )
        self.assertEqual(self.audit[-1], "queue_job")

    def test_an_https_receiver_carries_its_allowlist(self) -> None:
        self.add(
            self.writing_client(),
            receiver="192.0.2.9",
            transport="https",
            public_key="",
            allow="192.0.2.9/32",
        )
        self.assertEqual(self.queued[0]["payload"]["allow"], ["192.0.2.9/32"])

    def password_on(self, page: str) -> str:
        found = re.search(r"login \S+ password ([A-Za-z0-9_-]{32})\b", page)
        if found is None:
            self.fail("no password on the page")
        return found.group(1)

    def assert_hash_of(self, hashed: str, password: str) -> None:
        self.assertEqual(crypt(password, hashed), hashed)

    def test_an_https_receiver_s_password_is_shown_once_and_only_its_hash_queued(self) -> None:
        """B306 (security review S03): the job row is stored, so it carries the hash."""

        response = self.add(
            self.writing_client(),
            receiver="192.0.2.9",
            transport="https",
            public_key="",
            allow="192.0.2.9/32",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["cache-control"], "no-store")
        password = self.password_on(response.text)
        payload = self.queued[0]["payload"]
        self.assertNotIn(password, json.dumps(payload))
        self.assert_hash_of(payload["secret_hash"], password)
        page = self.writing_client().get("/certificates/receivers").text
        self.assertNotIn(password, page)

    def test_a_new_secret_is_for_an_https_receiver_and_shown_once(self) -> None:
        self.records.append(record("192.0.2.9", transport="https", allow=("192.0.2.9/32",)))
        client = self.writing_client()
        page = client.get("/certificates/receivers").text
        self.assertIn('action="/certificates/receivers/secret"', page)

        def ask(receiver: str) -> Any:
            return client.post(
                "/certificates/receivers/secret",
                data={
                    "receiver": receiver,
                    "idempotency_key": str(uuid4()),
                    auth.CSRF_FIELD: auth.csrf_token(client.cookies[auth.SESSION_COOKIE]),
                },
                follow_redirects=False,
            )

        refused = ask("lb-02.example.net")
        self.assertIn("is not an https receiver", refused.text)
        self.assertEqual(self.queued, [])

        response = ask("192.0.2.9")
        password = self.password_on(response.text)
        self.assertEqual(self.queued[0]["payload"]["action"], "secret")
        self.assert_hash_of(self.queued[0]["payload"]["secret_hash"], password)

    def test_a_refused_form_is_drawn_again_with_what_was_typed(self) -> None:
        response = self.add(self.writing_client(), public_key="not a key")

        self.assertEqual(response.status_code, 200)
        self.assertIn("not a public key in OpenSSH", response.text)
        self.assertIn('value="lb-03.example.net"', response.text)
        self.assertEqual(self.queued, [])

    def test_removing_queues_one_remove_job_for_a_receiver_nothing_names(self) -> None:
        response = self.remove(self.writing_client(), "lb-02.example.net")

        self.assertEqual(response.status_code, 303)
        self.assertEqual(
            self.queued[0]["payload"], {"receiver": "lb-02.example.net", "action": "remove"}
        )

    def test_removing_a_receiver_in_use_is_refused_on_the_page(self) -> None:
        response = self.remove(self.writing_client(), "lb-01")

        self.assertEqual(response.status_code, 200)
        self.assertIn("still receives app.example.com", response.text)
        self.assertEqual(self.queued, [])

    def failed(self, receiver: str, action: str, *, job_id: int = 7) -> Any:
        return replace(
            queued(
                operation="cert_receiver",
                cluster=None,
                state="done",
                payload={"receiver": receiver, "action": action},
            ),
            id=job_id,
            outcome="failed",
            result={
                "outcome": "failed",
                "result": None,
                "error": {"code": "receiver_unresolvable", "message": "does not resolve"},
            },
        )

    def test_a_failed_registration_is_a_row_of_its_own_with_the_helper_s_words(self) -> None:
        self.activity = [self.failed("lb-03.example.net", "add")]

        page = self.writing_client().get("/certificates/receivers").text

        self.assertIn('<tr class="receiver-row receiver-ghost" data-receiver-ghost="7">', page)
        self.assertIn("<strong>lb-03.example.net</strong>", page)
        self.assertIn('data-receiver-dismiss="7"', page)
        self.assertIn(
            '<span>Registration failed</span><span aria-hidden="true">·</span>'
            '<a href="/jobs#job-7">Job 7</a></span> '
            '<small class="receiver-job-message">does not resolve</small>',
            page,
        )
        self.assertNotIn("preview-notice", page)

    def test_a_running_removal_spins_on_its_row_and_a_failed_one_is_a_badge_there(self) -> None:
        running = queued(
            operation="cert_receiver",
            cluster=None,
            state="running",
            payload={"receiver": "lb-02.example.net", "action": "remove"},
        )
        self.activity = [replace(running, id=8)]
        page = self.writing_client().get("/certificates/receivers").text
        self.assertIn('data-busy="lb-02.example.net"><span class="badge-spinner"', page)
        self.assertIn(
            '<span>Removing</span><span aria-hidden="true">·</span><a href="/jobs#job-8">Job 8</a>',
            page,
        )
        self.assertNotIn("receiver-ghost", page)

        self.activity = [self.failed("lb-02.example.net", "remove", job_id=9)]
        page = self.writing_client().get("/certificates/receivers").text
        self.assertIn(
            '<span>Removal failed</span><span aria-hidden="true">·</span><a href="/jobs#job-9">Job 9</a>',
            page,
        )
        self.assertNotIn("receiver-ghost", page)
