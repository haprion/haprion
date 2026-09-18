"""The receivers page (B142): the rows, the commands each host runs, the two jobs.

The engine's registration is tested with the engine. This side owns the
reading of the registry block, the derivation of the fetch commands from a
row, the form's refusals said before a job is queued, and the routes' gates.
"""

from __future__ import annotations

import unittest
from dataclasses import replace
from typing import Any
from unittest import mock
from uuid import uuid4

from haproxy_ui import auth, certificate_receivers
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

    def test_a_legacy_row_is_not_removable_from_here(self) -> None:
        _, rows = certificate_receivers.parse_receiver_rows(
            block(record("pve-01.example.net", layout="flat", owner="svc-app"))
        )
        self.assertTrue(rows[0].legacy)
        self.assertFalse(rows[0].removable)


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
        self.assertEqual(len(steps), 2)
        linux, windows = steps
        self.assertIn("sftp -b - -i /root/.ssh/certfetch", linux.command)
        self.assertIn("get /app.example.com/app.example.com.pfx", linux.command)
        self.assertIn("get /app.example.com/app.example.com.password", linux.command)
        self.assertIn('@"', windows.command)
        self.assertIn("C:\\certs\\app.example.com.pfx", windows.command)
        self.assertIn("install-pkcs12.ps1", windows.note)

    def test_https_pins_the_interface_and_fetches_under_the_allowlist(self) -> None:
        (row,) = self.rows(record("192.0.2.9", transport="https", allow=("192.0.2.9/32",)))
        steps = certificate_receivers.fetch_steps(row, "mgr.example.net")
        self.assertIn("openssl s_client -connect mgr.example.net:443", steps[0].command)
        self.assertIn(
            "https://mgr.example.net/certdist/192.0.2.9/<certificate>/fullchain.pem",
            steps[1].command,
        )
        self.assertIn("--cacert manager-ui.pem", steps[1].command)

    def test_a_receiver_holding_nothing_still_gets_its_commands(self) -> None:
        (row,) = self.rows(record("lb-02.example.net"))
        steps = certificate_receivers.fetch_steps(row, None)
        self.assertIn("crx-lb-02-example-net@<manager>:<certificate>/", steps[0].command)

    def test_the_key_is_made_on_the_receiver_and_named_after_it(self) -> None:
        first, second = certificate_receivers.key_steps("lb-02.example.net")
        self.assertIn("ssh-keygen -t ed25519 -N '' -C lb-02.example.net", first.command)
        self.assertIn("C:\\certs\\certfetch", first.note)
        self.assertEqual(second.command, "cat /root/.ssh/certfetch.pub")


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
        }
        for name, fields in cases.items():
            with self.subTest(name), self.assertRaises(certificate_receivers.ReceiverProblem):
                self.payload(**fields)

    def test_a_removal_needs_a_registered_receiver_nothing_names(self) -> None:
        rows = certificate_receivers.parse_receiver_rows(
            block(
                record("lb-01", certificates=("app.example.com",)),
                record("lb-02.example.net"),
                record("pve-01.example.net", layout="flat"),
            )
        )[1]
        self.assertEqual(
            certificate_receivers.removal("lb-02.example.net", rows),
            {"receiver": "lb-02.example.net", "action": "remove"},
        )
        for name in ("lb-01", "pve-01.example.net", "nobody"):
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
                "haproxy_ui.db.cluster_certificates",
                side_effect=lambda *_a, **_k: [
                    replace(
                        certificate_reading(),
                        result={**certificate_reading().result, "registry": block(*self.records)},
                    )
                ],
            ),
            mock.patch(
                "haproxy_ui.db.operation_jobs", side_effect=lambda *_a, **_k: list(self.activity)
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
        return client.post("/certificates/receivers", data=data, follow_redirects=False)

    def remove(self, client: Any, receiver: str, *, token: str | None = None) -> Any:
        token = auth.csrf_token(client.cookies[auth.SESSION_COOKIE]) if token is None else token
        return client.post(
            "/certificates/receivers/remove",
            data={"receiver": receiver, "idempotency_key": str(uuid4()), auth.CSRF_FIELD: token},
            follow_redirects=False,
        )


class ThePage(ReceiverRouteTestCase):
    def test_it_lists_the_rows_with_their_commands_and_the_form(self) -> None:
        page = self.writing_client().get("/certificates/receivers").text

        self.assertIn("<h1>Receivers</h1>", page)
        self.assertIn("<strong>lb-01</strong>", page)
        self.assertIn('app.example.com <span class="target-kind">pkcs12</span>', page)
        self.assertIn("get /app.example.com/app.example.com.pfx", page)
        self.assertIn("crx-lb-02-example-net@mgr.example.net:&lt;certificate&gt;/", page)
        # In use: no Remove; nothing yet: Remove.
        self.assertIn('title="Use Remove from… on the certificate first"', page)
        self.assertIn('name="receiver" value="lb-02.example.net"', page)
        self.assertIn("Register the receiver", page)
        self.assertIn('href="/certificates?view=registry">Cancel', page)
        self.assertIn("ssh-keygen -t ed25519", page)

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
        self.assertIn('<span class="receiver-transport">· sftp</span>', page)
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

    def test_a_failed_job_is_said_at_the_top_with_the_helper_s_words(self) -> None:
        self.activity = [
            replace(
                queued(
                    operation="cert_receiver",
                    cluster=None,
                    state="done",
                    payload={"receiver": "lb-03.example.net", "action": "add"},
                ),
                outcome="failed",
                result={
                    "outcome": "failed",
                    "result": None,
                    "error": {"code": "receiver_unresolvable", "message": "does not resolve"},
                },
            )
        ]
        page = self.writing_client().get("/certificates/receivers").text
        self.assertIn("Registering lb-03.example.net failed.</strong> does not resolve", page)
