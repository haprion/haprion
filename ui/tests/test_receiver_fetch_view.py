"""*Last fetched* (B496, 10; B498): the poller's reading, the table, and where it is said.

Pinned here: the poller asks the reading in the cert_list call and moves its
starting point only on a reading with every witness read; the Receivers page,
the certificate's row and *Needs attention* say the same thing about one
receiver; and a page that did not read the fetches says nothing about them
rather than "not fetched".
"""

from __future__ import annotations

import contextlib
import json
import re
import subprocess
import unittest
from collections.abc import Mapping
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest import mock

from haprion_ui import attention, certificate_receivers, certificates, demo, poller
from tests.test_login import LoginTestCase, configuration
from tests.test_poller import document

NOW = datetime(2026, 11, 8, 12, 0, tzinfo=UTC)
WRITTEN = NOW - timedelta(days=9)


def block(published_at: datetime | None = WRITTEN) -> dict[str, Any]:
    stamp = published_at.isoformat().replace("+00:00", "Z") if published_at else None
    return {
        "manager": "mgr.example.com",
        "certificates": [
            {
                "id": "app.example.com",
                "targets": {
                    "clusters": [],
                    "receivers": [
                        {
                            "id": "lb-02.example.net",
                            "format": "pem",
                            "published_at": stamp,
                            "current": True,
                        }
                    ],
                },
            }
        ],
        "receiver_records": [
            {
                "id": "lb-02.example.net",
                "transport": "rsync",
                "layout": "per-certificate",
                "owner": "crx-lb-02-example-net",
                "path": "/srv/receivers/lb-02.example.net",
                "allow": [],
                "certificates": ["app.example.com"],
            }
        ],
    }


class TheReceiversRow(unittest.TestCase):
    def row(self, fetched: Mapping[str, datetime] | None) -> certificate_receivers.ReceiverRow:
        _, rows = certificate_receivers.parse_receiver_rows(block(), fetched)
        return rows[0]

    def test_a_fetch_after_the_copy_is_plain_and_one_before_it_is_behind(self) -> None:
        after = self.row({"lb-02.example.net": WRITTEN + timedelta(hours=1)})
        before = self.row({"lb-02.example.net": WRITTEN - timedelta(hours=1)})

        self.assertFalse(after.fetched_before_publish)
        self.assertTrue(before.fetched_before_publish)
        self.assertRegex(after.fetched_label, r"^\d\d-\d\d-\d\d \d\d:\d\d:\d\d$")

    def test_none_seen_is_never_and_none_read_is_not_known(self) -> None:
        self.assertEqual(self.row({}).fetched_label, "Never")
        self.assertTrue(self.row({}).fetches_known)
        self.assertFalse(self.row(None).fetches_known)


class TheCertificatesState(unittest.TestCase):
    def target(self, fetched: datetime | None, *, known: bool = True) -> certificates.TargetView:
        return certificates.TargetView(
            name="lb-02.example.net",
            kind="receiver",
            published_at=WRITTEN,
            published_label="Published",
            current=True,
            fetched_at=fetched,
            fetches_known=known,
        )

    def state(self, *targets: certificates.TargetView) -> tuple[str, str, str]:
        return certificates._registry_state(
            {"readable": True},
            targets,
            identifier="app.example.com",
            fingerprint="",
            carriage={},
            now=NOW,
        )

    def test_fetched_says_installing_is_not_reported(self) -> None:
        _, detail, tone = self.state(self.target(WRITTEN + timedelta(minutes=5)))
        self.assertEqual((detail, tone), ("Fetched; installing it is not reported", "healthy"))

    def test_one_not_fetched_since_the_copy_is_counted(self) -> None:
        _, detail, _ = self.state(
            self.target(WRITTEN - timedelta(days=1)),
            replace(self.target(WRITTEN + timedelta(hours=1)), name="lb-03.example.net"),
        )
        self.assertEqual(detail, "1 of 2 receivers have not fetched it")

    def test_fetches_not_read_say_what_they_always_said(self) -> None:
        _, detail, _ = self.state(self.target(None, known=False))
        self.assertEqual(detail, "Whether it was fetched is not reported")


class NeedsAttention(unittest.TestCase):
    def registry(self, fetched: datetime | None, *, written: datetime = WRITTEN) -> Any:
        target = certificates.TargetView(
            name="lb-02.example.net",
            kind="receiver",
            published_at=written,
            published_label="",
            current=True,
            fetched_at=fetched,
            fetches_known=True,
        )
        return mock.Mock(certificates=[mock.Mock(identifier="app.example.com", targets=(target,))])

    def test_a_copy_unfetched_for_a_week_is_a_row_and_a_fetched_one_is_not(self) -> None:
        (item,) = attention.from_receiver_fetches(self.registry(None), now=NOW)

        self.assertEqual(item.subject, "lb-02.example.net")
        self.assertTrue(item.message.startswith("has not fetched app.example.com, written for it "))
        self.assertEqual(item.link, "/certificates/receivers")
        self.assertEqual(item.page, "Certificates")
        self.assertEqual(
            attention.from_receiver_fetches(self.registry(WRITTEN + timedelta(days=1)), now=NOW), []
        )

    def test_a_copy_written_less_than_a_week_ago_waits(self) -> None:
        recent = self.registry(None, written=NOW - timedelta(days=6))
        self.assertEqual(attention.from_receiver_fetches(recent, now=NOW), [])

    def test_the_next_unfetched_renewal_is_a_new_row(self) -> None:
        (first,) = attention.from_receiver_fetches(self.registry(None), now=NOW)
        (later,) = attention.from_receiver_fetches(
            self.registry(None, written=WRITTEN - timedelta(days=60)), now=NOW
        )
        self.assertNotEqual(first.variant, later.variant)


class ThePollerAsksWithTheCertificates(unittest.TestCase):
    class Pool:
        def connection(self) -> Any:
            return contextlib.nullcontext(mock.Mock())

    def readings(self, *, unread: list[dict[str, str]] | None = None) -> Any:
        self.asked: list[Mapping[str, Any]] = []

        def run(cluster: str | None, request_id: str, reads: Mapping[str, Any]) -> Any:
            self.asked.append(reads)
            certs = document(
                "cert_list",
                result={
                    "interface_served": None,
                    "registry": {"certificates": [], "receivers": []},
                },
                cluster=None,
                request_id=request_id,
            )
            fetches = document(
                "receiver_fetches",
                result={
                    "since": "2026-11-01T00:00:00Z",
                    "receivers": [
                        {
                            "id": "lb-02.example.net",
                            "transport": "rsync",
                            "fetched_at": "2026-11-08T06:00:04Z",
                        },
                        {"id": "lb-03.example.net", "transport": "sftp", "fetched_at": None},
                    ],
                    "unread": unread or [],
                },
                cluster=None,
                request_id=request_id,
            )
            outer = document(
                "readings",
                result={
                    "reads": {
                        "cert_list": {"exit_code": 0, "envelope": certs, "stderr": ""},
                        "receiver_fetches": {"exit_code": 0, "envelope": fetches, "stderr": ""},
                    }
                },
                cluster=None,
                request_id=request_id,
            )
            return subprocess.CompletedProcess([], 0, json.dumps(outer), "")

        return run

    def test_one_call_carries_both_and_the_fetch_is_recorded(self) -> None:
        watch = poller.ReceiverFetchWatch()
        with (
            mock.patch("haprion_ui.db.record_manager_certificates"),
            mock.patch("haprion_ui.db.replace_search_entries"),
            mock.patch("haprion_ui.db.record_receiver_fetches") as recorded,
        ):
            run = self.readings()
            self.assertTrue(poller.poll_manager(self.Pool(), run, watch))
            self.assertTrue(poller.poll_manager(self.Pool(), run, watch))

        self.assertEqual(sorted(self.asked[0]), ["cert_list", "receiver_fetches"])
        self.assertEqual(self.asked[0]["receiver_fetches"], {})
        self.assertIn("since", self.asked[-1]["receiver_fetches"])
        self.assertEqual(
            recorded.call_args.args[1],
            {"lb-02.example.net": datetime(2026, 11, 8, 6, 0, 4, tzinfo=UTC)},
        )

    def test_a_witness_not_read_keeps_the_starting_point(self) -> None:
        watch = poller.ReceiverFetchWatch()
        with (
            mock.patch("haprion_ui.db.record_manager_certificates"),
            mock.patch("haprion_ui.db.replace_search_entries"),
            mock.patch("haprion_ui.db.record_receiver_fetches"),
        ):
            poller.poll_manager(
                self.Pool(), self.readings(unread=[{"source": "journal", "reason": "no"}]), watch
            )

        self.assertIsNone(watch.since)
        self.assertEqual(watch.parameters(), {})


class TheReceiversPage(LoginTestCase):
    def test_the_column_says_each_receiver_s_fetch(self) -> None:
        client = self.client(replace(configuration(), demo_fixture=True))
        self.sign_in(client)
        with mock.patch.object(demo, "receiver_fetches", wraps=demo.receiver_fetches):
            page = client.get("/certificates/receivers").text

        self.assertIn('<th scope="col">Last fetched</th>', page)
        cells = {
            name: cell
            for name, cell in re.findall(
                r'<strong>([^<]+)</strong></td>.*?<td data-label="Last fetched">(.*?)</td>',
                page,
                re.S,
            )
        }
        self.assertIn('class="warning-text"', cells["backup-demo.example"])
        self.assertIn("Never", cells["kiosk-demo.example"])
        self.assertNotIn("warning-text", cells["192.0.2.40"])


if __name__ == "__main__":
    unittest.main()
