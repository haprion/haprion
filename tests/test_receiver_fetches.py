"""When each certificate receiver last fetched (B496, 10; B498).

The two witnesses are read from text the manager already writes: sshd's line in
the journal and nginx's `combined` line. What is pinned here is that only a
receiver's own account or location counts, that the newest wins, that a witness
that cannot be read is said rather than turned into "never fetched", and that
the reading's document is the one its schema describes.
"""

from __future__ import annotations

import io
import json
import stat
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest import mock

from haprion import exit_codes, receiver_fetches
from haprion.cli import receiver_fetches_helper
from haprion.config import Receiver
from tests.contract_schema import assert_contract

RECEIVERS = {
    "lb-02.example.net": Receiver(
        receiver_id="lb-02.example.net",
        path=Path("/srv/receivers/lb-02.example.net"),
        owner="crx-lb-02-example-net",
        transport="rsync",
    ),
    "lb-03.example.net": Receiver(
        receiver_id="lb-03.example.net",
        path=Path("/srv/receivers/lb-03.example.net"),
        owner="crx-lb-03-example-net",
        transport="sftp",
    ),
    "192.0.2.40": Receiver(
        receiver_id="192.0.2.40",
        path=Path("/srv/receivers/192.0.2.40"),
        owner="www-data",
        transport="https",
        allow=("192.0.2.0/24",),
    ),
}
ACCOUNTS = {
    "crx-lb-02-example-net": "lb-02.example.net",
    "crx-lb-03-example-net": "lb-03.example.net",
}


def journal(message: str, at: datetime) -> str:
    return json.dumps(
        {"MESSAGE": message, "__REALTIME_TIMESTAMP": str(int(at.timestamp() * 1_000_000))}
    )


def accepted(account: str, at: datetime) -> str:
    return journal(
        f"Accepted publickey for {account} from 192.0.2.10 port 52892 ssh2: ED25519 SHA256:abc", at
    )


def combined(path: str, status: int, at: datetime, *, method: str = "GET") -> str:
    stamp = at.strftime("%d/%b/%Y:%H:%M:%S +0000")
    return (
        f'192.0.2.40 - 192.0.2.40 [{stamp}] "{method} {path} HTTP/1.1" {status} 3120 "-" '
        '"curl/8.5.0"'
    )


NOW = datetime(2026, 11, 8, 12, 0, tzinfo=UTC)


class TheSshWitness(unittest.TestCase):
    def test_a_receiver_s_login_is_its_fetch_and_the_newest_wins(self) -> None:
        found = receiver_fetches.ssh_logins(
            [
                accepted("crx-lb-02-example-net", NOW - timedelta(hours=2)),
                accepted("crx-lb-02-example-net", NOW - timedelta(minutes=5)),
                accepted("crx-lb-02-example-net", NOW - timedelta(hours=1)),
            ],
            ACCOUNTS,
        )

        self.assertEqual(found, {"lb-02.example.net": NOW - timedelta(minutes=5)})

    def test_anyone_else_s_login_or_another_line_is_not(self) -> None:
        found = receiver_fetches.ssh_logins(
            [
                accepted("operator", NOW),
                journal(
                    "Accepted password for crx-lb-02-example-net from 192.0.2.10 port 1 ssh2", NOW
                ),
                journal(
                    "Failed publickey for crx-lb-03-example-net from 192.0.2.10 port 1 ssh2", NOW
                ),
                "not json",
                json.dumps(
                    {"MESSAGE": "Accepted publickey for crx-lb-03-example-net from x port 1 "}
                ),
            ],
            ACCOUNTS,
        )

        self.assertEqual(found, {})


class TheHttpsWitness(unittest.TestCase):
    def test_a_200_under_the_receiver_s_location_is_its_fetch(self) -> None:
        found = receiver_fetches.https_fetches(
            [
                combined(
                    "/certdist/192.0.2.40/app.example.com/fullchain.pem",
                    200,
                    NOW - timedelta(hours=3),
                ),
                combined(
                    "/certdist/192.0.2.40/app.example.com/privkey.pem",
                    200,
                    NOW - timedelta(hours=1),
                ),
            ],
            ["192.0.2.40"],
            "/certdist",
        )

        self.assertEqual(found, {"192.0.2.40": NOW - timedelta(hours=1)})

    def test_a_refusal_another_location_or_another_method_is_not(self) -> None:
        found = receiver_fetches.https_fetches(
            [
                combined("/certdist/192.0.2.40/app.example.com/fullchain.pem", 401, NOW),
                combined("/certdist/192.0.2.40/app.example.com/fullchain.pem", 403, NOW),
                combined("/certdist/manager-ui.pem", 200, NOW),
                combined("/certdist/192.0.2.41/app.example.com/fullchain.pem", 200, NOW),
                combined("/certdist/192.0.2.40/x", 200, NOW, method="POST"),
                combined("/proxies", 200, NOW),
                "x" * (receiver_fetches.MAX_LINE + 1),
            ],
            ["192.0.2.40"],
            "/certdist",
        )

        self.assertEqual(found, {})

    def test_the_log_and_the_one_rotated_before_it_are_read(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            log = Path(raw) / "haprion-receivers.access.log"
            log.with_name(log.name + ".1").write_text("older\n", encoding="utf-8")
            log.write_text("newer\n", encoding="utf-8")

            self.assertEqual(receiver_fetches.log_lines(log), ["older", "newer"])
            self.assertEqual(receiver_fetches.log_lines(Path(raw) / "absent.log"), [])


class AWitnessThatCannotBeRead(unittest.TestCase):
    def test_is_said_and_the_other_one_still_answers(self) -> None:
        def broken(_since: datetime) -> list[str]:
            raise receiver_fetches.Unreadable("the journal could not be read: no permission")

        fetches = receiver_fetches.read(
            RECEIVERS,
            since=NOW - timedelta(days=1),
            prefix="/certdist",
            journal=broken,
            access_log=lambda: [combined("/certdist/192.0.2.40/a/fullchain.pem", 200, NOW)],
        )

        self.assertEqual(fetches.found, {"192.0.2.40": NOW})
        self.assertEqual(
            fetches.unread, (("journal", "the journal could not be read: no permission"),)
        )
        result = receiver_fetches.result(RECEIVERS, fetches)
        self.assertEqual(
            [(entry["id"], entry["fetched_at"]) for entry in result["receivers"]],
            [
                ("192.0.2.40", "2026-11-08T12:00:00Z"),
                ("lb-02.example.net", None),
                ("lb-03.example.net", None),
            ],
        )

    def test_a_fetch_before_the_moment_asked_from_is_left_out(self) -> None:
        fetches = receiver_fetches.read(
            RECEIVERS,
            since=NOW - timedelta(hours=1),
            prefix="/certdist",
            journal=lambda _since: [],
            access_log=lambda: [
                combined("/certdist/192.0.2.40/a/x.pem", 200, NOW - timedelta(hours=2))
            ],
        )

        self.assertEqual(fetches.found, {})

    def test_journalctl_that_fails_is_unreadable_and_no_match_is_empty(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            for name, script, wanted in (
                ("none", "#!/bin/sh\nexit 1\n", []),
                ("fails", "#!/bin/sh\necho 'Failed to open files' >&2\nexit 1\n", None),
                ("found", "#!/bin/sh\necho line\nexit 0\n", ["line"]),
            ):
                program = Path(raw) / name
                program.write_text(script, encoding="utf-8")
                program.chmod(program.stat().st_mode | stat.S_IXUSR)
                with self.subTest(name):
                    if wanted is None:
                        with self.assertRaises(receiver_fetches.Unreadable):
                            receiver_fetches.journal_lines(NOW, journalctl=str(program))
                    else:
                        self.assertEqual(
                            receiver_fetches.journal_lines(NOW, journalctl=str(program)), wanted
                        )


class TheReading(unittest.TestCase):
    def run_helper(
        self, parameters: dict[str, Any], *, cluster: str | None = None
    ) -> tuple[int, Any]:
        request = {
            "schema_version": 1,
            "operation": "receiver_fetches",
            "cluster": cluster,
            "request_id": "ffffffff-ffff-4fff-8fff-ffffffffffff",
            "parameters": parameters,
        }
        asked: dict[str, Any] = {}

        def read(receivers: Any, *, since: datetime, prefix: str) -> receiver_fetches.Fetches:
            asked.update(since=since, prefix=prefix, receivers=sorted(receivers))
            return receiver_fetches.Fetches(
                found={"lb-02.example.net": since + timedelta(minutes=1)}, unread=()
            )

        output = io.StringIO()
        runtime = SimpleNamespace(registry=SimpleNamespace(receivers=RECEIVERS))
        with (
            mock.patch.object(receiver_fetches_helper, "load_policy"),
            mock.patch.object(receiver_fetches_helper, "load_runtime_config", return_value=runtime),
        ):
            code = receiver_fetches_helper.main(
                [],
                input_stream=io.BytesIO(json.dumps(request).encode()),
                output_stream=output,
                error_stream=io.StringIO(),
                require_root=False,
                read=read,
            )
        self.asked = asked
        return code, json.loads(output.getvalue()) if output.getvalue() else None

    def test_answers_every_receiver_in_its_contract(self) -> None:
        since = (datetime.now(UTC) - timedelta(hours=1)).replace(microsecond=0)
        code, document = self.run_helper({"since": since.isoformat().replace("+00:00", "Z")})

        self.assertEqual(code, 0)
        assert_contract("haprion-receiver-fetches", json.dumps(document))
        self.assertEqual(self.asked["since"], since)
        self.assertEqual(self.asked["prefix"], "/certdist")
        self.assertEqual(len(document["result"]["receivers"]), 3)

    def test_a_moment_too_far_back_is_held_to_the_bound_and_none_is_eight_days(self) -> None:
        code, _ = self.run_helper({"since": "2020-01-01T00:00:00Z"})
        self.assertEqual(code, 0)
        self.assertGreater(self.asked["since"], datetime.now(UTC) - timedelta(days=32))

        self.run_helper({})
        self.assertLess(
            abs(self.asked["since"] - (datetime.now(UTC) - timedelta(days=8))), timedelta(minutes=1)
        )

    def test_a_cluster_or_a_time_without_an_offset_is_refused(self) -> None:
        for parameters, cluster in (({}, "alpha"), ({"since": "2026-11-08T06:00:00"}, None)):
            with self.subTest(cluster=cluster, parameters=parameters):
                code, document = self.run_helper(parameters, cluster=cluster)
                self.assertEqual(code, exit_codes.USAGE)
                assert_contract("haprion-receiver-fetches", json.dumps(document))


if __name__ == "__main__":
    unittest.main()
