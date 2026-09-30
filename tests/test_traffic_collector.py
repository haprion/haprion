from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from datetime import UTC, date, datetime
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from haproxy_mgmt.traffic_collector import (
    CLOSED_DAY_GRACE,
    CollectorConfig,
    CollectorError,
    NodeTarget,
    ProtocolError,
    Response,
    SSHError,
    _database_row,
    _entry,
    _failure_outcome,
    _parse_response,
    _replace,
    _within_margin,
    collect,
    collect_node,
    load_config,
)

NOW = datetime(2026, 9, 8, 12, tzinfo=UTC)


class TrafficCollectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.mirror = root / "mirror"
        self.staging = root / "staging"
        self.mirror.mkdir()
        self.staging.mkdir()
        self.target = NodeTarget("alpha", "node-a", "node-a.example.com")
        self.config = CollectorConfig(
            user="svc-logread",
            key=root / "key",
            known_hosts=root / "known_hosts",
            mirror=self.mirror,
            staging=self.staging,
            nodes=(self.target,),
        )

    def response(self, wanted: date, offset: int, payload: bytes, **flags: object) -> Response:
        return Response(
            size=offset + len(payload),
            offset=offset,
            sent=len(payload),
            eof=bool(flags.get("eof", True)),
            reset=bool(flags.get("reset", False)),
            skipped_bytes=int(flags.get("skipped_bytes", 0)),
            payload=payload,
        )

    def test_a_record_the_database_cannot_take_is_the_row_parser_s_refusal(self) -> None:
        """One exception type for everything a record can be, so `_ingest_part`
        can step over it. A stamp past the year 9999 raised OSError or
        ValueError and a NUL in a text field reached PostgreSQL, which refused
        the whole batch - each a permanent stop, since the checkpoint never
        passes the record that raised (review 2026-09-17, finding 3)."""

        base = {
            "schema": 1,
            "at": 1_700_000_000,
            "request": 1,
            "client": "192.0.2.1",
            "method": "GET",
            "host": "a.example.test",
            "path": "/",
            "frontend": "f",
            "backend": "b",
            "server": "s1",
            "status": 200,
            "request_time": 0,
            "queue_time": 0,
            "connect_time": 0,
            "response_time": 0,
            "total_time": 0,
            "bytes": 0,
        }
        row = _database_row("alpha", "node-a", json.dumps(base).encode())
        self.assertEqual(row[7], "a.example.test")
        for change in ({"at": 2**62}, {"at": 10**12}, {"path": "/a\0b"}, {"host": "\0"}):
            with self.subTest(change=change), self.assertRaises(CollectorError):
                _database_row("alpha", "node-a", json.dumps(base | change).encode())
        self.assertEqual(
            _database_row("alpha", "node-a", json.dumps(base | {"at": 253402300799}).encode())[3],
            datetime(9999, 12, 31, 23, 59, 59, tzinfo=UTC),
        )

    def test_the_margin_day_is_not_reported_as_older_than_the_database_keeps(self) -> None:
        """The mirror keeps one day below the oldest partition on purpose
        (B155); that day is not an anomaly and is not counted every minute.
        A day older than the margin, or newer than every partition, is."""

        days = frozenset({"20260910", "20260911", "20260917"})
        self.assertTrue(_within_margin("2026-09-09", days))
        self.assertFalse(_within_margin("2026-09-08", days))
        self.assertFalse(_within_margin("2026-09-18", days))
        self.assertFalse(_within_margin("not-a-day", days))

    def test_the_nodes_are_fetched_at_once_and_one_failing_leaves_the_other(self) -> None:
        """Fas 16 punkt 1: a run takes as long as its slowest node, not their sum."""

        other = NodeTarget("alpha", "node-b", "node-b.example.com")
        configured = CollectorConfig(
            user="svc-logread",
            key=self.config.key,
            known_hosts=self.config.known_hosts,
            mirror=self.mirror,
            staging=self.staging,
            nodes=(self.target, other),
        )
        # The first fetch of each node waits for the other's; in series the
        # first node would wait alone and the barrier would break.
        together = threading.Barrier(2, timeout=5)
        first = {self.target.node: True, other.node: True}

        def fetch(target: NodeTarget, wanted: date, offset: int) -> Response:
            if first[target.node]:
                first[target.node] = False
                together.wait()
            if target.node == "node-b":
                raise SSHError("node-b did not answer")
            return self.response(wanted, offset, b"")

        errors = StringIO()
        with patch("sys.stderr", errors):
            self.assertEqual(collect(configured, now=NOW, fetch=fetch), 1)

        self.assertTrue((self.mirror / "alpha--node-a.jsonl").exists())
        self.assertIn("alpha/node-b: node-b did not answer", errors.getvalue())
        meta = json.loads((self.mirror / "alpha--node-b.meta.json").read_text())
        self.assertIsNone(meta["last_success"])
        self.assertNotEqual(meta["outcome"], "ok")

    def test_new_data_is_fsynced_to_a_part_then_atomically_assembled(self) -> None:
        calls: list[tuple[date, int]] = []

        def fetch(_target: NodeTarget, wanted: date, offset: int) -> Response:
            calls.append((wanted, offset))
            payload = b'{"schema":1,"path":"/"}\n' if wanted == NOW.date() and offset == 0 else b""
            return self.response(wanted, offset, payload)

        self.assertEqual(collect(self.config, now=NOW, fetch=fetch), 0)
        self.assertEqual(
            (self.mirror / "alpha--node-a.jsonl").read_bytes(),
            b'{"schema":1,"path":"/"}\n',
        )
        meta = json.loads((self.mirror / "alpha--node-a.meta.json").read_bytes())
        self.assertEqual((meta["outcome"], meta["last_success"]), ("ok", NOW.isoformat()))
        self.assertEqual(calls[0], (NOW.date(), 0))

    def test_rerun_uses_the_committed_part_size_and_does_not_duplicate(self) -> None:
        line = b'{"schema":1}\n'

        def fetch(_target: NodeTarget, wanted: date, offset: int) -> Response:
            payload = line if wanted == NOW.date() and offset == 0 else b""
            return self.response(wanted, offset, payload)

        self.assertEqual(collect(self.config, now=NOW, fetch=fetch), 0)
        self.assertEqual(collect(self.config, now=NOW, fetch=fetch), 0)
        self.assertEqual((self.mirror / "alpha--node-a.jsonl").read_bytes(), line)

    def test_yesterday_is_read_again_until_the_midnight_grace_has_passed(self) -> None:
        yesterday = NOW.date() - date.resolution
        for age in range(2, 14):
            marker = self.staging / f"alpha--node-a--{NOW.date() - age * date.resolution}.done"
            marker.write_bytes(b"")
        calls: list[tuple[date, int]] = []

        def fetch(_target: NodeTarget, wanted: date, offset: int) -> Response:
            calls.append((wanted, offset))
            return self.response(wanted, offset, b"")

        shortly_after_midnight = datetime(2026, 9, 8, 0, 1, tzinfo=UTC)
        collect_node(
            self.config,
            self.target,
            now=shortly_after_midnight,
            fetch=fetch,
        )
        self.assertIn((yesterday, 0), calls)
        marker = self.staging / f"alpha--node-a--{yesterday}.done"
        self.assertFalse(marker.exists())

        calls.clear()
        collect_node(
            self.config,
            self.target,
            now=shortly_after_midnight + CLOSED_DAY_GRACE,
            fetch=fetch,
        )
        self.assertIn((yesterday, 0), calls)
        self.assertTrue(marker.exists())

    def test_failure_preserves_the_mirror_and_last_success(self) -> None:
        line = b'{"schema":1}\n'

        def good(_target: NodeTarget, wanted: date, offset: int) -> Response:
            return self.response(
                wanted, offset, line if wanted == NOW.date() and offset == 0 else b""
            )

        self.assertEqual(collect(self.config, now=NOW, fetch=good), 0)

        def failed(_target: NodeTarget, _wanted: date, _offset: int) -> Response:
            raise SSHError("unreachable")

        later = datetime(2026, 9, 8, 12, 1, tzinfo=UTC)
        self.assertEqual(collect(self.config, now=later, fetch=failed), 1)
        self.assertEqual((self.mirror / "alpha--node-a.jsonl").read_bytes(), line)
        meta = json.loads((self.mirror / "alpha--node-a.meta.json").read_bytes())
        self.assertEqual(meta["last_success"], NOW.isoformat())
        self.assertEqual(meta["last_attempt"], later.isoformat())
        self.assertEqual(meta["outcome"], "ssh")

    def test_database_failure_is_visible_without_erasing_mirror_success(self) -> None:
        configured = CollectorConfig(
            self.config.user,
            self.config.key,
            self.config.known_hosts,
            self.config.mirror,
            self.config.staging,
            self.config.nodes,
            "haproxy_ui",
            "/run/postgresql",
        )

        def fetch(_target: NodeTarget, wanted: date, offset: int) -> Response:
            return self.response(wanted, offset, b"")

        with patch(
            "haproxy_mgmt.traffic_collector._ingest_database",
            side_effect=CollectorError("database import failed"),
        ):
            self.assertEqual(collect(configured, now=NOW, fetch=fetch), 1)

        meta = json.loads((self.mirror / "alpha--node-a.meta.json").read_bytes())
        self.assertEqual(meta["outcome"], "database")
        self.assertEqual(meta["last_attempt"], NOW.isoformat())
        self.assertEqual(meta["last_success"], NOW.isoformat())

    def test_remote_reset_discards_the_local_day_without_advancing_a_cursor(self) -> None:
        part = self.staging / "alpha--node-a--2026-09-08.jsonl"
        part.write_bytes(b"old\n")

        def reset(_target: NodeTarget, wanted: date, offset: int) -> Response:
            return Response(0, offset, 0, True, True, 0, b"")

        self.assertEqual(collect(self.config, now=NOW, fetch=reset), 0)
        self.assertEqual(part.read_bytes(), b"")
        self.assertEqual((self.mirror / "alpha--node-a.jsonl").read_bytes(), b"")

    def test_configuration_refuses_duplicate_destinations_and_relative_paths(self) -> None:
        path = Path(self.temporary.name) / "collector.json"
        value = {
            "schema_version": 1,
            "user": "svc-logread",
            "key": "/etc/key",
            "known_hosts": "/etc/known_hosts",
            "mirror": "relative",
            "staging": "/srv/logs/staging",
            "nodes": [{"cluster": "alpha", "node": "node-a", "host": "node-a.example.com"}],
        }
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(CollectorError, "mirror must be absolute"):
            load_config(path, require_secure=False)

    def test_missing_or_symlinked_working_directory_is_refused(self) -> None:
        self.staging.rmdir()
        with self.assertRaisesRegex(CollectorError, "cannot stat staging"):
            collect(self.config, now=NOW, fetch=lambda *_args: None)  # type: ignore[arg-type]

        self.staging.symlink_to(self.mirror, target_is_directory=True)
        with self.assertRaisesRegex(CollectorError, "staging is not a directory or is a symlink"):
            collect(self.config, now=NOW, fetch=lambda *_args: None)  # type: ignore[arg-type]

    def test_response_flags_must_agree_with_the_cursor_and_remote_size(self) -> None:
        day = NOW.date()
        headers = (
            {
                "file": day.isoformat(),
                "size": 10,
                "offset": 0,
                "sent": 0,
                "eof": True,
                "reset": False,
                "skipped_bytes": 0,
            },
            {
                "file": day.isoformat(),
                "size": 0,
                "offset": 0,
                "sent": 0,
                "eof": True,
                "reset": True,
                "skipped_bytes": 0,
            },
        )
        for header in headers:
            raw = json.dumps(header).encode() + b"\n"
            with (
                self.subTest(header=header),
                self.assertRaisesRegex(CollectorError, "inconsistent"),
            ):
                _parse_response(raw, day, 0)

    def test_metadata_failure_categories_are_stable_and_operator_facing(self) -> None:
        self.assertEqual(_failure_outcome(SSHError("down")), "ssh")
        self.assertEqual(_failure_outcome(ProtocolError("bad header")), "protocol")
        self.assertEqual(_failure_outcome(OSError("full disk")), "disk")

    def test_every_temporary_file_is_renamed_within_one_directory(self) -> None:
        """The first real run failed on exactly this; a unit test now holds it.

        Not a style rule. `ProtectSystem=strict` with two `ReadWritePaths`
        entries puts the mirror and staging in separate bind mounts, and
        `rename` across two mounts is EXDEV even when one filesystem backs
        both - so a temporary staged in the wrong directory cannot be published
        at all.
        """

        renames: list[tuple[Path, Path]] = []
        real = os.replace

        def watched(source: object, destination: object) -> None:
            renames.append((Path(str(source)).parent, Path(str(destination)).parent))
            real(source, destination)  # type: ignore[arg-type]

        def fetch(_target: NodeTarget, wanted: date, offset: int) -> Response:
            payload = b'{"schema":1,"path":"/"}\n' if wanted == NOW.date() and offset == 0 else b""
            return self.response(wanted, offset, payload)

        with patch("haproxy_mgmt.traffic_collector.os.replace", watched):
            self.assertEqual(collect(self.config, now=NOW, fetch=fetch), 0)

        self.assertTrue(renames, "nothing was published")
        for source, destination in renames:
            self.assertEqual(source, destination, "a rename crossed two ReadWritePaths entries")

    def test_failed_atomic_replace_preserves_destination_and_removes_temporary(self) -> None:
        destination = self.mirror / "state.json"
        destination.write_bytes(b"old\n")

        with (
            patch("haproxy_mgmt.traffic_collector.os.replace", side_effect=OSError("full disk")),
            self.assertRaisesRegex(OSError, "full disk"),
        ):
            _replace(destination, b"new\n")

        self.assertEqual(destination.read_bytes(), b"old\n")
        self.assertEqual(list(self.mirror.glob(".state.json.new-*")), [])

    def test_atomic_replace_sets_the_requested_mode_independent_of_umask(self) -> None:
        destination = self.mirror / "state.json"
        previous = os.umask(0o077)
        try:
            _replace(destination, b"state\n", 0o640)
        finally:
            os.umask(previous)

        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o640)

    def test_check_config_parses_without_contacting_a_node(self) -> None:
        output = StringIO()
        with (
            patch.object(sys, "argv", ["collector", "--check-config", "/etc/config.json"]),
            patch("haproxy_mgmt.traffic_collector.load_config", return_value=self.config) as loader,
            patch("haproxy_mgmt.traffic_collector.collect") as collect_mock,
            redirect_stdout(output),
            self.assertRaises(SystemExit) as stopped,
        ):
            _entry()

        self.assertEqual(stopped.exception.code, 0)
        loader.assert_called_once_with(Path("/etc/config.json"))
        collect_mock.assert_not_called()
        self.assertEqual(output.getvalue(), "parsed 1 node(s) as svc-logread\n")


if __name__ == "__main__":
    unittest.main()


INSTALL = Path(__file__).resolve().parents[1] / "install" / "platform"
STEP = INSTALL / "13-platform-traffic-collector"
RENDER = re.compile(r"^import json\nimport sys\n.*?^PY$", re.DOTALL | re.MULTILINE)


class WhatTheInstallationStepWrites(unittest.TestCase):
    """The step and the loader must agree, and only one of them is tested code.

    The configuration is rendered by a small Python block inside a shell
    script. Extracting and running that block is the only way this suite can
    say the installed file will parse; asserting the field names by hand would
    pass while the script wrote something else.
    """

    def render(self, inventory: list[str]) -> dict[str, object]:
        found = RENDER.search(STEP.read_text())
        if found is None:
            self.fail("the configuration renderer is no longer where the test extracts it from")
        source = found.group(0).removesuffix("PY")
        # The command is this interpreter and a block read out of our own
        # installation script; nothing here comes from outside the repository.
        result = subprocess.run(  # noqa: S603
            [
                sys.executable,
                "-c",
                source,
                "svc-logread",
                "/etc/haproxy-manager/traffic-collector/id_ed25519",
                "/etc/haproxy-manager/traffic-collector/known_hosts",
                "/apps/haproxy-manager/logs/mirror",
                "/apps/haproxy-manager/logs/staging",
                "haproxy_ui",
                "/var/run/postgresql",
                *inventory,
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        value: dict[str, object] = json.loads(result.stdout)
        return value

    def written(self, inventory: list[str]) -> Path:
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory)
        path = Path(directory) / "traffic-collector.json"
        path.write_text(json.dumps(self.render(inventory)))
        return path

    def test_the_collector_accepts_what_the_step_renders(self) -> None:
        path = self.written(["alpha:node-a:node-a.example.com", "beta:node-c:node-c.example.com"])

        config = load_config(path, require_secure=False)

        self.assertEqual(config.user, "svc-logread")
        self.assertEqual(
            [(item.cluster, item.node, item.host) for item in config.nodes],
            [
                ("alpha", "node-a", "node-a.example.com"),
                ("beta", "node-c", "node-c.example.com"),
            ],
        )
        self.assertEqual(config.mirror, Path("/apps/haproxy-manager/logs/mirror"))
        self.assertEqual(config.staging, Path("/apps/haproxy-manager/logs/staging"))

    def test_a_node_whose_name_is_its_hostname_is_rendered_whole(self) -> None:
        """`node_host` returns the whole entry when there is no colon."""

        config = load_config(self.written(["alpha:lb-01:lb-01"]), require_secure=False)

        self.assertEqual(config.nodes[0].host, "lb-01")

    def test_the_mirror_and_staging_share_a_parent(self) -> None:
        """One place, one filesystem, one volume to size.

        No longer what makes the rename safe - the unit gives systemd each
        directory as its own `ReadWritePaths` entry, so a rename between them
        is EXDEV whatever the disk says, and every temporary file is therefore
        written in the directory it is renamed into.
        """

        config = load_config(
            self.written(["alpha:node-a:node-a.example.com"]), require_secure=False
        )

        self.assertEqual(config.mirror.parent, config.staging.parent)


class TheCollectorUnits(unittest.TestCase):
    def setUp(self) -> None:
        self.rendered = {}
        for kind in ("service", "timer"):
            source = INSTALL / "examples" / f"haproxy-ui-traffic-collector.{kind}.example"
            self.rendered[kind] = (
                source.read_text()
                .replace("PLATFORM_ROOT", "/apps/haproxy-manager")
                .replace("COLLECTOR_USER", "haproxy-ui-collector")
            )

    def test_it_runs_as_the_collector_and_may_gain_nothing(self) -> None:
        service = self.rendered["service"]

        self.assertIn("User=haproxy-ui-collector", service)
        self.assertIn("NoNewPrivileges=yes", service)
        self.assertIn("CapabilityBoundingSet=\n", service)
        self.assertIn(
            "ExecStart=/opt/haproxy-mgmt/current/bin/haproxy-ui-traffic-collector",
            service,
        )
        self.assertNotIn("/apps/haproxy-manager/current/venv", service)

    def test_it_may_write_only_the_mirror_and_staging(self) -> None:
        self.assertIn(
            "ReadWritePaths=/apps/haproxy-manager/logs/mirror /apps/haproxy-manager/logs/staging",
            self.rendered["service"],
        )
        self.assertIn("ProtectSystem=strict", self.rendered["service"])

    def test_it_speaks_ssh_and_nothing_else(self) -> None:
        self.assertIn("RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6", self.rendered["service"])

    def test_it_is_a_timer_rather_than_a_daemon(self) -> None:
        self.assertIn("Type=oneshot", self.rendered["service"])
        self.assertIn("OnActiveSec=2min", self.rendered["timer"])
        self.assertNotIn("OnBootSec=", self.rendered["timer"])
        self.assertIn("OnUnitActiveSec=1min", self.rendered["timer"])

    def test_the_nodes_come_from_the_cluster_file_not_the_answers(self) -> None:
        """A node added from the interface (B211) survives this step being run again."""

        step = STEP.read_text()

        self.assertIn('"$CLUSTER_CONFIG" -c "$1" --field nodes', step)
        self.assertNotIn("cluster_value NODES", step)

    def test_sudo_is_tested_as_the_collector_not_listed_by_root(self) -> None:
        step = STEP.read_text()

        self.assertIn(
            'sudo -n -u "$COLLECTOR_USER" sudo -n -l',
            step,
        )
        self.assertNotIn('sudo -n -l -U "$COLLECTOR_USER"', step)

    @unittest.skipUnless(shutil.which("systemd-analyze"), "systemd is not installed here")
    def test_real_systemd_accepts_both_units(self) -> None:
        analyze = shutil.which("systemd-analyze") or ""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for kind, text in self.rendered.items():
                (root / f"haproxy-ui-traffic-collector.{kind}").write_text(text)
            for kind in ("timer", "service"):
                result = subprocess.run(  # noqa: S603
                    [analyze, "verify", str(root / f"haproxy-ui-traffic-collector.{kind}")],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                #
                # The release tree is not installed where this suite runs, so
                # the command the unit starts is expected to be unreachable.
                # Every other complaint about our own units is a defect.
                #
                complaints = [
                    line
                    for line in (result.stderr + result.stdout).splitlines()
                    if "haproxy-ui-traffic-collector" in line and "is not executable" not in line
                ]

                self.assertEqual(complaints, [], result.stderr or result.stdout)
