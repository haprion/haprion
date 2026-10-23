from __future__ import annotations

import importlib.util
import io
import json
import re
import shutil
import signal
import socket
import subprocess
import tempfile
import time
import unittest
import unittest.mock
from datetime import UTC, date, datetime, timedelta
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest import mock

BASE = Path(__file__).resolve().parents[1]


def load_script() -> ModuleType:
    path = BASE / "install" / "node" / "haprion-traffic-log-read"
    spec = importlib.util.spec_from_loader(
        "traffic_log_node", SourceFileLoader("traffic_log_node", str(path))
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load node helper")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


HELPER = load_script()
TODAY = date(2026, 9, 8)


class TrafficLogNodeReaderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def call(self, request: str) -> tuple[int, dict[str, object] | None, bytes]:
        output = io.BytesIO()
        code = HELPER.serve(request, self.root, output, today=TODAY)
        if not output.getvalue():
            return code, None, b""
        line, payload = output.getvalue().split(b"\n", 1)
        return code, json.loads(line), payload

    def write(self, day: str, data: bytes) -> None:
        (self.root / f"traffic-{day}.jsonl").write_bytes(data)

    def test_only_an_exact_date_and_decimal_offset_are_accepted(self) -> None:
        for request in (
            "",
            "2026-09-08",
            "2026-09-08 -1",
            "2026-09-08 0 extra",
            "../../etc/passwd 0",
            "2026-02-30 0",
            "2026-08-25 0",
            "2026-09-09 0",
            "2026-09-08 1234567890123",
        ):
            with self.subTest(request=request):
                self.assertEqual(self.call(request), (64, None, b""))

    def test_missing_day_is_an_empty_result(self) -> None:
        code, header, payload = self.call("2026-09-08 0")
        self.assertEqual((code, payload), (0, b""))
        assert header is not None
        self.assertEqual((header["size"], header["sent"], header["eof"]), (0, 0, True))

    def test_missing_day_resets_a_cursor_that_can_no_longer_exist(self) -> None:
        code, header, payload = self.call("2026-09-08 12")
        self.assertEqual((code, payload), (0, b""))
        assert header is not None
        self.assertEqual((header["size"], header["reset"], header["eof"]), (0, True, True))

    def test_cursor_returns_only_whole_records(self) -> None:
        first = b'{"schema":1,"path":"/one"}\n'
        second = b'{"schema":1,"path":"/two"}\n'
        self.write("2026-09-08", first + second)

        code, header, payload = self.call(f"2026-09-08 {len(first)}")

        self.assertEqual((code, payload), (0, second))
        assert header is not None
        self.assertEqual(header["offset"], len(first))
        self.assertTrue(header["eof"])

    def test_offset_beyond_a_replaced_file_requests_a_reset(self) -> None:
        self.write("2026-09-08", b"{}\n")
        code, header, payload = self.call("2026-09-08 99")
        self.assertEqual((code, payload), (0, b""))
        assert header is not None
        self.assertTrue(header["reset"])
        self.assertEqual(header["size"], 3)

    def test_symlink_is_refused(self) -> None:
        target = self.root / "elsewhere"
        target.write_bytes(b"{}\n")
        (self.root / "traffic-2026-09-08.jsonl").symlink_to(target)
        self.assertEqual(self.call("2026-09-08 0"), (65, None, b""))

    def test_a_file_that_grows_while_it_is_read_is_answered_to_its_measured_size(self) -> None:
        #
        # rsyslog appends between the size and the read. The answer must stop
        # at the size it states, or the collector rightly refuses it - which
        # it did on internal at 25 000 requests a second (26-10-12).
        #
        first = b'{"request":1}\n{"request":2}\n'
        self.write("2026-09-08", first)
        path = self.root / "traffic-2026-09-08.jsonl"
        measured = HELPER.os.fstat

        def growing(descriptor: int) -> Any:
            result = measured(descriptor)
            with path.open("ab") as appended:
                appended.write(b'{"request":3}\n')
            return result

        with unittest.mock.patch.object(HELPER.os, "fstat", side_effect=growing):
            code, header, payload = self.call("2026-09-08 0")

        self.assertEqual(code, 0)
        assert header is not None
        self.assertEqual(header["size"], len(first))
        self.assertEqual(payload, first)
        self.assertTrue(header["eof"])
        code, header, payload = self.call(f"2026-09-08 {len(first)}")
        self.assertEqual(payload, b'{"request":3}\n')

    def test_a_day_is_its_hours_read_as_one(self) -> None:
        early = b'{"hour":0}\n'
        later = b'{"hour":5,"n":1}\n{"hour":5,"n":2}\n'
        last = b'{"hour":13}\n'
        self.write("2026-09-08T00", early)
        self.write("2026-09-08T05", later)
        self.write("2026-09-08T13", last)

        code, header, payload = self.call("2026-09-08 0")
        self.assertEqual((code, payload), (0, early + later + last))
        assert header is not None
        self.assertEqual(header["size"], len(early + later + last))

        middle = len(early) + later.index(b"\n") + 1
        code, header, payload = self.call(f"2026-09-08 {middle}")
        self.assertEqual(payload, b'{"hour":5,"n":2}\n' + last)

    def test_a_whole_day_file_from_before_the_hours_comes_first(self) -> None:
        self.write("2026-09-08T14", b'{"after":1}\n')
        self.write("2026-09-08", b'{"before":1}\n')

        code, _, payload = self.call("2026-09-08 0")
        self.assertEqual((code, payload), (0, b'{"before":1}\n{"after":1}\n'))

    def test_an_hour_still_written_while_a_later_one_is_measured_keeps_its_offsets(self) -> None:
        """The later hour is measured first, so an earlier one is final when its size is taken."""

        self.write("2026-09-08T00", b'{"n":1}\n')
        self.write("2026-09-08T01", b'{"n":3}\n')
        earlier = self.root / "traffic-2026-09-08T00.jsonl"
        measured = HELPER.os.fstat

        def appending(descriptor: int) -> Any:
            if HELPER.os.readlink(f"/proc/self/fd/{descriptor}").endswith("T01.jsonl"):
                with earlier.open("ab") as appended:
                    appended.write(b'{"n":2}\n')
            return measured(descriptor)

        with unittest.mock.patch.object(HELPER.os, "fstat", side_effect=appending):
            code, header, payload = self.call("2026-09-08 0")

        self.assertEqual(code, 0)
        assert header is not None
        self.assertEqual(payload, b'{"n":1}\n{"n":2}\n{"n":3}\n')
        self.assertEqual(header["size"], len(payload))

    def test_a_day_that_loses_an_hour_it_has_open_is_answered_as_gone(self) -> None:
        self.write("2026-09-08T00", b'{"n":1}\n')
        self.write("2026-09-08T05", b'{"n":2}\n')
        measured = HELPER.os.fstat

        def removing(descriptor: int) -> Any:
            if HELPER.os.readlink(f"/proc/self/fd/{descriptor}").endswith("T00.jsonl"):
                (self.root / "traffic-2026-09-08T05.jsonl").unlink()
            return measured(descriptor)

        with unittest.mock.patch.object(HELPER.os, "fstat", side_effect=removing):
            code, header, payload = self.call("2026-09-08 4")

        self.assertEqual((code, payload), (0, b""))
        assert header is not None
        self.assertEqual((header["size"], header["reset"]), (0, True))

    def test_a_symlinked_hour_is_refused(self) -> None:
        target = self.root / "elsewhere"
        target.write_bytes(b"{}\n")
        self.write("2026-09-08T00", b"{}\n")
        (self.root / "traffic-2026-09-08T03.jsonl").symlink_to(target)
        self.assertEqual(self.call("2026-09-08 0"), (65, None, b""))

    def test_incomplete_final_record_is_not_sent(self) -> None:
        self.write("2026-09-08", b"{}\nunfinished")
        code, header, payload = self.call("2026-09-08 0")
        self.assertEqual((code, payload), (0, b"{}\n"))
        assert header is not None
        self.assertFalse(header["eof"])


def render_rule() -> str:
    """The rule exactly as the node installer writes it."""

    script = BASE / "install" / "node" / "haprion-traffic-log-enable"
    return subprocess.run(
        [str(script), "--print"], capture_output=True, text=True, check=True
    ).stdout


#
# Stands in for journalctl: records its arguments and prints what the test
# wrote, in the shape `journalctl -o json --output-fields=MESSAGE --all` was
# measured to print (26-10-03). The values are invented.
#
JOURNALCTL_STUB = """#!/bin/bash
printf '%s\\n' "$@" > "$STUB_ARGS"
cat "$STUB_OUTPUT"
exit "${STUB_EXIT:-0}"
"""


def journal_entry(number: int, message: object) -> str:
    return json.dumps(
        {
            "MESSAGE": message,
            "__CURSOR": f"s=0000;i={number:x};b=1111;m=1;t=1;x=1",
            "__REALTIME_TIMESTAMP": str(1_790_000_000_000_000 + number),
            "__MONOTONIC_TIMESTAMP": "1",
        }
    )


class WafJournalReaderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.journal = self.root / "machine.haprion-waf"
        self.journal.mkdir()
        self.stub = self.root / "journalctl"
        self.stub.write_text(JOURNALCTL_STUB)
        self.stub.chmod(0o755)
        self.args = self.root / "args"
        self.output = self.root / "output"
        self.output.write_text("")

    def call(
        self, request: str, *, exit_code: int = 0, journal: Path | None = None
    ) -> tuple[int, Any, list[dict[str, Any]]]:
        output = io.BytesIO()
        environment = {"STUB_ARGS": str(self.args), "STUB_OUTPUT": str(self.output)}
        environment["STUB_EXIT"] = str(exit_code)
        with unittest.mock.patch.dict("os.environ", environment):
            code = HELPER.serve_waf(
                request, output, journalctl=str(self.stub), journal=journal or self.journal
            )
        if not output.getvalue():
            return code, None, []
        head, *rows = output.getvalue().decode().splitlines()
        return code, json.loads(head), [json.loads(row) for row in rows]

    def arguments(self) -> list[str]:
        return self.args.read_text().splitlines()

    def test_only_waf_and_a_cursor_or_a_dash_are_accepted(self) -> None:
        for request in (
            "waf",
            "waf ",
            "waf  -",
            "waf a b",
            "waf ../x",
            "waf " + "a" * 513,
            "WAF -",
        ):
            with self.subTest(request=request):
                self.assertEqual(self.call(request)[0], 64)
        self.assertFalse(self.args.exists())

    def test_a_node_whose_engine_never_ran_has_nothing_to_read(self) -> None:
        code, head, rows = self.call("waf -", journal=self.root / "absent")
        self.assertEqual(code, 0)
        self.assertEqual(head, {"cursor": "", "eof": True, "reset": False, "sent": 0})
        self.assertEqual(rows, [])
        self.assertFalse(self.args.exists())

    def test_whole_lines_after_the_cursor_from_the_engine_s_own_journal(self) -> None:
        long = "x" * 20_000
        self.output.write_text(
            "\n".join(
                [
                    journal_entry(1, '{"level":"error","match":{"rule_id":942100}}'),
                    journal_entry(2, None),  # what journalctl prints without --all
                    journal_entry(3, list(b"caf\xc3\xa9 \xff")),  # not clean UTF-8
                    journal_entry(4, long),
                ]
            )
            + "\n"
        )
        code, head, rows = self.call("waf s=0000;i=0;b=1111;m=1;t=1;x=1")
        self.assertEqual(code, 0)
        self.assertEqual(
            head,
            {"cursor": "s=0000;i=4;b=1111;m=1;t=1;x=1", "eof": True, "reset": False, "sent": 3},
        )
        self.assertEqual(
            [row["message"] for row in rows][:2],
            [
                '{"level":"error","match":{"rule_id":942100}}',
                "caf\u00e9 \ufffd",
            ],
        )
        self.assertEqual(len(rows[2]["message"]), 20_000)
        self.assertEqual(rows[0]["at"], 1_790_000_000_000_001)
        arguments = self.arguments()
        for wanted in (
            "--namespace=haprion-waf",
            "--unit=coraza-spoa.service",
            "--output=json",
            "--all",
            "--after-cursor=s=0000;i=0;b=1111;m=1;t=1;x=1",
        ):
            self.assertIn(wanted, arguments)

    def test_from_the_oldest_entry_without_a_cursor(self) -> None:
        self.output.write_text(journal_entry(1, "first") + "\n")
        code, head, rows = self.call("waf -")
        self.assertEqual((code, head["sent"], rows[0]["message"]), (0, 1, "first"))
        self.assertFalse(any(a.startswith("--after-cursor") for a in self.arguments()))

    def test_a_cursor_journald_refuses_asks_for_a_start_over(self) -> None:
        code, head, rows = self.call("waf s=gone;i=1", exit_code=1)
        self.assertEqual(code, 0)
        self.assertEqual(head, {"cursor": "", "eof": True, "reset": True, "sent": 0})

    def test_a_journal_that_cannot_be_read_from_the_start_is_an_error(self) -> None:
        self.assertEqual(self.call("waf -", exit_code=1)[0], 65)

    def test_a_response_is_bounded_and_resumes_after_its_last_line(self) -> None:
        self.output.write_text("".join(journal_entry(n, f"line {n}") + "\n" for n in range(1, 6)))
        with unittest.mock.patch.object(HELPER, "WAF_MAX_ENTRIES", 2):
            code, head, rows = self.call("waf -")
        self.assertEqual(code, 0)
        self.assertEqual(head["eof"], False)
        self.assertEqual(head["cursor"], "s=0000;i=2;b=1111;m=1;t=1;x=1")
        self.assertEqual([row["message"] for row in rows], ["line 1", "line 2"])

    def test_a_response_never_crosses_what_the_collector_takes(self) -> None:
        """The collector refuses more than MAX_SEND; the line that would cross
        it waits, and the cursor stays before it. A line too large on its own
        is stepped over rather than stopping the reader at it for ever."""

        self.output.write_text("".join(journal_entry(n, "x" * 400) + "\n" for n in range(1, 6)))
        with unittest.mock.patch.object(HELPER, "MAX_SEND", 1000):
            code, head, rows = self.call("waf -")
        self.assertEqual(code, 0)
        self.assertEqual((head["eof"], head["sent"], len(rows)), (False, 2, 2))
        self.assertEqual(head["cursor"], "s=0000;i=2;b=1111;m=1;t=1;x=1")
        self.assertEqual(rows[-1]["cursor"], head["cursor"])

        self.output.write_text(
            journal_entry(1, "x" * 2000) + "\n" + journal_entry(2, "small") + "\n"
        )
        with unittest.mock.patch.object(HELPER, "MAX_SEND", 1000):
            code, head, rows = self.call("waf -")
        self.assertEqual((head["eof"], head["cursor"]), (True, "s=0000;i=2;b=1111;m=1;t=1;x=1"))
        self.assertEqual([row["message"] for row in rows], ["small"])


class TrafficLogRsyslogRuleTests(unittest.TestCase):
    """What the node's own log chain has to be true for.

    Every assertion here stands for a way the withdrawn build failed or could
    have failed silently: a rule Ubuntu's own haproxy rule swallowed first, a
    tag match wide enough to capture the classic stream, and a template option
    this rsyslog accepts in validation and then ignores at startup.
    """

    def setUp(self) -> None:
        self.rule = render_rule()

    def test_it_sorts_before_ubuntus_terminating_haproxy_rule(self) -> None:
        script = (BASE / "install" / "node" / "haprion-traffic-log-enable").read_text()

        self.assertIn('RSYSLOG_RULE="/etc/rsyslog.d/48-haprion-traffic.conf"', script)

    def test_the_restart_loss_window_is_reported_for_enable_and_disable(self) -> None:
        script = (BASE / "install" / "node" / "haprion-traffic-log-enable").read_text()

        message = "HAProxy cannot buffer log lines during that brief window"
        self.assertEqual(script.count(message), 2)
        self.assertIn("systemctl restart rsyslog", script)

    def test_it_matches_the_traffic_tag_exactly_and_stops(self) -> None:
        self.assertIn('$programname == "haproxy-traffic"', self.rule)
        self.assertNotIn("$programname startswith", self.rule)
        self.assertNotIn(":programname, startswith", self.rule)
        self.assertIn("stop", self.rule)

    def test_only_a_json_record_reaches_the_day_file(self) -> None:
        """Measured on a node: HAProxy sends more than transactions on this tag.

        An SSL handshake failure and "Proxy ... stopped" both arrived as plain
        text and were counted as malformed by the reader. Both are duplicates
        of what the classic log already holds, so the tag's other lines are
        dropped rather than filed. The guard sits inside the tag match and
        before the stop, so nothing on the tag falls through to Ubuntu's rule.
        """

        self.assertIn('if ($msg startswith " {") then {', self.rule)
        tag = self.rule.index('$programname == "haproxy-traffic"')
        guard = self.rule.index('$msg startswith " {"')
        action = self.rule.index('action(type="omfile"')
        stop = self.rule.index("\n    stop\n")
        self.assertLess(tag, guard)
        self.assertLess(guard, action)
        self.assertLess(action, stop)

    def test_each_hour_is_a_file_named_from_the_current_utc_date_and_hour(self) -> None:
        self.assertIn("/var/log/haprion/traffic-%$now-utc%T%$hour-utc%.jsonl", self.rule)

    def test_each_hour_stops_at_the_limit_the_retention_measures(self) -> None:
        """One formula for the limit and the budget it is a twenty-fourth of (B356)."""

        self.assertIn(f'rotation.sizeLimit="{PRUNE.hour_cap(PRUNE.LOG_ROOT)}"', self.rule)
        self.assertNotIn("sizeLimitCommand", self.rule)

    def test_only_the_payload_is_written_and_not_a_syslog_header(self) -> None:
        """Measured, not assumed: `%msg%` keeps RFC3164's separating space.

        `ltrim` is rejected as a field option by this rsyslog at startup while
        `rsyslogd -N1` still passes, so the option would be dropped in silence
        and every line would begin with a space the reader does not expect.
        """

        directives = [line for line in self.rule.splitlines() if not line.lstrip().startswith("#")]

        self.assertIn('string="%msg:2:$:drop-last-lf%\\n"', self.rule)
        self.assertNotIn("ltrim", "\n".join(directives))
        self.assertNotIn("%HOSTNAME%", self.rule)
        self.assertNotIn("%TIMESTAMP%", self.rule)

    def test_the_file_is_group_readable_and_no_wider(self) -> None:
        self.assertIn('fileCreateMode="0640"', self.rule)

    def test_the_directory_is_set_group_id_so_files_inherit_the_read_group(self) -> None:
        prepare = (BASE / "install" / "04-node-prepare").read_text()

        self.assertIn(
            'ensure_dir "$TRAFFIC_LOG_ROOT" "${RSYSLOG_WRITER}:${LOGS_GROUP}" 2750', prepare
        )

    @unittest.skipUnless(shutil.which("rsyslogd"), "rsyslog is not installed here")
    def test_the_real_rsyslog_parser_accepts_the_rule(self) -> None:
        """The installed rsyslogd is confined to /etc/rsyslog.d by AppArmor.

        A copy of the same binary under another path is unconfined, which is
        the only way to run the real parser over a file this suite owns.
        """

        source = shutil.which("rsyslogd")
        assert source is not None
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "rsyslogd"
            shutil.copy2(source, binary)
            binary.chmod(0o755)
            configuration = root / "rule.conf"
            configuration.write_text(self.rule)
            result = subprocess.run(
                [str(binary), "-N1", "-f", str(configuration)],
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
            self.assertNotIn("error", (result.stderr + result.stdout).lower())


@unittest.skipUnless(shutil.which("rsyslogd"), "rsyslog is not installed here")
class TrafficLogRsyslogStopsAnHourAtItsLimit(unittest.TestCase):
    """The rule as written, run by the real rsyslogd, flooded past a small limit (B356).

    A copy of the binary outside AppArmor's reach, on a socket in this test's
    directory, with the rule's log directory and limit pointed here.
    """

    LIMIT = 4000

    def test_a_flood_fills_one_hour_to_its_limit_and_no_further(self) -> None:
        source = shutil.which("rsyslogd")
        assert source is not None
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "rsyslogd"
            shutil.copy2(source, binary)
            binary.chmod(0o755)
            (root / "work").mkdir()
            (root / "log").mkdir()
            socket_path = root / "socket"
            rule = render_rule().replace("/var/log/haprion/", f"{root / 'log'}/")
            rule = re.sub(
                r'rotation\.sizeLimit="[0-9]+"', f'rotation.sizeLimit="{self.LIMIT}"', rule
            )
            (root / "rsyslog.conf").write_text(
                f'global(workDirectory="{root / "work"}")\n'
                'module(load="imuxsock" SysSock.Use="off")\n'
                f'input(type="imuxsock" Socket="{socket_path}")\n' + rule
            )
            process = subprocess.Popen(
                [str(binary), "-n", "-f", str(root / "rsyslog.conf"), "-i", str(root / "pid")],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                deadline = time.monotonic() + 10
                while not socket_path.exists() and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertTrue(socket_path.exists(), "rsyslog did not listen")
                started = datetime.now(UTC)
                with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sender:
                    for number in range(400):
                        record = json.dumps({"n": number, "path": "/" + "x" * 80})
                        sender.sendto(
                            f"<150>Oct 12 13:30:00 haproxy-traffic[1]: {record}".encode(),
                            str(socket_path),
                        )
                time.sleep(1)
            finally:
                process.send_signal(signal.SIGTERM)
                process.wait(timeout=10)

            files = sorted((root / "log").iterdir())
            hours = {
                f"traffic-{moment:%Y-%m-%dT%H}.jsonl" for moment in (started, datetime.now(UTC))
            }
            self.assertTrue(files)
            self.assertLessEqual({path.name for path in files}, hours)
            written = b"".join(path.read_bytes() for path in files)
            lines = written.splitlines()
            # Stopped near the limit: at most one batch past it, far short of the flood.
            self.assertGreaterEqual(len(written), self.LIMIT * len(files) // 2)
            self.assertLess(len(written), (self.LIMIT + 16 * 1024) * len(files))
            self.assertLess(len(lines), 400)
            self.assertTrue(all(json.loads(line)["path"] for line in lines))


def load_prune() -> ModuleType:
    path = BASE / "install" / "node" / "haprion-traffic-log-prune"
    spec = importlib.util.spec_from_loader(
        "traffic_log_prune", SourceFileLoader("traffic_log_prune", str(path))
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load node helper")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PRUNE = load_prune()


class TrafficLogRetentionTests(unittest.TestCase):
    """Whole files disappear; nothing is ever renamed.

    logrotate would move the file a fetch is reading between two names, and
    there is no instant where both names resolve. A run landing in that gap
    reads an empty file and reports success, which is worse than an error.
    """

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def write(self, name: str, data: bytes = b'{"schema":1}\n') -> Path:
        path = self.root / name
        path.write_bytes(data)
        return path

    def test_the_window_matches_what_the_reader_will_serve(self) -> None:
        self.assertEqual(PRUNE.RETENTION_DAYS, HELPER.RETENTION_DAYS)

    def test_the_oldest_day_inside_the_window_is_kept(self) -> None:
        oldest = "traffic-2026-08-26.jsonl"
        self.write(oldest)

        self.assertEqual(PRUNE.prune(self.root, today=TODAY), [])
        self.assertTrue((self.root / oldest).exists())

    def test_the_day_just_outside_the_window_is_removed(self) -> None:
        self.write("traffic-2026-08-25.jsonl")

        self.assertEqual(PRUNE.prune(self.root, today=TODAY), ["traffic-2026-08-25.jsonl"])
        self.assertFalse((self.root / "traffic-2026-08-25.jsonl").exists())

    def test_nothing_this_chain_did_not_write_is_touched(self) -> None:
        for name in (
            "traffic-2026-08-25.jsonl.gz",
            "traffic-2026-08-25.jsonl.1",
            "traffic-2026-13-01.jsonl",
            "traffic-old.jsonl",
            "haproxy.log",
            ".hidden",
        ):
            self.write(name)

        self.assertEqual(PRUNE.prune(self.root, today=TODAY), [])
        self.assertEqual(len(list(self.root.iterdir())), 6)

    def test_a_symlink_named_like_an_expired_day_is_left_alone(self) -> None:
        """Nothing here creates one, which is why one must not be followed."""

        target = self.write("real.jsonl")
        (self.root / "traffic-2026-08-01.jsonl").symlink_to(target)

        self.assertEqual(PRUNE.prune(self.root, today=TODAY), [])
        self.assertTrue(target.exists())

    def test_a_missing_directory_is_not_an_error(self) -> None:
        self.assertEqual(PRUNE.prune(self.root / "absent", today=TODAY), [])

    def test_an_expired_day_goes_with_its_hours_the_last_hour_first(self) -> None:
        """The reader then sees a day that is going as its beginning, or as gone."""

        for name in (
            "traffic-2026-08-25.jsonl",
            "traffic-2026-08-25T00.jsonl",
            "traffic-2026-08-25T23.jsonl",
        ):
            self.write(name)
        self.write("traffic-2026-08-26T00.jsonl")
        order: list[str] = []
        unlink = PRUNE.os.unlink

        def recorded(path: Path) -> None:
            order.append(Path(path).name)
            unlink(path)

        with mock.patch.object(PRUNE.os, "unlink", side_effect=recorded):
            removed = PRUNE.prune(self.root, today=TODAY)

        self.assertEqual(
            order,
            [
                "traffic-2026-08-25T23.jsonl",
                "traffic-2026-08-25T00.jsonl",
                "traffic-2026-08-25.jsonl",
            ],
        )
        self.assertEqual(removed, sorted(order))
        self.assertTrue((self.root / "traffic-2026-08-26T00.jsonl").exists())

    def test_an_hour_outside_the_day_is_not_one_this_chain_wrote(self) -> None:
        for name in (
            "traffic-2026-08-25T24.jsonl",
            "traffic-2026-08-25T7.jsonl",
            "traffic-2026-08-25T07.jsonl.1",
        ):
            self.write(name)

        self.assertEqual(PRUNE.prune(self.root, today=TODAY), [])


class TrafficLogSpaceBudgetTests(unittest.TestCase):
    """S05 (security review 26-10-13): the window was days, not bytes (B307)."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for day in ("2026-09-04", "2026-09-05", "2026-09-06", TODAY.isoformat()):
            (self.root / f"traffic-{day}.jsonl").write_bytes(b"x" * 100)

    def run_with(self, *, capacity: int, free: int) -> list[str]:
        space = mock.Mock(f_blocks=capacity, f_frsize=1, f_bavail=free)
        with mock.patch.object(PRUNE.os, "statvfs", return_value=space):
            return list(PRUNE.over_budget(self.root, today=TODAY))

    def test_within_budget_nothing_goes(self) -> None:
        self.assertEqual(self.run_with(capacity=4000, free=3000), [])

    def test_over_its_share_the_oldest_finished_days_go_until_it_fits(self) -> None:
        # 400 bytes held, a quarter of 1000 is 250: two days go, oldest first.
        self.assertEqual(
            self.run_with(capacity=1000, free=900),
            ["traffic-2026-09-04.jsonl", "traffic-2026-09-05.jsonl"],
        )

    def test_short_of_free_space_today_is_never_removed(self) -> None:
        removed = self.run_with(capacity=10_000, free=0)
        self.assertEqual(len(removed), 3)
        self.assertTrue((self.root / f"traffic-{TODAY.isoformat()}.jsonl").exists())

    def test_a_day_goes_whole_with_its_hours(self) -> None:
        for hour in ("00", "13"):
            (self.root / f"traffic-2026-09-04T{hour}.jsonl").write_bytes(b"x" * 100)
            (self.root / f"traffic-{TODAY.isoformat()}T{hour}.jsonl").write_bytes(b"x" * 100)
        # 800 bytes held, a quarter of 2400 is 600: the oldest day goes, all three files.
        self.assertEqual(
            self.run_with(capacity=2400, free=2000),
            [
                "traffic-2026-09-04.jsonl",
                "traffic-2026-09-04T00.jsonl",
                "traffic-2026-09-04T13.jsonl",
            ],
        )


class TrafficLogHourLimitTests(unittest.TestCase):
    """Today is bounded where it is written: an hour stops at a twenty-fourth of the share (B356)."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def cap_on(self, capacity: int, root: Path | None = None) -> int:
        space = mock.Mock(f_blocks=capacity, f_frsize=1, f_bavail=capacity)
        with mock.patch.object(PRUNE.os, "statvfs", return_value=space) as statvfs:
            cap: int = PRUNE.hour_cap(root or self.root)
        self.measured = Path(statvfs.call_args.args[0])
        return cap

    def test_a_day_of_full_hours_is_the_share_of_the_filesystem(self) -> None:
        capacity = 48 * 1024**3
        self.assertEqual(self.cap_on(capacity), int(capacity * PRUNE.SPACE_SHARE) // 24)
        self.assertLessEqual(self.cap_on(capacity) * 24, capacity * PRUNE.SPACE_SHARE)

    def test_the_limit_is_never_zero_which_rsyslog_reads_as_none(self) -> None:
        self.assertEqual(self.cap_on(1000), PRUNE.MIN_HOUR_CAP)

    def test_a_directory_not_made_yet_is_measured_where_it_will_be(self) -> None:
        self.cap_on(10**9, self.root / "haprion")
        self.assertEqual(self.measured, self.root)

    def test_the_hour_just_ended_is_named_when_it_reached_the_limit(self) -> None:
        now = datetime(2026, 9, 8, 14, 7, tzinfo=UTC)
        (self.root / "traffic-2026-09-08T13.jsonl").write_bytes(b"x" * 100)
        with mock.patch.object(PRUNE, "hour_cap", return_value=100):
            self.assertEqual(PRUNE.capped(self.root, now=now), "traffic-2026-09-08T13.jsonl")
        with mock.patch.object(PRUNE, "hour_cap", return_value=101):
            self.assertIsNone(PRUNE.capped(self.root, now=now))
        self.assertIsNone(PRUNE.capped(self.root, now=now + timedelta(hours=1)))

    def test_the_command_prints_the_limit_and_takes_nothing_else(self) -> None:
        script = BASE / "install" / "node" / "haprion-traffic-log-prune"
        printed = subprocess.run(
            [str(script), "--hour-cap"], capture_output=True, text=True, check=True
        ).stdout
        self.assertEqual(int(printed), PRUNE.hour_cap(PRUNE.LOG_ROOT))
        refused = subprocess.run([str(script), "--what"], capture_output=True, check=False)
        self.assertEqual(refused.returncode, 64)


class TrafficLogRetentionUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        script = BASE / "install" / "node" / "haprion-traffic-log-enable"
        printed = subprocess.run(
            [str(script), "--print-units"], capture_output=True, text=True, check=True
        ).stdout
        self.service, self.timer = printed.split("--- timer ---\n")

    def test_the_pass_runs_hourly_and_catches_up_after_downtime(self) -> None:
        # Hourly for the space budget (B307): a flood fills a disk within a day.
        self.assertIn("OnCalendar=hourly", self.timer)
        self.assertIn("Persistent=true", self.timer)

    def test_the_pass_can_write_nowhere_but_the_log_directory(self) -> None:
        self.assertIn("ProtectSystem=strict", self.service)
        self.assertIn("ReadWritePaths=/var/log/haprion", self.service)
        self.assertIn("PrivateNetwork=yes", self.service)
        self.assertIn("NoNewPrivileges=yes", self.service)

    @unittest.skipUnless(shutil.which("systemd-analyze"), "systemd is not installed here")
    def test_real_systemd_accepts_both_units(self) -> None:
        analyze = shutil.which("systemd-analyze")
        assert analyze is not None
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "haprion-traffic-log-prune.service").write_text(self.service)
            (root / "haprion-traffic-log-prune.timer").write_text(self.timer)
            for unit in ("haprion-traffic-log-prune.timer", "haprion-traffic-log-prune.service"):
                result = subprocess.run(
                    [analyze, "verify", str(root / unit)],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                #
                # Verifying the timer does not reach into the service it
                # starts, so both are checked. The one complaint expected on a
                # machine that is not a node is that the command it starts is
                # not installed here; anything else is a real defect.
                #
                complaints = [
                    line
                    for line in (result.stderr + result.stdout).splitlines()
                    if line.strip() and "haprion-traffic-log-prune" in line
                ]

                self.assertEqual(
                    [line for line in complaints if "is not executable" not in line],
                    [],
                    result.stderr or result.stdout,
                )
