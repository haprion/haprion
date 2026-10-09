from __future__ import annotations

import importlib.util
import io
import json
import shutil
import subprocess
import tempfile
import unittest
import unittest.mock
from datetime import date
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import ModuleType
from typing import Any

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

    def test_incomplete_final_record_is_not_sent(self) -> None:
        self.write("2026-09-08", b"{}\nunfinished")
        code, header, payload = self.call("2026-09-08 0")
        self.assertEqual((code, payload), (0, b"{}\n"))
        assert header is not None
        self.assertFalse(header["eof"])


if __name__ == "__main__":
    unittest.main()


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

    def test_the_day_file_is_named_from_the_current_utc_date(self) -> None:
        self.assertIn("/var/log/haprion/traffic-%$now-utc%.jsonl", self.rule)

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


class TrafficLogRetentionUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        script = BASE / "install" / "node" / "haprion-traffic-log-enable"
        printed = subprocess.run(
            [str(script), "--print-units"], capture_output=True, text=True, check=True
        ).stdout
        self.service, self.timer = printed.split("--- timer ---\n")

    def test_the_pass_runs_daily_and_catches_up_after_downtime(self) -> None:
        self.assertIn("OnCalendar=daily", self.timer)
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
