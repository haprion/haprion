from __future__ import annotations

import importlib.util
import io
import json
import shutil
import subprocess
import tempfile
import unittest
from datetime import date
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import ModuleType

BASE = Path(__file__).resolve().parents[1]


def load_script() -> ModuleType:
    path = BASE / "install" / "node" / "haproxy-traffic-log-read"
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

    script = BASE / "install" / "node" / "haproxy-traffic-log-enable"
    return subprocess.run(
        [str(script), "--print"], capture_output=True, text=True, check=True
    ).stdout


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
        script = (BASE / "install" / "node" / "haproxy-traffic-log-enable").read_text()

        self.assertIn('RSYSLOG_RULE="/etc/rsyslog.d/48-haproxy-manager-traffic.conf"', script)

    def test_it_matches_the_traffic_tag_exactly_and_stops(self) -> None:
        self.assertIn('$programname == "haproxy-traffic"', self.rule)
        self.assertNotIn("startswith", self.rule)
        self.assertIn("stop", self.rule)

    def test_the_day_file_is_named_from_the_current_utc_date(self) -> None:
        self.assertIn("/var/log/haproxy-manager/traffic-%$now-utc%.jsonl", self.rule)

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

        self.assertIn('ensure_dir "$TRAFFIC_LOG_ROOT" "syslog:${LOGREAD_GROUP}" 2750', prepare)

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
