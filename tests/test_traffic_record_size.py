"""The largest traffic record HAProxy can write fits the line it is written on.

Review 2026-11-05, T01: the log line's `len` was 2048, and the fields a client
chooses (method, host, path) were not capped, so a long path or a long Host
made HAProxy cut the record in the middle of its JSON. The collector then had
nothing to read, and the one request an attacker shaped was missing from the
traffic log. This test builds the largest possible record from the format
itself, every field at its bound and every byte of a client's text spelled
the longest way the JSON encoder can, and requires it to fit.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

from haprion import generate

GOLDEN = Path(__file__).resolve().parent / "golden" / "cluster-settings" / "1000-frontends.cfg"

#
# rsyslog's default `maxMessageSize`: it cuts a message longer than this, and
# nothing on the node raises it.
#
RSYSLOG_MAXIMUM = 8192
#
# The syslog header in front of the record in `format local`: priority, time,
# tag and process ID. Generous; the real one is about fifty bytes.
#
HEADER = 100
#
# HAProxy's JSON encoder writes a byte it cannot send as is - an invalid UTF-8
# byte in an HTTP/2 path, measured 2026-11-05 - as `ÿ`, six bytes.
#
ESCAPED = 6

#
# The most each field of the format can take, in bytes on the line, between the
# quotes. A field with no entry here is a field someone added without asking
# whether it fits. Only the three a client writes are counted at the longest
# escape; the others are names the configuration or the engine chose, in ASCII.
#
LONGEST = {
    "schema": 1,
    "node": 64,
    "at": 20,
    "request": 20,
    "client": 64,
    "method": generate.TRAFFIC_METHOD_BYTES * ESCAPED,
    "host": generate.TRAFFIC_HOST_BYTES * ESCAPED,
    "path": generate.TRAFFIC_PATH_BYTES * ESCAPED,
    "frontend": 128,
    "backend": 128,
    "server": 128,
    "status": 20,
    "request_time": 20,
    "queue_time": 20,
    "connect_time": 20,
    "response_time": 20,
    "total_time": 20,
    "bytes": 20,
    "termination": 2,
    "rule": 160,
    "waf_rules": 1024,
    "waf_score": 20,
    "waf_error": 20,
    "waf_id": 96,
}


class TrafficRecordSizeTests(unittest.TestCase):
    def fields(self) -> list[str]:
        return re.findall(r"%\(([a-z_]+)\)", generate.HTTP_TRAFFIC_LOG_FORMAT)

    def test_every_field_of_the_format_has_a_bound(self) -> None:
        self.assertEqual(sorted(self.fields()), sorted(LONGEST))

    def test_the_largest_record_fits_the_log_line_and_rsyslog(self) -> None:
        total = 2  # the braces
        for name in self.fields():
            # "name":"value", - the quotes are counted for numbers too
            total += len(name) + 2 + 1 + 2 + LONGEST[name] + 1
        total += HEADER
        self.assertLessEqual(total, generate.TRAFFIC_LOG_LENGTH, total)
        self.assertLessEqual(generate.TRAFFIC_LOG_LENGTH, RSYSLOG_MAXIMUM)

    def test_the_format_cuts_what_the_client_chooses(self) -> None:
        text = GOLDEN.read_text()
        self.assertIn(f" len {generate.TRAFFIC_LOG_LENGTH} ", text)
        for variable, bound in (
            ("traffic_host", generate.TRAFFIC_HOST_BYTES),
            ("traffic_method", generate.TRAFFIC_METHOD_BYTES),
            ("traffic_path", generate.TRAFFIC_PATH_BYTES),
        ):
            with self.subTest(variable=variable):
                self.assertRegex(
                    text, rf"http-request set-var\(txn\.{variable}\) \S+,bytes\(0,{bound}\)"
                )
                self.assertIn(f"var(txn.{variable})", generate.HTTP_TRAFFIC_LOG_FORMAT)

    def test_the_cut_bounds_are_what_the_collector_stores(self) -> None:
        self.assertEqual(generate.TRAFFIC_METHOD_BYTES, 16)
        self.assertEqual(generate.TRAFFIC_HOST_BYTES, 253)
        self.assertLessEqual(generate.TRAFFIC_PATH_BYTES, 8192)


if __name__ == "__main__":
    unittest.main()
