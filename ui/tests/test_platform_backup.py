"""The weekly restore check measures a restore against the archive, not against live.

Compared with the live database, the check failed every week retention had
something to do between the dump and the check (2026-09-20: job live 59,
restored 63) while the restore itself was perfect. What a restore owes is the
rows the archive holds; how far live has moved since is information.
"""

from __future__ import annotations

import os
import re
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "install/platform/bin/haprion-backup"

#
# What `pg_restore --data-only --table=<t> --file=-` writes: a header, one COPY
# block, one line per row, and the `\.` terminator. A value with a newline in it
# is escaped by COPY, so it is still one line; a value that is the two characters
# backslash-dot is escaped as `\\.` and must not end the block.
#
FAKE_PG_RESTORE = r"""#!/bin/sh
table=""
for argument in "$@"; do
    case "$argument" in --table=*) table="${argument#--table=}" ;; esac
done
line() { printf '%s\n' "$1"; }
line "--"
line "-- PostgreSQL database dump"
line "SET statement_timeout = 0;"
case "$table" in
    job)
        line 'COPY public.job (id, result) FROM stdin;'
        line '1	r'
        line '2	two\nlines'
        line '3	\\.'
        line '\.'
        ;;
    app_user)
        line 'COPY public.app_user (id) FROM stdin;'
        line '1'
        line '\.'
        ;;
    *)
        line "COPY public.$table (id) FROM stdin;"
        line '\.'
        ;;
esac
line "-- dump complete"
"""


def function(name: str, source: str) -> str:
    match = re.search(rf"^{name}\(\) \{{\n.*?^\}}\n", source, re.MULTILINE | re.DOTALL)
    if match is None:
        raise AssertionError(f"{name} is not defined in {SCRIPT}")
    return match.group(0)


class TheRestoreCheck(unittest.TestCase):
    source: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.source = SCRIPT.read_text()

    def test_the_archive_is_counted_one_row_per_line_between_copy_and_terminator(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fake = Path(directory) / "pg_restore"
            fake.write_text(FAKE_PG_RESTORE)
            fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
            program = (
                "set -Eeuo pipefail\n"
                "TABLES=(app_user app_session audit_event login_attempt job)\n"
                + function("archive_counts", self.source)
                + "archive_counts /nonexistent.dump\n"
            )
            result = subprocess.run(  # noqa: S603 - fixed program, test fixture PATH
                ["/bin/bash", "-c", program],
                capture_output=True,
                text=True,
                check=True,
                env={**os.environ, "PATH": f"{directory}:{os.environ['PATH']}"},
            )

        self.assertEqual(
            result.stdout.splitlines(),
            ["app_user=1", "app_session=0", "audit_event=0", "login_attempt=0", "job=3"],
        )

    def test_the_restore_is_compared_with_the_archive_and_live_is_only_shown(self) -> None:
        verify = function("do_verify_restore", self.source)

        self.assertIn('expected="$(archive_counts "$archive")"', verify)
        self.assertIn('done <<<"$expected"', verify)
        self.assertIn('"$expected_count" == "$restored_count"', verify)
        self.assertNotIn('"$live_count" == "$restored_count"', verify)
        self.assertIn('die "the restore does not match the archive"', verify)


if __name__ == "__main__":
    unittest.main()
