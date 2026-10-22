"""`haprion-retention horizon` makes the partitions ahead and removes nothing (review 2026-10-22, 3-2).

Run by bash with its root check and configuration directory pointed at a scratch
tree, and `psql` replaced by a stub that records every statement. Step 11 and
every update run this; a statement that deleted anything there would delete on
the way past, which the installer promises it does not.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "install" / "platform" / "bin" / "haprion-retention"

#
# Every table exists; every count is nought.
#
PSQL_STUB = """#!/bin/sh
for argument; do printf '%s\\n---\\n' "$argument" >> "$RECORD"; done
case "$*" in
    *to_regclass*) echo t ;;
    *) for argument; do [ "$argument" = -c ] && echo 0; done ;;
esac
exit 0
"""


class TheHorizonRemovesNothing(unittest.TestCase):
    def test_partitions_are_made_ahead_and_nothing_is_dropped_or_deleted(self) -> None:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        (root / "ui-admin.conf").write_text("DB_NAME=haprion\nDB_ROLE=haprion\n")
        psql = root / "psql"
        psql.write_text(PSQL_STUB)
        psql.chmod(0o755)
        script = root / "haprion-retention"
        text = SCRIPT.read_text()
        for old, new in (
            ("CONFIG_DIRECTORY=/etc/haprion", f"CONFIG_DIRECTORY={root}"),
            ('[[ $EUID -eq 0 ]] || die "run this with sudo"', ":"),
        ):
            self.assertIn(old, text)
            text = text.replace(old, new)
        script.write_text(text)
        record = root / "record"

        done = subprocess.run(
            ["/bin/bash", str(script), "horizon"],
            capture_output=True,
            text=True,
            env={"PATH": f"{root}:/usr/bin:/bin", "RECORD": str(record)},
            check=False,
            timeout=60,
        )

        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        statements = record.read_text().lower()
        self.assertIn("metric_partition(", statements)
        self.assertIn("traffic_log_partition(", statements)
        self.assertIn("waf_match_partition(", statements)
        for word in ("drop ", "delete ", "truncate "):
            self.assertNotIn(word, statements)


if __name__ == "__main__":
    unittest.main()
