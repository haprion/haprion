"""The keepalived state file in a group-writable directory (review 26-10-30, E5).

/run/haproxy belongs to the haproxy group. The writer runs as root from
keepalived and the node status reads as root: neither may follow a link that
somebody with that group put there.
"""

from __future__ import annotations

import os
import re
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
WRITER = ROOT / "install/node/haprion-keepalived-state"
STATUS = ROOT / "install/node/haprion-node-status"
READING = re.compile(
    r"^def read_keepalived_state\(.*?(?=^def read_cluster)", re.DOTALL | re.MULTILINE
)


class TheWriter(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name) / "run"
        self.directory.mkdir()
        script = WRITER.read_text()
        self.assertIn('STATE_DIR="/run/haproxy"', script)
        self.script = Path(temporary.name) / "writer"
        self.script.write_text(script.replace("/run/haproxy", str(self.directory)))

    def write(self, state: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # the script under test, in a temporary directory
            ["/bin/bash", str(self.script), state],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_the_temporary_name_is_not_one_that_can_be_guessed(self) -> None:
        script = WRITER.read_text()
        self.assertIn("mktemp", script)
        self.assertNotIn('"${STATE_FILE}.$$"', script)

    def test_a_link_in_the_state_file_s_place_is_replaced_not_written_through(self) -> None:
        victim = self.directory.parent / "victim"
        victim.write_text("untouched\n")
        (self.directory / "keepalived.state").symlink_to(victim)
        self.assertEqual(self.write("MASTER").returncode, 0)
        state = self.directory / "keepalived.state"
        self.assertFalse(state.is_symlink())
        self.assertEqual(state.read_text(), "MASTER\n")
        self.assertEqual(stat.S_IMODE(state.stat().st_mode), 0o644)
        self.assertEqual(victim.read_text(), "untouched\n")
        self.assertEqual([path.name for path in self.directory.iterdir()], ["keepalived.state"])

    def test_a_state_it_does_not_know_is_refused(self) -> None:
        self.assertEqual(self.write("STOP").returncode, 64)


class TheReader(unittest.TestCase):
    def setUp(self) -> None:
        found = READING.search(STATUS.read_text())
        assert found, "read_keepalived_state is no longer where the test extracts it from"
        self.source = found.group(0)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.state = self.directory / "keepalived.state"

    def read(self) -> Any:
        namespace: dict[str, Any] = {
            "os": os,
            "S_ISREG": stat.S_ISREG,
            "KEEPALIVED_STATE": self.state,
        }
        exec(self.source, namespace)  # noqa: S102 - verbatim function from the node script
        return namespace["read_keepalived_state"]()

    def test_a_regular_file_is_read(self) -> None:
        self.state.write_text("BACKUP\n")
        self.assertEqual(self.read(), "BACKUP")

    def test_a_missing_file_is_no_state(self) -> None:
        self.assertIsNone(self.read())

    def test_a_link_is_not_followed(self) -> None:
        elsewhere = self.directory / "elsewhere"
        elsewhere.write_text("not a state\n")
        self.state.symlink_to(elsewhere)
        self.assertIsNone(self.read())

    def test_a_pipe_is_not_read(self) -> None:
        os.mkfifo(self.state)
        self.assertIsNone(self.read())


if __name__ == "__main__":
    unittest.main()
