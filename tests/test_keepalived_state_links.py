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
from unittest import mock

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
        self.assertIn('WORK_DIR="/run/haprion-keepalived"', script)
        self.work = Path(temporary.name) / "work"
        self.script.write_text(
            script.replace("/run/haproxy", str(self.directory)).replace(
                "/run/haprion-keepalived", str(self.work)
            )
        )
        # install -o root -g root needs root; the test is not, so it makes its own.
        self.bin = Path(temporary.name) / "bin"
        self.bin.mkdir()
        shim = self.bin / "install"
        shim.write_text('#!/bin/sh\nfor last; do :; done\nmkdir -p -m 755 "$last"\n')
        shim.chmod(0o755)
        spy = self.bin / "mktemp"
        spy.write_text(
            f'#!/bin/sh\necho "$1" >> "{self.bin / "made"}"\nexec /usr/bin/mktemp "$@"\n'
        )
        spy.chmod(0o755)

    def write(self, state: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # the script under test, in a temporary directory
            ["/bin/bash", str(self.script), state],
            env={**os.environ, "PATH": f"{self.bin}:{os.environ['PATH']}"},
            capture_output=True,
            text=True,
            check=False,
        )

    def test_the_temporary_name_is_not_one_that_can_be_guessed(self) -> None:
        script = WRITER.read_text()
        self.assertIn("mktemp", script)
        self.assertNotIn('"${STATE_FILE}.$$"', script)

    def test_the_temporary_file_is_made_where_the_group_cannot_write(self) -> None:
        """Review 26-10-30, R3: a name in the group's directory can be swapped for a link."""

        self.assertEqual(self.write("BACKUP").returncode, 0)
        made = Path((self.bin / "made").read_text().strip())
        self.assertEqual(made.parent, self.work)
        self.assertNotEqual(made.parent, self.directory)
        self.assertEqual(stat.S_IMODE(self.work.stat().st_mode), 0o755)
        self.assertEqual((self.directory / "keepalived.state").read_text(), "BACKUP\n")
        self.assertEqual(list(self.work.iterdir()), [])

    def test_a_directory_in_the_state_file_s_place_does_not_take_the_file(self) -> None:
        (self.directory / "keepalived.state").mkdir()
        self.assertNotEqual(self.write("MASTER").returncode, 0)
        self.assertEqual(list((self.directory / "keepalived.state").iterdir()), [])
        self.assertEqual(list(self.work.iterdir()), [])

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

    def test_a_file_of_another_owner_is_not_state(self) -> None:
        """Review 26-10-30, R3: the group can put a file there; only root's is the writer's."""

        self.state.write_text("BACKUP\n")
        with mock.patch.object(os, "geteuid", return_value=os.getuid() + 1):
            self.assertIsNone(self.read())

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
