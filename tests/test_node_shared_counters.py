"""Whether a node's HAProxy keeps its counters across a reload (N3, 2026-10-09).

A reload starts `Uptime_sec` from nought whether or not `shm-stats-file` is in
use, so the node says which it is, read from what runs: the path the running
release's `global` names, and whether HAProxy's worker has that file mapped
shared. The functions are extracted from `install/node/haprion-node-status`
verbatim, as `test_node_runtime_stat` does, because the script is installed on
the nodes rather than imported.

The mapping lines are in the form measured on 3.4.6 (`/proc/<pid>/maps` of a
worker with the directive set, 2026-10-09).
"""

from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import Any

SCRIPT = Path(__file__).resolve().parents[1] / "install" / "node" / "haprion-node-status"
PART = re.compile(r"^SHM_STATS_FILE = .*?(?=^#\n# A pool's own row)", re.DOTALL | re.MULTILINE)

SHM = "/run/haproxy/stats.shm"
MAPPED = (
    "5d1c2a000000-5d1c2a0b2000 r--p 00000000 fd:00 1048601                    /usr/sbin/haproxy\n"
    "73fcbdc79000-73fcbdc89000 rw-s 00000000 00:01 6092                       "
    "[anon_shmem:errors:startup_logs]\n"
    f"73fcbccf2000-73fcbce00000 rw-s 00000000 00:2c 3393728                    {SHM}\n"
)
UNMAPPED = MAPPED.splitlines(keepends=True)[0]

CORE = """global
    log /dev/log local0
    chroot /var/lib/haproxy
    shm-stats-file {path}
    default-path config

defaults
    mode http
"""


class WhatTheNodeSaysAboutItsCounters(unittest.TestCase):
    def setUp(self) -> None:
        found = PART.search(SCRIPT.read_text())
        assert found, "the function is no longer where the test extracts it from"
        namespace: dict[str, Any] = {"re": re, "Path": Path}
        exec(found.group(0), namespace)  # noqa: S102 - the file under test, read from disk
        self.path = namespace["shm_stats_path"]
        self.shared = namespace["shared_counters"]
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root)

    def node(self, config: str | None, maps: str | None, pid: int = 4242) -> bool | None:
        root = Path(tempfile.mkdtemp(dir=self.root))
        release = root / "releases" / "20261009-080943"
        release.mkdir(parents=True, exist_ok=True)
        if config is not None:
            (release / "haproxy.cfg").write_text(config)
        if maps is not None:
            (root / "proc" / str(pid)).mkdir(parents=True)
            (root / "proc" / str(pid) / "maps").write_text(maps)
        result: bool | None = self.shared(pid, release / "RELEASE", root / "proc")
        return result

    def test_the_worker_holding_the_named_file_keeps_its_counters(self) -> None:
        self.assertIs(self.node(CORE.format(path=SHM), MAPPED), True)

    def test_no_directive_means_no(self) -> None:
        self.assertIs(self.node(CORE.replace("    shm-stats-file {path}\n", ""), MAPPED), False)

    def test_a_directive_the_running_worker_did_not_take_is_no(self) -> None:
        """Written but not in force, e.g. before the reload that reads it."""

        self.assertIs(self.node(CORE.format(path=SHM), UNMAPPED), False)

    def test_a_different_file_mapped_is_no(self) -> None:
        self.assertIs(self.node(CORE.format(path="/run/haproxy/other.shm"), MAPPED), False)

    def test_what_cannot_be_read_is_unknown_not_no(self) -> None:
        self.assertIsNone(self.node(CORE.format(path=SHM), None))
        self.assertIsNone(self.node(None, MAPPED))
        self.assertIsNone(self.shared(None, self.root / "RELEASE", self.root / "proc"))
        self.assertIsNone(self.shared(4242, None, self.root / "proc"))

    def test_only_the_global_section_counts(self) -> None:
        config = CORE.replace("    shm-stats-file {path}\n", "") + f"    shm-stats-file {SHM}\n"

        self.assertIsNone(self.path(config))

    def test_a_relative_path_is_the_masters_working_directory(self) -> None:
        """systemd starts HAProxy in `/`; measured that the name is opened relative to it."""

        self.assertEqual(self.path(CORE.format(path="stats.shm")), "/stats.shm")
        self.assertEqual(self.path(CORE.format(path=SHM)), SHM)

    def test_a_trailing_comment_is_not_part_of_the_path(self) -> None:
        self.assertEqual(self.path(CORE.format(path=f"{SHM}  # carried over reloads")), SHM)
