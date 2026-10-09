"""The account rsyslog writes as: one rule, in the two node scripts.

Ubuntu drops to `syslog`; Debian 13 writes as root with no `syslog` account
(measured 2026-09-24). The traffic log's directory is owned by whichever it is,
and two scripts decide that - 04-node-prepare, which a node restore also runs
(B180), and haprion-traffic-log-enable - so they are run against the same
configurations here and must answer alike.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = (ROOT / "install/04-node-prepare", ROOT / "install/node/haprion-traffic-log-enable")
BASH = shutil.which("bash") or "/bin/bash"
FUNCTION = re.compile(r"^rsyslog_writer\(\) \{\n.*?^\}\n", re.MULTILINE | re.DOTALL)

CASES = {
    "ubuntu": ({"rsyslog.conf": "$PrivDropToUser syslog\n$PrivDropToGroup syslog\n"}, "syslog"),
    "debian": ({"rsyslog.conf": 'module(load="imuxsock")\n'}, "root"),
    "no configuration at all": ({}, "root"),
    "the newer form": ({"rsyslog.conf": 'global(privDrop.user.name="svc-app")\n'}, "svc-app"),
    "a drop-in wins": (
        {
            "rsyslog.conf": "$PrivDropToUser syslog\n",
            "rsyslog.d/10-local.conf": "$PrivDropToUser svc-app\n",
        },
        "svc-app",
    ),
    "comments do not count": (
        {"rsyslog.conf": '#$PrivDropToUser syslog\n# global(privdrop.user.name="x")\n'},
        "root",
    ),
}


def function_text(script: Path) -> str:
    found = FUNCTION.search(script.read_text())
    if found is None:
        raise AssertionError(f"{script} has no rsyslog_writer")
    return found.group(0)


class OneRuleTwoScripts(unittest.TestCase):
    def test_both_scripts_carry_the_same_function(self) -> None:
        first, second = (function_text(script) for script in SCRIPTS)
        self.assertEqual(first, second)

    def test_the_scripts_answer_as_rsyslog_would(self) -> None:
        function = function_text(SCRIPTS[0])
        for name, (written, expected) in CASES.items():
            with self.subTest(case=name), tempfile.TemporaryDirectory() as raw:
                etc = Path(raw) / "etc"
                (etc / "rsyslog.d").mkdir(parents=True)
                for relative, text in written.items():
                    (etc / relative).write_text(text)
                shell = subprocess.run(
                    [BASH, "-c", f"{function}\nrsyslog_writer"],
                    capture_output=True,
                    text=True,
                    check=True,
                    env={
                        **os.environ,
                        "RSYSLOG_CONFIG": str(etc / "rsyslog.conf"),
                        "RSYSLOG_DROPINS": str(etc / "rsyslog.d"),
                    },
                ).stdout.strip()
                self.assertEqual(shell, expected)
