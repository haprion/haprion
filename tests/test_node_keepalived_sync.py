"""The node's keepalived step, exercised as the shell it actually is.

The function is extracted from `install/node/haproxy-pull-deploy` verbatim and
run with `keepalived` and `systemctl` replaced by recording stubs. That proves
the branches - when it does nothing, when it reloads, and what it leaves behind
when the configuration test fails - without a node.

It deliberately does not prove the wiring: that keepalived reads an included
file, and that the reload does not move the address, are facts about a real
node measured on one (2026-09-01, and again per cluster during rollout). This
is about the decisions the script makes around them, which is the half that can
silently take a wrong branch.
"""

from __future__ import annotations

import re
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "install" / "node" / "haproxy-pull-deploy"
FUNCTION = re.compile(r"^sync_keepalived_addresses\(\) \{.*?^\}$", re.DOTALL | re.MULTILINE)

STUB = """#!/bin/sh
echo "$(basename "$0") $*" >> "$RECORD"
exit "${%s:-0}"
"""

#
# `install -o root -g root` is right on a node, where this runs as root, and
# impossible in a test that does not. Ownership is not what these cases are
# about - they are about which branch is taken - so the flags are dropped and
# the copy is real.
#
INSTALL_STUB = """#!/bin/sh
set -eu
kept=""
while [ $# -gt 0 ]; do
    case "$1" in
        -o|-g) shift 2 ;;
        *) kept="${kept} \"$1\""; shift ;;
    esac
done
eval exec /usr/bin/install ${kept}
"""


class TheKeepalivedStep(unittest.TestCase):
    def setUp(self) -> None:
        found = FUNCTION.search(SCRIPT.read_text())
        assert found, "the function is no longer where the test extracts it from"
        self.function = found.group(0)
        self.root = Path(tempfile.mkdtemp())
        (self.root / "bin").mkdir()
        for name, variable in (("keepalived", "TEST_EXIT"), ("systemctl", "RELOAD_EXIT")):
            stub = self.root / "bin" / name
            stub.write_text(STUB % variable)
            stub.chmod(0o755)
        installer = self.root / "bin" / "install"
        installer.write_text(INSTALL_STUB)
        installer.chmod(0o755)
        (self.root / "release" / "keepalived").mkdir(parents=True)
        (self.root / "etc").mkdir()
        self.published = self.root / "release" / "keepalived" / "addresses.conf"
        self.conf = self.root / "etc" / "keepalived.conf"
        self.installed = self.root / "etc" / "addresses.conf"
        self.record = self.root / "record"

    def run_step(self, **environment: str) -> tuple[int, str]:
        script = self.root / "step.sh"
        script.write_text(
            "set -Eeuo pipefail\n"
            'log() { echo "$*"; }\n'
            f'CURRENT="{self.root / "release"}"\n'
            f'KEEPALIVED_CONF="{self.conf}"\n'
            f'KEEPALIVED_ADDRESSES="{self.installed}"\n'
            f"{self.function}\n"
            "sync_keepalived_addresses\n"
        )
        finished = subprocess.run(
            ["/bin/bash", str(script)],
            capture_output=True,
            text=True,
            env={
                "PATH": f"{self.root / 'bin'}:/usr/bin:/bin",
                "RECORD": str(self.record),
                **environment,
            },
            check=False,
        )
        return finished.returncode, finished.stdout

    def calls(self) -> str:
        return self.record.read_text() if self.record.exists() else ""

    def test_a_release_without_an_address_list_is_not_an_error(self) -> None:
        # Every cluster is in this state until its repository has been through
        # a publish that writes one.
        code, _ = self.run_step()

        self.assertEqual(code, 0)
        self.assertFalse(self.installed.exists())
        self.assertEqual(self.calls(), "")

    def test_a_node_without_the_include_line_gets_the_file_and_no_reload(self) -> None:
        #
        # The rollout order rests on this. The include cannot be added before
        # the file exists - keepalived would be pointed at something absent -
        # and the file cannot arrive if installing it required the include. So
        # the deploy delivers it inert, and a person adds the include after.
        #
        self.published.write_text("    192.0.2.20\n")
        self.conf.write_text("vrrp_instance alpha {\n}\n")

        code, output = self.run_step()

        self.assertEqual(code, 0)
        self.assertEqual(self.installed.read_text(), "    192.0.2.20\n")
        self.assertEqual(self.calls(), "")
        self.assertIn("NOT in use on this node", output)

    def include(self) -> None:
        self.conf.write_text(f"virtual_ipaddress {{\n    include {self.installed}\n}}\n")

    def test_a_changed_list_is_installed_and_keepalived_reloaded(self) -> None:
        self.published.write_text("    192.0.2.20\n")
        self.include()

        code, _ = self.run_step()

        self.assertEqual(code, 0)
        self.assertEqual(self.installed.read_text(), "    192.0.2.20\n")
        self.assertIn("--config-test", self.calls())
        self.assertIn("systemctl reload keepalived", self.calls())

    def test_an_unchanged_list_reloads_nothing(self) -> None:
        # Most deploys change only HAProxy configuration, and a reload of
        # keepalived on every one of them would be a risk taken for nothing.
        self.published.write_text("    192.0.2.20\n")
        self.installed.write_text("    192.0.2.20\n")
        self.include()

        code, _ = self.run_step()

        self.assertEqual(code, 0)
        self.assertEqual(self.calls(), "")

    def test_a_rejected_list_is_restored_and_never_reloaded(self) -> None:
        #
        # The single most important branch. keepalived skips an address it
        # cannot parse at runtime and carries on, so a reload after a failed
        # test would turn a mistyped address into a VIP that never appears and
        # says nothing about why.
        #
        self.published.write_text("    not-an-address\n")
        self.installed.write_text("    192.0.2.20\n")
        self.include()

        code, output = self.run_step(TEST_EXIT="5")

        self.assertEqual(code, 1)
        self.assertEqual(self.installed.read_text(), "    192.0.2.20\n")
        self.assertNotIn("reload", self.calls())
        self.assertIn("previous address list restored", output)

    def test_a_first_list_that_is_rejected_leaves_nothing_behind(self) -> None:
        # There is no previous file to restore, and leaving the rejected one in
        # place would mean the next unrelated deploy found them equal and
        # skipped the step that would have refused it again.
        self.published.write_text("    not-an-address\n")
        self.include()

        code, _ = self.run_step(TEST_EXIT="5")

        self.assertEqual(code, 1)
        self.assertFalse(self.installed.exists())

    def test_a_failed_reload_is_reported_rather_than_assumed(self) -> None:
        self.published.write_text("    192.0.2.20\n")
        self.installed.write_text("    192.0.2.21\n")
        self.include()

        code, output = self.run_step(RELOAD_EXIT="1")

        self.assertEqual(code, 1)
        self.assertEqual(self.installed.read_text(), "    192.0.2.21\n")
        self.assertIn("keepalived reload failed", output)
