"""The node's configuration activation, run for real in a temporary tree (review 2026-10-03, F2).

`haprion-pull-deploy` switched `current` to the new release before HAProxy
reloaded. A run stopped in between left a node whose status read the new
release - so the manager skipped it as current - and whose next run found the
files identical to what was offered and said "no reload needed". HAProxy kept
the old configuration with nothing anywhere saying so.

The script is run by bash with its fixed paths rewritten to a scratch
directory, and the commands that need a real node - rsync, haproxy, systemctl,
chown - replaced by stubs that record what they were asked, as
`test_cert_pull_script` does for the certificate marker this follows. The
status side is `haprion-node-status`'s reader, extracted verbatim.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any

from tests.node_fixture import SYSTEMCTL_STUB, NodeTree

BASE = Path(__file__).resolve().parents[1]
DEPLOY = BASE / "install" / "node" / "haprion-pull-deploy"
STATUS = BASE / "install" / "node" / "haprion-node-status"

#
# rsync as the script calls it: the last argument is the stage directory.
#
RSYNC_STUB = """#!/bin/sh
for last; do :; done
cp -a "$OFFERED/." "$last"
"""

#
# `haproxy -c` counts its calls and, when asked, kills the script at one of
# them: the first is the candidate, the second the check after `current` was
# switched - the moment between the switch and the reload.
#
HAPROXY_STUB = """#!/bin/sh
echo check >> "$RECORD"
[ -e "${FAIL_CHECK:-/nonexistent}" ] && exit 1
count=$(grep -c '^check$' "$RECORD")
[ "$count" = "${KILL_AT_CHECK:-0}" ] && kill -KILL "$PPID"
exit 0
"""

CHOWN_STUB = "#!/bin/sh\nexit 0\n"

READER = re.compile(
    r"^def running_release_file\(.*?(?=^def leaf_fingerprint)", re.DOTALL | re.MULTILINE
)


def release_text(version: int, commit: str) -> str:
    return f"schema=1\ncluster=alpha\nversion={version}\nhash={commit}\ntimestamp=2026-10-04T09:00:00+00:00\n"


SERVER_STATE_STUB = """#!/bin/sh
# The node's server state helper as far as these scripts use it: every reload
# goes through it (Fas 20, B263), and it reloads with systemctl.
[ "$1" = reload ] && exec systemctl reload haproxy
exit 64
"""


class Node(unittest.TestCase):
    """The scratch node and the run of the script on it."""

    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.tree = NodeTree.build(self.root)
        self.haproxy = self.tree.haproxy
        self.releases = self.tree.releases
        self.pending = self.root / "run" / "deploy.pending"
        self.pending.parent.mkdir()
        self.incomplete = self.root / "state" / "pull-deploy.incomplete"
        self.record = self.root / "record"
        self.offered = self.root / "offered"
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for name, body in (
            ("rsync", RSYNC_STUB),
            ("haproxy", HAPROXY_STUB),
            ("systemctl", SYSTEMCTL_STUB),
            ("haprion-server-state", SERVER_STATE_STUB),
            ("chown", CHOWN_STUB),
        ):
            path = self.bin / name
            path.write_text(body)
            path.chmod(0o755)
        conf = self.root / "node.conf"
        conf.write_text(
            "MANAGER=mgr.example.com\nCONFIG_PULL_USER=svc-app\nCONFIG_PULL_KEY=/dev/null\n"
            "CONFIG_REMOTE_PATH=/srv/alpha/\n"
        )
        self.script = self.bin / "haprion-pull-deploy"
        self.script.write_text(
            DEPLOY.read_text()
            .replace('NODE_CONF="/etc/haprion/node.conf"', f'NODE_CONF="{conf}"')
            .replace('HAPROXY_DIR="/etc/haproxy"', f'HAPROXY_DIR="{self.haproxy}"')
            .replace('PENDING="/run/haprion-pull-deploy.pending"', f'PENDING="{self.pending}"')
            .replace(
                'INCOMPLETE="/var/lib/haprion/pull-deploy.incomplete"',
                f'INCOMPLETE="{self.incomplete}"',
            )
            .replace("/run/haprion-deploy.lock", str(self.root / "deploy.lock"))
            .replace(
                'SERVER_STATE="/usr/sbin/haprion-server-state"',
                f'SERVER_STATE="{self.bin}/haprion-server-state"',
            )
            .replace('KEEPALIVED_CONF="/etc/keepalived/', f'KEEPALIVED_CONF="{self.root}/')
            .replace(
                'KEEPALIVED_ADDRESSES="/etc/keepalived/', f'KEEPALIVED_ADDRESSES="{self.root}/'
            )
            .replace(
                'LEFT_MARKER="/etc/haprion/left-cluster"', f'LEFT_MARKER="{self.root}/left-cluster"'
            )
        )
        self.left = self.root / "left-cluster"
        #
        # The node as 04-node-prepare leaves it, serving its first release.
        #
        self.old = self.tree.install("20261004-080000", 7, "a" * 40)
        self.write_release(self.offered, 8, "b" * 40)

        found = READER.search(STATUS.read_text())
        assert found, "the reader is no longer where the test extracts it from"
        namespace: dict[str, Any] = {
            "Path": Path,
            "CURRENT_RELEASE": self.haproxy / "current" / "RELEASE",
            "RELEASES": self.releases,
            "CONFIG_PENDING": self.pending,
            "DEPLOY_INCOMPLETE": self.incomplete,
        }
        exec(found.group(0), namespace)  # noqa: S102 - the file under test, read from disk
        self.read_release = namespace["read_release"]

    def write_release(self, directory: Path, version: int, commit: str) -> Path:
        return self.tree.write_release(directory, version, commit)

    def deploy(
        self,
        *,
        kill_at_check: int = 0,
        fail_reload: bool = False,
        fail_check: bool = False,
        fail_start: bool = False,
    ) -> tuple[int, str]:
        self.record.unlink(missing_ok=True)
        flag = self.root / "flag"
        flag.touch()
        environment = {
            "FAIL_CHECK": str(flag) if fail_check else "/nonexistent",
            "FAIL_START": str(flag) if fail_start else "/nonexistent",
            "PATH": f"{self.bin}:/usr/bin:/bin",
            "OFFERED": str(self.offered),
            "RECORD": str(self.record),
            "UNITS": str(self.tree.units),
            "KILL_AT_CHECK": str(kill_at_check),
            "FAIL_RELOAD": str(self.root / "fail-reload") if fail_reload else "/nonexistent",
            "TMPDIR": str(self.root),
        }
        if fail_reload:
            (self.root / "fail-reload").touch()
        finished = subprocess.run(
            ["/bin/bash", str(self.script)],
            capture_output=True,
            text=True,
            env=environment,
            check=False,
        )
        (self.root / "fail-reload").unlink(missing_ok=True)
        return finished.returncode, finished.stdout + finished.stderr

    def reloads(self) -> int:
        if not self.record.exists():
            return 0
        return self.record.read_text().splitlines().count("systemctl reload haproxy")


class TheActivationIsRememberedUntilHaproxyReloads(Node):
    def test_a_deploy_reloads_once_and_leaves_no_marker(self) -> None:
        code, output = self.deploy()

        self.assertEqual(code, 0, output)
        self.assertEqual(self.reloads(), 1)
        self.assertFalse(self.pending.exists())
        self.assertEqual(self.read_release()["hash"], "b" * 40)

    def test_a_run_stopped_after_the_switch_is_reported_on_the_old_release(self) -> None:
        code, _ = self.deploy(kill_at_check=2)

        self.assertEqual(code, -9)
        self.assertEqual(
            (self.haproxy / "current" / "RELEASE").read_text(), release_text(8, "b" * 40)
        )
        self.assertEqual(self.reloads(), 0)
        self.assertTrue(self.pending.exists())
        # What HAProxy runs, not what the link says - so the manager sees the node behind.
        self.assertEqual(self.read_release()["hash"], "a" * 40)

    def test_the_next_run_finishes_the_reload_instead_of_calling_it_done(self) -> None:
        self.deploy(kill_at_check=2)

        code, output = self.deploy()

        self.assertEqual(code, 0, output)
        self.assertNotIn("No change. No deploy or reload needed.", output)
        self.assertIn("never reloaded", output)
        self.assertEqual(self.reloads(), 1)
        self.assertFalse(self.pending.exists())
        self.assertEqual(self.read_release()["hash"], "b" * 40)

    def test_an_unchanged_run_without_a_marker_does_nothing(self) -> None:
        self.deploy()

        code, output = self.deploy()

        self.assertEqual(code, 0, output)
        self.assertIn("No change. No deploy or reload needed.", output)
        self.assertEqual(self.reloads(), 0)

    def test_a_failed_reload_rolls_back_and_clears_the_marker(self) -> None:
        code, output = self.deploy(fail_reload=True)

        self.assertEqual(code, 1, output)
        self.assertEqual(self.haproxy.joinpath("current").resolve(), self.old.resolve())
        self.assertFalse(self.pending.exists())
        self.assertEqual(self.read_release()["hash"], "a" * 40)

    def test_a_marker_that_names_no_release_reports_nothing(self) -> None:
        for content in ("/etc/passwd\n", "", f"{self.releases}/../x\n"):
            with self.subTest(content=content):
                self.pending.write_text(content)
                self.assertIsNone(self.read_release()["hash"])


class AConfigurationOfItsOwnIsRefused(Node):
    """Review 26-10-24, 03-03: a node's own haproxy.cfg or conf.d was loaded instead of the release."""

    def test_a_plain_file_or_directory_stops_the_deploy_before_anything_changes(self) -> None:
        for name in ("haproxy.cfg", "conf.d", "maps"):
            with self.subTest(name=name):
                path = self.haproxy / name
                path.unlink()
                if name == "haproxy.cfg":
                    path.write_text("# mine\n")
                else:
                    path.mkdir()
                    (path / "mine.cfg").write_text("# mine\n")

                code, output = self.deploy()

                self.assertEqual(code, 1, output)
                self.assertIn(f"{path} is not the link to current/{name}", output)
                self.assertEqual(self.reloads(), 0)
                self.assertEqual(self.read_release()["hash"], "a" * 40)
                if path.is_dir():
                    shutil.rmtree(path)
                else:
                    path.unlink()
                path.symlink_to(Path("current") / name)

    def test_a_missing_haproxy_cfg_is_refused_and_a_missing_waf_is_not(self) -> None:
        (self.haproxy / "waf").unlink()
        code, output = self.deploy()
        self.assertEqual(code, 0, output)

        (self.haproxy / "haproxy.cfg").unlink()
        code, output = self.deploy()
        self.assertEqual(code, 1, output)
        self.assertIn("haproxy.cfg is not the link", output)


class AStepAfterTheReloadThatFailsIsRemembered(Node):
    """Review 26-10-30, D1: keepalived.conf is measured by no status field, so a node whose
    keepalived step failed after the reload was current by hash and skipped next time."""

    def setUp(self) -> None:
        super().setUp()
        stub = self.bin / "keepalived"
        stub.write_text(f'#!/bin/sh\n[ -e "{self.root}/keepalived-fails" ] && exit 1\nexit 0\n')
        stub.chmod(0o755)
        #
        # `install -o root` is a node's; the copy is what these cases are about.
        #
        installer = self.bin / "install"
        installer.write_text(
            '#!/bin/sh\nset -eu\nkept=""\nwhile [ $# -gt 0 ]; do\n    case "$1" in\n'
            '        -o|-g) shift 2 ;;\n        *) kept="${kept} \\"$1\\""; shift ;;\n'
            "    esac\ndone\neval exec /usr/bin/install ${kept}\n"
        )
        installer.chmod(0o755)
        self.addresses = self.root / "addresses.conf"
        (self.root / "keepalived.conf").write_text(
            f"virtual_ipaddress {{\n    include {self.addresses}\n}}\n"
        )
        (self.offered / "keepalived").mkdir()
        (self.offered / "keepalived" / "addresses.conf").write_text("    192.0.2.20\n")

    def keepalived_fails(self, failing: bool) -> None:
        marker = self.root / "keepalived-fails"
        marker.touch() if failing else marker.unlink(missing_ok=True)

    def test_a_failed_keepalived_step_leaves_the_node_incomplete(self) -> None:
        self.keepalived_fails(True)

        code, output = self.deploy()

        self.assertEqual(code, 1, output)
        self.assertIn("keepalived rejected", output)
        self.assertEqual(self.read_release()["hash"], "b" * 40)
        self.assertIs(self.read_release()["complete"], False)

    def test_the_next_run_with_an_unchanged_release_completes_it(self) -> None:
        self.keepalived_fails(True)
        self.deploy()
        self.keepalived_fails(False)

        code, output = self.deploy()

        self.assertEqual(code, 0, output)
        self.assertIn("No change.", output)
        self.assertIs(self.read_release()["complete"], True)
        self.assertEqual(self.addresses.read_text(), "    192.0.2.20\n")

    def test_an_unchanged_run_that_fails_again_stays_incomplete(self) -> None:
        self.keepalived_fails(True)
        self.deploy()

        code, _ = self.deploy()

        self.assertEqual(code, 1)
        self.assertIs(self.read_release()["complete"], False)

    def test_a_clean_deploy_is_complete(self) -> None:
        code, output = self.deploy()

        self.assertEqual(code, 0, output)
        self.assertIs(self.read_release()["complete"], True)
        self.assertFalse(self.incomplete.exists())

    def test_a_run_stopped_before_the_reload_finishes_with_the_marker_removed(self) -> None:
        self.deploy(kill_at_check=2)

        code, output = self.deploy()

        self.assertEqual(code, 0, output)
        self.assertIs(self.read_release()["complete"], True)

    def test_a_reboot_between_the_link_switch_and_the_reload_is_not_called_complete(self) -> None:
        self.deploy(kill_at_check=2)
        self.pending.unlink()  # a reboot empties /run; HAProxy then starts from `current`

        self.assertIs(self.read_release()["complete"], False)


class ARemovedNodeRejoinsOnTheNewReleaseOnly(Node):
    """Logic review 26-10-22, L1: a node added again started HAProxy and
    keepalived on the configuration from before it left, before the new one was
    validated, and kept them running when it was refused."""

    def setUp(self) -> None:
        super().setUp()
        #
        # As `haprion-pull-deploy` leaves a node that left: both stopped and
        # disabled, and the marker.
        #
        self.left.touch()
        self.tree.set_unit("haproxy", active=False)
        self.tree.set_unit("keepalived", active=False)

    def calls(self) -> list[str]:
        return self.record.read_text().splitlines() if self.record.exists() else []

    def test_both_start_after_the_release_is_installed_keepalived_last(self) -> None:
        code, output = self.deploy()

        self.assertEqual(code, 0, output)
        calls = self.calls()
        haproxy = calls.index("systemctl enable --quiet --now haproxy")
        keepalived = calls.index("systemctl enable --quiet --now keepalived")
        self.assertEqual(calls[:2], ["check", "check"])
        self.assertLess(haproxy, keepalived)
        self.assertNotIn("systemctl reload haproxy", calls)
        self.assertFalse(self.left.exists())
        self.assertFalse(self.pending.exists())
        self.assertEqual(self.read_release()["hash"], "b" * 40)

    def test_a_refused_release_starts_nothing_and_keeps_the_node_out(self) -> None:
        code, output = self.deploy(fail_check=True)

        self.assertEqual(code, 1, output)
        self.assertFalse([call for call in self.calls() if call.startswith("systemctl enable")])
        self.assertTrue(self.left.exists())
        self.assertEqual(self.haproxy.joinpath("current").resolve(), self.old.resolve())

    def test_haproxy_that_does_not_start_rolls_back_and_keeps_the_node_out(self) -> None:
        code, output = self.deploy(fail_start=True)

        self.assertEqual(code, 1, output)
        calls = self.calls()
        self.assertNotIn("systemctl enable --quiet --now keepalived", calls)
        self.assertIn("systemctl disable --quiet --now haproxy", calls)
        self.assertTrue(self.left.exists())
        self.assertEqual(self.haproxy.joinpath("current").resolve(), self.old.resolve())
        self.assertFalse(self.pending.exists())

    def test_a_haproxy_an_earlier_attempt_started_is_reloaded_onto_the_new_release(self) -> None:
        """Code review 26-10-22, 1A-2: an attempt that started HAProxy and then
        failed on keepalived kept the marker, and the next one's `enable --now`
        did nothing to a running HAProxy - the node said it ran the new release
        and served the one before."""

        self.tree.set_unit("haproxy", active=True)

        code, output = self.deploy()

        self.assertEqual(code, 0, output)
        calls = self.calls()
        self.assertIn("systemctl reload haproxy", calls)
        self.assertLess(
            calls.index("systemctl reload haproxy"),
            calls.index("systemctl enable --quiet --now keepalived"),
        )
        self.assertTrue(self.tree.is_active("haproxy"))
        self.assertTrue(self.tree.is_active("keepalived"))
        self.assertFalse(self.left.exists())
        self.assertEqual(self.read_release()["hash"], "b" * 40)

    def test_an_unchanged_release_is_still_installed_and_started(self) -> None:
        self.write_release(self.root / "same", 7, "a" * 40)
        self.offered = self.root / "same"

        code, output = self.deploy()

        self.assertEqual(code, 0, output)
        self.assertNotIn("No change.", output)
        self.assertIn("systemctl enable --quiet --now keepalived", self.calls())
        self.assertFalse(self.left.exists())


if __name__ == "__main__":
    unittest.main()
