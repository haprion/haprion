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
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any

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
count=$(grep -c '^check$' "$RECORD")
[ "$count" = "${KILL_AT_CHECK:-0}" ] && kill -KILL "$PPID"
exit 0
"""

SYSTEMCTL_STUB = """#!/bin/sh
echo "systemctl $*" >> "$RECORD"
case "$1" in
    reload) [ "$2" = haproxy ] && [ -e "$FAIL_RELOAD" ] && exit 1 ;;
    is-active|is-enabled) exit 3 ;;
esac
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


class TheActivationIsRememberedUntilHaproxyReloads(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.haproxy = self.root / "etc-haproxy"
        self.releases = self.haproxy / "releases"
        self.pending = self.root / "run" / "deploy.pending"
        self.pending.parent.mkdir()
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
            .replace("/run/lock/haprion-deploy.lock", str(self.root / "deploy.lock"))
            .replace(
                'SERVER_STATE="/usr/sbin/haprion-server-state"',
                f'SERVER_STATE="{self.bin}/haprion-server-state"',
            )
            .replace('KEEPALIVED_CONF="/etc/keepalived/', f'KEEPALIVED_CONF="{self.root}/')
            .replace(
                'KEEPALIVED_ADDRESSES="/etc/keepalived/', f'KEEPALIVED_ADDRESSES="{self.root}/'
            )
        )
        #
        # The node as 04-node-prepare leaves it: haproxy.cfg and conf.d are
        # links through `current`, which points at the first release.
        #
        self.old = self.write_release(self.releases / "20261004-080000", 7, "a" * 40)
        self.haproxy.joinpath("current").symlink_to(self.old)
        self.haproxy.joinpath("haproxy.cfg").symlink_to(self.haproxy / "current" / "haproxy.cfg")
        self.haproxy.joinpath("conf.d").symlink_to(self.haproxy / "current" / "conf.d")
        self.write_release(self.offered, 8, "b" * 40)

        found = READER.search(STATUS.read_text())
        assert found, "the reader is no longer where the test extracts it from"
        namespace: dict[str, Any] = {
            "Path": Path,
            "CURRENT_RELEASE": self.haproxy / "current" / "RELEASE",
            "RELEASES": self.releases,
            "CONFIG_PENDING": self.pending,
        }
        exec(found.group(0), namespace)  # noqa: S102 - the file under test, read from disk
        self.read_release = namespace["read_release"]

    def write_release(self, directory: Path, version: int, commit: str) -> Path:
        (directory / "conf.d").mkdir(parents=True)
        (directory / "maps").mkdir()
        (directory / "haproxy.cfg").write_text(f"# version {version}\n")
        (directory / "RELEASE").write_text(release_text(version, commit))
        return directory

    def deploy(self, *, kill_at_check: int = 0, fail_reload: bool = False) -> tuple[int, str]:
        self.record.unlink(missing_ok=True)
        environment = {
            "PATH": f"{self.bin}:/usr/bin:/bin",
            "OFFERED": str(self.offered),
            "RECORD": str(self.record),
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


if __name__ == "__main__":
    unittest.main()
