"""The node's half of a certificate deletion, run for real in a temporary tree.

`haprion-cert-remove` and the verb `haprion-cert-trigger` dispatches to it.
The scripts are run by bash with their fixed paths rewritten to a scratch
directory, so what is held is the behaviour and not a reading of the text: an
ID the installed configuration still names is refused before anything is
removed, an absent file is not an error, and the wrapper hands the verb to the
right helper through `sudo` and refuses everything else.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
REMOVE = BASE / "install" / "node" / "haprion-cert-remove"
TRIGGER = BASE / "install" / "node" / "haprion-cert-trigger"

#
# A `sudo` that records what it was asked to run and runs it. The scripts
# call `sudo -n <helper> <ids...>`; the record is what the tests read.
#
SUDO_STUB = """#!/bin/sh
shift
printf '%s\\n' "$*" >> "$RECORD"
exec "$@"
"""


class ScriptFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        self.haproxy = self.root / "etc" / "haproxy"
        self.certs = self.haproxy / "certs"
        for directory in (self.certs, self.haproxy / "conf.d", self.haproxy / "crt-lists"):
            directory.mkdir(parents=True)
        (self.haproxy / "haproxy.cfg").write_text("global\n", encoding="utf-8")
        (self.root / "bin").mkdir()
        (self.root / "lock").mkdir()
        sudo = self.root / "bin" / "sudo"
        sudo.write_text(SUDO_STUB)
        sudo.chmod(0o755)
        self.record = self.root / "record"
        #
        # The scripts as installed, with the fixed paths pointed here.
        #
        self.remove = self.root / "bin" / "haprion-cert-remove"
        self.remove.write_text(
            REMOVE.read_text()
            .replace('CERTS_DIR="/etc/haproxy/certs"', f'CERTS_DIR="{self.certs}"')
            .replace('HAPROXY_DIR="/etc/haproxy"', f'HAPROXY_DIR="{self.haproxy}"')
            .replace("/run/lock/haprion-cert-pull.lock", str(self.root / "lock" / "cert.lock"))
        )
        self.remove.chmod(0o755)
        self.pull = self.root / "bin" / "haprion-cert-pull"
        self.pull.write_text('#!/bin/sh\necho pull "$@"\n')
        self.pull.chmod(0o755)
        self.trigger = self.root / "bin" / "haprion-cert-trigger"
        self.trigger.write_text(
            TRIGGER.read_text()
            .replace('PULL_HELPER="/usr/sbin/haprion-cert-pull"', f'PULL_HELPER="{self.pull}"')
            .replace(
                'REMOVE_HELPER="/usr/sbin/haprion-cert-remove"',
                f'REMOVE_HELPER="{self.remove}"',
            )
        )
        self.trigger.chmod(0o755)

    def run_remove(self, *ids: str) -> tuple[int, str]:
        finished = subprocess.run(
            ["/bin/bash", str(self.remove), *ids],
            capture_output=True,
            text=True,
            env={"PATH": "/usr/bin:/bin"},
            check=False,
        )
        return finished.returncode, finished.stdout + finished.stderr

    def run_trigger(self, request: str) -> tuple[int, str]:
        finished = subprocess.run(
            ["/bin/bash", str(self.trigger)],
            capture_output=True,
            text=True,
            env={
                "PATH": f"{self.root / 'bin'}:/usr/bin:/bin",
                "RECORD": str(self.record),
                "SSH_ORIGINAL_COMMAND": request,
            },
            check=False,
        )
        return finished.returncode, finished.stdout + finished.stderr

    def carried(self, *ids: str) -> None:
        for identifier in ids:
            (self.certs / f"{identifier}.pem").write_text("key and chain\n", encoding="utf-8")


class RemovingOnTheNode(ScriptFixture):
    def test_an_unlisted_certificate_is_removed_and_no_reload_is_asked_for(self) -> None:
        self.carried("old.example.com", "keep.example.com")
        code, output = self.run_remove("old.example.com")
        self.assertEqual(code, 0, output)
        self.assertFalse((self.certs / "old.example.com.pem").exists())
        self.assertTrue((self.certs / "keep.example.com.pem").exists())
        self.assertIn("No reload needed", output)

    def test_a_certificate_a_crt_list_names_is_refused_and_nothing_is_removed(self) -> None:
        self.carried("old.example.com", "other.example.com")
        (self.haproxy / "crt-lists" / "main.list").write_text(
            f"{self.certs}/old.example.com.pem alpn h2\n", encoding="utf-8"
        )
        code, output = self.run_remove("other.example.com", "old.example.com")
        self.assertEqual(code, 1)
        self.assertIn("still named by the installed configuration", output)
        self.assertTrue((self.certs / "old.example.com.pem").exists())
        self.assertTrue((self.certs / "other.example.com.pem").exists())

    def test_a_conf_d_fragment_counts_as_installed_configuration_too(self) -> None:
        self.carried("old.example.com")
        (self.haproxy / "conf.d" / "10-site.cfg").write_text(
            f"bind :443 ssl crt {self.certs}/old.example.com.pem\n", encoding="utf-8"
        )
        code, _ = self.run_remove("old.example.com")
        self.assertEqual(code, 1)
        self.assertTrue((self.certs / "old.example.com.pem").exists())

    def test_an_absent_certificate_is_not_an_error(self) -> None:
        code, output = self.run_remove("never.example.com")
        self.assertEqual(code, 0, output)
        self.assertIn("was not present", output)

    def test_an_invalid_id_and_no_id_are_refused(self) -> None:
        self.assertEqual(self.run_remove("../haproxy.cfg")[0], 1)
        self.assertEqual(self.run_remove()[0], 64)


class TheTriggerDispatchesTheVerb(ScriptFixture):
    def test_cert_remove_reaches_the_remove_helper_through_sudo(self) -> None:
        self.carried("old.example.com")
        code, output = self.run_trigger("cert-remove old.example.com")
        self.assertEqual(code, 0, output)
        self.assertEqual(self.record.read_text().strip(), f"{self.remove} old.example.com")
        self.assertFalse((self.certs / "old.example.com.pem").exists())

    def test_cert_pull_still_reaches_the_pull_helper(self) -> None:
        code, output = self.run_trigger("cert-pull a.example b.example")
        self.assertEqual(code, 0, output)
        self.assertEqual(self.record.read_text().strip(), f"{self.pull} a.example b.example")

    def test_an_unknown_verb_and_a_bad_id_are_refused_before_sudo(self) -> None:
        for request in ("cert-delete a.example", "cert-remove ../x", "cert-remove"):
            with self.subTest(request=request):
                code, output = self.run_trigger(request)
                self.assertEqual(code, 64, output)
        self.assertFalse(self.record.exists())


if __name__ == "__main__":
    unittest.main()
