"""The node's certificate activation, run for real in a temporary tree.

`haprion-cert-pull` is run by bash with its fixed paths rewritten to a scratch
directory and the commands that need a real node - rsync, haproxy, systemctl,
install as root - replaced by stubs that record what they were asked. openssl
is the real one, on a real certificate and key.

The case the review of 2026-09-26 found (F5): a run killed after the new files
were installed and before HAProxy was reloaded. The next run found the files
identical to what the manager offers and said "no reload needed", so the old
certificate stayed in service indefinitely.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any

BASE = Path(__file__).resolve().parents[1]
PULL = BASE / "install" / "node" / "haprion-cert-pull"

#
# rsync as the script calls it: `rsync -t -e <ssh> user@host:<id>.pem <dest>`.
# The last two arguments are all that matter here.
#
RSYNC_STUB = """#!/bin/sh
for last; do :; done
source=""
for argument; do
    [ "$argument" = "$last" ] && break
    source="$argument"
done
cp "$OFFERED/${source##*:}" "$last"
"""

#
# `haproxy -c` records the check and, when asked to, kills the script that
# called it - the moment between installing the files and reloading.
#
HAPROXY_STUB = """#!/bin/sh
echo check >> "$RECORD"
[ -e "$KILL_AT_CHECK" ] && kill -KILL "$PPID"
[ -e "$FAIL_CHECK" ] && exit 1
exit 0
"""

SYSTEMCTL_STUB = """#!/bin/sh
echo "$*" >> "$RECORD"
exit 0
"""

#
# `install -o root -g root -m 600 src dest` without root: the owner cannot be
# set here, and the mode and the copy are what the script depends on.
#
INSTALL_STUB = """#!/bin/sh
while [ $# -gt 2 ]; do shift; done
cp "$1" "$2" && chmod 600 "$2"
"""


def certificate(directory: Path, name: str) -> bytes:
    key = directory / f"{name}.key"
    cert = directory / f"{name}.crt"
    subprocess.run(
        [
            "/usr/bin/openssl",
            "ecparam",
            "-name",
            "prime256v1",
            "-genkey",
            "-noout",
            "-out",
            str(key),
        ],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            "/usr/bin/openssl", "req", "-new", "-x509", "-key", str(key), "-out", str(cert),
            "-days", "30", "-subj", f"/CN={name}.example.com",
        ],
        check=True,
        capture_output=True,
    )  # fmt: skip
    return cert.read_bytes() + key.read_bytes()


SERVER_STATE_STUB = """#!/bin/sh
# The node's server state helper as far as these scripts use it: every reload
# goes through it (Fas 20, B263), and it reloads with systemctl. `update-certs`
# (P5) answers what `$RUNTIME` says: 0 replaced, 3 not held, 70 refused.
[ "$1" = reload ] && exec systemctl reload haproxy
if [ "$1" = update-certs ]; then
    echo "$*" >> "$RECORD"
    exit "${RUNTIME:-3}"
fi
exit 64
"""


class CertPull(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        self.certs = self.root / "certs"
        self.certs.mkdir()
        self.offered = self.root / "offered"
        self.offered.mkdir()
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.record = self.root / "record"
        self.pending = self.root / "run" / "cert.pending"
        self.pending.parent.mkdir()
        conf = self.root / "node.conf"
        conf.write_text(
            "MANAGER=mgr.example.com\nCERT_PULL_USER=svc-app\nCERT_PULL_KEY=/dev/null\n",
            encoding="utf-8",
        )
        for name, body in (
            ("rsync", RSYNC_STUB),
            ("haproxy", HAPROXY_STUB),
            ("systemctl", SYSTEMCTL_STUB),
            ("haprion-server-state", SERVER_STATE_STUB),
            ("install", INSTALL_STUB),
        ):
            path = self.bin / name
            path.write_text(body, encoding="utf-8")
            path.chmod(0o755)
        self.script = self.bin / "haprion-cert-pull"
        self.script.write_text(
            PULL.read_text(encoding="utf-8")
            .replace('NODE_CONF="/etc/haprion/node.conf"', f'NODE_CONF="{conf}"')
            .replace('CERTS_DIR="/etc/haproxy/certs"', f'CERTS_DIR="{self.certs}"')
            .replace('PENDING="/run/haprion-cert-pull.pending"', f'PENDING="{self.pending}"')
            .replace("/run/lock/haprion-cert-pull.lock", str(self.root / "cert.lock"))
            .replace(
                'SERVER_STATE="/usr/sbin/haprion-server-state"',
                f'SERVER_STATE="{self.bin}/haprion-server-state"',
            ),
            encoding="utf-8",
        )
        self.old = certificate(self.root, "old")
        self.new = certificate(self.root, "new")

    def offer(self, content: bytes) -> None:
        (self.offered / "cert-a.pem").write_bytes(content)

    def run_pull(self, runtime: int = 3, **flags: bool) -> tuple[int, str]:
        environment = {
            "RUNTIME": str(runtime),
            "PATH": f"{self.bin}:/usr/bin:/bin",
            "OFFERED": str(self.offered),
            "RECORD": str(self.record),
            "KILL_AT_CHECK": str(self.root / "kill") if flags.get("kill") else "/nonexistent",
            "FAIL_CHECK": str(self.root / "fail") if flags.get("fail") else "/nonexistent",
            "TMPDIR": str(self.root),
        }
        for flag in ("kill", "fail"):
            marker = self.root / flag
            if flags.get(flag):
                marker.touch()
            else:
                marker.unlink(missing_ok=True)
        finished = subprocess.run(
            ["/bin/bash", str(self.script), "cert-a"],
            capture_output=True,
            text=True,
            env=environment,
            check=False,
        )
        return finished.returncode, finished.stdout + finished.stderr

    def reloads(self) -> int:
        if not self.record.exists():
            return 0
        return self.record.read_text().splitlines().count("reload haproxy")

    def test_a_new_certificate_is_installed_and_reloaded_once(self) -> None:
        self.offer(self.new)

        code, output = self.run_pull()

        self.assertEqual(code, 0, output)
        self.assertEqual((self.certs / "cert-a.pem").read_bytes(), self.new)
        self.assertEqual(self.reloads(), 1)
        self.assertFalse(self.pending.exists())

    def test_a_certificate_haproxy_holds_is_replaced_without_a_reload(self) -> None:
        """Fas 20 P5: `set ssl cert` and `commit` through the helper."""

        (self.certs / "cert-a.pem").write_bytes(self.old)
        self.offer(self.new)

        code, output = self.run_pull(runtime=0)

        self.assertEqual(code, 0, output)
        self.assertIn("without a reload", output)
        self.assertEqual((self.certs / "cert-a.pem").read_bytes(), self.new)
        self.assertIn("update-certs cert-a", self.record.read_text().splitlines())
        self.assertEqual(self.reloads(), 0)
        self.assertFalse(self.pending.exists())

    def test_a_certificate_haproxy_does_not_hold_or_refuses_is_reloaded(self) -> None:
        for answer in (3, 70, 69):
            with self.subTest(answer):
                self.record.unlink(missing_ok=True)
                (self.certs / "cert-a.pem").write_bytes(self.old)
                self.offer(self.new)

                code, output = self.run_pull(runtime=answer)

                self.assertEqual(code, 0, output)
                self.assertEqual(self.reloads(), 1)
                self.assertEqual((self.certs / "cert-a.pem").read_bytes(), self.new)
                self.assertFalse(self.pending.exists())

    def test_a_refused_check_never_reaches_the_running_haproxy(self) -> None:
        (self.certs / "cert-a.pem").write_bytes(self.old)
        self.offer(self.new)

        code, _output = self.run_pull(runtime=0, fail=True)

        self.assertEqual(code, 1)
        self.assertNotIn("update-certs", self.record.read_text())

    def test_an_unchanged_certificate_is_not_reloaded(self) -> None:
        (self.certs / "cert-a.pem").write_bytes(self.new)
        self.offer(self.new)

        code, output = self.run_pull()

        self.assertEqual(code, 0, output)
        self.assertIn("No reload needed", output)
        self.assertEqual(self.reloads(), 0)

    def test_a_run_killed_before_the_reload_is_finished_by_the_next(self) -> None:
        (self.certs / "cert-a.pem").write_bytes(self.old)
        self.offer(self.new)

        code, _output = self.run_pull(kill=True)

        self.assertEqual(code, -9)
        self.assertEqual((self.certs / "cert-a.pem").read_bytes(), self.new)
        self.assertEqual(self.reloads(), 0)
        self.assertTrue(self.pending.exists())

        code, output = self.run_pull()

        self.assertEqual(code, 0, output)
        self.assertNotIn("No reload needed", output)
        self.assertIn("never reloaded", output)
        self.assertEqual(self.reloads(), 1)
        self.assertFalse(self.pending.exists())

        code, output = self.run_pull()
        self.assertIn("No reload needed", output)
        self.assertEqual(self.reloads(), 1)

    def test_a_refused_check_restores_the_old_file_and_leaves_nothing_pending(self) -> None:
        (self.certs / "cert-a.pem").write_bytes(self.old)
        self.offer(self.new)

        code, output = self.run_pull(fail=True)

        self.assertEqual(code, 1, output)
        self.assertEqual((self.certs / "cert-a.pem").read_bytes(), self.old)
        self.assertEqual(self.reloads(), 0)
        self.assertFalse(self.pending.exists())

    def test_a_temporary_file_a_killed_run_left_is_swept(self) -> None:
        stray = self.certs / ".haprion-cert-pull.cert-a.pem"
        stray.write_bytes(self.old)
        self.offer(self.new)

        code, output = self.run_pull()

        self.assertEqual(code, 0, output)
        self.assertFalse(stray.exists())
        self.assertEqual(sorted(os.listdir(self.certs)), ["cert-a.pem"])


STATUS = BASE / "install" / "node" / "haprion-node-status"


def status_functions(certs: Path, pending: Path) -> dict[str, Any]:
    """`read_certificates` and what it calls, out of the status script as installed."""

    text = STATUS.read_text(encoding="utf-8")
    start = text.index("PEM = ")
    constants = text[start : text.index("\n\n\n", start)]
    functions = text[text.index("def leaf_fingerprint(") : text.index("def read_validation(")]
    namespace: dict[str, Any] = {
        "base64": __import__("base64"),
        "hashlib": __import__("hashlib"),
        "re": __import__("re"),
        "Path": Path,
        "run": lambda *_a: subprocess.CompletedProcess(_a, 0),
    }
    exec(constants, namespace)  # noqa: S102 - the file under test, read from disk
    exec(functions, namespace)  # noqa: S102
    namespace["CERTS_DIR"] = certs
    namespace["CERT_PENDING"] = pending
    return namespace


class TheNodeDoesNotReportWhatItDoesNotServe(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        self.certs = self.root / "certs"
        self.certs.mkdir()
        self.pending = self.root / "cert.pending"
        pem = certificate(self.root, "a")
        for name in ("cert-a", "cert-b"):
            (self.certs / f"{name}.pem").write_bytes(pem)
        self.read = status_functions(self.certs, self.pending)["read_certificates"]

    def ids(self) -> list[str]:
        return [entry["id"] for entry in self.read()]

    def test_without_a_marker_every_certificate_is_reported(self) -> None:
        self.assertEqual(self.ids(), ["cert-a", "cert-b"])

    def test_a_certificate_awaiting_its_reload_is_left_out(self) -> None:
        self.pending.write_text("cert-b\n", encoding="ascii")
        self.assertEqual(self.ids(), ["cert-a"])

    def test_a_marker_that_cannot_be_read_leaves_everything_out(self) -> None:
        self.pending.mkdir()
        self.assertEqual(self.ids(), [])


if __name__ == "__main__":
    unittest.main()
