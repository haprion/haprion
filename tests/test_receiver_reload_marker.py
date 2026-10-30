"""The reference fetch scripts reload again after a reload that failed (E08).

The scripts install the pair and reload last. A reload that failed used to end
the run with the files in place, and the next timer run found them identical
and went out with 0: the service kept the old certificate. They run as root
and install with `-o root -g root`, which a test cannot, so `install` is the
real one with those two options dropped. The fetch itself is a stand-in that
copies a directory.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "examples" / "receivers"
OPENSSL = "/usr/bin/openssl"

FAKE_INSTALL = """#!/bin/sh
args=
while [ $# -gt 0 ]; do
    case "$1" in
        -o|-g) shift 2 ;;
        *) args="$args $1"; shift ;;
    esac
done
exec /usr/bin/install $args
"""

FAKE_RSYNC = """#!/bin/sh
for last; do :; done
cp -R "$FAKE_SOURCE"/. "$last"
"""


class AFailedReloadIsRetried(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for name, text in (("install", FAKE_INSTALL), ("rsync", FAKE_RSYNC)):
            (self.bin / name).write_text(text)
            (self.bin / name).chmod(0o755)
        self.source = self.root / "source"
        self.source.mkdir()
        self.target = self.root / "target"
        self.target.mkdir()
        self.reloads = self.root / "reloads"
        self.reload = self.root / "reload"
        self.mode = self.root / "reload-mode"
        self.mode.write_text("fail")
        self.reload.write_text(
            f'#!/bin/sh\necho reload >> "{self.reloads}"\n[ "$(cat "{self.mode}")" = ok ]\n'
        )
        self.reload.chmod(0o755)
        self.new_pair()

    def new_pair(self) -> None:
        subprocess.run(
            [
                OPENSSL,
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:prime256v1",
                "-nodes",
                "-keyout",
                str(self.source / "privkey.pem"),
                "-out",
                str(self.source / "fullchain.pem"),
                "-days",
                "2",
                "-subj",
                "/CN=lb-01.example.net",
            ],
            check=True,
            capture_output=True,
        )

    def run_script(self) -> int:
        environment = {
            **os.environ,
            "PATH": f"{self.bin}:{os.environ['PATH']}",
            "FAKE_SOURCE": str(self.source),
            "TARGET": str(self.target),
            "RELOAD": str(self.reload),
        }
        return subprocess.run(
            ["/bin/sh", str(SCRIPTS / "fetch-rsync")], env=environment, capture_output=True
        ).returncode

    def reload_count(self) -> int:
        return len(self.reloads.read_text().split()) if self.reloads.exists() else 0

    def test_the_next_run_reloads_although_the_files_are_identical(self) -> None:
        self.assertNotEqual(self.run_script(), 0)
        self.assertEqual(self.reload_count(), 1)
        self.assertTrue((self.target / ".reload-pending").exists())

        self.mode.write_text("ok")
        self.assertEqual(self.run_script(), 0)
        self.assertEqual(self.reload_count(), 2)
        self.assertFalse((self.target / ".reload-pending").exists())

        self.assertEqual(self.run_script(), 0)
        self.assertEqual(self.reload_count(), 2)

    def test_both_files_are_installed_and_no_temporary_name_is_left(self) -> None:
        self.mode.write_text("ok")
        self.assertEqual(self.run_script(), 0)

        self.assertEqual(
            sorted(path.name for path in self.target.iterdir()), ["fullchain.pem", "privkey.pem"]
        )
        self.assertEqual(
            (self.target / "privkey.pem").read_bytes(), (self.source / "privkey.pem").read_bytes()
        )
        self.assertEqual((self.target / "privkey.pem").stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.target / "fullchain.pem").stat().st_mode & 0o777, 0o644)

    def test_a_new_certificate_is_installed_and_reloaded(self) -> None:
        self.mode.write_text("ok")
        self.run_script()
        shutil.rmtree(self.source)
        self.source.mkdir()
        self.new_pair()

        self.assertEqual(self.run_script(), 0)
        self.assertEqual(self.reload_count(), 2)


if __name__ == "__main__":
    unittest.main()
