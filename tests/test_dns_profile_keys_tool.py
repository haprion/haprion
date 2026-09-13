"""The installation's key tool, run the way step 15 runs it."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "dns-profile-keys.py"


def run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-I", str(TOOL), *args], capture_output=True, text=True, check=False
    )


class KeyToolTests(unittest.TestCase):
    def test_create_writes_a_named_pair_and_show_reads_its_identifier(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            private_dir = Path(raw) / "secrets"
            public_dir = Path(raw) / "config"
            private_dir.mkdir()
            public_dir.mkdir()
            created = run("create", "--private", str(private_dir), "--public", str(public_dir))
            self.assertEqual(created.returncode, 0, created.stderr)
            key_id = created.stdout.strip()
            self.assertRegex(key_id, r"^[0-9a-f]{16}$")
            self.assertEqual([p.name for p in private_dir.iterdir()], [f"{key_id}.key"])
            self.assertEqual([p.name for p in public_dir.iterdir()], [f"{key_id}.pub"])
            self.assertEqual((private_dir / f"{key_id}.key").stat().st_mode & 0o777, 0o600)
            self.assertEqual((public_dir / f"{key_id}.pub").stat().st_mode & 0o777, 0o640)

            shown = run("show", "--public", str(public_dir / f"{key_id}.pub"))
            self.assertEqual(shown.stdout.strip(), key_id)

            second = run("create", "--private", str(private_dir), "--public", str(public_dir))
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertNotEqual(second.stdout.strip(), key_id)
            self.assertEqual(len(list(private_dir.iterdir())), 2)

    def test_a_missing_directory_or_a_private_file_in_the_public_slot_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            missing = run("create", "--private", str(Path(raw) / "no"), "--public", raw)
            self.assertEqual(missing.returncode, 1)
            self.assertIn("existing directory", missing.stderr)

            private_dir = Path(raw) / "secrets"
            private_dir.mkdir()
            created = run("create", "--private", str(private_dir), "--public", raw)
            self.assertEqual(created.returncode, 0, created.stderr)
            private_file = next(private_dir.iterdir())
            shown = run("show", "--public", str(private_file))
            self.assertEqual(shown.returncode, 1)
            self.assertIn("holds a haproxy-dns-profile-private-key-v1", shown.stderr)


if __name__ == "__main__":
    unittest.main()
