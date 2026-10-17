"""The certbot package: built where it runs, carried as an archive, made current by step 14 (B322)."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from typing import Any

BASE = Path(__file__).resolve().parents[1]


def tool() -> Any:
    spec = importlib.util.spec_from_file_location(
        "build_certbot_package", BASE / "tools/build-certbot-package.py"
    )
    assert spec is not None and spec.loader is not None  # noqa: S101 - local tool must exist
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


TOOL = tool()
RELEASE = "5.8.0-0123456789ab"


class ThePostinst(unittest.TestCase):
    """Run as written, with its fixed paths moved under a temporary directory."""

    def install(self, raw: str, *, set_up: bool, current: str | None = None) -> tuple[Path, str]:
        top = Path(raw)
        root, lib = top / "opt/haprion-certbot", top / "usr/lib/haprion/certbot"
        step, timer = top / "step14", top / "renew.timer"
        lib.mkdir(parents=True)
        member = f"{str(root).lstrip('/')}/releases/{RELEASE}/INSTALLATION.json"
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as tar:
            info = tarfile.TarInfo(member)
            info.size = 2
            tar.addfile(info, io.BytesIO(b"{}"))
        archive = lib / f"release-{RELEASE}.tar"
        archive.write_bytes(buffer.getvalue())
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        (lib / "PAYLOAD").write_text(
            f"RELEASE_ID={RELEASE}\nRELEASE_ARCHIVE={archive.name}\nRELEASE_SHA256={digest}\n"
        )
        step.write_text(
            f'#!/bin/sh\necho "step 14 $1"\nln -sfn releases/{RELEASE} {root}/current\n'
        )
        step.chmod(0o755)
        if set_up:
            timer.write_text("")
        if current is not None:
            root.mkdir(parents=True, exist_ok=True)
            (root / "current").symlink_to(current)
        script = (
            TOOL.POSTINST.replace(TOOL.ROOT, str(root))
            .replace(f"/{TOOL.LIB}", str(lib))
            .replace(TOOL.STEP, str(step))
            .replace(TOOL.TIMER, str(timer))
        )
        done = subprocess.run(
            ["/bin/sh", "-c", script, "postinst", "configure"],
            capture_output=True,
            text=True,
            check=True,
        )
        return root, done.stdout

    def test_a_first_installation_unpacks_and_leaves_it_to_setup(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root, said = self.install(raw, set_up=False)

            self.assertTrue((root / "releases" / RELEASE / "INSTALLATION.json").is_file())
            self.assertFalse((root / "current").exists())
            self.assertIn("haprion-setup makes it current", said)

    def test_a_manager_already_set_up_runs_step_14(self) -> None:
        """Step 14 makes it current only after a dry-run renewal, and puts the previous back."""

        with tempfile.TemporaryDirectory() as raw:
            root, said = self.install(raw, set_up=True, current="releases/5.7.0-old")

            self.assertIn("step 14 -", said)
            self.assertEqual((root / "current").readlink(), Path(f"releases/{RELEASE}"))

    def test_the_current_release_is_left_alone(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            _, said = self.install(raw, set_up=True, current=f"releases/{RELEASE}")

            self.assertIn("already current", said)
            self.assertNotIn("step 14", said)

    def test_a_damaged_archive_unpacks_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            payload = Path(raw) / "usr/lib/haprion/certbot/PAYLOAD"
            original = TOOL.POSTINST
            try:
                TOOL.POSTINST = original.replace(
                    f". /{TOOL.LIB}/PAYLOAD",
                    f". /{TOOL.LIB}/PAYLOAD; RELEASE_SHA256={'0' * 64}",
                )
                with self.assertRaises(subprocess.CalledProcessError):
                    self.install(raw, set_up=False)
            finally:
                TOOL.POSTINST = original
            self.assertTrue(payload.is_file())
            self.assertFalse((Path(raw) / "opt/haprion-certbot/releases" / RELEASE).exists())


class TheBuild(unittest.TestCase):
    def test_it_is_built_by_the_same_installer_a_manager_runs(self) -> None:
        self.assertIn("tools/install-certbot-env.py", TOOL.BUILD)
        self.assertIn("--target /opt/haprion-certbot", TOOL.BUILD)

    def test_the_interface_needs_it(self) -> None:
        self.assertIn("haprion-certbot", TOOL.ui.depends("3.13").split(", "))
