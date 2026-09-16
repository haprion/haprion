from __future__ import annotations

import hashlib
import json
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

INSTALLER_PATH = Path(__file__).resolve().parents[1] / "tools" / "install-release.py"
SPEC = spec_from_file_location("install_release", INSTALLER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load release installer")
install_release_module = module_from_spec(SPEC)
SPEC.loader.exec_module(install_release_module)


class InstallReleaseTests(unittest.TestCase):
    def make_wheel(self, root: Path) -> tuple[Path, str]:
        wheel = root / "haproxy_manager-0.1.0-py3-none-any.whl"
        with zipfile.ZipFile(wheel, "w") as archive:
            archive.writestr("haproxy_mgmt/__init__.py", "")
            archive.writestr(
                "haproxy_mgmt/compatibility.json",
                '{"schema_version":1,"engine_api":1}\n',
            )
            archive.writestr("haproxy_mgmt/cli/__init__.py", "")
            archive.writestr(
                "haproxy_mgmt/cli/example.py",
                "def main():\n    return 0\n",
            )
            archive.writestr(
                "haproxy_manager-0.1.0.dist-info/METADATA",
                "Metadata-Version: 2.4\nName: haproxy-manager\nVersion: 0.1.0\n",
            )
            archive.writestr(
                "haproxy_manager-0.1.0.dist-info/entry_points.txt",
                "[console_scripts]\nhaproxy-example = haproxy_mgmt.cli.example:main\n",
            )
        digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
        return wheel, digest

    def test_installs_frozen_versioned_release_and_switches_current(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            work = Path(raw).resolve()
            wheel, digest = self.make_wheel(work)
            target = work / "target"
            release_id = install_release_module.install_release(
                wheel=wheel,
                expected_sha256=digest,
                target=target,
                python=Path(sys.executable),
                require_root=False,
            )

            release = target / "releases" / release_id
            self.assertEqual((target / "current").readlink(), Path("releases") / release_id)
            metadata = json.loads((release / "INSTALLATION.json").read_text())
            self.assertEqual(metadata["wheel_sha256"], digest)
            self.assertEqual(metadata["entry_points"], ["haproxy-example"])
            self.assertEqual(metadata["engine_api"], 1)
            self.assertRegex(metadata["pynacl"], r"^1\.")
            self.assertRegex(metadata["psycopg"], r"^3\.")
            self.assertEqual(stat.S_IMODE(release.stat().st_mode), 0o555)
            self.assertEqual(stat.S_IMODE((release / "bin/haproxy-example").stat().st_mode), 0o555)
            self.assertEqual(
                stat.S_IMODE((release / "lib/haproxy_mgmt/__init__.py").stat().st_mode), 0o444
            )
            launcher = (release / "bin/haproxy-example").read_text()
            self.assertTrue(launcher.startswith(f"#!{sys.executable} -I\n"))
            self.assertNotIn(str(INSTALLER_PATH.parents[1]), launcher)
            subprocess.run(  # noqa: S603 - generated local test launcher
                [str(release / "bin/haproxy-example")], check=True
            )

            for path in sorted(release.rglob("*"), reverse=True):
                if path.is_dir():
                    path.chmod(0o755)
            release.chmod(0o755)

    def test_rejects_hash_mismatch_and_unsafe_wheel_member(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            work = Path(raw).resolve()
            wheel, digest = self.make_wheel(work)
            with self.assertRaisesRegex(install_release_module.InstallError, "does not match"):
                install_release_module.install_release(
                    wheel=wheel,
                    expected_sha256="0" * 64,
                    target=work / "target-a",
                    python=Path(sys.executable),
                    require_root=False,
                )

            with zipfile.ZipFile(wheel, "a") as archive:
                archive.writestr("../escape", "bad")
            unsafe_digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
            with self.assertRaisesRegex(install_release_module.InstallError, "unsafe path"):
                install_release_module.install_release(
                    wheel=wheel,
                    expected_sha256=unsafe_digest,
                    target=work / "target-b",
                    python=Path(sys.executable),
                    require_root=False,
                )

            self.assertNotEqual(digest, unsafe_digest)

    def test_a_pre_metadata_wheel_remains_installable_as_engine_api_zero(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            work = Path(raw).resolve()
            wheel, _ = self.make_wheel(work)
            with zipfile.ZipFile(wheel, "r") as source:
                members = {
                    item.filename: source.read(item)
                    for item in source.infolist()
                    if item.filename != "haproxy_mgmt/compatibility.json"
                }
            wheel.unlink()
            with zipfile.ZipFile(wheel, "w") as target:
                for name, content in members.items():
                    target.writestr(name, content)
            digest = hashlib.sha256(wheel.read_bytes()).hexdigest()

            release_id = install_release_module.install_release(
                wheel=wheel,
                expected_sha256=digest,
                target=work / "target",
                python=Path(sys.executable),
                require_root=False,
            )

            metadata = json.loads(
                ((work / "target/releases" / release_id) / "INSTALLATION.json").read_text()
            )
            self.assertEqual(metadata["engine_api"], 0)

    def test_a_runtime_without_pynacl_is_refused_by_name(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            # A stand-in interpreter that has PyYAML's answer but no PyNaCl.
            fake = Path(raw) / "python3"
            fake.write_text('#!/bin/sh\necho \'{"python": "3.12.0", "pyyaml": "6.0.0"}\'\n')
            fake.chmod(0o755)
            with self.assertRaisesRegex(install_release_module.InstallError, "PyNaCl"):
                install_release_module.inspect_runtime(fake)

    def test_a_runtime_without_psycopg_is_refused_by_name(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fake = Path(raw) / "python3"
            fake.write_text(
                '#!/bin/sh\necho \'{"python": "3.12.0", "pyyaml": "6.0.0", "pynacl": "1.6.2"}\'\n'
            )
            fake.chmod(0o755)
            with self.assertRaisesRegex(install_release_module.InstallError, "psycopg"):
                install_release_module.inspect_runtime(fake)


if __name__ == "__main__":
    unittest.main()
