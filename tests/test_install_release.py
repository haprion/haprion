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

from haprion import (
    carried_package,
    debian_package,
    keyring_package,
    node_package,
    waf_engine_package,
)
from tests.test_keyring_package import deb as keyring_deb
from tests.test_waf_engine_package import deb as engine_deb

INSTALLER_PATH = Path(__file__).resolve().parents[1] / "tools" / "install-release.py"
NODE_PACKAGE_SOURCE = Path(node_package.__file__).read_text(encoding="utf-8")
WAF_ENGINE_SOURCE = Path(waf_engine_package.__file__).read_text(encoding="utf-8")
KEYRING_SOURCE = Path(keyring_package.__file__).read_text(encoding="utf-8")
CARRIED_SOURCE = Path(carried_package.__file__).read_text(encoding="utf-8")
DEBIAN_PACKAGE_SOURCE = Path(debian_package.__file__).read_text(encoding="utf-8")
EPOCH = 1_790_000_000
COMMIT = "0123456789ab" + "0" * 28
SPEC = spec_from_file_location("install_release", INSTALLER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load release installer")
install_release_module = module_from_spec(SPEC)
SPEC.loader.exec_module(install_release_module)


class InstallReleaseTests(unittest.TestCase):
    def make_wheel(self, root: Path, *, config: str | None = None) -> tuple[Path, str]:
        root.mkdir(parents=True, exist_ok=True)
        wheel = root / "haprion-0.1.0-py3-none-any.whl"
        with zipfile.ZipFile(wheel, "w") as archive:
            archive.writestr("haprion/__init__.py", "")
            if config is not None:
                # A reader that accepts, or refuses with `config` (11-03).
                refuse = "" if config == "ok" else f"    raise ValueError({config!r})\n"
                archive.writestr(
                    "haprion/config.py",
                    "def load_policy(path, require_secure=True):\n"
                    f"{refuse}    return path\n"
                    "def load_runtime_config(policy, require_secure=True):\n"
                    "    return policy\n",
                )
            archive.writestr(
                "haprion/compatibility.json",
                '{"schema_version":1,"engine_api":1}\n',
            )
            # The release verifies its node package with its own verifier.
            archive.writestr("haprion/node_package.py", NODE_PACKAGE_SOURCE)
            archive.writestr("haprion/waf_engine_package.py", WAF_ENGINE_SOURCE)
            archive.writestr("haprion/keyring_package.py", KEYRING_SOURCE)
            archive.writestr("haprion/carried_package.py", CARRIED_SOURCE)
            archive.writestr("haprion/debian_package.py", DEBIAN_PACKAGE_SOURCE)
            archive.writestr("haprion/cli/__init__.py", "")
            archive.writestr(
                "haprion/cli/example.py",
                "def main():\n    return 0\n",
            )
            archive.writestr(
                "haprion-0.1.0.dist-info/METADATA",
                "Metadata-Version: 2.4\nName: haprion\nVersion: 0.1.0\n",
            )
            archive.writestr(
                "haprion-0.1.0.dist-info/entry_points.txt",
                "[console_scripts]\nhaprion-example = haprion.cli.example:main\n",
            )
        digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
        return wheel, digest

    def make_package(self, root: Path) -> tuple[Path, str]:
        files = {path: f"# {path}\n".encode() for path in node_package.CONTENTS}
        deb = node_package.write_package(
            root / "package-build", files, upstream="0.1.0", epoch=EPOCH, commit=COMMIT
        )
        return deb, hashlib.sha256(deb.read_bytes()).hexdigest()

    def test_the_node_package_travels_in_the_release_and_is_found_there(self) -> None:
        """B180: a node restore installs exactly the package of the running release."""

        with tempfile.TemporaryDirectory() as raw:
            work = Path(raw).resolve()
            wheel, digest = self.make_wheel(work)
            deb, deb_digest = self.make_package(work)
            release_id = install_release_module.install_release(
                wheel=wheel,
                expected_sha256=digest,
                target=work / "target",
                python=Path(sys.executable),
                require_root=False,
                node_package=deb,
                node_package_sha256=deb_digest,
            )
            release = work / "target" / "releases" / release_id
            metadata = json.loads((release / "INSTALLATION.json").read_text())
            self.assertEqual(
                metadata["node_package"],
                {
                    "file": "haprion-node.deb",
                    "version": f"0.1.0+git20260921141320.{COMMIT[:12]}",
                    "commit": COMMIT,
                    "sha256": deb_digest,
                },
            )
            found = node_package.release_package(release)
            assert found is not None
            self.assertEqual((found.commit, found.sha256), (COMMIT, deb_digest))

            # The same release again with another package is not changed in place.
            with self.assertRaisesRegex(
                install_release_module.InstallError, "not changed in place"
            ):
                install_release_module.install_release(
                    wheel=wheel,
                    expected_sha256=digest,
                    target=work / "target",
                    python=Path(sys.executable),
                    require_root=False,
                )
            for path in sorted(release.rglob("*"), reverse=True):
                path.chmod(0o700 if path.is_dir() else 0o600)
            release.chmod(0o700)

    def test_a_release_that_cannot_read_the_configuration_does_not_become_current(self) -> None:
        """Review 26-10-24, 11-03: going back with apt left helpers that answered CONFIG."""

        with tempfile.TemporaryDirectory() as raw:
            work = Path(raw).resolve()
            policy = work / "runtime-policy.yaml"
            policy.write_text("schema_version: 1\n")
            target = work / "target"
            accepting = self.make_wheel(work / "first", config="ok")
            first = install_release_module.install_release(
                wheel=accepting[0],
                expected_sha256=accepting[1],
                target=target,
                python=Path(sys.executable),
                require_root=False,
                policy=policy,
            )
            refusing = self.make_wheel(work / "second", config="unknown key vrrp_router_id")
            with self.assertRaisesRegex(
                install_release_module.InstallError, "unknown key vrrp_router_id.*not moved"
            ):
                install_release_module.install_release(
                    wheel=refusing[0],
                    expected_sha256=refusing[1],
                    target=target,
                    python=Path(sys.executable),
                    require_root=False,
                    policy=policy,
                )
            self.assertEqual((target / "current").resolve().name, first)
            for path in sorted(target.rglob("*"), reverse=True):
                if not path.is_symlink():
                    path.chmod(0o700 if path.is_dir() else 0o600)

    def test_the_waf_engine_package_travels_in_the_release_and_is_found_there(self) -> None:
        """B298: a restored node that ran the engine gets the release's."""

        with tempfile.TemporaryDirectory() as raw:
            work = Path(raw).resolve()
            wheel, digest = self.make_wheel(work)
            engine = engine_deb(work)
            engine_digest = hashlib.sha256(engine.read_bytes()).hexdigest()
            release_id = install_release_module.install_release(
                wheel=wheel,
                expected_sha256=digest,
                target=work / "target",
                python=Path(sys.executable),
                require_root=False,
                waf_engine_package=engine,
                waf_engine_package_sha256=engine_digest,
            )
            release = work / "target" / "releases" / release_id
            metadata = json.loads((release / "INSTALLATION.json").read_text())
            self.assertEqual(
                metadata["waf_engine_package"],
                {"file": "haprion-coraza-spoa.deb", "version": "0.9.0-7", "sha256": engine_digest},
            )
            found = waf_engine_package.release_package(release)
            assert found is not None
            self.assertEqual(found.sha256, engine_digest)
            with self.assertRaisesRegex(
                install_release_module.InstallError, "not changed in place"
            ):
                install_release_module.install_release(
                    wheel=wheel,
                    expected_sha256=digest,
                    target=work / "target",
                    python=Path(sys.executable),
                    require_root=False,
                )
            for path in sorted(release.rglob("*"), reverse=True):
                path.chmod(0o700 if path.is_dir() else 0o600)
            release.chmod(0o700)

    def test_the_key_package_travels_in_the_release_and_is_found_there(self) -> None:
        """B339: the node package depends on it; a node restored from files gets the release's."""

        with tempfile.TemporaryDirectory() as raw:
            work = Path(raw).resolve()
            wheel, digest = self.make_wheel(work)
            key = keyring_deb(work)
            key_digest = hashlib.sha256(key.read_bytes()).hexdigest()
            release_id = install_release_module.install_release(
                wheel=wheel,
                expected_sha256=digest,
                target=work / "target",
                python=Path(sys.executable),
                require_root=False,
                keyring_package=key,
                keyring_package_sha256=key_digest,
            )
            release = work / "target" / "releases" / release_id
            metadata = json.loads((release / "INSTALLATION.json").read_text())
            self.assertEqual(
                metadata["keyring_package"],
                {
                    "file": "haprion-archive-keyring.deb",
                    "version": "2026.10.17",
                    "sha256": key_digest,
                },
            )
            found = keyring_package.release_package(release)
            assert found is not None
            self.assertEqual(found.sha256, key_digest)
            wrong = keyring_deb(work, name="something-else")
            with self.assertRaisesRegex(
                install_release_module.InstallError, "repository key package verification failed"
            ):
                install_release_module.install_release(
                    wheel=wheel,
                    expected_sha256=digest,
                    target=work / "other",
                    python=Path(sys.executable),
                    require_root=False,
                    keyring_package=wrong,
                    keyring_package_sha256=hashlib.sha256(wrong.read_bytes()).hexdigest(),
                )
            for path in sorted(release.rglob("*"), reverse=True):
                path.chmod(0o700 if path.is_dir() else 0o600)
            release.chmod(0o700)

    def test_a_waf_engine_package_that_is_not_one_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            work = Path(raw).resolve()
            wheel, digest = self.make_wheel(work)
            wrong = engine_deb(work, name="something-else")
            with self.assertRaisesRegex(
                install_release_module.InstallError, "WAF engine package verification failed"
            ):
                install_release_module.install_release(
                    wheel=wheel,
                    expected_sha256=digest,
                    target=work / "target",
                    python=Path(sys.executable),
                    require_root=False,
                    waf_engine_package=wrong,
                    waf_engine_package_sha256=hashlib.sha256(wrong.read_bytes()).hexdigest(),
                )

    def test_a_node_package_that_does_not_verify_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            work = Path(raw).resolve()
            wheel, digest = self.make_wheel(work)
            broken = work / "broken.deb"
            broken.write_bytes(b"not a package")
            broken_digest = hashlib.sha256(broken.read_bytes()).hexdigest()
            with self.assertRaisesRegex(install_release_module.InstallError, "node package"):
                install_release_module.install_release(
                    wheel=wheel,
                    expected_sha256=digest,
                    target=work / "target",
                    python=Path(sys.executable),
                    require_root=False,
                    node_package=broken,
                    node_package_sha256=broken_digest,
                )
            with self.assertRaisesRegex(install_release_module.InstallError, "both"):
                install_release_module.install_release(
                    wheel=wheel,
                    expected_sha256=digest,
                    target=work / "target",
                    python=Path(sys.executable),
                    require_root=False,
                    node_package=broken,
                )

    def test_a_release_without_a_package_says_so(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            release = Path(raw)
            (release / "INSTALLATION.json").write_text('{"release_id": "x"}\n')
            self.assertIsNone(node_package.release_package(release))
            self.assertIsNone(node_package.release_package(release / "missing"))

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
            self.assertEqual(metadata["entry_points"], ["haprion-example"])
            self.assertEqual(metadata["engine_api"], 1)
            self.assertRegex(metadata["pynacl"], r"^1\.")
            self.assertRegex(metadata["psycopg"], r"^3\.")
            self.assertEqual(stat.S_IMODE(release.stat().st_mode), 0o555)
            self.assertEqual(stat.S_IMODE((release / "bin/haprion-example").stat().st_mode), 0o555)
            self.assertEqual(
                stat.S_IMODE((release / "lib/haprion/__init__.py").stat().st_mode), 0o444
            )
            launcher = (release / "bin/haprion-example").read_text()
            shebang = f"#!{sys.executable} -I\n"
            self.assertTrue(launcher.startswith(shebang))
            # The body, not the interpreter line: a checkout set up with
            # tools/bootstrap-dev keeps its interpreter inside it (26-10-10).
            self.assertNotIn(str(INSTALLER_PATH.parents[1]), launcher.removeprefix(shebang))
            subprocess.run(  # generated local test launcher
                [str(release / "bin/haprion-example")], check=True
            )

            for path in sorted(release.rglob("*"), reverse=True):
                if path.is_dir():
                    path.chmod(0o755)
            release.chmod(0o755)

    def test_old_releases_are_pruned_after_activation_but_never_the_rollback_path(self) -> None:
        """B156: ten stay by default; the new release and the one it replaced
        always stay, whatever their age, and nothing is removed before the
        link has moved."""

        import os
        import time

        with tempfile.TemporaryDirectory() as raw:
            work = Path(raw).resolve()
            wheel, digest = self.make_wheel(work)
            target = work / "target"
            releases = target / "releases"
            releases.mkdir(parents=True)
            #
            # Six frozen-looking old releases, oldest first, the oldest of
            # them being the one `current` points at.
            #
            for index in range(6):
                old = releases / f"0.0.{index}-old"
                (old / "lib").mkdir(parents=True)
                (old / "lib" / "x").write_text("x")
                (old / "lib").chmod(0o555)
                old.chmod(0o555)
                os.utime(old, (1_000_000 + index, 1_000_000 + index))
            (target / "current").symlink_to(Path("releases") / "0.0.0-old")
            time.sleep(0.01)

            release_id = install_release_module.install_release(
                wheel=wheel,
                expected_sha256=digest,
                target=target,
                python=Path(sys.executable),
                require_root=False,
                keep=3,
            )
            left = sorted(p.name for p in releases.iterdir())
            # The newest three by time are the new release and the two newest
            # old ones; the predecessor 0.0.0-old stays although it is oldest.
            self.assertEqual(left, ["0.0.0-old", "0.0.4-old", "0.0.5-old", release_id])
            self.assertEqual((target / "current").readlink(), Path("releases") / release_id)

            with self.assertRaises(install_release_module.InstallError):
                install_release_module.install_release(
                    wheel=wheel,
                    expected_sha256=digest,
                    target=target,
                    python=Path(sys.executable),
                    require_root=False,
                    keep=1,
                )
            for path in sorted(releases.rglob("*"), reverse=True):
                if path.is_dir():
                    path.chmod(0o755)
            for path in releases.iterdir():
                path.chmod(0o755)

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

    def test_a_wheel_without_engine_metadata_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            work = Path(raw).resolve()
            wheel, _ = self.make_wheel(work)
            with zipfile.ZipFile(wheel, "r") as source:
                members = {
                    item.filename: source.read(item)
                    for item in source.infolist()
                    if item.filename != "haprion/compatibility.json"
                }
            wheel.unlink()
            with zipfile.ZipFile(wheel, "w") as target:
                for name, content in members.items():
                    target.writestr(name, content)
            digest = hashlib.sha256(wheel.read_bytes()).hexdigest()

            with self.assertRaisesRegex(
                install_release_module.InstallError, "no engine compatibility metadata"
            ):
                install_release_module.install_release(
                    wheel=wheel,
                    expected_sha256=digest,
                    target=work / "target",
                    python=Path(sys.executable),
                    require_root=False,
                )
            self.assertFalse((work / "target").exists())

    def test_a_runtime_without_pynacl_is_refused_by_name(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            # A stand-in interpreter that has PyYAML's answer but no PyNaCl.
            fake = Path(raw) / "python3"
            fake.write_text('#!/bin/sh\necho \'{"python": "3.13.0", "pyyaml": "6.0.0"}\'\n')
            fake.chmod(0o755)
            with self.assertRaisesRegex(install_release_module.InstallError, "PyNaCl"):
                install_release_module.inspect_runtime(fake)

    def test_a_runtime_without_psycopg_is_refused_by_name(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fake = Path(raw) / "python3"
            fake.write_text(
                '#!/bin/sh\necho \'{"python": "3.13.0", "pyyaml": "6.0.0", "pynacl": "1.6.2"}\'\n'
            )
            fake.chmod(0o755)
            with self.assertRaisesRegex(install_release_module.InstallError, "psycopg"):
                install_release_module.inspect_runtime(fake)

    def test_a_runtime_below_the_floor_is_refused(self) -> None:
        # 3.13 is the floor (B303): the lowest a supported distribution ships.
        with tempfile.TemporaryDirectory() as raw:
            fake = Path(raw) / "python3"
            fake.write_text(
                '#!/bin/sh\necho \'{"python": "3.12.9", "pyyaml": "6.0.0",'
                ' "pynacl": "1.6.2", "psycopg": "3.2.0"}\'\n'
            )
            fake.chmod(0o755)
            with self.assertRaisesRegex(install_release_module.InstallError, "3.13 or newer"):
                install_release_module.inspect_runtime(fake)


if __name__ == "__main__":
    unittest.main()
