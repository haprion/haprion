"""The web interface package: built where it runs, carried as an archive (B266)."""

from __future__ import annotations

import importlib.util
import os
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
        "build_ui_package", BASE / "tools/build-ui-package.py"
    )
    assert spec is not None and spec.loader is not None  # noqa: S101 - local tool must exist
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


TOOL = tool()


class Distributions(unittest.TestCase):
    def test_each_package_takes_only_the_python_its_venv_was_built_for(self) -> None:
        self.assertEqual(
            TOOL.depends("3.14", 1).split(", ")[:2], ["python3 (>= 3.14)", "python3 (<< 3.15)"]
        )
        self.assertEqual(TOOL.DISTRIBUTIONS["ubuntu26.04"].python, "3.14")
        self.assertEqual(TOOL.DISTRIBUTIONS["debian13"].python, "3.13")
        self.assertIn("haprion-cli", TOOL.depends("3.13", 1))

    def test_it_needs_an_engine_at_the_level_the_release_requires(self) -> None:
        """Review 2026-10-22, 6-4: a CLI downgrade changed the engine under the interface unseen."""

        self.assertIn("haprion-engine (>= 31)", TOOL.depends("3.13", 31).split(", "))
        commit = TOOL._git(BASE, "rev-parse", "HEAD").decode().strip()
        self.assertGreaterEqual(TOOL.required_engine_api(BASE, commit), 1)

    def test_the_versions_sort_apart_per_distribution(self) -> None:
        self.assertEqual(
            {d.suffix for d in TOOL.DISTRIBUTIONS.values()}, {"~ubuntu26.04", "~deb13"}
        )


class TheBuild(unittest.TestCase):
    """What makes the release the same bytes twice, and runnable where it lands."""

    def test_it_is_built_at_its_final_path_against_the_system_python(self) -> None:
        self.assertIn('R="/opt/haprion-ui/releases/$RELEASE_ID"', TOOL.BUILD)
        self.assertIn("--python /usr/bin/python3 --python-preference only-system", TOOL.BUILD)
        self.assertIn("--locked --no-dev --no-editable", TOOL.BUILD)

    def test_what_varies_between_builds_is_left_out(self) -> None:
        build = TOOL.BUILD
        # Our two distributions from reproducible wheels, not from source trees.
        self.assertIn("--no-install-project --no-install-package haprion", build)
        self.assertIn("uv_cache.json", build)
        self.assertIn("-name __pycache__ -prune -exec rm -rf {} +", build)
        # The import proof writes no bytecode after the cleanup.
        self.assertIn('venv/bin/python" -B -c', build)
        self.assertIn('--sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0', build)
        # Modes set, not taken from the cache the operator's umask made.
        self.assertIn("--mode=u+rw,go=rX", build)

    def test_the_archive_modes_are_set_whatever_the_files_came_with(self) -> None:
        # What the uv cache and uv itself leave: 0664 under umask 002, 0666 locks.
        given = {"cached.py": 0o664, ".lock": 0o666, "private": 0o600, "tool": 0o775}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "tree").mkdir(mode=0o700)
            for name, mode in given.items():
                (root / "tree" / name).write_text("")
                os.chmod(root / "tree" / name, mode)
            subprocess.run(  # noqa: S603 - fixed arguments
                ["/usr/bin/tar", "--mode=u+rw,go=rX", "-cf", str(root / "a.tar"),
                 "-C", str(root), "tree"],
                check=True,
            )  # fmt: skip
            with tarfile.open(root / "a.tar") as archive:
                modes = {member.name: member.mode for member in archive.getmembers()}
        self.assertEqual(
            modes,
            {"tree": 0o755, "tree/cached.py": 0o644, "tree/.lock": 0o644,
             "tree/private": 0o644, "tree/tool": 0o755},
        )  # fmt: skip

    def test_the_migration_bundle_travels_with_the_release(self) -> None:
        self.assertIn('cp /src/ui/alembic.ini "$R/migration/alembic.ini"', TOOL.BUILD)

    def test_the_migration_tool_is_locked_and_kept_out_of_the_services_venv(self) -> None:
        build = TOOL.BUILD
        self.assertIn("--locked --only-group migrate", build)
        self.assertIn('--target "$R/migration/lib" --require-hashes', build)
        self.assertIn('PYTHONPATH="$R/migration/lib"', build)


class TheTree(unittest.TestCase):
    def test_the_package_carries_the_archive_its_digest_and_the_image(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            work = Path(raw)
            archive = work / "release.tar"
            archive.write_bytes(b"release")
            root = work / "root"
            tree = work / "src"
            moved = [entry for entry, _ in TOOL.MOVED]
            for relative, *_ in [(e, None) for e in (*TOOL.SHARED, *TOOL.TOOLS, *moved)]:
                path = tree / relative
                if relative.endswith("/"):
                    path.mkdir(parents=True)
                    (path / "file").write_text(relative)
                else:
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(relative)
            for command in TOOL.COMMANDS:
                (tree / f"install/platform/bin/haprion-{command}").parent.mkdir(
                    parents=True, exist_ok=True
                )
                (tree / f"install/platform/bin/haprion-{command}").write_text(command)

            TOOL.assemble(
                root,
                tree=tree,
                archive=archive,
                release_id="0.1.0-0123456789ab",
                licence=b"licence\n",
                commit="0" * 40,
                image="docker.io/library/debian:13",
                digest="sha256:" + "1" * 64,
            )

            lib = root / "usr/lib/haprion/ui"
            self.assertEqual((lib / "release-0.1.0-0123456789ab.tar").read_bytes(), b"release")
            payload = (lib / "PAYLOAD").read_text()
            self.assertIn("RELEASE_ID=0.1.0-0123456789ab\n", payload)
            self.assertIn(f"RELEASE_SHA256={TOOL.sha256(archive)}\n", payload)
            self.assertIn(
                "image: docker.io/library/debian:13@sha256:" + "1" * 64,
                (root / "usr/share/doc/haprion-ui/BUILD").read_text(),
            )
            postinst = (root / "DEBIAN/postinst").read_text()
            # An installed release is never unpacked over; a new one is
            # checked against its digest, unpacked beside and moved in whole.
            self.assertIn('if [ ! -d "$release" ]; then', postinst)
            self.assertIn("sha256sum --check", postinst)
            self.assertIn(
                'mv -T "$unpack/opt/haprion-ui/releases/$RELEASE_ID" "$release"', postinst
            )
            self.assertLess(postinst.index("sha256sum"), postinst.index("tar -xf"))
            # Over a running installation the update is the whole of it (D2).
            self.assertIn(
                '/usr/share/haprion-ui/install/platform/update-platform-release "$RELEASE_ID"',
                postinst,
            )
            share = root / "usr/share/haprion-ui"
            self.assertTrue((share / "install/lib.sh").is_file())
            self.assertTrue((share / "install/platform/file").is_file())
            self.assertTrue((share / "tools/dns-profile-keys.py").is_file())
            for command in TOOL.COMMANDS:
                self.assertEqual(
                    (root / f"usr/sbin/haprion-{command}").stat().st_mode & 0o777, 0o755
                )
            # The manager is installed from the packages alone: haprion-setup
            # runs from beside its steps, which the package carries.
            setup = root / "usr/sbin/haprion-setup"
            self.assertEqual(setup.stat().st_mode & 0o777, 0o755)
            self.assertIn(
                'exec /usr/share/haprion-ui/install/haprion-setup "$@"', setup.read_text()
            )
            for step in (
                "haprion-setup",
                "01-manager-prepare",
                "02-manager-config",
                "03-manager-keys",
            ):
                self.assertTrue((share / "install" / step).is_file(), step)
            self.assertIn("sudo haprion-setup", postinst)

    def test_what_the_manager_steps_read_beside_them_is_carried(self) -> None:
        carried = {relative for relative, _ in TOOL.shared_files(BASE)}
        for needed in (
            "install/sysusers/haprion.conf",
            "install/tmpfiles/haprion.conf",
            "install/apt-keys/powerdns-dnsdist.asc",
            "install/apt-keys/haproxy-debian-net.asc",
            "install/apt-keys/haproxy-ubuntu-ppa.asc",
            "tools/dns-profile-keys.py",
            "certbot/uv.lock",
        ):
            self.assertIn(needed, carried)
        # A src/haprion in the package would pass for a source tree: the
        # tools would import the engine from it (install test, 26-10-17).
        self.assertEqual({path for path in carried if path.startswith("src/")}, set())


if __name__ == "__main__":
    unittest.main()
