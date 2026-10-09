"""The web interface package: built where it runs, carried as an archive (B266)."""

from __future__ import annotations

import importlib.util
import sys
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
            TOOL.depends("3.14").split(", ")[:2], ["python3 (>= 3.14)", "python3 (<< 3.15)"]
        )
        self.assertEqual(TOOL.DISTRIBUTIONS["ubuntu26.04"].python, "3.14")
        self.assertEqual(TOOL.DISTRIBUTIONS["debian13"].python, "3.13")
        self.assertIn("haprion-cli", TOOL.depends("3.13"))

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

    def test_the_migration_bundle_travels_with_the_release(self) -> None:
        self.assertIn('cp /src/ui/alembic.ini "$R/migration/alembic.ini"', TOOL.BUILD)


class TheTree(unittest.TestCase):
    def test_the_package_carries_the_archive_its_digest_and_the_image(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            work = Path(raw)
            archive = work / "release.tar"
            archive.write_bytes(b"release")
            root = work / "root"

            TOOL.assemble(
                root,
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
            self.assertIn('tar -xf "/usr/lib/haprion/ui/$RELEASE_ARCHIVE" -C /', postinst)
            # An installed release is never unpacked over.
            self.assertIn('if [ ! -d "$release" ]; then', postinst)


if __name__ == "__main__":
    unittest.main()
