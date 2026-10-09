"""The node release is minimal, reproducible and verified before extraction."""

from __future__ import annotations

import gzip
import io
import os
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from haproxy_mgmt import node_bundle

BASE = Path(__file__).resolve().parents[1]


TOOL = node_bundle


def read_member(archive: tarfile.TarFile, member: tarfile.TarInfo) -> bytes:
    """A member's bytes; a directory or link carries none."""

    extracted = archive.extractfile(member)
    return b"" if extracted is None else extracted.read()


class NodeBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        for relative in TOOL.PAYLOAD:
            path = self.source / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"payload:{relative}\n")
            path.chmod(TOOL.payload_mode(relative))
        subprocess.run(["/usr/bin/git", "init", "-q", str(self.source)], check=True)
        subprocess.run(["/usr/bin/git", "-C", str(self.source), "add", "."], check=True)
        self.commit_source("payload")
        self.commit = subprocess.run(
            ["/usr/bin/git", "-C", str(self.source), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        self.bundle = self.root / "node.tar.gz"

    def commit_source(self, message: str) -> None:
        subprocess.run(
            ["/usr/bin/git", "-C", str(self.source), "commit", "-q", "-m", message],
            check=True,
            env={
                **os.environ,
                "GIT_AUTHOR_NAME": "Node bundle test",
                "GIT_AUTHOR_EMAIL": "node-bundle@example.invalid",
                "GIT_COMMITTER_NAME": "Node bundle test",
                "GIT_COMMITTER_EMAIL": "node-bundle@example.invalid",
            },
        )

    def build(self) -> tuple[str, str]:
        return TOOL.build_bundle(self.source, self.bundle)

    def test_bundle_contains_only_the_manifest_and_node_installation_payload(self) -> None:
        release, digest = self.build()

        verified, manifest = TOOL.verify_bundle(self.bundle, digest)
        self.assertEqual(verified, release)
        self.assertEqual(manifest["commit"], self.commit)
        with tarfile.open(self.bundle, "r:gz") as archive:
            names = {item.name for item in archive.getmembers()}
        self.assertEqual(
            names,
            {f"{release}/MANIFEST.json", *(f"{release}/{name}" for name in TOOL.PAYLOAD)},
        )
        self.assertFalse(any("platform" in name or "__pycache__" in name for name in names))

    def test_two_builds_of_the_same_commit_are_byte_identical(self) -> None:
        _, first = self.build()
        second_path = self.root / "second.tar.gz"
        _, second = TOOL.build_bundle(self.source, second_path)

        self.assertEqual(first, second)
        self.assertEqual(self.bundle.read_bytes(), second_path.read_bytes())

    def test_wrong_external_digest_is_refused(self) -> None:
        self.build()

        with self.assertRaisesRegex(TOOL.BundleError, "does not match"):
            TOOL.verify_bundle(self.bundle, "0" * 64)

    def test_oversized_bundle_is_refused_before_archive_parsing(self) -> None:
        self.bundle.write_bytes(b"x" * (TOOL.MAX_BUNDLE_BYTES + 1))

        with self.assertRaisesRegex(TOOL.BundleError, "size limit"):
            TOOL.verify_bundle(self.bundle)

    def test_changed_payload_is_refused_by_the_internal_manifest(self) -> None:
        release, _ = self.build()
        changed = self.root / "changed.tar.gz"
        with tarfile.open(self.bundle, "r:gz") as source:
            held = [(item, read_member(source, item)) for item in source.getmembers()]
        with (
            changed.open("wb") as raw,
            gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed,
            tarfile.open(fileobj=compressed, mode="w") as target,
        ):
            for item, data in held:
                if item.name == f"{release}/install/node/haproxy-node-status":
                    data += b"changed\n"
                    item.size = len(data)
                target.addfile(item, io.BytesIO(data))

        with self.assertRaisesRegex(TOOL.BundleError, "digest mismatch"):
            TOOL.verify_bundle(changed)

    def test_path_traversal_and_symlinks_are_refused(self) -> None:
        for name, kind in (("../escape", "file"), ("release/link", "symlink")):
            with self.subTest(name=name):
                archive_path = self.root / f"unsafe-{kind}.tar.gz"
                with tarfile.open(archive_path, "w:gz") as archive:
                    item = tarfile.TarInfo(name)
                    if kind == "symlink":
                        item.type = tarfile.SYMTYPE
                        item.linkname = "/etc/passwd"
                        archive.addfile(item)
                    else:
                        item.size = 1
                        archive.addfile(item, io.BytesIO(b"x"))
                with self.assertRaises(TOOL.BundleError):
                    TOOL.verify_bundle(archive_path)

    def test_builder_refuses_a_symlinked_payload(self) -> None:
        payload = self.source / TOOL.PAYLOAD[-1]
        payload.unlink()
        payload.symlink_to("/etc/passwd")
        subprocess.run(["/usr/bin/git", "-C", str(self.source), "add", "."], check=True)
        self.commit_source("symlink")

        with self.assertRaisesRegex(TOOL.BundleError, "Git mode 120000"):
            self.build()

    def test_a_release_requires_a_clean_commit(self) -> None:
        with (
            patch.object(TOOL, "_git", side_effect=[self.commit, " M file"]),
            self.assertRaisesRegex(TOOL.BundleError, "uncommitted changes"),
        ):
            TOOL.source_commit(self.source)

    def test_existing_output_is_not_overwritten(self) -> None:
        self.bundle.write_bytes(b"keep")

        with self.assertRaisesRegex(TOOL.BundleError, "already exists"):
            self.build()
        self.assertEqual(self.bundle.read_bytes(), b"keep")


class NodeBundleTransportContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.script = (BASE / "tools" / "install-node-bundle").read_text()

    def test_one_shared_ssh_session_carries_the_install(self) -> None:
        self.assertIn("ControlMaster=auto", self.script)
        self.assertIn("ControlPersist=180", self.script)
        self.assertIn("ControlPath=${control_dir}/%r@%h", self.script)

    def test_the_artifact_is_verified_before_any_remote_staging(self) -> None:
        verify = self.script.index('verify --bundle "$bundle" --sha256 "$expected_sha"')
        staging = self.script.index("mktemp -d /tmp/haproxy-node-bundle")
        self.assertLess(verify, staging)

    def test_state_is_backed_up_on_both_sides_of_the_remote_install(self) -> None:
        before, after = [
            index
            for index, line in enumerate(self.script.splitlines())
            if line.strip() == 'sudo "$STATE_BACKUP" -c "$cluster"'
        ]
        install = self.script.splitlines().index(
            'ssh -tt "${ssh_opts[@]}" "$node" "$remote_install"'
        )
        self.assertLess(before, install)
        self.assertGreater(after, install)
        self.assertIn('sudo test -x "$STATE_BACKUP"', self.script)
        # The engine's own command, scoped to the cluster the bundle goes to:
        # the other cluster is neither written nor archived.
        self.assertIn("STATE_BACKUP=/opt/haprion/current/bin/haproxy-state-backup", self.script)
        self.assertNotIn("/usr/local/sbin", self.script)

    def test_staging_has_a_narrow_shape_and_is_deleted(self) -> None:
        self.assertIn("^/tmp/haproxy-node-bundle\\.[A-Za-z0-9]+$", self.script)
        self.assertIn("find '$remote_dir' -depth -delete", self.script)

    def test_dry_run_stops_before_backups_and_staging(self) -> None:
        dry_run = self.script.index('if [[ "$dry_run" == "yes" ]]')
        backup = self.script.index('sudo "$STATE_BACKUP" -c "$cluster"')
        staging = self.script.index("mktemp -d /tmp/haproxy-node-bundle")
        self.assertLess(dry_run, backup)
        self.assertLess(dry_run, staging)

    def test_a_package_is_verified_and_its_architecture_checked_before_any_write(self) -> None:
        verify = self.script.index("sha256sum -c --quiet -")
        arch = self.script.index("the package is built for")
        dry_run = self.script.index('if [[ "$dry_run" == "yes" ]]')
        backup = self.script.index('sudo "$STATE_BACKUP" -c "$cluster"')
        # The architecture check is in the preflight, which a dry run also runs.
        self.assertLess(verify, dry_run)
        self.assertLess(arch, dry_run)
        self.assertLess(dry_run, backup)
        self.assertIn("^haproxy-manager-[a-z0-9-]+$", self.script)

    def test_the_package_is_checked_again_on_the_node_and_installed_with_the_bundle(self) -> None:
        self.assertIn(
            "printf '%s  %s\\\\n' '$package_sha' package.deb | sha256sum -c -", self.script
        )
        self.assertLess(
            self.script.index("${package_install}"),
            self.script.index("sudo ./04-node-prepare"),
        )


if __name__ == "__main__":
    unittest.main()
