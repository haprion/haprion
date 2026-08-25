"""Writing a release where the nodes can fetch it.

Ownership is the point of most of these cases: the published tree is the one
place where getting permissions wrong breaks deployment silently, and it has
done so before.
"""

from __future__ import annotations

import grp
import os
import tempfile
import unittest
from pathlib import Path

from haproxy_mgmt.release_install import (
    DIRECTORY_MODE,
    FILE_MODE,
    PUBLISH_GROUP,
    InstallError,
    install_release,
)
from haproxy_mgmt.release_layout import ReleaseMetadata

ARTIFACT = {
    "haproxy.cfg": b"global\n  daemon\n",
    "conf.d/10-stats.cfg": b"frontend stats\n  bind 192.0.2.10:8404\n",
    "maps/hosts.map": b"host.example.com backend_a\n",
}
COMMIT = "a" * 40
NODE_PATH = "alpha-node"


def metadata(version: int = 7, commit: str = COMMIT) -> ReleaseMetadata:
    return ReleaseMetadata(
        cluster="alpha", version=version, commit=commit, timestamp="2026-08-25T20:00:00Z"
    )


class Recorder:
    """Stands in for chown so ownership can be asserted without being root."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, int, int]] = []

    def __call__(self, path: Path, uid: int, gid: int) -> None:
        self.calls.append((str(path), uid, gid))


class InstallFixture(unittest.TestCase):
    """Shared helper only. Kept free of test methods so the classes below do not
    inherit and re-run each other's cases."""

    def install(self, publish: Path, recorder: Recorder, **overrides: object):
        arguments: dict[str, object] = {
            "node_path": NODE_PATH,
            "artifact": ARTIFACT,
            "metadata": metadata(),
            "group": grp.getgrgid(os.getgid()).gr_name,
            "change_owner": recorder,
        }
        arguments.update(overrides)
        return install_release(publish, **arguments)  # type: ignore[arg-type]


class InstallTests(InstallFixture):
    def test_the_artifact_lands_where_the_node_pulls(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            publish = Path(raw) / "alpha"
            result = self.install(publish, Recorder())
            root = publish / "releases" / COMMIT / NODE_PATH
            self.assertTrue(result.created)
            for relative, content in ARTIFACT.items():
                self.assertEqual((root / relative).read_bytes(), content)

    def test_release_metadata_is_written_at_the_pulled_level(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            publish = Path(raw) / "alpha"
            self.install(publish, Recorder())
            stamp = publish / "releases" / COMMIT / NODE_PATH / "RELEASE"
            self.assertIn(b"version=7", stamp.read_bytes())
            self.assertIn(b"hash=" + COMMIT.encode(), stamp.read_bytes())

    def test_current_points_at_the_release_relatively(self) -> None:
        """A relative link survives the tree being moved or mirrored."""
        with tempfile.TemporaryDirectory() as raw:
            publish = Path(raw) / "alpha"
            self.install(publish, Recorder())
            current = publish / "current"
            self.assertTrue(current.is_symlink())
            self.assertEqual(os.readlink(current), f"releases/{COMMIT}")

    def test_everything_written_is_owned_by_the_publish_group(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            publish = Path(raw) / "alpha"
            recorder = Recorder()
            self.install(publish, recorder)
            gid = os.getgid()
            self.assertTrue(recorder.calls)
            for path, uid, applied in recorder.calls:
                self.assertEqual(uid, 0, f"{path} was not given to root")
                self.assertEqual(applied, gid, f"{path} was not given to the publish group")
            recorded = {path for path, _, _ in recorder.calls}
            self.assertIn(str(publish), recorded)
            self.assertIn(str(publish / "releases"), recorded)
            self.assertIn(str(publish / "current.new"), recorded)

    def test_modes_follow_the_published_tree_model(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            publish = Path(raw) / "alpha"
            self.install(publish, Recorder())
            release = publish / "releases" / COMMIT
            self.assertEqual(release.stat().st_mode & 0o777, DIRECTORY_MODE)
            for path in release.rglob("*"):
                expected = DIRECTORY_MODE if path.is_dir() else FILE_MODE
                self.assertEqual(path.stat().st_mode & 0o777, expected, str(path))

    def test_no_partial_release_is_left_behind_on_failure(self) -> None:
        """A node must never observe a half written release."""
        with tempfile.TemporaryDirectory() as raw:
            publish = Path(raw) / "alpha"

            def explode(path: Path, uid: int, gid: int) -> None:
                if path.name == "haproxy.cfg":
                    raise OSError("disk full")

            with self.assertRaises(OSError):
                self.install(publish, Recorder(), change_owner=explode)
            releases = publish / "releases"
            self.assertEqual(sorted(entry.name for entry in releases.iterdir()), [])


class ImmutabilityTests(InstallFixture):
    def test_republishing_the_same_commit_reuses_the_release(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            publish = Path(raw) / "alpha"
            self.install(publish, Recorder())
            again = self.install(publish, Recorder())
            self.assertFalse(again.created)
            self.assertTrue(again.already_current)

    def test_a_release_whose_metadata_disagrees_is_refused(self) -> None:
        """The tree holds something other than what its name claims."""
        with tempfile.TemporaryDirectory() as raw:
            publish = Path(raw) / "alpha"
            self.install(publish, Recorder())
            with self.assertRaises(InstallError) as caught:
                self.install(publish, Recorder(), metadata=metadata(version=9))
            self.assertIn("incorrect metadata", str(caught.exception))

    def test_an_existing_release_is_never_rewritten(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            publish = Path(raw) / "alpha"
            self.install(publish, Recorder())
            target = publish / "releases" / COMMIT / NODE_PATH / "haproxy.cfg"
            before = target.stat().st_mtime_ns
            self.install(publish, Recorder())
            self.assertEqual(target.stat().st_mtime_ns, before)


class CurrentLinkTests(InstallFixture):
    def test_a_new_release_moves_the_link(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            publish = Path(raw) / "alpha"
            self.install(publish, Recorder())
            second = "b" * 40
            result = self.install(publish, Recorder(), metadata=metadata(version=8, commit=second))
            self.assertTrue(result.created)
            self.assertFalse(result.already_current)
            self.assertEqual(os.readlink(publish / "current"), f"releases/{second}")

    def test_the_previous_release_stays_on_disk(self) -> None:
        """Releases are immutable; moving the link is not a deletion."""
        with tempfile.TemporaryDirectory() as raw:
            publish = Path(raw) / "alpha"
            self.install(publish, Recorder())
            self.install(publish, Recorder(), metadata=metadata(version=8, commit="b" * 40))
            self.assertTrue((publish / "releases" / COMMIT).is_dir())

    def test_no_staging_link_survives(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            publish = Path(raw) / "alpha"
            self.install(publish, Recorder())
            self.assertFalse((publish / "current.new").exists())


class GroupTests(unittest.TestCase):
    def test_the_publish_group_is_the_one_the_nodes_use(self) -> None:
        """Guards the constant against drifting from the shell copies."""
        self.assertEqual(PUBLISH_GROUP, "haproxy-pull")

    def test_a_missing_group_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            with self.assertRaises(InstallError) as caught:
                install_release(
                    Path(raw) / "alpha",
                    node_path=NODE_PATH,
                    artifact=ARTIFACT,
                    metadata=metadata(),
                    group="no-such-group-exists-here",
                    change_owner=Recorder(),
                )
            self.assertEqual(caught.exception.exit_code, 78)


if __name__ == "__main__":
    unittest.main()
