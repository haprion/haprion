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
from typing import Any
from unittest import mock

from haprion.release_install import (
    DIRECTORY_MODE,
    FILE_MODE,
    PUBLISH_GROUP,
    InstallError,
    InstallResult,
    install_release,
    prune_releases,
)
from haprion.release_layout import NODE_DIRECTORIES, ReleaseMetadata

ARTIFACT = {
    "haproxy.cfg": b"global\n  daemon\n",
    "conf.d/0010-stats.cfg": b"frontend stats\n  bind 192.0.2.10:8404\n",
    "maps/hosts.map": b"host.example.com backend_a\n",
}
COMMIT = "a" * 40
NODE_PATH = "alpha-node"


def metadata(
    version: int = 7, commit: str = COMMIT, timestamp: str = "2026-08-25T20:00:00Z"
) -> ReleaseMetadata:
    return ReleaseMetadata(cluster="alpha", version=version, commit=commit, timestamp=timestamp)


class Recorder:
    """Stands in for chown so ownership can be asserted without being root."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, int, int]] = []

    def __call__(self, path: Path, uid: int, gid: int) -> None:
        self.calls.append((str(path), uid, gid))


def release_directories(publish: Path, names: list[str], *, newest_last: bool = True) -> None:
    """Releases under `releases/`, each a minute newer than the one before it."""

    for offset, name in enumerate(names):
        directory = publish / "releases" / name
        directory.mkdir(parents=True)
        (directory / "RELEASE").write_text("schema=1\n")
        stamp = 1_000_000 + 60 * (offset if newest_last else -offset)
        os.utime(directory, (stamp, stamp))


class PruningTheManagersReleases(unittest.TestCase):
    """Review 26-10-30, D5: every publish added a full copy and nothing took one away."""

    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.publish = Path(directory.name) / "published"
        self.names = [f"{index:040x}" for index in range(1, 12)]
        release_directories(self.publish, self.names)

    def remaining(self) -> set[str]:
        return {entry.name for entry in (self.publish / "releases").iterdir()}

    def test_eleven_releases_leave_the_newest_ten(self) -> None:
        removed = prune_releases(self.publish, running=set())

        self.assertEqual(removed, [self.names[0]])
        self.assertEqual(self.remaining(), set(self.names[1:]))

    def test_the_release_current_names_stays(self) -> None:
        (self.publish / "current").symlink_to(Path("releases") / self.names[0])

        self.assertEqual(prune_releases(self.publish, running=set()), [])
        self.assertEqual(self.remaining(), set(self.names))

    def test_a_release_a_node_reports_stays(self) -> None:
        self.assertEqual(prune_releases(self.publish, running={self.names[0]}), [])
        self.assertEqual(self.remaining(), set(self.names))

    def test_without_a_reading_of_the_nodes_every_release_stays(self) -> None:
        self.assertEqual(prune_releases(self.publish, running=None), [])
        self.assertEqual(self.remaining(), set(self.names))

    def test_a_stage_older_than_an_hour_goes_whatever_the_nodes_say(self) -> None:
        old = self.publish / "releases" / f".{'a' * 40}.x1"
        fresh = self.publish / "releases" / f".{'b' * 40}.x2"
        for stage, stamp in ((old, 1_000_000), (fresh, 1_000_000 + 3000)):
            stage.mkdir()
            os.utime(stage, (stamp, stamp))

        removed = prune_releases(self.publish, running=None, now=1_000_000 + 3700)

        self.assertEqual(removed, [old.name])
        self.assertFalse(old.exists())
        self.assertTrue(fresh.exists())

    def test_fewer_than_ten_are_left_alone(self) -> None:
        for name in self.names[:5]:
            for path in sorted((self.publish / "releases" / name).rglob("*"), reverse=True):
                path.unlink()
            (self.publish / "releases" / name).rmdir()

        self.assertEqual(prune_releases(self.publish, running=set()), [])


class EmptyDirectoryTests(unittest.TestCase):
    """A cluster with no map files still ships an empty maps/.

    Measured against the shell path on 2026-08-26: it creates conf.d and maps
    with `mkdir -p` before merging, so external - which has no map files - has
    always shipped an empty maps/. The step 1 parity check compared files and
    could not see it.
    """

    def test_the_node_directories_exist_even_when_nothing_lands_in_them(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            publish = Path(raw) / "published"
            recorder = Recorder()
            result = install_release(
                publish,
                node_path=NODE_PATH,
                artifact={"haproxy.cfg": b"global\n  daemon\n"},
                index={},
                metadata=metadata(),
                group=grp.getgrgid(os.getgid()).gr_name,
                change_owner=recorder,
            )
            node_root = result.release / NODE_PATH
            for directory in NODE_DIRECTORIES:
                self.assertTrue((node_root / directory).is_dir(), directory)
                self.assertEqual((node_root / directory).stat().st_mode & 0o777, DIRECTORY_MODE)
            #
            # Ownership is applied while the release is still staged, so the
            # recorded path ends with the node-relative one.
            #
            owned = [call[0] for call in recorder.calls if call[0].endswith(f"{NODE_PATH}/maps")]
            self.assertEqual(
                [(0, os.getgid())], [call[1:] for call in recorder.calls if call[0] in owned]
            )


class TheReleaseIsOnDiskBeforeItIsVisible(unittest.TestCase):
    """Review 26-10-24, 01-05: after a power cut the files could come back empty."""

    def test_every_file_is_synced_before_the_rename(self) -> None:
        synced: list[int] = []
        real = os.fsync

        def fsync(descriptor: int) -> None:
            synced.append(descriptor)
            real(descriptor)

        with tempfile.TemporaryDirectory() as raw, mock.patch("os.fsync", side_effect=fsync):
            result = install_release(
                Path(raw) / "published",
                node_path=NODE_PATH,
                artifact={"haproxy.cfg": b"global\n", "conf.d/0010-core.cfg": b"defaults\n"},
                index={"index.json": b"{}"},
                metadata=metadata(),
                group=grp.getgrgid(os.getgid()).gr_name,
                change_owner=Recorder(),
            )
            files = [path for path in result.release.rglob("*") if path.is_file()]
            directories = [path for path in result.release.rglob("*") if path.is_dir()]
        # Each file, and each directory and the release itself, at least once.
        self.assertGreaterEqual(len(synced), len(files) + len(directories) + 1)


class InstallFixture(unittest.TestCase):
    """Shared helper only. Kept free of test methods so the classes below do not
    inherit and re-run each other's cases."""

    def install(self, publish: Path, recorder: Recorder, **overrides: object) -> InstallResult:
        arguments: dict[str, Any] = {
            "node_path": NODE_PATH,
            "artifact": ARTIFACT,
            "index": {},
            "metadata": metadata(),
            "group": grp.getgrgid(os.getgid()).gr_name,
            "change_owner": recorder,
        }
        arguments.update(overrides)
        return install_release(publish, **arguments)


class WhatTheReleaseKeepsAndTheNodeNeverSees(InstallFixture):
    """The manager's own index of a release, one level above the node's view.

    The nodes fetch `node_path` whole, with `--delete`, and everything under it
    that ends in `.cfg` is loaded by HAProxy. A file the manager keeps about a
    release therefore cannot live there - not because it would be read, but
    because it would be one careless glob or one rsync away from being read or
    removed.
    """

    def test_the_index_lands_beside_the_level_the_node_pulls(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            publish = Path(raw) / "alpha"
            result = self.install(publish, Recorder(), index={"MANIFEST.json": b'{"schema": 1}\n'})
            self.assertEqual((result.release / "MANIFEST.json").read_bytes(), b'{"schema": 1}\n')
            self.assertFalse((result.release / NODE_PATH / "MANIFEST.json").exists())

    def test_a_release_from_a_tree_without_one_carries_none(self) -> None:
        """Every release published before the manifest existed looks like this."""

        with tempfile.TemporaryDirectory() as raw:
            result = self.install(Path(raw) / "alpha", Recorder(), index={})
            self.assertFalse((result.release / "MANIFEST.json").exists())

    def test_the_index_is_owned_like_the_rest_of_the_release(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            recorder = Recorder()
            result = self.install(Path(raw) / "alpha", recorder, index={"MANIFEST.json": b"{}\n"})
            manifest = result.release / "MANIFEST.json"
            self.assertEqual(manifest.stat().st_mode & 0o777, FILE_MODE)


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

    def test_a_second_write_of_the_same_commit_may_carry_a_later_timestamp(self) -> None:
        """The case a repair after a crash has to be able to reach.

        A run interrupted between the commit and the install is finished by
        installing the same commit again, and the second attempt takes its
        timestamp from its own clock. Comparing the whole stamp made that an
        error, so the only interrupted publish the system could handle was one
        it refused to finish.
        """

        with tempfile.TemporaryDirectory() as raw:
            publish = Path(raw) / "alpha"
            self.install(publish, Recorder())
            again = self.install(
                publish, Recorder(), metadata=metadata(timestamp="2026-08-25T21:30:00Z")
            )

            self.assertFalse(again.created)
            self.assertTrue(again.already_current)
            #
            # And the stamp on disk is the original one. The release is written
            # once; a repair confirms it rather than restating it.
            #
            stamp = (publish / "releases" / COMMIT / NODE_PATH / "RELEASE").read_text()
            self.assertIn("timestamp=2026-08-25T20:00:00Z", stamp)

    def test_a_release_whose_commit_disagrees_is_still_refused(self) -> None:
        """Tolerating the timestamp must not tolerate the identity."""

        with tempfile.TemporaryDirectory() as raw:
            publish = Path(raw) / "alpha"
            self.install(publish, Recorder())
            stamp = publish / "releases" / COMMIT / NODE_PATH / "RELEASE"
            stamp.write_text(stamp.read_text().replace(f"hash={COMMIT}", "hash=" + "b" * 40))

            with self.assertRaises(InstallError) as caught:
                self.install(publish, Recorder())
            self.assertIn("hash", str(caught.exception))

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

    def test_the_tree_links_to_itself_so_a_node_s_path_holds_under_its_narrow_root(self) -> None:
        """A node asks for `<cluster>/current/`; its key reads this tree alone (B358)."""

        with tempfile.TemporaryDirectory() as raw:
            publish = Path(raw) / "alpha"
            recorder = Recorder()
            self.install(publish, recorder)
            link = publish / "alpha"
            self.assertEqual(os.readlink(link), ".")
            self.assertEqual((link / "current").resolve(), (publish / "current").resolve())
            self.assertIn((str(publish / "alpha.new"), 0, os.getgid()), recorder.calls)
            self.assertFalse((publish / "alpha.new").exists())

            again = Recorder()
            self.install(publish, again, metadata=metadata(version=8, commit="b" * 40))
            self.assertNotIn(str(publish / "alpha.new"), [call[0] for call in again.calls])

    def test_something_else_where_the_link_goes_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            publish = Path(raw) / "alpha"
            (publish / "alpha").mkdir(parents=True)
            with self.assertRaisesRegex(InstallError, "not the cluster's link to itself"):
                self.install(publish, Recorder())

    def test_no_staging_link_survives(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            publish = Path(raw) / "alpha"
            self.install(publish, Recorder())
            self.assertFalse((publish / "current.new").exists())


class GroupTests(unittest.TestCase):
    def test_the_publish_group_is_the_one_the_nodes_use(self) -> None:
        """Guards the constant against drifting from the shell copies."""
        self.assertEqual(PUBLISH_GROUP, "_haprion-pull")

    def test_a_missing_group_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            with self.assertRaises(InstallError) as caught:
                install_release(
                    Path(raw) / "alpha",
                    node_path=NODE_PATH,
                    artifact=ARTIFACT,
                    index={},
                    metadata=metadata(),
                    group="no-such-group-exists-here",
                    change_owner=Recorder(),
                )
            self.assertEqual(caught.exception.exit_code, 78)


if __name__ == "__main__":
    unittest.main()
