"""Turning received bytes into a version, against real repositories."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from haproxy_mgmt.repo_snapshot import (
    ConcurrentUpdate,
    PublishError,
    build_candidate_tree,
    commit_and_swap,
    read_tree_files,
    resolve_head,
)

HAPROXY_CFG = b"global\n  daemon\ndefaults\n  mode http\n"
RESERVATIONS = b"reservations: []\n"
GENERATED = b"frontend managed\n  bind 192.0.2.20:80\n"


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["/usr/bin/git", "-C", str(repo), *args], capture_output=True, text=True, check=True
    ).stdout.strip()


class RepositoryFixture(unittest.TestCase):
    def repository(self, root: Path) -> Path:
        repo = root / "alpha"
        repo.mkdir()
        git(repo, "init", "-q", "-b", "main")
        git(repo, "config", "user.name", "Example Maintainer")
        git(repo, "config", "user.email", "maintainer@example.com")
        for relative, content in (
            ("core/haproxy.cfg", HAPROXY_CFG),
            ("manual/reservations.yaml", RESERVATIONS),
            ("managed/generated/40-managed.cfg", GENERATED),
        ):
            target = repo / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "Initial example configuration")
        return repo


class HeadTests(RepositoryFixture):
    def test_the_branch_and_commit_are_reported(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            repo = self.repository(Path(raw))
            branch, commit = resolve_head(repo)
            self.assertEqual(branch, "refs/heads/main")
            self.assertEqual(commit, git(repo, "rev-parse", "HEAD"))

    def test_a_detached_head_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            repo = self.repository(Path(raw))
            git(repo, "checkout", "-q", "--detach")
            with self.assertRaises(PublishError) as caught:
                resolve_head(repo)
            self.assertIn("branch", str(caught.exception))


class CandidateTreeTests(RepositoryFixture):
    def test_managed_is_carried_over_untouched(self) -> None:
        """The rule a human publish rests on: generated output is not shipped here."""
        with tempfile.TemporaryDirectory() as raw:
            repo = self.repository(Path(raw))
            _, head = resolve_head(repo)
            snapshot = build_candidate_tree(
                repo,
                head,
                {
                    "core/haproxy.cfg": HAPROXY_CFG + b"  option httplog\n",
                    "manual/reservations.yaml": RESERVATIONS,
                },
            )
            files = read_tree_files(repo, snapshot.tree)
            self.assertEqual(files["managed/generated/40-managed.cfg"], GENERATED)
            self.assertIn(b"httplog", files["core/haproxy.cfg"])

    def test_an_unchanged_candidate_is_reported_as_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            repo = self.repository(Path(raw))
            _, head = resolve_head(repo)
            snapshot = build_candidate_tree(
                repo,
                head,
                {"core/haproxy.cfg": HAPROXY_CFG, "manual/reservations.yaml": RESERVATIONS},
            )
            self.assertTrue(snapshot.unchanged)

    def test_a_deleted_file_does_not_survive(self) -> None:
        """The silent-drift failure in the other direction."""
        with tempfile.TemporaryDirectory() as raw:
            repo = self.repository(Path(raw))
            extra = repo / "manual" / "conf.d" / "50-extra.cfg"
            extra.parent.mkdir(parents=True)
            extra.write_bytes(b"backend extra\n  mode http\n")
            git(repo, "add", "-A")
            git(repo, "commit", "-qm", "Add an extra backend")
            _, head = resolve_head(repo)

            snapshot = build_candidate_tree(
                repo,
                head,
                {"core/haproxy.cfg": HAPROXY_CFG, "manual/reservations.yaml": RESERVATIONS},
            )
            self.assertNotIn("manual/conf.d/50-extra.cfg", read_tree_files(repo, snapshot.tree))

    def test_the_repository_index_is_never_touched(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            repo = self.repository(Path(raw))
            _, head = resolve_head(repo)
            before = (repo / ".git" / "index").read_bytes()
            build_candidate_tree(
                repo,
                head,
                {
                    "core/haproxy.cfg": HAPROXY_CFG + b"# changed\n",
                    "manual/reservations.yaml": RESERVATIONS,
                },
            )
            self.assertEqual((repo / ".git" / "index").read_bytes(), before)
            self.assertEqual(git(repo, "status", "--porcelain"), "")

    def test_a_path_outside_the_snapshot_layers_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            repo = self.repository(Path(raw))
            _, head = resolve_head(repo)
            with self.assertRaises(PublishError) as caught:
                build_candidate_tree(
                    repo,
                    head,
                    {
                        "core/haproxy.cfg": HAPROXY_CFG,
                        "manual/reservations.yaml": RESERVATIONS,
                        "managed/generated/99-sneaky.cfg": b"# not this path's to publish\n",
                    },
                )
            self.assertIn("managed/generated/99-sneaky.cfg", str(caught.exception))


class CommitTests(RepositoryFixture):
    def test_a_version_is_created_and_the_branch_moves(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            repo = self.repository(Path(raw))
            branch, head = resolve_head(repo)
            snapshot = build_candidate_tree(
                repo,
                head,
                {
                    "core/haproxy.cfg": HAPROXY_CFG + b"  option httplog\n",
                    "manual/reservations.yaml": RESERVATIONS,
                },
            )
            commit = commit_and_swap(
                repo, branch=branch, tree=snapshot.tree, parent=head, message="Enable HTTP logging"
            )
            self.assertEqual(git(repo, "rev-parse", "HEAD"), commit)
            self.assertEqual(git(repo, "log", "-1", "--pretty=%s"), "Enable HTTP logging")
            self.assertEqual(git(repo, "rev-list", "--count", "HEAD"), "2")

    def test_a_moved_branch_writes_nothing(self) -> None:
        """Compare and swap: a concurrent publish must not be overwritten."""
        with tempfile.TemporaryDirectory() as raw:
            repo = self.repository(Path(raw))
            branch, head = resolve_head(repo)
            snapshot = build_candidate_tree(
                repo,
                head,
                {
                    "core/haproxy.cfg": HAPROXY_CFG + b"  option httplog\n",
                    "manual/reservations.yaml": RESERVATIONS,
                },
            )
            # Someone else publishes first.
            (repo / "manual" / "reservations.yaml").write_bytes(b"reservations: [1]\n")
            git(repo, "add", "-A")
            git(repo, "commit", "-qm", "Concurrent version")
            moved = git(repo, "rev-parse", "HEAD")

            with self.assertRaises(ConcurrentUpdate):
                commit_and_swap(
                    repo, branch=branch, tree=snapshot.tree, parent=head, message="Too late"
                )
            self.assertEqual(git(repo, "rev-parse", "HEAD"), moved)


class IdentityTests(RepositoryFixture):
    def test_a_repository_without_an_identity_is_refused(self) -> None:
        """Better to stop than to record versions under a machine-derived address."""
        with tempfile.TemporaryDirectory() as raw:
            repo = self.repository(Path(raw))
            branch, head = resolve_head(repo)
            snapshot = build_candidate_tree(
                repo,
                head,
                {
                    "core/haproxy.cfg": HAPROXY_CFG + b"  option httplog\n",
                    "manual/reservations.yaml": RESERVATIONS,
                },
            )
            git(repo, "config", "--unset", "user.email")
            with self.assertRaises(PublishError) as caught:
                commit_and_swap(
                    repo, branch=branch, tree=snapshot.tree, parent=head, message="No identity"
                )
            self.assertIn("user.email", str(caught.exception))
            self.assertEqual(git(repo, "rev-parse", "HEAD"), head)

    def test_the_repository_identity_is_what_gets_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            repo = self.repository(Path(raw))
            branch, head = resolve_head(repo)
            snapshot = build_candidate_tree(
                repo,
                head,
                {
                    "core/haproxy.cfg": HAPROXY_CFG + b"  option httplog\n",
                    "manual/reservations.yaml": RESERVATIONS,
                },
            )
            commit_and_swap(
                repo, branch=branch, tree=snapshot.tree, parent=head, message="Enable HTTP logging"
            )
            self.assertEqual(
                git(repo, "log", "-1", "--pretty=%an <%ae>"),
                "Example Maintainer <maintainer@example.com>",
            )


if __name__ == "__main__":
    unittest.main()
