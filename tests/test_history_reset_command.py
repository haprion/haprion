"""The two confirmations, and what happens when they are not given.

A reset must never be the outcome of a mistake, a held-down key, or a closed
pipe. These cases are about refusing, because the refusing is the part that has
to be right every single time.
"""

from __future__ import annotations

import io
import os
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import yaml

from haproxy_mgmt.cli.history_reset import CONFIRMATION, main
from haproxy_mgmt.history_reset import history_path

BASE = Path(__file__).resolve().parents[1]
HAPROXY_CFG = b"global\n  daemon\ndefaults\n  mode http\n"


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["/usr/bin/git", "-C", str(repo), *args], capture_output=True, text=True, check=True
    ).stdout.strip()


class CommandTests(unittest.TestCase):
    def runtime(self, root: Path) -> tuple[Path, Path]:
        """A policy file and a cluster whose repository has three versions."""

        config_root = root / "config"
        publish_root = root / "published"
        cert_root = root / "validation-certs"
        for directory in (config_root, publish_root / "alpha", cert_root):
            directory.mkdir(parents=True)
        (cert_root / "validation.pem").write_text("dummy PEM\n", encoding="utf-8")

        seed = root / "seed"
        seed.mkdir()
        git(seed, "init", "-q", "-b", "main")
        git(seed, "config", "user.name", "Example Maintainer")
        git(seed, "config", "user.email", "maintainer@example.com")
        (seed / "core").mkdir()
        (seed / "manual").mkdir()
        (seed / "manual" / "reservations.yaml").write_bytes(b"reservations: []\n")
        for number in range(3):
            (seed / "core" / "haproxy.cfg").write_bytes(HAPROXY_CFG + f"# {number}\n".encode())
            git(seed, "add", "-A")
            git(seed, "commit", "-qm", f"Version {number + 1}")

        history = config_root / "alpha.git"
        subprocess.run(
            ["/usr/bin/git", "clone", "-q", "--bare", str(seed), str(history)],
            check=True,
            capture_output=True,
        )
        git(history, "config", "user.name", "Example Maintainer")
        git(history, "config", "user.email", "maintainer@example.com")
        draft = config_root / "alpha"
        git(history, "worktree", "add", "-q", str(draft), "main")

        clusters = yaml.safe_load((BASE / "examples/clusters.yaml").read_text())
        cluster = clusters["clusters"]["alpha"]
        cluster["config_path"] = str(draft)
        cluster["publish_path"] = str(publish_root / "alpha")
        cluster["validation_certs"] = str(cert_root)
        clusters_file = root / "clusters.yaml"
        clusters_file.write_text(yaml.safe_dump(clusters), encoding="utf-8")

        policy = root / "runtime-policy.yaml"
        policy.write_text(
            yaml.safe_dump(
                {
                    "schema_version": 1,
                    "cluster_file": str(clusters_file),
                    "config_root": str(config_root),
                    "publish_root": str(publish_root),
                    "validation_certs_root": str(cert_root),
                }
            ),
            encoding="utf-8",
        )
        return policy, draft

    def run_command(self, policy: Path, answers: str, publish_result: int = 0):
        published: list[str] = []

        def publish(cluster_id: str) -> int:
            published.append(cluster_id)
            return publish_result

        output = io.StringIO()
        code = main(
            ["-c", "alpha"],
            policy_path=policy,
            stream_in=io.StringIO(answers),
            stream_out=output,
            require_root=False,
            publish=publish,
            change_owner=lambda path, uid, gid: None,
        )
        return code, output.getvalue(), published

    # ------------------------------------------------------------------ refusing

    def test_answering_no_changes_nothing(self) -> None:
        with TemporaryDirectory() as raw:
            policy, draft = self.runtime(Path(raw))
            before = git(draft, "rev-parse", "HEAD")
            code, output, published = self.run_command(policy, "n\n")
            self.assertEqual(code, 0)
            self.assertIn("Nothing was changed", output)
            self.assertEqual(git(draft, "rev-parse", "HEAD"), before)
            self.assertEqual(published, [])

    def test_the_default_answer_is_no(self) -> None:
        """A held-down return key must not reset a cluster."""
        with TemporaryDirectory() as raw:
            policy, draft = self.runtime(Path(raw))
            before = git(draft, "rev-parse", "HEAD")
            code, output, _ = self.run_command(policy, "\n\n\n")
            self.assertEqual(code, 0)
            self.assertIn("Nothing was changed", output)
            self.assertEqual(git(draft, "rev-parse", "HEAD"), before)

    def test_a_closed_pipe_is_not_a_yes(self) -> None:
        with TemporaryDirectory() as raw:
            policy, draft = self.runtime(Path(raw))
            before = git(draft, "rev-parse", "HEAD")
            code, _, _ = self.run_command(policy, "")
            self.assertEqual(code, 0)
            self.assertEqual(git(draft, "rev-parse", "HEAD"), before)

    def test_the_wrong_phrase_stops_it(self) -> None:
        with TemporaryDirectory() as raw:
            policy, draft = self.runtime(Path(raw))
            before = git(draft, "rev-parse", "HEAD")
            code, output, published = self.run_command(policy, "y\nreset\n")
            self.assertEqual(code, 0)
            self.assertIn("did not match", output)
            self.assertEqual(git(draft, "rev-parse", "HEAD"), before)
            self.assertEqual(published, [])

    def test_yes_alone_is_not_enough(self) -> None:
        with TemporaryDirectory() as raw:
            policy, draft = self.runtime(Path(raw))
            before = git(draft, "rev-parse", "HEAD")
            code, _, _ = self.run_command(policy, "y\n\n")
            self.assertEqual(code, 0)
            self.assertEqual(git(draft, "rev-parse", "HEAD"), before)

    def test_running_without_root_refuses(self) -> None:
        with TemporaryDirectory() as raw:
            policy, _ = self.runtime(Path(raw))
            output = io.StringIO()
            code = main(
                ["-c", "alpha"],
                policy_path=policy,
                stream_in=io.StringIO(""),
                stream_out=output,
            )
            expected = 0 if os.geteuid() == 0 else 77
            self.assertEqual(code, expected)

    # ------------------------------------------------------------------ doing it

    def test_both_confirmations_reset_and_publish(self) -> None:
        with TemporaryDirectory() as raw:
            policy, draft = self.runtime(Path(raw))
            code, output, published = self.run_command(policy, f"y\n{CONFIRMATION}\n")
            self.assertEqual(code, 0, output)
            self.assertEqual(git(draft, "rev-list", "--first-parent", "--count", "HEAD"), "1")
            self.assertEqual(published, ["alpha"])
            self.assertIn("3 versions", output)
            self.assertIn("haproxy-deploy -c alpha", output)

    def test_the_previous_history_is_named_in_the_output(self) -> None:
        """The undo path has to be readable from the screen, not looked up later."""
        with TemporaryDirectory() as raw:
            policy, draft = self.runtime(Path(raw))
            _, output, _ = self.run_command(policy, f"y\n{CONFIRMATION}\n")
            archives = sorted(path.name for path in draft.parent.glob("*.pre-reset-*"))
            self.assertEqual(len(archives), 2, archives)
            for name in archives:
                self.assertIn(name, output)

    def test_a_failed_publish_is_reported_as_unfinished(self) -> None:
        """The reset stands, so the operator must be told what is now inconsistent."""
        with TemporaryDirectory() as raw:
            policy, draft = self.runtime(Path(raw))
            code, output, _ = self.run_command(policy, f"y\n{CONFIRMATION}\n", publish_result=65)
            self.assertEqual(code, 65)
            self.assertIn("refers to a version that", output)
            self.assertIn("haproxy-publish -c alpha", output)
            self.assertEqual(git(draft, "rev-list", "--first-parent", "--count", "HEAD"), "1")

    def test_it_does_not_deploy(self) -> None:
        """Reloading production nodes is not this command's job."""
        with TemporaryDirectory() as raw:
            policy, _ = self.runtime(Path(raw))
            _, output, _ = self.run_command(policy, f"y\n{CONFIRMATION}\n")
            self.assertNotIn("Deploying", output)
            self.assertIn("already running this configuration", output)

    def test_the_layout_still_works_afterwards(self) -> None:
        with TemporaryDirectory() as raw:
            policy, draft = self.runtime(Path(raw))
            self.run_command(policy, f"y\n{CONFIRMATION}\n")
            self.assertEqual(git(history_path(draft), "rev-parse", "--is-bare-repository"), "true")
            self.assertEqual(git(draft, "status", "--porcelain"), "")


if __name__ == "__main__":
    unittest.main()
