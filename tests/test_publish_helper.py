"""Publishing across the privilege boundary, against real repositories.

The cases that matter here are the ones where the boundary is the point: that
root derives the artifact instead of accepting one, that the version is recorded
only after validation passes, and that a starting point which moved is refused
rather than overwritten.
"""

from __future__ import annotations

import grp
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

from haprion import tls_policy
from haprion.candidate_validation import ValidationResult
from haprion.cli.publish_helper import main
from haprion.cluster_lock import hold
from haprion.version_history import count_versions, request_id_of
from tests.contract_schema import assert_contract

BASE = Path(__file__).resolve().parents[1]
REQUEST_ID = "22222222-2222-4222-8222-222222222222"

#
# A cluster that is set up correctly, which now includes the TLS defaults
# `core/` is expected to carry: a publish refuses when they disagree with
# `tls_policy`, and a fixture without them would be testing a cluster nobody
# would be allowed to publish. Rendered rather than pasted, so the fixture
# cannot drift from the check the way core/ drifted from the generator.
#
HAPROXY_CFG = (
    "global\n  daemon\n"
    f"  {tls_policy.DEFAULT_PATH_LINE}\n"
    + tls_policy.core_defaults_lines("  ")
    + "defaults\n  mode http\n"
).encode()
RESERVATIONS = b"{}\n"
GENERATED = b"frontend managed\n  bind 192.0.2.20:80\n"
CORE_CFG = b"frontend core\n  bind 192.0.2.20:81\n"


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["/usr/bin/git", "-C", str(repo), *args], capture_output=True, text=True, check=True
    ).stdout.strip()


class Recorder:
    """Stands in for chown so ownership can be asserted without being root."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, int, int]] = []

    def __call__(self, path: Path, uid: int, gid: int) -> None:
        self.calls.append((str(path), uid, gid))


class PublishFixture(unittest.TestCase):
    """Shared setup only; no test methods, so subclasses do not re-run each other."""

    def runtime(self, root: Path, *, linked_worktree: bool = False) -> Path:
        config_root = root / "config"
        publish_root = root / "published"
        cert_root = root / "validation-certs"
        for directory in (config_root, publish_root, cert_root):
            directory.mkdir(parents=True)
        (cert_root / "validation.pem").write_text("dummy PEM\n", encoding="utf-8")

        self.repo = self.repository(config_root, linked_worktree=linked_worktree)
        self.publish_path = publish_root / "alpha"

        clusters = yaml.safe_load((BASE / "examples/clusters.yaml").read_text())
        cluster = clusters["clusters"]["alpha"]
        cluster["config_path"] = str(self.repo)
        cluster["publish_path"] = str(self.publish_path)
        cluster["validation_certs"] = str(cert_root)
        cluster_path = root / "clusters.yaml"
        cluster_path.write_text(yaml.safe_dump(clusters), encoding="utf-8")

        policy = {
            "schema_version": 1,
            "cluster_file": str(cluster_path),
            "config_root": str(config_root),
            "publish_root": str(publish_root),
            "validation_certs_root": str(cert_root),
        }
        policy_path = root / "runtime-policy.yaml"
        policy_path.write_text(yaml.safe_dump(policy), encoding="utf-8")
        self.run_root = root / "run"
        self.lock_root = root / "locks"
        return policy_path

    def repository(self, config_root: Path, *, linked_worktree: bool) -> Path:
        """The draft area, in either layout B10 step 6 leaves behind."""

        draft = config_root / "alpha"
        if linked_worktree:
            history = config_root / "alpha.git"
            git(Path("/"), "init", "--quiet", "--bare", "--initial-branch=main", str(history))
            git(history, "config", "user.name", "Example Maintainer")
            git(history, "config", "user.email", "maintainer@example.com")
            git(history, "worktree", "add", "--quiet", "--orphan", "-b", "main", str(draft))
        else:
            draft.mkdir()
            git(draft, "init", "-q", "-b", "main")
            git(draft, "config", "user.name", "Example Maintainer")
            git(draft, "config", "user.email", "maintainer@example.com")

        for relative, content in (
            ("core/haproxy.cfg", HAPROXY_CFG),
            ("core/conf.d/0010-core.cfg", CORE_CFG),
            ("manual/reservations.yaml", RESERVATIONS),
            ("managed/generated/1040-managed.cfg", GENERATED),
        ):
            target = draft / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
        git(draft, "add", "-A")
        git(draft, "commit", "-qm", "Initial example configuration")
        return draft

    def edit(self, relative: str, content: bytes) -> None:
        """Change the draft area, the way an operator does before publishing."""

        (self.repo / relative).write_bytes(content)

    def draft_files(self) -> dict[str, str]:
        """Exactly what the thin caller sends: the draft's core/ and manual/."""

        return {
            str(path.relative_to(self.repo)): path.read_text(encoding="utf-8")
            for path in sorted(self.repo.rglob("*"))
            if path.is_file() and str(path.relative_to(self.repo)).startswith(("core/", "manual/"))
        }

    def request(self, **overrides: object) -> io.BytesIO:
        parameters: dict[str, object] = {
            "files": self.draft_files(),
            "expected_head": git(self.repo, "rev-parse", "HEAD"),
            "comment": "Added serverxyz",
        }
        parameters.update(overrides)
        return io.BytesIO(
            json.dumps(
                {
                    "schema_version": 1,
                    "operation": "publish_version",
                    "cluster": "alpha",
                    "request_id": REQUEST_ID,
                    "parameters": parameters,
                }
            ).encode()
        )

    def run_publish(
        self,
        policy_path: Path,
        stream: io.BytesIO,
        *,
        valid: bool = True,
        diagnostics: str = "Configuration file is valid\n",
    ) -> tuple[int, str, str]:
        seen: list[Path] = []

        def validate(candidate_root: Path, request_id: str) -> ValidationResult:
            seen.append(candidate_root)
            self.seen_files = {
                str(path.relative_to(candidate_root)): path.read_bytes()
                for path in sorted(candidate_root.rglob("*"))
                if path.is_file()
            }
            return ValidationResult(valid=valid, diagnostics=diagnostics)

        stdout = io.StringIO()
        stderr = io.StringIO()
        self.recorder = Recorder()
        code = main(
            [],
            policy_path=policy_path,
            run_root=self.run_root,
            lock_root=self.lock_root,
            input_stream=stream,
            output_stream=stdout,
            error_stream=stderr,
            require_secure=False,
            require_root=False,
            validator=validate,
            group=grp.getgrgid(os.getgid()).gr_name,
            change_owner=self.recorder,
        )
        self.sandbox_roots = seen
        return code, stdout.getvalue(), stderr.getvalue()


class PublishTests(PublishFixture):
    def test_a_version_is_recorded_and_the_release_installed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy_path = self.runtime(Path(raw))
            before = git(self.repo, "rev-parse", "HEAD")
            self.edit("core/haproxy.cfg", HAPROXY_CFG + b"  option httplog\n")
            code, stdout, stderr = self.run_publish(policy_path, self.request())
            document = assert_contract("haprion-publish", stdout)
            result = document["result"]

            self.assertEqual((code, stderr), (0, ""))
            self.assertEqual(document["operation"], "publish")
            self.assertEqual(document["outcome"], "done")
            self.assertTrue(result["changed"])
            self.assertEqual(result["version"], 2)
            self.assertEqual(result["hash"], git(self.repo, "rev-parse", "HEAD"))
            self.assertNotEqual(result["hash"], before)
            self.assertIs(result["deployment_required"], True)
            self.assertEqual(result["next_command"], "haprion-deploy -c alpha")
            self.assertEqual(result["comment"], "Added serverxyz")
            self.assertEqual(git(self.repo, "log", "-1", "--format=%s"), "Added serverxyz")

            release = Path(result["release"]) / "alpha"
            self.assertIn(b"httplog", (release / "haproxy.cfg").read_bytes())
            self.assertEqual((release / "conf.d/1040-managed.cfg").read_bytes(), GENERATED)
            self.assertIn("version=2\n", (release / "RELEASE").read_text())
            self.assertEqual(
                os.readlink(self.publish_path / "current"), f"releases/{result['hash']}"
            )

    def test_the_version_it_records_is_bound_to_the_request(self) -> None:
        """Half of the evidence a restart needs, written where it survives.

        The operator's comment stays the whole subject: that is what the version
        list shows, and a UUID there would be noise. The binding rides in a
        trailer, which every reader of the list ignores and a recovery reads
        exactly.
        """

        with tempfile.TemporaryDirectory() as raw:
            policy_path = self.runtime(Path(raw))
            self.edit("core/haproxy.cfg", HAPROXY_CFG + b"  option httplog\n")
            code, stdout, _ = self.run_publish(policy_path, self.request())

            self.assertEqual(code, 0)
            document = assert_contract("haprion-publish", stdout)
            head = git(self.repo, "rev-parse", "HEAD")
            self.assertEqual(request_id_of(self.repo, head), document["request_id"])
            self.assertEqual(git(self.repo, "log", "-1", "--format=%s"), "Added serverxyz")

    def test_the_draft_area_is_clean_afterwards(self) -> None:
        """Without the index refresh the draft reads as dirty to every later check."""
        with tempfile.TemporaryDirectory() as raw:
            policy_path = self.runtime(Path(raw))
            self.edit("core/haproxy.cfg", HAPROXY_CFG + b"  option httplog\n")
            code, _, stderr = self.run_publish(policy_path, self.request())
            self.assertEqual((code, stderr), (0, ""))
            self.assertEqual(git(self.repo, "status", "--porcelain"), "")

    def test_managed_is_carried_over_and_validated_with_the_candidate(self) -> None:
        """Root validates the committed tree, not the bytes it was handed."""
        with tempfile.TemporaryDirectory() as raw:
            policy_path = self.runtime(Path(raw))
            self.edit("core/haproxy.cfg", HAPROXY_CFG + b"  option httplog\n")
            self.run_publish(policy_path, self.request())
            self.assertEqual(self.seen_files["conf.d/1040-managed.cfg"], GENERATED)
            self.assertIn(b"httplog", self.seen_files["haproxy.cfg"])
            self.assertFalse(self.sandbox_roots[0].exists())

    def test_the_linked_worktree_layout_publishes_the_same_way(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy_path = self.runtime(Path(raw), linked_worktree=True)
            self.edit("core/haproxy.cfg", HAPROXY_CFG + b"  option httplog\n")
            code, stdout, stderr = self.run_publish(policy_path, self.request())
            result = assert_contract("haprion-publish", stdout)["result"]
            self.assertEqual((code, stderr), (0, ""))
            self.assertEqual(result["version"], 2)
            self.assertEqual(git(self.repo, "status", "--porcelain"), "")

    def test_a_stale_core_is_refused_before_a_version_is_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy_path = self.runtime(Path(raw))
            before = git(self.repo, "rev-parse", "HEAD")
            self.edit(
                "core/haproxy.cfg",
                HAPROXY_CFG.replace(f"  {tls_policy.DEFAULT_PATH_LINE}\n".encode(), b""),
            )

            code, stdout, _stderr = self.run_publish(policy_path, self.request())

            self.assertEqual(code, 75)
            self.assertEqual(json.loads(stdout)["error"]["code"], "tls_defaults_stale")
            self.assertEqual(git(self.repo, "rev-parse", "HEAD"), before)

    def test_an_unchanged_retry_is_held_to_the_same_policy(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy_path = self.runtime(Path(raw))
            self.edit(
                "core/haproxy.cfg",
                HAPROXY_CFG.replace(f"  {tls_policy.DEFAULT_PATH_LINE}\n".encode(), b""),
            )
            git(self.repo, "commit", "-qam", "Human edit to core")

            code, stdout, _stderr = self.run_publish(policy_path, self.request())

            self.assertEqual(code, 75)
            self.assertEqual(json.loads(stdout)["error"]["code"], "tls_defaults_stale")
            self.assertFalse((self.publish_path / "current").exists())

    def test_an_unchanged_candidate_creates_no_version(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy_path = self.runtime(Path(raw))
            before = git(self.repo, "rev-parse", "HEAD")
            code, stdout, stderr = self.run_publish(policy_path, self.request())
            document = assert_contract("haprion-publish", stdout)
            result = document["result"]
            self.assertEqual((code, stderr), (0, ""))
            #
            # A verified no-op is `done`, not a failure: the contract says so,
            # and an operator who publishes twice has not made a mistake.
            #
            self.assertEqual(document["outcome"], "done")
            self.assertFalse(result["changed"])
            self.assertIsNone(result["published_at"])
            self.assertEqual(result["hash"], before)
            self.assertEqual(git(self.repo, "rev-parse", "HEAD"), before)
            #
            # No version was recorded, but the release for the head that already
            # existed is now published. A published area that lags the
            # repository is the state an interrupted run leaves behind, and it
            # cannot be told apart from one that was never published - so both
            # are repaired the same way. `deployment_required` says so plainly
            # rather than letting the nodes lag a release nobody mentioned.
            #
            self.assertTrue(result["deployment_required"])
            self.assertEqual(os.readlink(self.publish_path / "current"), f"releases/{before}")


class RefusalTests(PublishFixture):
    def test_a_moved_starting_point_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy_path = self.runtime(Path(raw))
            self.edit("core/haproxy.cfg", HAPROXY_CFG + b"  option httplog\n")
            stream = self.request(expected_head="0" * 40)
            before = git(self.repo, "rev-parse", "HEAD")
            code, stdout, stderr = self.run_publish(policy_path, stream)
            self.assertEqual(code, 75)
            self.assertIn("changed after this candidate was prepared", stderr)
            document = assert_contract("haprion-publish", stdout)
            self.assertEqual(document["outcome"], "blocked")
            self.assertEqual(document["error"]["code"], "base_version_changed")
            self.assertEqual(git(self.repo, "rev-parse", "HEAD"), before)

    def test_an_invalid_candidate_records_nothing(self) -> None:
        """The order the shell path established: validate, then commit."""
        with tempfile.TemporaryDirectory() as raw:
            policy_path = self.runtime(Path(raw))
            before = git(self.repo, "rev-parse", "HEAD")
            self.edit("core/haproxy.cfg", HAPROXY_CFG + b"  option httplog\n")
            code, stdout, stderr = self.run_publish(
                policy_path,
                self.request(),
                valid=False,
                diagnostics="[ALERT] parsing error\n",
            )
            document = assert_contract("haprion-publish", stdout)
            self.assertEqual(code, 65)
            self.assertIn("configuration is invalid", stderr)
            self.assertEqual(document["outcome"], "failed")
            self.assertEqual(document["error"]["code"], "candidate_invalid")
            self.assertIn("parsing error", document["error"]["details"]["diagnostics"])
            self.assertEqual(git(self.repo, "rev-parse", "HEAD"), before)
            self.assertFalse(self.publish_path.exists())

    def test_paths_outside_the_published_layers_are_refused(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy_path = self.runtime(Path(raw))
            for path in ("managed/generated/1050-x.cfg", "../escape.cfg", "/etc/passwd"):
                stream = self.request(
                    files={
                        "core/haproxy.cfg": HAPROXY_CFG.decode(),
                        path: "frontend x\n",
                    }
                )
                code, stdout, stderr = self.run_publish(policy_path, stream)
                self.assertEqual(code, 65)
                self.assertIn("ERROR:", stderr)
                document = assert_contract("haprion-publish", stdout)
                self.assertEqual(document["error"]["code"], "bad_input")

    def test_a_second_publish_with_the_release_in_place_asks_for_no_deploy(self) -> None:
        """The genuine no-op the contract describes: nothing recorded, nothing
        moved, and no deploy implied."""

        with tempfile.TemporaryDirectory() as raw:
            policy_path = self.runtime(Path(raw))
            self.edit("core/haproxy.cfg", HAPROXY_CFG + b"  option httplog\n")
            self.run_publish(policy_path, self.request())

            code, stdout, _ = self.run_publish(policy_path, self.request())

            self.assertEqual(code, 0)
            result = assert_contract("haprion-publish", stdout)["result"]
            self.assertFalse(result["changed"])
            self.assertIs(result["deployment_required"], False)
            self.assertIsNone(result["next_command"])
            self.assertTrue(result["already_current"])

    def test_an_interrupted_publish_is_finished_without_a_second_version(self) -> None:
        """Phase 6's repair: a commit whose release never landed.

        The crash window is between the reference swap and the install. On the
        retry the candidate matches the head that the interrupted run recorded,
        so nothing new is committed - and the release the nodes fetch is written
        from that same commit rather than from a new one.
        """

        with tempfile.TemporaryDirectory() as raw:
            policy_path = self.runtime(Path(raw))
            self.edit("core/haproxy.cfg", HAPROXY_CFG + b"  option httplog\n")
            self.run_publish(policy_path, self.request())

            head = git(self.repo, "rev-parse", "HEAD")
            versions = count_versions(self.repo)
            #
            # What the crash left: the version is recorded, the release is gone.
            #
            shutil.rmtree(self.publish_path / "releases" / head)
            (self.publish_path / "current").unlink()

            code, stdout, _ = self.run_publish(policy_path, self.request())

            self.assertEqual(code, 0)
            result = assert_contract("haprion-publish", stdout)["result"]
            self.assertFalse(result["changed"])
            self.assertEqual(count_versions(self.repo), versions)
            self.assertEqual(git(self.repo, "rev-parse", "HEAD"), head)
            self.assertEqual(result["hash"], head)
            self.assertTrue(result["deployment_required"])
            self.assertEqual(os.readlink(self.publish_path / "current"), f"releases/{head}")

    def test_a_held_cluster_lock_blocks_the_publish_without_writing(self) -> None:
        """The lock a publish did not use to take at all.

        The compare-and-swap on the branch reference already caught a second
        publish, but nothing serialised a publish against a revert, and nothing
        stopped a deploy from reading the release area while this run was
        rewriting it.
        """

        with tempfile.TemporaryDirectory() as raw:
            policy_path = self.runtime(Path(raw))
            before = git(self.repo, "rev-parse", "HEAD")
            self.edit("core/haproxy.cfg", HAPROXY_CFG + b"  option httplog\n")

            with hold("alpha", operation="deploy", root=self.lock_root):
                code, stdout, _ = self.run_publish(policy_path, self.request())

            self.assertEqual(code, 75)
            document = assert_contract("haprion-publish", stdout)
            self.assertEqual(document["outcome"], "blocked")
            self.assertEqual(document["error"]["code"], "operation_locked")
            self.assertEqual(git(self.repo, "rev-parse", "HEAD"), before)
            self.assertFalse(self.publish_path.exists())

    def test_a_comment_with_control_characters_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy_path = self.runtime(Path(raw))
            code, _, stderr = self.run_publish(
                policy_path, self.request(comment="Added\x1b[2Jserverxyz")
            )
            self.assertEqual(code, 65)
            self.assertIn("control characters", stderr)

    def test_an_empty_comment_and_a_short_head_are_refused(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy_path = self.runtime(Path(raw))
            for overrides, expected in (
                ({"comment": "   "}, "comment"),
                ({"expected_head": "abc"}, "commit ID"),
            ):
                code, _, stderr = self.run_publish(policy_path, self.request(**overrides))
                self.assertEqual(code, 65)
                self.assertIn(expected, stderr)

    def test_argv_is_refused_before_anything_is_read(self) -> None:
        stderr = io.StringIO()
        code = main(
            ["-c", "alpha"],
            input_stream=io.BytesIO(b""),
            output_stream=io.StringIO(),
            error_stream=stderr,
            require_root=False,
        )
        self.assertEqual(code, 64)
        self.assertIn("no command-line arguments", stderr.getvalue())

    @unittest.skipIf(os.geteuid() == 0, "the refusal only applies to a non-root caller")
    def test_a_non_root_invocation_is_refused(self) -> None:
        stderr = io.StringIO()
        code = main(
            [],
            input_stream=io.BytesIO(b""),
            output_stream=io.StringIO(),
            error_stream=stderr,
        )
        self.assertEqual(code, 77)
        self.assertIn("must run as root", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
